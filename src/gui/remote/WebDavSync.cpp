// SPDX-License-Identifier: GPL-2.0-or-later
#include "WebDavSync.h"

#include "core/Database.h"
#include "gui/DatabaseOpenDialog.h"
#include "gui/DatabaseWidget.h"
#include "gui/entry/EntryView.h"
#include "gui/group/GroupView.h"
#include "networking/WebDavMerge.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QHeaderView>
#include <QLineEdit>
#include <QNetworkInformation>
#include <QPointer>
#include <QPushButton>
#include <QScopeGuard>
#include <QTableWidget>
#include <QTemporaryFile>
#include <QTextDocument>
#include <QVBoxLayout>
#include <algorithm>

WebDavSync::WebDavSync(DatabaseWidget* widget, WebDavSession* session, QObject* parent)
    : QObject(parent)
    , m_widget(widget)
    , m_session(session)
{
    auto updateMode = [this] {
        const bool unlocked = !m_widget->isLocked() && m_widget->database()->isInitialized();
        m_session->setChecksEnabled(unlocked);
        if (unlocked && m_widget->currentMode() == DatabaseWidget::Mode::ViewMode) {
            m_session->checkForChanges();
        }
    };
    connect(widget, &DatabaseWidget::currentModeChanged, this, updateMode);
    connect(widget, &DatabaseWidget::databaseUnlocked, this, [this, updateMode] {
        m_waitingPath.clear();
        updateMode();
    });
    connect(qApp, &QGuiApplication::applicationStateChanged, this, [this](Qt::ApplicationState state) {
        if (state == Qt::ApplicationActive) {
            m_session->checkForChanges();
        }
    });
#if QT_VERSION >= QT_VERSION_CHECK(6, 4, 0)
    QNetworkInformation::loadDefaultBackend();
#else
    QNetworkInformation::load(QNetworkInformation::Feature::Reachability);
#endif
    if (auto* network = QNetworkInformation::instance()) {
        connect(network, &QNetworkInformation::reachabilityChanged, this, [this](auto state) {
            if (state == QNetworkInformation::Reachability::Online) {
                m_session->networkRestored();
            }
        });
    }
    connect(
        session,
        &WebDavSession::remoteChanged,
        this,
        [this](const QString& path) { reconcile(path, false); },
        Qt::QueuedConnection);
    updateMode();
}

WebDavSync::~WebDavSync()
{
    if (m_session) {
        m_session->setChecksEnabled(false);
    }
}

void WebDavSync::reviewUnlocked(const QSharedPointer<Database>& remote)
{
    if (remote && m_session && remote->filePath() == m_session->remotePath()) {
        m_dialog.clear();
        reconcile(remote->filePath(), true, {}, remote);
    }
}

void WebDavSync::display(const QSharedPointer<Database>& db)
{
    auto* group = m_widget->currentGroup();
    auto* entry = m_widget->currentSelectedEntry();
    const auto groupId = group ? group->uuid() : QUuid();
    const auto entryId = entry ? entry->uuid() : QUuid();
    db->setFilePath(m_session->localPath());
    m_widget->replaceDatabase(db);
    if (auto* selected = db->rootGroup()->findGroupByUuid(groupId)) {
        m_widget->groupView()->setCurrentGroup(selected);
    }
    if (auto* selected = db->rootGroup()->findEntryByUuid(entryId)) {
        m_widget->entryView()->setCurrentEntry(selected);
    }
}

void WebDavSync::review()
{
    if (m_applying) {
        m_reviewRequested = true;
    } else {
        reconcile(m_session->remotePath(), true);
    }
}

void WebDavSync::chooseVersions(const WebDavMerge& plan,
                                const QString& path,
                                quint64 revision,
                                const QSharedPointer<Database>& unlocked)
{
    auto* dialog = new QDialog(m_widget);
    m_dialog = dialog;
    dialog->setObjectName("webDavConflicts");
    dialog->setWindowTitle(tr("Review WebDAV conflicts"));
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto* layout = new QVBoxLayout(dialog);
    auto* table = new QTableWidget(plan.conflicts.size() + int(plan.chooseStructure), 4, dialog);
    table->setHorizontalHeaderLabels({tr("Entry"), tr("This device"), tr("WebDAV"), tr("Keep")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->hide();
    layout->addWidget(table);
    auto* reveal = new QCheckBox(tr("Show passwords"), dialog);
    layout->addWidget(reveal);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
    layout->addWidget(buttons);
    auto* ok = buttons->button(QDialogButtonBox::Ok);
    ok->setText(tr("Merge and sync"));
    ok->setEnabled(false);
    QHash<QUuid, QComboBox*> selectors;
    int row = 0;
    auto addChoice = [&](const QUuid& uuid) {
        auto* choice = new QComboBox(table);
        choice->addItems({tr("Choose…"), tr("This device"), tr("WebDAV")});
        table->setCellWidget(row, 3, choice);
        selectors.insert(uuid, choice);
        ++row;
    };
    if (plan.chooseStructure) {
        table->setItem(row, 0, new QTableWidgetItem(tr("Database settings and groups")));
        addChoice({});
    }
    for (const auto& conflict : plan.conflicts) {
        auto* entry = conflict.local ? conflict.local : conflict.remote;
        QString label = entry->path();
        if (conflict.local && conflict.remote) {
            label += "\n" + conflict.local->calculateDifference(conflict.remote).join(", ");
        }
        table->setItem(row, 0, new QTableWidgetItem(label));
        int column = 1;
        for (auto* version : {conflict.local, conflict.remote}) {
            if (version) {
                auto* password = new QLineEdit(table);
                password->setReadOnly(true);
                password->setEchoMode(QLineEdit::Password);
                password->setText(version->password());
                password->setToolTip(Qt::convertFromPlainText(
                    version->path() + "\n" + version->timeInfo().lastModificationTime().toLocalTime().toString()));
                connect(reveal, &QCheckBox::toggled, password, [password](bool show) {
                    password->setEchoMode(show ? QLineEdit::Normal : QLineEdit::Password);
                });
                table->setCellWidget(row, column, password);
            } else {
                table->setItem(row, column, new QTableWidgetItem(tr("Not present")));
            }
            ++column;
        }
        addChoice(conflict.uuid);
    }
    for (auto* choice : selectors) {
        connect(choice, &QComboBox::currentIndexChanged, dialog, [ok, selectors] {
            ok->setEnabled(
                std::all_of(selectors.cbegin(), selectors.cend(), [](auto* box) { return box->currentIndex() != 0; }));
        });
    }
    connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    connect(m_widget, &DatabaseWidget::databaseLockRequested, dialog, &QDialog::reject);
    connect(m_widget, &DatabaseWidget::databaseReplaced, dialog, &QDialog::reject);
    connect(this, &QObject::destroyed, dialog, &QDialog::reject);
    connect(m_session, &WebDavSession::remoteChanged, dialog, [dialog, path](const QString& latest) {
        if (latest != path) {
            dialog->reject();
        }
    });
    connect(dialog, &QDialog::accepted, this, [this, selectors, path, revision, unlocked] {
        m_dialog.clear();
        if (path != m_session->remotePath() || revision != m_session->localRevision()) {
            m_session->checkForChanges();
            return;
        }
        QHash<QUuid, WebDavMerge::Side> choices;
        for (auto it = selectors.cbegin(); it != selectors.cend(); ++it) {
            choices.insert(it.key(),
                           it.value()->currentIndex() == 1 ? WebDavMerge::Side::Local : WebDavMerge::Side::Remote);
        }
        reconcile(path, true, choices, unlocked);
    });
    table->resizeColumnsToContents();
    table->resizeRowsToContents();
    table->horizontalHeader()->setStretchLastSection(true);
    dialog->resize(720, 300);
    dialog->open();
}

void WebDavSync::reconcile(const QString& path,
                           bool interactive,
                           const QHash<QUuid, WebDavMerge::Side>& choices,
                           const QSharedPointer<Database>& unlocked)
{
    if (!m_session || m_dialog || m_applying || path.isEmpty() || path != m_session->remotePath()) {
        return;
    }
    QPointer<WebDavSync> self(this);
    const auto local = m_widget->database();
    const auto revision = m_session->localRevision();
    auto current = [&] {
        return self && m_session && m_widget->database() == local
               && m_widget->currentMode() == DatabaseWidget::Mode::ViewMode && !m_widget->isSaving()
               && path == m_session->remotePath() && m_session->localRevision() == revision;
    };
    if (!current()) {
        return;
    }
    if (!interactive && !local->isModified() && path == m_waitingPath && revision == m_waitingRevision) {
        m_session->reportReview(m_waitingMessage, m_waitingAction);
        return;
    }
    using Action = WebDavSession::ConflictAction;
    auto waitForReview = [&](const QString& message, Action action = Action::Review) {
        m_waitingPath = path;
        m_waitingMessage = message;
        m_waitingRevision = revision;
        m_waitingAction = action;
        m_session->reportReview(message, action);
    };
    m_applying = true;
    m_session->pauseChecks(true);
    const auto done = qScopeGuard([self, session = m_session] {
        if (session) {
            session->pauseChecks(false);
        }
        if (self) {
            self->m_applying = false;
            if (self->m_reviewRequested) {
                self->m_reviewRequested = false;
                QTimer::singleShot(0, self, &WebDavSync::review);
            }
        }
    });
    if (m_session->isReadOnly() && (local->isModified() || !m_session->canReceiveRemote())) {
        m_session->reportReview(tr("Local changes are preserved. This WebDAV connection cannot safely upload them."),
                                Action::SaveLocalCopy);
        return;
    }
    if (local->isModified()) {
        // The editor has closed. Checkpoint its committed changes behind the session's
        // conflict barrier before computing a plan from the encrypted working copy.
        if (m_widget->save() && self && interactive) {
            m_reviewRequested = true;
        }
        return;
    }
    auto unmodified = [&] { return current() && !local->isModified(); };
    auto remote = unlocked ? unlocked : QSharedPointer<Database>::create();
    const bool opened = unlocked || remote->open(path, local->key());
    if (!unmodified()) {
        return;
    }
    if (opened && m_session->canReceiveRemote()) {
        if (m_session->installRemote()) {
            display(remote);
        }
        return;
    }
    if (!opened && interactive) {
        auto* dialog = new DatabaseOpenDialog(m_widget);
        m_dialog = dialog;
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setIntent(DatabaseOpenDialog::Intent::WebDavMerge);
        dialog->setTarget(m_widget, path);
        connect(m_widget, &DatabaseWidget::databaseLockRequested, dialog, &QDialog::reject);
        connect(this, &QObject::destroyed, dialog, &QDialog::reject);
        dialog->showMessage(m_session->canReceiveRemote()
                                ? tr("Unlock the updated database to use it with its new master key.")
                                : tr("Unlock the remote database to review its changes. A merged database will use the "
                                     "master key of this device."),
                            MessageWidget::Information,
                            MessageWidget::DisableAutoHide);
        dialog->open();
        return;
    }
    if (!opened) {
        waitForReview(tr("Unlock the updated WebDAV database to review it. Your local copy is preserved."));
        return;
    }

    Database base;
    const auto basePath = m_session->basePath();
    const bool hasBase = !basePath.isEmpty() && base.open(basePath, local->key());
    if (!unmodified()) {
        return;
    }
    WebDavMerge plan(hasBase ? &base : nullptr, *local, *remote);
    if (!plan.compatible) {
        waitForReview(tr("The remote file has a different database root. Your local copy is preserved."),
                      Action::SaveLocalCopy);
        return;
    }
    if ((plan.chooseStructure || !plan.conflicts.isEmpty()) && choices.isEmpty()) {
        waitForReview(hasBase ? tr("Conflicting changes need your review. The entire upload is on hold.")
                              : tr("The common baseline is unavailable. Review both versions before syncing."));
        if (interactive) {
            chooseVersions(plan, path, revision, unlocked);
        }
        return;
    }
    auto candidate = QSharedPointer<Database>::create();
    const bool useLocal = choices.value({}, plan.startingCopy) == WebDavMerge::Side::Local;
    const auto source = useLocal ? m_session->localPath() : path;
    QTemporaryFile result(QFileInfo(path).absolutePath() + "/transfer-XXXXXX");
    if (!result.open()) {
        m_session->reportReview(tr("Could not create an encrypted merge candidate."));
        return;
    }
    result.close();
    QString error;
    if (!candidate->open(source, useLocal ? local->key() : remote->key(), &error) || !unmodified()) {
        return;
    }
    if (!plan.apply(*candidate, choices)) {
        m_session->reportReview(tr("The selected changes need manual review because their destination group changed."),
                                choices.isEmpty() ? Action::SaveLocalCopy : Action::Review);
        return;
    }
    if (unlocked && !useLocal && !candidate->setKey(local->key())) {
        return;
    }
    if (!unmodified()) {
        return;
    }
    if (!candidate->saveAs(result.fileName(), Database::Atomic, {}, &error)) {
        if (self) {
            m_session->reportReview(tr("Could not save the encrypted merge candidate: %1").arg(error));
        }
        return;
    }
    if (unmodified() && m_session->installMerged(result.fileName(), revision)) {
        display(candidate);
    }
}
