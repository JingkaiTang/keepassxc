// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef KEEPASSXC_WEBDAVSYNC_H
#define KEEPASSXC_WEBDAVSYNC_H

#include "networking/WebDavMerge.h"
#include "networking/WebDavSession.h"
#include <QObject>
#include <QPointer>

#include <QSharedPointer>

class QDialog;

class Database;
class DatabaseWidget;

class WebDavSync : public QObject
{
    Q_OBJECT
public:
    WebDavSync(DatabaseWidget* widget, WebDavSession* session, QObject* parent);
    ~WebDavSync() override;
    void review();
    void reviewUnlocked(const QSharedPointer<Database>& remote);

private:
    void reconcile(const QString& path,
                   bool interactive,
                   const QHash<QUuid, WebDavMerge::Side>& choices = {},
                   const QSharedPointer<Database>& unlocked = {});
    void chooseVersions(const WebDavMerge& plan,
                        const QString& path,
                        quint64 revision,
                        const QSharedPointer<Database>& unlocked);
    void display(const QSharedPointer<Database>& db);

    DatabaseWidget* const m_widget;
    QPointer<WebDavSession> m_session;
    QPointer<QDialog> m_dialog;
    QString m_waitingPath;
    QString m_waitingMessage;
    WebDavSession::ConflictAction m_waitingAction = WebDavSession::ConflictAction::None;
    quint64 m_waitingRevision = 0;
    bool m_applying = false;
    bool m_reviewRequested = false;
};

#endif
