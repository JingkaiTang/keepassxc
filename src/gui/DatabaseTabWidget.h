/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or (at your option)
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPASSXC_DATABASETABWIDGET_H
#define KEEPASSXC_DATABASETABWIDGET_H

#include "DatabaseOpenDialog.h"
#include "config-keepassx.h"
#include "gui/MessageWidget.h"
#include "wizard/ImportWizard.h"

#include <QSet>
#include <QTabWidget>
#include <QTimer>

class Database;
class DatabaseWidget;
class DatabaseWidgetStateSync;
class DatabaseOpenWidget;
#ifdef KPXC_FEATURE_NETWORK
class WebDavDialog;
class WebDavSession;
#endif

class DatabaseTabWidget : public QTabWidget
{
    Q_OBJECT

public:
    explicit DatabaseTabWidget(QWidget* parent = nullptr);
    ~DatabaseTabWidget() override;
    void mergeDatabase(const QString& filePath);

    QString tabName(int index);
    DatabaseWidget* currentDatabaseWidget();
    DatabaseWidget* databaseWidgetFromIndex(int index) const;

    bool canSave(int index = -1) const;
    bool isModified(int index = -1) const;
    bool hasLockableDatabases() const;

public slots:
    void lockAndSwitchToFirstUnlockedDatabase(int index = -1);
    void addDatabaseTab(const QString& filePath,
                        bool inBackground = false,
                        const QString& password = {},
                        const QString& keyfile = {});
    void addDatabaseTab(DatabaseWidget* dbWidget, bool inBackground = false);
    bool closeDatabaseTab(int index);
    bool closeDatabaseTab(DatabaseWidget* dbWidget);
    bool closeAllDatabaseTabs();
    bool closeCurrentDatabaseTab();
    bool closeDatabaseTabFromSender();
    void updateTabName(int index = -1);

    DatabaseWidget* newDatabase();
    void openDatabase();
#ifdef KPXC_FEATURE_NETWORK
    void openWebDav();
    void updateWebDavCredentials();
    void forgetWebDavCredentials();
#endif
    void mergeDatabase();
    void importFile();
    bool saveDatabase(int index = -1);
    bool saveDatabaseAs(int index = -1);
    bool saveDatabaseBackup(int index = -1);
    void exportToCsv();
    void exportToHtml();
    void exportToXML();

    bool lockDatabases();
    void lockDatabasesDelayed();
    void lockDatabasesOnUserSwitch();
    void closeDatabaseFromSender();
    void unlockDatabaseInDialog(DatabaseWidget* dbWidget, DatabaseOpenDialog::Intent intent);
    void unlockDatabaseInDialog(DatabaseWidget* dbWidget, DatabaseOpenDialog::Intent intent, const QString& filePath);
    void unlockDatabaseInDialogForSync(const QString& filePath);
    void unlockAnyDatabaseInDialog(DatabaseOpenDialog::Intent intent);
    void relockPendingDatabase();

    void showDatabaseReports(bool state);
    void showDatabaseSettings(bool state);
    void showDatabaseSecurity();
#ifdef KPXC_FEATURE_BROWSER
    void showPasskeys();
    void importPasskey();
    void importPasskeyToEntry();
    void removePasskeyFromEntry();
#endif
    void performGlobalAutoType(const QString& search);
    void performBrowserUnlock();

signals:
    void databaseOpened(DatabaseWidget* dbWidget);
    void databaseClosed(const QString& filePath);
    void databaseUnlocked(DatabaseWidget* dbWidget);
    void databaseLocked(DatabaseWidget* dbWidget);
    void activeDatabaseChanged(DatabaseWidget* dbWidget);
    void tabNameChanged();
    void tabVisibilityChanged(bool tabsVisible);
    void messageGlobal(const QString&, MessageWidget::MessageType type);
    void messageDismissGlobal();
    void databaseUnlockDialogFinished(bool accepted, DatabaseWidget* dbWidget);

private slots:
    void toggleTabbar();
    void emitActiveDatabaseChanged();
    void emitDatabaseLockChanged();
    void handleDatabaseUnlockDialogFinished(bool accepted, DatabaseWidget* dbWidget);
    void handleExportError(const QString& reason);

private:
    QSharedPointer<Database> execNewDatabaseWizard();
    void updateLastDatabases(DatabaseWidget* widget);
#ifdef KPXC_FEATURE_NETWORK
    struct WebDavConnection
    {
        WebDavSession* session = nullptr;
        QPointer<DatabaseWidget> widget;
        QPointer<WebDavDialog> dialog;
        QMetaObject::Connection rememberLogin;
        QString user;
        quint64 loginRevision = 0;
        bool ready = false;
    };
    void startWebDav(const QString& reference, WebDavDialog* login, bool inBackground);
    void attachWebDav(WebDavSession* session, bool inBackground);
    void enterWebDavLogin(WebDavSession* session);
    void applyWebDavLogin(WebDavSession* session, WebDavDialog* dialog);
    void releaseWebDav(const QString& reference);
    template <typename Operation, typename Callback>
    void runWebDavCredentialTask(WebDavSession* session, Operation operation, Callback completed);

    QHash<QString, WebDavConnection> m_webDavConnections;
    QPointer<WebDavDialog> m_webDavOpenDialog;
#endif
    bool warnOnExport();
    void displayUnlockDialog();

    QPointer<DatabaseWidgetStateSync> m_dbWidgetStateSync;
    QPointer<DatabaseWidget> m_dbWidgetPendingLock;
    QPointer<DatabaseOpenDialog> m_databaseOpenDialog;
    QPointer<ImportWizard> m_importWizard;
    QTimer m_lockDelayTimer;
    bool m_databaseOpenInProgress;
    QSet<DatabaseWidget*> m_widgetsPendingClose;
};

#endif // KEEPASSXC_DATABASETABWIDGET_H
