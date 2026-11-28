/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPASSXC_TESTWEBDAVSESSION_H
#define KEEPASSXC_TESTWEBDAVSESSION_H

#include <QObject>
#include <QSslConfiguration>

class TestWebDavSession : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void connectionReferences();
    void recentDisplayNames();
    void consecutiveSaves();
    void backgroundChecks_data();
    void backgroundChecks();
    void legacyCache_data();
    void legacyCache();
    void rateLimitedCheck();
    void lockedUploadRetries();
    void conflictAndMerge_data();
    void conflictAndMerge();
    void offlineRecovery();
    void interruptedUpload();
    void interruptedRefresh();
    void readOnly_data();
    void readOnly();
    void bareWrites_data();
    void bareWrites();
    void rateLimitedBareVerification();
    void weakWrites_data();
    void weakWrites();
    void renewCredentials();
    void anonymousReadDoesNotVerifyLogin();
    void uploadWithoutEtag();
    void rejectedValidator();
    void editCredentialsDuringUpload();

private:
    QSslConfiguration m_originalTls;
    QByteArray m_original;
    QByteArray m_changed;
    QByteArray m_remote;
};

#endif // KEEPASSXC_TESTWEBDAVSESSION_H
