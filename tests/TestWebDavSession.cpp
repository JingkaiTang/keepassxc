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

#include "TestWebDavSession.h"

#include "networking/WebDavSession.h"
#include "util/MockWebDavServer.h"

#include <QDir>
#include <QSaveFile>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTest>
#include <QUuid>

QTEST_GUILESS_MAIN(TestWebDavSession)

namespace
{
    QByteArray readFile(const QString& path)
    {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    }

    bool commitLocalSave(const QString& path, const QByteArray& contents)
    {
        QSaveFile file(path);
        return file.open(QIODevice::WriteOnly) && file.write(contents) == contents.size() && file.commit();
    }
}

void TestWebDavSession::initTestCase()
{
    // Keep manifests, lock files and working copies separate even for concurrent test runs.
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setApplicationName("kpxc-test-webdav-" + QUuid::createUuid().toString(QUuid::WithoutBraces));
    m_originalTls = QSslConfiguration::defaultConfiguration();
    QSslConfiguration::setDefaultConfiguration(MockWebDavServer::trustedConfiguration());
    QVERIFY2(QSslSocket::supportsSsl(), "The HTTPS tests require a TLS-enabled Qt Network backend");
    m_original = readFile(QStringLiteral(KEEPASSX_TEST_DATA_DIR "/NewDatabase.kdbx"));
    m_changed = readFile(QStringLiteral(KEEPASSX_TEST_DATA_DIR "/NewDatabase2.kdbx"));
    m_remote = readFile(QStringLiteral(KEEPASSX_TEST_DATA_DIR "/SyncDatabase.kdbx"));
    QVERIFY(!m_original.isEmpty());
    QVERIFY(!m_changed.isEmpty());
    QVERIFY(!m_remote.isEmpty());
}

void TestWebDavSession::cleanupTestCase()
{
    QSslConfiguration::setDefaultConfiguration(m_originalTls);
    QDir dataDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
    QCOMPARE(dataDir.dirName(), QCoreApplication::applicationName());
    QVERIFY(dataDir.removeRecursively());
}

void TestWebDavSession::connectionReferences()
{
    const QUrl url("https://vault.test/shared/Passwords.kdbx");
    QVERIFY(WebDavSession::isValidUrl(url));
    const auto reference = WebDavSession::referenceFor(url, "alice");
    QVERIFY(WebDavSession::isReference(reference));
    QCOMPARE(WebDavSession::referenceFor(url, "alice"), reference);
    QVERIFY(reference != WebDavSession::referenceFor(url, "bob"));
    QVERIFY(reference != WebDavSession::referenceFor(QUrl("https://vault.test:444/shared/Passwords.kdbx"), "alice"));
    QVERIFY(!WebDavSession::isReference("kpxc-webdav:../another-file"));
    for (const auto& badUrl : {"http://vault.test/db.kdbx", "https://user:pw@vault.test/db.kdbx",
                               "https://vault.test/db.kdbx?token=secret", "https://vault.test/db.kdbx#fragment"}) {
        QVERIFY2(!WebDavSession::isValidUrl(QUrl(badUrl)), badUrl);
    }
}

void TestWebDavSession::consecutiveSaves()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.pauseUpload = true;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QCOMPARE(readFile(session.localPath()), m_original);
    QCOMPARE(WebDavSession::savedUrl(session.reference()), server.url());
    const QString synced = session.statusText();

    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_COMPARE(server.uploaded.size(), 1);
    QVERIFY(session.statusText() != synced);
    // While the first PUT response is withheld, two more atomic saves replace the working copy.
    QVERIFY(commitLocalSave(session.localPath(), m_original));
    session.localSaved();
    QVERIFY(commitLocalSave(session.localPath(), m_remote));
    session.localSaved();
    server.releaseUpload();
    QTRY_COMPARE(server.contents, m_remote);
    QTRY_COMPARE(session.statusText(), synced);
    QCOMPARE(server.uploaded, QList<QByteArray>({m_changed, m_remote}));
    QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\"", "\"2\""}));
}

void TestWebDavSession::conflictAndMerge()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);

    server.contents = m_remote;
    server.etag = "\"phone\"";
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_VERIFY(session.hasConflict());
    QCOMPARE(readFile(session.localPath()), m_changed);
    QCOMPARE(server.contents, m_remote);
    QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\""}));

    QSignalSpy mergeReady(&session, &WebDavSession::mergeReady);
    session.fetchForMerge();
    QTRY_COMPARE(mergeReady.count(), 1);
    QCOMPARE(readFile(mergeReady.first().first().toString()), m_remote);
    QCOMPARE(readFile(session.localPath()), m_changed);
    QVERIFY(commitLocalSave(session.localPath(), m_original)); // stand-in for a committed KDBX merge
    session.localSaved();
    QVERIFY(session.acceptMergeBase());
    QTRY_COMPARE(server.contents, m_original);
    QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\"", "\"phone\""}));
}

void TestWebDavSession::offlineRecovery()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    const auto url = server.url();
    const auto port = server.serverPort();
    const auto reference = WebDavSession::referenceFor(url, "alice");
    {
        WebDavSession session(reference, url);
        session.setCredentials("alice", {});
        QSignalSpy ready(&session, &WebDavSession::ready);
        session.open();
        QTRY_COMPARE(ready.count(), 1);
        server.close();
        // Process exited between local file commit and notification to the background uploader.
        QVERIFY(commitLocalSave(session.localPath(), m_changed));
    }
    WebDavSession session(reference, {});
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QCOMPARE(readFile(session.localPath()), m_changed);
    QCOMPARE(server.contents, m_original);
    QVERIFY(server.start(port));
    session.retry();
    QTRY_COMPARE(server.contents, m_changed);
    QCOMPARE(server.preconditions.last(), "\"1\"");
}

void TestWebDavSession::interruptedUpload()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.pauseUpload = true;
    const auto reference = WebDavSession::referenceFor(server.url(), "alice");
    {
        WebDavSession session(reference, server.url());
        session.setCredentials("alice", {});
        QSignalSpy ready(&session, &WebDavSession::ready);
        session.open();
        QTRY_COMPARE(ready.count(), 1);

        QVERIFY(commitLocalSave(session.localPath(), m_changed));
        session.localSaved();
        QTRY_COMPARE(server.contents, m_changed);
        // The server committed the first upload, but its response has not reached the client.
        QVERIFY(commitLocalSave(session.localPath(), m_remote));
        session.localSaved();
    }
    server.releaseUpload();

    WebDavSession reopened(reference, {});
    reopened.setCredentials("alice", {});
    QSignalSpy ready(&reopened, &WebDavSession::ready);
    reopened.open();
    QTRY_COMPARE(ready.count(), 1);
    QTRY_COMPARE(server.contents, m_remote);
    QVERIFY(!reopened.hasConflict());
    QCOMPARE(server.uploaded, QList<QByteArray>({m_changed, m_remote}));
    QCOMPARE(server.preconditions.last(), "\"2\"");
}

void TestWebDavSession::readOnly_data()
{
    QTest::addColumn<QByteArray>("etag");
    QTest::newRow("missing") << QByteArray();
    QTest::newRow("weak") << QByteArray("W/\"1\"");
}

void TestWebDavSession::readOnly()
{
    QFETCH(QByteArray, etag);
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.etag = etag;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QVERIFY(session.isReadOnly());
    QCOMPARE(readFile(session.localPath()), m_original);
    QCOMPARE(server.preconditions.size(), 0);
}

void TestWebDavSession::renewCredentials()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.password = "old-password";
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", "old-password");
    QSignalSpy ready(&session, &WebDavSession::ready);
    QSignalSpy reauthenticate(&session, &WebDavSession::authenticationRequired);
    session.open();
    QTRY_COMPARE(ready.count(), 1);

    server.password = "new-password";
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_COMPARE(reauthenticate.count(), 1);
    QCOMPARE(server.contents, m_original);
    QCOMPARE(readFile(session.localPath()), m_changed);

    session.setCredentials("alice", "new-password");
    session.retry();
    QTRY_COMPARE(server.contents, m_changed);
    QCOMPARE(ready.count(), 1);
}

void TestWebDavSession::uploadWithoutEtag()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.omitUploadEtag = true;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    const auto synced = session.statusText();

    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_COMPARE(server.contents, m_changed);
    QTRY_COMPARE(session.statusText(), synced);
    QVERIFY(commitLocalSave(session.localPath(), m_remote));
    session.localSaved();
    QTRY_COMPARE(server.contents, m_remote);
    QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\"", "\"2\""}));
}
