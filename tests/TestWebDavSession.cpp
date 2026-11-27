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
} // namespace

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
    for (const auto& badUrl : {"http://vault.test/db.kdbx",
                               "https://user:pw@vault.test/db.kdbx",
                               "https://vault.test/db.kdbx?token=secret",
                               "https://vault.test/db.kdbx#fragment"}) {
        QVERIFY2(!WebDavSession::isValidUrl(QUrl(badUrl)), badUrl);
    }
}

void TestWebDavSession::recentDisplayNames()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    WebDavSession first(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    WebDavSession second(WebDavSession::referenceFor(server.url(), "bob"), server.url());
    const auto missing = WebDavSession::referenceFor(server.url(), "unknown");
    QSignalSpy firstReady(&first, &WebDavSession::ready);
    QSignalSpy secondReady(&second, &WebDavSession::ready);
    first.open();
    second.open();
    QTRY_COMPARE(firstReady.count(), 1);
    QTRY_COMPARE(secondReady.count(), 1);

    QCOMPARE(WebDavSession::recentDisplayNames({first.reference()}).value(first.reference()),
             server.url().toDisplayString());
    auto labels = WebDavSession::recentDisplayNames({first.reference(), second.reference(), missing, "local.kdbx"});
    QVERIFY(labels.value(first.reference()).contains(server.url().toDisplayString()));
    QVERIFY(labels.value(first.reference()) != labels.value(second.reference()));
    QVERIFY(!labels.value(missing).isEmpty());
    QVERIFY(!labels.contains("local.kdbx"));
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

void TestWebDavSession::conflictAndMerge_data()
{
    QTest::addColumn<bool>("fixedWeakTag");
    QTest::newRow("strong version changed") << false;
    QTest::newRow("remote bytes changed under identical weak tag") << true;
}

void TestWebDavSession::conflictAndMerge()
{
    QFETCH(bool, fixedWeakTag);
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    if (fixedWeakTag) {
        server.etag = "W/\"1\"";
        server.supportsLock = true;
    }
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);

    server.contents = m_remote;
    if (!fixedWeakTag) {
        server.etag = "\"phone\"";
    }
    const auto latestTag = server.etag;
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_VERIFY(session.hasConflict());
    QCOMPARE(readFile(session.localPath()), m_changed);
    QCOMPARE(server.contents, m_remote);
    if (fixedWeakTag) {
        QVERIFY(server.preconditions.isEmpty());
        QCOMPARE(server.unlocks, 1);
    } else {
        QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\""}));
    }

    QSignalSpy mergeReady(&session, &WebDavSession::mergeReady);
    session.fetchForMerge();
    QTRY_COMPARE(mergeReady.count(), 1);
    QCOMPARE(readFile(mergeReady.first().first().toString()), m_remote);
    QCOMPARE(readFile(session.localPath()), m_changed);
    QVERIFY(commitLocalSave(session.localPath(), m_original)); // stand-in for a committed KDBX merge
    session.localSaved();
    QVERIFY(session.acceptMergeBase());
    QTRY_COMPARE(server.contents, m_original);
    QTRY_VERIFY(!session.hasPendingUpload());
    QCOMPARE(server.preconditions.last(), latestTag);
    if (fixedWeakTag) {
        QCOMPARE(server.lockedReads, 2);
        QCOMPARE(server.unlocks, 2);
        QCOMPARE(server.preconditions.size(), 1);
    }
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
    QTest::newRow("wildcard") << QByteArray("*");
    QTest::newRow("list") << QByteArray("\"a\", \"b\"");
    QTest::newRow("bare list") << QByteArray("a,b");
    QTest::newRow("broken weak tag") << QByteArray("W/a");
    QTest::newRow("unmatched quote") << QByteArray("\"a");
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

void TestWebDavSession::bareWrites_data()
{
    QTest::addColumn<bool>("ignoresStale");
    QTest::newRow("bare If-Match enforced") << false;
    QTest::newRow("bare If-Match ignored") << true;
}

void TestWebDavSession::bareWrites()
{
    QFETCH(bool, ignoresStale);
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.etag = "bare-1";
    server.uploadEtagOverride = "\"put-response\"";
    server.ignoreStaleProbe = ignoresStale;
    const auto reference = WebDavSession::referenceFor(server.url(), "alice");
    {
        WebDavSession session(reference, server.url());
        session.setCredentials("alice", {});
        QSignalSpy ready(&session, &WebDavSession::ready);
        session.open();
        QTRY_COMPARE(ready.count(), 1);
        QVERIFY(session.isReadOnly());
        QVERIFY(session.canProbeWrites());
        QCOMPARE(server.probeCreates, 0);
        session.probeWrites();
        QTRY_COMPARE(server.probeDeletes, 1);
        QTRY_VERIFY(session.canProbeWrites() || !session.isReadOnly());
        QCOMPARE(session.isReadOnly(), ignoresStale);
        QCOMPARE(server.probeMatches, QList<QByteArray>({"test-1", "test-1"}));
        QCOMPARE(server.contents, m_original);
        QVERIFY(server.preconditions.isEmpty());
        if (ignoresStale) {
            return;
        }
        QVERIFY(commitLocalSave(session.localPath(), m_changed));
        session.localSaved();
        QTRY_COMPARE(server.contents, m_changed);
        QTRY_VERIFY(!session.hasPendingUpload());
        QCOMPARE(server.preconditions, QList<QByteArray>({"bare-1"}));
        // A different PUT response format must not replace the authoritative bare GET tag.
        const auto accepted = server.etag;
        server.contents = m_remote;
        server.etag = "from-phone";
        QVERIFY(commitLocalSave(session.localPath(), m_original));
        session.localSaved();
        QTRY_VERIFY(session.hasConflict());
        QCOMPARE(server.contents, m_remote);
        QCOMPARE(readFile(session.localPath()), m_original);
        QCOMPARE(server.preconditions.last(), accepted);
    }
    const auto checkScope = [](const QUrl& url, const QString& user, bool readOnly) {
        WebDavSession session(WebDavSession::referenceFor(url, user), url);
        session.setCredentials(user, {});
        QSignalSpy ready(&session, &WebDavSession::ready);
        session.open();
        QTRY_COMPARE(ready.count(), 1);
        QCOMPARE(session.isReadOnly(), readOnly);
    };
    checkScope(server.url(), "alice", false);
    checkScope(server.url().resolved(QUrl("sibling.kdbx")), "alice", false);
    checkScope(server.url(), "bob", true);
    checkScope(server.url().resolved(QUrl("other/vault.kdbx")), "alice", true);
    QCOMPARE(server.probeCreates, 1);
}

void TestWebDavSession::weakWrites_data()
{
    QTest::addColumn<bool>("supportsLock");
    QTest::addColumn<bool>("shared");
    QTest::addColumn<bool>("rejectsMatch");
    QTest::newRow("exclusive lock and weak If-Match") << true << false << false;
    QTest::newRow("server rejects weak If-Match") << true << false << true;
    QTest::newRow("exclusive lock unavailable") << false << false << false;
    QTest::newRow("server grants shared lock") << true << true << false;
}

void TestWebDavSession::weakWrites()
{
    QFETCH(bool, supportsLock);
    QFETCH(bool, shared);
    QFETCH(bool, rejectsMatch);
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.etag = "W/\"opaque,1\"";
    server.supportsLock = supportsLock;
    server.sharedLock = shared;
    server.rejectConditionalWrites = rejectsMatch;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QVERIFY(!session.isReadOnly());
    QCOMPARE(server.locks, 0);
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    if (supportsLock && !shared && !rejectsMatch) {
        QTRY_COMPARE(server.contents, m_changed);
        QTRY_VERIFY(!session.hasPendingUpload());
    } else {
        QTRY_VERIFY(session.isReadOnly());
        QCOMPARE(server.contents, m_original);
        QCOMPARE(readFile(session.localPath()), m_changed);
    }
    QCOMPARE(server.locks, supportsLock ? 1 : 0);
    QCOMPARE(server.unlocks, server.locks);
    QVERIFY(!server.locked);
    if (supportsLock && !shared) {
        QCOMPARE(server.lockedReads, 1);
        QCOMPARE(server.preconditions, QList<QByteArray>({server.etag}));
        QCOMPARE(server.putLocks, QList<QByteArray>({'(' + server.token + ')'}));
    } else {
        QVERIFY(server.preconditions.isEmpty());
    }
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

void TestWebDavSession::anonymousReadDoesNotVerifyLogin()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", "write-password");
    QSignalSpy ready(&session, &WebDavSession::ready);
    QSignalSpy authenticated(&session, &WebDavSession::authenticated);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QCOMPARE(authenticated.count(), 0);

    server.password = "write-password";
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_COMPARE(authenticated.count(), 1);
    QCOMPARE(server.contents, m_changed);
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

void TestWebDavSession::rejectedValidator()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.rejectConditionalWrites = true;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", {});
    QSignalSpy ready(&session, &WebDavSession::ready);
    session.open();
    QTRY_COMPARE(ready.count(), 1);
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_VERIFY(session.isReadOnly());
    QCOMPARE(readFile(session.localPath()), m_changed);
    QCOMPARE(server.contents, m_original);
    QCOMPARE(server.preconditions, QList<QByteArray>({"\"1\""}));
}

void TestWebDavSession::editCredentialsDuringUpload()
{
    MockWebDavServer server;
    QVERIFY(server.start());
    server.contents = m_original;
    server.password = "correct";
    server.pauseUpload = true;
    WebDavSession session(WebDavSession::referenceFor(server.url(), "alice"), server.url());
    session.setCredentials("alice", "correct");
    QSignalSpy authenticated(&session, &WebDavSession::authenticated);
    QSignalSpy rejected(&session, &WebDavSession::authenticationRequired);
    session.open();
    QTRY_COMPARE(authenticated.count(), 1);
    authenticated.clear();
    QVERIFY(commitLocalSave(session.localPath(), m_changed));
    session.localSaved();
    QTRY_COMPARE(server.contents, m_changed);

    // A response to the previous login must never validate an unverified replacement password.
    session.setCredentials("alice", "typo");
    server.releaseUpload();
    QTRY_COMPARE(rejected.count(), 1);
    QCOMPARE(authenticated.count(), 0);
}
