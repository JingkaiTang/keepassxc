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

#ifndef KEEPASSXC_MOCKWEBDAVSERVER_H
#define KEEPASSXC_MOCKWEBDAVSERVER_H

#include "config-keepassx-tests.h"

#include <QFile>
#include <QHash>
#include <QPointer>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTemporaryDir>
#include <QUrl>
#include <functional>

// Qt test mode always uses ~/.qttest on Linux, even with an isolated XDG_DATA_HOME.
class WebDavTestStorage
{
public:
    WebDavTestStorage()
    {
#ifdef Q_OS_LINUX
        qputenv("XDG_DATA_HOME", directory.path().toUtf8());
        QStandardPaths::setTestModeEnabled(false);
#else
        QStandardPaths::setTestModeEnabled(true);
#endif
    }
    ~WebDavTestStorage()
    {
#ifdef Q_OS_LINUX
        if (previousDataHome.isNull()) {
            qunsetenv("XDG_DATA_HOME");
        } else {
            qputenv("XDG_DATA_HOME", previousDataHome);
        }
#endif
        QStandardPaths::setTestModeEnabled(previousMode);
    }

private:
    const bool previousMode = QStandardPaths::isTestModeEnabled();
#ifdef Q_OS_LINUX
    QTemporaryDir directory;
    const QByteArray previousDataHome = qgetenv("XDG_DATA_HOME");
#endif
};

// A loopback-only HTTPS resource with optimistic concurrency and optional Basic authentication.
class MockWebDavServer : public QTcpServer
{
public:
    bool start(quint16 port = 0)
    {
        return listen(QHostAddress::LocalHost, port);
    }

    QUrl url() const
    {
        return QUrl(QStringLiteral("https://127.0.0.1:%1/vault.kdbx").arg(serverPort()));
    }

    static QSslConfiguration trustedConfiguration()
    {
        auto config = QSslConfiguration::defaultConfiguration();
        config.setCaCertificates({QSslCertificate(fixture("test-ca.pem"))});
        return config;
    }

    void releaseUpload()
    {
        pauseUpload = false;
        if (pausedSocket) {
            respond(pausedSocket, "204 No Content", {}, etagHeader());
            pausedSocket.clear();
        }
    }

    void releaseRead()
    {
        holdRead = false;
        if (heldRead) {
            respond(heldRead, "200 OK", heldContents, heldTag);
            heldRead.clear();
        }
    }

    QByteArray contents;
    bool holdRead = false;
    QPointer<QSslSocket> heldRead;
    QByteArray etag = "\"1\"";
    QByteArray password;
    QList<QByteArray> reads;
    QList<QByteArray> ifNoneMatch;
    int downloaded = 0;
    QByteArray headTag;
    bool rateLimited = false;
    std::function<void(const QByteArray&)> beforePut;
    bool pauseUpload = false;
    bool omitUploadEtag = false;
    QByteArray uploadEtagOverride;
    bool rejectConditionalWrites = false;
    bool ignoreStaleProbe = false;
    int probeCreates = 0;
    int probeDeletes = 0;
    QList<QByteArray> probeMatches;
    bool supportsLock = false;
    bool sharedLock = false;
    bool locked = false;
    int locks = 0;
    int unlocks = 0;
    int lockedReads = 0;
    QList<QByteArray> putLocks;
    const QByteArray token = "<opaquelocktoken:local-test>";
    QList<QByteArray> uploaded;
    QList<QByteArray> preconditions;

protected:
    void incomingConnection(qintptr descriptor) override
    {
        auto* socket = new QSslSocket(this);
        socket->setLocalCertificate(QSslCertificate(fixture("test-cert.pem")));
        socket->setPrivateKey(QSslKey(fixture("test-key.pem"), QSsl::Rsa));
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        if (!socket->setSocketDescriptor(descriptor)) {
            delete socket;
            return;
        }
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QSslSocket::readyRead, this, [this, socket, buffer = QByteArray()]() mutable {
            buffer += socket->readAll();
            const auto offset = buffer.indexOf("\r\n\r\n");
            if (offset < 0) {
                return;
            }

            const auto lines = buffer.left(offset).split('\n');
            QHash<QByteArray, QByteArray> headers;
            for (const auto& line : lines) {
                const auto colon = line.indexOf(':');
                if (colon > 0) {
                    headers.insert(line.left(colon).toLower(), line.mid(colon + 1).trimmed());
                }
            }
            const auto length = headers.value("content-length").toLongLong();
            if (buffer.size() - offset - 4 < length) {
                return;
            }
            const auto request = lines.first().split(' ');
            const auto method = request.first();
            const auto path = request.value(1);
            const auto body = buffer.mid(offset + 4, length);
            if (!password.isEmpty() && headers.value("authorization") != "Basic " + ("alice:" + password).toBase64()) {
                respond(socket, "401 Unauthorized", {}, "WWW-Authenticate: Basic realm=\"WebDAV test\"\r\n");
            } else if (path.contains("/keepassxc-write-test-")) {
                handleProbe(socket, method, path, headers, body);
            } else if (method == "LOCK" && supportsLock) {
                if (locked || headers.value("if-match") != "*" || headers.value("depth") != "0") {
                    respond(socket, "423 Locked");
                    return;
                }
                locked = true;
                ++locks;
                const QByteArray scope = sharedLock ? "<d:shared/>" : "<d:exclusive/>";
                const auto xml = "<d:prop xmlns:d=\"DAV:\"><d:lockdiscovery><d:activelock><d:lockscope>" + scope
                    + "</d:lockscope><d:locktype><d:write/></d:locktype><d:locktoken><d:href>"
                    + token.mid(1, token.size() - 2) + "</d:href></d:locktoken></d:activelock></d:lockdiscovery></d:prop>";
                respond(socket, "200 OK", xml, "Lock-Token: " + token + "\r\n");
            } else if (method == "UNLOCK" && locked && headers.value("lock-token") == token) {
                locked = false;
                ++unlocks;
                respond(socket, "204 No Content");
            } else if (method == "GET" || method == "HEAD") {
                if (locked && headers.value("if") == '(' + token + ')') {
                    ++lockedReads;
                }
                reads.append(method);
                ifNoneMatch.append(headers.value("if-none-match"));
                if (rateLimited) {
                    respond(socket, "429 Too Many Requests", {}, "Retry-After: 120\r\n");
                } else if (holdRead && method == "GET") {
                    heldRead = socket;
                    heldContents = contents;
                    heldTag = etagHeader();
                } else if (method == "HEAD" && !headTag.isEmpty()) {
                    respond(socket, "200 OK", {}, "ETag: " + headTag + "\r\n");
                } else if (!etag.isEmpty() && headers.value("if-none-match") == etag) {
                    respond(socket, "304 Not Modified", {}, etagHeader());
                } else {
                    downloaded += method == "GET";
                    respond(socket, "200 OK", method == "GET" ? contents : QByteArray(), etagHeader());
                }
            } else if (method == "PUT") {
                if (beforePut) {
                    beforePut(headers.value("if-match"));
                }
                preconditions.append(headers.value("if-match"));
                putLocks.append(headers.value("if"));
                if (rejectConditionalWrites || etag.isEmpty() || preconditions.last() != etag
                    || (supportsLock && (!locked || putLocks.last() != '(' + token + ')'))) {
                    respond(socket, "412 Precondition Failed");
                    return;
                }
                contents = buffer.mid(offset + 4, length);
                uploaded.append(contents);
                if (!etag.startsWith("W/")) {
                    const auto next = QByteArray::number(++version);
                    etag = etag.startsWith('"') ? '"' + next + '"' : next;
                }
                if (pauseUpload) {
                    pausedSocket = socket;
                } else {
                    const auto tag = uploadEtagOverride.isEmpty() ? etagHeader() : "ETag: " + uploadEtagOverride + "\r\n";
                    respond(socket, "204 No Content", {}, omitUploadEtag ? QByteArray() : tag);
                }
            } else {
                respond(socket, "405 Method Not Allowed");
            }
        });
        socket->startServerEncryption();
    }

private:
    void handleProbe(QSslSocket* socket, const QByteArray& method, const QByteArray& path,
                     const QHash<QByteArray, QByteArray>& headers, const QByteArray& body)
    {
        if (method == "PUT" && headers.value("if-none-match") == "*" && probePath.isEmpty()) {
            ++probeCreates;
            probePath = path;
            probeBody = body;
            probeVersion = 1;
            respond(socket, "201 Created");
        } else if (probePath != path) {
            respond(socket, "404 Not Found");
        } else if (method == "GET") {
            respond(socket, "200 OK", probeBody, "ETag: test-" + QByteArray::number(probeVersion) + "\r\n");
        } else if (method == "PUT") {
            probeMatches.append(headers.value("if-match"));
            if (probeMatches.last() != "test-" + QByteArray::number(probeVersion) && !ignoreStaleProbe) {
                respond(socket, "412 Precondition Failed");
                return;
            }
            probeBody = body;
            ++probeVersion;
            respond(socket, "204 No Content");
        } else if (method == "DELETE") {
            ++probeDeletes;
            probePath.clear();
            respond(socket, "204 No Content");
        } else {
            respond(socket, "405 Method Not Allowed");
        }
    }

    QByteArray heldContents;
    QByteArray heldTag;
    QByteArray probePath;
    QByteArray probeBody;
    int probeVersion = 0;

    static QByteArray fixture(const QString& name)
    {
        QFile file(QStringLiteral(KEEPASSX_TEST_DATA_DIR "/webdav/") + name);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    }

    QByteArray etagHeader() const
    {
        return etag.isEmpty() ? QByteArray() : "ETag: " + etag + "\r\n";
    }

    static void
    respond(QSslSocket* socket, const QByteArray& status, const QByteArray& body = {}, const QByteArray& headers = {})
    {
        socket->write("HTTP/1.1 " + status + "\r\n" + headers
                      + "Connection: close\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" + body);
        socket->disconnectFromHost();
    }

    QPointer<QSslSocket> pausedSocket;
    int version = 1;
};

#endif // KEEPASSXC_MOCKWEBDAVSERVER_H
