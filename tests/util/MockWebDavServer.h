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
#include <QTcpServer>
#include <QUrl>

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

    QByteArray contents;
    QByteArray etag = "\"1\"";
    QByteArray password;
    bool pauseUpload = false;
    bool omitUploadEtag = false;
    bool rejectConditionalWrites = false;
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
            const auto method = lines.first().split(' ').first();
            if (!password.isEmpty() && headers.value("authorization") != "Basic " + ("alice:" + password).toBase64()) {
                respond(socket, "401 Unauthorized", {}, "WWW-Authenticate: Basic realm=\"WebDAV test\"\r\n");
            } else if (method == "GET" || method == "HEAD") {
                respond(socket, "200 OK", method == "GET" ? contents : QByteArray(), etagHeader());
            } else if (method == "PUT") {
                preconditions.append(headers.value("if-match"));
                if (rejectConditionalWrites || etag.isEmpty() || preconditions.last() != etag) {
                    respond(socket, "412 Precondition Failed");
                    return;
                }
                contents = buffer.mid(offset + 4, length);
                uploaded.append(contents);
                etag = "\"" + QByteArray::number(++version) + "\"";
                if (pauseUpload) {
                    pausedSocket = socket;
                } else {
                    respond(socket, "204 No Content", {}, omitUploadEtag ? QByteArray() : etagHeader());
                }
            } else {
                respond(socket, "405 Method Not Allowed");
            }
        });
        socket->startServerEncryption();
    }

private:
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
