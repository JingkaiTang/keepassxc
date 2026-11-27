// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 KeePassXC Team

#include "WebDavWrite.h"

#include <QAuthenticator>
#include <QBuffer>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QScopeGuard>
#include <algorithm>
#include <QUuid>
#include <QXmlStreamReader>

namespace WebDavWrite
{
    Kind kind(const QByteArray& tag)
    {
        if (tag.isEmpty()) {
            return Kind::Invalid;
        }
        if (tag.startsWith("W/\"")) {
            return Kind::Weak;
        }
        return tag.startsWith('"') ? Kind::Strong : Kind::Bare;
    }

    QByteArray parseTag(QByteArray tag)
    {
        // Remove HTTP optional whitespace only. Never turn a list or wildcard into a write condition.
        while (tag.startsWith(' ') || tag.startsWith('\t')) {
            tag.remove(0, 1);
        }
        while (tag.endsWith(' ') || tag.endsWith('\t')) {
            tag.chop(1);
        }
        if (tag.isEmpty() || tag == "*") {
            return {};
        }
        const bool weak = tag.startsWith("W/");
        const bool quoted = weak || tag.startsWith('"');
        const int start = weak ? 3 : 1;
        if (quoted && (tag.size() < start + 1 || tag.at(start - 1) != '"' || !tag.endsWith('"'))) {
            return {};
        }
        for (qsizetype i = quoted ? start : 0; i < tag.size() - (quoted ? 1 : 0); ++i) {
            const auto c = static_cast<unsigned char>(tag.at(i));
            if (c < 0x21 || c == '"' || c == 0x7f || (!quoted && (c == ',' || c == '*' || c >= 0x80))) {
                return {};
            }
        }
        return tag;
    }
}

namespace
{
    using namespace WebDavWrite;
    using Headers = QList<QPair<QByteArray, QByteArray>>;

    struct Response
    {
        int status;
        QByteArray tag;
        QByteArray token;
        QByteArray body;
        QByteArray hash;
        bool ok() const { return status >= 200 && status < 300; }
    };

    // Sequential DAV requests on one resource, with the same TLS and redirect rules as the main session.
    class Resource
    {
    public:
        Resource(const Connection& login, const QUrl& url)
            : m_url(url)
        {
            m_network.setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
            QObject::connect(&m_network, &QNetworkAccessManager::authenticationRequired, &m_network,
                             [this, &login](QNetworkReply* reply, QAuthenticator* auth) {
                                 if (reply->url() == m_url && !reply->property("triedLogin").toBool()) {
                                     reply->setProperty("triedLogin", true);
                                     auth->setUser(login.user);
                                     auth->setPassword(login.password);
                                 }
                             });
        }

        Response send(const QByteArray& method, const Headers& headers = {}, QIODevice* upload = nullptr,
                      bool hashBody = false)
        {
            QNetworkRequest request(m_url);
            request.setTransferTimeout(30000);
            request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
            request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KeePassXC"));
            for (const auto& header : headers) {
                request.setRawHeader(header.first, header.second);
            }
            if (method == "PUT") {
                request.setRawHeader("Content-Type", "application/octet-stream");
            }
            std::unique_ptr<QNetworkReply> reply(method == "PUT" ? m_network.put(request, upload)
                                                                  : m_network.sendCustomRequest(request, method, upload));
            reply->setReadBufferSize(64 * 1024);
            QByteArray body;
            QCryptographicHash hash(QCryptographicHash::Sha256);
            auto drain = [&] {
                while (reply->bytesAvailable() > 0) {
                    const auto data = reply->read(64 * 1024);
                    if (data.isEmpty()) {
                        break;
                    }
                    if (hashBody) {
                        hash.addData(data);
                    } else if (body.size() + data.size() <= 64 * 1024) {
                        body.append(data);
                    } else {
                        reply->abort();
                        break;
                    }
                }
            };
            QEventLoop loop;
            QObject::connect(reply.get(), &QIODevice::readyRead, &loop, drain);
            QObject::connect(reply.get(), &QNetworkReply::finished, &loop, &QEventLoop::quit);
            if (!reply->isFinished()) {
                loop.exec();
            }
            drain();
            auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (reply->error() != QNetworkReply::NoError && status < 400) {
                status = 0;
            }
            authenticated |= reply->property("triedLogin").toBool() && status >= 200 && status < 300;
            return {status, parseTag(reply->rawHeader("ETag")), reply->rawHeader("Lock-Token"), body, hash.result()};
        }

        Response sendBytes(const QByteArray& method, const Headers& headers, QByteArray data)
        {
            QBuffer buffer(&data);
            buffer.open(QIODevice::ReadOnly);
            return send(method, headers, &buffer);
        }

        bool authenticated = false;

    private:
        QUrl m_url;
        QNetworkAccessManager m_network;
    };

    bool validLockToken(const QByteArray& token)
    {
        if (!token.startsWith('<') || !token.endsWith('>')) {
            return false;
        }
        const auto uri = token.mid(1, token.size() - 2);
        const auto parsed = QUrl::fromEncoded(uri, QUrl::StrictMode);
        return parsed.isValid() && !parsed.scheme().isEmpty()
               && std::all_of(uri.cbegin(), uri.cend(), [](unsigned char c) {
                      return c > 0x20 && c < 0x7f && c != '<' && c != '>';
                  });
    }

    bool confirmsExclusiveLock(const QByteArray& body, const QByteArray& token)
    {
        QXmlStreamReader xml(body);
        QStringList path;
        bool exclusive = false, write = false, matches = false, confirmed = false;
        while (!xml.atEnd()) {
            xml.readNext();
            if (xml.isStartElement()) {
                path.append(xml.namespaceUri() == QStringLiteral("DAV:") ? xml.name().toString() : QString());
                if (path == QStringList{"prop", "lockdiscovery", "activelock"}) {
                    exclusive = write = matches = false;
                } else if (path == QStringList{"prop", "lockdiscovery", "activelock", "lockscope", "exclusive"}) {
                    exclusive = true;
                } else if (path == QStringList{"prop", "lockdiscovery", "activelock", "locktype", "write"}) {
                    write = true;
                } else if (path == QStringList{"prop", "lockdiscovery", "activelock", "locktoken", "href"}) {
                    matches = xml.readElementText().trimmed().toUtf8() == token.mid(1, token.size() - 2);
                    path.removeLast();
                }
            } else if (xml.isEndElement()) {
                if (path == QStringList{"prop", "lockdiscovery", "activelock"}) {
                    confirmed |= exclusive && write && matches;
                }
                path.removeLast();
            } else if (xml.isDTD()) {
                return false;
            }
        }
        return !xml.hasError() && confirmed;
    }

    LockedResult failure(int status)
    {
        if (status == 401) {
            return {Outcome::Authenticate, status, {}};
        }
        if (status == 0 || status == 408 || status == 423 || status == 429 || status >= 500) {
            return {Outcome::Retry, status, {}};
        }
        return {Outcome::Error, status, {}};
    }
}

WebDavWrite::ProbeResult WebDavWrite::probeBare(const Connection& connection)
{
    const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const auto filename = QStringLiteral("keepassxc-write-test-%1.kdbx").arg(id);
    const QUrl url = connection.url.adjusted(QUrl::RemoveFilename).resolved(QUrl(filename));
    Resource resource(connection, url);
    const QByteArray a = id.toUtf8() + "/1", b = id.toUtf8() + "/2", c = id.toUtf8() + "/3";
    if (*connection.canceled || resource.send("GET").status != 404 || *connection.canceled) {
        return {};
    }
    const auto created = resource.sendBytes("PUT", {{"If-None-Match", "*"}}, a);
    if (created.status == 412) {
        return {};
    }
    const auto first = resource.send("GET");
    if (first.status == 404) {
        return {};
    }
    bool passed = false;
    if (created.ok() && first.status == 200 && first.body == a && kind(first.tag) == Kind::Bare && !*connection.canceled) {
        const auto current = resource.sendBytes("PUT", {{"If-Match", first.tag}}, b);
        const auto second = resource.send("GET");
        if (current.ok() && second.status == 200 && second.body == b && kind(second.tag) == Kind::Bare
            && first.tag != second.tag && !*connection.canceled) {
            const auto stale = resource.sendBytes("PUT", {{"If-Match", first.tag}}, c);
            const auto last = resource.send("GET");
            passed = stale.status == 412 && last.status == 200 && last.body == b && last.tag == second.tag;
        }
    }
    // A lost create/PUT response may still have committed. Only remove our own random marker.
    const auto owned = resource.send("GET");
    if (owned.status != 200 || (owned.body != a && owned.body != b && owned.body != c)) {
        return {false, owned.status == 404 ? QString() : filename};
    }
    Headers cleanupHeaders;
    if (!owned.tag.isEmpty()) {
        cleanupHeaders.append({"If-Match", owned.tag});
    }
    const auto removed = resource.send("DELETE", cleanupHeaders);
    if ((!removed.ok() && removed.status != 404) || resource.send("GET").status != 404) {
        return {false, filename};
    }
    return {passed, {}};
}

WebDavWrite::LockedResult WebDavWrite::writeLocked(const Connection& connection, const QString& snapshot,
                                                   const QByteArray& baseHash)
{
    const auto removeSnapshot = qScopeGuard([&] { QFile::remove(snapshot); });
    QFile file(snapshot);
    if (!file.open(QIODevice::ReadOnly) || *connection.canceled) {
        return {Outcome::Error, 0, {}};
    }
    Resource resource(connection, connection.url);
    const auto lock = resource.sendBytes("LOCK", {{"Depth", "0"}, {"Timeout", "Second-120"}, {"If-Match", "*"},
                                                  {"Content-Type", "application/xml; charset=utf-8"}},
        "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>"
        "<D:locktype><D:write/></D:locktype></D:lockinfo>");
    if (!lock.ok()) {
        if (lock.status == 405 || lock.status == 501 || lock.status == 403) {
            return {Outcome::Unsupported, lock.status, {}};
        }
        return failure(lock.status);
    }
    if (!validLockToken(lock.token)) {
        return {Outcome::Unsupported, lock.status, {}};
    }
    const auto putWhileLocked = [&]() -> LockedResult {
        if (lock.status != 200 || !confirmsExclusiveLock(lock.body, lock.token)) {
            return {Outcome::Unsupported, lock.status, {}};
        }
        if (*connection.canceled) {
            return {Outcome::Verify, 0, {}};
        }
        const QByteArray condition = '(' + lock.token + ')';
        const auto remote = resource.send("GET", {{"If", condition}}, nullptr, true);
        if (remote.status != 200) {
            return failure(remote.status);
        }
        if (remote.hash != baseHash || kind(remote.tag) != Kind::Weak || *connection.canceled) {
            return {Outcome::Verify, 0, {}};
        }
        const auto put = resource.send("PUT", {{"If", condition}, {"If-Match", remote.tag}}, &file);
        if (put.status == 412) {
            return {Outcome::Rejected, 412, remote.tag};
        }
        if (put.status == 200 || put.status == 204) {
            return {Outcome::Verify, put.status, {}};
        }
        return failure(put.status);
    };
    auto result = putWhileLocked();
    result.releaseFailed = !resource.send("UNLOCK", {{"Lock-Token", lock.token}}).ok();
    result.authenticated = resource.authenticated;
    return result;
}
