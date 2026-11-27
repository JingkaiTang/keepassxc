/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "WebDavSession.h"
#include "WebDavWrite.h"
#include "format/KeePass2.h"

#include <QAuthenticator>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QtConcurrentRun>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QtEndian>

namespace
{
    const QString prefix = QStringLiteral("kpxc-webdav:");
    constexpr auto privateFile = QFile::ReadOwner | QFile::WriteOwner;
    constexpr auto privateDirectory = privateFile | QFile::ExeOwner;

    QString directoryFor(const QString& reference)
    {
        if (!WebDavSession::isReference(reference)) {
            return {};
        }
        const auto root = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        return root.isEmpty() ? QString() : root + "/webdav/" + reference.mid(prefix.size());
    }

    QJsonObject manifest(const QString& directory)
    {
        QFile file(directory + "/connection.json");
        if (directory.isEmpty() || !file.open(QIODevice::ReadOnly)) {
            return {};
        }
        return QJsonDocument::fromJson(file.read(65536)).object();
    }

    QUrl canonicalUrl(QUrl url)
    {
        if (url.port() == 443) {
            url.setPort(-1);
        }
        return url.adjusted(QUrl::NormalizePathSegments);
    }

    QByteArray databaseHash(QFile& file)
    {
        if (!file.seek(0)) {
            return {};
        }
        const auto header = file.peek(12);
        if (header.size() != 12 || qFromLittleEndian<quint32>(header.constData()) != KeePass2::SIGNATURE_1
            || qFromLittleEndian<quint32>(header.constData() + 4) != KeePass2::SIGNATURE_2) {
            return {};
        }
        const auto version = qFromLittleEndian<quint32>(header.constData() + 8);
        if (version < KeePass2::FILE_VERSION_MIN
            || (version & KeePass2::FILE_VERSION_CRITICAL_MASK) > KeePass2::FILE_VERSION_MAX || file.size() <= 12) {
            return {};
        }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        return hash.addData(&file) ? hash.result() : QByteArray();
    }

    QByteArray databaseHash(const QString& path)
    {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? databaseHash(file) : QByteArray();
    }

    bool copyBytes(QIODevice& from, QIODevice& to)
    {
        QByteArray chunk(128 * 1024, Qt::Uninitialized);
        qint64 count;
        while ((count = from.read(chunk.data(), chunk.size())) > 0) {
            if (to.write(chunk.constData(), count) != count) {
                return false;
            }
        }
        return count == 0;
    }
} // namespace

WebDavSession::WebDavSession(const QString& reference, const QUrl& url, QObject* parent)
    : QObject(parent)
    , m_reference(reference)
    , m_url(url.isEmpty() ? savedUrl(reference) : canonicalUrl(url))
    , m_directory(directoryFor(reference))
{
    m_retryTimer.setSingleShot(true);
    connect(&m_retryTimer, &QTimer::timeout, this, &WebDavSession::retry);
}

WebDavSession::~WebDavSession()
{
    if (m_workerCanceled) {
        *m_workerCanceled = true;
    }
    if (m_reply) {
        disconnect(m_reply, nullptr, this, nullptr);
        m_reply->abort();
        // The upload QIODevice must outlive its reply.
        delete m_reply;
    }
}

bool WebDavSession::isValidUrl(const QUrl& url)
{
    return url.isValid() && url.scheme() == QStringLiteral("https") && !url.host().isEmpty()
           && !url.authority(QUrl::FullyEncoded).contains('@') && !url.hasQuery() && !url.hasFragment()
           && !url.fileName().isEmpty();
}

QString WebDavSession::referenceFor(const QUrl& url, const QString& user)
{
    if (!isValidUrl(url)) {
        return {};
    }
    const auto bytes = canonicalUrl(url).toEncoded() + '\0' + user.toUtf8();
    return prefix + QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
}

bool WebDavSession::isReference(const QString& reference)
{
    if (!reference.startsWith(prefix) || reference.size() != prefix.size() + 64) {
        return false;
    }
    for (auto ch : QStringView(reference).mid(prefix.size())) {
        if (!(ch >= u'0' && ch <= u'9') && !(ch >= u'a' && ch <= u'f')) {
            return false;
        }
    }
    return true;
}

QUrl WebDavSession::savedUrl(const QString& reference)
{
    const auto url = QUrl::fromEncoded(manifest(directoryFor(reference)).value("url").toString().toLatin1());
    return isValidUrl(url) ? url : QUrl();
}

QHash<QString, QString> WebDavSession::recentDisplayNames(const QStringList& references)
{
    QHash<QString, QString> names;
    QHash<QString, int> counts;
    for (const auto& reference : references) {
        if (isReference(reference) && !names.contains(reference)) {
            const auto url = savedUrl(reference).toDisplayString();
            names.insert(reference, url);
            ++counts[url];
        }
    }

    for (auto it = names.begin(); it != names.end(); ++it) {
        const auto connection = it.key().right(8);
        if (it.value().isEmpty()) {
            it.value() = tr("Unavailable WebDAV database (%1)").arg(connection);
        } else if (counts.value(it.value()) > 1) {
            it.value() = tr("%1 (connection %2)").arg(it.value(), connection);
        }
    }
    return names;
}

QString WebDavSession::reference() const
{
    return m_reference;
}
QUrl WebDavSession::url() const
{
    return m_url;
}
QString WebDavSession::localPath() const
{
    return m_directory + "/database.kdbx";
}
QString WebDavSession::statusText() const
{
    return m_status;
}
bool WebDavSession::isReadOnly() const
{
    if (m_baseHash.isEmpty()) {
        return false;
    }
    return m_etag.isEmpty() || m_etag == m_disabledTag
           || (WebDavWrite::kind(m_etag) == WebDavWrite::Kind::Bare && !m_bareVerified);
}

QString WebDavSession::bareProofPath() const
{
    const auto scope = m_url.adjusted(QUrl::RemoveFilename).toEncoded() + '\0' + m_user.toUtf8();
    const auto key = QCryptographicHash::hash(scope, QCryptographicHash::Sha256).toHex();
    return QFileInfo(m_directory).dir().filePath("bare-v1-" + QString::fromLatin1(key));
}

bool WebDavSession::canProbeWrites() const
{
    return m_ready && m_credentialsSet && !m_workerCanceled && !m_reply && !m_bareVerified
           && WebDavWrite::kind(m_etag) == WebDavWrite::Kind::Bare;
}

void WebDavSession::probeWrites()
{
    if (!canProbeWrites()) {
        return;
    }
    m_retryTimer.stop();
    m_workerCanceled = std::make_shared<std::atomic_bool>(false);
    const WebDavWrite::Connection login{m_url, m_user, m_password, m_workerCanceled};
    auto* watcher = new QFutureWatcher<WebDavWrite::ProbeResult>(this);
    connect(watcher, &QFutureWatcherBase::finished, this, [this, watcher] {
        const auto result = watcher->result();
        const auto canceled = m_workerCanceled->load();
        m_workerCanceled.reset();
        watcher->deleteLater();
        if (!result.leftover.isEmpty()) {
            setStatus(tr("Write verification could not clean up the temporary file: %1").arg(result.leftover));
        } else if (canceled) {
            retry();
        } else if (!result.passed) {
            setStatus(tr("Read-only: the server did not pass conditional write verification."));
        } else {
            QSaveFile proof(bareProofPath());
            if (!proof.open(QIODevice::WriteOnly) || proof.write("verified") != 8 || !proof.commit()) {
                setStatus(tr("Could not save the WebDAV synchronization state."));
                return;
            }
            m_bareVerified = true;
            m_disabledTag.clear();
            request(Operation::Verify);
        }
    });
    watcher->setFuture(QtConcurrent::run(WebDavWrite::probeBare, login));
    setStatus(tr("Verifying conditional writes with a temporary file…"));
}
bool WebDavSession::hasConflict() const
{
    return m_conflict;
}
bool WebDavSession::hasPendingUpload() const
{
    return m_dirty || !m_attemptHash.isEmpty();
}

void WebDavSession::setCredentials(const QString& user, const QString& password)
{
    if (m_workerCanceled) {
        *m_workerCanceled = true;
    }
    ++m_credentialsRevision;
    m_credentialsSet = referenceFor(m_url, user) == m_reference;
    m_user = m_credentialsSet ? user : QString();
    m_password = m_credentialsSet ? password : QString();
    m_needsAuth = false;
    QFile proof(bareProofPath());
    m_bareVerified = m_credentialsSet && proof.open(QIODevice::ReadOnly) && proof.read(9) == "verified";
}

bool WebDavSession::prepareCache()
{
    if (!isValidUrl(m_url) || m_directory.isEmpty()) {
        stopWithError(tr("Enter a full HTTPS database URL without credentials, a query or a fragment."));
        return false;
    }
    if (!QDir().mkpath(m_directory) || !QFile::setPermissions(m_directory, privateDirectory)) {
        stopWithError(tr("Could not prepare a private folder for this WebDAV database."));
        return false;
    }
    auto lock = std::make_unique<QLockFile>(m_directory + "/session.lock");
    lock->setStaleLockTime(0);
    if (!lock->tryLock()) {
        stopWithError(tr("This WebDAV database is already in use, or its working folder cannot be locked."));
        return false;
    }
    const auto data = manifest(m_directory);
    if (QFile::exists(m_directory + "/connection.json") && savedUrl(m_reference) != m_url) {
        stopWithError(tr("The saved WebDAV connection is invalid."));
        return false;
    }
    m_lock = std::move(lock);
    // Any files left by an interrupted transfer contain only encrypted database data.
    const QDir directory(m_directory);
    for (const auto& file : directory.entryList({"transfer-*"}, QDir::Files)) {
        QFile::remove(directory.filePath(file));
    }
    m_disabledTag = QByteArray::fromBase64(data.value("disabledTag").toString().toLatin1());
    m_etag = WebDavWrite::parseTag(QByteArray::fromBase64(data.value("etag").toString().toLatin1()));
    m_baseHash = QByteArray::fromHex(data.value("base").toString().toLatin1());
    m_attemptHash = QByteArray::fromHex(data.value("attempt").toString().toLatin1());
    return !data.isEmpty() || record({}, {});
}

bool WebDavSession::record(const QByteArray& etag, const QByteArray& base, const QByteArray& attempt)
{
    QJsonObject state{{"url", QString::fromLatin1(m_url.toEncoded())},
                      {"etag", QString::fromLatin1(etag.toBase64())},
                      {"base", QString::fromLatin1(base.toHex())},
                      {"attempt", QString::fromLatin1(attempt.toHex())}};
    if (!etag.isEmpty() && etag == m_disabledTag) {
        state.insert("disabledTag", QString::fromLatin1(m_disabledTag.toBase64()));
    } else {
        m_disabledTag.clear();
    }
    const auto bytes = QJsonDocument(state).toJson(QJsonDocument::Compact);
    QSaveFile file(m_directory + "/connection.json");
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(privateFile) || file.write(bytes) != bytes.size()
        || !file.commit()) {
        stopWithError(tr("Could not save the WebDAV synchronization state."));
        return false;
    }
    m_etag = etag;
    m_baseHash = base;
    m_attemptHash = attempt;
    return true;
}

void WebDavSession::open()
{
    if (m_reply || m_ready || (!m_lock && !prepareCache())) {
        return;
    }
    const auto localHash = databaseHash(localPath());
    if (QFile::exists(localPath()) && localHash.isEmpty()) {
        stopWithError(tr("The encrypted WebDAV working copy could not be read."));
        return;
    }
    m_dirty = !localHash.isEmpty() && localHash != m_baseHash;
    if (m_dirty || (!localHash.isEmpty() && !m_attemptHash.isEmpty())) {
        setStatus(tr("Saved locally, waiting to sync"));
        publishReady();
        retry();
        return;
    }
    request(Operation::Download);
}

void WebDavSession::retry()
{
    if (m_reply || m_workerCanceled) {
        return;
    }
    m_retryTimer.stop();
    if (!m_lock || !m_ready) {
        open();
    } else if (m_conflict) {
        if (m_operation == Operation::Merge && !m_mergeFile) {
            fetchForMerge();
        } else {
            request(Operation::Verify);
        }
    } else if (!m_attemptHash.isEmpty() || !m_dirty || isReadOnly()) {
        request(Operation::Verify);
    } else {
        request(Operation::Upload);
    }
}

void WebDavSession::localSaved()
{
    if (!m_ready) {
        return;
    }
    m_dirty = true;
    if (!m_reply && !m_workerCanceled && !m_conflict && !m_needsAuth && !isReadOnly()) {
        retry();
    }
}

void WebDavSession::publishReady()
{
    if (!m_ready) {
        m_ready = true;
        emit ready();
    }
}

void WebDavSession::setStatus(const QString& message)
{
    m_status = message;
    emit statusChanged();
}

void WebDavSession::stopWithError(const QString& message)
{
    setStatus(message);
    if (!m_ready) {
        emit failed(message);
    }
}

void WebDavSession::retryLater(const QString& message)
{
    setStatus(message);
    if (!m_ready && !databaseHash(localPath()).isEmpty()) {
        publishReady();
    }
    if (!m_ready) {
        emit failed(message);
    } else {
        m_retryTimer.start(m_retryDelay);
        m_retryDelay = qMin(60000, m_retryDelay * 2);
    }
}

void WebDavSession::prepareNetwork()
{
    if (m_network && m_requestRevision == m_credentialsRevision) {
        return;
    }
    // Reset authentication and connection caches only *after* the old request finishes.
    // Clearing an active manager can close a PUT socket before its response is delivered.
    if (m_network) {
        m_network->deleteLater();
    }
    m_network = new QNetworkAccessManager(this);
    m_requestRevision = m_credentialsRevision;
    m_network->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    connect(m_network,
            &QNetworkAccessManager::authenticationRequired,
            this,
            [this](QNetworkReply* reply, QAuthenticator* auth) {
                if (m_credentialsSet && m_credentialsRevision == m_requestRevision && reply == m_reply
                    && reply->url() == m_url && !reply->property("webDavAuthTried").toBool()) {
                    reply->setProperty("webDavAuthTried", true);
                    auth->setUser(m_user);
                    auth->setPassword(m_password);
                }
            });
}

void WebDavSession::request(Operation operation)
{
    if (m_workerCanceled || (operation == Operation::Upload && isReadOnly())) {
        return;
    }
    m_retryTimer.stop();
    auto transfer = std::make_unique<QTemporaryFile>(m_directory + "/transfer-XXXXXX");
    if (!transfer->open()) {
        stopWithError(tr("Could not create a private WebDAV transfer file."));
        return;
    }
    QNetworkRequest request(m_url);
    request.setTransferTimeout(30000);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KeePassXC"));
    prepareNetwork();
    if (operation == Operation::Upload) {
        QFile local(localPath());
        if (!local.open(QIODevice::ReadOnly) || !copyBytes(local, *transfer) || !transfer->flush()) {
            stopWithError(tr("Could not read the saved database for upload."));
            return;
        }
        const auto hash = databaseHash(*transfer);
        if (hash.isEmpty() || !transfer->seek(0) || m_etag.isEmpty()) {
            stopWithError(tr("The saved database or its remote version could not be verified."));
            return;
        }
        if (hash == m_baseHash) {
            m_dirty = false;
            continueSaving();
            return;
        }
        // Commit the exact identity of this snapshot before the server can see any bytes.
        if (!record(m_etag, m_baseHash, hash)) {
            return;
        }
        request.setRawHeader("If-Match", m_etag);
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/octet-stream"));
        m_dirty = false;
        if (WebDavWrite::kind(m_etag) == WebDavWrite::Kind::Weak) {
            transfer->setAutoRemove(false);
            transfer->close();
            startLockedUpload(transfer->fileName());
            return;
        }
        m_reply = m_network->put(request, transfer.get());
    } else {
        m_reply = m_network->get(request);
    }
    m_operation = operation;
    m_transferFailed = false;
    m_transfer = std::move(transfer);
    m_reply->setReadBufferSize(256 * 1024);
    connect(m_reply, &QNetworkReply::readyRead, this, &WebDavSession::readResponse);
    connect(m_reply, &QNetworkReply::finished, this, &WebDavSession::finished);
    setStatus(operation == Operation::Upload ? tr("Syncing…") : tr("Checking WebDAV database…"));
}

void WebDavSession::startLockedUpload(const QString& snapshot)
{
    m_workerCanceled = std::make_shared<std::atomic_bool>(false);
    const WebDavWrite::Connection login{m_url, m_user, m_password, m_workerCanceled};
    auto* watcher = new QFutureWatcher<WebDavWrite::LockedResult>(this);
    connect(watcher, &QFutureWatcherBase::finished, this, [this, watcher] {
        const auto result = watcher->result();
        watcher->deleteLater();
        const bool canceled = m_workerCanceled->load();
        m_workerCanceled.reset();
        if (canceled) {
            retry();
            return;
        }
        if (result.authenticated) {
            emit authenticated();
        }
        if (result.outcome == WebDavWrite::Outcome::Rejected) {
            m_rejectedEtag = result.rejectedTag;
        }
        if (result.releaseFailed) {
            retryLater(tr("Could not confirm release of the WebDAV lock. The local copy is preserved."));
            return;
        }
        using Outcome = WebDavWrite::Outcome;
        switch (result.outcome) {
        case Outcome::Rejected:
        case Outcome::Verify:
            request(Operation::Verify);
            break;
        case Outcome::Unsupported:
            disableWrites();
            break;
        case Outcome::Authenticate:
            m_needsAuth = true;
            setStatus(tr("WebDAV login required"));
            emit authenticationRequired();
            break;
        case Outcome::Retry:
            retryLater(tr("Saved locally, waiting to sync"));
            break;
        case Outcome::Error:
            stopWithError(tr("WebDAV request failed (HTTP %1).").arg(result.status));
            break;
        }
    });
    watcher->setFuture(QtConcurrent::run(WebDavWrite::writeLocked, login, snapshot, m_baseHash));
    setStatus(tr("Checking the remote database under an exclusive lock…"));
}

void WebDavSession::disableWrites()
{
    m_dirty = true;
    if (WebDavWrite::kind(m_etag) == WebDavWrite::Kind::Bare) {
        m_bareVerified = false;
        QFile::remove(bareProofPath());
    }
    m_disabledTag = m_etag;
    if (record(m_etag, m_baseHash)) {
        setStatus(tr("Read-only: the server could not protect this write. Local changes are preserved."));
    }
}

void WebDavSession::readResponse()
{
    const auto bytes = m_reply->readAll();
    if (m_operation != Operation::Upload && !m_transferFailed && m_transfer->write(bytes) != bytes.size()) {
        m_transferFailed = true;
        m_reply->abort();
    }
}

void WebDavSession::finished()
{
    if (m_reply->isReadable() && m_reply->bytesAvailable() > 0) {
        readResponse();
    }
    auto* reply = m_reply;
    m_reply = nullptr;
    reply->deleteLater();
    const auto operation = m_operation;
    const auto loginRevision = m_requestRevision;
    const bool currentLogin = loginRevision == m_credentialsRevision;
    const bool usedLogin = reply->property("webDavAuthTried").toBool();
    if (!currentLogin) {
        // Login was edited during this transfer. Validate the new choice in its own request.
        QTimer::singleShot(0, this, &WebDavSession::retry);
    }
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto etag = WebDavWrite::parseTag(reply->rawHeader("ETag"));
    if (m_transferFailed) {
        stopWithError(tr("The WebDAV download could not be written to disk."));
        return;
    }
    if (reply->error() == QNetworkReply::SslHandshakeFailedError) {
        const auto message = tr("Could not establish a trusted HTTPS connection to the WebDAV server.");
        setStatus(message);
        if (!m_ready && !databaseHash(localPath()).isEmpty()) {
            publishReady();
        } else if (!m_ready) {
            emit failed(message);
        }
        return;
    }
    if (status == 401) {
        if (!currentLogin) {
            return;
        }
        m_needsAuth = true;
        setStatus(tr("WebDAV login required"));
        if (!m_ready && !databaseHash(localPath()).isEmpty()) {
            publishReady();
        }
        emit authenticationRequired();
        return;
    }
    if (operation == Operation::Upload && status == 412) {
        m_rejectedEtag = m_etag;
        request(Operation::Verify);
        return;
    }
    if (reply->error() != QNetworkReply::NoError
        || (operation == Operation::Upload ? (status != 200 && status != 201 && status != 204) : status != 200)) {
        if (status == 0 || status == 408 || status == 429 || status >= 500) {
            retryLater(m_ready && (m_dirty || !m_attemptHash.isEmpty()) ? tr("Saved locally, waiting to sync")
                                                                        : tr("WebDAV unavailable. Offline"));
        } else {
            const auto message = tr("WebDAV request failed (HTTP %1).").arg(status);
            if (!m_ready && !databaseHash(localPath()).isEmpty()) {
                setStatus(message);
                publishReady();
            } else {
                stopWithError(message);
            }
        }
        return;
    }
    m_needsAuth = false;
    m_retryDelay = 5000;
    if (operation == Operation::Upload) {
        // Providers can format PUT and GET response tags differently. For compatibility
        // writes, take the next validator from the GET that also confirms the uploaded bytes.
        if (WebDavWrite::kind(m_etag) != WebDavWrite::Kind::Strong || WebDavWrite::kind(etag) != WebDavWrite::Kind::Strong) {
            request(Operation::Verify);
        } else if (record(etag, m_attemptHash)) {
            continueSaving();
        }
    } else {
        receiveFile(operation, etag);
    }
    // Public reads may succeed without the server ever checking the supplied login.
    if (usedLogin && m_credentialsRevision == loginRevision) {
        emit authenticated();
    }
}

void WebDavSession::receiveFile(Operation operation, const QByteArray& etag)
{
    const auto hash = m_transfer->flush() ? databaseHash(*m_transfer) : QByteArray();
    if (hash.isEmpty()) {
        const auto message = tr("The WebDAV response does not contain a readable KDBX database.");
        if (!m_ready && !databaseHash(localPath()).isEmpty()) {
            setStatus(message);
            publishReady();
        } else {
            stopWithError(message);
        }
        return;
    }
    if (operation == Operation::Download) {
        QSaveFile workingCopy(localPath());
        if (!workingCopy.open(QIODevice::WriteOnly) || !workingCopy.setPermissions(privateFile) || !m_transfer->seek(0)
            || !copyBytes(*m_transfer, workingCopy) || !workingCopy.commit()) {
            stopWithError(tr("Could not save the downloaded database."));
            return;
        }
        if (record(etag, hash)) {
            continueSaving();
            publishReady();
        }
        return;
    }
    if (operation == Operation::Merge && !etag.isEmpty()) {
        m_mergeFile = std::move(m_transfer);
        m_mergeHash = hash;
        m_mergeEtag = etag;
        setStatus(tr("Remote changes are ready to merge"));
        emit mergeReady(m_mergeFile->fileName());
        return;
    }
    const auto localHash = databaseHash(localPath());
    if (localHash.isEmpty()) {
        stopWithError(tr("The saved WebDAV working copy could not be read."));
        return;
    }
    const auto rejected = m_rejectedEtag;
    m_rejectedEtag.clear();
    if (!etag.isEmpty() && etag == rejected && hash == m_baseHash && localHash != hash) {
        // A server rejecting its own unchanged validator cannot safely accept automatic saves.
        m_etag = etag;
        disableWrites();
        return;
    }
    if (hash == m_baseHash || hash == m_attemptHash || hash == localHash) {
        // A lost PUT response, or an ETag-only change, can be reconciled by exact byte identity.
        if (record(etag, hash)) {
            m_conflict = false;
            m_dirty = localHash != hash;
            continueSaving();
        }
    } else {
        m_conflict = true;
        if (etag.isEmpty() && !record({}, m_baseHash)) {
            return;
        }
        setStatus(etag.isEmpty() ? tr("Read-only: the server did not provide a usable ETag.")
                                 : tr("Remote changes need to be merged"));
    }
}

void WebDavSession::continueSaving()
{
    if (isReadOnly()) {
        if (!m_disabledTag.isEmpty() && m_etag == m_disabledTag) {
            setStatus(tr("Read-only: the server could not protect this write. Local changes are preserved."));
        } else if (WebDavWrite::kind(m_etag) == WebDavWrite::Kind::Bare) {
            setStatus(tr("Read-only until conditional writes are verified for this folder and account."));
        } else {
            setStatus(tr("Read-only: the server did not provide a usable ETag."));
        }
    } else if (m_dirty) {
        request(Operation::Upload);
    } else {
        setStatus(tr("Synced"));
    }
}

void WebDavSession::fetchForMerge()
{
    if (m_conflict && !m_reply && !m_workerCanceled) {
        // An unlock/merge dialog may still own this snapshot. Keep its bytes paired with
        // their original validator until the user commits the merge.
        if (m_mergeFile) {
            emit mergeReady(m_mergeFile->fileName());
        } else {
            request(Operation::Merge);
        }
    }
}

bool WebDavSession::acceptMergeBase()
{
    if (!m_conflict || !m_mergeFile || m_mergeEtag.isEmpty() || !record(m_mergeEtag, m_mergeHash)) {
        return false;
    }
    m_mergeFile.reset();
    m_mergeEtag.clear();
    m_conflict = false;
    m_dirty = true;
    continueSaving();
    return true;
}
