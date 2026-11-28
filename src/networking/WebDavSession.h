/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KEEPASSXC_WEBDAVSESSION_H
#define KEEPASSXC_WEBDAVSESSION_H

#include <atomic>
#include <QHash>
#include <QObject>
#include <QTimer>
#include <QUrl>
#include <memory>

class QFile;
class QLockFile;
class QNetworkAccessManager;
class QNetworkReply;
class QTemporaryFile;

class WebDavSession : public QObject
{
    Q_OBJECT
public:
    enum class Status
    {
        Normal,
        Pending,
        NeedsAttention
    };
    WebDavSession(const QString& reference, const QUrl& url, QObject* parent = nullptr);
    ~WebDavSession() override;
    static QString referenceFor(const QUrl& url, const QString& user);
    static bool isReference(const QString& reference);
    static QUrl savedUrl(const QString& reference);
    static QHash<QString, QString> recentDisplayNames(const QStringList& references);
    static bool isValidUrl(const QUrl& url);

    QString reference() const;
    QUrl url() const;
    QString localPath() const;
    Status status() const;
    QString statusText() const;
    bool isReadOnly() const;
    bool hasConflict() const;
    bool hasPendingUpload() const;

    void setCredentials(const QString& user, const QString& password);
    void open();
    void localSaved();
    void retry();
    void setChecksEnabled(bool enabled);
    void checkForChanges();
    void networkRestored();
    void pauseChecks(bool pause);
    bool canReceiveRemote() const;
    QString remotePath() const;
    bool installRemote();
    QString basePath() const;
    quint64 localRevision() const;
    bool installMerged(const QString& path, quint64 revision);
    void reportReview(const QString& message);
    void fetchForMerge();
    bool acceptMergeBase();

signals:
    void ready();
    void remoteChanged(const QString& path);
    void statusChanged();
    void notice(const QString& message);
    void authenticated();
    void authenticationRequired();
    void failed(const QString& message);
    void mergeReady(const QString& localRemoteCopyPath);

private:
    enum class Operation
    {
        Download,
        Check,
        Head,
        Verify,
        Upload,
        Merge
    };
    bool prepareCache();
    bool recoverInstall();
    bool installCandidate(QFile& candidate, const QByteArray& hash);
    QString snapshotPath(const QByteArray& hash) const;
    bool keepSnapshot(QFile& source, const QByteArray& hash);
    void prepareNetwork();
    void startCheck();
    bool record(const QByteArray& etag, const QByteArray& base, const QByteArray& attempt = {});
    void setStatus(Status status, const QString& message);
    void publishReady();
    void request(Operation operation);
    QString bareProofPath() const;
    bool verifyBareWrites(const QByteArray& tag);
    void startLockedUpload(const QString& snapshot);
    void disableWrites();
    void readResponse();
    void finished();
    void receiveFile(Operation operation, const QByteArray& etag);
    void continueSaving(bool uploadConfirmed = false);
    void retryLater(const QString& message);
    void stopWithError(const QString& message);

    QString m_reference;
    QUrl m_url;
    QString m_directory;
    Status m_status = Status::Normal;
    QString m_statusText;
    QString m_user;
    QString m_password;
    bool m_credentialsSet = false;
    quint64 m_credentialsRevision = 0;
    quint64 m_requestRevision = 0;
    bool m_ready = false;
    bool m_dirty = false;
    quint64 m_localRevision = 0;
    bool m_conflict = false;
    bool m_needsAuth = false;
    bool m_transferFailed = false;
    Operation m_operation = Operation::Download;
    std::unique_ptr<QLockFile> m_lock;
    QNetworkAccessManager* m_network = nullptr;
    QNetworkReply* m_reply = nullptr;
    QTimer m_retryTimer;
    QTimer m_pollTimer;
    QTimer m_checkTimer;
    bool m_checkQueued = false;
    int m_checkPauses = 0;
    QByteArray m_headTag;
    QByteArray m_sampleTag;
    QByteArray m_sampleHash;
    bool m_pairingHead = false;
    bool m_headVerified = false;
    bool m_headDisabled = false;
    int m_headSkips = 0;
    qint64 m_retryAfter = 0;
    int m_retryDelay = 5000;

    // Last acknowledged remote representation, plus a PUT whose outcome may still be unknown.
    QByteArray m_etag;
    QByteArray m_baseHash;
    QByteArray m_attemptHash;
    QByteArray m_rejectedEtag;
    QByteArray m_disabledTag;
    bool m_bareVerified = false;
    QString m_probeError;
    std::shared_ptr<std::atomic_bool> m_workerCanceled;
    std::unique_ptr<QTemporaryFile> m_transfer;
    std::unique_ptr<QTemporaryFile> m_mergeFile;
    QByteArray m_mergeEtag;
    QByteArray m_mergeHash;
};

#endif
