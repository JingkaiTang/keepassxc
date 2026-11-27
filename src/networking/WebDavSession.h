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
    QString statusText() const;
    bool isReadOnly() const;
    bool hasConflict() const;
    bool hasPendingUpload() const;

    void setCredentials(const QString& user, const QString& password);
    void open();
    void localSaved();
    bool canProbeWrites() const;
    void probeWrites();
    void retry();
    void fetchForMerge();
    bool acceptMergeBase();

signals:
    void ready();
    void statusChanged();
    void authenticated();
    void authenticationRequired();
    void failed(const QString& message);
    void mergeReady(const QString& localRemoteCopyPath);

private:
    enum class Operation
    {
        Download,
        Verify,
        Upload,
        Merge
    };
    bool prepareCache();
    void prepareNetwork();
    bool record(const QByteArray& etag, const QByteArray& base, const QByteArray& attempt = {});
    void setStatus(const QString& message);
    void publishReady();
    void request(Operation operation);
    QString bareProofPath() const;
    void startLockedUpload(const QString& snapshot);
    void disableWrites();
    void readResponse();
    void finished();
    void receiveFile(Operation operation, const QByteArray& etag);
    void continueSaving();
    void retryLater(const QString& message);
    void stopWithError(const QString& message);

    QString m_reference;
    QUrl m_url;
    QString m_directory;
    QString m_status;
    QString m_user;
    QString m_password;
    bool m_credentialsSet = false;
    quint64 m_credentialsRevision = 0;
    quint64 m_requestRevision = 0;
    bool m_ready = false;
    bool m_dirty = false;
    bool m_conflict = false;
    bool m_needsAuth = false;
    bool m_transferFailed = false;
    Operation m_operation = Operation::Download;
    std::unique_ptr<QLockFile> m_lock;
    QNetworkAccessManager* m_network = nullptr;
    QNetworkReply* m_reply = nullptr;
    QTimer m_retryTimer;
    int m_retryDelay = 5000;

    // Last acknowledged remote representation, plus a PUT whose outcome may still be unknown.
    QByteArray m_etag;
    QByteArray m_baseHash;
    QByteArray m_attemptHash;
    QByteArray m_rejectedEtag;
    QByteArray m_disabledTag;
    bool m_bareVerified = false;
    std::shared_ptr<std::atomic_bool> m_workerCanceled;
    std::unique_ptr<QTemporaryFile> m_transfer;
    std::unique_ptr<QTemporaryFile> m_mergeFile;
    QByteArray m_mergeEtag;
    QByteArray m_mergeHash;
};

#endif
