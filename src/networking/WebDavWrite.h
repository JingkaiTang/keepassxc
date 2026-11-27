// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 KeePassXC Team

#ifndef KEEPASSXC_WEBDAVWRITE_H
#define KEEPASSXC_WEBDAVWRITE_H

#include <QByteArray>
#include <QUrl>
#include <atomic>
#include <memory>

namespace WebDavWrite
{
    enum class Kind
    {
        Invalid,
        Strong,
        Bare,
        Weak
    };

    QByteArray parseTag(QByteArray header);
    Kind kind(const QByteArray& parsedTag);

    struct Connection
    {
        QUrl url;
        QString user;
        QString password;
        std::shared_ptr<std::atomic_bool> canceled;
    };

    struct ProbeResult
    {
        bool passed = false;
        QString leftover;
    };

    // Both operations run on a worker thread. No live database bytes are used for the probe.
    ProbeResult probeBare(const Connection& connection);

    enum class Outcome
    {
        Verify,
        Rejected,
        Unsupported,
        Authenticate,
        Retry,
        Error
    };
    struct LockedResult
    {
        Outcome outcome;
        int status = 0;
        QByteArray rejectedTag;
        bool authenticated = false;
        bool releaseFailed = false;
    };
    LockedResult writeLocked(const Connection& connection, const QString& snapshot, const QByteArray& baseHash);
}

#endif
