// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>

#ifndef KEEPASSXC_WEBDAVCREDENTIALS_H
#define KEEPASSXC_WEBDAVCREDENTIALS_H

#include <QString>

namespace WebDavCredentials
{
    enum class Result
    {
        Success,
        Missing,
        Unavailable,
    };

    Result read(const QString& reference, QString& user, QString& password);
    Result write(const QString& reference, const QString& user, const QString& password);
    Result remove(const QString& reference);
} // namespace WebDavCredentials

#endif // KEEPASSXC_WEBDAVCREDENTIALS_H
