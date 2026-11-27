// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef KEEPASSXC_WEBDAVMERGE_H
#define KEEPASSXC_WEBDAVMERGE_H

#include <QHash>
#include <QList>
#include <QUuid>

class Database;
class Entry;

// All source databases are immutable for the lifetime of the plan. Only apply to a disposable copy.
class WebDavMerge
{
public:
    enum class Side
    {
        Local,
        Remote
    };
    struct Conflict
    {
        QUuid uuid;
        const Entry* local;
        const Entry* remote;
    };
    WebDavMerge(const Database* base, const Database& local, const Database& remote);
    bool compatible = false;
    bool chooseStructure = false;
    Side startingCopy = Side::Local;
    QList<Conflict> conflicts;
    bool apply(Database& candidate, const QHash<QUuid, Side>& choices) const;

private:
    const Database& m_local;
    const Database& m_remote;
    QHash<QUuid, const Entry*> m_selected;
};
#endif
