/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or (at your option)
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPASSXC_WEBDAVDIALOG_H
#define KEEPASSXC_WEBDAVDIALOG_H

#include <QDialog>
#include <QUrl>

class QCheckBox;
class QLineEdit;

// An existing reference pins the URL and account while updating a login.
class WebDavDialog : public QDialog
{
    Q_OBJECT
public:
    explicit WebDavDialog(QWidget* parent,
                          const QString& reference = {},
                          const QUrl& url = {},
                          const QString& user = {});

    QUrl url() const;
    QString user() const;
    QString password() const;
    bool remember() const;

private:
    QLineEdit* m_url;
    QLineEdit* m_user;
    QLineEdit* m_password;
    QCheckBox* m_remember;
};

#endif // KEEPASSXC_WEBDAVDIALOG_H
