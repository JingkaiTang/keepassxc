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

#include "WebDavDialog.h"

#include "networking/WebDavSession.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

WebDavDialog::WebDavDialog(QWidget* parent, const QString& reference, const QUrl& initialUrl, const QString& username)
    : QDialog(parent)
    , m_url(new QLineEdit(this))
    , m_user(new QLineEdit(this))
    , m_password(new QLineEdit(this))
    , m_remember(new QCheckBox(tr("Remember login on this device"), this))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setObjectName("webDavDialog");
    setWindowTitle(reference.isEmpty() ? tr("Open from WebDAV") : tr("Update WebDAV Login"));
    m_url->setObjectName("webDavUrl");
    m_url->setPlaceholderText("https://example.org/dav/passwords.kdbx");
    m_url->setText(initialUrl.toString(QUrl::FullyEncoded));
    m_url->setReadOnly(!reference.isEmpty());
    m_user->setObjectName("webDavUser");
    m_user->setText(username);
    m_password->setObjectName("webDavPassword");
    m_password->setEchoMode(QLineEdit::Password);
    m_remember->setObjectName("webDavRemember");
    m_remember->setChecked(true);

    auto form = new QFormLayout;
    form->addRow(tr("HTTPS database file URL:"), m_url);
    form->addRow(tr("WebDAV username:"), m_user);
    form->addRow(tr("WebDAV password:"), m_password);
    form->addRow(m_remember);

    auto error = new QLabel(this);
    error->setWordWrap(true);
    auto buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->setObjectName("buttonBox");
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    auto validate = [this, reference, buttons, error] {
        const bool valid = WebDavSession::isValidUrl(url());
        const bool matchingAccount = reference.isEmpty() || WebDavSession::referenceFor(url(), user()) == reference;
        buttons->button(QDialogButtonBox::Ok)->setEnabled(valid && matchingAccount);
        if (!valid && !m_url->text().isEmpty()) {
            error->setText(tr("Enter an HTTPS file URL without embedded credentials, a query, or a fragment."));
        } else if (valid && !matchingAccount) {
            error->setText(tr("Enter the WebDAV username originally used for this connection."));
        } else {
            error->clear();
        }
        error->setVisible(!error->text().isEmpty());
    };
    connect(m_url, &QLineEdit::textChanged, this, validate);
    connect(m_user, &QLineEdit::textChanged, this, validate);
    validate();

    auto layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(error);
    layout->addWidget(buttons);
    if (!reference.isEmpty()) {
        (username.isEmpty() ? m_user : m_password)->setFocus();
    }
}

QUrl WebDavDialog::url() const
{
    return QUrl(m_url->text().trimmed(), QUrl::StrictMode);
}

QString WebDavDialog::user() const
{
    return m_user->text();
}

QString WebDavDialog::password() const
{
    return m_password->text();
}

bool WebDavDialog::remember() const
{
    return m_remember->isChecked();
}
