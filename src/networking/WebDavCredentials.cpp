// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>

#include "WebDavCredentials.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QScopeGuard>

using WebDavCredentials::Result;

#if defined(Q_OS_WIN)
#include <windows.h>

#include <wincred.h>

namespace
{
    Result credentialError()
    {
        return GetLastError() == ERROR_NOT_FOUND ? Result::Missing : Result::Unavailable;
    }

    std::wstring targetName(const QString& reference)
    {
        return (QStringLiteral("KeePassXC/WebDAV/") + reference).toStdWString();
    }

    Result loadSecret(const QString& reference, QByteArray& data)
    {
        PCREDENTIALW credential = nullptr;
        if (!CredReadW(targetName(reference).c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
            return credentialError();
        }
        data = QByteArray(reinterpret_cast<const char*>(credential->CredentialBlob), credential->CredentialBlobSize);
        CredFree(credential);
        return Result::Success;
    }

    Result storeSecret(const QString& reference, const QByteArray& data)
    {
        if (data.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
            return Result::Unavailable;
        }
        auto target = targetName(reference);
        CREDENTIALW credential{};
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = target.data();
        credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(data.constData()));
        credential.CredentialBlobSize = static_cast<DWORD>(data.size());
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        return CredWriteW(&credential, 0) ? Result::Success : credentialError();
    }

    Result deleteSecret(const QString& reference)
    {
        return CredDeleteW(targetName(reference).c_str(), CRED_TYPE_GENERIC, 0) ? Result::Success : credentialError();
    }
} // namespace
#elif defined(Q_OS_MACOS)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

namespace
{
    CFMutableDictionaryRef credentialQuery(const QString& reference)
    {
        auto query =
            CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        auto account = reference.toCFString();
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, CFSTR("org.keepassxc.WebDAV"));
        CFDictionarySetValue(query, kSecAttrAccount, account);
        CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
        CFRelease(account);
        return query;
    }

    Result keychainResult(OSStatus status)
    {
        if (status == errSecSuccess) {
            return Result::Success;
        }
        return status == errSecItemNotFound ? Result::Missing : Result::Unavailable;
    }

    Result loadSecret(const QString& reference, QByteArray& data)
    {
        auto query = credentialQuery(reference);
        const auto releaseQuery = qScopeGuard([&] { CFRelease(query); });
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        CFTypeRef value = nullptr;
        auto status = SecItemCopyMatching(query, &value);
        if (status == errSecSuccess) {
            data = QByteArray::fromCFData(static_cast<CFDataRef>(value));
            CFRelease(value);
        }
        return keychainResult(status);
    }

    Result storeSecret(const QString& reference, const QByteArray& data)
    {
        auto query = credentialQuery(reference);
        const auto releaseQuery = qScopeGuard([&] { CFRelease(query); });
        auto value = data.toCFData();
        const auto releaseData = qScopeGuard([&] { CFRelease(value); });
        const void* keys[]{kSecValueData};
        const void* values[]{value};
        auto update = CFDictionaryCreate(
            nullptr, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        const auto releaseUpdate = qScopeGuard([&] { CFRelease(update); });
        auto status = SecItemUpdate(query, update);
        if (status == errSecItemNotFound) {
            CFDictionarySetValue(query, kSecValueData, value);
            status = SecItemAdd(query, nullptr);
        }
        return keychainResult(status);
    }

    Result deleteSecret(const QString& reference)
    {
        auto query = credentialQuery(reference);
        auto result = keychainResult(SecItemDelete(query));
        CFRelease(query);
        return result;
    }
} // namespace
#elif defined(Q_OS_UNIX)
#include "fdosecrets/objects/SessionCipher.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMetaType>
#include <QDBusReply>

namespace
{
    using FdoSecrets::wire::Secret;
    using FdoSecrets::wire::StringStringMap;
    using ObjectPaths = QList<QDBusObjectPath>;

    const QString serviceName = QStringLiteral("org.freedesktop.secrets");
    const QString servicePath = QStringLiteral("/org/freedesktop/secrets");
    const QString serviceInterface = QStringLiteral("org.freedesktop.Secret.Service");

    class Keyring
    {
    public:
        explicit Keyring(const QString& reference)
            : m_attributes{{"application", "org.keepassxc.WebDAV"}, {"connection", reference}}
        {
            qDBusRegisterMetaType<StringStringMap>();
            qDBusRegisterMetaType<Secret>();
            if (!m_bus.isConnected()) {
                return;
            }
            auto bus = m_bus.interface();
            auto owner = bus->serviceOwner(serviceName);
            if (!owner.isValid()) {
                auto activate = QDBusMessage::createMethodCall(
                    "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "StartServiceByName");
                activate.setArguments({serviceName, 0u});
                if (m_bus.call(activate, QDBus::Block, 3000).type() == QDBusMessage::ErrorMessage) {
                    return;
                }
                owner = bus->serviceOwner(serviceName);
            }
            // Pin this provider's unique name. Calling KeePassXC's own Secret Service
            // could prompt to unlock the very database we are trying to download.
            if (owner.isValid()) {
                const auto pid = bus->servicePid(owner.value());
                if (pid.isValid() && pid.value() != static_cast<uint>(QCoreApplication::applicationPid())) {
                    m_owner = owner.value();
                }
            }
        }

        ~Keyring()
        {
            if (!m_session.path().isEmpty()) {
                m_bus.send(QDBusMessage::createMethodCall(
                    m_owner, m_session.path(), "org.freedesktop.Secret.Session", "Close"));
            }
        }

        bool openSession()
        {
            if (m_owner.isEmpty()) {
                return false;
            }
            m_cipher = std::make_unique<FdoSecrets::DhIetf1024Sha256Aes128CbcPkcs7>();
            const auto publicKey = m_cipher->publicKey();
            if (publicKey.isEmpty()) {
                return false;
            }
            auto result = call(servicePath,
                               serviceInterface,
                               "OpenSession",
                               {m_cipher->Algorithm, QVariant::fromValue(QDBusVariant(publicKey))});
            if (result.signature() != "vo") {
                return false;
            }
            m_session = result.arguments().at(1).value<QDBusObjectPath>();
            auto peer = result.arguments().first().value<QDBusVariant>().variant().toByteArray();
            return m_session.path() != "/" && m_cipher->updateClientPublicKey(peer);
        }

        Result read(QByteArray& data)
        {
            ObjectPaths items;
            auto result = search(items);
            if (result != Result::Success) {
                return result;
            }
            if (!openSession()) {
                return Result::Unavailable;
            }
            QDBusReply<Secret> secret = call(
                items.front().path(), "org.freedesktop.Secret.Item", "GetSecret", {QVariant::fromValue(m_session)});
            if (!secret.isValid() || secret.value().session != m_session) {
                return Result::Unavailable;
            }
            const auto encrypted = secret.value();
            if (encrypted.parameters.size() != 16 || encrypted.value.isEmpty()) {
                return Result::Unavailable;
            }
            const auto decoded =
                m_cipher->decrypt({nullptr, encrypted.parameters, encrypted.value, encrypted.contentType});
            if (!decoded.parameters.isEmpty()) {
                return Result::Unavailable;
            }
            data = decoded.value;
            return Result::Success;
        }

        Result write(const QByteArray& data)
        {
            if (!openSession()) {
                return Result::Unavailable;
            }
            const QVariantMap properties{{"org.freedesktop.Secret.Item.Label",
                                          QCoreApplication::translate("WebDavCredentials", "KeePassXC WebDAV login")},
                                         {"org.freedesktop.Secret.Item.Attributes", QVariant::fromValue(m_attributes)}};
            const auto encoded = m_cipher->encrypt({nullptr, {}, data, QStringLiteral("application/json")});
            if (encoded.parameters.isEmpty() || encoded.value.isEmpty()) {
                return Result::Unavailable;
            }
            Secret secret{m_session, encoded.parameters, encoded.value, encoded.contentType};
            auto result = call(servicePath + "/aliases/default",
                               "org.freedesktop.Secret.Collection",
                               "CreateItem",
                               {properties, QVariant::fromValue(secret), true});
            if (result.signature() != "oo" || result.arguments().at(0).value<QDBusObjectPath>().path() == "/") {
                return Result::Unavailable;
            }
            return Result::Success;
        }

        Result remove()
        {
            ObjectPaths items;
            auto result = search(items);
            if (result != Result::Success) {
                return result;
            }
            for (const auto& item : items) {
                QDBusReply<QDBusObjectPath> prompt = call(item.path(), "org.freedesktop.Secret.Item", "Delete");
                if (!prompt.isValid() || prompt.value().path() != "/") {
                    return Result::Unavailable;
                }
            }
            return Result::Success;
        }

    private:
        QDBusMessage
        call(const QString& path, const QString& interface, const QString& method, const QVariantList& args = {}) const
        {
            auto request = QDBusMessage::createMethodCall(m_owner, path, interface, method);
            request.setArguments(args);
            return m_bus.call(request, QDBus::Block, 3000);
        }

        Result search(ObjectPaths& unlocked)
        {
            if (m_owner.isEmpty()) {
                return Result::Unavailable;
            }
            auto result = call(servicePath, serviceInterface, "SearchItems", {QVariant::fromValue(m_attributes)});
            if (result.signature() != "aoao") {
                return Result::Unavailable;
            }
            unlocked = qdbus_cast<ObjectPaths>(result.arguments().at(0));
            if (!qdbus_cast<ObjectPaths>(result.arguments().at(1)).isEmpty()) {
                return Result::Unavailable;
            }
            return unlocked.isEmpty() ? Result::Missing : Result::Success;
        }

        QDBusConnection m_bus = QDBusConnection::sessionBus();
        StringStringMap m_attributes;
        std::unique_ptr<FdoSecrets::DhIetf1024Sha256Aes128CbcPkcs7> m_cipher;
        QString m_owner;
        QDBusObjectPath m_session;
    };

    Result loadSecret(const QString& reference, QByteArray& data)
    {
        return Keyring(reference).read(data);
    }

    Result storeSecret(const QString& reference, const QByteArray& data)
    {
        return Keyring(reference).write(data);
    }

    Result deleteSecret(const QString& reference)
    {
        return Keyring(reference).remove();
    }
} // namespace
#else
namespace
{
    Result loadSecret(const QString&, QByteArray&)
    {
        return Result::Unavailable;
    }
    Result storeSecret(const QString&, const QByteArray&)
    {
        return Result::Unavailable;
    }
    Result deleteSecret(const QString&)
    {
        return Result::Unavailable;
    }
} // namespace
#endif

Result WebDavCredentials::read(const QString& reference, QString& user, QString& password)
{
    user.clear();
    password.clear();
    QByteArray data;
    auto result = loadSecret(reference, data);
    if (result != Result::Success) {
        return result;
    }
    auto values = QJsonDocument::fromJson(data).array();
    if (values.size() != 2 || !values.at(0).isString() || !values.at(1).isString()) {
        return Result::Unavailable;
    }
    user = values.at(0).toString();
    password = values.at(1).toString();
    return Result::Success;
}

Result WebDavCredentials::write(const QString& reference, const QString& user, const QString& password)
{
    return storeSecret(reference, QJsonDocument(QJsonArray{user, password}).toJson(QJsonDocument::Compact));
}

Result WebDavCredentials::remove(const QString& reference)
{
    return deleteSecret(reference);
}
