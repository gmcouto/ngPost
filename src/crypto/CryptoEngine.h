#ifndef CRYPTOENGINE_H
#define CRYPTOENGINE_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>
#include <sodium.h>
#include <utility>

struct CryptoKeys
{
    QByteArray masterKey;

    CryptoKeys() = default;
    ~CryptoKeys()
    {
        clear();
    }
    CryptoKeys(const CryptoKeys &) = default;
    CryptoKeys(CryptoKeys &&) = default;

    CryptoKeys &operator=(const CryptoKeys &other)
    {
        if(this != &other)
        {
            clear();
            masterKey = other.masterKey;
        }
        return *this;
    }

    CryptoKeys &operator=(CryptoKeys &&other) noexcept
    {
        if(this != &other)
        {
            clear();
            masterKey = std::move(other.masterKey);
        }
        return *this;
    }

    // Wipe sensitive key material so keys never linger in heap memory.
    void clear()
    {
        if(!masterKey.isEmpty())
        {
            sodium_memzero(masterKey.data(), static_cast<size_t>(masterKey.size()));
            masterKey.clear();
        }
    }
};

struct BodyEncryptionResult
{
    QByteArray ciphertext;
    QByteArray tag;

    BodyEncryptionResult() = default;
    ~BodyEncryptionResult()
    {
        clear();
    }
    BodyEncryptionResult(const BodyEncryptionResult &) = default;
    BodyEncryptionResult(BodyEncryptionResult &&) = default;

    BodyEncryptionResult &operator=(const BodyEncryptionResult &other)
    {
        if(this != &other)
        {
            clear();
            ciphertext = other.ciphertext;
            tag = other.tag;
        }
        return *this;
    }

    BodyEncryptionResult &operator=(BodyEncryptionResult &&other) noexcept
    {
        if(this != &other)
        {
            clear();
            ciphertext = std::move(other.ciphertext);
            tag = std::move(other.tag);
        }
        return *this;
    }

    void clear()
    {
        ciphertext.clear();
        tag.clear();
    }
};

class CryptoEngine
{
public:
    static QByteArray generateSalt();
    static QByteArray generateControlSalt();
    static bool deriveKey(const QString &password, const QByteArray &salt, QByteArray &key, QString *error = nullptr);
    static bool deriveKeys(const QString &password, const QByteArray &salt, CryptoKeys &keys, QString *error = nullptr);
    static bool deriveBodyNonce(const QByteArray &key, quint32 segmentIndex, QByteArray &nonce, QString *error = nullptr);
    static bool deriveControlKey(const QByteArray &masterKey, QByteArray &key, QString *error = nullptr);
    static bool deriveControlTweak(const QByteArray &masterKey, quint32 segmentIndex, quint32 lineIndex,
                                   QByteArray &tweak, QString *error = nullptr);
    static bool encryptBody(const QByteArray &plaintext, const QByteArray &key, quint32 segmentIndex,
                            BodyEncryptionResult &result, QString *error = nullptr);

private:
    static bool initialize(QString *error);
    static bool validateKey(const QByteArray &key, const char *name, QString *error);
    static QByteArray uint32Be(quint32 value);
};

#endif
