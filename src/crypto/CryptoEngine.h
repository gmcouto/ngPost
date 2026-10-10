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
    QByteArray bodyKey;
    QByteArray controlKey;

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
            bodyKey = other.bodyKey;
            controlKey = other.controlKey;
        }
        return *this;
    }

    CryptoKeys &operator=(CryptoKeys &&other) noexcept
    {
        if(this != &other)
        {
            clear();
            masterKey = std::move(other.masterKey);
            bodyKey = std::move(other.bodyKey);
            controlKey = std::move(other.controlKey);
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
        if(!bodyKey.isEmpty())
        {
            sodium_memzero(bodyKey.data(), static_cast<size_t>(bodyKey.size()));
            bodyKey.clear();
        }
        if(!controlKey.isEmpty())
        {
            sodium_memzero(controlKey.data(), static_cast<size_t>(controlKey.size()));
            controlKey.clear();
        }
    }
};

struct BodyEncryptionResult
{
    QByteArray ciphertext;
    QByteArray tag;
    QByteArray nonce;

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
            nonce = other.nonce;
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
            nonce = std::move(other.nonce);
        }
        return *this;
    }

    // Wipe the derived nonce on destruction.
    void clear()
    {
        if(!nonce.isEmpty())
            sodium_memzero(nonce.data(), static_cast<size_t>(nonce.size()));
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
    static bool decryptBody(const QByteArray &ciphertext, const QByteArray &tag, const QByteArray &key,
                            quint32 segmentIndex, QByteArray &plaintext, QString *error = nullptr);

private:
    static bool initialize(QString *error);
    static bool validateKey(const QByteArray &key, const char *name, QString *error);
    static QByteArray uint32Be(quint32 value);
};

#endif
