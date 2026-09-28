#ifndef CRYPTOENGINE_H
#define CRYPTOENGINE_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

struct CryptoKeys
{
    QByteArray masterKey;
    QByteArray bodyKey;
    QByteArray controlKey;
};

struct BodyEncryptionResult
{
    QByteArray ciphertext;
    QByteArray tag;
    QByteArray nonce;
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
