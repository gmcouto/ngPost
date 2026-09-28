#ifndef FF1CIPHER_H
#define FF1CIPHER_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

class FF1Cipher
{
public:
    static bool encryptLine(const QByteArray &plaintext, const QByteArray &masterKey, quint32 segmentIndex,
                            quint32 lineIndex, const QByteArray &salt, QByteArray &wire, QString *error = nullptr);
    static bool decryptLine(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                            quint32 lineIndex, QByteArray &plaintext, QByteArray *salt = nullptr,
                            QString *error = nullptr);
    static bool encryptControlLines(const QByteArray &block, const QByteArray &masterKey, quint32 segmentIndex,
                                    const QByteArray &salt, QByteArray &wire, QString *error = nullptr);
    static bool decryptControlLines(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                                    QByteArray &block, QByteArray *salt = nullptr, QString *error = nullptr);
    static bool isAlphabetByte(uchar value);
};

#endif
