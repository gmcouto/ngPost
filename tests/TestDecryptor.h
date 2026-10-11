#ifndef TESTDECRYPTOR_H
#define TESTDECRYPTOR_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

class TestDecryptor
{
public:
    static bool decryptBody(const QByteArray &ciphertext, const QByteArray &tag, const QByteArray &key,
                            quint32 segmentIndex, QByteArray &plaintext, QString *error = nullptr);

    static bool decryptLine(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                            quint32 lineIndex, QByteArray &plaintext, QByteArray *salt = nullptr,
                            QString *error = nullptr);
    static bool decryptLine(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                            quint32 lineIndex, QByteArray &plaintext, QByteArray *salt,
                            quint32 *extractedSegmentIndex, QString *error = nullptr);

    static bool decryptControlLines(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                                    QByteArray &block, QByteArray *salt = nullptr, QString *error = nullptr);
    static bool decryptControlLines(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                                    QByteArray &block, QByteArray *salt, quint32 *extractedSegmentIndex,
                                    QString *error = nullptr);
};

#endif
