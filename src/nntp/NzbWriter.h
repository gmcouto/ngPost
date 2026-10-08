#ifndef NZBWRITER_H
#define NZBWRITER_H

#include <QMap>
#include <QString>

class QTextStream;

class NzbWriter
{
public:
    static void writeHead(QTextStream &stream, const QString &tab,
                          const QMap<QString, QString> &meta,
                          const QString &archivePassword = QString(),
                          const QString &encryptionPassword = QString());
    static void writeSegment(QTextStream &stream, const QString &tab, qint64 bytes, uint number,
                             const QString &messageId, quint32 segmentIndex = 0);
};

#endif
