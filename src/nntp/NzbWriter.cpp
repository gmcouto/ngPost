#include "NzbWriter.h"


#include <QTextStream>

QString NzbWriter::xmlEscape(const QString &value)
{
    QString escaped(value);
    escaped.replace('&', QStringLiteral("&amp;"));
    escaped.replace('<', QStringLiteral("&lt;"));
    escaped.replace('>', QStringLiteral("&gt;"));
    escaped.replace('"', QStringLiteral("&quot;"));
    escaped.replace('\'', QStringLiteral("&apos;"));
    return escaped;
}

void NzbWriter::writeHead(QTextStream &stream, const QString &tab,
                          const QMap<QString, QString> &meta,
                          const QString &archivePassword,
                          const QString &encryptionPassword)
{
    const bool encrypted = !encryptionPassword.isEmpty();
    if(!encrypted && archivePassword.isEmpty() && meta.isEmpty())
        return;

    stream << tab << "<head>\n";
    for(auto itMeta = meta.cbegin(); itMeta != meta.cend(); ++itMeta)
    {
        if((encrypted && itMeta.key().compare(QStringLiteral("password"), Qt::CaseInsensitive) == 0)
                || itMeta.key().compare(QStringLiteral("yenc_encrypted"), Qt::CaseInsensitive) == 0)
            continue;
        stream << tab << tab << "<meta type=\"" << xmlEscape(itMeta.key()) << "\">"
               << xmlEscape(itMeta.value()) << "</meta>\n";
    }
    if(encrypted)
    {
        stream << tab << tab << "<meta type=\"yenc_encrypted\">true</meta>\n"
               << tab << tab << "<meta type=\"password\">"
               << xmlEscape(encryptionPassword) << "</meta>\n";
    }
    else if(!archivePassword.isEmpty())
        stream << tab << tab << "<meta type=\"password\">"
               << xmlEscape(archivePassword) << "</meta>\n";
    stream << tab << "</head>\n\n";
}

void NzbWriter::writeSegment(QTextStream &stream, const QString &tab, qint64 bytes, uint number,
                             const QString &messageId, quint32 segmentIndex)
{
    stream << tab << "<segment bytes=\"" << bytes << "\" number=\"" << number << "\"";
    if(segmentIndex != 0)
        stream << " segmentIndex=\"" << segmentIndex << "\"";
    stream << ">" << xmlEscape(messageId) << "</segment>\n";
}
