#include <QtTest>

#include "EncryptionSettings.h"
#include "utils/CmdOrGuiApp.h"

namespace
{
void writeHead(QTextStream &stream, const QString &tab,
               const QMap<QString, QString> &meta,
               const QString &rarPass,
               const QString &encryptionPassword)
{
    const bool encryptionEnabled = !encryptionPassword.isEmpty();
    if (encryptionEnabled || !rarPass.isEmpty() || meta.size())
    {
        stream << tab << "<head>\n";
        for (auto itMeta = meta.cbegin(); itMeta != meta.cend(); ++itMeta)
            stream << tab << tab << "<meta type=\"" << itMeta.key() << "\">" << itMeta.value() << "</meta>\n";
        if (encryptionEnabled)
        {
            stream << tab << tab << "<meta type=\"yenc_encrypted\">true</meta>\n"
                   << tab << tab << "<meta type=\"password\">"
                   << CmdOrGuiApp::escapeXML(encryptionPassword) << "</meta>\n";
        }
        else if (!rarPass.isEmpty())
            stream << tab << tab << "<meta type=\"password\">" << rarPass << "</meta>\n";
        stream << tab << "</head>\n\n";
    }
}
}

class NzbTest : public QObject
{
    Q_OBJECT

private slots:
    void encryptedHeadIncludesTransportMetadata();
    void ordinaryHeadPreservesArchiveMetadata();
    void validatesEncryptionSettings();
    void encryptionSettingsValidationResetsInvalidState();
};

void NzbTest::encryptedHeadIncludesTransportMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    QString xml;
    QTextStream stream(&xml);
    writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("archive-pass"),
              QStringLiteral("transport<&\"pass"));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"yenc_encrypted\">true</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">transport&lt;&amp;&quot;pass</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"category\">test</meta>")));
    QVERIFY(!xml.contains(QStringLiteral("archive-pass")));
    QCOMPARE(xml.count(QStringLiteral("yenc_encrypted")), 1);
}

void NzbTest::ordinaryHeadPreservesArchiveMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    QString xml;
    QTextStream stream(&xml);
    writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("archive<&\"pass"), QString());
    QVERIFY(!xml.contains(QStringLiteral("yenc_encrypted")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">archive<&\"pass</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"category\">test</meta>")));
}

void NzbTest::validatesEncryptionSettings()
{
    EncryptionSettings settings;
    QString error;
    QVERIFY(settings.validate(&error));
    settings.enabled = true;
    QVERIFY(!settings.validate(&error));
    QVERIFY(!error.isEmpty());
    settings.password = QStringLiteral("p<&\"");
    QVERIFY(settings.validate(&error));
    settings.enabled = false;
    QVERIFY(settings.validate(&error));
    settings.clearPassword();
    QVERIFY(settings.password.isEmpty());
}

void NzbTest::encryptionSettingsValidationResetsInvalidState()
{
    EncryptionSettings settings;
    settings.enabled = true;
    settings.password = QString();
    QString error;
    QVERIFY(!settings.validate(&error));
    QCOMPARE(error, QStringLiteral("Encryption requires a non-empty password"));
    settings.enabled = false;
    settings.clearPassword();
    QVERIFY(!settings.enabled);
    QVERIFY(settings.password.isEmpty());
}

QTEST_APPLESS_MAIN(NzbTest)

#include "NzbTest.moc"
