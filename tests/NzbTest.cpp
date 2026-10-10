#include <QtTest>

#include "EncryptionSettings.h"
#include "nntp/NzbWriter.h"

class NzbTest : public QObject
{
    Q_OBJECT

private slots:
    void encryptedHeadIncludesTransportMetadata();
    void ordinaryHeadPreservesArchiveMetadata();
    void ordinaryHeadPreservesArchiveMetadataWithoutDuplicatePassword();
    void writerOwnsEscapingForRawMetadata();
    void writerRejectsInjectionAttempts();
    void segmentsArePlainNzb11();
    void validatesEncryptionSettings();
    void encryptionSettingsValidationResetsInvalidState();
};

void NzbTest::encryptedHeadIncludesTransportMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    meta.insert(QStringLiteral("password"), QStringLiteral("archive-pass"));
    meta.insert(QStringLiteral("YENC_ENCRYPTED"), QStringLiteral("false"));
    QString xml;
    QTextStream stream(&xml);
    NzbWriter::writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("archive-pass"),
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
    NzbWriter::writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("archive<&\"pass"));
    QVERIFY(!xml.contains(QStringLiteral("yenc_encrypted")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">archive&lt;&amp;&quot;pass</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"category\">test</meta>")));
}

void NzbTest::ordinaryHeadPreservesArchiveMetadataWithoutDuplicatePassword()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    meta.insert(QStringLiteral("password"), QStringLiteral("meta-pass"));
    QString xml;
    QTextStream stream(&xml);
    NzbWriter::writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("archive-pass"), QString());
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">archive-pass</meta>")));
    QVERIFY(!xml.contains(QStringLiteral("meta-pass")));
    QCOMPARE(xml.count(QStringLiteral("<meta type=\"password\">")), 1);
}

void NzbTest::writerOwnsEscapingForRawMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("cat<>\"&'"), QStringLiteral("va<lue&\""));
    QString xml;
    QTextStream stream(&xml);
    NzbWriter::writeHead(stream, QStringLiteral("  "), meta, QString());
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"cat&lt;&gt;&quot;&amp;&apos;\">va&lt;lue&amp;&quot;</meta>")));
    QVERIFY(!xml.contains(QStringLiteral("</meta><meta")));
}

void NzbTest::writerRejectsInjectionAttempts()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("other"), QStringLiteral("x</meta><meta type=\"peekable\">true"));
    QString xml;
    QTextStream stream(&xml);
    NzbWriter::writeHead(stream, QStringLiteral("  "), meta, QStringLiteral("p</meta><meta"));
    QVERIFY(xml.contains(QStringLiteral("x&lt;/meta&gt;&lt;meta type=&quot;peekable&quot;&gt;true")));
    QVERIFY(xml.contains(QStringLiteral("p&lt;/meta&gt;&lt;meta")));
    QVERIFY(!xml.contains(QStringLiteral("<meta type=\"peekable\">")));
}

void NzbTest::segmentsArePlainNzb11()
{
    // Segment identity lives only in the article bootstrap; NZB segments are
    // identical for encrypted and ordinary uploads.
    QString xml;
    QTextStream stream(&xml);
    NzbWriter::writeSegment(stream, QStringLiteral("      "), 4, 1,
                            QStringLiteral("one@example.invalid"));
    NzbWriter::writeSegment(stream, QStringLiteral("      "), 4, 2,
                            QStringLiteral("two<&@example.invalid"));
    QCOMPARE(xml, QStringLiteral("      <segment bytes=\"4\" number=\"1\">one@example.invalid</segment>\n"
                                 "      <segment bytes=\"4\" number=\"2\">two&lt;&amp;@example.invalid</segment>\n"));
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
