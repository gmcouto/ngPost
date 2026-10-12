#include <QtTest>
#include <QXmlStreamReader>

#include "EncryptionSettings.h"
#include "PostingJob.h"
#include "utils/CmdOrGuiApp.h"

class NzbTest : public QObject
{
    Q_OBJECT

private slots:
    void encryptedHeadIncludesTransportMetadata();
    void ordinaryHeadPreservesArchiveMetadata();
    void rejectsConflictingMetadata();
    void deduplicatesMatchingMetadata();
    void validatesEncryptionSettings();
    void encryptionSettingsValidationResetsInvalidState();
    void rejectsXmlUnrepresentablePasswords();
    void acceptsXmlSpecialAndSurrogatePairPasswords();
    void roundTripsPasswordMetaThroughXmlParser_data();
    void roundTripsPasswordMetaThroughXmlParser();
};

void NzbTest::encryptedHeadIncludesTransportMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    QString xml;
    QTextStream stream(&xml);
    QString error;
    // Archive pass matching transport pass is accepted (no conflict)
    QVERIFY(PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta,
                                    QStringLiteral("transport<&\"pass"),
                                    true,
                                    QStringLiteral("transport<&\"pass"),
                                    &error));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"yenc_encrypted\">true</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">transport&lt;&amp;&quot;pass</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"category\">test</meta>")));
    QCOMPARE(xml.count(QStringLiteral("yenc_encrypted")), 1);
    QCOMPARE(xml.count(QStringLiteral("type=\"password\"")), 1);
}

void NzbTest::ordinaryHeadPreservesArchiveMetadata()
{
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("category"), QStringLiteral("test"));
    QString xml;
    QTextStream stream(&xml);
    QString error;
    QVERIFY(PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta,
                                    QStringLiteral("archive<&\"pass"),
                                    false, QString(), &error));
    QVERIFY(!xml.contains(QStringLiteral("yenc_encrypted")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">archive&lt;&amp;&quot;pass</meta>")));
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"category\">test</meta>")));
}

void NzbTest::rejectsConflictingMetadata()
{
    QString xml;
    QTextStream stream(&xml);
    QString error;

    // 1. Conflicting -m password with encryption password
    QMap<QString, QString> meta1;
    meta1.insert(QStringLiteral("password"), QStringLiteral("wrong_pass"));
    QVERIFY(!PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta1,
                                     QString(), true, QStringLiteral("correct_pass"), &error));
    QVERIFY(error.contains(QStringLiteral("Conflicting metadata")));

    // 2. Conflicting -m yenc_encrypted=false when encryption is enabled
    QMap<QString, QString> meta2;
    meta2.insert(QStringLiteral("yenc_encrypted"), QStringLiteral("false"));
    QVERIFY(!PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta2,
                                     QString(), true, QStringLiteral("correct_pass"), &error));
    QVERIFY(error.contains(QStringLiteral("Conflicting metadata")));

    // 3. Conflicting -m yenc_encrypted=true when encryption is disabled
    QMap<QString, QString> meta3;
    meta3.insert(QStringLiteral("yenc_encrypted"), QStringLiteral("true"));
    QVERIFY(!PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta3,
                                     QString(), false, QString(), &error));
    QVERIFY(error.contains(QStringLiteral("Conflicting metadata")));

    // 4. Conflicting archive pass and encryption pass
    QMap<QString, QString> meta4;
    QVERIFY(!PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta4,
                                     QStringLiteral("rar_pass"), true, QStringLiteral("enc_pass"), &error));
    QVERIFY(error.contains(QStringLiteral("Conflicting passwords")));
}

void NzbTest::deduplicatesMatchingMetadata()
{
    // If -m password matches encryption password, exactly ONE <meta type="password"> is emitted
    QMap<QString, QString> meta;
    meta.insert(QStringLiteral("password"), CmdOrGuiApp::escapeXML(QStringLiteral("my<&>pass")));
    meta.insert(QStringLiteral("yenc_encrypted"), QStringLiteral("true"));
    QString xml;
    QTextStream stream(&xml);
    QString error;
    QVERIFY(PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta,
                                    QString(), true, QStringLiteral("my<&>pass"), &error));
    QCOMPARE(xml.count(QStringLiteral("type=\"password\"")), 1);
    QCOMPARE(xml.count(QStringLiteral("type=\"yenc_encrypted\"")), 1);
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">my&lt;&amp;&gt;pass</meta>")));
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

void NzbTest::rejectsXmlUnrepresentablePasswords()
{
    // Body Std Section 4: passwords that cannot be XML 1.0 content must be refused before posting.
    const QStringList badPasswords = {
        QStringLiteral("secret") + QChar(0x01) + QStringLiteral("tail"), // C0 control
        QStringLiteral("nul") + QChar(0x00) + QStringLiteral("in"),      // NUL
        QStringLiteral("vt") + QChar(0x0B) + QStringLiteral("nope"),     // U+000B
        QStringLiteral("bad") + QChar(0xFFFE) + QStringLiteral("nc"),    // U+FFFE
        QStringLiteral("bad") + QChar(0xFFFF) + QStringLiteral("nc"),    // U+FFFF
        QString(QChar(0xD83D)) + QStringLiteral("alone"),                      // unpaired high surrogate
        QStringLiteral("alone") + QString(QChar(0xDE00)),                      // unpaired low surrogate
    };
    for (const QString &pass : badPasswords)
    {
        EncryptionSettings settings;
        settings.enabled = true;
        settings.password = pass;
        QString error;
        QVERIFY(!EncryptionSettings::isXmlRepresentable(pass));
        QVERIFY(!settings.validate(&error));
        QVERIFY(!error.isEmpty());
        // The error must never echo the password (or any fragment of it).
        QVERIFY(!error.contains(QStringLiteral("secret")));
        QVERIFY(!error.contains(QStringLiteral("alone")));
        QVERIFY(!error.contains(QStringLiteral("nope")));

        // Defence in depth: the NZB head writer refuses the same password (GUI path has no validate()).
        QMap<QString, QString> meta;
        QString xml;
        QTextStream stream(&xml);
        QString writeError;
        QVERIFY(!PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta, QString(), true, pass, &writeError));
        QVERIFY(!writeError.isEmpty());
        QVERIFY(!writeError.contains(QStringLiteral("secret")));
        QVERIFY(!xml.contains(QStringLiteral("<meta type=\"password\">")));
    }
}

void NzbTest::acceptsXmlSpecialAndSurrogatePairPasswords()
{
    // Escaped XML-special characters, a CR (written as &#xD;) and a non-BMP code point (U+1F600) are representable.
    const QString pass = QStringLiteral("a&<>\"'\U0001F600z\rq");
    QVERIFY(EncryptionSettings::isXmlRepresentable(pass));
    QVERIFY(EncryptionSettings::isXmlRepresentable(QStringLiteral("tab\tnl\ncr\r")));

    EncryptionSettings settings;
    settings.enabled = true;
    settings.password = pass;
    QString error;
    QVERIFY(settings.validate(&error));

    QMap<QString, QString> meta;
    QString xml;
    QTextStream stream(&xml);
    QString writeError;
    QVERIFY(PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta, QString(), true, pass, &writeError));
    stream.flush();
    // Password meta is XML-escaped; the emoji is carried as raw UTF-8 text; the CR is a character reference.
    QVERIFY(xml.contains(QStringLiteral("<meta type=\"password\">a&amp;&lt;&gt;&quot;&apos;\U0001F600z&#xD;q</meta>")));
    QVERIFY(!xml.contains(QStringLiteral("z\rq")));
}

void NzbTest::roundTripsPasswordMetaThroughXmlParser_data()
{
    // Body Std Section 4: each password must parse back from <meta type="password"> to exactly the KDF input.
    // Raw CR is normalized to LF by XML 1.0 parsers, so CR must be written as &#xD;.
    QTest::addColumn<QString>("password");
    QTest::newRow("cr") << QStringLiteral("x\ry");
    QTest::newRow("crlf") << QStringLiteral("x\r\ny");
    QTest::newRow("tab_lf") << QStringLiteral("a\tb\nc");
    QTest::newRow("xml_specials") << QStringLiteral("&<>\"'");
    QTest::newRow("non_bmp") << QString::fromUtf8("\xF0\x9F\x98\x80");
    QTest::newRow("replacement_char") << QString::fromUtf8("\xEF\xBF\xBD");
    QTest::newRow("private_use_e000") << QString(QChar(0xE000));
    // The CLI refuses an empty encryption password, so this row only exercises writeNzbHead directly.
    QTest::newRow("empty") << QString();
}

void NzbTest::roundTripsPasswordMetaThroughXmlParser()
{
    QFETCH(QString, password);
    QVERIFY(EncryptionSettings::isXmlRepresentable(password));

    QMap<QString, QString> meta;
    QString xml;
    QTextStream stream(&xml);
    QString writeError;
    QVERIFY2(PostingJob::writeNzbHead(stream, QStringLiteral("  "), meta, QString(), true, password, &writeError),
             qPrintable(writeError));
    stream.flush();
    QVERIFY(!xml.contains(QLatin1Char('\r')));  // no raw CR anywhere in the head

    const QString document = QStringLiteral("<nzb>") + xml + QStringLiteral("</nzb>");
    QXmlStreamReader reader(document);
    QString parsed;
    bool found = false;
    while (!reader.atEnd())
    {
        reader.readNext();
        if (reader.isStartElement() && reader.name() == QLatin1String("meta")
                && reader.attributes().value(QLatin1String("type")) == QLatin1String("password"))
        {
            parsed = reader.readElementText();
            found = true;
        }
    }
    QVERIFY2(!reader.hasError(), qPrintable(reader.errorString()));
    QVERIFY(found);
    QCOMPARE(parsed, password);
}

QTEST_APPLESS_MAIN(NzbTest)

#include "NzbTest.moc"
