#include <QtTest>

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

QTEST_APPLESS_MAIN(NzbTest)

#include "NzbTest.moc"
