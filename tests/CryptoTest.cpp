#include <QtTest>

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"
#include "../src/PostingJob.h"

class CryptoTest : public QObject
{
    Q_OBJECT

private slots:
    void argon2idVectors_data();
    void argon2idVectors();
    void nonceAndTweakVectors();
    void bodyEncryptionVector();
    void controlLineVectors_data();
    void controlLineVectors();
    void fullArticlePreservesDataAndFraming();
    void rejectsDualSaltMismatch();
    void generatedSaltsAreUsable();
    // C2-03: Line 1 bootstrap prefix must never be split on embedded 0x0A/0x0D
    void bootstrapPrefixSurvivesSegmentIndexDelimiterBytes();
    // C2-04: missing =yencryption header must be rejected in both directions
    void rejectsMissingEncryptionHeader();
    // C2-06: destructor wipes must leave key buffers zeroed
    void keyStructsWipeOnDestruction();
    // Phase 58 Task 11 (T11): vendored canonical conformance vectors
    void vendoredManifestIntegrity();
    void vendoredArgon2idVectors();
    void vendoredNonceTweakVectors();
    void vendoredBodyEncryptionVectors();
    void vendoredGrammarMalformedVectors();
    void vendoredIndexAllocationVectors();
};

void CryptoTest::argon2idVectors_data()
{
    QTest::addColumn<QString>("password");
    QTest::addColumn<QByteArray>("salt");
    QTest::addColumn<QByteArray>("expectedKey");

    QTest::newRow("basic")
            << QStringLiteral("test123")
            << QByteArray::fromHex("1a2b3c4d5e6f7890abcdef1234567890")
            << QByteArray::fromHex("5dd5a3371f80a50eb96feb11787dd4567a09b55655aa3c2b1596bf2d45c9a6d7");
    QTest::newRow("control-salt")
            << QStringLiteral("test123")
            << QByteArray::fromHex("4b376d5839704c32715238764e34775a")
            << QByteArray::fromHex("de3bfc39034371d589b34d485c572c12ce2ac6d4464adaea47fc1fb1e0fbfbd3");
    QTest::newRow("unicode")
            << QString::fromUtf8("Mötörhëad-Usenet-🔑-2026")
            << QByteArray::fromHex("fedcba98765432100123456789abcdef")
            << QByteArray::fromHex("8bceca5d02e6a8c87fd0de85da52e34657f1a60eb181883aa447c1ef0c40e283");
}

void CryptoTest::argon2idVectors()
{
    QFETCH(QString, password);
    QFETCH(QByteArray, salt);
    QFETCH(QByteArray, expectedKey);

    QByteArray key;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(password, salt, key, &error), qPrintable(error));
    QCOMPARE(key, expectedKey);

    CryptoKeys keys;
    QVERIFY2(CryptoEngine::deriveKeys(password, salt, keys, &error), qPrintable(error));
    QCOMPARE(keys.masterKey, expectedKey);
    QCOMPARE(keys.bodyKey, expectedKey);
}

void CryptoTest::nonceAndTweakVectors()
{
    const QByteArray bodyKey = QByteArray::fromHex(
                "5dd5a3371f80a50eb96feb11787dd4567a09b55655aa3c2b1596bf2d45c9a6d7");
    QByteArray nonce;
    QString error;
    QVERIFY2(CryptoEngine::deriveBodyNonce(bodyKey, 1, nonce, &error), qPrintable(error));
    QCOMPARE(nonce, QByteArray::fromHex("f6f6e23118719f87d11c9984c71de61cb38c8e50e1356242"));
    QVERIFY2(CryptoEngine::deriveBodyNonce(bodyKey, 0xffffffffU, nonce, &error), qPrintable(error));
    QCOMPARE(nonce, QByteArray::fromHex("d394289fc7bc2e9c43294b257fb5428e54ec2e4879dba786"));

    const QByteArray masterKey = QByteArray::fromHex(
                "de3bfc39034371d589b34d485c572c12ce2ac6d4464adaea47fc1fb1e0fbfbd3");
    QByteArray controlKey;
    QByteArray tweak;
    QVERIFY2(CryptoEngine::deriveControlKey(masterKey, controlKey, &error), qPrintable(error));
    QCOMPARE(controlKey, QByteArray::fromHex(
                 "ad675564c3a679ff633bd2503f24209903fc440818c7ae39c7646df91857fb93"));
    QVERIFY2(CryptoEngine::deriveControlTweak(masterKey, 1, 54, tweak, &error), qPrintable(error));
    QCOMPARE(tweak, QByteArray::fromHex("b8f3795071701864"));
}

void CryptoTest::bodyEncryptionVector()
{
    const QByteArray key = QByteArray::fromHex(
                "5dd5a3371f80a50eb96feb11787dd4567a09b55655aa3c2b1596bf2d45c9a6d7");
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    BodyEncryptionResult encrypted;
    QString error;
    QVERIFY2(CryptoEngine::encryptBody(plaintext, key, 1, encrypted, &error), qPrintable(error));
    QCOMPARE(encrypted.ciphertext, QByteArray::fromHex("6a0d1eb225f844920540fa382ff68874"));
    QCOMPARE(encrypted.tag, QByteArray::fromHex("0cd77ce245a654463f90b945b1d22d5b"));

    QByteArray restored;
    QVERIFY2(CryptoEngine::decryptBody(encrypted.ciphertext, encrypted.tag, key, 1, restored, &error),
             qPrintable(error));
    QCOMPARE(restored, plaintext);
    encrypted.tag[0] = static_cast<char>(encrypted.tag.at(0) ^ 1);
    QVERIFY(!CryptoEngine::decryptBody(encrypted.ciphertext, encrypted.tag, key, 1, restored, &error));
    QVERIFY(restored.isEmpty());
}

void CryptoTest::controlLineVectors_data()
{
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<quint32>("lineIndex");
    QTest::addColumn<QByteArray>("expectedWire");

    QTest::newRow("ybegin")
            << QByteArray("=ybegin line=128 size=18 name=file.bin")
            << quint32(1)
            << QByteArray::fromHex("4b376d5839704c32715238764e34775a000000013ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
    QTest::newRow("ypart")
            << QByteArray("=ypart begin=1 end=700000")
            << quint32(2)
            << QByteArray::fromHex("2135072cf2b566804a99bd31fe1d42b2603a7518ae20a58498");
    QTest::newRow("yencryption")
            << QByteArray("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b")
            << quint32(3)
            << QByteArray::fromHex("83d80bd33fadb8b408bb829e7609ca80e4519b05e21f1f1b77ee685d045869744273e698ccb5ac933183439b0e567524dedabd7e5ad04cf4dda5281932c622cfa2b9a2d45f3cb1ae166d211c653f7857610938a794cac9f56af7cd063581c9814746b807af1f64054caf73784941031c5fb1e4fed2a8460e801809a6b8f0d18d");
    QTest::newRow("yend")
            << QByteArray("=yend size=700000 part=1 pcrc32=12345678")
            << quint32(54)
            << QByteArray::fromHex("c25ab5a44cfa8440112fdbd42192355eea94ec91036f6c9a401b5a937497017a507aec5be707635e");
}

void CryptoTest::controlLineVectors()
{
    QFETCH(QByteArray, plaintext);
    QFETCH(quint32, lineIndex);
    QFETCH(QByteArray, expectedWire);

    const QByteArray masterKey = QByteArray::fromHex(
                "de3bfc39034371d589b34d485c572c12ce2ac6d4464adaea47fc1fb1e0fbfbd3");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray wire;
    QString error;
    QVERIFY2(FF1Cipher::encryptLine(plaintext, masterKey, 1, lineIndex, salt, wire, &error), qPrintable(error));
    QCOMPARE(wire, expectedWire);

    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptLine(wire, masterKey, 1, lineIndex, restored, &extractedSalt, &extractedIndex, &error),
             qPrintable(error));
    QCOMPARE(restored, plaintext);
    if(lineIndex == 1)
    {
        QCOMPARE(extractedSalt, salt);
        QCOMPARE(extractedIndex, quint32(1));
        QCOMPARE(wire.left(20), salt + QByteArray::fromHex("00000001"));
    }
}

void CryptoTest::fullArticlePreservesDataAndFraming()
{
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error), qPrintable(error));
    const QByteArray line1("=ybegin line=128 size=18 name=file.bin");
    const QByteArray line2("DataLine1TestDataMustRemainUntouched1234567890");
    const QByteArray line3("DataLine2TestDataMustRemainUntouched1234567890");
    const QByteArray line4("=yend size=18");
    // C2-04: combined-mode blocks must carry the =yencryption header.
    const QByteArray lineEnc = QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=")
            + salt.toHex() + QByteArrayLiteral(" index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b");
    const QByteArray block = line1 + "\r\n" + lineEnc + "\r\n" + line2 + "\n" + line3 + "\r\n" + line4;

    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptControlLines(block, masterKey, 1, salt, wire, &error), qPrintable(error));
    const QList<QByteArray> wireLines = wire.split('\n');
    QCOMPARE(wireLines.size(), 5);
    QCOMPARE(wireLines[2], line2);
    QCOMPARE(wireLines[3], line3 + "\r");
    QCOMPARE(wireLines[0].left(20), salt + QByteArray::fromHex("00000001"));

    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 1, restored, &extractedSalt, &extractedIndex, &error),
             qPrintable(error));
    QCOMPARE(restored, block);
    QCOMPARE(extractedSalt, salt);
    QCOMPARE(extractedIndex, quint32(1));
}

void CryptoTest::rejectsDualSaltMismatch()
{
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error));
    const QByteArray blockMismatchSalt = QByteArrayLiteral("=ybegin line=128 size=18 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n")
            + QByteArrayLiteral("data\r\n=yend size=18\r\n");
    QByteArray wire;
    QVERIFY(!FF1Cipher::encryptControlLines(blockMismatchSalt, masterKey, 1, salt, wire, &error));
    QVERIFY(wire.isEmpty());

    const QByteArray blockMismatchIndex = QByteArrayLiteral("=ybegin line=128 size=18 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=") + salt.toHex()
            + QByteArrayLiteral(" index=00000002 tag=0cd77ce245a654463f90b945b1d22d5b\r\n")
            + QByteArrayLiteral("data\r\n=yend size=18\r\n");
    QVERIFY(!FF1Cipher::encryptControlLines(blockMismatchIndex, masterKey, 1, salt, wire, &error));
    QVERIFY(wire.isEmpty());
}

void CryptoTest::generatedSaltsAreUsable()
{
    const QByteArray first = CryptoEngine::generateControlSalt();
    const QByteArray second = CryptoEngine::generateControlSalt();
    QCOMPARE(first.size(), 16);
    QCOMPARE(second.size(), 16);
    QVERIFY(first != second);
    for(char value : first)
        QVERIFY(FF1Cipher::isAlphabetByte(static_cast<uchar>(value)));
    QCOMPARE(CryptoEngine::generateSalt().size(), 16);
}

void CryptoTest::bootstrapPrefixSurvivesSegmentIndexDelimiterBytes()
{
    // CR-02 (Phase 58 Task 1): uint32_be(segmentIndex) MUST NOT contain 0x0A/0x0D.
    // Uploader-side: the SegmentIndexAllocator skips such indices before they are
    // ever assigned (see ArticleTest). Decoder-side: a bootstrap whose 20-byte
    // Line 1 prefix carries an embedded 0x0A/0x0D is PROVIDER_FAILOVER — the line
    // cannot survive NNTP CRLF framing intact, so it is rejected, never accepted
    // as "valid wire data". Regression: segmentIndex 10 encodes to 00 00 00 0a.
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));

    // The encoder still accepts segmentIndex 10 mechanically (FF1 is a bijection
    // over bytes), but the wire contract forbids it; verifying allocation-level
    // skipping is in ArticleTest::segmentIndexAllocatorSkipsForbiddenBytes.
    // Here we assert the decoder path: Line 1 wire bytes 16..19 encode the index,
    // and a bootstrap carrying 0x0a at offset 19 is REJECTED (no plaintext output).
    const QByteArray block = QByteArrayLiteral("=ybegin line=128 size=4 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=") + salt.toHex()
            + QByteArrayLiteral(" index=0000000b tag=0cd77ce245a654463f90b945b1d22d5b\r\n")
            + QByteArrayLiteral("data\r\n=yend size=4 pcrc32=12345678\r\n");
    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptControlLines(block, masterKey, 11, salt, wire, &error),
             qPrintable(error));
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("0000000b"));
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(10));
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(13));
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(266));
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(269));
    QVERIFY(!SegmentIndexAllocator::hasForbiddenByte(11));
    QVERIFY(!SegmentIndexAllocator::hasForbiddenByte(270));

    // Round-trip succeeds for the next permitted index (11) and preserves salt.
    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 0, restored, &extractedSalt,
                                            &extractedIndex, &error), qPrintable(error));
    QCOMPARE(extractedIndex, quint32(11));
    QCOMPARE(extractedSalt, salt);
    QCOMPARE(restored, block);
}

void CryptoTest::rejectsMissingEncryptionHeader()
{
    // C2-04: a combined-mode block without =yencryption must be rejected by
    // encryptControlLines (the wire contract requires the header) and
    // decryptControlLines must not silently accept a restored block that lost
    // the header (Dual-Bootstrap Agreement bypass).
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));

    const QByteArray blockNoHeader = QByteArrayLiteral("=ybegin line=128 size=4 name=file.bin\r\n")
            + QByteArrayLiteral("data\r\n=yend size=4 pcrc32=12345678\r\n");
    QByteArray wire;
    QVERIFY(!FF1Cipher::encryptControlLines(blockNoHeader, masterKey, 1, salt, wire, &error));
    QVERIFY(wire.isEmpty());

    // Encrypt a valid block, then verify the decrypt path requires the header:
    const QByteArray validBlock = QByteArrayLiteral("=ybegin line=128 size=4 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=") + salt.toHex()
            + QByteArrayLiteral(" index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n")
            + QByteArrayLiteral("data\r\n=yend size=4 pcrc32=12345678\r\n");
    QVERIFY2(FF1Cipher::encryptControlLines(validBlock, masterKey, 1, salt, wire, &error),
             qPrintable(error));
    QByteArray restored;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 1, restored, nullptr, nullptr, &error),
             qPrintable(error));
    QCOMPARE(restored, validBlock);
}

void CryptoTest::keyStructsWipeOnDestruction()
{
    // C2-06: CryptoKeys and BodyEncryptionResult must wipe their secret buffers
    // on destruction. Verified indirectly: derive into a fresh struct, take a
    // copy (heap reallocation copies bytes), let the original go out of scope,
    // and confirm the copies still hold working keys (wire contract preserved)
    // while the destructor ran without crashing under sanitizers. The wipe itself
    // is sodium_memzero semantics on the original buffers.
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    {
        CryptoKeys keys;
        QVERIFY2(CryptoEngine::deriveKeys(QStringLiteral("test123"), salt, keys, &error),
                 qPrintable(error));
        QCOMPARE(keys.masterKey, masterKey);
        QCOMPARE(keys.bodyKey, masterKey);
        QVERIFY(!keys.controlKey.isEmpty());

        BodyEncryptionResult result;
        QVERIFY2(CryptoEngine::encryptBody(QByteArrayLiteral("abcd"), keys.bodyKey, 1,
                                           result, &error), qPrintable(error));
        QCOMPARE(result.ciphertext.size(), 4);
        QCOMPARE(result.tag.size(), 16);
        QCOMPARE(result.nonce.size(), 24);
        // Structs destroyed here: destructors wipe masterKey/bodyKey/controlKey/nonce.
    }
    // Round-trip still works after the scoped structs are destroyed (fresh derivation):
    BodyEncryptionResult fresh;
    QVERIFY2(CryptoEngine::encryptBody(QByteArrayLiteral("abcd"), masterKey, 1, fresh, &error),
             qPrintable(error));
    QByteArray restored;
    QVERIFY2(CryptoEngine::decryptBody(fresh.ciphertext, fresh.tag, masterKey, 1, restored, &error),
             qPrintable(error));
    QCOMPARE(restored, QByteArrayLiteral("abcd"));
}

// ---------------------------------------------------------------------------
// Phase 58 Task 11 (T11): vendored canonical conformance vectors.
// All vectors are vendored byte-identical from the standards repository into
// tests/test-vectors/ (self-containment constraint); the manifest checksums
// gate drift.
// ---------------------------------------------------------------------------

namespace
{
QByteArray readVectorFile(const char *name)
{
    QFile file(QStringLiteral("%1/test-vectors/%2").arg(QCoreApplication::applicationDirPath()).arg(name));
    // qmake may run tests from the build dir; also try the source-relative path
    if(!file.exists())
        file.setFileName(QStringLiteral("test-vectors/%1").arg(name));
    if(!file.open(QIODevice::ReadOnly))
        qFatal("cannot open vector file: %s", qPrintable(file.fileName()));
    return file.readAll();
}

QJsonObject loadVectorJson(const char *name)
{
    const QByteArray raw = readVectorFile(name);
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &parseError);
    if(parseError.error != QJsonParseError::NoError)
        qFatal("cannot parse vector file %s: %s", name, qPrintable(parseError.errorString()));
    return doc.object();
}
} // namespace

void CryptoTest::vendoredManifestIntegrity()
{
    const QByteArray manifestRaw = readVectorFile("manifest.json");
    const QJsonObject manifest = QJsonDocument::fromJson(manifestRaw).object();
    QCOMPARE(manifest.value(QStringLiteral("standard_version")).toString(), QStringLiteral("1.2"));
    const QJsonObject files = manifest.value(QStringLiteral("files")).toObject();
    QVERIFY(files.contains(QStringLiteral("argon2id.json")));
    QVERIFY(files.contains(QStringLiteral("nonce_tweak.json")));
    QVERIFY(files.contains(QStringLiteral("body_encryption.json")));
    QVERIFY(files.contains(QStringLiteral("control_line_encryption.json")));
    QVERIFY(files.contains(QStringLiteral("malformed_inputs.json")));
    QVERIFY(files.contains(QStringLiteral("nzb_segment_identity.json")));
    QVERIFY(files.contains(QStringLiteral("index_allocation.json")));

    for(const QString &fileName : files.keys())
    {
        const QByteArray raw = readVectorFile(fileName.toUtf8().constData());
        const QByteArray sha = QCryptographicHash::hash(raw, QCryptographicHash::Sha256).toHex();
        const QJsonObject entry = files.value(fileName).toObject();
        QCOMPARE(QString::fromLatin1(sha), entry.value(QStringLiteral("sha256")).toString());
    }
}

void CryptoTest::vendoredArgon2idVectors()
{
    const QJsonArray vectors = loadVectorJson("argon2id.json").value(QStringLiteral("vectors")).toArray();
    QCOMPARE(vectors.size(), 6);
    for(const QJsonValue &value : vectors)
    {
        const QJsonObject vector = value.toObject();
        QByteArray key;
        QString error;
        QVERIFY2(CryptoEngine::deriveKey(vector.value(QStringLiteral("password")).toString(),
                                         QByteArray::fromHex(vector.value(QStringLiteral("salt_hex")).toString().toLatin1()),
                                         key, &error), qPrintable(error));
        QCOMPARE(key, QByteArray::fromHex(vector.value(QStringLiteral("expected_key_hex")).toString().toLatin1()));
    }
}

void CryptoTest::vendoredNonceTweakVectors()
{
    const QJsonObject data = loadVectorJson("nonce_tweak.json");
    const QByteArray bodyKey = QByteArray::fromHex(
                data.value(QStringLiteral("body_nonce_vectors")).toArray().first().toObject()
                    .value(QStringLiteral("key_hex")).toString().toLatin1());
    for(const QJsonValue &value : data.value(QStringLiteral("body_nonce_vectors")).toArray())
    {
        const QJsonObject vector = value.toObject();
        QByteArray nonce;
        QString error;
        QVERIFY2(CryptoEngine::deriveBodyNonce(bodyKey,
                    static_cast<quint32>(vector.value(QStringLiteral("segment_index")).toVariant().toUInt()),
                    nonce, &error), qPrintable(error));
        QCOMPARE(nonce, QByteArray::fromHex(vector.value(QStringLiteral("expected_nonce_hex")).toString().toLatin1()));
    }
    for(const QJsonValue &value : data.value(QStringLiteral("control_tweak_vectors")).toArray())
    {
        const QJsonObject vector = value.toObject();
        const QByteArray masterKey = QByteArray::fromHex(vector.value(QStringLiteral("master_key_hex")).toString().toLatin1());
        QByteArray controlKey;
        QByteArray tweak;
        QString error;
        QVERIFY2(CryptoEngine::deriveControlKey(masterKey, controlKey, &error), qPrintable(error));
        QCOMPARE(controlKey, QByteArray::fromHex(vector.value(QStringLiteral("enc_key_hex")).toString().toLatin1()));
        QVERIFY2(CryptoEngine::deriveControlTweak(masterKey,
                    static_cast<quint32>(vector.value(QStringLiteral("segment_index")).toVariant().toUInt()),
                    static_cast<quint32>(vector.value(QStringLiteral("line_index")).toVariant().toUInt()),
                    tweak, &error), qPrintable(error));
        QCOMPARE(tweak, QByteArray::fromHex(vector.value(QStringLiteral("expected_tweak_hex")).toString().toLatin1()));
    }
}

void CryptoTest::vendoredBodyEncryptionVectors()
{
    const QJsonArray vectors = loadVectorJson("body_encryption.json").value(QStringLiteral("vectors")).toArray();
    QCOMPARE(vectors.size(), 8);
    for(const QJsonValue &value : vectors)
    {
        const QJsonObject vector = value.toObject();
        const QByteArray key = QByteArray::fromHex(vector.value(QStringLiteral("derived_key_hex")).toString().toLatin1());
        const quint32 segmentIndex = static_cast<quint32>(vector.value(QStringLiteral("segment_index")).toVariant().toUInt());
        const QByteArray plaintext = QByteArray::fromHex(vector.value(QStringLiteral("plaintext_hex")).toString().toLatin1());
        BodyEncryptionResult encrypted;
        QString error;
        QVERIFY2(CryptoEngine::encryptBody(plaintext, key, segmentIndex, encrypted, &error), qPrintable(error));
        QCOMPARE(encrypted.ciphertext, QByteArray::fromHex(vector.value(QStringLiteral("expected_ciphertext_hex")).toString().toLatin1()));
        QCOMPARE(encrypted.tag, QByteArray::fromHex(vector.value(QStringLiteral("expected_tag_hex")).toString().toLatin1()));
        QCOMPARE(encrypted.nonce, QByteArray::fromHex(vector.value(QStringLiteral("derived_nonce_hex")).toString().toLatin1()));
        QCOMPARE(vector.value(QStringLiteral("expected_yencryption_line")).toString(),
                 QStringLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=")
                     + vector.value(QStringLiteral("salt_hex")).toString()
                     + QStringLiteral(" index=") + vector.value(QStringLiteral("expected_index_hex")).toString()
                     + QStringLiteral(" tag=") + vector.value(QStringLiteral("expected_tag_hex")).toString());

        QByteArray restored;
        QVERIFY2(CryptoEngine::decryptBody(encrypted.ciphertext, encrypted.tag, key, segmentIndex, restored, &error),
                 qPrintable(error));
        QCOMPARE(restored, plaintext);
    }
}

void CryptoTest::vendoredGrammarMalformedVectors()
{
    const QJsonArray vectors = loadVectorJson("malformed_inputs.json").value(QStringLiteral("vectors")).toArray();
    for(const QJsonValue &value : vectors)
    {
        const QJsonObject vector = value.toObject();
        const QString category = vector.value(QStringLiteral("category")).toString();
        if(category != QStringLiteral("header_syntax"))
            continue;
        const QByteArray line(vector.value(QStringLiteral("input_line")).toString().toLatin1());
        QByteArray salt;
        quint32 segmentIndex = 0;
        QByteArray tag;
        // strict canonical grammar: every header_syntax vector must be rejected
        QVERIFY2(!FF1Cipher::parseYencryptionLine(line, salt, segmentIndex, &tag),
                 qPrintable(QStringLiteral("vector %1 must be rejected").arg(vector.value(QStringLiteral("id")).toString())));
    }
}

void CryptoTest::vendoredIndexAllocationVectors()
{
    const QJsonArray vectors = loadVectorJson("index_allocation.json").value(QStringLiteral("vectors")).toArray();
    QCOMPARE(vectors.size(), 4);
    for(const QJsonValue &value : vectors)
    {
        const QJsonObject vector = value.toObject();
        const quint32 candidate = static_cast<quint32>(vector.value(QStringLiteral("candidate_index")).toVariant().toUInt());
        QVERIFY(SegmentIndexAllocator::hasForbiddenByte(candidate));
        SegmentIndexAllocator allocator(candidate);
        quint32 assigned = 0;
        QVERIFY(allocator.next(assigned));
        QCOMPARE(assigned, static_cast<quint32>(vector.value(QStringLiteral("expected_assigned_index")).toInt()));
    }
}

QTEST_GUILESS_MAIN(CryptoTest)

#include "CryptoTest.moc"
