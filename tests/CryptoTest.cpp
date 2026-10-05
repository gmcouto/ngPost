#include <QtTest>

#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"

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
    void hmacAndKeyDerivationSanity();
    void cryptographicEdgeCases();
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
            << QByteArray::fromHex("4b376d5839704c32715238764e34775a3ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
    QTest::newRow("ypart")
            << QByteArray("=ypart begin=1 end=700000")
            << quint32(2)
            << QByteArray::fromHex("2135072cf2b566804a99bd31fe1d42b2603a7518ae20a58498");
    QTest::newRow("yencryption")
            << QByteArray("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b")
            << quint32(3)
            << QByteArray::fromHex("72944db7426759aff6f27824ee38058d141a1a4a1ac080d4d828b846ccdeb2b978d88a6ffd4fa429ba2cc8a5424ac5e764786ec4aecf9024c59dcde8dae191553185af39ee7bbed0c7c6cbf1f74441c8c2d1f7765017357436500472ac212d1055dbc707af61306e409e180e1f311c9c87");
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
    QVERIFY2(FF1Cipher::decryptLine(wire, masterKey, 1, lineIndex, restored, &extractedSalt, &error),
             qPrintable(error));
    QCOMPARE(restored, plaintext);
    if(lineIndex == 1)
        QCOMPARE(extractedSalt, salt);
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
    const QByteArray block = line1 + "\r\n" + line2 + "\n" + line3 + "\r\n" + line4;

    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptControlLines(block, masterKey, 1, salt, wire, &error), qPrintable(error));
    const QList<QByteArray> wireLines = wire.split('\n');
    QCOMPARE(wireLines.size(), 4);
    QCOMPARE(wireLines[1], line2);
    QCOMPARE(wireLines[2], line3 + "\r");
    QCOMPARE(wireLines[0].left(16), salt);

    QByteArray restored;
    QByteArray extractedSalt;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 1, restored, &extractedSalt, &error),
             qPrintable(error));
    QCOMPARE(restored, block);
    QCOMPARE(extractedSalt, salt);
}

void CryptoTest::rejectsDualSaltMismatch()
{
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error));
    const QByteArray block = QByteArrayLiteral("=ybegin line=128 size=18 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b\r\n")
            + QByteArrayLiteral("data\r\n=yend size=18\r\n");
    QByteArray wire;
    QVERIFY(!FF1Cipher::encryptControlLines(block, masterKey, 1, salt, wire, &error));
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

void CryptoTest::hmacAndKeyDerivationSanity()
{
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    CryptoKeys keys;
    QString error;
    QVERIFY2(CryptoEngine::deriveKeys(QStringLiteral("test123"), salt, keys, &error), qPrintable(error));
    QCOMPARE(keys.masterKey.size(), 32);
    QCOMPARE(keys.bodyKey.size(), 32);
    QCOMPARE(keys.controlKey.size(), 32);
    QVERIFY(keys.masterKey != keys.controlKey);

    QByteArray nonce;
    QVERIFY2(CryptoEngine::deriveBodyNonce(keys.bodyKey, 1, nonce, &error), qPrintable(error));
    QCOMPARE(nonce.size(), 24);

    QByteArray tweak;
    QVERIFY2(CryptoEngine::deriveControlTweak(keys.masterKey, 1, 1, tweak, &error), qPrintable(error));
    QCOMPARE(tweak.size(), 8);
}

void CryptoTest::cryptographicEdgeCases()
{
    // GAP-34-06: Zero-payload, max uint32 index, and corrupted tag rejection
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    CryptoKeys keys;
    QString error;
    QVERIFY(CryptoEngine::deriveKeys(QStringLiteral("edgecases123"), salt, keys, &error));

    // Zero-length payload encryption
    const QByteArray emptyPlaintext;
    BodyEncryptionResult emptyResult;
    QVERIFY2(CryptoEngine::encryptBody(emptyPlaintext, keys.bodyKey, 1, emptyResult, &error),
             qPrintable(error));
    QCOMPARE(emptyResult.ciphertext.size(), 0);
    QCOMPARE(emptyResult.tag.size(), 16);

    // Max uint32 segment index
    BodyEncryptionResult maxResult;
    QVERIFY2(CryptoEngine::encryptBody(QByteArray("test"), keys.bodyKey, 0xffffffffU,
                                       maxResult, &error), qPrintable(error));
    QCOMPARE(maxResult.ciphertext.size(), 4);
    QCOMPARE(maxResult.tag.size(), 16);

    // Corrupted tag rejection
    QByteArray corruptedTag = maxResult.tag;
    corruptedTag[0] = static_cast<char>(corruptedTag[0] ^ 0x01);
    QByteArray decrypted;
    QVERIFY(!CryptoEngine::decryptBody(maxResult.ciphertext, corruptedTag, keys.bodyKey,
                                       0xffffffffU, decrypted, &error));
    QVERIFY(decrypted.isEmpty());
}

QTEST_APPLESS_MAIN(CryptoTest)

#include "CryptoTest.moc"
