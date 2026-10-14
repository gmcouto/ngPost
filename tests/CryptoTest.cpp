#include <QtTest>

#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"
#include "../src/PostingJob.h"

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

bool testDecryptBody(const QByteArray &ciphertext, const QByteArray &tag, const QByteArray &key,
                     quint32 segmentIndex, const QByteArray &aad, QByteArray &plaintext, QString *error = nullptr)
{
    plaintext.clear();
    if(key.size() != 32 || tag.size() != 16 || aad.isEmpty())
    {
        if(error) *error = QStringLiteral("Invalid parameters for body decryption");
        return false;
    }
    QByteArray nonce;
    if(!CryptoEngine::deriveBodyNonce(key, segmentIndex, nonce, error))
        return false;
    QByteArray combined = ciphertext + tag;
    plaintext.resize(ciphertext.size());
    unsigned long long decryptedLen = 0;
    const int status = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char *>(plaintext.data()), &decryptedLen,
        nullptr,
        reinterpret_cast<const unsigned char *>(combined.constData()),
        static_cast<unsigned long long>(combined.size()),
        reinterpret_cast<const unsigned char *>(aad.constData()),
        static_cast<unsigned long long>(aad.size()),
        reinterpret_cast<const unsigned char *>(nonce.constData()),
        reinterpret_cast<const unsigned char *>(key.constData()));
    if(status != 0 || decryptedLen != static_cast<unsigned long long>(ciphertext.size()))
    {
        plaintext.clear();
        if(error) *error = QStringLiteral("Authentication failed");
        return false;
    }
    return true;
}
} // namespace

class CryptoTest : public QObject
{
    Q_OBJECT

private slots:
    void controlLineVectors_data();
    void controlLineVectors();
    void fullArticlePreservesDataAndFraming();
    void generatedSaltsAreUsable();
    // Missing =yencryption header must be rejected in both directions
    void rejectsMissingEncryptionHeader();
    // Vendored canonical conformance vectors
    void vendoredArgon2idVectors();
    void vendoredNonceTweakVectors();
    void vendoredBodyEncryptionVectors();
    void vendoredIndexAllocationVectors();
    // Full-article FF1 vectors (deterministic combined-mode restoration)
    void fullArticleVectors_data();
    void fullArticleVectors();
};

void CryptoTest::controlLineVectors_data()
{
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<quint32>("lineIndex");
    QTest::addColumn<QByteArray>("expectedWire");

    // Single-line FF1 vectors read straight from the vendored fixture
    const QJsonObject data = loadVectorJson("control_line_encryption.json");
    QHash<QString, QJsonObject> byId;
    for(const QJsonValue &value : data.value(QStringLiteral("vectors")).toArray())
    {
        const QJsonObject vector = value.toObject();
        if(!vector.contains(QStringLiteral("expected_wire_hex")))
            continue;
        byId.insert(vector.value(QStringLiteral("id")).toString(), vector);
    }

    struct LineCase { const char *fixtureId; const char *row; };
    const LineCase lineCases[] = {
        {"control-vec-01-line-1-ybegin-single",   "ybegin_single"},
        {"control-vec-02-line-1-ybegin-multipart","ybegin_multipart"},
        {"control-vec-03-line-2-ypart",           "ypart"},
        {"control-vec-04-line-3-yencryption",     "yencryption"},
        {"control-vec-05-line-4-yend-single",     "yend_single"},
        {"control-vec-06-yend-multipart", "yend_multipart"},
    };
    for(const LineCase &lineCase : lineCases)
    {
        const QJsonObject vector = byId.value(QLatin1String(lineCase.fixtureId));
        QVERIFY2(!vector.isEmpty(), lineCase.fixtureId);
        QTest::newRow(lineCase.row)
                << QByteArray(vector.value(QStringLiteral("plaintext_line")).toString().toLatin1())
                << static_cast<quint32>(vector.value(QStringLiteral("line_index")).toInt())
                << QByteArray::fromHex(vector.value(QStringLiteral("expected_wire_hex")).toString().toLatin1());
    }
}

void CryptoTest::controlLineVectors()
{
    QFETCH(QByteArray, plaintext);
    QFETCH(quint32, lineIndex);
    QFETCH(QByteArray, expectedWire);

    const QByteArray salt = QByteArray::fromHex(
                loadVectorJson("control_line_encryption.json")
                    .value(QStringLiteral("vectors")).toArray().first().toObject()
                    .value(QStringLiteral("salt_hex")).toString().toLatin1());
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error), qPrintable(error));
    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptLine(plaintext, masterKey, 1, lineIndex, salt, wire, &error), qPrintable(error));
    QCOMPARE(wire, expectedWire);
    if(lineIndex == 1)
        QCOMPARE(wire.left(20), salt + QByteArray::fromHex("00000001"));
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
    const QByteArray lineEnc = QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=")
            + salt.toHex() + QByteArrayLiteral(" index=00000001 tag=24d9229edfc04aeaeedcf105bc91e695");
    const QByteArray block = line1 + "\r\n" + lineEnc + "\r\n" + line2 + "\n" + line3 + "\r\n" + line4;

    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptControlLines(block, masterKey, 1, salt, wire, &error), qPrintable(error));
    const QList<QByteArray> wireLines = wire.split('\n');
    QCOMPARE(wireLines.size(), 5);
    QCOMPARE(wireLines[2], line2);
    QCOMPARE(wireLines[3], line3 + "\r");
    QCOMPARE(wireLines[0].left(20), salt + QByteArray::fromHex("00000001"));
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

void CryptoTest::rejectsMissingEncryptionHeader()
{
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

    const QByteArray validBlock = QByteArrayLiteral("=ybegin line=128 size=4 name=file.bin\r\n")
            + QByteArrayLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=") + salt.toHex()
            + QByteArrayLiteral(" index=00000001 tag=24d9229edfc04aeaeedcf105bc91e695\r\n")
            + QByteArrayLiteral("data\r\n=yend size=4 pcrc32=12345678\r\n");
    QVERIFY2(FF1Cipher::encryptControlLines(validBlock, masterKey, 1, salt, wire, &error),
             qPrintable(error));
    QCOMPARE(wire.left(20), salt + QByteArray::fromHex("00000001"));
    const QList<QByteArray> validLines = wire.split('\n');
    QCOMPARE(validLines.size(), 5);
    QCOMPARE(validLines[2], QByteArrayLiteral("data\r"));
}

void CryptoTest::fullArticleVectors_data()
{
    QTest::addColumn<QString>("fixtureId");
    QTest::newRow("combined_one_byte") << QStringLiteral("control-vec-11-combined-one-byte-data");
    QTest::newRow("full_article_54_lines") << QStringLiteral("control-vec-08-full-article-54-lines");
    // single-part article whose name= contains " part=" must keep single-part layout (Control Std Section 9)
    QTest::newRow("single_part_name_contains_part") << QStringLiteral("control-vec-12-single-part-name-contains-part");
}

void CryptoTest::fullArticleVectors()
{
    QFETCH(QString, fixtureId);
    const QJsonObject data = loadVectorJson("control_line_encryption.json");
    QJsonObject vector;
    for(const QJsonValue &value : data.value(QStringLiteral("vectors")).toArray())
    {
        if(value.toObject().value(QStringLiteral("id")).toString() == fixtureId)
        {
            vector = value.toObject();
            break;
        }
    }
    QVERIFY2(!vector.isEmpty(), qPrintable(fixtureId));

    const QByteArray salt = QByteArray::fromHex(vector.value(QStringLiteral("salt_hex")).toString().toLatin1());
    const quint32 segmentIndex = static_cast<quint32>(vector.value(QStringLiteral("segment_index")).toInt());
    const QString password = vector.value(QStringLiteral("password")).toString();

    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(password, salt, masterKey, &error), qPrintable(error));

    QByteArray block;
    for(const QJsonValue &lineVal : vector.value(QStringLiteral("input_lines")).toArray())
    {
        block += lineVal.toString().toLatin1();
        block += "\r\n";
    }

    QByteArray wire;
    QVERIFY2(FF1Cipher::encryptControlLines(block, masterKey, segmentIndex, salt, wire, &error), qPrintable(error));

    const QJsonArray expectedWireHex = vector.value(QStringLiteral("expected_wire_lines_hex")).toArray();
    // Every line is CRLF-terminated, so strip the final terminator before splitting to get the exact count.
    QByteArray wireBody = wire;
    QVERIFY(wireBody.endsWith("\r\n"));
    wireBody.chop(2);
    const QList<QByteArray> wireLines = wireBody.split('\n');
    QCOMPARE(wireLines.size(), static_cast<int>(expectedWireHex.size()));

    for(int i = 0; i < expectedWireHex.size(); ++i)
    {
        QByteArray actual = wireLines.at(i);
        if(actual.endsWith('\r'))
            actual.chop(1);
        const QByteArray expected = QByteArray::fromHex(expectedWireHex.at(i).toString().toLatin1());
        QCOMPARE(actual, expected);
    }
}

void CryptoTest::vendoredArgon2idVectors()
{
    const QJsonArray vectors = loadVectorJson("argon2id.json").value(QStringLiteral("vectors")).toArray();
    QCOMPARE(vectors.size(), 9);
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
    QCOMPARE(vectors.size(), 9);
    for(const QJsonValue &value : vectors)
    {
        const QJsonObject vector = value.toObject();
        const QByteArray key = QByteArray::fromHex(vector.value(QStringLiteral("derived_key_hex")).toString().toLatin1());
        const quint32 segmentIndex = static_cast<quint32>(vector.value(QStringLiteral("segment_index")).toVariant().toUInt());
        const QByteArray plaintext = QByteArray::fromHex(vector.value(QStringLiteral("plaintext_hex")).toString().toLatin1());
        const QJsonObject aadObj = vector.value(QStringLiteral("aad")).toObject();
        const QByteArray expectedAad = QByteArray::fromHex(aadObj.value(QStringLiteral("expected_aad_hex")).toString().toLatin1());
        const QByteArray nameBytes = QByteArray::fromHex(aadObj.value(QStringLiteral("name_bytes_hex")).toString().toLatin1());
        // The production AAD builder must reproduce the canonical serialization.
        QCOMPARE(CryptoEngine::buildBodyAad(
                     static_cast<quint32>(aadObj.value(QStringLiteral("part_number")).toInt()),
                     static_cast<quint32>(aadObj.value(QStringLiteral("part_begin")).toInt()),
                     aadObj.value(QStringLiteral("segment_bytes")).toVariant().toULongLong(),
                     nameBytes),
                 expectedAad);
        BodyEncryptionResult encrypted;
        QString error;
        QVERIFY2(CryptoEngine::encryptBody(plaintext, key, segmentIndex, expectedAad, encrypted, &error), qPrintable(error));
        QCOMPARE(encrypted.ciphertext, QByteArray::fromHex(vector.value(QStringLiteral("expected_ciphertext_hex")).toString().toLatin1()));
        QCOMPARE(encrypted.tag, QByteArray::fromHex(vector.value(QStringLiteral("expected_tag_hex")).toString().toLatin1()));
        QCOMPARE(vector.value(QStringLiteral("expected_yencryption_line")).toString(),
                 QStringLiteral("=yencryption cipher=XChaCha20-Poly1305 salt=")
                     + vector.value(QStringLiteral("salt_hex")).toString()
                     + QStringLiteral(" index=") + vector.value(QStringLiteral("expected_index_hex")).toString()
                     + QStringLiteral(" tag=") + vector.value(QStringLiteral("expected_tag_hex")).toString());

        QByteArray restored;
        QVERIFY2(testDecryptBody(encrypted.ciphertext, encrypted.tag, key, segmentIndex, expectedAad, restored, &error),
                 qPrintable(error));
        QCOMPARE(restored, plaintext);

        QByteArray tamperedTag = encrypted.tag;
        tamperedTag[0] = static_cast<char>(tamperedTag.at(0) ^ 1);
        QVERIFY(!testDecryptBody(encrypted.ciphertext, tamperedTag, key, segmentIndex, expectedAad, restored, &error));
        QVERIFY(restored.isEmpty());
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
