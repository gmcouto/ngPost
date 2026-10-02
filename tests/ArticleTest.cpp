#include <QtTest>

#include "PostingJob.h"
#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"
#include "utils/Yenc.h"

class ArticleTest : public QObject
{
    Q_OBJECT

private slots:
    void encryptedSinglePartUsesStrictFraming();
    void encryptedMultipartUsesStrictFraming();
    void unencryptedArticleIsUnchanged();
    void segmentIndicesProgressReleaseWide();
    void segmentIndexAllocatorRejectsExhaustion();
};

void ArticleTest::encryptedSinglePartUsesStrictFraming()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, masterKey, salt, 1);

    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 1, plaintext.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QCOMPARE(crc32, quint32(0x59fb5938));
    QCOMPARE(wire.left(16), salt);
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("00000001"));

    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, encryption.masterKey, 1, restored,
                                            &extractedSalt, &extractedIndex, &error), qPrintable(error));
    QCOMPARE(extractedSalt, salt);
    QCOMPARE(extractedIndex, quint32(1));
    const QList<QByteArray> lines = restored.split('\n');
    QVERIFY(lines.size() >= 4);
    QCOMPARE(lines.at(0), QByteArrayLiteral("=ybegin line=128 size=16 name=file.bin\r"));
    QCOMPARE(lines.at(1), QByteArray("=yencryption cipher=XChaCha20-Poly1305 salt=")
             + salt.toHex() + QByteArrayLiteral(" index=00000001 tag=1d46c0a9faf019cb5c745a08e9f4462e\r"));
    QVERIFY(!restored.contains("=ypart"));
    QCOMPARE(lines.at(lines.size() - 2), QByteArrayLiteral("=yend size=16 crc32=59fb5938\r"));
}

void ArticleTest::encryptedMultipartUsesStrictFraming()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, masterKey, salt, 1);

    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 2, plaintext.size() * 2, 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QCOMPARE(wire.left(16), salt);
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("00000001"));

    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, encryption.masterKey, 1, restored,
                                            &extractedSalt, &extractedIndex, &error), qPrintable(error));
    QCOMPARE(extractedSalt, salt);
    QCOMPARE(extractedIndex, quint32(1));
    const QList<QByteArray> lines = restored.split('\n');
    QCOMPARE(lines.at(0), QByteArrayLiteral("=ybegin part=1 total=2 line=128 size=32 name=file.bin\r"));
    QCOMPARE(lines.at(1), QByteArrayLiteral("=ypart begin=1 end=16\r"));
    QCOMPARE(lines.at(2), QByteArray("=yencryption cipher=XChaCha20-Poly1305 salt=")
             + salt.toHex() + QByteArrayLiteral(" index=00000001 tag=1d46c0a9faf019cb5c745a08e9f4462e\r"));
    QCOMPARE(lines.at(lines.size() - 2), QByteArrayLiteral("=yend size=16 part=1 pcrc32=59fb5938\r"));
}

void ArticleTest::unencryptedArticleIsUnchanged()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    QByteArray article;
    quint32 crc32 = 0;
    QString error;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 1, plaintext.size(), 0, QByteArrayLiteral("file.bin"),
                                 nullptr, article, crc32, &error), qPrintable(error));
    QCOMPARE(crc32, quint32(0x615f3aca));
    QVERIFY(article.startsWith("=ybegin part=1 total=1 line=128 size=16 name=file.bin\r\n"
                               "=ypart begin=1 end=16\r\n"));
    QVERIFY(article.endsWith("\r\n=yend size=16 pcrc32=615f3aca\r\n"));
    QVERIFY(!article.contains("=yencryption"));
}

void ArticleTest::segmentIndicesProgressReleaseWide()
{
    SegmentIndexAllocator indices;
    quint32 segmentIndex = 0;
    QVERIFY(indices.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(1));
    QVERIFY(indices.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(2));
    QVERIFY(indices.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(3));
}

void ArticleTest::segmentIndexAllocatorRejectsExhaustion()
{
    SegmentIndexAllocator indices(0xffffffffU);
    quint32 segmentIndex = 0;
    QVERIFY(indices.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(0xffffffffU));
    QVERIFY(!indices.next(segmentIndex));
}

QTEST_APPLESS_MAIN(ArticleTest)

#include "ArticleTest.moc"
