#include <QtTest>

#include "PostingJob.h"
#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"
#include "utils/Yenc.h"

class ArticleTest : public QObject
{
    Q_OBJECT

private slots:
    void encryptedArticleUsesCiphertextCrc();
    void unencryptedArticleIsUnchanged();
    void segmentIndicesProgressReleaseWide();
};

void ArticleTest::encryptedArticleUsesCiphertextCrc()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    YencEncryptionContext encryption;
    encryption.salt = salt;
    encryption.segmentIndex = 1;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, encryption.masterKey, &error),
             qPrintable(error));
    encryption.bodyKey = encryption.masterKey;

    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 1, plaintext.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QCOMPARE(crc32, quint32(0x59fb5938));
    QVERIFY(!wire.contains("=yencryption"));
    QVERIFY(!wire.contains("=ybegin"));
    QCOMPARE(wire.left(16), salt);

    QByteArray restored;
    QByteArray extractedSalt;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, encryption.masterKey, 1, restored,
                                            &extractedSalt, &error), qPrintable(error));
    QCOMPARE(extractedSalt, salt);
    const QList<QByteArray> lines = restored.split('\n');
    QVERIFY(lines.size() >= 5);
    QVERIFY(lines.at(0).startsWith("=ybegin "));
    QVERIFY(lines.at(1).startsWith("=ypart "));
    QCOMPARE(lines.at(2), QByteArray("=yencryption cipher=XChaCha20-Poly1305 salt=")
             + salt.toHex() + QByteArrayLiteral(" tag=1d46c0a9faf019cb5c745a08e9f4462e\r"));
    QVERIFY(lines.at(lines.size() - 2).contains("pcrc32=59fb5938"));
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

QTEST_APPLESS_MAIN(ArticleTest)

#include "ArticleTest.moc"
