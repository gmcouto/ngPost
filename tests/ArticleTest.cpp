#include <QtTest>

#include <sstream>

#include "PostingJob.h"
#include "crypto/CryptoEngine.h"
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
    // Index framing rule: allocator must skip indices whose uint32_be contains 0x0A/0x0D
    void segmentIndexAllocatorSkipsForbiddenBytes();
    // Worst-case escape payloads must not overflow the encode buffer
    void worstCaseEscapePayloadDoesNotOverflow();
    // Exact-128-column wrap and empty payloads must not inject blank lines
    void exactWrapAndEmptyPayloadPreserveSingleCrlf();
};

void ArticleTest::encryptedSinglePartUsesStrictFraming()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, salt, 1);

    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 1, plaintext.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(crc32 != 0);
    QCOMPARE(wire.left(16), salt);
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("00000001"));
    QVERIFY(!wire.contains("=ybegin"));
    QVERIFY(!wire.contains("=ypart"));
    QVERIFY(!wire.contains("=yend"));
    const QList<QByteArray> lines = wire.split('\n');
    QVERIFY(lines.size() >= 3);
}

void ArticleTest::encryptedMultipartUsesStrictFraming()
{
    const QByteArray plaintext = QByteArray::fromHex("48656c6c6f20576f726c642e747874ff");
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, salt, 1);

    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(plaintext, 1, 2, plaintext.size() * 2, 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(crc32 != 0);
    QCOMPARE(wire.left(16), salt);
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("00000001"));
    QVERIFY(!wire.contains("=ybegin"));
    QVERIFY(!wire.contains("=ypart"));
    QVERIFY(!wire.contains("=yend"));
    const QList<QByteArray> lines = wire.split('\n');
    QVERIFY(lines.size() >= 4);
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

    quint32 expectedCrc = 0xFFFFFFFF;
    uchar *yencBody = new uchar[plaintext.size() * 2];
    Yenc::encode(plaintext.constData(), plaintext.size(), yencBody, expectedCrc);
    std::stringstream ss;
    ss << "=ybegin part=1 total=1 line=128 size=16 name=file.bin\r\n"
       << "=ypart begin=1 end=16\r\n"
       << yencBody << "\r\n"
       << "=yend size=16 pcrc32=" << std::hex << expectedCrc << "\r\n";
    delete[] yencBody;

    QCOMPARE(article, QByteArray::fromStdString(ss.str()));
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

void ArticleTest::segmentIndexAllocatorSkipsForbiddenBytes()
{
    // Index framing rule: indices whose uint32_be encoding contains 0x0A
    // or 0x0D would split the Line 1 bootstrap on the wire and must be skipped.
    // Canonical index_allocation.json vectors: candidates 10, 13, 266, 269.
    quint32 segmentIndex = 0;

    // candidate 10 -> assigned 11
    SegmentIndexAllocator skipTen(10);
    QVERIFY(skipTen.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(11));

    // candidate 13 -> assigned 14
    SegmentIndexAllocator skipThirteen(13);
    QVERIFY(skipThirteen.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(14));

    // candidate 266 (0x0000010A) -> assigned 267
    SegmentIndexAllocator skip266(266);
    QVERIFY(skip266.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(267));

    // candidate 269 (0x0000010D) -> assigned 270
    SegmentIndexAllocator skip269(269);
    QVERIFY(skip269.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(270));

    // forbidden byte in any of the four positions
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(0x0A000000U));
    QVERIFY(SegmentIndexAllocator::hasForbiddenByte(0x000D0000U));
    QVERIFY(!SegmentIndexAllocator::hasForbiddenByte(0xFFFFFFFFU));

    // consecutive allocation crossing forbidden values: 8, 9 -> 11 (10 skipped)
    SegmentIndexAllocator cross(8);
    QVERIFY(cross.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(8));
    QVERIFY(cross.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(9));
    QVERIFY(cross.next(segmentIndex));
    QCOMPARE(segmentIndex, quint32(11));
}

void ArticleTest::worstCaseEscapePayloadDoesNotOverflow()
{
    // A payload of bytes that all require escaping (0xD6 -> (0xD6+42)&0xFF == 0x00,
    // 0xED -> '=', 0x00 -> '\n') used to overflow the encode destination buffer
    // (size*2+4) because CRLF line terminators were not budgeted. The fixed
    // allocation covers 2N + N/32 + 64 bytes; this test fails under the old
    // allocation (heap-buffer-overflow detected by sanitizers) and must pass now.
    QByteArray payload;
    payload.resize(1000);
    for(int i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>(i % 3 == 0 ? char(0xD6) : (i % 3 == 1 ? char(0xED) : char(0x00)));

    QByteArray article;
    quint32 crc32 = 0;
    QString error;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 nullptr, article, crc32, &error), qPrintable(error));
    // Article must be well-formed and parseable by FF1's plain (unencrypted) framing:
    QVERIFY(article.startsWith("=ybegin part=1 total=1 line=128 size=1000 name=file.bin\r\n"));
    QVERIFY(article.endsWith("\r\n"));
    QVERIFY(article.contains("=yend size=1000 pcrc32="));

    // Encrypted path with the same hostile payload:
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, salt, 1);
    QByteArray wire;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(wire.left(16) == salt);
    QVERIFY(wire.mid(16, 4) == QByteArray::fromHex("00000001"));

    // Wire bytes are FF1-encrypted; the salt/index bootstrap stays verifiable.
    QCOMPARE(wire.left(16), salt);
    QCOMPARE(wire.mid(16, 4), QByteArray::fromHex("00000001"));
    QVERIFY(!wire.contains("=ybegin"));
}

void ArticleTest::exactWrapAndEmptyPayloadPreserveSingleCrlf()
{
    // When the encoded stream wraps exactly on a 128-column boundary the
    // old code emitted a double CRLF (blank line) before =yend; a zero-byte
    // payload did the same. Downstream FF1 tweak derivation counts physical
    // lines, so a blank line desynchronized the =yend tweak.
    // Encrypted articles must preserve single CRLF.
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QString error;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, salt, 1);

    // 128 ASCII 'A's encode to 128 column-exact chars and trigger the wrap.
    const QByteArray payload(128, 'A');
    QByteArray wire;
    quint32 crc32 = 0;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(!wire.contains("\r\n\r\n"));
    QVERIFY(!wire.contains("=yend"));

    // Zero-byte payload in encrypted mode:
    const QByteArray empty;
    QVERIFY2(Yenc::encodeArticle(empty, 1, 1, 0, 0, QByteArrayLiteral("empty.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(!wire.contains("\r\n\r\n"));
    QVERIFY(!wire.contains("=yend"));
}

QTEST_APPLESS_MAIN(ArticleTest)

#include "ArticleTest.moc"
