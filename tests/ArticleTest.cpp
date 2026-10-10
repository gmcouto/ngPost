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
    // Index framing rule: allocator must skip indices whose uint32_be contains 0x0A/0x0D
    void segmentIndexAllocatorSkipsForbiddenBytes();
    // Worst-case escape payloads must not overflow the encode buffer
    void worstCaseEscapePayloadDoesNotOverflow();
    // Exact-128-column wrap and empty payloads must not inject blank lines
    void exactWrapAndEmptyPayloadPreserveSingleCrlf();
    // Trailing whitespace at end of line must be escaped
    void trailingWhitespaceAtLineEndIsEscaped();
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

void ArticleTest::segmentIndexAllocatorSkipsForbiddenBytes()
{
    // Index framing rule: indices whose uint32_be encoding contains 0x0A
    // or 0x0D would split the Line 1 bootstrap on the wire and must be skipped.
    // Canonical index_allocation.json (VEC-07) vectors: candidates 10, 13, 266, 269.
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
    YencEncryptionContext encryption(masterKey, masterKey, salt, 1);
    QByteArray wire;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QVERIFY(wire.left(16) == salt);
    QVERIFY(wire.mid(16, 4) == QByteArray::fromHex("00000001"));

    // Round-trip: restoring control lines must succeed.
    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 1, restored, &extractedSalt,
                                            &extractedIndex, &error), qPrintable(error));
    QCOMPARE(extractedSalt, salt);
    QCOMPARE(extractedIndex, quint32(1));
}

void ArticleTest::exactWrapAndEmptyPayloadPreserveSingleCrlf()
{
    // When the encoded stream wraps exactly on a 128-column boundary the
    // old code emitted a double CRLF (blank line) before =yend; a zero-byte
    // payload did the same. Downstream FF1 tweak derivation counts physical
    // lines, so a blank line desynchronized the =yend tweak.
    // 128 ASCII 'A's encode to 128 column-exact chars and trigger the wrap.
    const QByteArray payload(128, 'A');

    QByteArray article;
    quint32 crc32 = 0;
    QString error;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 nullptr, article, crc32, &error), qPrintable(error));
    // No blank line may appear anywhere in the article.
    QVERIFY(!article.contains("\r\n\r\n"));
    // Exactly one CRLF separates the encoded payload from =yend.
    QVERIFY(article.contains("\r\n=yend size=128 "));

    // Zero-byte payload: no blank line between headers and =yend.
    QByteArray empty;
    QVERIFY2(Yenc::encodeArticle(empty, 1, 1, 0, 0, QByteArrayLiteral("empty.bin"),
                                 nullptr, article, crc32, &error), qPrintable(error));
    QVERIFY(!article.contains("\r\n\r\n"));
    QVERIFY(article.contains("\r\n=yend size=0 "));

    // Encrypted path on the exact-wrap payload: blank lines would break the
    // FF1 lineIndex count and prevent control-line restoration.
    const QByteArray salt("K7mX9pL2qR8vN4wZ", 16);
    QByteArray masterKey;
    QVERIFY2(CryptoEngine::deriveKey(QStringLiteral("test123"), salt, masterKey, &error),
             qPrintable(error));
    YencEncryptionContext encryption(masterKey, masterKey, salt, 1);
    QByteArray wire;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 &encryption, wire, crc32, &error), qPrintable(error));
    QByteArray restored;
    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QVERIFY2(FF1Cipher::decryptControlLines(wire, masterKey, 1, restored, &extractedSalt,
                                            &extractedIndex, &error), qPrintable(error));
    QVERIFY(!restored.contains("\r\n\r\n"));
    QVERIFY(restored.contains("\r\n=yend size=128 "));
}

void ArticleTest::trailingWhitespaceAtLineEndIsEscaped()
{
    // The yEnc escape rule applies to OUTPUT byte values 0x20/0x09 at
    // line boundaries. Output space (0x20) comes from input byte 246 (0xF6),
    // output tab (0x09) from input byte 223 (0xDF). A raw output space at the
    // final column before a line wrap must be '='-escaped; the old condition
    // (column - 1 == maxwidth) was unreachable and left it unescaped.
    // 127 'A' bytes fill columns 0..126; the next byte lands at column 127
    // (the last column of line 1).
    QByteArray payload(127, 'A');
    payload += char(0xF6); // encodes to output space 0x20 at column 127

    QByteArray article;
    quint32 crc32 = 0;
    QString error;
    QVERIFY2(Yenc::encodeArticle(payload, 1, 1, payload.size(), 0, QByteArrayLiteral("file.bin"),
                                 nullptr, article, crc32, &error), qPrintable(error));
    // output space (0x20) + 64 = 0x60 ('`'): escaped as "=\x60" before the wrap CRLF.
    QVERIFY(article.contains(QByteArrayLiteral("=\x60\r\n=yend")));
    QVERIFY(!article.contains(QByteArrayLiteral(" \r\n=yend")));
}

QTEST_APPLESS_MAIN(ArticleTest)

#include "ArticleTest.moc"
