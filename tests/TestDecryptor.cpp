#include "TestDecryptor.h"

#include "crypto/CryptoEngine.h"
#include "crypto/FF1Cipher.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <sodium.h>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
const int Radix = 253;
const int SaltSize = 16;
const int KeySize = 32;
const int TweakSize = 8;
const int TagSize = 16;

void setError(QString *error, const QString &message)
{
    if(error)
        *error = message;
}

struct EvpCipherContextDeleter
{
    void operator()(EVP_CIPHER_CTX *context) const
    {
        EVP_CIPHER_CTX_free(context);
    }
};

struct BnContextDeleter
{
    void operator()(BN_CTX *context) const
    {
        BN_CTX_free(context);
    }
};

struct BignumDeleter
{
    void operator()(BIGNUM *number) const
    {
        BN_clear_free(number);
    }
};

using EvpCipherContext = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherContextDeleter>;
using BnContext = std::unique_ptr<BN_CTX, BnContextDeleter>;
using Bignum = std::unique_ptr<BIGNUM, BignumDeleter>;

bool byteToNumeral(uchar value, uchar &numeral)
{
    if(value >= 1 && value <= 9)
    {
        numeral = value - 1;
        return true;
    }
    if(value == 11)
    {
        numeral = 9;
        return true;
    }
    if(value == 12)
    {
        numeral = 10;
        return true;
    }
    if(value >= 14)
    {
        numeral = value - 3;
        return true;
    }
    return false;
}

bool numeralToByte(uchar numeral, uchar &value)
{
    if(numeral <= 8)
    {
        value = numeral + 1;
        return true;
    }
    if(numeral == 9)
    {
        value = 11;
        return true;
    }
    if(numeral == 10)
    {
        value = 12;
        return true;
    }
    if(numeral <= 252)
    {
        value = numeral + 3;
        return true;
    }
    return false;
}

bool bytesToNumerals(const QByteArray &bytes, std::vector<uchar> &numerals, QString *error)
{
    if(bytes.size() < 2)
    {
        setError(error, QStringLiteral("FF1 input must contain at least two bytes"));
        return false;
    }
    numerals.clear();
    numerals.reserve(static_cast<size_t>(bytes.size()));
    for(char byte : bytes)
    {
        uchar numeral = 0;
        if(!byteToNumeral(static_cast<uchar>(byte), numeral))
        {
            setError(error, QStringLiteral("Control line contains a byte outside the Radix 253 alphabet"));
            numerals.clear();
            return false;
        }
        numerals.push_back(numeral);
    }
    return true;
}

bool numeralsToBytes(const std::vector<uchar> &numerals, QByteArray &bytes, QString *error)
{
    bytes.resize(static_cast<int>(numerals.size()));
    for(size_t index = 0; index < numerals.size(); ++index)
    {
        uchar value = 0;
        if(!numeralToByte(numerals[index], value))
        {
            bytes.clear();
            setError(error, QStringLiteral("FF1 produced an invalid Radix 253 numeral"));
            return false;
        }
        bytes[static_cast<int>(index)] = static_cast<char>(value);
    }
    return true;
}

bool numeralsToBignum(const std::vector<uchar> &numerals, BIGNUM *number)
{
    BN_zero(number);
    for(uchar numeral : numerals)
    {
        if(!BN_mul_word(number, Radix) || !BN_add_word(number, numeral))
            return false;
    }
    return true;
}

bool bignumToNumerals(const BIGNUM *number, int length, std::vector<uchar> &numerals)
{
    Bignum value(BN_dup(number));
    if(!value)
        return false;
    numerals.assign(static_cast<size_t>(length), 0);
    for(int index = length - 1; index >= 0; --index)
    {
        const BN_ULONG remainder = BN_div_word(value.get(), Radix);
        if(remainder == static_cast<BN_ULONG>(-1))
            return false;
        numerals[static_cast<size_t>(index)] = static_cast<uchar>(remainder);
    }
    return BN_is_zero(value.get());
}

bool bignumToBytes(const BIGNUM *number, int length, QByteArray &bytes)
{
    bytes.fill('\0', length);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return BN_bn2binpad(number, reinterpret_cast<unsigned char *>(bytes.data()), length) == length;
#else
    const int encodedLength = BN_num_bytes(number);
    if(encodedLength > length)
        return false;
    return BN_bn2bin(number, reinterpret_cast<unsigned char *>(bytes.data()) + length - encodedLength) == encodedLength;
#endif
}

bool aesBlock(EVP_CIPHER_CTX *context, const unsigned char input[16], unsigned char output[16])
{
    int outputLength = 0;
    return EVP_EncryptUpdate(context, output, &outputLength, input, 16) == 1 && outputLength == 16;
}

bool cbcMac(EVP_CIPHER_CTX *context, const QByteArray &data, QByteArray &result)
{
    if(data.size() % 16 != 0)
        return false;
    unsigned char state[16] = {0};
    unsigned char input[16];
    unsigned char output[16];
    for(int offset = 0; offset < data.size(); offset += 16)
    {
        for(int index = 0; index < 16; ++index)
            input[index] = state[index] ^ static_cast<uchar>(data[offset + index]);
        if(!aesBlock(context, input, output))
        {
            sodium_memzero(state, sizeof(state));
            sodium_memzero(input, sizeof(input));
            sodium_memzero(output, sizeof(output));
            return false;
        }
        std::copy(output, output + 16, state);
    }
    result = QByteArray(reinterpret_cast<const char *>(state), 16);
    sodium_memzero(state, sizeof(state));
    sodium_memzero(input, sizeof(input));
    sodium_memzero(output, sizeof(output));
    return true;
}

QByteArray uint32Be(quint32 value)
{
    QByteArray bytes(4, Qt::Uninitialized);
    bytes[0] = static_cast<char>((value >> 24) & 0xff);
    bytes[1] = static_cast<char>((value >> 16) & 0xff);
    bytes[2] = static_cast<char>((value >> 8) & 0xff);
    bytes[3] = static_cast<char>(value & 0xff);
    return bytes;
}

bool ff1Transform(const QByteArray &key, const QByteArray &tweak, const QByteArray &input,
                  bool decrypt, QByteArray &output, QString *error)
{
    output.clear();
    if(key.size() != KeySize)
    {
        setError(error, QStringLiteral("FF1 key must be exactly 32 bytes"));
        return false;
    }
    if(tweak.size() != TweakSize)
    {
        setError(error, QStringLiteral("FF1 tweak must be exactly 8 bytes"));
        return false;
    }

    std::vector<uchar> numerals;
    if(!bytesToNumerals(input, numerals, error))
        return false;

    EvpCipherContext cipher(EVP_CIPHER_CTX_new());
    BnContext bnContext(BN_CTX_new());
    if(!cipher || !bnContext
            || EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_ecb(), nullptr,
                                  reinterpret_cast<const unsigned char *>(key.constData()), nullptr) != 1
            || EVP_CIPHER_CTX_set_padding(cipher.get(), 0) != 1)
    {
        setError(error, QStringLiteral("Unable to initialize AES-256 for FF1"));
        return false;
    }

    const int n = static_cast<int>(numerals.size());
    const int u = n / 2;
    const int v = n - u;

    Bignum radixPower(BN_new());
    Bignum radixValue(BN_new());
    Bignum exponent(BN_new());
    if(!radixPower || !radixValue || !exponent
            || !BN_set_word(radixValue.get(), Radix) || !BN_set_word(exponent.get(), v)
            || !BN_exp(radixPower.get(), radixValue.get(), exponent.get(), bnContext.get())
            || !BN_sub_word(radixPower.get(), 1))
    {
        setError(error, QStringLiteral("Unable to calculate FF1 domain size"));
        return false;
    }
    const int b = (BN_num_bits(radixPower.get()) + 7) / 8;
    const int d = 4 * ((b + 3) / 4) + 4;

    QByteArray p(16, '\0');
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    p[3] = static_cast<char>((Radix >> 16) & 0xff);
    p[4] = static_cast<char>((Radix >> 8) & 0xff);
    p[5] = static_cast<char>(Radix & 0xff);
    p[6] = 10;
    p[7] = static_cast<char>(u & 0xff);
    p.replace(8, 4, uint32Be(static_cast<quint32>(n)));
    p.replace(12, 4, uint32Be(static_cast<quint32>(tweak.size())));

    const int padding = (16 - ((tweak.size() + b + 1) % 16)) % 16;
    const QByteArray qPrefix = tweak + QByteArray(padding, '\0');
    std::vector<uchar> a(numerals.begin(), numerals.begin() + u);
    std::vector<uchar> second(numerals.begin() + u, numerals.end());

    Bignum number(BN_new());
    Bignum y(BN_new());
    Bignum modulus(BN_new());
    Bignum calculated(BN_new());
    Bignum radix(BN_new());
    Bignum power(BN_new());
    if(!number || !y || !modulus || !calculated || !radix || !power || !BN_set_word(radix.get(), Radix))
    {
        setError(error, QStringLiteral("Unable to allocate FF1 arithmetic state"));
        return false;
    }

    for(int roundOffset = 0; roundOffset < 10; ++roundOffset)
    {
        const int round = decrypt ? 9 - roundOffset : roundOffset;
        const std::vector<uchar> &roundInput = decrypt ? a : second;
        if(!numeralsToBignum(roundInput, number.get()))
        {
            setError(error, QStringLiteral("Unable to encode FF1 numeral string"));
            return false;
        }
        QByteArray numberBytes;
        if(!bignumToBytes(number.get(), b, numberBytes))
        {
            setError(error, QStringLiteral("FF1 numeral string exceeds its domain"));
            return false;
        }

        QByteArray q = qPrefix;
        q.append(static_cast<char>(round));
        q.append(numberBytes);
        QByteArray r;
        if(!cbcMac(cipher.get(), p + q, r))
        {
            setError(error, QStringLiteral("FF1 pseudorandom function failed"));
            return false;
        }
        QByteArray s = r;
        for(quint32 blockIndex = 1; s.size() < d; ++blockIndex)
        {
            unsigned char block[16];
            unsigned char encrypted[16];
            QByteArray indexBytes(16, '\0');
            indexBytes.replace(12, 4, uint32Be(blockIndex));
            for(int index = 0; index < 16; ++index)
                block[index] = static_cast<uchar>(r[index]) ^ static_cast<uchar>(indexBytes[index]);
            if(!aesBlock(cipher.get(), block, encrypted))
            {
                sodium_memzero(block, sizeof(block));
                sodium_memzero(encrypted, sizeof(encrypted));
                setError(error, QStringLiteral("FF1 expansion failed"));
                return false;
            }
            s.append(reinterpret_cast<const char *>(encrypted), 16);
            sodium_memzero(block, sizeof(block));
            sodium_memzero(encrypted, sizeof(encrypted));
        }
        if(!BN_bin2bn(reinterpret_cast<const unsigned char *>(s.constData()), d, y.get()))
        {
            setError(error, QStringLiteral("Unable to decode FF1 pseudorandom output"));
            return false;
        }

        const int m = round % 2 == 0 ? u : v;
        if(!BN_set_word(power.get(), m) || !BN_exp(modulus.get(), radix.get(), power.get(), bnContext.get()))
        {
            setError(error, QStringLiteral("Unable to calculate FF1 round modulus"));
            return false;
        }
        const std::vector<uchar> &operand = decrypt ? second : a;
        if(!numeralsToBignum(operand, number.get()))
        {
            setError(error, QStringLiteral("Unable to encode FF1 round operand"));
            return false;
        }
        const int arithmeticStatus = decrypt ? BN_sub(calculated.get(), number.get(), y.get())
                                             : BN_add(calculated.get(), number.get(), y.get());
        if(!arithmeticStatus || !BN_nnmod(calculated.get(), calculated.get(), modulus.get(), bnContext.get()))
        {
            setError(error, QStringLiteral("FF1 round arithmetic failed"));
            return false;
        }
        std::vector<uchar> next;
        if(!bignumToNumerals(calculated.get(), m, next))
        {
            setError(error, QStringLiteral("Unable to decode FF1 round result"));
            return false;
        }
        if(decrypt)
        {
            second = a;
            a = next;
        }
        else
        {
            a = second;
            second = next;
        }
    }

    std::vector<uchar> result = a;
    result.insert(result.end(), second.begin(), second.end());
    return numeralsToBytes(result, output, error);
}

bool matchesControlLine(const QByteArray &line, const QByteArray &name)
{
    return line == name || (line.startsWith(name) && line.size() > name.size() && line[name.size()] == ' ');
}

bool isControlLine(const QByteArray &line)
{
    return matchesControlLine(line, QByteArrayLiteral("=ybegin"))
            || matchesControlLine(line, QByteArrayLiteral("=ypart"))
            || matchesControlLine(line, QByteArrayLiteral("=yend"))
            || matchesControlLine(line, QByteArrayLiteral("=yencryption"));
}

struct Line
{
    QByteArray content;
    QByteArray ending;
};

std::vector<Line> splitLines(const QByteArray &block)
{
    std::vector<Line> lines;
    int start = 0;
    for(int index = 0; index < block.size(); ++index)
    {
        if(block[index] != '\n')
            continue;
        const int contentEnd = index > start && block[index - 1] == '\r' ? index - 1 : index;
        lines.push_back({block.mid(start, contentEnd - start), block.mid(contentEnd, index - contentEnd + 1)});
        start = index + 1;
    }
    if(start < block.size())
        lines.push_back({block.mid(start), QByteArray()});
    return lines;
}

QByteArray joinLines(const std::vector<Line> &lines)
{
    QByteArray block;
    for(const Line &line : lines)
    {
        block.append(line.content);
        block.append(line.ending);
    }
    return block;
}
}

bool TestDecryptor::decryptBody(const QByteArray &ciphertext, const QByteArray &tag, const QByteArray &key,
                               quint32 segmentIndex, QByteArray &plaintext, QString *error)
{
    plaintext.clear();
    QByteArray nonce;
    if(key.size() != KeySize || tag.size() != TagSize || !CryptoEngine::deriveBodyNonce(key, segmentIndex, nonce, error))
    {
        if(tag.size() != TagSize)
            setError(error, QStringLiteral("Authentication tag must be exactly 16 bytes"));
        return false;
    }

    QByteArray sealed = ciphertext + tag;
    QByteArray candidate(ciphertext.size(), Qt::Uninitialized);
    unsigned long long plaintextLength = 0;
    const int status = crypto_aead_xchacha20poly1305_ietf_decrypt(
                reinterpret_cast<unsigned char *>(candidate.data()), &plaintextLength, nullptr,
                reinterpret_cast<const unsigned char *>(sealed.constData()),
                static_cast<unsigned long long>(sealed.size()), nullptr, 0,
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(key.constData()));
    sodium_memzero(sealed.data(), static_cast<size_t>(sealed.size()));
    sodium_memzero(nonce.data(), static_cast<size_t>(nonce.size()));
    if(status != 0)
    {
        sodium_memzero(candidate.data(), static_cast<size_t>(candidate.size()));
        setError(error, QStringLiteral("Body authentication failed"));
        return false;
    }
    candidate.resize(static_cast<int>(plaintextLength));
    plaintext = candidate;
    return true;
}

bool TestDecryptor::decryptLine(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                               quint32 lineIndex, QByteArray &plaintext, QByteArray *salt, QString *error)
{
    return decryptLine(wire, masterKey, segmentIndex, lineIndex, plaintext, salt, nullptr, error);
}

bool TestDecryptor::decryptLine(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                               quint32 lineIndex, QByteArray &plaintext, QByteArray *salt,
                               quint32 *extractedSegmentIndex, QString *error)
{
    plaintext.clear();
    if(masterKey.size() != KeySize || lineIndex == 0)
    {
        setError(error, QStringLiteral("Invalid key or control-line index"));
        return false;
    }
    if(lineIndex != 1 && segmentIndex == 0)
    {
        setError(error, QStringLiteral("segmentIndex must be non-zero"));
        return false;
    }

    quint32 effectiveSegmentIndex = segmentIndex;
    QByteArray ciphertext = wire;
    if(lineIndex == 1)
    {
        if(wire.size() < SaltSize + 4 + 2)
        {
            setError(error, QStringLiteral("Encrypted Line 1 is too short"));
            return false;
        }
        const QByteArray extractedSalt = wire.left(SaltSize);
        for(char value : extractedSalt)
        {
            if(!FF1Cipher::isAlphabetByte(static_cast<uchar>(value)))
            {
                setError(error, QStringLiteral("Line 1 salt contains a byte outside the Radix 253 alphabet"));
                return false;
            }
        }
        const quint32 extractedIndex = (static_cast<uchar>(wire[16]) << 24)
                                     | (static_cast<uchar>(wire[17]) << 16)
                                     | (static_cast<uchar>(wire[18]) << 8)
                                     | static_cast<uchar>(wire[19]);
        if(extractedIndex == 0)
        {
            setError(error, QStringLiteral("Extracted segmentIndex must be non-zero"));
            return false;
        }
        for(int shift = 24; shift >= 0; shift -= 8)
        {
            const uchar b = static_cast<uchar>((extractedIndex >> shift) & 0xFF);
            if(b == 0x0A || b == 0x0D)
            {
                setError(error, QStringLiteral("Line 1 segmentIndex contains forbidden delimiter byte"));
                return false;
            }
        }
        if(segmentIndex != 0 && extractedIndex != segmentIndex)
        {
            setError(error, QStringLiteral("segmentIndex mismatch on Line 1"));
            return false;
        }
        effectiveSegmentIndex = extractedIndex;
        if(salt)
            *salt = extractedSalt;
        if(extractedSegmentIndex)
            *extractedSegmentIndex = extractedIndex;
        ciphertext.remove(0, SaltSize + 4);
    }

    QByteArray controlKey;
    QByteArray tweak;
    if(!CryptoEngine::deriveControlKey(masterKey, controlKey, error)
            || !CryptoEngine::deriveControlTweak(masterKey, effectiveSegmentIndex, lineIndex, tweak, error)
            || !ff1Transform(controlKey, tweak, ciphertext, true, plaintext, error))
    {
        if(!controlKey.isEmpty())
            sodium_memzero(controlKey.data(), static_cast<size_t>(controlKey.size()));
        if(!tweak.isEmpty())
            sodium_memzero(tweak.data(), static_cast<size_t>(tweak.size()));
        plaintext.clear();
        return false;
    }
    sodium_memzero(controlKey.data(), static_cast<size_t>(controlKey.size()));
    sodium_memzero(tweak.data(), static_cast<size_t>(tweak.size()));
    return true;
}

bool TestDecryptor::decryptControlLines(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                                       QByteArray &block, QByteArray *salt, QString *error)
{
    return decryptControlLines(wire, masterKey, segmentIndex, block, salt, nullptr, error);
}

bool TestDecryptor::decryptControlLines(const QByteArray &wire, const QByteArray &masterKey, quint32 segmentIndex,
                                       QByteArray &block, QByteArray *salt, quint32 *extractedSegmentIndex,
                                       QString *error)
{
    block.clear();
    std::vector<Line> lines = splitLines(wire);
    if(lines.size() < 2)
    {
        setError(error, QStringLiteral("Encrypted yEnc block is incomplete"));
        return false;
    }

    QByteArray extractedSalt;
    quint32 extractedIndex = 0;
    QByteArray firstLine;
    if(!decryptLine(lines.front().content, masterKey, segmentIndex, 1, firstLine, &extractedSalt, &extractedIndex, error)
            || !matchesControlLine(firstLine, QByteArrayLiteral("=ybegin")))
    {
        setError(error, QStringLiteral("Unable to restore =ybegin line"));
        return false;
    }
    lines.front().content = firstLine;

    const quint32 effectiveSegmentIndex = extractedIndex;

    for(size_t offset = 1; offset + 1 < lines.size(); ++offset)
    {
        QByteArray candidate;
        QString probeError;
        if(!decryptLine(lines[offset].content, masterKey, effectiveSegmentIndex, static_cast<quint32>(offset + 1),
                        candidate, nullptr, nullptr, &probeError))
        {
            setError(error, QStringLiteral("FF1 header-region decryption failed (provider corruption)"));
            return false;
        }
        if(!isControlLine(candidate))
            break;
        lines[offset].content = candidate;
    }

    QByteArray finalLine;
    const quint32 finalIndex = static_cast<quint32>(lines.size());
    if(!decryptLine(lines.back().content, masterKey, effectiveSegmentIndex, finalIndex, finalLine, nullptr, nullptr, error)
            || !matchesControlLine(finalLine, QByteArrayLiteral("=yend")))
    {
        setError(error, QStringLiteral("Unable to restore =yend line"));
        return false;
    }
    lines.back().content = finalLine;

    const bool isMultipart = firstLine.contains(" part=") || (lines.size() > 1 && matchesControlLine(lines[1].content, QByteArrayLiteral("=ypart")));
    size_t expectedYencIndex = 0;
    if(isMultipart)
    {
        if(lines.size() < 4)
        {
            setError(error, QStringLiteral("Multipart yEnc block is too short"));
            return false;
        }
        if(!matchesControlLine(lines[1].content, QByteArrayLiteral("=ypart")))
        {
            setError(error, QStringLiteral("Multipart yEnc block requires =ypart at physical line 2"));
            return false;
        }
        if(!matchesControlLine(lines[2].content, QByteArrayLiteral("=yencryption")))
        {
            setError(error, QStringLiteral("Multipart yEnc block requires =yencryption at physical line 3"));
            return false;
        }
        expectedYencIndex = 2;
    }
    else
    {
        if(lines.size() < 3)
        {
            setError(error, QStringLiteral("Single-part yEnc block is too short"));
            return false;
        }
        if(!matchesControlLine(lines[1].content, QByteArrayLiteral("=yencryption")))
        {
            setError(error, QStringLiteral("Single-part yEnc block requires =yencryption at physical line 2"));
            return false;
        }
        expectedYencIndex = 1;
    }

    for(size_t i = 0; i < lines.size(); ++i)
    {
        if(i != expectedYencIndex && matchesControlLine(lines[i].content, QByteArrayLiteral("=yencryption")))
        {
            setError(error, QStringLiteral("yEnc block contains duplicate or misplaced =yencryption lines"));
            return false;
        }
    }

    QByteArray headerSalt;
    quint32 headerIndex = 0;
    if(!FF1Cipher::parseYencryptionLine(lines[expectedYencIndex].content, headerSalt, headerIndex)
            || headerSalt != extractedSalt || headerIndex != extractedIndex)
    {
        setError(error, QStringLiteral("Line 1 salt and =yencryption salt must match"));
        return false;
    }

    if(salt)
        *salt = extractedSalt;
    if(extractedSegmentIndex)
        *extractedSegmentIndex = extractedIndex;
    block = joinLines(lines);
    return true;
}
