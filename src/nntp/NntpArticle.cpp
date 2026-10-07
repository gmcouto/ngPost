//========================================================================
//
// Copyright (C) 2020 Matthieu Bruel <Matthieu.Bruel@gmail.com>
// This file is a part of ngPost : https://github.com/mbruel/ngPost
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3..
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>
//
//========================================================================

#include "NntpArticle.h"
#include "NntpConnection.h"
#include "NgPost.h"
#include "nntp/NntpFile.h"
#include "nntp/Nntp.h"
#include "utils/Yenc.h"
#include <cstring>
#include <sstream>

ushort NntpArticle::sNbMaxTrySending = 5;

NntpArticle::NntpArticle(NntpFile *file, uint part, qint64 pos, qint64 bytes,
                         const std::string *from, bool obfuscation, quint32 segmentIndex):
    _nntpFile(file), _part(part), _segmentIndex(segmentIndex),
    _id(QUuid::createUuid()),
    _from(from),
    _subject(nullptr),
    _body(nullptr),
    _bodySize(0),
    _filePos(pos), _fileBytes(bytes),
    _nbTrySending(0),
    _msgId()
{
    file->addArticle(this);
    connect(this, &NntpArticle::posted, _nntpFile, &NntpFile::onArticlePosted, Qt::QueuedConnection);
    connect(this, &NntpArticle::failed, _nntpFile, &NntpFile::onArticleFailed, Qt::QueuedConnection);

    if (!obfuscation)
    {
        std::stringstream ss;
        ss << _nntpFile->nameWithQuotes().toStdString() << " (" << part << "/" << _nntpFile->nbArticles() << ")";

        std::string subject = ss.str();
        _subject = new char[subject.length()+1];
        std::strcpy(_subject, subject.c_str());
    }
}

bool NntpArticle::yEncBody(const char data[], const YencEncryptionContext *encryption, QString *error)
{
    if(encryption && encryption->segmentIndex != _segmentIndex)
    {
        if(error)
            *error = QStringLiteral("Article segment index does not match encryption context");
        return false;
    }

    QByteArray block;
    quint32 crc32 = 0;
    if(!Yenc::encodeArticle(QByteArray(data, static_cast<int>(_fileBytes)), _part,
                            _nntpFile->nbArticles(), _nntpFile->fileSize(), _filePos,
                            QByteArray::fromStdString(_nntpFile->fileName()), encryption,
                            block, crc32, error))
        return false;
    block += QByteArrayLiteral(".\r\n");
    // C2-07: release any previously allocated body before re-allocating so
    // repeated yEncBody invocations never leak the earlier buffer.
    delete[] _body;
    _body = nullptr;
    _bodySize = block.size();
    _body = new char[block.size() + 1];
    std::memcpy(_body, block.constData(), static_cast<size_t>(block.size()));
    _body[block.size()] = '\0';
    return true;
}

NntpArticle::~NntpArticle()
{
    freeMemory();
}


//NntpArticle::NntpArticle(const std::string &from, const std::string &groups, const std::string &subject, const std::string &body):
//    _nntpFile(nullptr), _part(1),
//    _id(QUuid::createUuid()),
//    _from(from), _groups(groups),
//    _subject(subject),
//    _body(nullptr),
//    _filePos(0), _fileBytes(0),
//    _yencBody(nullptr),
//    _yencSize(0),
//    _crc32(0xFFFFFFFF),
//    _nbTrySending(0)
//{

//    _body->operator+=(Nntp::ENDLINE);
//    _body->operator+=(".");
//    _body->operator+=(Nntp::ENDLINE);
//}

QString NntpArticle::str() const
{
    if (_msgId.isEmpty())
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
        _msgId = _id.toString(sMsgIdFormat);
#else
        _msgId = _id.toString();
#endif
    return QString("%5 - Article #%1/%2 <id: %3, nbTrySend: %4>").arg(
                _part).arg(_nntpFile->nbArticles()).arg(_msgId).arg(
                _nbTrySending).arg(_nntpFile->name());
}

bool NntpArticle::tryResend()
{
    if (_nbTrySending < sNbMaxTrySending)
    {
        // get a new UUID
        _id = QUuid::createUuid();
        return true;
    }
    else
        return false;
}

void NntpArticle::write(NntpConnection *con, const std::string &idSignature)
{
    ++_nbTrySending;
    const std::string h = header(idSignature);
    con->write(h.data(), static_cast<qint64>(h.size()));
    // RFC 3977 §3.1.1 dot-stuffing (Phase 58 Task 9): a body line whose first
    // byte is 0x2E must have that byte doubled before the socket write, or the
    // server strips it — corrupting e.g. the Line 1 bootstrap of encrypted
    // articles. Applied to the BODY only: the header/protocol writes above are
    // never stuffed. The trailing article terminator ("\r\n.\r\n") is exempt —
    // it IS the terminator and must reach the server unstuffed.
    if(_body && _bodySize > 0 && articleBodyNeedsDotStuffing())
    {
        static thread_local QByteArray stuffedBody;
        stuffedBody.resize(static_cast<int>(_bodySize * 2));
        qint64 outSize = 0;
        bool atLineStart = true;
        const qint64 terminatorPos = _bodySize - 3; // potential "\r\n.\r\n" suffix
        for(qint64 i = 0; i < _bodySize; ++i)
        {
            const uchar byte = static_cast<uchar>(_body[i]);
            if(atLineStart && byte == 0x2E && i != terminatorPos)
                stuffedBody[static_cast<int>(outSize++)] = '.';
            stuffedBody[static_cast<int>(outSize++)] = static_cast<char>(byte);
            atLineStart = (byte == 0x0A);
        }
        con->write(stuffedBody.constData(), outSize);
    }
    else
        con->write(_body, _bodySize);
}

bool NntpArticle::articleBodyNeedsDotStuffing() const
{
    bool atLineStart = true;
    const qint64 terminatorPos = _bodySize - 3;
    for(qint64 i = 0; i < _bodySize; ++i)
    {
        const uchar byte = static_cast<uchar>(_body[i]);
        if(atLineStart && byte == 0x2E && i != terminatorPos)
            return true;
        atLineStart = (byte == 0x0A);
    }
    return false;
}

std::string NntpArticle::header(const std::string &idSignature) const
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    QByteArray msgId = _id.toByteArray(sMsgIdFormat);
#else
    QByteArray msgId = _id.toByteArray();
#endif
    std::stringstream ss;
    ss << "From: "        << (_from == nullptr ? NgPost::randomStdFrom() : *_from)    << Nntp::ENDLINE
       << "Newsgroups: "  << _nntpFile->groups()  << Nntp::ENDLINE
       << "Subject: "     << (_subject == nullptr ? msgId.constData() : _subject) << Nntp::ENDLINE
       << "Message-ID: <" << msgId.constData() << "@" << idSignature << ">" << Nntp::ENDLINE
       << Nntp::ENDLINE;
    _msgId = QString("%1@%2").arg(msgId.constData()).arg(idSignature.c_str());
    return ss.str();
}

void NntpArticle::dumpToFile(const QString &path, const std::string &articleIdSignature)
{
    QString fileName = QString("%1/%2_%3.yenc").arg(path).arg(_nntpFile->fileName().c_str()).arg(_part);
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly))
    {
        qDebug() << "[NntpArticle::dumpToFile] error creating file " << fileName;
        return;
    }

    const std::string h = header(articleIdSignature);
    file.write(h.data(), static_cast<qint64>(h.size()));
    file.write(_body, _bodySize);
    file.close();
}
