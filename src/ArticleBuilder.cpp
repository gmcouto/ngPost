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

#include "ArticleBuilder.h"
#include "Poster.h"
#include "NgPost.h"
#include "PostingJob.h"
#include "nntp/NntpArticle.h"
#include "nntp/NntpFile.h"
#include "utils/Yenc.h"

ArticleBuilder::ArticleBuilder(Poster *poster, QObject *parent):
    QObject (parent),
    _ngPost(poster->_ngPost),
    _poster(poster),
    _job(poster->_job),
    _buffer(new char[static_cast<quint64>(_ngPost->articleSize())+1])
{
    connect(this, &ArticleBuilder::scheduleNextArticle, this, &ArticleBuilder::onPrepareNextArticle, Qt::QueuedConnection);
}

ArticleBuilder::~ArticleBuilder()
{
    delete[] _buffer;
}

NntpArticle *ArticleBuilder::getNextArticle(const QString &threadName)
{
    _job->_secureDiskAccess.lock();
    NntpArticle *article = _job->_readNextArticleIntoBufferPtr(threadName, &_buffer);
    _job->_secureDiskAccess.unlock();
    if (article)
    {
        // F6.3: keys are derived lazily (not in the PostingJob constructor);
        // this is the first consumer. On failure, stop the job cleanly.
        if (!_job->_ensureEncryptionKeys())
        {
            _job->_error(_job->_encryptionError);
            _job->_stopPosting = 0x1;
            _job->_noMoreFiles = 0x1;
            emit _job->stopPosting();
            return nullptr;
        }
        QString error;
        const YencEncryptionContext encryption(_job->_encryptionKeys.bodyKey,
                                                _job->_encryptionKeys.masterKey,
                                                _job->_encryptionSalt,
                                                article->segmentIndex());
        const YencEncryptionContext *encryptionPtr = _job->_encryptionEnabled ? &encryption : nullptr;
        if(!article->yEncBody(_buffer, encryptionPtr, &error))
        {
            _job->_secureDiskAccess.lock();
            article->nntpFile()->removeArticle(article);
            // F6.4: _encryptionError is a QString shared with other builder
            // threads; the write must stay inside the same critical section as
            // removeArticle to avoid a refcount race on the failure path.
            _job->_encryptionError = QStringLiteral("Unable to encode article: %1").arg(error);
            _job->_secureDiskAccess.unlock();
            delete article;
            _job->_error(_job->_encryptionError);
            _job->_stopPosting = 0x1;
            _job->_noMoreFiles = 0x1;
            // _finishPosting() is a main-thread orchestrator (qApp->processEvents,
            // thread joins) and must never run on this builder/connection thread.
            // onStopPosting performs the same teardown+postingFinished pair, queued
            // onto the PostingJob's own thread (see PostingJob.cpp stopPosting wiring).
            emit _job->stopPosting();
            return nullptr;
        }

#ifdef __SAVE_ARTICLES__
        article->dumpToFile("/tmp", _ngPost->aticleSignature());
#endif
    }
    return article;
}


void ArticleBuilder::onPrepareNextArticle()
{
    // Early-return if stop requested; avoids reading/encoding articles
    // after an error or shutdown signal has already been raised.
    if (MB_LoadAtomic(_job->_stopPosting))
        return;

    QMutexLocker lock(&_poster->_secureArticles); // thread safety (coming from _builderThread)

    NntpArticle *article = getNextArticle(_poster->_builderThread.objectName());
    if (article)
        _poster->_articles.enqueue(article);
}
