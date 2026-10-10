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

#ifndef POSTINGJOB_H
#define POSTINGJOB_H
#include "utils/Macros.h"
#include "crypto/CryptoEngine.h"

#include <QFileInfoList>
#include <QVector>
#include <QSet>
#include <QQueue>
#include <QTextStream>
#include <QMutex>
#include <QTime>
#include <QTimer>
#include <QElapsedTimer>
#include <thread>
class QProcess;
class NgPost;
class NntpConnection;
class NntpFile;
class NntpArticle;
class PostingWidget;
class Poster;

using AtomicBool = QAtomicInteger<unsigned short>; // 16 bit only (faster than using 8 bit variable...)

class SegmentIndexAllocator
{
private:
    quint32 _next;

public:
    // CR-02: an index whose uint32_be encoding contains 0x0A or 0x0D would split
    // the Line 1 bootstrap on the wire and is forbidden; skip such indices.
    static bool hasForbiddenByte(quint32 index)
    {
        for(int shift = 0; shift < 32; shift += 8)
        {
            const uchar byte = static_cast<uchar>((index >> shift) & 0xFFU);
            if(byte == 0x0A || byte == 0x0D)
                return true;
        }
        return false;
    }

    SegmentIndexAllocator(quint32 start = 1) : _next(start) {}

    bool next(quint32 &segmentIndex)
    {
        if(_next == 0)
            return false;
        while(SegmentIndexAllocator::hasForbiddenByte(_next))
        {
            if(_next == 0xFFFFFFFFU)
                return false; // exhaustion, not wraparound
            ++_next;
        }
        segmentIndex = _next;
        if(_next == 0xFFFFFFFFU)
            _next = 0; // fully exhausted; next() will return false
        else
            ++_next;
        return true;
    }
};

/*!
 * \brief PostingJob is an active object that will do a posting job
 * it will be possible to move it to a thread to not freeze the HMI
 * it will signal it's progressbarion to PostingWidget
 *
 * NgPost will only have one PostingJob active at a time
 * but it will be able to hold a Pending queue
 */
class PostingJob : public QObject
{
    Q_OBJECT
    friend class Poster;
    friend class ArticleBuilder;
    friend class NgPost;

private:
    NgPost *const _ngPost; //!< handle on the application to access global configs
    QFileInfoList _files; //!< populated on constuction using a QStringList of paths

    PostingWidget *const _postWidget;

    QProcess   *_extProc;
    QDir       *_compressDir;
    bool        _limitProcDisplay;
    ushort      _nbProcDisp;

#ifdef __USE_TMP_RAM__
    QString        _tmpPath; //!< can be overwritten by _ngPost->_ramPath
#else
    const QString  _tmpPath;
#endif
    const QString  _rarPath;
    QString        _rarArgs;
    const uint     _rarSize;
    const bool     _useRarMax;
    const uint     _par2Pct;

    const bool    _doCompress;
    const bool    _doPar2;
    const QString _rarName;
    const QString _rarPass;
    const bool    _keepRar;
    bool          _splitArchive;



    QVector<NntpConnection*> _nntpConnections; //!< the NNTP connections (owning the TCP sockets)
    QVector<NntpConnection*> _closedConnections; //!< the NNTP connections (owning the TCP sockets)

    QString               _nzbName; //!< name of nzb that we'll write (without the extension)
    QQueue<NntpFile*>     _filesToUpload;  //!< list of files to upload (that we didn't start)
    QSet<NntpFile*>       _filesInProgress;//!< files in queue to be uploaded (Articles have been produced)
    QSet<NntpFile*>       _filesFailed;//!< files that couldn't be read
    uint                  _nbFiles;  //!< number of files to post in this iteration
    uint                  _nbPosted; //!< number of files posted


    QString      _nzbFilePath;
    QFile       *_nzb;       //!< nzb file that will be filled on the fly when a file is fully posted
    QTextStream  _nzbStream; //!< txt stream for the nzb file

    NntpFile    *_nntpFile; //!< current file that is getting processed
    QFile       *_file;     //!< file handler on the file getting processed
    uint         _part;     //!< part number (Article) on the current file

    QElapsedTimer _timeStart; //!< to get some stats (upload time and avg speed)
    quint64       _totalSize; //!< total size (in Bytes) to be uploaded
    QElapsedTimer _pauseTimer;   //!< to record the time when ngPost is in pause
    qint64        _pauseDuration; //!< total duration of all pauses

    int     _nbConnections; //!< available number of NntpConnection (we may loose some)
    int     _nbThreads;     //!< size of the ThreadPool

    uint      _nbArticlesUploaded; //!< number of Articles that have been uploaded (+ failed ones)
    uint      _nbArticlesFailed;   //!< number of Articles that failed to be uploaded
    quint64   _uploadedSize;       //!< bytes posted (to compute the avg speed)
    uint      _nbArticlesTotal;    //!< number of Articles of all the files to post


    AtomicBool  _stopPosting;
    AtomicBool  _noMoreFiles;

    bool _postStarted;
    bool _packed;
    bool _postFinished;

    const bool _obfuscateArticles;
    const bool _obfuscateFileName;
    const bool _encryptionEnabled;
    QString _encryptionPassword;
    QByteArray _encryptionSalt;
    CryptoKeys _encryptionKeys;
    //! F6.3: the 64 MiB Argon2id KDF runs on a worker thread spawned by the
    //! constructor (never on the GUI thread); _ensureEncryptionKeys() waits
    //! for it. _encryptionKeysState is 0 while deriving, 1 when ready, 2 on
    //! failure (all guarded by _encryptionKeysMutex).
    QMutex _encryptionKeysMutex; //!< guards _encryptionKeysState/_encryptionError (F6.3)
    QMutex _encryptionKeysJoinMutex; //!< serializes joining _encryptionKeysWorker (F6.3)
    int _encryptionKeysState;
    std::thread _encryptionKeysWorker;
    SegmentIndexAllocator _segmentIndices;
    QString _encryptionError;

    AtomicBool  _delFilesAfterPost;
    const QFileInfoList _originalFiles;


    QMutex _secureDiskAccess;

    QVector<Poster*> _posters;

    const bool  _overwriteNzb;

    QMap<QString, QString> _obfuscatedFileNames;

    const QList<QString> _grpList; //!< Newsgroup where we're posting in a list format to write in the nzb file
    const std::string    _from;               //!< email of poster (if empty, random one will be used for each file)

    bool _use7z;

    bool _isPaused;

    QTimer _resumeTimer;

    bool _isActiveJob;


#ifdef __COMPUTE_IMMEDIATE_SPEED__
    quint64    _immediateSize;       //!< bytes posted (to compute the avg speed)
    QTimer     _immediateSpeedTimer;
    QString    _immediateSpeed;
    const bool _useHMI;
#endif

public:
    PostingJob(NgPost *ngPost,
               const QString &nzbFilePath,
               const QFileInfoList &files,
               PostingWidget *postWidget,
               const QList<QString> &grpList,
               const std::string    &from,
               bool obfuscateArticles,
               bool obfuscateFileName,
               const QString &tmpPath,
               const QString &rarPath,
               const QString &rarArgs,
               uint rarSize,
               bool useRarMax,
               uint par2Pct,
               bool doCompress,
               bool doPar2,
               const QString &rarName,
               const QString &rarPass,
               bool keepRar = false,
               bool delFilesAfterPost = false,
               bool overwriteNzb = true,
               QObject *parent = nullptr,
               const QString &encryptionPassword = QString());
    ~PostingJob();


    void pause();
    void resume();

    inline QString avgSpeed() const;

    inline void articlePosted(quint64 size);
    inline void articleFailed(quint64 size);

    inline uint nbArticlesTotal() const;
    inline uint nbArticlesUploaded() const;
    inline uint nbArticlesFailed() const;
    inline bool hasUploaded() const;

    inline const QString &nzbName() const;
    inline const QString &rarName() const;
    inline const QString &rarPass() const;
    inline QString postSize() const;

    inline bool hasCompressed() const;
    inline bool hasPacking() const;
    inline bool isPacked() const;
    inline bool hasPostStarted() const;
    inline bool hasPostFinished() const;
    inline bool hasPostFinishedSuccessfully() const;

    inline PostingWidget *widget() const;

    inline QString getFirstOriginalFile() const;

    inline void setDelFilesAfterPosted(bool delFiles);

    inline QString groups() const;
    inline QString from() const;

    inline bool isPosting() const;

    inline bool isPaused() const;

    inline const QString &nzbFilePath() const;

    inline static QString humanSize(double size);


#ifdef __COMPUTE_IMMEDIATE_SPEED__
    inline const QString &immediateSpeed() const;
#endif

    static QString sslSupportInfo();
    static bool supportsSsl();

signals:
    void startPosting(bool isActiveJob);    //!< connected to onStartPosting (to be able to run on a different Thread)
    void stopPosting();

    void postingStarted();  //!< emitted at the end of onStartPosting
    void noMoreConnection();
    void postingFinished();

    void archiveFileNames(QStringList paths);
    void articlesNumber(uint nbArticles);

    void filePosted(QString filePath, uint nbArticles, uint nbFailed);

    void packingDone();


public slots:
    void onStopPosting(); //!< for HMI

private slots:
    void onStartPosting(bool isActiveJob);
    void onDisconnectedConnection(NntpConnection *con);

    void onNntpFileStartPosting();
    void onNntpFilePosted();
    void onNntpErrorReading();

    void onExtProcReadyReadStandardOutput();
    void onExtProcReadyReadStandardError();

    void onCompressionFinished(int exitCode);
    void onGenPar2Finished(int exitCode);

    void onResumeTriggered();

#ifdef __COMPUTE_IMMEDIATE_SPEED__
    void onImmediateSpeedComputation();
#endif


private:
    void _log(const QString &aMsg, bool newline = true) const; //!< log function for QString
    void _error(const QString &error) const;

    // F6.3: the 64 MiB Argon2id KDF must not run in the PostingJob constructor
    // (GUI-thread stall). The constructor spawns a worker that derives the keys
    // while packing/compression proceeds; _ensureEncryptionKeys() joins it and
    // returns false on derivation failure (keys ready before first encoding).
    bool _ensureEncryptionKeys();
    void _deriveEncryptionKeysWorker();

    int  _createNntpConnections();
    void _preparePostersArticles();

    NntpArticle *_readNextArticleIntoBufferPtr(const QString &threadName, char **bufferPtr);


    void _delOriginalFiles();

    inline NntpFile *_getNextFile();

    void _initPosting();
    void _postFiles();
    void _finishPosting();

    void _closeNzb();
    void _printStats() const;    


    bool startCompressFiles(const QString &cmdRar,
                            const QString &tmpFolder,
                            const QString &archiveName,
                            const QString &pass,
                            uint volSize = 0);
    bool startGenPar2(const QString &tmpFolder,
                      const QString &archiveName,
                      uint redundancy = 0);

    bool _canCompress() const;
    bool _canGenPar2() const;

    void _cleanExtProc();
    void _cleanCompressDir();

    QString _createArchiveFolder(const QString &tmpFolder, const QString &archiveName);

    bool _checkTmpFolder() const;


    qint64 _dirSize(const QString &path);

    inline QString timestamp() const;
};


QString PostingJob::avgSpeed() const
{
    QString power = " ";
    double bandwidth = 0.;

    if (_timeStart.isValid())
    {
        double sec = (_timeStart.elapsed()-_pauseDuration)/1000.;
        bandwidth = _uploadedSize / sec;

        if (bandwidth > 1024)
        {
            bandwidth /= 1024;
            power = "k";
        }
        if (bandwidth > 1024)
        {
            bandwidth /= 1024;
            power = "M";
        }
    }

    return QString("%1 %2B/s").arg(bandwidth, 6, 'f', 2).arg(power);
}

NntpFile *PostingJob::_getNextFile()
{
    if (_filesToUpload.size())
    {
        NntpFile *file = _filesToUpload.dequeue();
        _filesInProgress.insert(file);
        return file;
    }
    else
        return nullptr;
}

QString PostingJob::timestamp() const
{
    return QTime::currentTime().toString("hh:mm:ss.zzz");
}

void PostingJob::articlePosted(quint64 size)
{
    _uploadedSize += size;
    ++_nbArticlesUploaded;
#ifdef __COMPUTE_IMMEDIATE_SPEED__
    if (_useHMI)
        _immediateSize += size;
#endif
}

void PostingJob::articleFailed(quint64 size)
{
    _uploadedSize += size;
    ++_nbArticlesUploaded;
    ++_nbArticlesFailed;
#ifdef __COMPUTE_IMMEDIATE_SPEED__
    if (_useHMI)
        _immediateSize += size;
#endif
}

uint PostingJob::nbArticlesTotal() const { return _nbArticlesTotal; }
uint PostingJob::nbArticlesUploaded() const { return _nbArticlesUploaded; }
uint PostingJob::nbArticlesFailed() const{ return _nbArticlesFailed; }
bool PostingJob::hasUploaded() const{ return _nbArticlesTotal > 0; }

const QString &PostingJob::nzbName() const { return _nzbName; }
const QString &PostingJob::rarName() const { return _rarName; }
const QString &PostingJob::rarPass() const { return _rarPass; }
QString PostingJob::postSize() const { return humanSize(static_cast<double>(_totalSize)); }

QString PostingJob::humanSize(double size)
{
    QString unit = "B";
    if (size > 1024)
    {
        size /= 1024;
        unit = "kB";
    }
    if (size > 1024)
    {
        size /= 1024;
        unit = "MB";
    }
    if (size > 1024)
    {
        size /= 1024;
        unit = "GB";
    }
    return QString("%1 %2").arg(size, 0, 'f', 2).arg(unit);
}

bool PostingJob::hasCompressed() const { return _doCompress; }
inline bool PostingJob::hasPacking() const { return _doCompress || _doPar2; }
bool PostingJob::isPacked() const { return _packed; }
bool PostingJob::hasPostStarted() const { return _postStarted; }
bool PostingJob::hasPostFinished() const { return _postFinished; }
bool PostingJob::hasPostFinishedSuccessfully() const { return _postFinished && !_nbArticlesFailed; }

PostingWidget *PostingJob::widget() const { return _postWidget; }

QString PostingJob::getFirstOriginalFile() const
{
    if (_originalFiles.isEmpty())
        return QString();
    else
        return _originalFiles.first().absoluteFilePath();
}

void PostingJob::setDelFilesAfterPosted(bool delFiles)
{
    _delFilesAfterPost = delFiles ? 0x1 : 0x0;
}

QString PostingJob::groups() const { return _grpList.join(","); }
QString PostingJob::from() const { return _obfuscateArticles ? QString() : QString::fromStdString(_from); }

bool PostingJob::isPosting() const
{
    return MB_LoadAtomic(_stopPosting) == 0x0;
}
bool PostingJob::isPaused() const { return _isPaused; }

const QString &PostingJob::nzbFilePath() const { return _nzbFilePath; }

#ifdef __COMPUTE_IMMEDIATE_SPEED__
const QString &PostingJob::immediateSpeed() const { return _immediateSpeed; }
#endif

#endif // POSTINGJOB_H
