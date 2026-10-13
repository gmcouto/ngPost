#include <QtTest>
#include "NgPost.h"
#include "PostingJob.h"

class ConfigTest : public QObject
{
    Q_OBJECT
public:
    explicit ConfigTest(NgPost &app) : app(app) {}
private:
    NgPost &app;
private slots:
    void refusesOversizedEncryptedFileBeforePosting()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QFile file(dir.filePath("tiny.bin"));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("hello");
        file.close();
        PostingJob job(&app, dir.filePath("out.nzb"), QFileInfoList{QFileInfo(file)},
                       nullptr, QList<QString>{QStringLiteral("alt.binaries.test")}, "test@example.invalid",
                       false, false, dir.path(), QString(), QString(), 0, false, 0, false, false,
                       QString(), QString(), false, false, true, nullptr, QStringLiteral("transport-secret"));
        QObject::disconnect(&job, nullptr, &app, nullptr);
        job.testFileSize = qint64(1) << 32;
        QSignalSpy finished(&job, &PostingJob::postingFinished);
        job._postFiles();
        QCOMPARE(finished.count(), 1);
        QCOMPARE(job._nbArticlesUploaded, quint64(0));
        QVERIFY(job._nntpConnections.isEmpty());
        QVERIFY(job._filesToUpload.isEmpty());
        QVERIFY(!QFile::exists(dir.filePath("out.nzb")));
    }

    void saveConfigKeepsEncryptTrue()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QString input = dir.filePath("input.conf");
        QFile file(input);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("ENCRYPT = true\nENCRYPT-PASSWORD = transport-secret\n");
        file.close();
        QVERIFY(app._parseConfig(input).isEmpty());
        QVERIFY(app._encryption.enabled);
        QString saved = dir.filePath("saved.conf");
        app.saveConfig(saved);
        QFile output(saved);
        QVERIFY(output.open(QIODevice::ReadOnly));
        QVERIFY(!output.readAll().contains("transport-secret"));
        app._encryption.enabled = false;
        QVERIFY(app._parseConfig(saved).isEmpty());
        QVERIFY(app._encryption.enabled);
    }
};

int main(int argc, char **argv)
{
    NgPost app(argc, argv);
    ConfigTest test(app);
    return QTest::qExec(&test, argc, argv);
}
#include "ConfigTest.moc"
