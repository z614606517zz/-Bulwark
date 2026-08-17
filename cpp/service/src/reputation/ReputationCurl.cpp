#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/Logger.h" // programDataDir()

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>
#include <QProcess>

#include <algorithm>

namespace bulwark::service::reputation {

QString ReputationCurl::proxyUrl;

QStringList ReputationCurl::buildArgs(const QString& method, const QString& url,
                                      const QStringList& headers,
                                      const QList<QPair<QString, QString>>* form, int timeoutSeconds) {
    QStringList args;
    args << QStringLiteral("-sS") << QStringLiteral("-k") << QStringLiteral("-L")
         << QStringLiteral("--max-redirs") << QStringLiteral("5")
         << QStringLiteral("--max-time") << QString::number(std::max(5, timeoutSeconds))
         << QStringLiteral("-X") << method;
    if (!proxyUrl.isEmpty())
        args << QStringLiteral("--proxy") << proxyUrl;
    for (const QString& h : headers)
        args << QStringLiteral("-H") << h;
    if (form)
        for (const auto& kv : *form)
            args << QStringLiteral("--data-urlencode") << (kv.first + QLatin1Char('=') + kv.second);
    args << QStringLiteral("-w") << QStringLiteral("\nHTTPSTATUS:%{http_code}");
    args << url;
    return args;
}

std::pair<int, QString> ReputationCurl::run(const QStringList& args, int timeoutSeconds,
                                            const QByteArray& stdinData) {
    // 失败诊断:以前所有失败都塌缩成「HTTP 0」,连是没启动、超时、还是 TLS 报错都分不出来。
    // 现在每条失败路径都把 curl 的 stderr / 退出码 / 耗时记进 rep_diag.log。
    const qint64 t0 = QDateTime::currentMSecsSinceEpoch();
    const auto elapsed = [t0] { return QDateTime::currentMSecsSinceEpoch() - t0; };

    QProcess p;
    p.start(QStringLiteral("curl.exe"), args);
    if (!p.waitForStarted(5000)) {
        diag(QStringLiteral("curl 未能启动(%1ms):%2").arg(elapsed()).arg(p.errorString()));
        return { 0, QString() };
    }
    // 可选:经 stdin 送请求体(配合 --data-binary @-)。注意用它时必须关闭写通道,否则 curl
    // 会一直等 EOF,而 --max-time 只从传输开始计时、救不了这种挂 —— 目前没有调用方用这条路。
    if (!stdinData.isEmpty()) {
        p.write(stdinData);
        p.waitForBytesWritten(5000);
    }
    p.closeWriteChannel();
    if (!p.waitForFinished((std::max(5, timeoutSeconds) + 10) * 1000)) {
        const QString err = QString::fromUtf8(p.readAllStandardError()).trimmed();
        p.kill();
        p.waitForFinished(1000);
        diag(QStringLiteral("curl 超时被杀(%1ms,--max-time=%2s):%3")
                 .arg(elapsed()).arg(std::max(5, timeoutSeconds))
                 .arg(err.isEmpty() ? QStringLiteral("(stderr 为空)") : err));
        return { 0, QString() };
    }
    const QString out = QString::fromUtf8(p.readAllStandardOutput());
    static const QString marker = QStringLiteral("\nHTTPSTATUS:");
    const int idx = out.lastIndexOf(marker);
    if (idx < 0) {
        // 传输层失败(DNS/TLS/连接/被 --max-time 中断):curl 用 -sS 把原因写在 stderr。
        const QString err = QString::fromUtf8(p.readAllStandardError()).trimmed();
        diag(QStringLiteral("curl 失败(%1ms,exit=%2):%3")
                 .arg(elapsed()).arg(p.exitCode())
                 .arg(err.isEmpty() ? QStringLiteral("(stderr 为空)") : err));
        return { 0, out };
    }
    const QString body = out.left(idx);
    const int code = out.mid(idx + marker.size()).trimmed().toInt();
    return { code, body };
}

std::pair<int, QString> ReputationCurl::get(const QString& url, const QStringList& headers, int timeoutSeconds) {
    return run(buildArgs(QStringLiteral("GET"), url, headers, nullptr, timeoutSeconds), timeoutSeconds);
}

std::pair<int, QString> ReputationCurl::postForm(const QString& url,
                                                 const QList<QPair<QString, QString>>& form,
                                                 const QStringList& headers, int timeoutSeconds) {
    return run(buildArgs(QStringLiteral("POST"), url, headers, &form, timeoutSeconds), timeoutSeconds);
}

std::pair<int, QString> ReputationCurl::postRaw(const QString& url, const QString& body,
                                                const QStringList& headers, int timeoutSeconds) {
    QStringList args;
    args << QStringLiteral("-sS") << QStringLiteral("-k") << QStringLiteral("-L")
         << QStringLiteral("--max-redirs") << QStringLiteral("5")
         << QStringLiteral("--max-time") << QString::number(std::max(5, timeoutSeconds))
         << QStringLiteral("-X") << QStringLiteral("POST");
    if (!proxyUrl.isEmpty())
        args << QStringLiteral("--proxy") << proxyUrl;
    for (const QString& h : headers)
        args << QStringLiteral("-H") << h;
    // 请求体直接作参数(--data-raw)。曾试过改走 stdin(--data-binary @-)以躲开引号转义,
    // 结果 curl 会一直等 stdin EOF、--max-time 又只从传输开始计时,于是每次都挂到被杀。
    // QProcess 的参数转义对 JSON 是够用的(ThreatFox 走同一条路一直正常),故保持 --data-raw。
    args << QStringLiteral("--data-raw") << body;
    args << QStringLiteral("-w") << QStringLiteral("\nHTTPSTATUS:%{http_code}");
    args << url;
    return run(args, timeoutSeconds);
}

std::pair<int, QString> ReputationCurl::postFile(const QString& url, const QString& filePath,
                                                 const QStringList& headers, int timeoutSeconds) {
    // Multipart upload; -F implies POST. File transfers can be slow, so floor
    // the timeout higher than the JSON-request default.
    const int t = std::max(30, timeoutSeconds);
    QStringList args;
    args << QStringLiteral("-sS") << QStringLiteral("-k") << QStringLiteral("-L")
         << QStringLiteral("--max-redirs") << QStringLiteral("5")
         << QStringLiteral("--max-time") << QString::number(t);
    if (!proxyUrl.isEmpty())
        args << QStringLiteral("--proxy") << proxyUrl;
    for (const QString& h : headers)
        args << QStringLiteral("-H") << h;
    args << QStringLiteral("-F")
         << (QStringLiteral("file=@") + filePath + QStringLiteral(";type=application/octet-stream"));
    args << QStringLiteral("-w") << QStringLiteral("\nHTTPSTATUS:%{http_code}");
    args << url;
    return run(args, t);
}

std::pair<int, QString> ReputationCurl::download(const QString& url, const QString& destPath,
                                                 const QStringList& headers, int timeoutSeconds) {
    // 下载几 MB 的载荷,超时地板比 JSON 请求高得多。
    const int t = std::max(30, timeoutSeconds);
    QStringList args;
    args << QStringLiteral("-sS") << QStringLiteral("-k") << QStringLiteral("-L")
         << QStringLiteral("--max-redirs") << QStringLiteral("5")
         << QStringLiteral("--max-time") << QString::number(t);
    if (!proxyUrl.isEmpty())
        args << QStringLiteral("--proxy") << proxyUrl;
    for (const QString& h : headers)
        args << QStringLiteral("-H") << h;
    // 断点续传刻意【不用】(--continue-at):暂存目录里的半个文件可能来自上一次失败的、
    // 甚至是另一个版本的下载,续传会把两段不同来源的字节拼成一个哈希对不上的文件,
    // 而失败原因看起来会像「服务器发错了」。每次都重下,几 MB 的代价换一个确定的结论。
    args << QStringLiteral("-o") << destPath;
    args << QStringLiteral("-w") << QStringLiteral("\nHTTPSTATUS:%{http_code}");
    args << url;
    const auto res = run(args, t);
    diag(QStringLiteral("download %1 -> HTTP %2").arg(QFileInfo(destPath).fileName()).arg(res.first));
    return res;
}

void ReputationCurl::diag(const QString& line) {
    // 这里原来是「无锁 + 无上限」地往 rep_diag.log 追加:
    //   1) diag() 被多个线程调用(IP 情报消费线程、各信誉源、代理健康探测),各自 open/write/close
    //      同一个文件。Windows 上并发追加不保证原子,行与行会互相截断/覆盖。
    //   2) 永不轮转。服务是 7x24 常驻的,这个文件只会一直长下去。
    // 加一把静态锁把「查大小 -> 轮转 -> 追加」串起来,并沿用 service.log 已有的单代轮转约定。
    static QMutex mx;
    QMutexLocker lock(&mx);

    constexpr qint64 kMaxBytes = 2 * 1024 * 1024; // 诊断用途,2MB 足够回溯
    const QString path = QDir(programDataDir()).filePath(QStringLiteral("rep_diag.log"));
    if (QFileInfo(path).size() >= kMaxBytes) {
        const QString prev = path + QStringLiteral(".1");
        QFile::remove(prev);
        QFile::rename(path, prev); // 失败也无妨:最坏是这次没轮转成,下次再试
    }

    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text)) {
        const QString row = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")) +
                            QLatin1Char(' ') + line + QLatin1Char('\n');
        f.write(row.toUtf8());
        f.close();
    }
}

} // namespace bulwark::service::reputation
