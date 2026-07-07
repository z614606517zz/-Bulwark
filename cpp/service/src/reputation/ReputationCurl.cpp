#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/Logger.h" // programDataDir()

#include <QDateTime>
#include <QDir>
#include <QFile>
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

std::pair<int, QString> ReputationCurl::run(const QStringList& args, int timeoutSeconds) {
    QProcess p;
    p.start(QStringLiteral("curl.exe"), args);
    if (!p.waitForStarted(5000)) return { 0, QString() };
    if (!p.waitForFinished((std::max(5, timeoutSeconds) + 10) * 1000)) {
        p.kill();
        p.waitForFinished(1000);
        return { 0, QString() };
    }
    const QString out = QString::fromUtf8(p.readAllStandardOutput());
    static const QString marker = QStringLiteral("\nHTTPSTATUS:");
    const int idx = out.lastIndexOf(marker);
    if (idx < 0) return { 0, out };
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

void ReputationCurl::diag(const QString& line) {
    QFile f(QDir(programDataDir()).filePath(QStringLiteral("rep_diag.log")));
    if (f.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text)) {
        const QString row = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")) +
                            QLatin1Char(' ') + line + QLatin1Char('\n');
        f.write(row.toUtf8());
        f.close();
    }
}

} // namespace bulwark::service::reputation
