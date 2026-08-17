#pragma once
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

#include <utility>

// Shared "make an HTTPS request via the system curl.exe" helper for reputation
// clients. Faithful to Bulwark.Service/Reputation/ReputationCurl.cs: .NET's
// HttpClient can hit "SSL connection could not be established" under service /
// SYSTEM contexts (Schannel/SSPI), so curl.exe (system network stack) is used
// instead. Returns (http status code, body); any failure -> (0, "").
namespace bulwark::service::reputation {

class ReputationCurl {
public:
    // Global proxy URL (e.g. "http://127.0.0.1:7890"); empty = direct.
    static QString proxyUrl;

    // GET. headers like "apikey: xxx" / "X-OTX-API-KEY: xxx".
    static std::pair<int, QString> get(const QString& url, const QStringList& headers, int timeoutSeconds);

    // POST application/x-www-form-urlencoded; form auto url-encoded.
    static std::pair<int, QString> postForm(const QString& url,
                                             const QList<QPair<QString, QString>>& form,
                                             const QStringList& headers, int timeoutSeconds);

    // POST a raw request body (e.g. application/json). Caller supplies headers
    // such as "Content-Type: application/json" and any auth headers.
    static std::pair<int, QString> postRaw(const QString& url, const QString& body,
                                           const QStringList& headers, int timeoutSeconds);

    // Multipart file upload (curl -F "file=@path;type=application/octet-stream").
    static std::pair<int, QString> postFile(const QString& url, const QString& filePath,
                                             const QStringList& headers, int timeoutSeconds);

    // GET straight to a file (curl -o). Returns (http status, curl stderr on failure).
    //
    // 为什么不能用上面的 get():那四个方法都把响应体收进 QString 再返回。更新载荷是几 MB 的
    // PE,走内存要经「curl -> QProcess 管道 -> QByteArray -> QString(UTF-16,体积翻倍)」,
    // 而且二进制过一遍 QString 转换本身就是错的。-o 让 curl 直接落盘,内存里只留状态码。
    //
    // 注意:HTTP 非 200 时 curl 仍会把错误响应体写进目标文件(没用 -f),故调用方必须在
    // code != 200 时删掉它 —— 否则会留下一个「长度不对的 exe」在暂存目录里。
    static std::pair<int, QString> download(const QString& url, const QString& destPath,
                                            const QStringList& headers, int timeoutSeconds);

    // Append a diagnostic line to %ProgramData%\Bulwark\rep_diag.log (ReputationHttp.DiagLog).
    static void diag(const QString& line);

private:
    static QStringList buildArgs(const QString& method, const QString& url, const QStringList& headers,
                                 const QList<QPair<QString, QString>>* form, int timeoutSeconds);
    // stdinData 非空时经 curl 的 stdin 送请求体(配合 --data-binary @-)。
    // 之所以不把 JSON 直接当命令行参数(--data-raw):Windows 上参数里的双引号要经
    // QProcess -> CRT 两层转义,JSON 体到 curl 手里就坏了,服务端只会回 400 invalid json。
    // 走 stdin 零转义、零临时文件,也不会把请求体暴露在命令行里(其它进程可见)。
    static std::pair<int, QString> run(const QStringList& args, int timeoutSeconds,
                                       const QByteArray& stdinData = QByteArray());
};

} // namespace bulwark::service::reputation
