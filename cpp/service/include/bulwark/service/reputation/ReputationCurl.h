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

    // Append a diagnostic line to %ProgramData%\Bulwark\rep_diag.log (ReputationHttp.DiagLog).
    static void diag(const QString& line);

private:
    static QStringList buildArgs(const QString& method, const QString& url, const QStringList& headers,
                                 const QList<QPair<QString, QString>>* form, int timeoutSeconds);
    static std::pair<int, QString> run(const QStringList& args, int timeoutSeconds);
};

} // namespace bulwark::service::reputation
