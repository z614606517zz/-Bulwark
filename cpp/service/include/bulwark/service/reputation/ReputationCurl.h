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

//
// ============================ TLS 校验策略 ============================
//
// 【为什么必须有这个枚举,而不是一个全局开关】
//
// 本类原先给【每一条】curl 命令都无条件加了 `-k`(等价 --insecure),也就是彻底关闭证书
// 链与主机名校验。受影响的不只是情报查询:
//   · 信誉代理请求头里带 `Authorization: Bearer <token>`;
//   · VT / 微步 / MalwareBazaar / OTX / MetaDefender / HybridAnalysis 各自带 API 密钥;
//   · postFile 会把【用户的文件整体上传】;
//   · UpdateService 的清单获取与载荷下载也走这里 —— 那是「取一段代码,以 SYSTEM 跑起来」。
// 于是任何中间人都能用一张自签证书解密并篡改上述全部流量,并顺手收走所有密钥。
// 这与 UpdateService 里「拒绝在明文信道上取更新」的显式设计意图直接冲突:开了 https 却
// 关掉校验,对主动攻击者而言与明文等价。
//
// 但直接删掉 `-k` 不够 —— 自有端点(信誉代理 / 更新服务器)可能用自签证书,一删就会让情报
// 查询和在线更新【静默失效】,那是另一种严重退化。所以按目标分两类:
//
//   PublicCa : 第三方公网 API。走 curl 默认的完整校验(公网可信 CA + 主机名)。零配置即安全。
//   Pinned   : 自有端点。按下面 ownCaBundlePath / ownPinnedPublicKeys 的配置做【私有信任】:
//                ① 配了 CA 文件  -> `--cacert <file>`:只信这一份锚,链与主机名照常校验(首选);
//                ② 只配了公钥 pin -> `--pinnedpubkey sha256//...` + 跳过链校验。仍然强于裸 -k:
//                   证书换了、被中间人替了,公钥对不上就连不上;
//                ③ 都没配        -> 退回 PublicCa 的完整校验(而不是退回不校验)。
//
// 铁律:`-k` 【绝不】再单独出现。它只在 ② 里与 --pinnedpubkey 同时出现,那时公钥固定
// 已经替代了链校验的作用。
//
enum class TlsMode {
    PublicCa,   // 第三方公网端点:完整校验
    Pinned,     // 自有端点:私有信任锚(CA 文件 / 公钥固定)
};

class ReputationCurl {
public:
    // Global proxy URL (e.g. "http://127.0.0.1:7890"); empty = direct.
    static QString proxyUrl;

    // ---- 自有端点(信誉代理 / 更新服务器)的信任锚。由 main 从配置接线,二者可都为空。----
    // PEM 文件路径。非空时 TlsMode::Pinned 走 `--cacert`,这是最强也最省心的一档:
    // 链校验与主机名校验都保留,只是把信任根收窄到这一份。
    static QString ownCaBundlePath;
    // 公钥 pin,形如 "sha256//base64=="(可多条,证书轮换期同时接受新旧)。仅在未配置 CA
    // 文件时使用。取法:openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    static QStringList ownPinnedPublicKeys;

    // 自有端点是否已配置任一信任锚。未配置时 Pinned 会退回完整公网校验并记一条诊断 ——
    // 调用方无需分支,但运维需要知道「pinning 其实没生效」。
    static bool ownTrustAnchorConfigured();

    // GET. headers like "apikey: xxx" / "X-OTX-API-KEY: xxx".
    static std::pair<int, QString> get(const QString& url, const QStringList& headers, int timeoutSeconds,
                                       TlsMode tls = TlsMode::PublicCa);

    // POST application/x-www-form-urlencoded; form auto url-encoded.
    static std::pair<int, QString> postForm(const QString& url,
                                             const QList<QPair<QString, QString>>& form,
                                             const QStringList& headers, int timeoutSeconds,
                                             TlsMode tls = TlsMode::PublicCa);

    // POST a raw request body (e.g. application/json). Caller supplies headers
    // such as "Content-Type: application/json" and any auth headers.
    static std::pair<int, QString> postRaw(const QString& url, const QString& body,
                                           const QStringList& headers, int timeoutSeconds,
                                           TlsMode tls = TlsMode::PublicCa);

    // Multipart file upload (curl -F "file=@path;type=application/octet-stream").
    static std::pair<int, QString> postFile(const QString& url, const QString& filePath,
                                             const QStringList& headers, int timeoutSeconds,
                                             TlsMode tls = TlsMode::PublicCa);

    // GET straight to a file (curl -o). Returns (http status, curl stderr on failure).
    //
    // 为什么不能用上面的 get():那四个方法都把响应体收进 QString 再返回。更新载荷是几 MB 的
    // PE,走内存要经「curl -> QProcess 管道 -> QByteArray -> QString(UTF-16,体积翻倍)」,
    // 而且二进制过一遍 QString 转换本身就是错的。-o 让 curl 直接落盘,内存里只留状态码。
    //
    // 注意:HTTP 非 200 时 curl 仍会把错误响应体写进目标文件(没用 -f),故调用方必须在
    // code != 200 时删掉它 —— 否则会留下一个「长度不对的 exe」在暂存目录里。
    static std::pair<int, QString> download(const QString& url, const QString& destPath,
                                            const QStringList& headers, int timeoutSeconds,
                                            TlsMode tls = TlsMode::PublicCa);

    // Append a diagnostic line to %ProgramData%\Bulwark\rep_diag.log (ReputationHttp.DiagLog).
    static void diag(const QString& line);

private:
    // 按 TlsMode 给出这次请求的 TLS 相关 curl 参数。这是全类【唯一】决定校验强度的地方 ——
    // 五个公开方法都必须经它,免得再出现「某一条路径悄悄不校验」。
    static QStringList tlsArgs(TlsMode mode);

    static QStringList buildArgs(const QString& method, const QString& url, const QStringList& headers,
                                 const QList<QPair<QString, QString>>* form, int timeoutSeconds,
                                 TlsMode tls);
    // stdinData 非空时经 curl 的 stdin 送请求体(配合 --data-binary @-)。
    // 之所以不把 JSON 直接当命令行参数(--data-raw):Windows 上参数里的双引号要经
    // QProcess -> CRT 两层转义,JSON 体到 curl 手里就坏了,服务端只会回 400 invalid json。
    // 走 stdin 零转义、零临时文件,也不会把请求体暴露在命令行里(其它进程可见)。
    static std::pair<int, QString> run(const QStringList& args, int timeoutSeconds,
                                       const QByteArray& stdinData = QByteArray());
};

} // namespace bulwark::service::reputation
