// ProcessInspector.cpp — Windows 进程取证与主动处置实现。
// 对应 .NET Bulwark.Service/Monitoring/ProcessInspector.cs。
//
// 关键设计:
//  * 签名:先 WinVerifyTrust 验嵌入式签名,失败再回退到 catalog(系统组件常见)。
//  * 证书画像:CryptQueryObject 取签名者证书 -> 指纹/有效期/吊销;签名时间尽力而为,
//    拿不到就留空(保守——避免把合法签名误判为"证书过期后签名")。
//  * 命令行:内核/ETW 进程事件不带命令行,这里按 PID 读 PEB 回填(仅 64 位宿主)。
//  * 处置:结束进程树时对"关键系统进程"设安全门槛,宁可不结束也不冒 0xEF 蓝屏风险。
//  * 缓存:签名/哈希等按 文件身份(路径|大小|修改时间) 缓存,规避进程风暴下重复计算。

#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QByteArray>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QVector>

#include <cstring>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <tlhelp32.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using namespace bulwark::service::monitoring;

namespace {

// ---- FILETIME -> QDateTime(UTC) ---------------------------------------------
QDateTime fileTimeToQDateTime(const FILETIME& ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart == 0)
        return QDateTime();
    // FILETIME 为自 1601-01-01 起的 100ns 间隔;换算到自 Unix 纪元的毫秒。
    constexpr quint64 kEpochDiffMs = 11644473600000ULL; // 1601->1970 的毫秒差
    const qint64 ms = static_cast<qint64>(u.QuadPart / 10000ULL) - static_cast<qint64>(kEpochDiffMs);
    return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC);
}

// ---- 文件身份(用于缓存键) --------------------------------------------------
// 身份 = 小写路径 | 大小 | 修改时刻。文件被替换(大小或时间变了)即自动失效,所以缓存
// 不会把旧文件的验签结论安到新文件头上。
QString identityFrom(const QString& path, const QFileInfo& fi)
{
    return path.toLower() + QLatin1Char('|')
         + QString::number(fi.size()) + QLatin1Char('|')
         + QString::number(fi.lastModified().toUTC().toMSecsSinceEpoch());
}

// 文件不存在则返回空(不缓存瞬态缺失)。
QString fileIdentity(const QString& path)
{
    if (path.isEmpty())
        return QString();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
        return QString();
    return identityFrom(path, fi);
}

// ---- 轻量事实缓存(每类事实一张表,统一互斥) --------------------------------
constexpr int kCacheCapacity = 8192;
QMutex g_cacheMx;

//
// 两代(hot / cold)缓存,取代原先「装满即整表 clear()」。
//
// 原实现在 size() >= kCacheCapacity 时把整张表清空。后果是一次溢出丢掉【全部】已验结论,
// 连最热的那几十个主体(svchost / explorer / 服务自身的 exe)一起丢 —— 而重算一条的代价是
// 一次 WinVerifyTrust 加一次整文件 SHA-256,毫秒量级。也就是说「装满」的那一瞬之后,每条
// 事件都要重付一次全额取证;而装满恰恰发生在文件事件风暴里(短时间见到上万个不同文件),
// 正是最不该再加负担的时刻。这是一个周期性的取证雪崩。
//
// 两代之后,溢出只是把 hot 整体降级成 cold:查找先看 hot 再看 cold,命中 cold 就提回 hot。
// 于是热集合能跨越溢出继续命中,只有连续两代都没被碰过的冷条目才真正淘汰。内存上限从
// kCacheCapacity 变成 2 x kCacheCapacity(存的都是 bool / QString / CertInfo 这类小对象)。
//
template <typename T>
struct FactCache {
    QHash<QString, T> hot;
    QHash<QString, T> cold;
};

template <typename T>
void insertHotLocked(FactCache<T>& store, const QString& id, const T& value)
{
    if (store.hot.size() >= kCacheCapacity) {
        store.cold = std::move(store.hot); // 老一代降级(而不是丢弃),热条目仍可被提回
        store.hot.clear();                 // move 后状态未定义,显式清空
    }
    store.hot.insert(id, value);
}

// 已知文件身份时的取值入口。id 为空表示「文件身份不可知」——照算但不缓存。
template <typename T, typename F>
T cachedFactById(FactCache<T>& store, const QString& id, F compute)
{
    if (id.isEmpty())
        return compute();
    {
        QMutexLocker lk(&g_cacheMx);
        const auto h = store.hot.constFind(id);
        if (h != store.hot.constEnd())
            return h.value();
        const auto c = store.cold.find(id);
        if (c != store.cold.end()) {
            const T v = c.value();
            store.cold.erase(c);
            insertHotLocked(store, id, v); // 提回新生代
            return v;
        }
    }
    T value = compute(); // 在锁外计算,避免长 I/O 持锁;竞态下重复计算无害
    {
        QMutexLocker lk(&g_cacheMx);
        insertHotLocked(store, id, value);
    }
    return value;
}

// 只有路径时的取值入口:自己算一次文件身份(一次 stat)。
template <typename T, typename F>
T cachedFact(FactCache<T>& store, const QString& path, F compute)
{
    return cachedFactById(store, fileIdentity(path), compute);
}

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

} // namespace

// ============================ 签名 / 证书 内部实现 ============================
namespace {

// 嵌入式 Authenticode 验证的原始状态码(不塌缩)。ERROR_SUCCESS 表示完全可信;
// 其余值区分得出「摘要不匹配」「根不受信」「过期」等具体原因 —— 更新准入需要这个区分。
long embeddedSignatureStatusRaw(const QString& path)
{
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wcstr(path);

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data;
    ZeroMemory(&data, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    return static_cast<long>(status);
}

// 嵌入式 Authenticode 验证(WinVerifyTrust)。仅做本机校验,不联网撤销。
bool verifyEmbeddedSignature(const QString& path)
{
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wcstr(path);

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data;
    ZeroMemory(&data, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE; // 撤销另行处理,签名验证路径不联网
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    return status == ERROR_SUCCESS;
}

// 目录(catalog)签名验证——很多系统组件本身不内嵌签名,签名在 .cat 里。
bool verifyCatalogSignature(const QString& path)
{
    HANDLE hFile = CreateFileW(wcstr(path), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    bool trusted = false;
    HCATADMIN hCatAdmin = nullptr;
    GUID driverAction = DRIVER_ACTION_VERIFY;

    if (CryptCATAdminAcquireContext2(&hCatAdmin, &driverAction, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, nullptr, 0);
        if (hashLen > 0) {
            QByteArray hash(static_cast<int>(hashLen), '\0');
            if (CryptCATAdminCalcHashFromFileHandle2(
                    hCatAdmin, hFile, &hashLen, reinterpret_cast<BYTE*>(hash.data()), 0)) {
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
                    hCatAdmin, reinterpret_cast<BYTE*>(hash.data()), hashLen, 0, nullptr);
                if (hCatInfo) {
                    trusted = true; // 命中任一目录即视为受信
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }

    CloseHandle(hFile);
    return trusted;
}

// 打开文件签名者证书(已复制,调用方负责 CertFreeCertificateContext)。
PCCERT_CONTEXT acquireSignerCert(const QString& path)
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) {
        return nullptr;
    }

    PCCERT_CONTEXT result = nullptr;
    DWORD cb = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &cb) && cb > 0) {
        QByteArray buf(static_cast<int>(cb), '\0');
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(), &cb)) {
            CERT_INFO* ci = reinterpret_cast<CERT_INFO*>(buf.data());
            PCCERT_CONTEXT found = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, ci, nullptr);
            if (found) {
                result = CertDuplicateCertificateContext(found);
                CertFreeCertificateContext(found);
            }
        }
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return result;
}

// 从一组 CRYPT_ATTRIBUTES 里找 PKCS#9 signingTime 并解码为 QDateTime。
bool findSigningTime(const CRYPT_ATTRIBUTES& attrs, QDateTime& out)
{
    for (DWORD i = 0; i < attrs.cAttr; ++i) {
        const CRYPT_ATTRIBUTE& a = attrs.rgAttr[i];
        if (a.pszObjId == nullptr || strcmp(a.pszObjId, szOID_RSA_signingTime) != 0)
            continue;
        if (a.cValue == 0)
            continue;
        FILETIME ft{};
        DWORD cb = sizeof(ft);
        if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_RSA_signingTime,
                              a.rgValue[0].pbData, a.rgValue[0].cbData, 0, &ft, &cb)) {
            const QDateTime dt = fileTimeToQDateTime(ft);
            if (dt.isValid()) {
                out = dt;
                return true;
            }
        }
    }
    return false;
}

// 尽力提取签名时间:主签名者已认证属性 -> 旧式反签名(PKCS#9 counterSign)。
// RFC3161 时间戳需解析嵌套 TSTInfo,较复杂;拿不到就返回无效(保守,绝不误报过期签名)。
QDateTime computeSigningTime(const QString& path)
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) {
        return QDateTime();
    }

    QDateTime result;
    DWORD cb = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb) && cb > 0) {
        QByteArray buf(static_cast<int>(cb), '\0');
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &cb)) {
            CMSG_SIGNER_INFO* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
            QDateTime t;
            if (findSigningTime(si->AuthAttrs, t)) {
                result = t;
            } else {
                for (DWORD i = 0; i < si->UnauthAttrs.cAttr && !result.isValid(); ++i) {
                    const CRYPT_ATTRIBUTE& a = si->UnauthAttrs.rgAttr[i];
                    if (a.pszObjId == nullptr || strcmp(a.pszObjId, szOID_RSA_counterSign) != 0 || a.cValue == 0)
                        continue;
                    DWORD cb2 = 0;
                    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                                           a.rgValue[0].pbData, a.rgValue[0].cbData, 0, nullptr, &cb2)
                        || cb2 == 0) {
                        continue;
                    }
                    QByteArray cbuf(static_cast<int>(cb2), '\0');
                    if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                                          a.rgValue[0].pbData, a.rgValue[0].cbData, 0, cbuf.data(), &cb2)) {
                        CMSG_SIGNER_INFO* cs = reinterpret_cast<CMSG_SIGNER_INFO*>(cbuf.data());
                        QDateTime t2;
                        if (findSigningTime(cs->AuthAttrs, t2))
                            result = t2;
                    }
                }
            }
        }
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return result;
}

// 用本机链引擎判定证书是否被吊销;默认只用缓存 CRL(不联网、不阻塞)。
bool computeCertRevoked(PCCERT_CONTEXT cert)
{
    if (!cert)
        return false;

    CERT_CHAIN_PARA para;
    ZeroMemory(&para, sizeof(para));
    para.cbSize = sizeof(para);

    DWORD flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    if (!ProcessInspector::onlineRevocationCheck)
        flags |= CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL; // 仅本机缓存,绝不联网

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore, &para, flags, nullptr, &chain))
        return false;

    bool revoked = false;
    if (chain) {
        revoked = (chain->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) != 0;
        CertFreeCertificateChain(chain);
    }
    return revoked;
}

} // namespace

// ============================ 公有 API:签名 / 哈希 ==========================
//
// 每类事实的「计算」与「缓存表」都提到这里的文件作用域,而不是各自藏在函数里的 static。
// 理由:除了逐项入口(isSigned / tryGetPublisher / …),还有一个一次性取齐全部事实的入口
// (collectForensics),两者必须共用同一张表 —— 否则同一个文件会被验两遍签、哈希两遍。
namespace {

FactCache<bool>    g_signedCache;
FactCache<QString> g_publisherCache;
FactCache<QString> g_sha256Cache;
FactCache<bool>    g_embeddedCache;
FactCache<ProcessInspector::CertInfo> g_certCache;

bool computeIsSigned(const QString& path)
{
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return false;
    if (verifyEmbeddedSignature(path))
        return true;
    return verifyCatalogSignature(path);
}

QString computePublisher(const QString& path)
{
    PCCERT_CONTEXT cert = acquireSignerCert(path);
    if (!cert)
        return QString();
    QString publisher;
    const DWORD cch = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (cch > 1) {
        QVector<wchar_t> buf(static_cast<int>(cch));
        if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), cch) > 1)
            publisher = QString::fromWCharArray(buf.data());
    }
    CertFreeCertificateContext(cert);
    return publisher;
}

QString computeSha256(const QString& path)
{
    if (path.isEmpty())
        return QString();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
        return QString();
    constexpr qint64 kMaxBytes = 256LL * 1024 * 1024; // 超大文件不哈希(膨胀样本另有体积规则)
    if (fi.size() > kMaxBytes)
        return QString();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f))
        return QString();
    // 大写十六进制:与 .NET Convert.ToHexString 及 FirstSeenStore 归一化一致。
    return QString::fromLatin1(h.result().toHex().toUpper());
}

bool computeHasEmbeddedSignature(const QString& path)
{
    if (path.isEmpty())
        return false;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    const bool ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                                     CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                     CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                                     nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return ok;
}

ProcessInspector::CertInfo computeCertInfo(const QString& path)
{
    ProcessInspector::CertInfo info;
    PCCERT_CONTEXT cert = acquireSignerCert(path);
    if (!cert)
        return info;

    BYTE thumb[20];
    DWORD cb = sizeof(thumb);
    if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, thumb, &cb)) {
        info.thumbprint = QString::fromLatin1(
            QByteArray(reinterpret_cast<char*>(thumb), static_cast<int>(cb)).toHex().toUpper());
    }

    info.notBeforeUtc = fileTimeToQDateTime(cert->pCertInfo->NotBefore);
    info.notAfterUtc  = fileTimeToQDateTime(cert->pCertInfo->NotAfter);
    info.signingTimeUtc = computeSigningTime(path); // 可能无效

    if (info.signingTimeUtc.isValid() && info.notAfterUtc.isValid() && info.notBeforeUtc.isValid()) {
        if (info.signingTimeUtc > info.notAfterUtc || info.signingTimeUtc < info.notBeforeUtc)
            info.signedAfterCertExpiry = true;
    }

    info.revoked = computeCertRevoked(cert);
    CertFreeCertificateContext(cert);
    return info;
}

} // namespace

bool ProcessInspector::isSigned(const QString& path)
{
    return cachedFact(g_signedCache, path, [&] { return computeIsSigned(path); });
}

QString ProcessInspector::tryGetPublisher(const QString& path)
{
    return cachedFact(g_publisherCache, path, [&] { return computePublisher(path); });
}

QString ProcessInspector::tryComputeSha256(const QString& path)
{
    return cachedFact(g_sha256Cache, path, [&] { return computeSha256(path); });
}

bool ProcessInspector::hasEmbeddedSignature(const QString& path)
{
    return cachedFact(g_embeddedCache, path, [&] { return computeHasEmbeddedSignature(path); });
}

//
// 一次性取齐富化阶段要用的全部文件取证事实。
//
// 【它解决什么】isSigned / tryGetPublisher / tryComputeSha256 / hasEmbeddedSignature /
// getCertInfo 各自都要先算一遍「文件身份」(小写路径|大小|修改时刻)当缓存键,而算身份就是
// 一次 QFileInfo stat。Worker::enrich 对同一个 path 连着调其中 4~5 个,紧接着又为了取文件
// 体积再构造一个 QFileInfo —— 于是一条事件要对同一个文件 stat 5~6 遍,即便这些事实全都命中
// 缓存、真正的验签与哈希一次都没跑。事件风暴下这笔开销按事件数线性放大,且全在主线程上。
//
// 本函数把 stat 收敛成一次:身份与文件体积都从这一次结果里来,再拿身份去查各张事实表。
// 求值范围与 enrich 原先的调用序列逐条对应(含「仅当没有可信签名时才判是否内嵌签名」这个
// 条件),所以结论完全一致 —— 省掉的只是重复的 stat。
//
ProcessInspector::ForensicFacts
ProcessInspector::collectForensics(const QString& path, bool includeCert)
{
    ForensicFacts f;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return f;

    // 全流程唯一一次 stat。
    const QFileInfo fi(path);
    f.isRealFile = fi.exists() && fi.isFile();
    const QString id = f.isRealFile ? identityFrom(path, fi) : QString();
    if (f.isRealFile)
        f.fileSize = fi.size();

    f.trustedSignature =
        cachedFactById(g_signedCache, id, [&] { return computeIsSigned(path); });
    f.publisher =
        cachedFactById(g_publisherCache, id, [&] { return computePublisher(path); });
    f.sha256 =
        cachedFactById(g_sha256Cache, id, [&] { return computeSha256(path); });
    // 与 enrich 原有逻辑一致:已经有可信签名时不必再问「是否内嵌了签名」。
    if (!f.trustedSignature)
        f.embeddedSignature =
            cachedFactById(g_embeddedCache, id, [&] { return computeHasEmbeddedSignature(path); });
    if (includeCert)
        f.cert = cachedFactById(g_certCache, id, [&] { return computeCertInfo(path); });
    return f;
}

bool ProcessInspector::isSignatureMismatch(const QString& path)
{
    // 内嵌了签名但不受信 = 可疑(篡改 / 盗用证书 / 根不受信任都会落到这里)。
    //
    // ⚠ 这是一个【威胁打分用】的粗判据,不要拿它当准入闸门:它分不清「文件被改过」
    // 和「这台机器没导入签发者的根证书」。在线更新曾经用它做校验,结果每次更新都被
    // 判成「疑似被篡改」而拒装 —— 因为驱动用的是自签测试证书,根不受信任是常态。
    // 需要区分的场合用 embeddedSignatureStatus()。
    return hasEmbeddedSignature(path) && !isSigned(path);
}

long ProcessInspector::embeddedSignatureStatus(const QString& path)
{
    return embeddedSignatureStatusRaw(path);
}

ProcessInspector::CertInfo ProcessInspector::getCertInfo(const QString& path)
{
    return cachedFact(g_certCache, path, [&] { return computeCertInfo(path); });
}

// ============================ 进程自省 =======================================
namespace {

// NtQueryInformationProcess 动态解析(避免链接 ntdll.lib 的可移植性问题)。
using NtQipFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQipFn resolveNtQip()
{
    static NtQipFn fn = []() -> NtQipFn {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        return nt ? reinterpret_cast<NtQipFn>(GetProcAddress(nt, "NtQueryInformationProcess")) : nullptr;
    }();
    return fn;
}

// PROCESS_BASIC_INFORMATION(六个指针宽字段;与 x64 布局一致)。
struct ProcBasicInfo {
    void* ExitStatus;
    void* PebBaseAddress;
    void* AffinityMask;
    void* BasePriority;
    void* UniqueProcessId;
    void* InheritedFromUniqueProcessId;
};
constexpr ULONG kProcessBasicInformation = 0;

bool readRemote(HANDLE h, const void* addr, void* buf, SIZE_T size)
{
    SIZE_T got = 0;
    return ReadProcessMemory(h, addr, buf, size, &got) && got == size;
}

} // namespace

QString ProcessInspector::tryGetProcessImagePath(int pid)
{
    if (pid <= 0)
        return QString();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return QString();
    QString result;
    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    if (QueryFullProcessImageNameW(h, 0, buf, &size) && size > 0)
        result = QString::fromWCharArray(buf, static_cast<int>(size));
    CloseHandle(h);
    return result;
}

QList<int> ProcessInspector::enumeratePids()
{
    QList<int> pids;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return pids;
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4)
                pids.append(static_cast<int>(pe.th32ProcessID));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return pids;
}

QString ProcessInspector::tryGetCommandLine(int pid)
{
    if (pid <= 0)
        return QString();
    if constexpr (sizeof(void*) != 8) // 仅 64 位宿主(PEB 偏移按 x64 硬编码)
        return QString();
    NtQipFn ntqip = resolveNtQip();
    if (!ntqip)
        return QString();

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return QString();

    QString result;
    ProcBasicInfo pbi{};
    ULONG retLen = 0;
    if (ntqip(h, kProcessBasicInformation, &pbi, sizeof(pbi), &retLen) == 0 && pbi.PebBaseAddress) {
        // PEB + 0x20 -> ProcessParameters
        void* procParams = nullptr;
        const char* pebParamsAddr = reinterpret_cast<const char*>(pbi.PebBaseAddress) + 0x20;
        if (readRemote(h, pebParamsAddr, &procParams, sizeof(procParams)) && procParams) {
            // ProcessParameters + 0x70 -> CommandLine (UNICODE_STRING: Len16, MaxLen16, pad32, Buffer64)
            unsigned char us[16] = {0};
            const char* cmdAddr = reinterpret_cast<const char*>(procParams) + 0x70;
            if (readRemote(h, cmdAddr, us, sizeof(us))) {
                unsigned short length = 0;
                quint64 bufferAddr = 0;
                std::memcpy(&length, us + 0, 2);
                std::memcpy(&bufferAddr, us + 8, 8);
                if (length > 0 && length <= 0x8000 && bufferAddr != 0) {
                    QByteArray raw(length, '\0');
                    if (readRemote(h, reinterpret_cast<const void*>(bufferAddr), raw.data(), length)) {
                        result = QString::fromWCharArray(
                            reinterpret_cast<const wchar_t*>(raw.constData()), length / 2);
                        while (result.endsWith(QChar(u'\0')))
                            result.chop(1);
                    }
                }
            }
        }
    }

    CloseHandle(h);
    return result;
}

int ProcessInspector::tryGetParentPid(int pid)
{
    if (pid <= 0)
        return 0;
    NtQipFn ntqip = resolveNtQip();
    if (!ntqip)
        return 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return 0;
    int parent = 0;
    ProcBasicInfo pbi{};
    ULONG retLen = 0;
    if (ntqip(h, kProcessBasicInformation, &pbi, sizeof(pbi), &retLen) == 0)
        parent = static_cast<int>(reinterpret_cast<uintptr_t>(pbi.InheritedFromUniqueProcessId));
    CloseHandle(h);
    return parent;
}

// ============================ 主动处置 =======================================
namespace {

// 关键系统进程名单(小写);结束它们会触发 0xEF CRITICAL_PROCESS_DIED 蓝屏。
// 【只有配合下面的 isSystemImageDir 一起用才成立】—— 名字本身不构成豁免理由,见 isCriticalProcess。
const QSet<QString>& criticalNames()
{
    static const QSet<QString> names = {
        QStringLiteral("system"),       QStringLiteral("smss.exe"),
        QStringLiteral("csrss.exe"),    QStringLiteral("wininit.exe"),
        QStringLiteral("winlogon.exe"), QStringLiteral("services.exe"),
        QStringLiteral("lsass.exe"),    QStringLiteral("lsaiso.exe"),
        QStringLiteral("fontdrvhost.exe")
    };
    return names;
}

// 映像是否位于「真正的系统目录」(普通用户写不进去:WRP + 高 ACL)。
// 刻意不含 \Program Files\ —— 那里普通安装程序能落文件,用它给关键进程发豁免就等于
// 认可 C:\Program Files\Foo\csrss.exe 也是关键进程。与驱动侧 BlwPathIsSystemImageDir 同义。
bool isSystemImageDir(const QString& path)
{
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    return lower.contains(QLatin1String("\\windows\\system32\\"))
        || lower.contains(QLatin1String("\\windows\\syswow64\\"))
        || lower.contains(QLatin1String("\\windows\\winsxs\\"));
}

// 内核权威的"关键进程"标记(Win8.1+ IsProcessCritical)。
// 返回 tri-state:1=关键,0=非关键,-1=无法确定(进程无法打开/查询)。
int queryKernelCritical(int pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return -1; // 打不开(多为受保护/系统进程)——交由上层按 fail-safe 处理
    BOOL critical = FALSE;
    int result = -1;
    if (IsProcessCritical(h, &critical))
        result = critical ? 1 : 0;
    CloseHandle(h);
    return result;
}

quint64 processCreationTime(int pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return 0;
    FILETIME create{}, exit{}, kernel{}, user{};
    quint64 result = 0;
    if (GetProcessTimes(h, &create, &exit, &kernel, &user)) {
        ULARGE_INTEGER u;
        u.LowPart = create.dwLowDateTime;
        u.HighPart = create.dwHighDateTime;
        result = u.QuadPart;
    }
    CloseHandle(h);
    return result;
}

// 结束进程树时用快照建父->子映射,BFS 收集后代;带 PID 复用防护(后代创建时间需晚于根)。
QVector<int> collectDescendants(int rootPid)
{
    QVector<int> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return result;

    QHash<int, QVector<int>> childrenByParent;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            const int pid = static_cast<int>(pe.th32ProcessID);
            const int ppid = static_cast<int>(pe.th32ParentProcessID);
            if (pid > 4)
                childrenByParent[ppid].push_back(pid);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    const quint64 rootStart = processCreationTime(rootPid);
    QSet<int> visited;
    visited.insert(rootPid);
    QVector<int> queue;
    queue.push_back(rootPid);
    constexpr int kMaxNodes = 4096;

    for (int qi = 0; qi < queue.size() && result.size() < kMaxNodes; ++qi) {
        const int cur = queue[qi];
        auto it = childrenByParent.constFind(cur);
        if (it == childrenByParent.constEnd())
            continue;
        for (int kid : it.value()) {
            if (visited.contains(kid))
                continue;
            visited.insert(kid);
            // PID 复用防护:若子进程创建时间早于根,说明是被复用的旧 PID,跳过。
            if (rootStart != 0) {
                const quint64 kidStart = processCreationTime(kid);
                if (kidStart != 0 && kidStart < rootStart)
                    continue;
            }
            result.push_back(kid);
            queue.push_back(kid);
        }
    }
    return result;
}

} // namespace

bool ProcessInspector::ensureDebugPrivilege()
{
    static bool s_result = []() -> bool {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;
        LUID luid;
        bool ok = false;
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            ok = (GetLastError() == ERROR_SUCCESS);
        }
        CloseHandle(token);
        return ok;
    }();
    return s_result;
}

bool ProcessInspector::isCriticalProcess(int pid)
{
    if (pid <= 4)
        return true; // System Idle / System

    const int kernel = queryKernelCritical(pid);
    if (kernel == 1)
        return true;
    if (kernel == -1)
        return true; // fail-safe:无法确认(受保护进程)一律视为关键,绝不冒险结束

    const QString path = tryGetProcessImagePath(pid);
    if (path.isEmpty())
        return true; // 拿不到映像路径同样保守处理

    // 名字命中关键进程名单【且】映像真的在系统目录里,才算关键进程。
    //
    // 只按名字判会把「改名成系统进程」这一最基础的伪装手法变成免杀护身符:实测机器上
    // C:\Users\<u>\AppData\Local\DBG\csrss.exe(SalatStealer,情报已确认恶意)就是靠这里
    // 拿到豁免 —— 用户态每 60 秒重试结束一次,连续几十小时"用户态结束 0 个"。
    // 真系统进程不受影响:它们本就在 System32,且上面的 IsProcessCritical 已经先拦一道。
    const QString name = QFileInfo(path).fileName().toLower();
    if (criticalNames().contains(name) && isSystemImageDir(path))
        return true;

    return false;
}

bool ProcessInspector::waitForExit(int pid, int msTimeout)
{
    if (pid <= 0)
        return true;
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(pid));
    if (!h) {
        // PID 根本不存在 = 已退出并被回收。其余失败(多为拒绝访问)= 无法确认,如实返回 false。
        return GetLastError() == ERROR_INVALID_PARAMETER;
    }
    // 进程对象在进程终止时进入已信号态 —— 即便还有别人持着它的句柄(僵尸)也一样。
    // 这正是「PID 还在快照里」判不出来的那种情况。
    const DWORD w = WaitForSingleObject(h, msTimeout < 0 ? 0 : static_cast<DWORD>(msTimeout));
    CloseHandle(h);
    return w == WAIT_OBJECT_0;
}

bool ProcessInspector::tryTerminateProcess(int pid)
{
    if (pid <= 4)
        return false;
    ensureDebugPrivilege();
    if (isCriticalProcess(pid))
        return false; // 关键进程安全门槛:直接跳过

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return false;
    const BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok != FALSE;
}

int ProcessInspector::terminateProcessTree(int rootPid)
{
    if (rootPid <= 4)
        return 0;
    ensureDebugPrivilege();

    int killed = 0;
    const QVector<int> descendants = collectDescendants(rootPid);
    // 先叶后根:从最后收集的后代往回结束,最后结束根,尽量减少"孤儿再派生"。
    for (int i = descendants.size() - 1; i >= 0; --i) {
        if (tryTerminateProcess(descendants[i]))
            ++killed;
    }
    if (tryTerminateProcess(rootPid))
        ++killed;
    return killed;
}

// NtSuspendProcess / NtResumeProcess 未在公开头声明,运行时从 ntdll 取。用于 VT 研判期间
// 冻结可疑进程(挂起其全部线程),对应 .NET Monitoring/ProcessControl。成功返回 true。
namespace {
using NtProcFn = LONG(NTAPI*)(HANDLE);
NtProcFn ntdllProc(const char* name) {
    static HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtProcFn>(GetProcAddress(ntdll, name)) : nullptr;
}
bool ntControlProcess(int pid, const char* fnName) {
    if (pid <= 0) return false;
    const NtProcFn fn = ntdllProc(fnName);
    if (!fn) return false;
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));
    if (!h) return false;
    const LONG st = fn(h);
    CloseHandle(h);
    return st == 0;
}
} // namespace

bool ProcessInspector::trySuspend(int pid) { return ntControlProcess(pid, "NtSuspendProcess"); }
bool ProcessInspector::tryResume(int pid)  { return ntControlProcess(pid, "NtResumeProcess"); }
