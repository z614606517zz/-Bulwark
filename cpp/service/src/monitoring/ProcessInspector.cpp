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

// ---- 文件身份(用于缓存键);文件不存在则返回空(不缓存瞬态缺失) ----------------
QString fileIdentity(const QString& path)
{
    if (path.isEmpty())
        return QString();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
        return QString();
    return path.toLower() + QLatin1Char('|')
         + QString::number(fi.size()) + QLatin1Char('|')
         + QString::number(fi.lastModified().toUTC().toMSecsSinceEpoch());
}

// ---- 轻量事实缓存(每类事实一张表,统一互斥) --------------------------------
constexpr int kCacheCapacity = 8192;
QMutex g_cacheMx;

template <typename T, typename F>
T cachedFact(QHash<QString, T>& store, const QString& path, F compute)
{
    const QString id = fileIdentity(path);
    if (id.isEmpty())
        return compute();
    {
        QMutexLocker lk(&g_cacheMx);
        auto it = store.constFind(id);
        if (it != store.constEnd())
            return it.value();
    }
    T value = compute(); // 在锁外计算,避免长 I/O 持锁;竞态下重复计算无害
    {
        QMutexLocker lk(&g_cacheMx);
        if (store.size() >= kCacheCapacity)
            store.clear();
        store.insert(id, value);
    }
    return value;
}

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

} // namespace

// ============================ 签名 / 证书 内部实现 ============================
namespace {

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

bool ProcessInspector::isSigned(const QString& path)
{
    static QHash<QString, bool> cache;
    return cachedFact(cache, path, [&]() -> bool {
        if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
            return false;
        if (verifyEmbeddedSignature(path))
            return true;
        return verifyCatalogSignature(path);
    });
}

QString ProcessInspector::tryGetPublisher(const QString& path)
{
    static QHash<QString, QString> cache;
    return cachedFact(cache, path, [&]() -> QString {
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
    });
}

QString ProcessInspector::tryComputeSha256(const QString& path)
{
    static QHash<QString, QString> cache;
    return cachedFact(cache, path, [&]() -> QString {
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
    });
}

bool ProcessInspector::hasEmbeddedSignature(const QString& path)
{
    static QHash<QString, bool> cache;
    return cachedFact(cache, path, [&]() -> bool {
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
    });
}

bool ProcessInspector::isSignatureMismatch(const QString& path)
{
    // 内嵌了签名但不受信 = 失配(篡改 / 盗用证书的典型特征)。
    return hasEmbeddedSignature(path) && !isSigned(path);
}

ProcessInspector::CertInfo ProcessInspector::getCertInfo(const QString& path)
{
    static QHash<QString, CertInfo> cache;
    return cachedFact(cache, path, [&]() -> CertInfo {
        CertInfo info;
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
    });
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

    const QString name = QFileInfo(path).fileName().toLower();
    if (criticalNames().contains(name))
        return true;

    return false;
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
