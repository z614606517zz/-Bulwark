#include "bulwark/service/UpdateService.h"

#include "bulwark/UpdateTrust.h"
#include "bulwark/Version.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/reputation/ReputationCurl.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include <algorithm>

// apply() 用 MoveFileExW / CopyFileW 直接操作:Qt 的 QFile::rename 在目标存在时行为
// 依平台而异,而这里需要的正是「替换已存在项」和「重启后删除」这两个 Win32 专有语义。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using bulwark::service::reputation::ReputationCurl;
using bulwark::service::monitoring::ProcessInspector;

namespace bulwark::service {

namespace {

// 文件 SHA-256(小写十六进制)。流式读取:载荷是几 MB 的 PE,不整块进内存。
QString fileSha256(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f))
        return QString();
    return QString::fromLatin1(h.result().toHex());
}

} // namespace

QString UpdateService::stagingRoot()
{
    // %LOCALAPPDATA% 而不是 %ProgramData%\Bulwark / 安装目录:后两者在内核 SelfGuard
    // 守护范围内,非本产品进程写入会被直接拒绝。详见头文件里的说明。
    QString base = qEnvironmentVariable("LOCALAPPDATA");
    if (base.trimmed().isEmpty())
        base = QDir::tempPath();
    return QDir(base).filePath(QStringLiteral("Bulwark/update"));
}

UpdateService::UpdateService(const BulwarkOptions& options)
{
    // 端点复用信誉代理解析出的地址(Update.BaseUrl 留空时),与 AttackChainEngine 同一取舍:
    // 本来就是同一台服务器,把混淆后的 URL 在配置里写第二遍只会多一处会跑偏的地方。
    const QString repBase = options.ReputationProxy.resolveBaseUrl().trimmed();
    baseUrl_ = options.Update.resolveBaseUrl(repBase);
    maskedUrl_ = ReputationProxyOptions::maskUrl(baseUrl_);
    token_ = options.ReputationProxy.resolveToken();
    channel_ = options.Update.Channel.trimmed().isEmpty() ? QStringLiteral("stable")
                                                          : options.Update.Channel.trimmed().toLower();
    if (options.Update.QueryTimeoutSeconds > 0)
        timeoutSecs_ = options.Update.QueryTimeoutSeconds;
    if (options.Update.DownloadTimeoutSeconds > 0)
        downloadTimeoutSecs_ = options.Update.DownloadTimeoutSeconds;
    extraThumbprints_ = options.Update.AllowedThumbprints;
    enabled_ = options.Update.Enabled;

    ReputationCurl::diag(QStringLiteral("Update init: enabled=%1 base=%2 channel=%3 current=%4")
                             .arg(enabled_ ? QStringLiteral("1") : QStringLiteral("0"),
                                  maskedUrl_, channel_, version::current()));
}

UpdateInfo UpdateService::check()
{
    UpdateInfo out;
    if (!enabled_) {
        out.error = QStringLiteral("在线更新已在配置中关闭(Bulwark:Update:Enabled=false)。");
        return out;
    }
    if (baseUrl_.isEmpty()) {
        out.error = QStringLiteral("未配置更新端点,也没有可复用的信誉代理地址。");
        return out;
    }
    // http 明文一律拒绝。更新是「下载并以 SYSTEM 执行」,明文信道上任何人都能替换载荷;
    // 虽然签名校验仍会拦住,但没有理由先把自己放到那个位置。localhost 放行,便于本地联调。
    if (!baseUrl_.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)
        && !baseUrl_.contains(QStringLiteral("127.0.0.1"))
        && !baseUrl_.contains(QStringLiteral("localhost"), Qt::CaseInsensitive)) {
        out.error = QStringLiteral("更新端点不是 https —— 拒绝在明文信道上取更新。");
        return out;
    }

    const QString url = baseUrl_ + QStringLiteral("/v1/update/manifest?channel=") + channel_;
    QStringList headers;
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);

    const auto res = ReputationCurl::get(url, headers, timeoutSecs_);
    if (res.first == 0) {
        out.error = QStringLiteral("连不上更新服务器(网络不通或 curl 不可用)。");
        return out;
    }
    if (res.first != 200) {
        out.error = QStringLiteral("更新服务器返回 HTTP ") + QString::number(res.first);
        return out;
    }

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.second.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        out.error = QStringLiteral("更新清单不是合法 JSON。");
        return out;
    }
    const QJsonObject o = doc.object();

    // 服务器用 available=false 表达「还没发布任何版本」。那是正常状态,不是错误 ——
    // 必须与「网络不通 / 端点配错」区分开,否则界面上只会笼统地写一句「检查更新失败」。
    out.ok = true;
    if (!o.value(QLatin1String("available")).toBool()) {
        out.available = false;
        return out;
    }

    out.version = o.value(QLatin1String("version")).toString().trimmed();
    out.label = o.value(QLatin1String("label")).toString().trimmed();
    out.notes = o.value(QLatin1String("notes")).toString();
    out.publishedUtc = o.value(QLatin1String("published")).toString().trimmed();

    for (const QJsonValue& v : o.value(QLatin1String("files")).toArray()) {
        const QJsonObject f = v.toObject();
        UpdateFileInfo fi;
        fi.name = f.value(QLatin1String("name")).toString().trimmed();
        fi.size = static_cast<qint64>(f.value(QLatin1String("size")).toDouble());
        fi.sha256 = f.value(QLatin1String("sha256")).toString().trimmed().toLower();
        fi.url = f.value(QLatin1String("url")).toString().trimmed();
        // 白名单在【收下清单的第一刻】就过,而不是等到下载时才判 —— 一份含
        // "..\\..\\windows\\system32\\x.dll" 的清单不该有机会走到拼路径那一步。
        if (!update::isAllowedPayloadName(fi.name)) {
            out.ok = false;
            out.available = false;
            out.error = QStringLiteral("更新清单包含不被允许的文件名,已整份拒绝。");
            ReputationCurl::diag(QStringLiteral("Update: rejected manifest, bad payload name"));
            return out;
        }
        if (fi.size <= 0 || fi.sha256.size() != 64) {
            out.ok = false;
            out.available = false;
            out.error = QStringLiteral("更新清单里的大小或哈希不合法,已整份拒绝。");
            return out;
        }
        out.totalBytes += fi.size;
        out.files.append(fi);
    }
    if (out.files.isEmpty()) {
        out.available = false;
        out.error = QStringLiteral("更新清单没有列出任何文件。");
        return out;
    }

    // 版本比较用逐段数字,不做字符串比较(否则 "1.10.0" < "1.2.0")。
    // 方向上宁可漏报:解析不出来就当没有更新,绝不弹一个下载不下来的提示。
    out.available = version::isNewerThanCurrent(out.version);
    ReputationCurl::diag(QStringLiteral("Update check: remote=%1 current=%2 available=%3 files=%4")
                             .arg(out.version, version::current(),
                                  out.available ? QStringLiteral("1") : QStringLiteral("0"))
                             .arg(out.files.size()));
    return out;
}

bool UpdateService::verifyFile(const QString& path, const UpdateFileInfo& want, QString* error) const
{
    const auto fail = [error](const QString& m) { if (error) *error = m; return false; };

    const QFileInfo fi(path);
    if (!fi.exists())
        return fail(QStringLiteral("下载后文件不存在"));

    // 2) 大小
    if (fi.size() != want.size)
        return fail(QStringLiteral("大小不符:期望 %1,实际 %2").arg(want.size).arg(fi.size()));

    // 3) SHA-256
    const QString got = fileSha256(path);
    if (got.isEmpty())
        return fail(QStringLiteral("无法计算 SHA-256(文件被占用?)"));
    if (got.compare(want.sha256, Qt::CaseInsensitive) != 0)
        return fail(QStringLiteral("SHA-256 不符 —— 传输损坏或文件被替换"));

    // 4) Authenticode + 钉死指纹。这一道才是真正的信任锚点:上面三道全部是服务器
    //    自己声明的东西,只能证明「下载没坏」。
    if (update::requiresSignature(want.name)) {
        if (!ProcessInspector::hasEmbeddedSignature(path))
            return fail(QStringLiteral("没有内嵌 Authenticode 签名 —— 拒绝安装"));
        const auto ci = ProcessInspector::getCertInfo(path);
        const QString tp = update::normalizeThumbprint(ci.thumbprint);
        if (tp.isEmpty())
            return fail(QStringLiteral("读不到签名者证书指纹 —— 拒绝安装"));
        const QSet<QString> pinned = update::pinnedThumbprints(extraThumbprints_);
        if (!pinned.contains(tp))
            return fail(QStringLiteral("签名者不在钉死名单内(指纹 ") + tp.left(16)
                        + QStringLiteral("…)—— 拒绝安装"));
        // 完整性:签名必须真的覆盖当前这些字节。指纹对得上并不证明内容没被动过 ——
        // 改掉 PE 里一个字节不会破坏内嵌的签名块,证书还在、指纹还是我们那张,只有
        // 摘要不再匹配。所以指纹(身份)和摘要(完整性)必须分别校验。
        //
        // 这里【刻意】按状态码判,而不是用 isSignatureMismatch():后者把所有非成功状态
        // 塌缩成「不可信」,于是「文件被改过」和「这台机器没导入我们的自签根证书」变成
        // 同一个答案。而驱动用的正是自签测试证书 —— 目标机器上「根不受信任」是常态。
        // 用它做闸门的后果是每一次更新都被判成「疑似被篡改」而拒装,实测踩过:
        //   Bulwark.sys 校验失败:签名与文件内容不匹配(疑似被篡改)—— 拒绝安装
        // 而那份文件与本地发布的副本逐字节相同、SHA-256 也已经过了。
        //
        // 放行「链不受信」是安全的:本通路的信任锚点是上面钉死的签名者指纹,不是
        // 目标机器的证书存储 —— 后者是我们自己在安装时导入的,不构成独立证据。
        const auto sigStatus = static_cast<quint32>(ProcessInspector::embeddedSignatureStatus(path));

        // 签名块与文件内容对不上 —— 这是唯一真正说明「被改动过」的状态。
        constexpr quint32 kBadDigest = 0x80096010u;   // TRUST_E_BAD_DIGEST
        if (sigStatus == kBadDigest)
            return fail(QStringLiteral("签名与文件内容不匹配(下载后被改动过)—— 拒绝安装"));

        // 只是「链建不起来 / 根不受信任」:可接受。目标机器的证书存储不是本通路的
        // 信任锚点(那张根证书本来就是我们安装时自己导入的,不构成独立证据),
        // 真正的锚点是上面已经比对过的钉死指纹。
        constexpr quint32 kUntrustedRoot     = 0x800B0109u;  // CERT_E_UNTRUSTEDROOT
        constexpr quint32 kChaining          = 0x800B010Au;  // CERT_E_CHAINING
        constexpr quint32 kUntrustedTestRoot = 0x800B010Du;  // CERT_E_UNTRUSTEDTESTROOT
        const bool chainOnly = (sigStatus == kUntrustedRoot || sigStatus == kChaining
                                || sigStatus == kUntrustedTestRoot);

        // 其余状态(过期、用途不符、签名结构损坏……)一律拒,并把状态码原样报出来。
        // 上一版把所有失败都说成「疑似被篡改」,结果真出问题时这句话把人带向了错误的
        // 方向 —— 状态码写出来,下次一眼就能定位。
        if (sigStatus != 0u && !chainOnly)
            return fail(QStringLiteral("签名校验未通过(WinVerifyTrust 0x")
                        + QString::number(sigStatus, 16).rightJustified(8, QLatin1Char('0'))
                        + QStringLiteral(")—— 拒绝安装"));
        if (ci.revoked)
            return fail(QStringLiteral("签名者证书已被吊销 —— 拒绝安装"));
    }
    return true;
}

namespace {

const wchar_t* wstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString win32Reason(DWORD err)
{
    // 把错误码翻成人话。只说「替换失败」害过我们一次:真实原因是文件被锁,
    // 而从现象上完全看不出来是占用还是权限。
    switch (err) {
    case ERROR_ACCESS_DENIED:      return QStringLiteral("访问被拒绝(可能被其他安全软件或自我保护拦下)");
    case ERROR_SHARING_VIOLATION:  return QStringLiteral("文件正被其他进程占用");
    case ERROR_FILE_NOT_FOUND:     return QStringLiteral("文件不存在");
    case ERROR_PATH_NOT_FOUND:     return QStringLiteral("路径不存在");
    case ERROR_DISK_FULL:          return QStringLiteral("磁盘空间不足");
    default:                       return QStringLiteral("Windows 错误 %1").arg(err);
    }
}

// 一次替换的记录,用于失败时按相反顺序回退。
struct SwapStep {
    QString target;   // 安装目录里的最终路径
    QString parked;   // 旧映像被改名后的路径(空 = 原本不存在,无需还原)
    bool    placed = false;  // 新文件是否已就位
};

} // namespace

UpdateApplyResult UpdateService::apply(const UpdateInfo& info, const QString& stagingDir)
{
    UpdateApplyResult r;

    if (stagingDir.isEmpty() || !QDir(stagingDir).exists()) {
        r.error = QStringLiteral("找不到已下载的更新文件,请重新下载。");
        return r;
    }

    // ---- 1) 使用的那一刻重新校验一遍 ----------------------------------------
    // 下载时已经校验过。这里【再来一遍】不是多余:暂存目录在 %LOCALAPPDATA%,普通用户
    // 可写,从「校验通过」到「真正取用」之间任何以该用户身份运行的进程都能把文件换掉。
    // 而接下来这些字节会被放进安装目录、其中一个还会作为内核驱动加载 —— 这是本产品里
    // 权限最高的一次写入,校验必须发生在使用的那一刻。
    if (info.files.isEmpty()) {
        r.error = QStringLiteral("更新清单为空,拒绝应用。");
        return r;
    }
    for (const UpdateFileInfo& f : info.files) {
        const QString path = QDir(stagingDir).filePath(f.name);
        QString why;
        if (!verifyFile(path, f, &why)) {
            r.error = f.name + QStringLiteral(" 校验失败:") + why;
            return r;
        }
    }

    // ---- 2) 只许前进 --------------------------------------------------------
    // 拒绝同版本与降级。降级是一条真实攻击路径:用一个【签名合法】的旧版本把已经修掉的
    // 漏洞换回来。
    if (!bulwark::version::isNewerThanCurrent(info.version)) {
        r.error = QStringLiteral("待装版本 %1 不比当前版本 %2 新,拒绝应用。")
                      .arg(info.version, bulwark::version::current());
        return r;
    }

    const QString installDir = QCoreApplication::applicationDirPath();
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"));

    // ---- 3) 逐个「旧的改名让位 -> 新的放到原名」 ----------------------------
    // 顺序固定,且每一步都记进 steps,失败时按相反顺序回退。
    QList<SwapStep> steps;
    bool failed = false;
    QString failName, failWhy;

    for (const UpdateFileInfo& f : info.files) {
        SwapStep st;
        st.target = QDir(installDir).filePath(f.name);
        const QString src = QDir(stagingDir).filePath(f.name);

        if (QFileInfo::exists(st.target)) {
            st.parked = st.target + QStringLiteral(".old-") + stamp;
            if (!MoveFileExW(wstr(st.target), wstr(st.parked), MOVEFILE_REPLACE_EXISTING)) {
                const DWORD e = GetLastError();
                failed = true; failName = f.name;
                failWhy = QStringLiteral("旧文件改名让位失败 —— ") + win32Reason(e);
                break;
            }
        }
        if (!CopyFileW(wstr(src), wstr(st.target), FALSE)) {
            const DWORD e = GetLastError();
            // 新文件没放成,先把刚改名的还原,再交给统一回退处理其余步骤。
            if (!st.parked.isEmpty())
                MoveFileExW(wstr(st.parked), wstr(st.target), MOVEFILE_REPLACE_EXISTING);
            failed = true; failName = f.name;
            failWhy = QStringLiteral("新文件写入失败 —— ") + win32Reason(e);
            break;
        }
        st.placed = true;
        steps.append(st);
        ++r.replaced;
    }

    if (failed) {
        // ---- 回退 ----------------------------------------------------------
        // 目标不是「恢复文件」,而是「恢复到一个可运行的状态」:装一半会得到
        // 新旧混版,比不装危险。
        for (int i = steps.size() - 1; i >= 0; --i) {
            const SwapStep& st = steps[i];
            if (st.placed) DeleteFileW(wstr(st.target));
            if (!st.parked.isEmpty())
                MoveFileExW(wstr(st.parked), wstr(st.target), MOVEFILE_REPLACE_EXISTING);
        }
        r.replaced = 0;
        r.rolledBack = true;
        r.needsRestart = false;
        r.error = failName + QStringLiteral(":") + failWhy
                  + QStringLiteral("。已回退,当前版本未被改动。");
        return r;
    }

    // ---- 4) 让位的旧映像:能删就删,删不掉排进重启删除队列 ------------------
    // 运行中的进程还映射着它们,所以现在通常删不掉 —— 这是正常的,不是错误,
    // 因此不影响 ok。实测 MOVEFILE_DELAY_UNTIL_REBOOT 在管理员下可用(err=0)。
    for (const SwapStep& st : steps) {
        if (st.parked.isEmpty()) continue;
        if (DeleteFileW(wstr(st.parked))) continue;
        MoveFileExW(wstr(st.parked), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    r.ok = true;
    r.needsRestart = true;
    return r;
}

UpdateDownloadResult UpdateService::download(
    const UpdateInfo& info, const std::function<void(int, int, QString, QString)>& onProgress)
{
    UpdateDownloadResult r;
    if (!info.ok || !info.available || info.files.isEmpty()) {
        r.error = QStringLiteral("没有可下载的更新。");
        return r;
    }
    if (baseUrl_.isEmpty()) {
        r.error = QStringLiteral("未配置更新端点。");
        return r;
    }

    // 每个版本一个独立目录,并且每次下载前清空 —— 上一次失败留下的半个文件绝不能
    // 被这一次当成「已经下好了」。
    const QString dir = QDir(stagingRoot()).filePath(info.version);
    QDir d(dir);
    if (d.exists())
        d.removeRecursively();
    if (!QDir().mkpath(dir)) {
        r.error = QStringLiteral("无法创建暂存目录:") + dir;
        return r;
    }
    r.stagingDir = dir;

    QStringList headers;
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);

    const int total = info.files.size();
    int done = 0;
    for (const UpdateFileInfo& f : info.files) {
        // 名字已在 check() 过白名单;这里再拼一次前也不用 f.url 里的路径,只用文件名,
        // 免得服务器给的 url 字段成为第二条能影响落盘位置的输入。
        const QString dest = QDir(dir).filePath(f.name);
        QString url = f.url;
        if (url.startsWith(QLatin1Char('/')))
            url = baseUrl_ + url;
        else
            url = baseUrl_ + QStringLiteral("/v1/update/file/") + channel_ + QLatin1Char('/') + f.name;

        if (onProgress) onProgress(done, total, f.name, QStringLiteral("下载中"));
        const auto res = ReputationCurl::download(url, dest, headers, downloadTimeoutSecs_);
        if (res.first != 200) {
            // 非 200 时 curl 已经把错误响应体写进了目标文件,必须删掉:留着就是一个
            // 长度不对的 exe 躺在暂存目录里。
            QFile::remove(dest);
            r.error = QStringLiteral("下载 %1 失败(HTTP %2)").arg(f.name).arg(res.first);
            d.removeRecursively();
            return r;
        }

        if (onProgress) onProgress(done, total, f.name, QStringLiteral("校验中"));
        QString why;
        if (!verifyFile(dest, f, &why)) {
            r.error = QStringLiteral("%1 校验失败:%2").arg(f.name, why);
            ReputationCurl::diag(QStringLiteral("Update REJECT %1: %2").arg(f.name, why));
            // 整份放弃并清空。装一半会让机器上出现「新 exe + 旧驱动」,比不更新危险得多。
            d.removeRecursively();
            r.stagingDir.clear();
            return r;
        }
        ++done;
        ++r.verified;
        if (onProgress) onProgress(done, total, f.name, QStringLiteral("已校验"));
    }

    r.ok = true;
    ReputationCurl::diag(QStringLiteral("Update staged %1 file(s) for %2 at %3")
                             .arg(r.verified).arg(info.version, dir));
    return r;
}

} // namespace bulwark::service
