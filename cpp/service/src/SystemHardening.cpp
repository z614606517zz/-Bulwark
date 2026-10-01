#include "bulwark/service/SystemHardening.h"

#include <QDateTime>
#include <QFileInfo>
#include <QMutexLocker>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <thread>
#include <vector>

namespace bulwark::service {

namespace {

inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }

// RAII:LocalFree / 关句柄。ACL 这一套 API 到处都要手工释放,漏一个就是长期运行的泄漏。
struct LocalFreer {
    void* p = nullptr;
    ~LocalFreer() { if (p) ::LocalFree(p); }
};
struct KeyCloser {
    HKEY k = nullptr;
    ~KeyCloser() { if (k) ::RegCloseKey(k); }
};
struct HandleCloser {
    HANDLE h = nullptr;
    ~HandleCloser() { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
};

// Everyone(S-1-1-0)。用 CreateWellKnownSid 而不是写死字符串:本地化系统上按名字查会失败。
bool everyoneSid(std::vector<BYTE>& out) {
    DWORD n = SECURITY_MAX_SID_SIZE;
    out.assign(n, 0);
    if (!::CreateWellKnownSid(WinWorldSid, nullptr, out.data(), &n))
        return false;
    out.resize(n);
    return true;
}

// 在对象的 DACL 里加一条 DENY ACE。已存在同样的一条则直接成功(幂等)。
bool addDenyAce(const QString& objectName, SE_OBJECT_TYPE type, DWORD mask, DWORD* winerr) {
    std::vector<BYTE> sid;
    if (!everyoneSid(sid)) {
        if (winerr) *winerr = ::GetLastError();
        return false;
    }
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD rc = ::GetNamedSecurityInfoW(wstr(objectName), type, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &oldDacl, nullptr, &sd);
    LocalFreer sdFree{sd};
    if (rc != ERROR_SUCCESS) {
        if (winerr) *winerr = rc;
        return false;
    }
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid.data());
    PACL newDacl = nullptr;
    rc = ::SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
    LocalFreer daclFree{newDacl};
    if (rc != ERROR_SUCCESS) {
        if (winerr) *winerr = rc;
        return false;
    }
    rc = ::SetNamedSecurityInfoW(const_cast<LPWSTR>(wstr(objectName)), type,
                                 DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    if (winerr) *winerr = rc;
    return rc == ERROR_SUCCESS;
}

// 删掉【正好是我们加的那一条】DENY ACE。
//
// 刻意不用 SetEntriesInAcl 的 REVOKE_ACCESS:那会把该主体的【全部】ACE 一并删掉,
// 包括本来就存在的 ALLOW Everyone —— 很多正常文件上都有。撤销一个封堵顺手拆掉别人的
// 权限设置是不可接受的,所以这里逐条走 DACL,只删类型/主体/掩码三者都对上的那条。
bool removeDenyAce(const QString& objectName, SE_OBJECT_TYPE type, DWORD mask, DWORD* winerr,
                   int* removedCount) {
    if (removedCount) *removedCount = 0;
    std::vector<BYTE> sid;
    if (!everyoneSid(sid)) {
        if (winerr) *winerr = ::GetLastError();
        return false;
    }
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD rc = ::GetNamedSecurityInfoW(wstr(objectName), type, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &dacl, nullptr, &sd);
    LocalFreer sdFree{sd};
    if (rc != ERROR_SUCCESS) {
        if (winerr) *winerr = rc;
        return false;
    }
    if (!dacl) {
        if (winerr) *winerr = ERROR_SUCCESS;
        return true;   // 没有 DACL 就没有我们的 ACE,视为已撤销
    }
    ACL_SIZE_INFORMATION si{};
    if (!::GetAclInformation(dacl, &si, sizeof(si), AclSizeInformation)) {
        if (winerr) *winerr = ::GetLastError();
        return false;
    }
    // 从后往前删:删掉一条会让后面的下标前移。
    bool changed = false;
    for (LONG i = static_cast<LONG>(si.AceCount) - 1; i >= 0; --i) {
        void* ace = nullptr;
        if (!::GetAce(dacl, static_cast<DWORD>(i), &ace) || !ace)
            continue;
        auto* hdr = static_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_DENIED_ACE_TYPE)
            continue;
        auto* d = static_cast<ACCESS_DENIED_ACE*>(ace);
        PSID aceSid = reinterpret_cast<PSID>(&d->SidStart);
        if (!::EqualSid(aceSid, reinterpret_cast<PSID>(sid.data())))
            continue;
        if (d->Mask != mask)
            continue;   // 别人加的、掩码不同的 DENY 不碰
        if (::DeleteAce(dacl, static_cast<DWORD>(i))) {
            changed = true;
            if (removedCount) ++(*removedCount);
        }
    }
    if (!changed) {
        if (winerr) *winerr = ERROR_SUCCESS;
        return true;   // 本来就没有
    }
    rc = ::SetNamedSecurityInfoW(const_cast<LPWSTR>(wstr(objectName)), type,
                                 DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    if (winerr) *winerr = rc;
    return rc == ERROR_SUCCESS;
}

bool hasDenyAce(const QString& objectName, SE_OBJECT_TYPE type, DWORD mask) {
    std::vector<BYTE> sid;
    if (!everyoneSid(sid))
        return false;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (::GetNamedSecurityInfoW(wstr(objectName), type, DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    LocalFreer sdFree{sd};
    if (!dacl)
        return false;
    ACL_SIZE_INFORMATION si{};
    if (!::GetAclInformation(dacl, &si, sizeof(si), AclSizeInformation))
        return false;
    for (DWORD i = 0; i < si.AceCount; ++i) {
        void* ace = nullptr;
        if (!::GetAce(dacl, i, &ace) || !ace)
            continue;
        auto* hdr = static_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_DENIED_ACE_TYPE)
            continue;
        auto* d = static_cast<ACCESS_DENIED_ACE*>(ace);
        if (::EqualSid(reinterpret_cast<PSID>(&d->SidStart),
                       reinterpret_cast<PSID>(sid.data())) && d->Mask == mask)
            return true;
    }
    return false;
}

// "HKLM\SOFTWARE\..." -> (HKEY_LOCAL_MACHINE, "SOFTWARE\...")
bool splitHive(const QString& full, HKEY* hive, QString* sub, QString* hiveName) {
    const int i = full.indexOf(QLatin1Char('\\'));
    if (i <= 0)
        return false;
    const QString h = full.left(i).toUpper();
    *sub = full.mid(i + 1);
    if (h == QLatin1String("HKLM") || h == QLatin1String("HKEY_LOCAL_MACHINE")) {
        *hive = HKEY_LOCAL_MACHINE;
        *hiveName = QStringLiteral("MACHINE");
    } else if (h == QLatin1String("HKCU") || h == QLatin1String("HKEY_CURRENT_USER")) {
        *hive = HKEY_CURRENT_USER;
        *hiveName = QStringLiteral("CURRENT_USER");
    } else if (h == QLatin1String("HKU") || h == QLatin1String("HKEY_USERS")) {
        *hive = HKEY_USERS;
        *hiveName = QStringLiteral("USERS");
    } else {
        return false;
    }
    return true;
}

// SetNamedSecurityInfo 用的注册表对象名要求 "MACHINE\..." / "CURRENT_USER\..." 这种前缀,
// 不是 "HKLM\..."。写错的话返回的是 ERROR_FILE_NOT_FOUND,很容易被当成「键不存在」。
QString regObjectName(const QString& full) {
    HKEY hive = nullptr;
    QString sub, hiveName;
    if (!splitHive(full, &hive, &sub, &hiveName))
        return QString();
    return hiveName + QLatin1Char('\\') + sub;
}

// 共享键名单:这些键上加 DENY 会打断正常软件。见头文件第 8 条。
bool isSharedRegistryKey(const QString& full) {
    const QString p = full.toLower();
    static const char* kShared[] = {
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\currentversion\\runonceex",
        "\\currentversion\\policies",
        "\\currentversion\\winlogon",
        "\\currentversion\\image file execution options",
        "\\currentcontrolset\\services",
        "\\currentversion\\explorer\\shell folders",
        "\\classes",
    };
    for (const char* s : kShared) {
        const QString needle = QString::fromLatin1(s);
        // 尾部完全等于该前缀(即「就是这个共享键本身」)才算共享;它下面恶意软件自建的
        // 子键仍可视为独占 —— 例如 ...\Services\<malware> 是独占的,\Services 根不是。
        if (p.endsWith(needle))
            return true;
    }
    return false;
}

QString regReadString(HKEY hive, const QString& sub, const QString& value, bool* present) {
    if (present) *present = false;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(hive, wstr(sub), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return QString();
    KeyCloser kc{k};
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(k, wstr(value), nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return QString();
    if (type == REG_DWORD) {
        DWORD v = 0;
        cb = sizeof(v);
        if (::RegQueryValueExW(k, wstr(value), nullptr, &type,
                               reinterpret_cast<LPBYTE>(&v), &cb) == ERROR_SUCCESS) {
            if (present) *present = true;
            return QString::number(v);
        }
        return QString();
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ)
        return QString();
    std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 2, 0);
    cb = static_cast<DWORD>((buf.size() - 1) * sizeof(wchar_t));
    if (::RegQueryValueExW(k, wstr(value), nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &cb) != ERROR_SUCCESS)
        return QString();
    if (present) *present = true;
    return QString::fromWCharArray(buf.data());
}

// 服务 DACL 是否已经足够紧:逐条 ACE 解析,而不是在整串 SDDL 上做子串匹配。
//
// 【第一版就是子串匹配,而且当场报了假警】它写的是「SDDL 里出现 ;AU) 或 ;IU) 就算未加固」。
// 本机实测读到的 DACL 是:
//   D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
//    (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
// IU / SU 拿到的是 CC(查配置) LC(查状态) SW(枚举依赖) LO(询问) CR(自定义控制) RC(读 DACL)——
// 【没有】WP(停止)、DC(改配置)、SD(删除)。也就是说这台机器上服务 DACL 本来就是安全的,
// 而第一版把它报成「未加固」并建议用户去动它。一个只读体检报出不存在的问题,比不报更坏:
// 它会把人引向一次没有必要、却真的会改系统的操作。
//
// 所以判据必须落在【权限】上而不是【主体是否出现过】上:只有当宽泛主体真的握着
// 停止/改配置/删除/改 DACL/改所有者之一时,才算未加固。
//
// SDDL 里 "WD" 有两种含义:在权限字段是 WRITE_DAC,在 SID 字段是 Everyone。所以必须按字段
// 切开看,不能整串找 —— 这也是子串匹配在这里根本不成立的另一个原因。
bool serviceDaclIsTight(const QString& sddl) {
    // 取 D: 之后的部分;S:(SACL)不参与判断。
    int d = sddl.indexOf(QLatin1String("D:"));
    if (d < 0)
        return false;
    QString acl = sddl.mid(d + 2);
    const int s = acl.indexOf(QLatin1String("S:"));
    if (s >= 0)
        acl = acl.left(s);

    static const QStringList kBroad = {
        QStringLiteral("AU"),   // Authenticated Users
        QStringLiteral("IU"),   // Interactive
        QStringLiteral("SU"),   // Service
        QStringLiteral("BU"),   // Builtin Users
        QStringLiteral("WD"),   // Everyone(SID 位置)
        QStringLiteral("AN"),   // Anonymous
        QStringLiteral("LG"),   // Local Guest
    };
    static const QStringList kDangerous = {
        QStringLiteral("DC"),   // SERVICE_CHANGE_CONFIG
        QStringLiteral("WP"),   // SERVICE_STOP
        QStringLiteral("SD"),   // DELETE
        QStringLiteral("WD"),   // WRITE_DAC(权限位置)
        QStringLiteral("WO"),   // WRITE_OWNER
    };

    int i = 0;
    while (i < acl.size()) {
        const int open = acl.indexOf(QLatin1Char('('), i);
        if (open < 0)
            break;
        const int close = acl.indexOf(QLatin1Char(')'), open);
        if (close < 0)
            break;
        const QString ace = acl.mid(open + 1, close - open - 1);
        i = close + 1;
        const QStringList f = ace.split(QLatin1Char(';'));
        if (f.size() < 6)
            continue;
        if (!f[0].startsWith(QLatin1Char('A')))   // 只看 allow;deny 只会更紧
            continue;
        const QString rights = f[2];
        const QString sid = f[5];
        if (!kBroad.contains(sid, Qt::CaseInsensitive))
            continue;
        // 权限串是 2 字符一组的拼接,必须对齐扫描 —— 逐字符找会把 "LCSW" 之类切错。
        for (int k = 0; k + 1 < rights.size(); k += 2) {
            if (kDangerous.contains(rights.mid(k, 2), Qt::CaseInsensitive))
                return false;
        }
    }
    return true;
}

constexpr DWORD kFileExecuteMask = FILE_EXECUTE;       // 3.5
constexpr DWORD kRegSetValueMask = KEY_SET_VALUE;      // 3.2

} // namespace

SystemHardening::SystemHardening(QObject* parent) : QObject(parent) {}

SystemHardening::~SystemHardening() {
    stopWatching();
    // 刻意【不】在析构里撤销 DENY ACE:那是跨重启的持久状态,服务停止不代表用户想解除封堵。
    // 撤销必须是显式动作(加白 / undenyExecute),否则「重启一次就全解开」会让这一层形同虚设。
    QMutexLocker lk(&mx_);
    if (!deniedExec_.isEmpty()) {
        log_.info(QStringLiteral("加固:本次运行加过 %1 条「拒绝执行」ACE,它们【跨重启持久存在】,"
                                "服务停止不会解除(解除请在界面加白该程序)。")
                      .arg(deniedExec_.size()));
    }
}

void SystemHardening::setTrustProbe(TrustProbeFn fn) {
    QMutexLocker lk(&mx_);
    trustProbe_ = std::move(fn);
}

// ---------------------------------------------------------------- 3.3 / 3.4 只读体检
QVector<SystemHardening::Finding> SystemHardening::inspect() const {
    QVector<Finding> v;

    // 3.3 lsass RunAsPPL
    {
        Finding f;
        f.id = QStringLiteral("RunAsPPL");
        f.title = QStringLiteral("lsass 以受保护进程轻量级(PPL)运行");
        bool present = false;
        const QString cur = regReadString(HKEY_LOCAL_MACHINE,
                                          QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Lsa"),
                                          QStringLiteral("RunAsPPL"), &present);
        f.satisfied = present && (cur == QLatin1String("1") || cur == QLatin1String("2"));
        f.current = present ? QStringLiteral("RunAsPPL = %1").arg(cur)
                            : QStringLiteral("未设置(lsass 未受 PPL 保护)");
        f.recommended = QStringLiteral("设置 RunAsPPL = 2");
        f.cost = QStringLiteral("需重启生效。会让部分依赖读取 lsass 内存的软件失效"
                                "(单点登录代理、某些企业 VPN / 指纹驱动、部分调试器)。"
                                "【必须写 2 而不是 1】:1 会把该策略写进 UEFI 变量,之后从注册表"
                                "删掉这个值也关不掉;2 是「启用但不写 UEFI 变量」,可以从注册表撤销。");
        f.needsReboot = true;
        f.reversible = true;
        // 已经是 1 的情况要单独说清楚:那个状态【不是】我们能撤销的
        if (present && cur == QLatin1String("1")) {
            f.cost += QStringLiteral(" ⚠ 当前值是 1,该状态可能已写入 UEFI 变量,"
                                     "本产品无法保证能撤销它。");
            f.reversible = false;
        }
        v.push_back(f);
    }

    // 3.4 自身服务 DACL
    {
        Finding f;
        f.id = QStringLiteral("SelfServiceDacl");
        f.title = QStringLiteral("本服务的服务对象 DACL 收紧(阻止非管理员停止/改配置/删除)");
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        QString cur = QStringLiteral("未能读取服务安全描述符");
        bool sat = false;
        if (scm) {
            SC_HANDLE svc = ::OpenServiceW(scm, L"BulwarkService", READ_CONTROL);
            if (svc) {
                DWORD needed = 0;
                ::QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, nullptr, 0, &needed);
                if (needed > 0) {
                    std::vector<BYTE> buf(needed, 0);
                    if (::QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, buf.data(),
                                                     needed, &needed)) {
                        LPWSTR sddl = nullptr;
                        if (::ConvertSecurityDescriptorToStringSecurityDescriptorW(
                                buf.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl,
                                nullptr)
                            && sddl) {
                            cur = QString::fromWCharArray(sddl);
                            ::LocalFree(sddl);
                            sat = serviceDaclIsTight(cur);
                        }
                    }
                }
                ::CloseServiceHandle(svc);
            } else {
                cur = QStringLiteral("打不开 BulwarkService(winerr=%1)").arg(::GetLastError());
            }
            ::CloseServiceHandle(scm);
        }
        f.satisfied = sat;
        f.current = cur;
        f.recommended = sat
            ? QStringLiteral("无需处理:宽泛主体只有查询/询问一类权限,已无停止/改配置/删除")
            : QStringLiteral("移除 Authenticated Users / Interactive 对本服务的"
                             "停止、改配置、删除权限,只保留 SYSTEM 与 Administrators");
        f.cost = QStringLiteral("非管理员将无法停止本服务(这正是目的)。"
                                "【诚实边界】有管理员权限的恶意软件仍然改得回来 —— 它能改 DACL。"
                                "这不是自保护,只是把门槛从「随便一个进程」提到「需要管理员」;"
                                "真正的自保护在内核 SelfGuard,无驱动时没有等价物。");
        f.needsReboot = false;
        v.push_back(f);
    }

    // 3.5 能力自检(不是系统状态,而是「这台机器上这个手段是否可用」)
    {
        Finding f;
        f.id = QStringLiteral("FileDenyExecuteAvailable");
        f.title = QStringLiteral("跨重启的「拒绝执行」ACE 可用性");
        f.satisfied = true;   // NTFS 上总是可用;非 NTFS 卷会在 denyExecute 里如实失败
        f.current = QStringLiteral("可用(NTFS DACL)。本次运行已加 %1 条")
                        .arg(deniedExecuteThisRun().size());
        f.recommended = QStringLiteral("对已确认恶意的映像调用 denyExecute(),与独占句柄叠加");
        f.cost = QStringLiteral("按文件不按路径:把文件复制一份即可绕过(副本不继承 DENY ACE,已实测)。"
                                "读取不受影响,所以不影响我们自己的隔离。跨重启持久,"
                                "必须能被加白撤销。");
        v.push_back(f);
    }
    return v;
}

bool SystemHardening::applyRunAsPpl(bool apply) {
    if (!apply) {
        log_.info(QStringLiteral("加固体检:建议设置 lsass RunAsPPL = 2(需重启)。"
                                "本次为【只读】调用,未做任何改动。"));
        return false;
    }
    HKEY k = nullptr;
    const LONG rc = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0,
                                    KEY_SET_VALUE | KEY_WOW64_64KEY, &k);
    if (rc != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("加固:打不开 Lsa 键(winerr=%1),RunAsPPL 未设置。").arg(rc));
        return false;
    }
    KeyCloser kc{k};
    // 【只接受 2】。写 1 会把策略写进 UEFI 变量,之后注册表里删掉也关不掉 —— 那就变成了
    // 一个我们无法撤销的系统级改动,直接违反「必须能撤销一切」。代码层面不给写 1 的机会。
    const DWORD val = 2;
    const LONG wr = ::RegSetValueExW(k, L"RunAsPPL", 0, REG_DWORD,
                                     reinterpret_cast<const BYTE*>(&val), sizeof(val));
    if (wr != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("加固:写 RunAsPPL 失败(winerr=%1)。").arg(wr));
        return false;
    }
    log_.warning(QStringLiteral("加固:已设置 lsass RunAsPPL = 2(刻意不是 1 —— 1 会写入 UEFI "
                                "变量且无法从注册表撤销)。【需要重启才生效】。"
                                "若有依赖读取 lsass 的软件(单点登录代理 / 某些 VPN 与指纹驱动)"
                                "出现异常,撤销办法是删除该值后重启。"));
    return true;
}

bool SystemHardening::revertRunAsPpl(bool apply) {
    if (!apply)
        return false;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return false;
    KeyCloser kc{k};
    const LONG rc = ::RegDeleteValueW(k, L"RunAsPPL");
    const bool ok = (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND);
    log_.warning(QStringLiteral("加固:撤销 RunAsPPL %1(需重启生效)。"
                                "注意:若该策略此前是以值 1 启用过的,它可能已写入 UEFI 变量,"
                                "删注册表值不足以关闭 —— 这正是本产品只写 2 的原因。")
                     .arg(ok ? QStringLiteral("成功") : QStringLiteral("失败")));
    return ok;
}

bool SystemHardening::applySelfServiceDacl(bool apply) {
    if (!apply) {
        log_.info(QStringLiteral("加固体检:建议收紧本服务 DACL。本次为【只读】调用,未做改动。"));
        return false;
    }
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        log_.warning(QStringLiteral("加固:连不上服务控制管理器(winerr=%1)。").arg(::GetLastError()));
        return false;
    }
    SC_HANDLE svc = ::OpenServiceW(scm, L"BulwarkService", WRITE_DAC | READ_CONTROL);
    if (!svc) {
        const DWORD e = ::GetLastError();
        ::CloseServiceHandle(scm);
        log_.warning(QStringLiteral("加固:打不开 BulwarkService 以改 DACL(winerr=%1)。").arg(e));
        return false;
    }
    // SY = LocalSystem, BA = Builtin Administrators。刻意保留 Administrators 的完全控制:
    // 把管理员也锁在外面会造成「服务坏了却没人能修」,而且它并不提高安全性
    //(管理员本来就能改 DACL 把自己加回来)。
    static const wchar_t* kSddl =
        L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
        L"(A;;CCLCSWLOCRRC;;;AU)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(kSddl, SDDL_REVISION_1, &sd,
                                                               nullptr)) {
        const DWORD e = ::GetLastError();
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        log_.warning(QStringLiteral("加固:SDDL 解析失败(winerr=%1)。").arg(e));
        return false;
    }
    LocalFreer sdFree{sd};
    const BOOL ok = ::SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd);
    const DWORD e = ok ? 0 : ::GetLastError();
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);
    if (ok) {
        log_.warning(QStringLiteral("加固:已收紧 BulwarkService 的 DACL —— "
                                    "Authenticated Users 只剩查询与启动,停止/改配置/删除"
                                    "仅限 SYSTEM 与 Administrators。"
                                    "【诚实边界】有管理员权限的恶意软件仍可改回来。"));
    } else {
        log_.warning(QStringLiteral("加固:收紧服务 DACL 失败(winerr=%1)。").arg(e));
    }
    return ok == TRUE;
}

// ---------------------------------------------------------------- 3.5 拒绝执行
bool SystemHardening::denyExecute(const QString& path) {
    const QString p = path.trimmed();
    if (p.isEmpty() || !QFileInfo::exists(p)) {
        log_.warning(QStringLiteral("加固:拒绝执行未生效 —— 文件不存在:%1").arg(p));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        if (trustProbe_ && trustProbe_(p)) {
            log_.info(QStringLiteral("加固:拒绝执行已跳过(该程序已加白):%1").arg(p));
            return false;
        }
    }
    DWORD err = 0;
    if (!addDenyAce(p, SE_FILE_OBJECT, kFileExecuteMask, &err)) {
        log_.warning(QStringLiteral("加固:加「拒绝执行」ACE 失败(winerr=%1)——"
                                    "该文件此刻【仍可被执行】(非 NTFS 卷 / 无 WRITE_DAC 权限):%2")
                         .arg(err)
                         .arg(p));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        if (!deniedExec_.contains(p, Qt::CaseInsensitive))
            deniedExec_ << p;
    }
    log_.warning(QStringLiteral("加固:已对 %1 加「拒绝执行」ACE(DENY Everyone:FILE_EXECUTE)。"
                                "启动它将失败(ERROR_ACCESS_DENIED 5),【且跨重启持久】——"
                                "这是独占句柄做不到的那一半。读取不受影响,故本产品的隔离与取哈希"
                                "照常。注意按文件不按路径:复制一份即可绕过。"
                                "撤销:用户在界面加白该程序。")
                     .arg(p));
    return true;
}

bool SystemHardening::undenyExecute(const QString& path) {
    const QString p = path.trimmed();
    if (p.isEmpty())
        return false;
    DWORD err = 0;
    int removed = 0;
    const bool ok = removeDenyAce(p, SE_FILE_OBJECT, kFileExecuteMask, &err, &removed);
    {
        QMutexLocker lk(&mx_);
        deniedExec_.removeAll(p);
    }
    if (ok) {
        log_.warning(QStringLiteral("加固:已移除 %1 上的「拒绝执行」ACE(%2 条),该程序又可运行。")
                         .arg(p)
                         .arg(removed));
    } else {
        // 撤销失败是本类里最需要喊出来的一种失败:它意味着一个跨重启的封堵留在了系统上
        // 而我们放不开它。
        log_.warning(QStringLiteral("加固:【移除「拒绝执行」ACE 失败】(winerr=%1)——"
                                    "该文件仍然无法被执行,且这是跨重启的状态。"
                                    "需要手工处理(在文件属性-安全里删掉 Everyone 的拒绝-执行):%2")
                         .arg(err)
                         .arg(p));
    }
    return ok;
}

bool SystemHardening::isExclusiveRegistryKey(const QString& hiveAndKey) {
    HKEY hive = nullptr;
    QString sub, hiveName;
    if (!splitHive(hiveAndKey, &hive, &sub, &hiveName))
        return false;
    return !isSharedRegistryKey(hiveAndKey);
}

void SystemHardening::watchKeyLive(const QString& hiveAndKey) {
    bool wasWatching = false;
    {
        QMutexLocker lk(&mx_);
        for (const Watched& w : watched_) {
            if (w.hiveAndKey.compare(hiveAndKey, Qt::CaseInsensitive) == 0)
                return;   // 已在监视中,幂等
        }
        wasWatching = watching_;
    }
    if (wasWatching)
        stopWatching();
    watchKey(hiveAndKey);
    if (wasWatching)
        startWatching();
    else
        startWatching();   // 之前没在监视(例如一个键都没登记过)—— 现在有了,起来
}

QStringList SystemHardening::deniedExecuteThisRun() const {
    QMutexLocker lk(&mx_);
    return deniedExec_;
}

bool SystemHardening::hasDenyExecute(const QString& path) const {
    return hasDenyAce(path.trimmed(), SE_FILE_OBJECT, kFileExecuteMask);
}

// ---------------------------------------------------------------- 3.2 注册表 DENY
bool SystemHardening::denyRegistryWrite(const QString& hiveAndKey, bool exclusiveKeyOnly) {
    if (!exclusiveKeyOnly) {
        log_.warning(QStringLiteral("加固:拒绝对 %1 加注册表 DENY ACE —— 调用方未声明"
                                    "「该键为恶意独占」。注册表安全描述符在【键】上而不在值上,"
                                    "对共享键加 DENY 会打断所有正常软件。")
                         .arg(hiveAndKey));
        return false;
    }
    if (isSharedRegistryKey(hiveAndKey)) {
        log_.warning(QStringLiteral("加固:拒绝对共享键加 DENY ACE:%1 —— "
                                    "该键被正常软件普遍使用(Run / Services 根 / Winlogon 一类),"
                                    "加 DENY 等于阻断每一个安装程序。这类键请用 3.1 的"
                                    "「即时监视 + 回滚」处理。")
                         .arg(hiveAndKey));
        return false;
    }
    const QString obj = regObjectName(hiveAndKey);
    if (obj.isEmpty()) {
        log_.warning(QStringLiteral("加固:无法识别注册表路径(需 HKLM\\... / HKCU\\...):%1")
                         .arg(hiveAndKey));
        return false;
    }
    DWORD err = 0;
    if (!addDenyAce(obj, SE_REGISTRY_KEY, kRegSetValueMask, &err)) {
        log_.warning(QStringLiteral("加固:注册表 DENY ACE 失败(winerr=%1)——"
                                    "该键此刻【仍可被写入】:%2")
                         .arg(err)
                         .arg(hiveAndKey));
        return false;
    }
    log_.warning(QStringLiteral("加固:已对 %1 加注册表「拒绝写值」ACE,"
                                "写入该键将失败(ERROR_ACCESS_DENIED 5),跨重启持久。"
                                "撤销:undenyRegistryWrite / 界面加白。")
                     .arg(hiveAndKey));
    return true;
}

bool SystemHardening::undenyRegistryWrite(const QString& hiveAndKey) {
    const QString obj = regObjectName(hiveAndKey);
    if (obj.isEmpty())
        return false;
    DWORD err = 0;
    int removed = 0;
    const bool ok = removeDenyAce(obj, SE_REGISTRY_KEY, kRegSetValueMask, &err, &removed);
    log_.warning(QStringLiteral("加固:移除 %1 的注册表 DENY ACE %2(%3 条,winerr=%4)")
                     .arg(hiveAndKey)
                     .arg(ok ? QStringLiteral("成功") : QStringLiteral("【失败】"))
                     .arg(removed)
                     .arg(err));
    return ok;
}

// ---------------------------------------------------------------- 3.1 即时监视 + 回滚
void SystemHardening::watchKey(const QString& hiveAndKey) {
    HKEY hive = nullptr;
    QString sub, hiveName;
    if (!splitHive(hiveAndKey, &hive, &sub, &hiveName)) {
        log_.warning(QStringLiteral("加固:监视键路径无法识别:%1").arg(hiveAndKey));
        return;
    }
    Watched wk;
    wk.hiveAndKey = hiveAndKey;
    // 立刻拍一份快照。没有快照的话,第一次变化就无从判断「新值」相对什么是新的,
    // 回滚会退化成「删掉一切」。
    HKEY k = nullptr;
    if (::RegOpenKeyExW(hive, wstr(sub), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)
        == ERROR_SUCCESS) {
        KeyCloser kc{k};
        for (DWORD i = 0;; ++i) {
            wchar_t name[16384] = {};
            DWORD nameLen = 16383;
            DWORD type = 0;
            if (::RegEnumValueW(k, i, name, &nameLen, nullptr, &type, nullptr, nullptr)
                != ERROR_SUCCESS)
                break;
            if (type != REG_SZ && type != REG_EXPAND_SZ)
                continue;
            const QString vn = QString::fromWCharArray(name, static_cast<int>(nameLen));
            bool present = false;
            wk.snapshot.insert(vn, regReadString(hive, sub, vn, &present));
        }
    }
    QMutexLocker lk(&mx_);
    watched_.push_back(wk);
    log_.info(QStringLiteral("加固:已登记即时监视 %1(基线 %2 个字符串值)")
                  .arg(hiveAndKey)
                  .arg(wk.snapshot.size()));
}

bool SystemHardening::startWatching() {
    QMutexLocker lk(&mx_);
    if (watching_)
        return true;
    if (watched_.isEmpty()) {
        log_.info(QStringLiteral("加固:没有登记任何监视键,即时监视未启动。"));
        return false;
    }
    stopEvent_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) {
        log_.warning(QStringLiteral("加固:创建停止事件失败(winerr=%1),即时监视未启动。")
                         .arg(::GetLastError()));
        return false;
    }
    watching_ = true;
    thread_ = new std::thread([this] { watchLoop(); });
    log_.warning(QStringLiteral("加固:注册表即时监视已启动(%1 个键)。"
                                "用 RegNotifyChangeKeyValue —— 内核在键变化时立刻唤醒,"
                                "不是轮询;既有的周期性比对天生留着「写进去等我们发现」的窗口。")
                     .arg(watched_.size()));
    return true;
}

void SystemHardening::stopWatching() {
    std::thread* t = nullptr;
    {
        QMutexLocker lk(&mx_);
        if (!watching_)
            return;
        watching_ = false;
        if (stopEvent_)
            ::SetEvent(static_cast<HANDLE>(stopEvent_));
        t = static_cast<std::thread*>(thread_);
        thread_ = nullptr;
    }
    if (t) {
        if (t->joinable())
            t->join();
        delete t;
    }
    QMutexLocker lk(&mx_);
    if (stopEvent_) {
        ::CloseHandle(static_cast<HANDLE>(stopEvent_));
        stopEvent_ = nullptr;
    }
    log_.info(QStringLiteral("加固:注册表即时监视已停止。"));
}

bool SystemHardening::isWatching() const {
    QMutexLocker lk(&mx_);
    return watching_;
}

QVector<SystemHardening::RollbackRecord> SystemHardening::rollbacks() const {
    QMutexLocker lk(&mx_);
    return rollbacks_;
}

void SystemHardening::watchLoop() {
    // 每个被监视的键各开一个键句柄与一个通知事件,用一次 WaitForMultipleObjects 等全部。
    // 这样 N 个键只占一个线程 —— 一个键一个线程在键多了之后会变成明显的资源浪费。
    // ⚠ 局部变量【不能】叫 slots:Qt 的 qobjectdefs.h 里 `slots` 是个宏(展开为空),
    // 于是 `std::vector<WatchSlot> slots;` 会被展开成 `std::vector<WatchSlot> ;`,
    // 报出来的却是一串看不出所以然的 C2059/C2530。
    struct WatchSlot {
        HKEY key = nullptr;
        HANDLE evt = nullptr;
        int watchedIndex = -1;
    };
    std::vector<WatchSlot> slotList;
    {
        QMutexLocker lk(&mx_);
        for (int i = 0; i < watched_.size(); ++i) {
            HKEY hive = nullptr;
            QString sub, hiveName;
            if (!splitHive(watched_[i].hiveAndKey, &hive, &sub, &hiveName))
                continue;
            HKEY k = nullptr;
            if (::RegOpenKeyExW(hive, wstr(sub), 0, KEY_NOTIFY | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                                &k) != ERROR_SUCCESS)
                continue;
            WatchSlot s;
            s.key = k;
            s.evt = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            s.watchedIndex = i;
            slotList.push_back(s);
        }
    }
    const auto arm = [](WatchSlot& s) {
        ::ResetEvent(s.evt);
        // bWatchSubtree=FALSE:只关心这个键自己的值。开子树会把整棵树的噪声全收进来,
        // 而回滚判据是按值做的,子树变化给不出「哪个值变了」。
        return ::RegNotifyChangeKeyValue(s.key, FALSE,
                                         REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
                                         s.evt, TRUE) == ERROR_SUCCESS;
    };
    for (WatchSlot& s : slotList)
        arm(s);

    std::vector<HANDLE> waits;
    waits.push_back(static_cast<HANDLE>(stopEvent_));
    for (WatchSlot& s : slotList)
        waits.push_back(s.evt);

    while (true) {
        const DWORD r = ::WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(),
                                                 FALSE, INFINITE);
        if (r == WAIT_OBJECT_0)
            break;   // stop
        if (r == WAIT_FAILED)
            break;
        const size_t idx = static_cast<size_t>(r - WAIT_OBJECT_0);
        if (idx == 0 || idx > slotList.size())
            break;
        WatchSlot& s = slotList[idx - 1];
        {
            QMutexLocker lk(&mx_);
            if (!watching_)
                break;
        }
        {
            Watched copy;
            int wi = s.watchedIndex;
            {
                QMutexLocker lk(&mx_);
                if (wi < 0 || wi >= watched_.size())
                    continue;
                copy = watched_[wi];
            }
            reconcileKey(copy);
            QMutexLocker lk(&mx_);
            if (wi >= 0 && wi < watched_.size())
                watched_[wi] = copy;   // 回写更新后的快照
        }
        arm(s);   // 通知是一次性的,处理完必须重新挂
    }
    for (WatchSlot& s : slotList) {
        if (s.evt)
            ::CloseHandle(s.evt);
        if (s.key)
            ::RegCloseKey(s.key);
    }
}

bool SystemHardening::reconcileKey(Watched& wk) {
    HKEY hive = nullptr;
    QString sub, hiveName;
    if (!splitHive(wk.hiveAndKey, &hive, &sub, &hiveName))
        return false;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(hive, wstr(sub), 0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return false;
    KeyCloser kc{k};

    // 读当前全部字符串值
    QHash<QString, QString> now;
    for (DWORD i = 0;; ++i) {
        wchar_t name[16384] = {};
        DWORD nameLen = 16383;
        DWORD type = 0;
        if (::RegEnumValueW(k, i, name, &nameLen, nullptr, &type, nullptr, nullptr)
            != ERROR_SUCCESS)
            break;
        if (type != REG_SZ && type != REG_EXPAND_SZ)
            continue;
        const QString vn = QString::fromWCharArray(name, static_cast<int>(nameLen));
        bool present = false;
        now.insert(vn, regReadString(hive, sub, vn, &present));
    }

    TrustProbeFn probe;
    {
        QMutexLocker lk(&mx_);
        probe = trustProbe_;
    }

    bool any = false;
    for (auto it = now.constBegin(); it != now.constEnd(); ++it) {
        const QString& vn = it.key();
        const QString& data = it.value();
        const bool had = wk.snapshot.contains(vn);
        if (had && wk.snapshot.value(vn) == data)
            continue;   // 没变

        // 【已加白的目标不回滚】用户自己装的程序会往这些键里写东西。把它们回滚掉,
        // 用户看到的是「我的软件设了开机启动但每次都消失」,而且完全看不出是谁干的。
        if (probe && probe(data)) {
            log_.info(QStringLiteral("加固:%1\\%2 变化指向已加白的程序,不回滚:%3")
                          .arg(wk.hiveAndKey, vn, data));
            wk.snapshot.insert(vn, data);   // 接受为新基线
            continue;
        }

        RollbackRecord rec;
        rec.keyPath = wk.hiveAndKey;
        rec.valueName = vn;
        rec.newData = data;
        rec.whenUtcIso = nowIso();
        bool ok = false;
        if (!had) {
            // 监视开始之后新出现的值 -> 删掉
            ok = (::RegDeleteValueW(k, wstr(vn)) == ERROR_SUCCESS);
            rec.restoredTo.clear();
        } else {
            const QString old = wk.snapshot.value(vn);
            const std::wstring w(reinterpret_cast<const wchar_t*>(old.utf16()), old.size());
            ok = (::RegSetValueExW(k, wstr(vn), 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(w.c_str()),
                                   static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)))
                  == ERROR_SUCCESS);
            rec.restoredTo = old;
        }
        if (ok) {
            any = true;
            {
                QMutexLocker lk(&mx_);
                rollbacks_.push_back(rec);
            }
            log_.warning(QStringLiteral("加固:已自动回滚注册表持久化 %1\\%2 —— "
                                        "新值「%3」已被%4。"
                                        "这是即时回滚(RegNotifyChangeKeyValue 唤醒),"
                                        "不是周期性扫描发现的。")
                             .arg(wk.hiveAndKey, vn, data)
                             .arg(had ? QStringLiteral("还原为「%1」").arg(rec.restoredTo)
                                      : QStringLiteral("删除")));
            emit rolledBack(rec.keyPath, rec.valueName, rec.newData, rec.restoredTo);
        } else {
            // 回滚失败必须说出来:那意味着恶意持久化还在,而我们以为处理了。
            log_.warning(QStringLiteral("加固:【回滚失败】%1\\%2(winerr=%3)——"
                                        "该持久化项仍然存在:%4")
                             .arg(wk.hiveAndKey, vn)
                             .arg(::GetLastError())
                             .arg(data));
            wk.snapshot.insert(vn, data);   // 避免每次通知都重试同一个失败项刷满日志
        }
    }
    // 被删掉的值:接受(用户或卸载程序删自启动项是正常的,我们不负责把它加回来)
    for (auto it = wk.snapshot.constBegin(); it != wk.snapshot.constEnd();) {
        if (!now.contains(it.key()))
            it = wk.snapshot.erase(it);
        else
            ++it;
    }
    return any;
}

} // namespace bulwark::service
