#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/ThreatRemediator.h"   // 诱饵登记为清理豁免(2.4)
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>   // CoInitializeEx / CoCreateInstance
#include <shlobj.h>    // IShellLinkW / IPersistFile / CLSID_ShellLink

namespace bulwark::service {

namespace {

// 合成 ActorPid(>4):用户态无真实 PID,但勒索监视器要求 ActorPid>0 才评估。
// 与 .NET SyntheticActorPid 一致。
//
// ⚠【原注释「这些事件 UserModeObserved=false 且不结束进程,不存在误杀风险」是错的】
// 诱饵命中在引擎里是【无条件 Block】(RuleEngine 第 5 步),流水线照常走到 killMalicious。
// 实测(verify2.log)因此出现过:
//     恶意进程终结:PID=11534336(用户态结束 0 个 + 驱动级内核结束)
// 即这个合成 PID 被真的下发进了内核封禁集,并被报告为「已终结」。11534336 是 4 的倍数,
// 完全可能是将来某个真实进程的 PID。
// 现在 Worker::killMalicious 开头会核对「该 PID 在进程快照里是否存在」并据此中止,
// 所以这个占位值不会再被当成处置目标。此处保留合成 PID 只为满足监视器的前置条件 ——
// 真正的归因由 0.5 的写入归因表(KernelFileWriteAttribution)提供。
constexpr int kSyntheticActorPid = 0x0B00000;
const QString kCanaryName = QStringLiteral("~$Bulwark_\xE8\xAF\xB7\xE5\x8B\xBF\xE5\x88\xA0\xE9\x99\xA4_DoNotDelete.docx");

QString expandEnv(const QString& p) {
    if (p.isEmpty()) return p;
    wchar_t buf[1024] = {};
    const DWORD n = ::ExpandEnvironmentStringsW(reinterpret_cast<LPCWSTR>(p.utf16()), buf, 1024);
    return (n == 0 || n > 1024) ? p : QString::fromWCharArray(buf);
}

// 解析 .lnk 快捷方式目标(IShellLink)。失败返回空。
QString resolveLnk(const QString& lnkPath) {
    QString result;
    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_IShellLinkW, reinterpret_cast<void**>(&link)))) {
        IPersistFile* pf = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
            if (SUCCEEDED(pf->Load(reinterpret_cast<LPCOLESTR>(lnkPath.utf16()), STGM_READ))) {
                wchar_t target[MAX_PATH] = {};
                if (SUCCEEDED(link->GetPath(target, MAX_PATH, nullptr, SLGP_UNCPRIORITY)))
                    result = QString::fromWCharArray(target);
            }
            pf->Release();
        }
        link->Release();
    }
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();
    return result;
}

// 从自启动项数据/文件解析被持久化的可执行路径(带引号、首 token、.lnk 目标、环境变量)。
QString resolveAutorunTarget(const QString& data) {
    if (data.trimmed().isEmpty()) return QString();
    QString s = expandEnv(data.trimmed());
    if (s.endsWith(QStringLiteral(".lnk"), Qt::CaseInsensitive)) {
        const QString t = resolveLnk(s);
        if (!t.isEmpty()) return t;
    }
    if (s.startsWith(QLatin1Char('"'))) {
        const int end = s.indexOf(QLatin1Char('"'), 1);
        if (end > 1) return s.mid(1, end - 1);
    }
    if (QFileInfo::exists(s)) return s;
    const int sp = s.indexOf(QLatin1Char(' '));
    if (sp > 0) {
        const QString first = s.left(sp);
        if (QFileInfo::exists(first)) return first;
    }
    return s;
}

QString regReadString(HKEY key, const wchar_t* valueName);   // 定义在下方

//
// 本机【真实用户】的配置文件目录。
//
// ===== 这个函数存在的理由,是本文件里两处「静默完全失效」=====
//
// 本服务以 LocalSystem 运行(sc qc:SERVICE_START_NAME = LocalSystem)。于是
// QStandardPaths 与 %APPDATA% 都会解析到 SYSTEM 自己的配置文件:
//     QStandardPaths::DocumentsLocation -> C:\Windows\system32\config\systemprofile\Documents
//     %APPDATA%                         -> C:\Windows\system32\config\systemprofile\AppData\Roaming
// 而这台机器上实测:systemprofile 下【只有 AppData 一个子目录】,Documents / Desktop /
// Pictures 一个都不存在;Roaming 下也【没有】Microsoft\Windows 这一层。后果是:
//
//   1) deployCanaries() 开头的 `if (!QFileInfo::exists(dir)) continue;` 把三个诱饵目录
//      全部跳过 -> canaryFiles_ 恒为空 -> engine_.addCanaryFile() 一次都不会被调用
//      -> 引擎里的诱饵集合永远是空的 -> RuleEngine 那条「canaryHit 无条件 Block +
//      100 分硬指标」永远不可能成立。也就是说勒索蜜罐这一整维在部署形态下是死的,
//      而且死得毫无痕迹:日志里那句「已投放 N 个勒索诱饵文件」在 canaryFiles_ 为空时
//      根本不打印,看日志只会看到「用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)」。
//
//   2) startStartupWatchers() 只剩 ProgramData 那个「所有用户」启动目录真实存在,
//      【用户自己的启动文件夹】—— 最常见的那种持久化 —— 没有人在看。
//
// 这一维恰恰是没有内核驱动时仅剩的两根支柱之一(另一根是 ETW 观测),所以这不是
// 「覆盖面小一点」,是把无驱动模式的一半防护说成有、其实没有。
//
// 正确做法:从 ProfileList 读每个真实用户的 ProfileImagePath。SYSTEM 有权读该键,
// 而且与登录状态无关 —— 离线用户的目录一样能投放诱饵,等他下次登录时保护已经就位。
//
QStringList userProfileDirs() {
    QStringList out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                        0, KEY_READ, &key) != ERROR_SUCCESS)
        return out;
    DWORD idx = 0;
    wchar_t sid[512];
    for (;;) {
        DWORD n = 512;
        const LONG r = ::RegEnumKeyExW(key, idx++, sid, &n, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS || r != ERROR_SUCCESS)
            break;
        // 只取真实交互用户(S-1-5-21-…)。刻意跳过 S-1-5-18/19/20(SYSTEM / LocalService /
        // NetworkService):它们的配置文件里没有文档目录,往那里投诱饵没有任何意义 ——
        // 上面第 1 条说的正是这个坑。
        const QString sidStr = QString::fromWCharArray(sid, static_cast<int>(n));
        if (!sidStr.startsWith(QStringLiteral("S-1-5-21-")))
            continue;
        HKEY sub = nullptr;
        if (::RegOpenKeyExW(key, sid, 0, KEY_READ, &sub) != ERROR_SUCCESS)
            continue;
        const QString path = expandEnv(regReadString(sub, L"ProfileImagePath"));
        ::RegCloseKey(sub);
        if (!path.isEmpty() && QFileInfo::exists(path))
            out << QDir::toNativeSeparators(path);
    }
    ::RegCloseKey(key);
    return out;
}

QStringList canaryFolders() {
    QStringList out;
    // 磁盘上的目录名【不随界面语言变化】:中文 Windows 上仍然是 Documents / Desktop /
    // Pictures(本地化只体现在 desktop.ini 的显示名)。本机实测的诱饵落点
    // C:\Users\1\Documents\ 正是这个形态。
    for (const QString& prof : userProfileDirs()) {
        for (const char* leaf : { "Documents", "Desktop", "Pictures" }) {
            const QString d = QDir(prof).filePath(QLatin1String(leaf));
            if (QFileInfo::exists(d))
                out << QDir::toNativeSeparators(d);
        }
    }
    // 兜底:ProfileList 一个真实用户都读不到时(极少见),退回本进程视角 —— 以交互用户
    // 身份调试运行服务时,那条路才是对的。加 exists 判断,不再把不存在的路径交出去。
    if (out.isEmpty()) {
        for (auto loc : { QStandardPaths::DocumentsLocation, QStandardPaths::DesktopLocation,
                          QStandardPaths::PicturesLocation }) {
            const QString d = QStandardPaths::writableLocation(loc);
            if (!d.isEmpty() && QFileInfo::exists(d))
                out << QDir::toNativeSeparators(d);
        }
    }
    return out;
}

QStringList startupFolders() {
    QStringList out;
    static const QString kRel =
        QStringLiteral("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    for (const QString& prof : userProfileDirs()) {
        const QString d = QDir(prof).filePath(kRel);
        if (QFileInfo::exists(d))
            out << QDir::toNativeSeparators(d);
    }
    // 「所有用户」启动目录。原实现里【只有这一条】是真实存在的。
    const QString progData = qEnvironmentVariable("ProgramData");
    if (!progData.isEmpty()) {
        const QString d = progData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        if (QFileInfo::exists(d))
            out << QDir::toNativeSeparators(d);
    }
    // 兜底同 canaryFolders:以交互用户身份运行时 %APPDATA% 才指向真实用户。
    const QString appData = qEnvironmentVariable("APPDATA");
    if (!appData.isEmpty()) {
        const QString d = QDir::toNativeSeparators(
            appData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        if (QFileInfo::exists(d) && !out.contains(d, Qt::CaseInsensitive))
            out << d;
    }
    return out;
}

// 自启动注册表位置。sub 是打开用的真实子键路径,display 是拿来做基线 keyId 与上报路径的
// 可读串 —— 两者必须分开:用户 hive 的 sub 以 SID 开头,直接拿 sub 拼 display 会把 SID 写两遍。
struct RegLoc {
    HKEY root;
    QString sub;
    QString display;
};

// 枚举 HKEY_USERS 下【已加载】的 hive 名(即 SID)。
//
// 跳过 *_Classes:那是每用户 COM 注册的 hive,量大且与自启动无关,扫它只会把轮询变慢。
// .DEFAULT 与 S-1-5-18/19/20 都【保留】—— 往默认用户模板或服务账户 hive 里写 Run 项
// 同样是持久化手段,没有理由只盯交互用户。
QStringList loadedUserHives() {
    QStringList out;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return out;
    for (DWORD i = 0;; ++i) {
        wchar_t name[512] = {};
        DWORD n = 511;
        if (::RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        const QString s = QString::fromWCharArray(name, static_cast<int>(n));
        if (s.endsWith(QStringLiteral("_Classes"), Qt::CaseInsensitive))
            continue;
        out << s;
    }
    ::RegCloseKey(k);
    return out;
}

// 【已修:原先这里的 4 条 HKEY_CURRENT_USER 读的是 SYSTEM 自己的 hive】
//
// 服务以 LocalSystem 运行且不做任何模拟(impersonation),所以 HKEY_CURRENT_USER 解析到
// S-1-5-18。后果是:用户自己的 Run / RunOnce / Policies\Explorer\Run 持久化 —— 最常见的
// 那一整类 —— 完全不在监视范围内,而日志和界面都不提示这件事。这与 userProfileDirs 当初
// 那个「诱饵一个都没投放」是同一个根因,只是这一处更隐蔽:HKCU 这条路径不会报错,
// 它只是安静地读了一个几乎永远是空的键,看起来和「用户没有可疑自启动项」一模一样。
//
// 改法:枚举 HKEY_USERS 下已加载的 hive,逐个打开 <SID>\SOFTWARE\...\Run 等子键。
// display 写成 HKU\<SID>\... 使多用户下的基线 keyId 天然唯一(原来按固定 rootName 拼,
// 两个用户的同名键会互相覆盖基线,那会产生「另一个用户装了软件 -> 这个用户被报新增项」)。
//
// 【诚实的覆盖边界】只覆盖【已加载】的 hive。未登录用户的 NTUSER.DAT 不挂在 HKEY_USERS 里,
// 要覆盖得 RegLoadKey 把它挂上来 —— 对一个几秒一轮的轮询监视器来说过于侵入(挂载别人的
// 用户 hive 会改变系统状态、还可能与登录流程抢占),刻意不做。实际影响很小:一个没登录的
// 用户的 Run 项要到他登录时才会被执行,而那时他的 hive 就已加载、也就进了监视范围。
QList<RegLoc> autorunRegLocations() {
    QList<RegLoc> v;
    static const wchar_t* kMachine[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    for (const wchar_t* s : kMachine) {
        const QString sub = QString::fromWCharArray(s);
        v.push_back({ HKEY_LOCAL_MACHINE, sub, QStringLiteral("HKLM\\") + sub });
    }
    static const wchar_t* kPerUser[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    };
    for (const QString& sid : loadedUserHives()) {
        for (const wchar_t* s : kPerUser) {
            const QString tail = QString::fromWCharArray(s);
            v.push_back({ HKEY_USERS, sid + QLatin1Char('\\') + tail,
                          QStringLiteral("HKU\\") + sid + QLatin1Char('\\') + tail });
        }
    }
    return v;
}

// 读一个字符串型注册表值。
//
// 【这里修掉一处会破坏堆的写法】原实现把第一次查询得到的 cb 直接复用给第二次调用,
// 而 RegQueryValueExW 的第三个 out 参数是【in/out】:传进去的是缓冲区容量,传出来的是实际
// 字节数。两次调用之间那个值完全可能被别人改长(自启动键是恶意软件和安装程序都在写的地方),
// 此时第二次调用会按【新的、更大的】长度写进只够旧长度的缓冲区 —— 越界写堆。
// 症状正是 0xC0000374(STATUS_HEAP_CORRUPTION),而且它不在越界的那一刻崩,
// 是在之后某次无关的堆操作上崩,所以极难对上。
//
// 现在:每次调用都把容量重新告诉它,并对返回的实际长度再做一次上界裁剪;
// 另外按【显式长度】构造 QString,不依赖值里一定有终止符(REG_SZ 允许没有)。
QString regReadString(HKEY key, const wchar_t* valueName) {
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return QString();
    if (cb > 1024 * 1024)   // 自启动项不该有 1MB 的字符串;异常值直接放弃,不去赌
        return QString();
    // 多留 4 字节:一个可能缺失的 UTF-16 终止符 + cb 为奇数时那半个字符。
    const DWORD cap = cb + 4;
    QByteArray buf(static_cast<int>(cap), '\0');
    DWORD got = cap;        // 【每次都传容量】,不复用上一次的长度
    if (::RegQueryValueExW(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &got) != ERROR_SUCCESS)
        return QString();
    if (got > cap)          // 理论上不会,但这是最后一道:宁可截断也不越界解释
        got = cap;
    int chars = static_cast<int>(got / sizeof(wchar_t));
    const wchar_t* w = reinterpret_cast<const wchar_t*>(buf.constData());
    while (chars > 0 && w[chars - 1] == L'\0')   // 去掉尾部终止符,再按显式长度构造
        --chars;
    QString s = QString::fromWCharArray(w, chars);
    return (type == REG_EXPAND_SZ) ? expandEnv(s) : s;
}

// 读取一个自启动键的全部值(name -> data)。
QHash<QString, QString> readAutorunValues(HKEY root, const wchar_t* sub) {
    QHash<QString, QString> out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return out;
    DWORD idx = 0;
    // 【初始化】原来是未初始化的 32KB 栈数组。配合下面那个 ERROR_MORE_DATA 的处理错误,
    // 会把一整片未初始化内存当成值名读出来。
    wchar_t nameBuf[16384] = {};
    constexpr DWORD kNameCap = 16384;
    for (;;) {
        DWORD nameLen = kNameCap;
        const LONG r = ::RegEnumValueW(key, idx++, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        //
        // 【ERROR_MORE_DATA 必须跳过这一条,不能当成功用】原实现把它和 ERROR_SUCCESS 一起
        // 放过,然后拿 nameLen 去构造 QString。但 RegEnumValueW 在 ERROR_MORE_DATA 时
        // 【不保证】回填 lpcchValueName(与 RegQueryInfoKey 不同,它不返回所需长度),
        // 于是那个长度是不可信的,按它去读 16384 个 wchar_t 就把整片未初始化栈内存读了出来。
        // 值名超过 16383 字符在现实里只可能是恶意构造,跳过它比赌它更对。
        if (r == ERROR_MORE_DATA)
            continue;   // idx 已由上面的 idx++ 前进,这里不能再加,否则会跳掉下一个值
        if (r != ERROR_SUCCESS) break;
        if (nameLen > kNameCap - 1)   // 兜底:绝不按大于容量的长度去解释缓冲区
            nameLen = kNameCap - 1;
        const QString name = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        if (name.isEmpty()) continue;
        out.insert(name, regReadString(key, reinterpret_cast<LPCWSTR>(name.utf16())));
    }
    ::RegCloseKey(key);
    return out;
}

} // namespace

UserModeBehaviorSource::UserModeBehaviorSource(bulwark::engine::RuleEngine& engine, QObject* parent)
    : EventSource(parent), engine_(engine) {
    startupDirs_ = startupFolders();
    watcher_ = new QFileSystemWatcher(this);
    connect(watcher_, &QFileSystemWatcher::directoryChanged, this, &UserModeBehaviorSource::onDirectoryChanged);
    connect(watcher_, &QFileSystemWatcher::fileChanged, this, &UserModeBehaviorSource::onFileChanged);
    regTimer_ = new QTimer(this);
    regTimer_->setInterval(4000); // 每 4s 轮询注册表自启动基线增量
    connect(regTimer_, &QTimer::timeout, this, &UserModeBehaviorSource::pollRegistry);
}

UserModeBehaviorSource::~UserModeBehaviorSource() { stop(); }

} // namespace bulwark::service

namespace bulwark::service {

void UserModeBehaviorSource::start() {
    if (started_) return;
    started_ = true;
    startStartupWatchers();
    deployCanaries();
    snapshotStartup();
    scanRegistryDelta(/*emitEvents=*/false); // 建立注册表基线,首轮不报
    regTimer_->start();
    // 把「覆盖了几个用户 hive」说出来。原实现在这一维彻底失效时(HKCU 解析到 SYSTEM 自己的
    // hive)一个字都不打,与「用户确实没有可疑自启动项」完全无法区分 —— 和 deployCanaries
    // 投放数为 0 时不出声是同一个教训。0 个用户 hive 是异常,必须是 warning 而不是 info。
    {
        const QStringList hives = loadedUserHives();
        const int total = autorunRegLocations().size();
        if (hives.isEmpty()) {
            log_.warning(QStringLiteral("自启动注册表监视:HKEY_USERS 下【没有枚举到任何用户 hive】——"
                                        "每用户的 Run / RunOnce 持久化当前不在监视范围内。"));
        } else {
            log_.info(QStringLiteral("自启动注册表监视:%1 个键(机器范围 5 个 + %2 个已加载用户 "
                                     "hive × 4)。已覆盖的 hive:%3。"
                                     "未登录用户的 hive 不挂在 HKEY_USERS 里,故不覆盖 ——"
                                     "他登录时 hive 即加载,那时就进监视范围。")
                          .arg(total)
                          .arg(hives.size())
                          .arg(hives.join(QStringLiteral(", "))));
        }
    }
    log_.info(QStringLiteral("用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)。"));
}

void UserModeBehaviorSource::stop() {
    if (regTimer_) regTimer_->stop();
    if (watcher_) {
        const QStringList dirs = watcher_->directories();
        const QStringList files = watcher_->files();
        if (!dirs.isEmpty()) watcher_->removePaths(dirs);
        if (!files.isEmpty()) watcher_->removePaths(files);
    }
    started_ = false;
}

void UserModeBehaviorSource::startStartupWatchers() {
    for (const QString& dir : startupDirs_) {
        if (QFileInfo::exists(dir)) {
            watcher_->addPath(dir);
            log_.info(QStringLiteral("监视启动文件夹:%1").arg(dir));
        }
    }
}

void UserModeBehaviorSource::snapshotStartup() {
    for (const QString& dir : startupDirs_) {
        QSet<QString> set;
        QDir d(dir);
        if (d.exists())
            for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot))
                set.insert(QStringLiteral("%1|%2|%3").arg(fi.fileName())
                               .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch()));
        startupBaseline_.insert(dir, set);
    }
}

void UserModeBehaviorSource::deployCanaries() {
    if (!canaryEnabled_) return;
    for (const QString& dir : canaryFolders()) {
        if (!QFileInfo::exists(dir)) continue;
        const QString path = QDir(dir).filePath(kCanaryName);
        if (!QFileInfo::exists(path)) {
            QFile f(path);
            if (!f.open(QIODevice::WriteOnly)) continue;
            f.write(QString::fromUtf8(
                "\xE6\xAD\xA4\xE6\x96\x87\xE4\xBB\xB6\xE4\xB8\xBA\xE7\xA3\x90\xE5\x9E\x92\xE4\xB8\xBB\xE5\x8A\xA8\xE9\x98\xB2"
                "\xE5\xBE\xA1\xE7\x9A\x84\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xEF\xBC\x8C\xE8\xAF\xB7\xE5\x8B"
                "\xBF\xE5\x88\xA0\xE9\x99\xA4\xE6\x88\x96\xE4\xBF\xAE\xE6\x94\xB9\xE3\x80\x82\r\n"
                "This is a Bulwark ransomware canary (honeypot) file. Do not delete or modify.\r\n").toUtf8());
            f.close();
        }
        ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                             FILE_ATTRIBUTE_HIDDEN);
        const QString native = QDir::toNativeSeparators(path);
        canaryFiles_.insert(native);
        engine_.addCanaryFile(native);   // 登记蜜罐:引擎侧命中即判强勒索信号
        watcher_->addPath(path);         // 监视诱饵文件本身
        // 再把诱饵登记到「写入归因」表(当前接的是 ETW 源)。QFileSystemWatcher 只会告诉
        // 我们「这个文件变了」,给不出【谁改的】—— 而引擎对 canaryHit 是无条件 Block,
        // 没有写入者 PID 就只能落 AlertedOnly。归因表补的正是这一位。未接线 / 归因未启用时
        // 这里是空操作,行为与从前一致。
        if (canarySink_)
            canarySink_(native);
    }
    // 把诱饵清单交给足迹清理的位置护栏(2.4)。整表替换,与 canaryFiles_ 始终一致。
    //
    // 不接这根线的后果是实测过的:0.5 那次跑下来,同一次诱饵触碰让 Remediator 把【诱饵自己】
    // 当成恶意释放物搬进隔离区 3 次。位置护栏没错 —— 诱饵确实是「用户可写落地区里的一个
    // 文档」;缺的是「这个文件是我们自己放的」这条信息,而只有这里知道。
    ThreatRemediator::setOwnCanaryFiles(QStringList(canaryFiles_.cbegin(), canaryFiles_.cend()));

    if (!canaryFiles_.isEmpty()) {
        log_.info(QStringLiteral("已投放 %1 个勒索诱饵文件并登记蜜罐%2(并已登记为清理豁免,"
                                 "避免把诱饵自己当成恶意释放物)。")
                      .arg(canaryFiles_.size())
                      .arg(canarySink_ ? QStringLiteral("(已登记写入归因)") : QString()));
    } else {
        //
        // 【这条 warning 是本次改动的一半价值】原实现在「一个诱饵都没投放」时一行都不打,
        // 于是蜜罐整维失效在日志上与正常运行【完全无法区分】—— 只能看到后面那句
        // 「用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)」,读起来一切正常。
        // 这正是它能长期潜伏的原因。现在只要投放数为 0 就必须喊出来:引擎的诱饵集合是空的,
        // RuleEngine 里「canaryHit 无条件拦截」那条永远不可能成立。
        //
        log_.warning(QStringLiteral("未投放任何勒索诱饵:没有找到可用的用户文档目录 —— "
                                    "勒索蜜罐这一维当前【不生效】(引擎诱饵集合为空,"
                                    "诱饵命中判据永远不成立)。若本服务以 LocalSystem 运行,"
                                    "请确认能读到 ProfileList 且用户配置文件目录存在。"));
    }
}

void UserModeBehaviorSource::onDirectoryChanged(const QString& dir) {
    if (!enabled_) return;
    QDir d(dir);
    QSet<QString> current;
    for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot)) {
        const QString sig = QStringLiteral("%1|%2|%3").arg(fi.fileName())
                                .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch());
        current.insert(sig);
        if (startupBaseline_.value(dir).contains(sig)) continue; // 已知,跳过
        const QString full = QDir::toNativeSeparators(fi.absoluteFilePath());
        if (canaryFiles_.contains(full)) continue;               // 保险:忽略我方诱饵
        const QString target = resolveAutorunTarget(fi.absoluteFilePath());
        emitAutorunFile(full, target.isEmpty() ? full : target);
    }
    startupBaseline_[dir] = current;
}

void UserModeBehaviorSource::onFileChanged(const QString& path) {
    if (!enabled_ || !canaryEnabled_) return;
    const QString full = QDir::toNativeSeparators(path);
    if (!canaryFiles_.contains(full)) return; // 只处理诱饵

    //
    // 【同一次触碰去重】0.5 实测:改写一个诱饵产出 4 条「拦截 FileWrite」+ 3 次足迹清理。
    // 原因不是逻辑重复,是 Windows 对一次写会生成多个变更通知(打开/写/改时间戳/关闭),
    // QFileSystemWatcher 把它们逐个递上来,而每一条都走完整的「无条件 Block + 结束进程树 +
    // 足迹清理」。后果有三层:日志里同一件事刷 4 遍(真实事件被淹)、清理器对同一批文件重复
    // 隔离、以及处置阶梯被重复施加。
    //
    // 窗口取 3 秒:它只合并「同一次写操作的那几个通知」。刻意【不】取更长 —— 真正的勒索
    // 是在【多个】文件上连续加密,那会持续触发别的诱饵、也会在窗口外再次触发这一个,
    // 所以短窗口不会把一波真实加密压成一条。压制发生时记一行,不做成静默合并。
    //
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    auto last = canaryLastEventMs_.find(full);
    if (last != canaryLastEventMs_.end() && nowMs - last.value() < kCanaryDebounceMs) {
        ++canarySuppressed_;
        // 每压制 3 条打一行,避免它自己变成新的噪声源。
        if (canarySuppressed_ % 3 == 1) {
            log_.info(QStringLiteral("勒索诱饵:已合并同一次触碰的重复变更通知(%1 ms 内,"
                                     "累计压制 %2 条)——Windows 一次写会产生多个通知,"
                                     "逐条处置会把同一件事刷成 4 遍:%3")
                          .arg(kCanaryDebounceMs)
                          .arg(canarySuppressed_)
                          .arg(full));
        }
        return;
    }
    canaryLastEventMs_.insert(full, nowMs);

    bulwark::SecurityEvent e;
    e.type = QFileInfo::exists(path) ? bulwark::EventType::FileWrite : bulwark::EventType::FileDelete;
    e.actorPid = kSyntheticActorPid;
    e.actorPath = QString::fromUtf8("(\xE7\x94\xA8\xE6\x88\xB7\xE6\x80\x81\xE8\xA1\x8C\xE4\xB8\xBA\xE7\x9B\x91"
                                    "\xE6\x8E\xA7\xC2\xB7\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5)");
    e.target = full;
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xE6\x96\x87\xE4\xBB\xB6\xE8\xA2\xAB"
                                 "\xE6\x94\xB9\xE5\x86\x99/\xE5\x88\xA0\xE9\x99\xA4\xEF\xBC\x88\xE7\x96\x91\xE4\xBC"
                                 "\xBC\xE5\x8B\x92\xE7\xB4\xA2\xE6\x89\xB9\xE9\x87\x8F\xE5\x8A\xA0\xE5\xAF\x86\xEF\xBC\x89");
    emit eventProduced(e);
    log_.warning(QStringLiteral("勒索诱饵被触碰:%1 —— 疑似勒索行为!").arg(full));

    // 诱饵可能被删除/加密:尽力重建并重新纳入监视,持续覆盖后续加密。
    if (!QFileInfo::exists(path)) {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(QByteArrayLiteral("Bulwark canary\r\n"));
            f.close();
            ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                                 FILE_ATTRIBUTE_HIDDEN);
        }
    }
    if (QFileInfo::exists(path) && !watcher_->files().contains(path))
        watcher_->addPath(path);
}

void UserModeBehaviorSource::pollRegistry() {
    if (!enabled_) return;
    scanRegistryDelta(/*emitEvents=*/true);
}

void UserModeBehaviorSource::scanRegistryDelta(bool emitEvents) {
    // 每轮重新枚举:用户登录 / 注销会让 HKEY_USERS 下的 hive 出现与消失,固定一份清单
    // 会漏掉本服务启动之后才登录的用户 —— 而那恰恰是最常见的时序。
    const QList<RegLoc> locs = autorunRegLocations();
    for (const RegLoc& loc : locs) {
        const QString keyId = loc.display;
        const QHash<QString, QString> current =
            readAutorunValues(loc.root, reinterpret_cast<const wchar_t*>(loc.sub.utf16()));
        auto it = regBaseline_.find(keyId);
        if (it == regBaseline_.end()) {
            regBaseline_.insert(keyId, current); // 首次:仅建基线
            continue;
        }
        if (emitEvents) {
            const QHash<QString, QString> baseline = it.value(); // 拷贝,随后安全更新
            for (auto ci = current.constBegin(); ci != current.constEnd(); ++ci) {
                auto bi = baseline.find(ci.key());
                const bool isNew = (bi == baseline.end());
                const bool changed = !isNew && bi.value().compare(ci.value(), Qt::CaseInsensitive) != 0;
                if (isNew || changed) {
                    const QString regPath = keyId + QStringLiteral("\\") + ci.key();
                    const QString target = resolveAutorunTarget(ci.value());
                    emitAutorunReg(regPath, ci.key(), ci.value(), target.isEmpty() ? ci.value() : target);
                }
            }
        }
        it.value() = current; // 更新基线
    }
}

void UserModeBehaviorSource::emitAutorunFile(const QString& filePath, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::FileWrite;
    e.actorPid = 0; // 用户态无法归因发起进程;以被持久化程序评估可信度
    e.actorPath = target;
    e.target = filePath;
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x90\x91\xE5\x90\xAF\xE5\x8A\xA8\xE6\x96\x87\xE4\xBB\xB6\xE5\xA4\xB9\xE5\x86\x99"
                                 "\xE5\x85\xA5\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8\xE7\xA8\x8B\xE5\xBA\x8F\xEF\xBC\x88"
                                 "\xE6\x8C\x81\xE4\xB9\x85\xE5\x8C\x96\xEF\xBC\x89");
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到启动文件夹新增/变更:%1").arg(filePath));
}

void UserModeBehaviorSource::emitAutorunReg(const QString& regPath, const QString& valueName,
                                            const QString& valueData, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::RegistryWrite;
    e.actorPid = 0;
    e.actorPath = target;
    e.target = regPath;
    e.userModeObserved = false;
    e.detail = QStringLiteral("\xE6\x96\xB0\xE5\xA2\x9E/\xE5\x8F\x98\xE6\x9B\xB4\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8"
                              "\xE9\xA1\xB9\xEF\xBC\x9A%1 = %2").arg(valueName, valueData);
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到自启动注册表变更:%1").arg(regPath));
}

} // namespace bulwark::service
