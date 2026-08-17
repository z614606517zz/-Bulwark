// 磁盘垃圾清理的扫描与执行。七道护栏的说明在头文件里,这里是它们的实现。
//
// 阅读顺序建议:norm/canonNorm/contained/neverTouch(护栏 ②③)-> admitRoot(护栏 ②)
// -> walk(护栏 ③④⑤⑥⑦)-> catalog(类别与根目录表,护栏 ①)-> scan / clean。

#include "bulwark/service/JunkCleaner.h"
#include "bulwark/service/Logger.h"

#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStorageInfo>

#include <climits>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

namespace bulwark::service {

using bulwark::JunkCategoryResult;
using bulwark::JunkCleanOutcome;
using bulwark::JunkLocation;
namespace junk = bulwark::junk;

namespace {

const Logger& log() {
    static const Logger l(QStringLiteral("JunkCleaner"));
    return l;
}

// 中文文案一律走 fromUtf8:不依赖源文件编码在 MSVC 上的解释方式(与项目其它模块同口径)。
QString zh(const char* s) { return QString::fromUtf8(s); }

// ============================ 路径规范化与包含性 ============================

// 比较用规范化:统一分隔符、转小写、去掉尾部分隔符。【只用于比较,不用于 I/O】。
QString norm(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (s.size() > 3 && s.endsWith(QLatin1Char('\\')))
        s.chop(1);
    return s.toLower();
}

// 规范化 + 解析重解析点(符号链接 / junction)。拿到「这个路径实际指向哪里」。
// 目标不存在时 canonicalFilePath() 返回空 —— 此时回落到 norm(),由调用方按「无法确认」处理。
QString canonNorm(const QString& p) {
    const QString c = QFileInfo(p).canonicalFilePath();
    return c.isEmpty() ? norm(p) : norm(c);
}

// child 是否在 parent 之下(或就是 parent)。两侧都必须已 norm()。
// 逐段比较,不是裸前缀匹配 —— 否则 "c:\windows\temp2" 会被判成在 "c:\windows\temp" 之下。
bool contained(const QString& parent, const QString& child) {
    if (child == parent)
        return true;
    return child.startsWith(parent + QLatin1Char('\\'));
}

// 路径里有几段(用于拒绝盘根之类过浅的目标)。"c:\windows\temp" -> 3。
int segmentCount(const QString& normalized) {
    return static_cast<int>(normalized.split(QLatin1Char('\\'), Qt::SkipEmptyParts).size());
}

//
// 目录到底能不能枚举。
//
// 【为什么不能只看 QDir::entryInfoList 的结果】它对「没有权限读这个目录」和「这个目录是空的」
// 返回同样的东西:一个空列表。于是扫描器会把「看不进去」静默算成「这里没东西」,用户看到的是
// 一个偏小的数字,而且界面上一个字的提示都没有。对一个要用户据此按下删除按钮的功能来说,这种
// 沉默不可接受 —— 它让「扫得准」和「扫不到」长得一模一样。
//
// 真机上这条路径是走得到的:Defender 的扫描历史目录 ACL 通常只放行 SYSTEM,服务以普通管理员
// 身份跑(比如从控制台手工启动、或诊断入口)时就读不进去。
//
// 用 Win32 直接问一次,把两种情况分开:可读的目录里必然至少枚举出 "." ,所以拿不到句柄就是
// 真出了问题,ERROR_ACCESS_DENIED 即「无权限」。
bool dirEnumerable(const QString& dir) {
    const QString pattern = QDir::toNativeSeparators(dir) + QStringLiteral("\\*");
    WIN32_FIND_DATAW fd{};
    const HANDLE h = ::FindFirstFileW(reinterpret_cast<const wchar_t*>(pattern.utf16()), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        ::FindClose(h);
        return true;
    }
    // 极少数文件系统对空目录直接回这两个码 —— 那属于「读得到,只是没东西」,不算不可读。
    const DWORD e = ::GetLastError();
    return e == ERROR_FILE_NOT_FOUND || e == ERROR_NO_MORE_FILES;
}

// ============================ 绝不触碰名单(护栏 ②)============================
//
// 这份名单的作用【不是】防攻击者 —— 根目录表是编译期写死的,攻击者碰不到。它防的是
// 「我们自己写错表」以及「重解析点把遍历带到了别处」。后果不对称:写错一行代码,删掉的是
// 用户的文件,所以宁可多一道冗余检查。
//
// 注意名单要与合法根目录不冲突:比如不能笼统禁掉 "\appdata\roaming\",否则「最近使用记录」
// 这一类(...\AppData\Roaming\Microsoft\Windows\Recent)就永远进不来。名单里的每一项都是
// 「任何垃圾类别都不该出现在这里」的位置。
bool neverTouch(const QString& pathNorm, const JunkCleanerPolicy& pol) {
    if (pathNorm.isEmpty())
        return true;
    // 盘根与只有一段的路径(如 "c:\" / "c:\windows")一律不许作为删除目标。
    if (segmentCount(pathNorm) < 2)
        return true;

    // 本产品安装目录:内核 SelfGuard 本来就护着它,这里再拦一次,免得清理逻辑去撞自我保护。
    if (!pol.selfDir.isEmpty()) {
        const QString self = norm(pol.selfDir);
        if (!self.isEmpty() && contained(self, pathNorm))
            return true;
    }

    // 隔离区金库:里面是已隔离的威胁样本,用户随时可能要还原。绝不能被当垃圾清掉。
    {
        const QString vault = norm(QDir(programDataDir()).filePath(QStringLiteral("quarantine")));
        if (contained(vault, pathNorm))
            return true;
    }

    static const char* kForbidden[] = {
        // 系统关键目录。这些地方的文件由 WRP 保护、也确实不是垃圾。
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\windows\\servicing\\", "\\windows\\assembly\\", "\\windows\\boot\\",
        "\\windows\\inf\\", "\\windows\\fonts\\", "\\windows\\security\\",
        "\\windows\\system\\", "\\windows\\systemapps\\", "\\windows\\systemresources\\",
        "\\system volume information\\", "\\windows\\csc\\",
        // 用户数据。清理工具永远不该出现在这些目录里。
        "\\documents\\", "\\desktop\\", "\\pictures\\", "\\videos\\", "\\music\\",
        "\\favorites\\", "\\contacts\\", "\\links\\", "\\searches\\", "\\saved games\\",
        "\\onedrive\\", "\\dropbox\\", "\\my documents\\",
        // 回收站走 Shell API,不允许任何目录遍历碰它(见头文件的产品决定)。
        "\\$recycle.bin",
    };
    for (const char* f : kForbidden)
        if (pathNorm.contains(QLatin1String(f)))
            return true;

    // 部署方额外指定的排除项。
    for (const QString& ex : pol.excludes) {
        const QString e = norm(ex);
        if (!e.isEmpty() && pathNorm.contains(e))
            return true;
    }

    // 用户显式信任过的东西不碰 —— 连「它是不是垃圾」这个判断都不该由我们代替他做。
    if (pol.isUserTrusted && pol.isUserTrusted(pathNorm))
        return true;

    return false;
}

// ============================ 根目录规格 ============================

struct RootSpec {
    QString path;             // 绝对目录
    QStringList patterns;     // 文件名通配;空 = 目录下所有文件
    bool recursive = true;
    bool removeEmptyDirs = true;
    bool applyAge = true;     // 是否套用「保留时长」阈值
    QString note;
};

struct CategorySpec {
    junk::Category category = junk::Category::WindowsTemp;
    junk::Risk     risk = junk::Risk::Safe;
    QString title;
    QString description;
    QList<RootSpec> roots;
    // 「只报告」类别用的体积探针:直接对点名的【单个文件】取大小,不进遍历、更不进删除代码路径。
    //
    // 为什么单列这个而不是复用 roots + scanOnly:休眠文件 / 页面文件位于盘根,而盘根被
    // neverTouch 无条件拒绝(段数 < 2)—— 那道拒绝是对的,不该为了报个体积去松它。用探针
    // 之后,「只报告」在实现上就真的只是 stat,而不是靠一个布尔去约束删除逻辑不要动手。
    QStringList sizeProbes;
    bool recycleBin = false;  // 走 Shell API,不做目录遍历
    bool scanOnly = false;    // 只统计体积,拒绝执行清理
};

// 位置备注。规格里显式写了就用它;没写而又按文件名通配过滤时,自动把「只清哪些」讲出来。
//
// 为什么值得自动补:实测 C:\Windows\Logs 下 269 个过期文件里只有 246 个落在清理范围内
// (刻意不动 .evtx 等),这个 23 个文件的差额在界面上原本完全不可见 —— 用户对着两个数字
// 会以为扫描漏了东西。把范围写出来,差额就自解释了。
QString locationNote(const RootSpec& root) {
    if (!root.note.isEmpty())
        return root.note;
    if (!root.patterns.isEmpty())
        return zh("仅清理 ") + root.patterns.join(QStringLiteral(" / "));
    return QString();
}

// 「宽目录」:本身合法但范围太大,只有在【非递归 + 指定了文件名通配】时才允许作为根。
// 这样 C:\Windows 这种根就只可能命中一个明确点名的文件(MEMORY.DMP),不可能扩散。
bool isBroadDir(const QString& pathNorm) {
    // 从环境变量推,而不是写死 C: —— 系统装在别的盘时写死会让这道检查整体失效。
    const QString drive = norm(qEnvironmentVariable("SystemDrive", QStringLiteral("C:")));
    const QStringList broad = {
        norm(qEnvironmentVariable("SystemRoot", drive + QStringLiteral("\\Windows"))),
        norm(qEnvironmentVariable("ProgramData", drive + QStringLiteral("\\ProgramData"))),
        drive + QStringLiteral("\\users"),
        // %ProgramData%\Bulwark 自身目录同样按宽目录对待(它下面有规则库/信誉缓存/隔离区/事件历史)。
        norm(programDataDir()),
    };
    return broad.contains(pathNorm);
}

// 根目录准入(护栏 ②)。不通过就整条根丢弃并记一条警告 —— 静默跳过会让「某类清不动」变成
// 一个查不出原因的怪现象。
bool admitRoot(const RootSpec& spec, const JunkCleanerPolicy& pol, QString* canonOut) {
    if (spec.path.trimmed().isEmpty())
        return false;
    const QFileInfo fi(spec.path);
    if (!fi.exists() || !fi.isDir())
        return false;               // 本机没有这个目录:正常情况,不算错误
    // 根本身是重解析点 -> 不用。合法的垃圾目录不会是 junction,而顺着它走出去的风险不值得冒。
    if (fi.isSymLink()) {
        log().warning(zh("垃圾清理:根目录是重解析点,已跳过:") + spec.path);
        return false;
    }
    const QString c = canonNorm(spec.path);
    if (neverTouch(c, pol)) {
        log().warning(zh("垃圾清理:根目录命中「绝不触碰」名单,已跳过:") + spec.path);
        return false;
    }
    if (isBroadDir(c) && (spec.recursive || spec.patterns.isEmpty())) {
        // 这是编码错误,不是环境问题 —— 明确报出来。
        log().error(zh("垃圾清理:宽目录只允许「非递归 + 指定通配」作为根,已拒绝:") + spec.path);
        return false;
    }
    *canonOut = c;
    return true;
}

// ============================ 遍历(扫描 / 删除)============================

struct WalkStats {
    qint64 bytes = 0;
    int files = 0;
    int dirs = 0;
    int skipped = 0;
    int unreadable = 0;   // 读不进去的子目录数(见 dirEnumerable 的说明)
    bool truncated = false;
};

//
// 进度上报器,带 200ms 节流。
//
// 节流是必须的:遍历里每个文件都发一条进度会把管道打爆(单次扫描上万个文件),而人眼在
// 200ms 粒度上根本看不出差别。之前只在【切换类别】时报一次,于是一个位置扫十几秒时界面
// 一动不动,和卡死没有区别 —— 现在每进一个目录就有机会报一次。
struct ProgressTicker {
    // 成员名不能叫 emit —— Qt 把 emit 定义成了空宏,`std::function<...> emit;` 会被展开成
    // 一个没有名字的声明,报出来是 C2208 加一串莫名的 C2059,跟真正的原因毫无关系。
    std::function<void(const QString& currentDir, qint64 bytes, int files)> sink;
    qint64 baseBytes = 0;   // 本类别在之前几个根上已经累计的量(进度要连续,不能每换根就归零)
    int    baseFiles = 0;
    const QElapsedTimer* clock = nullptr;
    qint64 lastMs = -1000;

    void maybe(const QString& dir, const WalkStats& st) {
        if (!sink || !clock)
            return;
        const qint64 now = clock->elapsed();
        if (now - lastMs < 200)
            return;
        lastMs = now;
        sink(dir, baseBytes + st.bytes, baseFiles + st.files);
    }
};

struct WalkCtx {
    const JunkCleanerPolicy* pol = nullptr;
    QString rootCanon;            // 已 canon+norm 的根,包含性校验的基准
    QDateTime cutoffUtc;          // 只处理早于该时刻的文件(无效 = 不按时间过滤)
    bool deleting = false;
    const QElapsedTimer* clock = nullptr;
    qint64 deadlineMs = 0;
    ProgressTicker* ticker = nullptr;   // 可空
};

constexpr int kMaxDepth = 24;     // 护栏 ⑦:深度上限

bool outOfBudget(const WalkCtx& ctx, const WalkStats& st) {
    if (st.files + st.skipped >= ctx.pol->maxFilesPerCategory)
        return true;
    return ctx.clock && ctx.clock->elapsed() >= ctx.deadlineMs;
}

void walk(const QString& dir, const RootSpec& spec, const WalkCtx& ctx, WalkStats& st, int depth) {
    if (depth > kMaxDepth) {
        st.truncated = true;
        return;
    }
    if (outOfBudget(ctx, st)) {
        st.truncated = true;
        return;
    }

    // 先问一句「这个目录读得进去吗」。读不进去就记一笔并返回 —— 绝不能像原来那样让它
    // 静默退化成「这里没东西」(见 dirEnumerable 的说明)。
    if (!dirEnumerable(dir)) {
        ++st.unreadable;
        return;
    }
    if (ctx.ticker)
        ctx.ticker->maybe(dir, st);

    // NoSymLinks:符号链接 / junction 直接不出现在列表里(护栏 ④)。Hidden|System 要带上 ——
    // 临时目录里的垃圾常带隐藏属性,漏掉它们等于漏掉大头。
    const QFileInfoList entries = QDir(dir).entryInfoList(
        QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System
            | QDir::NoSymLinks);

    for (const QFileInfo& fi : entries) {
        if (outOfBudget(ctx, st)) {
            st.truncated = true;
            return;
        }
        // 双保险:即便 NoSymLinks 因某种原因没滤掉,也在这里拦下(护栏 ④)。
        if (fi.isSymLink())
            continue;

        const QString full = fi.absoluteFilePath();
        const QString fullNorm = norm(full);

        // 护栏 ③(字符串层):由「已规范化的根」逐段拼接出来的路径必然仍在根之下;这里挡的是
        // 拼接过程中出现 ".." 之类异常的情况。目录还会在下面做一次真正的 canonical 校验。
        if (!contained(ctx.rootCanon, fullNorm)) {
            ++st.skipped;
            continue;
        }
        if (neverTouch(fullNorm, *ctx.pol)) {
            ++st.skipped;
            continue;
        }

        if (fi.isDir()) {
            if (!spec.recursive)
                continue;
            // 护栏 ③(真正的逃逸检查):只对【目录】做 canonical 解析 —— 目录数量比文件少几个
            // 数量级,而逃逸只可能发生在目录这一层(文件不会把遍历带走)。解析后仍须在根之下。
            const QString dirCanon = canonNorm(full);
            if (!contained(ctx.rootCanon, dirCanon) || neverTouch(dirCanon, *ctx.pol)) {
                log().warning(zh("垃圾清理:子目录解析后落在根之外,已跳过:") + full);
                ++st.skipped;
                continue;
            }
            walk(full, spec, ctx, st, depth + 1);
            if (ctx.deleting && spec.removeEmptyDirs) {
                // 只删空目录,且绝不删根本身。删不掉(还有内容 / 被占用)就算了,不追。
                // isEmpty 必须带上 Hidden|System:默认过滤器看不见隐藏文件,会把「只剩隐藏
                // 文件」的目录误判为空,白白发起一次注定失败的 rmdir。
                const bool empty = QDir(full).isEmpty(QDir::AllEntries | QDir::Hidden
                                                      | QDir::System | QDir::NoDotAndDotDot);
                if (empty && dirCanon != ctx.rootCanon) {
                    if (QDir().rmdir(full))
                        ++st.dirs;
                }
            }
            continue;
        }

        if (!fi.isFile())
            continue;
        if (!spec.patterns.isEmpty() && !QDir::match(spec.patterns, fi.fileName()))
            continue;

        // 护栏 ⑤:保留时长。刚写下的临时文件很可能正被某个安装程序使用。
        if (spec.applyAge && ctx.cutoffUtc.isValid() && fi.lastModified().toUTC() >= ctx.cutoffUtc) {
            ++st.skipped;
            continue;
        }

        const qint64 size = fi.size();
        if (!ctx.deleting) {
            st.bytes += size;
            ++st.files;
            continue;
        }

        // 护栏 ⑥:删不掉就跳过,如实计数。绝不尝试解锁、接管所有权或计划重启删除 ——
        // 那是给已确认恶意文件的处置手段,垃圾清理不该有这种能力。
        if (QFile::remove(full)) {
            st.bytes += size;
            ++st.files;
        } else {
            ++st.skipped;
        }
    }
}

// ============================ 类别与根目录表(护栏 ①)============================

// 各用户配置目录。服务以 LocalSystem 运行,所以 %TEMP% / QDir::homePath() 指向的是
// 系统账户自己的目录 —— 真正堆垃圾的是各个真人用户的目录,必须显式枚举。
QStringList userProfiles() {
    QStringList out;
    const QString drive = qEnvironmentVariable("SystemDrive", QStringLiteral("C:"));
    const QDir users(drive + QStringLiteral("\\Users"));
    if (!users.exists())
        return out;
    // 内置 / 特殊账户跳过:Public 里混着用户自己放的文件,Default 是新用户模板,
    // 动它们要么伤到用户数据,要么影响新建账户。
    static const QSet<QString> kSkip = {
        QStringLiteral("public"), QStringLiteral("default"), QStringLiteral("default user"),
        QStringLiteral("all users"), QStringLiteral("defaultapppool"),
        QStringLiteral("wdagutilityaccount"),
    };
    for (const QFileInfo& fi : users.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks)) {
        if (kSkip.contains(fi.fileName().toLower()))
            continue;
        out << fi.absoluteFilePath();
    }
    return out;
}

QString winDir() {
    QString w = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    while (w.endsWith(QLatin1Char('\\')))
        w.chop(1);
    return w;
}

// 浏览器缓存根。只收「确定只装缓存」的那几个目录名,绝不把浏览器配置目录整个纳入 ——
// 那里面有 Cookie、历史、密码、书签,它们不是垃圾。
void addBrowserCacheRoots(QList<RootSpec>& roots, const QString& profile) {
    const QString local = profile + QStringLiteral("\\AppData\\Local");
    // Chromium 系(Chrome / Edge):User Data 下每个配置文件各有一套缓存目录。
    struct Chromium { const char* userData; };
    static const Chromium kChromium[] = {
        { "\\Google\\Chrome\\User Data" },
        { "\\Microsoft\\Edge\\User Data" },
        { "\\BraveSoftware\\Brave-Browser\\User Data" },
        { "\\Chromium\\User Data" },
    };
    static const char* kCacheSubdirs[] = {
        "Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache",
        "Service Worker\\CacheStorage", "Service Worker\\ScriptCache",
    };
    for (const Chromium& c : kChromium) {
        const QDir ud(local + QLatin1String(c.userData));
        if (!ud.exists())
            continue;
        // 配置文件目录:Default 与 "Profile N"。其它名字(System Profile 等)不碰。
        QStringList profiles;
        for (const QFileInfo& d : ud.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks)) {
            const QString n = d.fileName();
            if (n.compare(QLatin1String("Default"), Qt::CaseInsensitive) == 0
                || n.startsWith(QLatin1String("Profile "), Qt::CaseInsensitive))
                profiles << d.absoluteFilePath();
        }
        for (const QString& p : profiles)
            for (const char* sub : kCacheSubdirs) {
                RootSpec r;
                r.path = p + QLatin1Char('\\') + QLatin1String(sub);
                roots << r;
            }
    }
    // Firefox:每个 profile 下 cache2。
    const QDir ffRoots(local + QStringLiteral("\\Mozilla\\Firefox\\Profiles"));
    if (ffRoots.exists()) {
        for (const QFileInfo& d : ffRoots.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks)) {
            RootSpec r;
            r.path = d.absoluteFilePath() + QStringLiteral("\\cache2");
            roots << r;
        }
    }
}

// 类别表。这是本功能【唯一】的删除范围来源 —— 全部写死在代码里,不接受任何外部输入。
QList<CategorySpec> catalog(const JunkCleanerPolicy& pol) {
    const QString win = winDir();
    const QStringList profiles = userProfiles();
    const QString pd = programDataDir();
    const QString drive = qEnvironmentVariable("SystemDrive", QStringLiteral("C:"));
    // %ProgramData% 本身(注意 pd 是它下面的 Bulwark 子目录)。绝不用 pd + "\\.." 去拼 ——
    // 包含性校验用的 norm() 不解析 "..",而根是 canonical 化过的,两边对不上会让整条根
    // 在遍历时被判成「越界」而全部跳过。
    const QString programData =
        qEnvironmentVariable("ProgramData", drive + QStringLiteral("\\ProgramData"));
    QList<CategorySpec> out;

    // 绝大多数应用缓存都是「每个用户各一份」的形态,这个小工具省掉十几遍相同的循环。
    // relative 是相对用户配置目录的路径,如 "\\AppData\\Local\\D3DSCache"。
    auto perUser = [&profiles](QList<RootSpec>& roots, const char* relative,
                              const QStringList& patterns = {}, bool recursive = true) {
        for (const QString& p : profiles) {
            RootSpec r;
            r.path = p + QLatin1String(relative);
            r.patterns = patterns;
            r.recursive = recursive;
            r.removeEmptyDirs = recursive;
            roots << r;
        }
    };

    // ---- 系统与用户临时文件 ----
    {
        CategorySpec c;
        c.category = junk::Category::WindowsTemp;
        c.risk = junk::Risk::Safe;
        c.title = zh("系统与用户临时文件");
        c.description = zh("程序运行时留下的中间文件。删除不影响任何已安装软件;为免弄坏"
                           "正在进行的安装,只清理超过保留时长未被改动的文件。");
        { RootSpec r; r.path = win + QStringLiteral("\\Temp"); c.roots << r; }
        for (const QString& p : profiles) {
            RootSpec r;
            r.path = p + QStringLiteral("\\AppData\\Local\\Temp");
            c.roots << r;
        }
        out << c;
    }

    // ---- 回收站 ----
    {
        CategorySpec c;
        c.category = junk::Category::RecycleBin;
        c.risk = junk::Risk::Caution;   // 里面是用户删掉但还没决定放弃的文件
        c.title = zh("回收站");
        c.description = zh("清空全部驱动器的回收站。里面是你删除但尚未彻底放弃的文件,"
                           "清空后无法再还原,因此默认不勾选;也无法按保留时长挑选。");
        c.recycleBin = true;
        out << c;
    }

    // ---- Windows 更新缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::WindowsUpdateCache;
        c.title = zh("Windows 更新缓存");
        c.description = zh("Windows 更新下载的安装包缓存。已安装的更新不受影响;若有更新"
                           "正在下载,清理后会重新下载。");
        { RootSpec r; r.path = win + QStringLiteral("\\SoftwareDistribution\\Download"); c.roots << r; }
        out << c;
    }

    // ---- 传递优化缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::DeliveryOptimization;
        c.title = zh("传递优化缓存");
        c.description = zh("Windows 用来在局域网内互相分发更新的缓存副本。删除后不影响"
                           "已安装更新,只是下次更新可能要多走一点公网流量。");
        { RootSpec r; r.path = win + QStringLiteral("\\SoftwareDistribution\\DeliveryOptimization"); c.roots << r; }
        { RootSpec r; r.path = win + QStringLiteral("\\ServiceProfiles\\NetworkService\\AppData\\Local"
                                                    "\\Microsoft\\Windows\\DeliveryOptimization\\Cache"); c.roots << r; }
        out << c;
    }

    // ---- 错误报告与内存转储 ----
    {
        CategorySpec c;
        c.category = junk::Category::ErrorReports;
        c.title = zh("错误报告与内存转储");
        c.description = zh("程序崩溃时留下的报告与内存转储文件,通常占用可观空间。"
                           "它们只在向微软或软件厂商反馈崩溃时有用。");
        { RootSpec r; r.path = pd + QStringLiteral("\\Microsoft\\Windows\\WER\\ReportQueue");   c.roots << r; }
        { RootSpec r; r.path = pd + QStringLiteral("\\Microsoft\\Windows\\WER\\ReportArchive"); c.roots << r; }
        { RootSpec r; r.path = pd + QStringLiteral("\\Microsoft\\Windows\\WER\\Temp");          c.roots << r; }
        { RootSpec r; r.path = win + QStringLiteral("\\Minidump");            c.roots << r; }
        { RootSpec r; r.path = win + QStringLiteral("\\LiveKernelReports");   c.roots << r; }
        // 系统内存转储是单独一个文件。以 C:\Windows 为根、非递归、只认这一个文件名 ——
        // admitRoot() 的「宽目录」规则保证了这种根不可能扩散到别的文件(见 isBroadDir)。
        {
            RootSpec r;
            r.path = win;
            r.patterns << QStringLiteral("MEMORY.DMP");
            r.recursive = false;
            r.removeEmptyDirs = false;
            c.roots << r;
        }
        for (const QString& p : profiles) {
            { RootSpec r; r.path = p + QStringLiteral("\\AppData\\Local\\CrashDumps"); c.roots << r; }
            { RootSpec r; r.path = p + QStringLiteral("\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue"); c.roots << r; }
            { RootSpec r; r.path = p + QStringLiteral("\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive"); c.roots << r; }
        }
        out << c;
    }

    // ---- 缩略图与图标缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::ThumbnailCache;
        c.title = zh("缩略图与图标缓存");
        c.description = zh("资源管理器为图片、视频、图标建立的缩略图数据库。删除后会自动"
                           "重建,首次浏览大量图片时略慢。资源管理器正在占用的文件会被跳过。");
        for (const QString& p : profiles) {
            RootSpec r;
            r.path = p + QStringLiteral("\\AppData\\Local\\Microsoft\\Windows\\Explorer");
            r.patterns << QStringLiteral("thumbcache_*.db") << QStringLiteral("iconcache_*.db");
            r.recursive = false;
            r.removeEmptyDirs = false;
            r.applyAge = false;   // 一直在被写,套时间阈值等于永远清不掉
            c.roots << r;
        }
        out << c;
    }

    // ---- 预读取文件 ----
    {
        CategorySpec c;
        c.category = junk::Category::Prefetch;
        c.risk = junk::Risk::Caution;
        c.title = zh("预读取文件(Prefetch)");
        c.description = zh("Windows 记录的程序启动预读数据。删除后系统与常用程序的前几次"
                           "启动会变慢,需要重新积累,因此默认不勾选。");
        {
            RootSpec r;
            r.path = win + QStringLiteral("\\Prefetch");
            r.patterns << QStringLiteral("*.pf");
            r.recursive = false;
            r.removeEmptyDirs = false;
            c.roots << r;
        }
        out << c;
    }

    // ---- 字体缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::FontCache;
        c.title = zh("字体缓存");
        c.description = zh("字体渲染缓存,损坏时会导致字体显示异常。删除后由系统自动重建。"
                           "字体缓存服务正在占用的文件会被跳过。");
        {
            RootSpec r;
            r.path = win + QStringLiteral("\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache");
            r.patterns << QStringLiteral("*.dat") << QStringLiteral("*.tmp");
            r.recursive = false;
            r.removeEmptyDirs = false;
            r.applyAge = false;
            c.roots << r;
        }
        out << c;
    }

    // ---- 系统日志 ----
    {
        CategorySpec c;
        c.category = junk::Category::SystemLogs;
        c.title = zh("系统安装与维护日志");
        c.description = zh("Windows 组件安装、更新与磁盘维护留下的日志。只用于排查系统"
                           "安装问题,不含系统事件日志(那些不在此范围内)。");
        {
            RootSpec r;
            r.path = win + QStringLiteral("\\Logs");
            r.patterns << QStringLiteral("*.log") << QStringLiteral("*.etl")
                       << QStringLiteral("*.dpx") << QStringLiteral("*.cab");
            r.removeEmptyDirs = false;   // 有些组件启动时假定自己的日志子目录存在
            c.roots << r;
        }
        out << c;
    }

    // ---- 浏览器缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::BrowserCache;
        c.title = zh("浏览器缓存");
        c.description = zh("浏览器缓存的网页与图片。【不含】Cookie、历史记录、密码和书签 ——"
                           "那些不是垃圾。清理后首次访问网站略慢;运行中的浏览器占用的文件会被跳过。");
        for (const QString& p : profiles)
            addBrowserCacheRoots(c.roots, p);
        out << c;
    }

    // ---- 最近使用记录 ----
    {
        CategorySpec c;
        c.category = junk::Category::RecentDocs;
        c.risk = junk::Risk::Caution;
        c.title = zh("最近使用记录");
        c.description = zh("「最近使用的文件」列表与任务栏跳转列表。只是快捷方式,不会动"
                           "真正的文件;但清理后这些列表会变空,因此默认不勾选。");
        for (const QString& p : profiles) {
            const QString recent = p + QStringLiteral("\\AppData\\Roaming\\Microsoft\\Windows\\Recent");
            {
                RootSpec r;
                r.path = recent;
                r.patterns << QStringLiteral("*.lnk");
                r.recursive = false;
                r.removeEmptyDirs = false;
                c.roots << r;
            }
            {
                RootSpec r;
                r.path = recent + QStringLiteral("\\AutomaticDestinations");
                r.patterns << QStringLiteral("*.automaticDestinations-ms");
                r.recursive = false;
                r.removeEmptyDirs = false;
                c.roots << r;
            }
        }
        out << c;
    }

    // ---- 本产品自身的过期日志 ----
    {
        CategorySpec c;
        c.category = junk::Category::SelfLogs;
        c.risk = junk::Risk::Caution;   // 这些是事后追查用的证据
        c.title = zh("本产品的过期日志");
        c.description = zh("超过保留期的审计日志与已滚动的服务日志。它们是事后追查安全事件的"
                           "证据,删除不可恢复,因此默认不勾选。当天的日志与事件历史不会被触碰。");
        {
            RootSpec r;
            r.path = pd + QStringLiteral("\\audit");
            r.patterns << QStringLiteral("*.jsonl");
            r.recursive = false;
            r.removeEmptyDirs = false;
            c.roots << r;
        }
        {
            // 已滚动的服务日志(service.log.1)。%ProgramData%\Bulwark 是宽目录,所以这条根
            // 必须「非递归 + 指定通配」—— 否则 admitRoot() 会直接拒绝它,规则库、信誉缓存、
            // 事件历史与隔离区都不会被波及。
            RootSpec r;
            r.path = pd;
            r.patterns << QStringLiteral("*.log.1");
            r.recursive = false;
            r.removeEmptyDirs = false;
            c.roots << r;
        }
        out << c;
    }

    // ---- 本产品自身的可重建缓存 ----
    //
    // 与上面的「本产品的过期日志」分开是有必要的:那一类删掉会丢事后追查的证据(所以是
    // Caution、默认不勾),而这一类删掉只是让下次多花一次网络往返,没有任何代价。混成一类
    // 会迫使用户在「想清缓存」和「不想丢证据」之间做一个本不该存在的取舍。
    //
    // ======================= 刻意【不】纳入的东西(勿"顺手补上")=======================
    //
    // 本产品在 %ProgramData%\Bulwark 下写了十几样东西,只有确实可重建的进了这一类。下面这些
    // 每一条都曾看起来像"缓存",但删掉都有真实代价 —— 而且代价的共同点是【用户从一个复选框
    // 上完全看不出来】,这正是不该把它们摆上去的理由:
    //
    //   · rules.json / settings.json —— 用户的防护策略与设置,不是缓存。
    //   · quarantine\ —— 已隔离的样本与索引,用户随时可能还原(neverTouch 已挡住)。
    //   · history\events.jsonl —— 事件历史,时间线与攻击图的数据来源,取证证据。
    //   · seen_hashes.txt —— 「本机首见」判据。删掉之后每个程序都重新变成首见,于是
    //     「首见 + 可疑目录」「带签名但本机首次出现」这一批软信号会同时被点亮,误报上升、
    //     检测质量下降。这是个静默的退化,不该由用户在垃圾清理页里承担。
    //   · baseline.json —— 行为基线画像。删掉即重新进入学习期,「偏离自身历史基线」这条
    //     检测在学习期内不产出任何结论。
    //   · tb_ip_quota.json —— 微步 IP 情报的额度记账。删掉会让当月用量重新从 0 算,
    //     进而超配额被服务端限流 —— 删它是【有害】的,不是无害的。
    //   · pending_intel_upload.jsonl —— 用户已同意贡献、尚未上传的情报,删掉就是白丢。
    //   · client-id.txt —— 机器标识。
    //   · vt_scan_history.json —— 用户在「云信誉」页看得见的查询历史。它该有自己的「清空」
    //     入口(与隔离区、事件历史同一模式),而不是混进垃圾清理里被一次勾选带走。
    //   · service.log / crash.log 的【当前】文件 —— 由保留时长阈值天然保护(一直在被追写);
    //     滚动后的 .log.1 归上面的「过期日志」类。
    //
    {
        CategorySpec c;
        c.category = junk::Category::SelfCache;
        c.risk = junk::Risk::Safe;
        c.title = zh("本产品的缓存文件");
        c.description = zh("云信誉本地缓存、攻击链组合表缓存、诊断日志与更新下载暂存。全部可重建 ——"
                           "删除后下次查询 / 刷新会自动重新获取,不影响任何检测能力,也不会动"
                           "防护规则、信任名单、隔离区与事件历史。");
        {
            // 逐个文件点名,【不用】「本产品目录下所有 *.json」这种宽匹配 —— 那一下就会把
            // 规则库、用户设置、行为基线、额度记账一起端掉。宽目录规则(isBroadDir)也要求
            // 这条根必须是「非递归 + 指定通配」,两道约束刚好一致。
            RootSpec r;
            r.path = pd;
            r.patterns << QStringLiteral("reputation.jsonl")   // 云信誉本地缓存(重查即恢复)
                       << QStringLiteral("attackchain.json")   // 攻击链组合表缓存(下次刷新重下)
                       << QStringLiteral("rep_diag.log");      // 信誉链路诊断日志(纯排障输出)
            r.recursive = false;
            r.removeEmptyDirs = false;
            r.note = zh("仅信誉缓存 / 组合表缓存 / 诊断日志;规则、设置、基线、隔离区不在此列");
            c.roots << r;
        }
        {
            // ECS/SIEM 告警导出:给外部系统的副本,原始记录仍在 history\ 与 audit\ 里。
            RootSpec r;
            r.path = pd + QStringLiteral("\\alerts");
            r.patterns << QStringLiteral("*.jsonl");
            c.roots << r;
        }
        // 更新下载暂存。刻意放在 %LOCALAPPDATA% 而不是安装目录 / %ProgramData%(那两处在内核
        // SelfGuard 守护范围内,见 UpdateService::stagingRoot),所以是每用户一份。
        // 校验通过后安装脚本会用它,装完就成了残留。
        perUser(c.roots, "\\AppData\\Local\\Bulwark\\update");
        // 安装 / 更新 / 收集日志脚本的工作目录残留。
        perUser(c.roots, "\\AppData\\Local\\Temp\\bulwark_setup");
        out << c;
    }

    // ---- Windows Installer 补丁基线缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::InstallerPatchCache;
        c.risk = junk::Risk::Caution;   // 见下面的副作用说明
        c.title = zh("Installer 补丁缓存");
        c.description = zh("MSI 补丁的基线副本,供软件「修复 / 卸载补丁」时回滚使用。删除后个别"
                           "软件的修复或卸载可能要求你重新提供原始安装包,因此默认不勾选。");
        { RootSpec r; r.path = win + QStringLiteral("\\Installer\\$PatchCache$"); c.roots << r; }
        out << c;
    }

    // ---- Windows Defender 扫描历史 ----
    {
        CategorySpec c;
        c.category = junk::Category::DefenderHistory;
        c.title = zh("Defender 扫描历史");
        c.description = zh("Windows Defender 的扫描结果记录。删除后「保护历史」列表会变空,"
                           "不影响 Defender 的防护能力与病毒库。");
        // 只动 Results(结果记录),不碰同级的 Store —— 那是引擎内部状态。
        // 该目录的 ACL 通常只放行 SYSTEM;以普通管理员身份运行时读不进去,那属于「无法访问」
        // 而不是「这里没东西」,两者必须区分开(否则用户看到一个偏小的数字却毫不知情)。
        {
            RootSpec r;
            r.path = programData
                   + QStringLiteral("\\Microsoft\\Windows Defender\\Scans\\History\\Results");
            c.roots << r;
        }
        out << c;
    }

    // ---- 系统升级 / 重置残留 ----
    {
        CategorySpec c;
        c.category = junk::Category::UpgradeLeftovers;
        c.title = zh("系统升级与重置残留");
        c.description = zh("升级助手下载的文件、「重置这台电脑」留下的日志与临时目录。"
                           "与「旧版 Windows 升级残留」不同,这些不承载回退能力,可以安全删除。");
        { RootSpec r; r.path = drive + QStringLiteral("\\$GetCurrent");  c.roots << r; }
        { RootSpec r; r.path = drive + QStringLiteral("\\$SysReset");    c.roots << r; }
        { RootSpec r; r.path = drive + QStringLiteral("\\$WINDOWS.~Q");  c.roots << r; }
        {
            // Panther 里除了日志还有 unattend 之类的应答文件,所以只按扩展名取日志。
            RootSpec r;
            r.path = win + QStringLiteral("\\Panther");
            r.patterns << QStringLiteral("*.log") << QStringLiteral("*.etl");
            r.removeEmptyDirs = false;
            r.note = zh("仅日志文件,不动安装应答文件");
            c.roots << r;
        }
        out << c;
    }

    // ---- 网络临时文件 ----
    {
        CategorySpec c;
        c.category = junk::Category::InternetCache;
        c.title = zh("网络临时文件");
        c.description = zh("系统网络组件(WinINet)缓存的下载内容,很多桌面程序的内置网页视图"
                           "也用它。【不含】Cookie —— 那在另一个目录,不在清理范围内。");
        perUser(c.roots, "\\AppData\\Local\\Microsoft\\Windows\\INetCache");
        out << c;
    }

    // ---- GPU 着色器缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::ShaderCache;
        c.title = zh("显卡着色器缓存");
        c.description = zh("显卡驱动编译好的着色器缓存。删除后游戏与图形程序首次运行会重新编译,"
                           "可能出现短时卡顿,之后恢复正常。");
        perUser(c.roots, "\\AppData\\Local\\D3DSCache");
        perUser(c.roots, "\\AppData\\Local\\NVIDIA\\DXCache");
        perUser(c.roots, "\\AppData\\Local\\NVIDIA\\GLCache");
        perUser(c.roots, "\\AppData\\Local\\AMD\\DxCache");
        perUser(c.roots, "\\AppData\\Local\\AMD\\GLCache");
        out << c;
    }

    // ---- 开发包管理器缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::PackageManagerCache;
        c.risk = junk::Risk::Caution;   // 断网 / 离线重装时要重新下载
        c.title = zh("开发包管理器缓存");
        c.description = zh("pip / npm / yarn / pnpm / NuGet / Gradle / Maven / Cargo / Go 下载的包缓存,"
                           "开发机上常占数 GB。删除后下次构建需要重新联网下载(离线环境请勿清理),"
                           "因此默认不勾选。");
        perUser(c.roots, "\\AppData\\Local\\pip\\Cache");
        perUser(c.roots, "\\AppData\\Roaming\\npm-cache");
        perUser(c.roots, "\\AppData\\Local\\npm-cache");
        perUser(c.roots, "\\AppData\\Local\\Yarn\\Cache");
        perUser(c.roots, "\\AppData\\Local\\pnpm-store");
        perUser(c.roots, "\\.nuget\\packages");
        perUser(c.roots, "\\.gradle\\caches");
        perUser(c.roots, "\\.m2\\repository");
        perUser(c.roots, "\\.cargo\\registry\\cache");
        perUser(c.roots, "\\AppData\\Local\\go-build");
        out << c;
    }

    // ---- 游戏平台缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::GameLauncherCache;
        c.title = zh("游戏平台缓存");
        c.description = zh("Steam / Epic 客户端的网页界面缓存与日志。【不含】已安装的游戏文件"
                           "与云存档 —— 那些不在清理范围内。");
        // 只用固定的用户目录路径:平台安装目录位置不固定,而猜安装目录去删东西不是好主意。
        perUser(c.roots, "\\AppData\\Local\\Steam\\htmlcache");
        perUser(c.roots, "\\AppData\\Roaming\\Steam\\htmlcache");
        perUser(c.roots, "\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache");
        perUser(c.roots, "\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache_4147");
        perUser(c.roots, "\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs");
        out << c;
    }

    // ---- Office 文档缓存 ----
    {
        CategorySpec c;
        c.category = junk::Category::OfficeCache;
        c.risk = junk::Risk::Caution;   // 可能含尚未同步到云端的改动
        c.title = zh("Office 文档缓存");
        c.description = zh("Office 的本地文档缓存。若有文档的改动尚未同步到 OneDrive / SharePoint,"
                           "清理可能导致这部分改动丢失,因此默认不勾选 —— 请先确认文档都已同步。");
        perUser(c.roots, "\\AppData\\Local\\Microsoft\\Office\\16.0\\OfficeFileCache");
        perUser(c.roots, "\\AppData\\Local\\Microsoft\\Office\\15.0\\OfficeFileCache");
        out << c;
    }

    // ---- 系统保留空间(只报告,不清理)----
    {
        CategorySpec c;
        c.category = junk::Category::SystemReserved;
        c.risk = junk::Risk::Caution;
        c.scanOnly = true;
        c.title = zh("系统保留空间");
        c.description = zh("休眠文件与虚拟内存页面文件,通常合计十几 GB,是磁盘占用排行里最大的两项。"
                           "本产品只报告它们占了多少、【绝不删除】:直接删会破坏休眠与内存交换。"
                           "确实要回收请用系统自带的方式关闭休眠(powercfg /h off)或调整虚拟内存。");
        // 走 sizeProbes 而不是 roots:这三个文件在盘根,而盘根被 neverTouch 无条件拒绝 ——
        // 那道拒绝是对的,不该为了报个体积去松它。探针只 stat,不进遍历与删除路径。
        c.sizeProbes << drive + QStringLiteral("\\hiberfil.sys")
                     << drive + QStringLiteral("\\pagefile.sys")
                     << drive + QStringLiteral("\\swapfile.sys");
        out << c;
    }

    // ---- 旧版 Windows 升级残留(只统计,不清理)----
    {
        CategorySpec c;
        c.category = junk::Category::WindowsOld;
        c.risk = junk::Risk::Caution;
        c.scanOnly = true;
        c.title = zh("旧版 Windows 升级残留");
        c.description = zh("系统升级后保留的旧版本文件,通常有数 GB。本产品只报告它占用的空间、"
                           "【不代为删除】:正确删除需要逐个接管上万个受保护文件的所有权,删一半"
                           "比不删更糟,而且删完就再也无法回退系统升级。请使用 Windows 自带的"
                           "「磁盘清理」或「存储感知」处理。");
        // drive 用函数作用域那一个,别在这里再声明一遍 —— /W4 会按 C4456「隐藏了外层局部声明」报警。
        { RootSpec r; r.path = drive + QStringLiteral("\\Windows.old");    c.roots << r; }
        { RootSpec r; r.path = drive + QStringLiteral("\\$WINDOWS.~BT");   c.roots << r; }
        { RootSpec r; r.path = drive + QStringLiteral("\\$WINDOWS.~WS");   c.roots << r; }
        out << c;
    }

    // 兜底自检:任何一个根都不许命中「绝不触碰」名单。这里只记日志(真正的拒绝在 admitRoot),
    // 目的是让写错表这件事在服务日志里立刻可见,而不是等用户报告文件没了。
    for (const CategorySpec& c : out)
        for (const RootSpec& r : c.roots)
            if (!r.path.isEmpty() && neverTouch(norm(r.path), pol))
                log().error(zh("垃圾清理:类别表里存在越界根目录(将被拒绝):") + r.path);

    return out;
}

// ============================ 回收站(Shell API)============================

struct RecycleInfo { bool ok = false; qint64 bytes = 0; qint64 items = 0; };

RecycleInfo queryRecycleBin() {
    RecycleInfo out;
    SHQUERYRBINFO info{};
    info.cbSize = sizeof(info);
    // pszRootPath = nullptr:所有驱动器上的全部回收站。
    if (SUCCEEDED(SHQueryRecycleBinW(nullptr, &info))) {
        out.ok = true;
        out.bytes = static_cast<qint64>(info.i64Size);
        out.items = static_cast<qint64>(info.i64NumItems);
    }
    return out;
}

bool emptyRecycleBin() {
    // 不弹确认框、不显示进度、不放提示音 —— 用户已经在 UI 上确认过一次了,这里再弹一个
    // 系统对话框只会让人以为程序卡住(而且服务是无界面会话,那个框根本没人能看见)。
    const HRESULT hr = SHEmptyRecycleBinW(
        nullptr, nullptr, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
    // S_FALSE = 回收站本来就是空的,同样算成功。
    return SUCCEEDED(hr);
}

// ============================ 公共辅助 ============================

int effectiveMinAge(int requested, const JunkCleanerPolicy& pol) {
    const int base = requested > 0 ? requested : pol.minAgeHours;
    return qBound(0, base, 24 * 365);
}

QSet<int> selectionSet(const QList<int>& categories) {
    QSet<int> s;
    for (int c : categories)
        s.insert(c);
    return s;
}

} // namespace

// ================================ 扫描 ================================

bulwark::ipc::JunkScanResponsePayload
JunkCleaner::scan(const bulwark::ipc::JunkScanRequestPayload& req,
                  const JunkCleanerPolicy& policy, const ProgressFn& progress) {
    bulwark::ipc::JunkScanResponsePayload res;
    res.requestId = req.requestId;
    res.enabled = policy.enabled;
    res.minAgeHours = effectiveMinAge(req.minAgeHours, policy);
    res.scannedUtc = QDateTime::currentDateTimeUtc();

    if (!policy.enabled) {
        res.message = zh("本服务未启用磁盘垃圾清理。");
        return res;
    }

    const QList<CategorySpec> specs = catalog(policy);
    const QSet<int> want = selectionSet(req.categories);
    const QDateTime cutoff = res.minAgeHours > 0
        ? QDateTime::currentDateTimeUtc().addSecs(-3600LL * res.minAgeHours)
        : QDateTime();

    QElapsedTimer clock;
    clock.start();
    const qint64 deadline = qMax(1, policy.maxSeconds) * 1000LL;

    int index = 0;
    int considered = 0;
    for (const CategorySpec& spec : specs) {
        if (!want.isEmpty() && !want.contains(static_cast<int>(spec.category)))
            continue;
        ++considered;
    }

    for (const CategorySpec& spec : specs) {
        if (!want.isEmpty() && !want.contains(static_cast<int>(spec.category)))
            continue;
        ++index;

        JunkCategoryResult r;
        r.category = spec.category;
        r.risk = spec.risk;
        r.title = spec.title;
        r.description = spec.description;
        const qint64 categoryStartMs = clock.elapsed();

        // 类别级进度(切换类别时报一次)。位置级的实时进度由下面的 ticker 负责 ——
        // 只有类别级的话,一个位置扫十几秒时界面完全不动,与卡死无法区分。
        const auto emitCategoryProgress = [&](const QString& currentPath,
                                              qint64 bytesSoFar, int filesSoFar) {
            if (!progress)
                return;
            bulwark::ipc::JunkProgressPayload p;
            p.requestId = req.requestId;
            p.cleaning = false;
            p.categoryIndex = index;
            p.categoryTotal = considered;
            p.categoryTitle = spec.title;
            p.currentPath = currentPath;
            p.bytesSoFar = bytesSoFar;
            p.filesSoFar = filesSoFar;
            progress(p);
        };
        emitCategoryProgress(QString(), res.totalBytes, res.totalFiles);

        if (spec.recycleBin) {
            const RecycleInfo info = queryRecycleBin();
            r.available = info.ok;
            if (info.ok) {
                r.bytes = info.bytes;
                r.fileCount = static_cast<int>(qMin<qint64>(info.items, INT_MAX));
                JunkLocation loc;
                loc.path = zh("所有驱动器的回收站");
                loc.note = zh("整体清空,不按保留时长过滤");
                loc.bytes = info.bytes;
                loc.fileCount = r.fileCount;
                r.locations << loc;
            } else {
                r.message = zh("无法读取回收站信息。");
            }
            r.recommended = false;   // Caution 一律不默认勾选
            r.cleanable = r.available && r.bytes > 0;
            res.totalBytes += r.bytes;
            res.totalFiles += r.fileCount;
            res.categories << r;
            continue;
        }

        int admitted = 0;

        // 体积探针(只报告类别用):单个文件、只 stat、不进遍历。这些文件通常位于盘根,
        // 走不了常规的根目录准入 —— 那道拒绝是对的,所以这里根本不走它。
        for (const QString& probe : spec.sizeProbes) {
            const QFileInfo pf(probe);
            if (!pf.exists() || !pf.isFile())
                continue;
            ++admitted;
            JunkLocation loc;
            loc.path = QDir::toNativeSeparators(probe);
            loc.bytes = pf.size();
            loc.fileCount = 1;
            loc.note = zh("仅报告体积,本产品不删除");
            r.locations << loc;
            r.bytes += loc.bytes;
            r.fileCount += 1;
        }

        for (const RootSpec& root : spec.roots) {
            QString rootCanon;
            if (!admitRoot(root, policy, &rootCanon))
                continue;
            ++admitted;

            ProgressTicker ticker;
            ticker.clock = &clock;
            ticker.baseBytes = res.totalBytes + r.bytes;   // 进度要连续,不能每换一个根就归零
            ticker.baseFiles = res.totalFiles + r.fileCount;
            ticker.sink = emitCategoryProgress;

            WalkCtx ctx;
            ctx.pol = &policy;
            ctx.rootCanon = rootCanon;
            ctx.cutoffUtc = cutoff;
            ctx.deleting = false;
            ctx.clock = &clock;
            ctx.deadlineMs = deadline;
            ctx.ticker = &ticker;

            WalkStats st;
            walk(root.path, root, ctx, st, 0);

            if (st.truncated)
                res.truncated = true;
            // 「一个文件都没有、也没跳过任何东西、而且读得进去」才算真的空,可以不占一行。
            // 读不进去的位置【必须】留一行 —— 那正是最需要让用户看见的情况。
            if (st.files == 0 && st.skipped == 0 && st.unreadable == 0)
                continue;

            JunkLocation loc;
            loc.path = QDir::toNativeSeparators(root.path);
            loc.note = locationNote(root);
            if (loc.note.isEmpty() && !root.applyAge && cutoff.isValid())
                loc.note = zh("该位置不适用保留时长");
            loc.bytes = st.bytes;
            loc.fileCount = st.files;
            loc.skipped = st.skipped;
            loc.unreadable = st.unreadable;
            r.locations << loc;
            r.bytes += st.bytes;
            r.fileCount += st.files;
            r.skipped += st.skipped;
            r.unreadable += st.unreadable;
        }
        r.elapsedMs = clock.elapsed() - categoryStartMs;
        res.unreadable += r.unreadable;

        r.available = admitted > 0;
        if (!r.available)
            r.message = zh("本机没有该类目录,或它们都不在允许清理的范围内。");
        else if (spec.scanOnly)
            r.message = zh("仅统计体积,本产品不代为删除(原因见说明)。");
        // 有读不进去的位置就明说。这里的措辞刻意点出「结果偏小」——「有 N 个目录无权限」
        // 对用户没有意义,他要知道的是这个数字能不能信。
        if (r.unreadable > 0) {
            if (!r.message.isEmpty())
                r.message += QLatin1Char(' ');
            r.message += QStringLiteral("有 %1 个子目录因权限不足无法读取,实际占用可能更多。")
                             .arg(r.unreadable);
        }
        // 可清理 = 本机有可用根目录 + 确有内容 + 不是「只统计不清理」的类别。
        r.cleanable = r.available && !spec.scanOnly && r.bytes > 0;
        // 建议勾选 = 可清理 且 属于安全档。Caution 一律不默认勾选(产品原则:少给意外)。
        r.recommended = r.cleanable && spec.risk == junk::Risk::Safe;

        res.totalBytes += spec.scanOnly ? 0 : r.bytes;  // 只读统计类不计入「可释放」总量
        res.totalFiles += spec.scanOnly ? 0 : r.fileCount;
        res.categories << r;

        if (clock.elapsed() >= deadline) {
            res.truncated = true;
            break;
        }
    }

    res.elapsedMs = clock.elapsed();
    if (res.message.isEmpty()) {
        // 耗时写进结论里。扫描只读目录元数据(不打开文件、不算哈希),上万个条目在暖缓存下
        // 一秒出头是正常的 —— 但「1 秒就完了」看起来太像出了问题,所以把耗时和实际过了多少
        // 文件一起报出来,让它变成可核对的数字而不是一个可疑现象。
        res.message = (res.truncated ? zh("扫描达到上限,结果为下限估计。")
                                     : zh("扫描完成。"))
            + QStringLiteral("耗时 %1 秒,检视 %2 个文件。")
                  .arg(res.elapsedMs / 1000.0, 0, 'f', 2)
                  .arg(res.totalFiles);
        if (res.unreadable > 0)
            res.message += QStringLiteral("其中 %1 个子目录因权限不足未能读取。").arg(res.unreadable);
    }
    log().info(QStringLiteral("垃圾扫描完成:%1 类,可释放约 %2 字节(%3 个文件),耗时 %4ms,"
                              "不可读目录 %5 个%6")
                   .arg(res.categories.size())
                   .arg(res.totalBytes)
                   .arg(res.totalFiles)
                   .arg(res.elapsedMs)
                   .arg(res.unreadable)
                   .arg(res.truncated ? QStringLiteral(",已达上限") : QString()));
    return res;
}

// ================================ 清理 ================================

bulwark::ipc::JunkCleanResponsePayload
JunkCleaner::clean(const bulwark::ipc::JunkCleanRequestPayload& req,
                   const JunkCleanerPolicy& policy, const ProgressFn& progress) {
    bulwark::ipc::JunkCleanResponsePayload res;
    res.requestId = req.requestId;
    res.finishedUtc = QDateTime::currentDateTimeUtc();

    if (!policy.enabled) {
        res.message = zh("本服务未启用磁盘垃圾清理。");
        return res;
    }
    // 空选择 = 什么都不做。刻意不把它解释成「清理全部」—— 删除动作只能来自用户对具体
    // 类别的显式勾选,一个空列表最可能的成因是 UI 出了问题,那时最不该做的就是全删。
    if (req.categories.isEmpty()) {
        res.message = zh("未选择任何类别,未执行清理。");
        return res;
    }

    const int minAge = effectiveMinAge(req.minAgeHours, policy);
    const QList<CategorySpec> specs = catalog(policy);
    const QSet<int> want = selectionSet(req.categories);
    const QDateTime cutoff = minAge > 0
        ? QDateTime::currentDateTimeUtc().addSecs(-3600LL * minAge)
        : QDateTime();

    QElapsedTimer clock;
    clock.start();
    const qint64 deadline = qMax(1, policy.maxSeconds) * 1000LL;

    int considered = 0;
    for (const CategorySpec& spec : specs)
        if (want.contains(static_cast<int>(spec.category)))
            ++considered;

    int index = 0;
    for (const CategorySpec& spec : specs) {
        if (!want.contains(static_cast<int>(spec.category)))
            continue;
        ++index;

        JunkCleanOutcome oc;
        oc.category = spec.category;
        oc.title = spec.title;

        // 与扫描同一套:类别级 + 位置级(节流)进度。删除阶段的进度比扫描更要紧 ——
        // 用户在等一个不可撤销的操作做完,界面不动会让人怀疑要不要强杀进程。
        const auto emitCleanProgress = [&](const QString& currentPath,
                                           qint64 bytesSoFar, int filesSoFar) {
            if (!progress)
                return;
            bulwark::ipc::JunkProgressPayload p;
            p.requestId = req.requestId;
            p.cleaning = true;
            p.categoryIndex = index;
            p.categoryTotal = considered;
            p.categoryTitle = spec.title;
            p.currentPath = currentPath;
            p.bytesSoFar = bytesSoFar;
            p.filesSoFar = filesSoFar;
            progress(p);
        };
        emitCleanProgress(QString(), res.freedBytes, res.deletedFiles);

        // 只读统计类:明确拒绝,并说清该找谁处理。不允许「悄悄什么也不做但报成功」。
        if (spec.scanOnly) {
            oc.success = false;
            oc.message = zh("本产品不代为删除该类内容,请使用 Windows 自带的「磁盘清理」"
                            "或「存储感知」。");
            res.outcomes << oc;
            continue;
        }

        if (spec.recycleBin) {
            const RecycleInfo before = queryRecycleBin();
            const bool ok = emptyRecycleBin();
            const RecycleInfo after = queryRecycleBin();
            oc.success = ok;
            if (ok) {
                oc.freedBytes = qMax<qint64>(0, before.bytes - (after.ok ? after.bytes : 0));
                oc.deletedFiles = static_cast<int>(
                    qMin<qint64>(qMax<qint64>(0, before.items - (after.ok ? after.items : 0)), INT_MAX));
                oc.message = zh("回收站已清空。");
            } else {
                oc.message = zh("清空回收站失败(可能有文件正被占用)。");
            }
            res.freedBytes += oc.freedBytes;
            res.deletedFiles += oc.deletedFiles;
            res.success = res.success || oc.success;
            res.outcomes << oc;
            log().info(QStringLiteral("垃圾清理:回收站 -> %1,释放 %2 字节")
                           .arg(ok ? QStringLiteral("成功") : QStringLiteral("失败"))
                           .arg(oc.freedBytes));
            continue;
        }

        int admitted = 0;
        for (const RootSpec& root : spec.roots) {
            QString rootCanon;
            if (!admitRoot(root, policy, &rootCanon))
                continue;
            ++admitted;

            ProgressTicker ticker;
            ticker.clock = &clock;
            ticker.baseBytes = res.freedBytes + oc.freedBytes;
            ticker.baseFiles = res.deletedFiles + oc.deletedFiles;
            ticker.sink = emitCleanProgress;

            WalkCtx ctx;
            ctx.pol = &policy;
            ctx.rootCanon = rootCanon;
            ctx.cutoffUtc = cutoff;
            ctx.deleting = true;
            ctx.clock = &clock;
            ctx.deadlineMs = deadline;
            ctx.ticker = &ticker;

            WalkStats st;
            walk(root.path, root, ctx, st, 0);

            oc.freedBytes += st.bytes;
            oc.deletedFiles += st.files;
            oc.deletedDirs += st.dirs;
            oc.skipped += st.skipped;
        }

        if (admitted == 0) {
            oc.success = false;
            oc.message = zh("本机没有该类目录,或它们都不在允许清理的范围内。");
        } else {
            oc.success = true;
            oc.message = oc.skipped > 0
                ? QStringLiteral("已删除 %1 个文件,跳过 %2 个(被占用或尚在保留时长内)。")
                      .arg(oc.deletedFiles).arg(oc.skipped)
                : QStringLiteral("已删除 %1 个文件。").arg(oc.deletedFiles);
        }

        res.freedBytes += oc.freedBytes;
        res.deletedFiles += oc.deletedFiles;
        res.skipped += oc.skipped;
        res.success = res.success || oc.success;
        res.outcomes << oc;

        // 每个类别都留一条日志。垃圾清理是【删文件】的功能,事后必须能查「什么时候删了多少」。
        log().info(QStringLiteral("垃圾清理:%1(%2)-> 删除 %3 个文件 / %4 个空目录,"
                                  "释放 %5 字节,跳过 %6")
                       .arg(spec.title, junk::categoryKey(spec.category))
                       .arg(oc.deletedFiles).arg(oc.deletedDirs)
                       .arg(oc.freedBytes).arg(oc.skipped));

        if (clock.elapsed() >= deadline)
            break;
    }

    res.finishedUtc = QDateTime::currentDateTimeUtc();
    if (res.message.isEmpty()) {
        res.message = res.success
            ? QStringLiteral("清理完成,共释放 %1 字节(%2 个文件)。")
                  .arg(res.freedBytes).arg(res.deletedFiles)
            : zh("没有任何类别被成功清理,详见每类的说明。");
    }
    return res;
}

// ============================== 大文件查找 ==============================
//
// 纯只读。没有删除路径 —— 理由见头文件里 LargeFileScanner 的说明。

namespace {

// 遍历时【整棵子树都跳过】的位置。
//
// 与垃圾清理的 neverTouch 不是同一份名单,因为目的不同:那份是「绝不删」,这份是「不必看」。
// 这里排掉的都是「里面全是系统自己的大文件,列出来对用户没有任何决策价值」的地方 ——
// 把 WinSxS 里几百个组件、或者 Program Files 里每个应用的主 DLL 列进「你可以清理的大文件」
// 只会淹没真正有用的那几行。
bool skipSubtreeForLargeScan(const QString& pathNorm, const LargeFileScannerPolicy& pol) {
    if (!pol.selfDir.isEmpty()) {
        const QString self = norm(pol.selfDir);
        if (!self.isEmpty() && contained(self, pathNorm))
            return true;
    }
    static const char* kSkip[] = {
        "\\windows\\winsxs", "\\windows\\servicing", "\\windows\\system32",
        "\\windows\\syswow64", "\\windows\\assembly", "\\windows\\installer",
        "\\windows\\softwaredistribution", "\\windows\\systemapps",
        "\\windows\\systemresources", "\\system volume information",
        "\\$windows.~bt", "\\$windows.~ws", "\\windows.old",
        // 隔离区金库:里面是已隔离样本,不该出现在「你可以清理的大文件」列表里。
        "\\bulwark\\quarantine",
    };
    for (const char* s : kSkip)
        if (pathNorm.contains(QLatin1String(s)))
            return true;
    for (const QString& ex : pol.excludes) {
        const QString e = norm(ex);
        if (!e.isEmpty() && pathNorm.contains(e))
            return true;
    }
    return false;
}

struct LargeScanState {
    QList<bulwark::LargeFileEntry> heap;   // 已收集的候选,按体积降序维护
    qint64 threshold = 0;                  // 当前真实门槛(收满 limit 后就是最小那条的体积)
    int scanned = 0;
    int unreadable = 0;
    bool truncated = false;
};

// 插入一个候选,维持「按体积降序 + 长度不超过 limit」。
//
// 用有序插入而不是「全收完再排序」:全盘可能有上百万个文件过阈值(阈值给低了的时候),
// 全收进内存再排等于让用户点一下就吃掉几百 MB 内存。收满之后 threshold 自动抬高,
// 后面比它小的连插入都不做,遍历成本回落到一次比较。
void offerCandidate(LargeScanState& st, const QFileInfo& fi, int limit) {
    const qint64 size = fi.size();
    if (st.heap.size() >= limit && size <= st.threshold)
        return;

    bulwark::LargeFileEntry e;
    e.path = QDir::toNativeSeparators(fi.absoluteFilePath());
    e.bytes = size;
    e.lastModifiedUtc = fi.lastModified().toUTC();
    e.suffix = fi.suffix().toLower();

    int pos = 0;
    while (pos < st.heap.size() && st.heap[pos].bytes >= size)
        ++pos;
    st.heap.insert(pos, e);
    if (st.heap.size() > limit)
        st.heap.removeLast();
    if (st.heap.size() >= limit)
        st.threshold = st.heap.last().bytes;
}

void largeWalk(const QString& dir, const LargeFileScannerPolicy& pol, LargeScanState& st,
               int depth, const QElapsedTimer& clock, qint64 deadlineMs,
               ProgressTicker* ticker) {
    if (depth > kMaxDepth) {
        st.truncated = true;
        return;
    }
    if (st.scanned >= pol.maxFilesScanned || clock.elapsed() >= deadlineMs) {
        st.truncated = true;
        return;
    }
    if (!dirEnumerable(dir)) {
        ++st.unreadable;
        return;
    }
    if (ticker) {
        WalkStats fake;                     // ticker 只用 bytes/files 两个字段
        fake.files = st.scanned;
        ticker->maybe(dir, fake);
    }

    const QFileInfoList entries = QDir(dir).entryInfoList(
        QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System
            | QDir::NoSymLinks);
    for (const QFileInfo& fi : entries) {
        if (st.scanned >= pol.maxFilesScanned || clock.elapsed() >= deadlineMs) {
            st.truncated = true;
            return;
        }
        if (fi.isSymLink())                 // 不跟随重解析点(与垃圾清理同一条纪律)
            continue;

        const QString full = fi.absoluteFilePath();
        if (fi.isDir()) {
            if (skipSubtreeForLargeScan(norm(full), pol))
                continue;
            largeWalk(full, pol, st, depth + 1, clock, deadlineMs, ticker);
            continue;
        }
        if (!fi.isFile())
            continue;
        ++st.scanned;
        if (fi.size() >= pol.minBytes)
            offerCandidate(st, fi, pol.limit);
    }
}

// 要扫的磁盘:本机固定磁盘。
//
// 刻意排掉网络盘与可移动介质:遍历一个网络共享可能要几分钟且把带宽吃满,而 U 盘插拔后
// 结果立刻过期 —— 两者都不是用户点「查找大文件」时期待发生的事。
QStringList fixedDiskRoots() {
    QStringList out;
    for (const QStorageInfo& si : QStorageInfo::mountedVolumes()) {
        if (!si.isValid() || !si.isReady() || si.isReadOnly())
            continue;
        QString root = QDir::toNativeSeparators(si.rootPath());
        // 只要盘符形态的本地卷(C:\ D:\ …);挂载到目录的卷与伪文件系统不参与。
        if (root.size() < 2 || root.at(1) != QLatin1Char(':'))
            continue;
        if (!root.endsWith(QLatin1Char('\\')))
            root += QLatin1Char('\\');       // GetDriveTypeW 要的是 "X:\" 形态

        // 判据用 GetDriveTypeW,不看文件系统名。
        //
        // 曾经按 fileSystemType() 里有没有 nfs/cifs/smb 来排网络盘 —— 那是行不通的:
        // Windows 上映射的 SMB 盘 GetVolumeInformation 同样报 "NTFS",按名字根本筛不掉;
        // 可写 U 盘也不会被 isReadOnly() 挡住(只有光盘会)。于是「排除网络盘与可移动介质」
        // 这句话在实现上是空的。DRIVE_FIXED 才是这句话的准确判据。
        if (::GetDriveTypeW(reinterpret_cast<const wchar_t*>(root.utf16())) != DRIVE_FIXED)
            continue;
        out << root;
    }
    return out;
}

} // namespace

bulwark::ipc::LargeFileScanResponsePayload
LargeFileScanner::scan(const bulwark::ipc::LargeFileScanRequestPayload& req,
                       const LargeFileScannerPolicy& policy, const ProgressFn& progress) {
    bulwark::ipc::LargeFileScanResponsePayload res;
    res.requestId = req.requestId;
    res.scannedUtc = QDateTime::currentDateTimeUtc();

    LargeFileScannerPolicy pol = policy;
    if (req.minBytes > 0)
        pol.minBytes = req.minBytes;
    if (req.limit > 0)
        pol.limit = req.limit;
    pol.minBytes = qMax<qint64>(1024 * 1024, pol.minBytes);   // 下限 1 MB:再低就没有意义了
    pol.limit = qBound(1, pol.limit, 2000);
    res.minBytes = pol.minBytes;

    const QStringList roots = fixedDiskRoots();
    if (roots.isEmpty()) {
        res.message = zh("没有找到可扫描的本地磁盘。");
        return res;
    }

    QElapsedTimer clock;
    clock.start();
    const qint64 deadline = qMax(1, pol.maxSeconds) * 1000LL;

    LargeScanState st;
    int index = 0;
    for (const QString& root : roots) {
        ++index;
        ProgressTicker ticker;
        ticker.clock = &clock;
        ticker.baseFiles = 0;
        const int idx = index;
        const int total = static_cast<int>(roots.size());
        const QString diskLabel = root;
        ticker.sink = [&progress, &req, idx, total, diskLabel](const QString& dir,
                                                              qint64, int files) {
            if (!progress)
                return;
            bulwark::ipc::JunkProgressPayload p;
            p.requestId = req.requestId;
            p.cleaning = false;
            p.categoryIndex = idx;
            p.categoryTotal = total;
            p.categoryTitle = diskLabel;
            p.currentPath = dir;
            p.filesSoFar = files;
            progress(p);
        };
        largeWalk(root, pol, st, 0, clock, deadline, &ticker);
        if (clock.elapsed() >= deadline) {
            st.truncated = true;
            break;
        }
    }

    res.files = st.heap;
    for (const bulwark::LargeFileEntry& f : res.files)
        res.totalBytes += f.bytes;
    res.scannedFiles = st.scanned;
    res.unreadable = st.unreadable;
    res.truncated = st.truncated;
    res.elapsedMs = clock.elapsed();
    res.message = QStringLiteral("检视 %1 个文件,列出最大的 %2 个,耗时 %3 秒。")
                      .arg(res.scannedFiles).arg(res.files.size())
                      .arg(res.elapsedMs / 1000.0, 0, 'f', 2);
    if (res.truncated)
        res.message += zh("已达扫描上限,可能还有更大的文件未被列出。");
    if (res.unreadable > 0)
        res.message += QStringLiteral("其中 %1 个目录因权限不足未能读取。").arg(res.unreadable);
    log().info(QStringLiteral("大文件查找:检视 %1 个文件,命中 %2 个(阈值 %3 字节),"
                              "耗时 %4ms,不可读目录 %5 个")
                   .arg(res.scannedFiles).arg(res.files.size()).arg(res.minBytes)
                   .arg(res.elapsedMs).arg(res.unreadable));
    return res;
}

} // namespace bulwark::service
