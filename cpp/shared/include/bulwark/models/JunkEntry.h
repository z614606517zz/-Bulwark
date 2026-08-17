#pragma once
#include <QString>
#include <QList>
#include <QJsonObject>

namespace bulwark {

//
// ============================ 磁盘垃圾清理:契约模型 ============================
//
// 设计要点(与常见清理工具的做法一致,但对一个安全产品另有更硬的约束):
//
// 1) 【类别是唯一的对外抓手,路径不是】枚举里的每一项在服务端对应一组【编译期固定】的根目录。
//    IPC 请求只携带类别序号,从不携带路径 —— 于是「垃圾清理」这条链路在任何情况下都无法被
//    用来删除任意文件。这是本功能最重要的一条设计:一个能删文件的接口如果接受调用方给的
//    路径,它就是一个远程文件删除原语,哪怕管道那头已经过认证也不该这么做。
//
// 2) 【序号是上线契约】序号进 IPC 线格式与审计日志,只能在末尾追加,不能重排、不能复用。
//    与 IpcMessageType 同一约定。
//
// 3) 【风险分档决定默认是否勾选】Safe 表示「删掉只是让缓存重建」,Caution 表示「有用户能
//    感知的副作用」。产品原则是尽量少给用户造成意外,所以 Caution 一律默认不勾,并且要在
//    描述里把副作用直说,而不是笼统写「可安全删除」。
//
namespace junk {

enum class Category {
    WindowsTemp = 0,       // 系统与各用户的临时文件目录
    RecycleBin,            // 回收站
    WindowsUpdateCache,    // Windows 更新下载缓存
    DeliveryOptimization,  // 传递优化(P2P 分发)缓存
    ErrorReports,          // 错误报告与崩溃/内存转储
    ThumbnailCache,        // 缩略图与图标缓存
    Prefetch,              // 预读取文件
    FontCache,             // 字体缓存
    SystemLogs,            // 系统安装与维护日志(CBS / DISM / Panther)
    BrowserCache,          // 浏览器缓存(不含 Cookie / 历史 / 密码 / 书签)
    RecentDocs,            // 最近使用记录(快捷方式)
    SelfLogs,              // 本产品自身的过期日志与审计
    WindowsOld,            // 旧版 Windows 升级残留(Windows.old / $WINDOWS.~BT)
    // ---- 以下为第二批(对着真机实测的漏扫补上的)。序号只能追加,见文件头说明。----
    InstallerPatchCache,   // Windows Installer 的补丁基线缓存($PatchCache$)
    DefenderHistory,       // Windows Defender 扫描历史记录
    UpgradeLeftovers,      // 系统升级/重置的临时目录($GetCurrent / $SysReset / $WINDOWS.~Q)
    InternetCache,         // 网络临时文件(INetCache,WinINet 的下载缓存)
    ShaderCache,           // GPU 着色器编译缓存(D3DSCache / NVIDIA / AMD)
    PackageManagerCache,   // 开发包管理器下载缓存(pip / npm / NuGet / Gradle / Maven / Cargo …)
    GameLauncherCache,     // 游戏平台的网页与日志缓存(Steam / Epic)
    OfficeCache,           // Office 文档缓存
    SystemReserved,        // 系统保留的大文件(休眠文件 / 页面文件 / 还原点)—— 只报告,永不删除
    SelfCache,             // 本产品自身的可重建缓存(信誉缓存 / 组合表 / 更新暂存 / 诊断日志)
};

enum class Risk {
    Safe = 0,   // 只影响缓存重建,不丢用户数据与设置
    Caution,    // 有可感知副作用(首次启动变慢 / 无法回退系统升级 / 丢最近打开记录)
};

// 稳定的 ASCII 键名。用于审计日志与诊断输出 —— 那些地方不能写中文标题(标题是 UI 文案,
// 会因为措辞调整而变),也不该写裸序号(事后没人看得懂 audit 里的 "category":7)。
QString categoryKey(Category c);
Category categoryFromKey(const QString& key);

} // namespace junk

// 一个已扫描位置的【聚合】结果。
//
// 刻意不逐文件上报:%TEMP% 与浏览器缓存动辄数万个文件,逐条塞进 IPC 既撑爆管道也没人看。
// UI 需要的是「哪个位置、多大、多少个文件」,真正的逐文件决策由服务端在清理时按同一套护栏
// 重新枚举 —— 也就是说扫描结果是【展示用的快照】,不是清理时的待删清单。这一点很关键:
// 扫描与清理之间可能过了几分钟,文件早就变了,拿旧清单去删既不准也不安全。
struct JunkLocation {
    QString path;            // 位置(已通过护栏校验的规范化路径)
    QString note;            // 补充说明(如「仅统计 24 小时前的文件」)
    qint64  bytes = 0;
    int     fileCount = 0;
    int     skipped = 0;     // 因被占用 / 太新 / 越界而跳过的条数
    // 有多少个子目录【读不进去】(权限不足)。
    //
    // 为什么要单独报这个:目录枚举失败与「目录是空的」在 Qt 层面返回同样的结果(空列表),
    // 于是扫描器会把「看不进去」静默当成「这里没东西」—— 用户看到一个偏小的数字,而且没有
    // 任何提示。对一个要用户据此做删除决定的界面来说,这种沉默是不能接受的:它让「扫得准」
    // 和「扫不到」长得一模一样。
    int     unreadable = 0;

    QJsonObject toJson() const;
    static JunkLocation fromJson(const QJsonObject& o);
};

// 一个类别的扫描结果。title / description 由【服务端】给出,UI 不再维护第二份中文映射 ——
// 两份文案迟早会不一致,而说明里写的是「删了会怎样」,必须与真正执行删除的那一侧同源。
struct JunkCategoryResult {
    junk::Category category = junk::Category::WindowsTemp;
    junk::Risk     risk = junk::Risk::Safe;
    QString title;
    QString description;
    bool    recommended = false;  // 是否建议默认勾选(Safe 且本机确有可清理内容)
    bool    available = true;     // 本机是否可用(目录不存在 / 权限不足 -> false)
    // 本类别当前是否真的可以执行清理。false 的两种成因:本机没有内容,或者这一类【设计上
    // 只统计不清理】(如旧版 Windows 升级残留)。
    //
    // 之所以单列一个字段而不是让界面去猜:界面需要据此决定给不给复选框,而唯一知道答案的是
    // 服务端。曾经想过让界面按 message 里的措辞判断 —— 那等于把一句中文文案变成协议,改一个
    // 字就静默失效,而失效的表现是「给了一个勾上也没用的复选框」。
    bool    cleanable = false;
    qint64  bytes = 0;
    int     fileCount = 0;
    int     skipped = 0;
    int     unreadable = 0;       // 本类别下读不进去的子目录总数(见 JunkLocation::unreadable)
    qint64  elapsedMs = 0;        // 本类别的扫描耗时。让「怎么这么快」变成一个可解释的数字
    QString message;              // 该类扫描时遇到的问题(权限不足等),如实回话
    QList<JunkLocation> locations;

    QJsonObject toJson() const;
    static JunkCategoryResult fromJson(const QJsonObject& o);
};

//
// ============================ 大文件查找 ============================
//
// 与按类别清理并列的第二种「回收磁盘空间」的办法:占地方的往往不是垃圾,而是几个用户自己
// 早就忘了的大文件(实测本机排行前列是休眠文件 13 GB、页面文件 8.7 GB,以及回收站里三个
// 890 MB 的文件)。清理工具普遍有这个功能。
//
// 【本功能纯只读,而且刻意不提供删除】
//
// 它报出来的是任意路径上的任意文件 —— 一旦再给一个「删除」接口,这个功能就变成了一个任意
// 文件删除原语,与按类别清理那边「IPC 只收类别序号、绝不收路径」的整套设计直接对立。所以
// 界面上只提供「在资源管理器中打开所在位置」,由用户自己在资源管理器里决定怎么处理。
// 这不是功能缺失,是刻意的边界:我们负责让他看见,不代他动手。
//
struct LargeFileEntry {
    QString   path;
    qint64    bytes = 0;
    QDateTime lastModifiedUtc;
    QString   suffix;            // 小写扩展名(不含点),供界面归类与排序;无扩展名则为空

    QJsonObject toJson() const;
    static LargeFileEntry fromJson(const QJsonObject& o);
};

// 一个类别的清理结果。
//
// success=false 时 message 必须说明【为什么没做成】(权限不足 / 目录不存在 / 该类未启用),
// 与进程处置的约定一致:不允许静默成功,也不允许把「跳过了 3000 个占用中的文件」说成完全成功。
struct JunkCleanOutcome {
    junk::Category category = junk::Category::WindowsTemp;
    QString title;
    bool    success = false;
    qint64  freedBytes = 0;
    int     deletedFiles = 0;
    int     deletedDirs = 0;
    int     skipped = 0;          // 被占用 / 太新 / 越界而未删的条数
    QString message;

    QJsonObject toJson() const;
    static JunkCleanOutcome fromJson(const QJsonObject& o);
};

} // namespace bulwark
