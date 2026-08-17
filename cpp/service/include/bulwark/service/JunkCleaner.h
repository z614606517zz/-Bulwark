#pragma once
#include "bulwark/ipc/Payloads.h"

#include <QString>
#include <QStringList>
#include <functional>

namespace bulwark::service {

//
// ======================== 磁盘垃圾清理:扫描与执行 ========================
//
// 功能形态与常见清理工具一致:扫描出各类可清理内容的体积 -> 用户勾选 -> 执行清理并汇报释放
// 的空间。但这是一个安全产品里的删除功能,所以它的设计首先要回答一个问题:
//
//              「这个功能有没有可能被用来删掉不该删的东西?」
//
// 下面七道护栏就是对这个问题的回答。它们不是可选的加固,是这个功能能存在的前提。
//
//  ① 【类别是唯一抓手,IPC 不接受路径】
//     每个类别对应一组【编译期写死】的根目录(见 .cpp 里的 catalog())。UI / 管道那头能表达
//     的只有「清理哪几类」。一个接受调用方给定路径的删除接口就是一个任意文件删除原语 ——
//     即便控制管道已经强制校验了客户端映像,也不该把这种原语摆在那里。
//
//  ② 【根目录准入校验】
//     每个根目录在使用前先过一遍 neverTouch 名单(安装目录、隔离区金库、System32/WinSxS/
//     Servicing、用户文档桌面图片、System Volume Information …)。这一道防的是【我们自己
//     写错表】,而不是防攻击者 —— 表是写死的,写错的后果却是删用户文件。
//
//  ③ 【规范化后的包含性校验】
//     每一个真要删的对象,其 canonicalFilePath 必须仍然落在它所属根目录之下。这一道防的是
//     重解析点逃逸:%TEMP% 下放一个指向 C:\Windows\System32 的 junction,天真的递归就会
//     顺着它走出去。这在临时目录里是攻击者完全可以做到的事(那目录本来就人人可写)。
//
//  ④ 【不跟随重解析点】
//     遍历时直接跳过符号链接 / junction,不进去。与 ③ 互补:③ 是事后拦,④ 是压根不走。
//
//  ⑤ 【保留时长阈值】
//     只动「最后修改时间早于 N 小时」的文件(默认 24 小时)。正在被安装程序 / 解压工具使用
//     的临时文件通常刚写下 —— 删掉它等于把别人正在进行的安装弄坏。这是清理工具最常见的
//     翻车方式,阈值就是为它准备的。
//
//  ⑥ 【占用即跳过,绝不升级手段】
//     删不掉(被占用 / 权限不足)就记一笔跳过,如实汇报。刻意【不】复用 QuarantineManager
//     的内核强删与「重启后删除」——那是给已确认恶意的文件用的处置手段,垃圾清理不该有能力
//     去动一个正在被使用的文件。
//
//  ⑦ 【有上限:条数 / 深度 / 时间】
//     一个病态目录树(几百万个文件、极深嵌套)不能把服务卡住。三个上限任一到达即停止并把
//     truncated 置位,如实告诉用户「这是下限估计」,而不是假装扫完了。
//
// 另外两条产品决定,写在这里以免以后被当成缺陷「修掉」:
//   · 回收站走 Shell API(SHQueryRecycleBin / SHEmptyRecycleBin),不做目录遍历。$Recycle.Bin
//     的内部结构是实现细节,手工删会留下索引残留;而且那里放的是【用户还没决定要不要删】的
//     文件,只能整体清空、不该按保留时长挑挑拣拣。
//   · 「旧版 Windows 升级残留」只统计体积、【不执行清理】。正确删除它需要对上万个受 ACL 保护
//     的文件逐个接管所有权,删一半比不删更糟,而且删完就再也回退不了系统升级。这件事交给
//     Windows 自己的磁盘清理 / 存储感知,我们只负责把它占了多少空间如实告诉用户。
//
struct JunkCleanerPolicy {
    bool enabled = true;
    int  minAgeHours = 24;              // 保留时长(护栏 ⑤)
    int  maxFilesPerCategory = 300000;  // 单类别条数上限(护栏 ⑦)
    int  maxSeconds = 120;              // 单次扫描 / 清理的时间上限(护栏 ⑦)
    QStringList excludes;               // 部署方额外指定的排除子串(并入 neverTouch)
    QString selfDir;                    // 本产品安装目录(绝不触碰)
    // 用户信任名单查询。命中即跳过 —— 用户显式信任过的东西,连「它是垃圾」这个判断都不该由
    // 我们代替他做。为空则不查(例如诊断入口)。
    std::function<bool(const QString&)> isUserTrusted;
};

//
// ======================== 大文件查找(纯只读)========================
//
// 与按类别清理并列的第二条回收磁盘空间的路子:占地方的往往不是垃圾,而是几个用户自己都忘了
// 的大文件。实测本机排行前列是休眠文件 13 GB、页面文件 8.7 GB,以及回收站里三个 890 MB 的
// 文件 —— 这些都不在任何"垃圾"类别里,但确实是用户想知道的。
//
// 【这个类没有、也不会有删除方法】它报的是任意路径上的任意文件;一旦配一个删除接口,整个
// 功能就变成了任意文件删除原语,与 JunkCleaner 那边「IPC 只收类别序号、绝不收路径」的护栏 ①
// 直接对立。界面只提供「在资源管理器中打开所在位置」,由用户自己决定怎么处理。
// 这不是功能没做完,是刻意的边界:我们负责让他看见,不代他动手。
//
// 复用 JunkCleaner 的那几条遍历纪律(不跟随重解析点、跳过系统关键目录与用户数据目录、
// 深度/时间/条数上限、读不进去的目录如实计数),因为它们的成因与那边完全一样。
//
struct LargeFileScannerPolicy {
    qint64 minBytes = 100LL * 1024 * 1024;  // 体积下限,默认 100 MB
    int    limit = 200;                     // 返回条数上限
    int    maxSeconds = 60;                 // 时间上限:全盘遍历必须有个头
    int    maxFilesScanned = 3000000;       // 检视文件数上限
    QStringList excludes;                   // 额外排除的路径子串(沿用 DiskCleanup.ExcludePaths)
    QString selfDir;                        // 本产品安装目录(不列出自己的文件)
};

class LargeFileScanner {
public:
    // 进度回调:复用垃圾清理那套载荷(cleaning 恒为 false,categoryTitle 填当前磁盘)。
    // 单独造一份进度协议不值得 —— 界面要显示的东西是一样的。
    using ProgressFn = std::function<void(const bulwark::ipc::JunkProgressPayload&)>;

    static bulwark::ipc::LargeFileScanResponsePayload
    scan(const bulwark::ipc::LargeFileScanRequestPayload& req,
         const LargeFileScannerPolicy& policy, const ProgressFn& progress = {});
};

class JunkCleaner {
public:
    // 进度回调。扫描 / 清理都可能跑十几秒,没有进度的界面与卡死无法区分。
    // 由调用方负责把它编组回主线程(本类在后台线程上被调用)。
    using ProgressFn = std::function<void(const bulwark::ipc::JunkProgressPayload&)>;

    // 扫描:纯只读,任何情况下都不删除、不修改任何文件。
    static bulwark::ipc::JunkScanResponsePayload
    scan(const bulwark::ipc::JunkScanRequestPayload& req,
         const JunkCleanerPolicy& policy, const ProgressFn& progress = {});

    // 清理:只清 req.categories 里显式列出的类别。空列表 = 什么都不做(不存在「清理全部」的
    // 隐式语义 —— 删除只能来自用户对具体类别的勾选)。
    static bulwark::ipc::JunkCleanResponsePayload
    clean(const bulwark::ipc::JunkCleanRequestPayload& req,
          const JunkCleanerPolicy& policy, const ProgressFn& progress = {});
};

} // namespace bulwark::service
