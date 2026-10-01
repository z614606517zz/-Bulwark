#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

class QTimer;

namespace bulwark::service {

// 用户态「禁止执行 / 禁止加载」原语 —— 无内核驱动时的执行前拦截。
//
// ============================ 它是什么 ============================
// 对目标文件长期持有一个 CreateFileW(GENERIC_READ, dwShareMode=0) 句柄。此后任何人再打开
// 该文件都会 ERROR_SHARING_VIOLATION(32),其中【包括 CreateProcess 为建映像 section 所做的
// 那次打开】和【加载器为 DLL 建 SEC_IMAGE 所做的那次打开】。于是样本启动不了、模块加载不进来。
//
// 这是本产品在 EventSource=Wmi / 驱动掉线时【第一个真正的行为前拦截】能力:在此之前用户态
// 的每一个 Block 都是事后补偿(见 EventSource.h 里那段「用户态规则引擎没有行为前拦截能力」)。
//
// ============================ 实测依据(不是推断)============================
// 下列每一条都在本机跑过,不是从文档推来的:
//   1. share-mode-0 句柄确实挡住 CreateProcess:同一个 exe,加锁前能启动 -> 加锁中启动失败
//      (winerror 32)-> 释放后又能启动。三段交替排除了「别的原因导致起不来」。
//   2. 对 DLL 同样成立:WinDLL() 在加锁中失败、释放后成功。
//   3. 【可以给正在运行的映像加锁】。原设计以为「文件已被映射 -> 拿不到独占句柄」,实测相反:
//      对正在运行的 python.exe 加锁成功。原因是加载器建完 section 就把文件句柄关了,不再参与
//      共享检查;保护运行中 exe 不被改写的是 MmFlushImageSection 那条路径,而【读】从来没被挡
//      (所以杀软能扫正在运行的程序)。
//      => 由此推翻了原计划里的 kill-then-lock 顺序:应当【先加锁再结束进程】,否则临死的进程
//         有机会在空窗里把自己重新拉起来。
//   4. 加锁期间 重命名 / 删除 / 复制 全部被拒。这让本原语比「按文件名拉黑」强得多:
//      改名再跑、删掉重投同路径,这两条常见绕过都走不通。
//   5. 没有更温和的共享模式可用。想过用 FILE_SHARE_READ 只挡执行、放过读取,实测不行:
//      共享检查把 FILE_EXECUTE 归进读一类,给了 FILE_SHARE_READ 就等于把加载器要的也给了。
//      (中途一版探针看上去显示 FILE_SHARE_READ|DELETE 能挡执行,但那是假象 —— 错误码是 5
//       而不是 32,且【不持任何句柄的对照行】同样被拒:那其实是本产品自己的内核 execblock 在
//       拦新投放的未签名 exe。该探针已作废,不作为依据。)
//
// ============================ 诚实的能力边界 ============================
// * 【不跨重启】。句柄随进程消失:机器重启后、以及本服务重启后到 replay() 跑完之前,文件是
//   可以执行的。内核那份名单由驱动写注册表、开机即生效,这一份做不到。真正跨重启的等价物是
//   阶段 3.5 的「文件 DACL 拒绝执行」,本类不冒充它。start() 会把这个空窗写进日志。
// * 【按路径,不按内容】。攻击者重新下载一份到别的路径就绕过了。哈希级封堵是另一回事。
// * 【锁住的文件我们自己也读不了、删不掉】。这是 share-mode-0 的必然代价(见上第 5 条)。
//   因此本类是该句柄的唯一持有者,并提供 suspendForRemediation():隔离/取哈希/删除之前必须
//   先调它,否则金库拷贝会因共享冲突失败。这不是缺陷,是必须遵守的协议。
//
// ============================ 与内核那份名单的契约对齐 ============================
// 调用方(Worker)对内核名单的用法是【追加 + 整表清空 + 权威读回】,加白撤销靠「清空 -> 重下发
// 其余条目」(Worker::reconcileKernelBlocksAfterTrust)。本类刻意实现完全相同的语义,使那段
// 加白对账代码【一行都不用改】就能同时管住用户态这份名单 —— 这正是约束 3(加白必须能撤销一切)
// 的命门所在。
//
// 条目形式也对齐:Worker 传进来的是【去掉盘符的路径子串】(如 \Users\x\Downloads\evil.exe),
// 因为内核拿到的映像路径可能是 \??\C:\... 也可能是 \Device\HarddiskVolumeN\...。用户态加锁需要
// 一个真实存在的文件,故内部把 needle 解析到各固定盘符上的具体路径再加锁;对外报出的仍是 needle,
// 以保持 persistedExecBlockList() 与内核同形(对账里的子串包含判断才成立)。
class UserModeExecBlock : public QObject {
    Q_OBJECT
public:
    // maxEntries:名单条数上限(约束 4:规则注入必须有上限)。超限时【拒绝新增并大声记录】,
    // 而不是悄悄挤掉旧条目 —— 静默丢弃一条已确认恶意的封堵比拒绝新增危险得多。
    explicit UserModeExecBlock(int maxEntries = 256, QObject* parent = nullptr);
    ~UserModeExecBlock() override;

    // 载入上次的清单并逐条重新加锁(服务启动时调一次)。返回成功武装的条目数。
    int replay();

    // ---- 与 EventSource 六个虚函数一一对应的契约 ----
    // 返回 true 仅表示【此刻真的握着至少一个句柄】,即拦截确实生效。文件不存在或抢不到句柄时
    // 条目仍会被记录(留待重试),但返回 false —— 绝不谎报一个并不存在的拦截。
    bool blockExecPath(const QString& needle);
    bool blockModuleLoad(const QString& needle);
    bool clearExecBlock();
    bool clearModuleNoLoad();
    QStringList persistedExecBlockList() const;
    QStringList persistedModuleNoLoadList() const;

    // 处置协议:隔离 / 取哈希 / 删除【之前】必须先放开句柄,否则那些操作会撞共享冲突而失败。
    // 放开后条目不删除,转为「待重新武装」:文件若还在(比如隔离失败)会被重试加锁;文件若已
    // 被移走则保持待武装,等同路径再次出现恶意文件时自动重新钉住。
    // absPath 为空表示全部挂起。返回被放开的句柄数。
    int suspendForRemediation(const QString& absPath);

    // 整体待机 / 唤醒(「退出界面即停止防护」用)。
    //
    // 与 suspendForRemediation 的区别不只是范围:那个只放开句柄,而【重试定时器照旧在跑】,
    // 于是最多 30 秒后 rearmPending() 会把刚放开的全部重新锁上 —— 拿它做待机等于「停了半分钟
    // 又自己恢复」,是一个只在实际使用时才暴露的失效。这里必须连定时器一起停。
    //
    // 待机【不清名单、不动落盘清单】:唤醒时按原名单重新武装即可,不需要再解析一遍 JSON,
    // 也不会因为待机过一次就把已确认恶意的条目丢掉。
    void setSuspended(bool suspended);
    bool isSuspended() const { return suspended_; }

    // 诊断:当前真正握着句柄的条目数 / 记录在册但未武装的条目数。
    int armedCount() const;
    int pendingCount() const;

private slots:
    // 周期性把「记录在册但没武装上」的条目再试一次(文件此刻可能已出现/已解除占用)。
    // 只有存在待武装条目时才做事,空转开销为零。
    void rearmPending();

private:
    struct Entry {
        QString needle;        // 去盘符子串,对外报出的形式(与内核同形)
        QStringList resolved;  // 已解析到的真实绝对路径
        QList<void*> handles;  // 与 resolved 平行的句柄(HANDLE);空 = 未武装
        bool inExec = false;   // 属于「禁止执行」名单
        bool inModule = false; // 属于「禁止加载」名单
        QString since;         // 首次加入时间(ISO,便于取证)
    };

    bool addEntry(const QString& needle, bool exec);
    bool armLocked(Entry& e);            // 尝试加锁(调用方须持 mx_)
    void releaseLocked(Entry& e);        // 关闭该条目全部句柄(调用方须持 mx_)
    bool clearListLocked(bool exec);     // 整表清空其中一份(调用方须持 mx_)
    QStringList resolveNeedle(const QString& needle) const;
    bool isRefusedPath(const QString& absPath) const;
    void save() const;                   // 原子落盘(调用方须持 mx_)
    QString manifestPath() const;

    mutable QMutex mx_;
    QHash<QString, Entry> entries_;      // needle(小写) -> 条目
    int maxEntries_ = 256;
    bool suspended_ = false;             // 待机中(见 setSuspended):句柄全放开且重试表停摆
    QTimer* rearm_ = nullptr;
    Logger log_{QStringLiteral("bulwark.service.ExecBlock")};
};

} // namespace bulwark::service
