#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

class QTimer;

namespace bulwark::service {

// 用户态进程收容与处置阶梯 —— 无内核驱动时把「结束进程」从一次性动作变成有次序的阶梯。
//
// ============================ 为什么需要它 ============================
// 无驱动时每一个 Block 都是【事后补偿】:事件到达时动作已经发生。既有实现只有一根梯级
// (killMalicious:用户态 terminateProcessTree + 驱动级兜底),于是两种常见情形无解:
//   · 杀不掉(句柄被保护 / 反杀 / 关键进程护栏拒绝)时,除了记一行日志之外什么也没做;
//   · 从「决定要杀」到「真的杀掉」之间,样本还能启动子进程、把自己重新拉起来。
// 本类补的是这两段:先断掉它继续作恶的能力,再去杀;杀不掉也至少已经被收容。
//
// ============================ 三个原语,各自的可撤销性天差地别 ============================
// 这一节是本类最重要的内容。三个原语看着同类,实际分属两种完全不同的东西,混用会直接违反
// 「加白必须能撤销一切」:
//
//   A. freeze/thaw(挂起/恢复,NtSuspendProcess)—— 【完全可撤销】
//      进程停住但活着,thaw() 之后继续运行,不丢状态。这是【等用户裁决】期间唯一可用的手段。
//
//   B. cutOffChildren(Job 对象 ActiveProcessLimit=1)—— 【不可撤销】
//      实测(job_probe.log,本机):
//        · 已在运行的进程可以被塞进一个新建 Job(不需要在创建时就指定);
//        · 目标【本来就在别的 Job 里】(桌面进程几乎都是),嵌套 Job 仍然成功(Win8+);
//        · 命中限制时子进程创建失败,错误码是 ERROR_NOT_ENOUGH_QUOTA(1816),不是 5;
//        · 【关掉我们自己的 Job 句柄后限制依然生效】—— 收容不依赖本服务存活;
//        · 【没有任何 API 能把进程从 Job 里放出来】。JOB_OBJECT_LIMIT_BREAKAWAY_OK 只影响
//          之后创建的子进程,对已在 Job 里的进程无效。只有进程退出才脱离。
//      => 所以 cutOffChildren 只允许用在【反正要结束这个进程】的路径上,那里它只需要成立
//         几十毫秒。绝不允许用在等用户裁决的路径上:用户点「放行」时我们没法还原,那个程序
//         会永久无法启动子进程,而且用户完全看不出原因。
//
//   C. 映像加锁(UserModeExecBlock,由外部注入)—— 可撤销(加白对账会清锁)
//      1.1 实测:可以给【正在运行】的映像加锁;加锁期间改名 / 删除 / 复制全部被拒。
//      => 这是「先锁再杀」顺序的依据:临死的进程没机会从同一路径把自己重新拉起来,
//         也没机会把文件换成另一个再跑。
//
// ============================ 处置阶梯的次序(每一步都有理由)============================
//   1) 锁映像       —— 断掉「同路径重新拉起」与「换个文件再跑」(1.1 实测)
//   2) 冻结         —— 立刻停住全部线程,后面几步期间不会再有新破坏
//   3) 断子         —— 即使它以某种方式被恢复,也起不了子进程(1816)
//   4) 结束进程树   —— 先叶后根,每个都过 ProcessInspector 的关键进程护栏
//   5) 内核兜底补刀 —— 有驱动时 ZwTerminateProcess(注入,无驱动时这一步如实记为不可用)
//   6) 确认死亡     —— waitForExit;【没确认到就不许说已拦截】
// 刻意【不】在本类里做「计划重启删除」:QuarantineManager 的隔离阶梯最后一级已经是
// MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)。再写一份就有两处能安排开机删文件,而删错文件
// 在重启后是不可恢复的。载荷的去除仍走隔离路径,本类只负责让进程停下来。
//
// ============================ 诚实的能力边界 ============================
// * 不跨重启:Job 句柄与冻结状态随本进程消失。重启后收容全部失效(内核那侧的 banProcess
//   也一样,它是 PID 集而 PID 不跨重启)。
// * 冻结不是拦截:被冻结的进程已经做过的事不会回滚。它买到的是「决定期间不再变坏」。
// * 关键进程一律跳过:全部经 ProcessInspector::isCriticalProcess(内核 IsProcessCritical
//   权威标记 + 名单 + 路径校验,fail-safe 判为关键),避免 0xEF 蓝屏。本类【自己】也再查一遍
//   自身 PID 与系统目录,不把安全性寄托于调用方纪律。
class UserModeProcessContainment : public QObject {
    Q_OBJECT
public:
    // maxEntries:同时被收容/冻结的进程数上限(约束 4)。超限时拒绝新增并大声记录,
    // 绝不静默挤掉已有条目。
    // frozenTtlMs:冻结自动解冻兜底。冻结一个进程而没人来裁决,等于把它永久挂死,而用户
    // 看到的只是「程序卡住了」。到期自动 thaw 并记一条 warning —— 宁可放过也不无声挂死。
    explicit UserModeProcessContainment(int maxEntries = 64, int frozenTtlMs = 120000,
                                        QObject* parent = nullptr);
    ~UserModeProcessContainment() override;

    // ---- 外部能力注入(与既有 setKernelAssist / setSelfUnlock 同一惯用法)----
    // 映像加锁:传入【去盘符路径子串】,交给 UserModeExecBlock / 内核名单。
    using LockImageFn = std::function<bool(const QString& needle)>;
    void setImageLocker(LockImageFn fn);
    // 内核级结束进程(BLW_CMD_KILL_PID)。未注入或返回 false 时阶梯如实记为「不可用/失败」。
    using KernelKillFn = std::function<bool(int pid)>;
    void setKernelKill(KernelKillFn fn);

    // ---- 2.2 断子:Job 对象 ActiveProcessLimit=1 ----
    // 【不可撤销】,只允许用在即将结束该进程的路径上。onlyWhenTerminating 是一道显式闸:
    // 调用方必须自己声明「我正在走终结流程」,写 false 会被拒绝并记录 —— 让误用变成一条
    // 日志,而不是一个用户永远查不出原因的故障。
    bool cutOffChildren(int pid, bool onlyWhenTerminating, const QString& why);
    bool isChildrenCutOff(int pid) const;

    // ---- 2.3 可逆冻结 ----
    // freeze:挂起全部线程。用于「检出即挂起」——在用户裁决 / 富化 / 信誉查询期间止损。
    //
    // autoThaw 区分的是两种完全不同的处境,不能合并:
    //   true (默认) —— 【等裁决】。到 frozenTtlMs 还没人来裁决就自动解冻。因为这种冻结的
    //       对象【尚未确认恶意】,把一个可能无辜的进程无声挂死,用户看到的只是「程序卡住」,
    //       连一条安全提示都没有。宁可放过也不无声挂死。
    //   false —— 【已确认恶意且没能杀掉】。这时挂着才是想要的结果:它停在那里不再作恶,
    //       日志已大声写明,用户在界面加白就能解除(reconcile 会调 thawByPathNeedle)。
    //       对这种进程套 TTL 等于「120 秒后自动放行一个已确认的恶意进程」。
    bool freeze(int pid, const QString& imagePath, const QString& why, bool autoThaw = true);
    // thaw:恢复。加白 / 用户选择放行 / 判定为误报时【必须】调用。
    bool thaw(int pid, const QString& why);
    // 加白对账用:解冻所有映像路径命中 needle 的进程。返回解冻数。
    int thawByPathNeedle(const QString& needle, const QString& why);
    int thawAll(const QString& why);
    bool isFrozen(int pid) const;
    QList<int> frozenPids() const;
    // 冻结时长(毫秒),用于「实测竞态窗口」与 UI 文案。-1 = 未冻结。
    qint64 frozenForMs(int pid) const;

    // ---- 2.1 处置阶梯 ----
    struct LadderStep {
        QString name;
        bool attempted = false;
        bool ok = false;
        QString detail;
    };
    struct LadderResult {
        bool imageLocked = false;
        bool frozen = false;
        bool childrenCutOff = false;
        bool userModeKilled = false;
        bool kernelKilled = false;
        bool confirmedGone = false;   // waitForExit 确认过,才允许对外说「已结束」
        int  killedInTree = 0;
        QVector<LadderStep> steps;
        // 供日志与 UI 用的一行摘要。刻意区分「已结束」与「已收容但仍在运行」——
        // 后者是用户最需要自己动手的情形,说成「已拦截」就是谎报。
        QString summary() const;
    };
    // imagePathNeedle:去盘符路径子串,空串表示不做映像加锁那一级。
    LadderResult disposeOf(int pid, const QString& imagePath, const QString& imagePathNeedle,
                           const QString& why);

    // 诊断:当前收容状态(写审计 / 门禁核对用)。
    QStringList describeState() const;

private:
    struct Entry {
        void*   job = nullptr;        // HANDLE,仅 cutOffChildren 用
        bool    frozen = false;
        bool    autoThaw = true;      // false = 已确认恶意,刻意挂到进程退出或用户加白
        qint64  frozenAtMs = 0;
        QString imagePath;
    };

    bool refuseTarget(int pid, const QString& imagePath, QString* why) const;
    void onTtlTick();

    mutable QMutex mx_;
    QHash<int, Entry> entries_;
    LockImageFn lockImage_;
    KernelKillFn kernelKill_;
    QTimer* ttl_ = nullptr;
    const int maxEntries_;
    const int frozenTtlMs_;
    Logger log_{QStringLiteral("bulwark.service.Containment")};
};

} // namespace bulwark::service
