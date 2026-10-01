#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

namespace bulwark::service {

// 阶段 3:用户确认型系统加固 + 跨重启的执行拒绝 + 注册表即时回滚。
//
// ============================ 这一组与阶段 1/2 的根本区别 ============================
// 阶段 1/2 的一切都【不跨重启】:独占句柄、WFP 动态会话、冻结、Job 收容,全都随服务进程消失。
// 本组是唯一能在重启后仍然成立的那一层,代价是它改的是【系统持久状态】,所以规矩反过来:
//   · 只读的 inspect() 随时可调,永不改动任何东西;
//   · 凡要改系统状态的动作,一律需要调用方显式传 apply=true,且受部署开关约束;
//   · 每一个动作都必须有配对的撤销动作,并且撤销路径【已经实测过】,不是推断。
//
// ============================ 实测依据(harden_probe.log / reg_probe3.log)============================
// 3.5 文件 DACL 拒绝执行:
//   1. 对文件加 DENY Everyone:(FILE_EXECUTE) 后,启动它失败,错误码 5(ERROR_ACCESS_DENIED)。
//      三段交替确证:基线 1223(本机另一款杀软在拦) -> 加 ACE 后 5 -> 移除 ACE 后又回 1223。
//   2. 【读取不受影响】。这是它比 UserModeExecBlock 的 share-mode-0 严格更好的地方:那把锁
//      连读和删一起挡,害得隔离必须先放手(1.1 里为此专门加了 suspendForRemediation 协议);
//      拒绝执行只拒执行,我们自己的金库拷贝、取哈希、删除全部照常。
//   3. 可撤销:删掉那条 DENY ACE 后行为立刻回到基线。
//   4. 【DENY 压过 ALLOW】。加完 DENY Everyone 之后再给 SYSTEM 补 (F),执行仍然是 5。
//      所以「拒绝所有人但放过自己执行」这件事用 deny-Everyone 表达不出来 —— 对本用途无妨
//      (我们从不需要执行恶意体),但任何想复用这个原语去「只拒别人」的想法都会撞墙。
//   5. 【按文件不按路径】。把被拒的文件复制一份,副本能跑(副本继承目录默认 ACL,不带 DENY)。
//      与按路径封堵是同一类绕过,不多也不少。这条必须写清楚,否则会被当成比实际更强的手段。
// 3.2 注册表 DENY ACE:
//   6. 必须用【带 ChangePermissions 的句柄】打开键才能改它的 DACL。用只读句柄去改会抛
//      UnauthorizedAccessException,而后续的写入测试会「成功」—— 看上去像是 deny 无效,
//      实际是 ACE 从来没被加上。第一轮探针就栽在这里,结论整条作废。
//   7. 加上 DENY Everyone:(SetValue) 后写值失败,错误码 5;移除后立刻恢复可写。
//   8. 【注册表安全描述符在「键」上,不在「值」上】。所以 DENY ACE 做不到「保护 Run 下的
//      某一个值、同时让 Run 本身可写」。对 Run / RunOnce 这类共享键加 DENY 会打断每一个
//      正经安装程序 —— 这正是本类把 3.2 限定为【恶意独占键】、把共享键交给 3.1 的原因。
//
// ============================ 为什么全部走 Win32 API 而不是 icacls / reg ============================
// 本产品自己带命令行硬拦。1.5 里已经栽过一次同类的坑(想用 vssadmin 结果被自己的规则挡住)。
// 一个安全产品去 spawn icacls.exe 来改 ACL,不但会被自己的检测盯上,还给了「劫持
// icacls.exe」这种绕过一个现成的入口。所以这里一律用 GetNamedSecurityInfoW /
// SetEntriesInAclW / SetNamedSecurityInfoW,不创建任何子进程。
class SystemHardening : public QObject {
    Q_OBJECT
public:
    explicit SystemHardening(QObject* parent = nullptr);
    ~SystemHardening() override;

    // 「这个路径是否已被用户加白」。3.1 的回滚、3.5 的拒绝执行都要先问它,避免把用户
    // 自己装的程序回滚掉 / 拒掉。未注入时按「一律不信任」处理(更安全,但会更吵)。
    using TrustProbeFn = std::function<bool(const QString& path)>;
    void setTrustProbe(TrustProbeFn fn);

    // ================= 只读体检(3.3 / 3.4,随时可调,绝不改动任何东西)=================
    struct Finding {
        QString id;
        QString title;
        bool    satisfied = false;  // 当前是否已处于加固状态
        QString current;            // 现状(实测读出来的,不是假定的)
        QString recommended;        // 建议动作
        QString cost;               // 【诚实的代价】:应用它会带来什么副作用
        bool    needsReboot = false;
        bool    reversible = true;
    };
    QVector<Finding> inspect() const;

    // 3.3 lsass RunAsPPL。值【必须是 2】,绝不能写 1 ——
    //   1 会把 RunAsPPL 写进 UEFI 变量,之后从注册表里删掉这个值也关不掉它;
    //   2 是「启用但不写 UEFI 变量」,可以从注册表撤销。
    // 这一条是本类里唯一一个「写错一个数字就变成不可逆」的动作,所以它在代码里也只接受 2。
    bool applyRunAsPpl(bool apply);
    bool revertRunAsPpl(bool apply);

    // 3.4 自身服务的 DACL:把 SERVICE_STOP / SERVICE_CHANGE_CONFIG / DELETE 从
    // Authenticated Users / INTERACTIVE 一类的宽泛主体上收掉,只留 SYSTEM 与 Administrators。
    // 诚实边界:有管理员权限的恶意软件仍能改回来(它能改 DACL)。这不是自保护,是提高门槛 ——
    // 真正的自保护在内核 SelfGuard 那一侧,无驱动时没有等价物。
    bool applySelfServiceDacl(bool apply);

    // ================= 3.5 文件 DACL 拒绝执行(跨重启)=================
    // UserModeExecBlock 的独占句柄不跨重启,这一层是它真正的补位。两者可以叠加:
    // 句柄挡住「现在」,ACE 挡住「重启之后」。
    bool denyExecute(const QString& path);
    bool undenyExecute(const QString& path);
    // 我们这次运行里加过 DENY 的路径(用于对账)。刻意【不】落盘:
    // 真正的权威是文件系统上的那条 ACE,再维护一份清单就会出现「清单说有、盘上没有」
    // 或者反过来的分歧 —— 1.4 里已经因为清单与真实状态分歧栽过一次。
    QStringList deniedExecuteThisRun() const;
    // 该注册表键是否为「恶意独占」(即加 DENY ACE 不会打断正常软件)。公开出来是因为调用方
    // 需要在【选工具之前】就知道答案:共享键只能走 3.1 回滚,独占键才能走 3.2 的 DENY ACE。
    static bool isExclusiveRegistryKey(const QString& hiveAndKey);
    // 运行时追加监视键并使其立即生效(用在清理完持久化之后)。
    // 已在监视中时会重启监视线程 —— 这是冷路径(只在一次足迹清理之后发生),用重启换实现简单。
    void watchKeyLive(const QString& hiveAndKey);
    // 判断某个路径上【当前】是否有我们这条 DENY ACE(直接读盘上的 DACL,不查清单)。
    bool hasDenyExecute(const QString& path) const;

    // ================= 3.2 注册表 DENY 写入(仅恶意独占键)=================
    // exclusiveKeyOnly 是一道显式闸,与 2.2 的 onlyWhenTerminating 同一用法:
    // 调用方必须声明「这个键是恶意软件独占的」。对共享键(Run / RunOnce / Services 根)
    // 一律拒绝并记录 —— 见上面第 8 条。
    bool denyRegistryWrite(const QString& hiveAndKey, bool exclusiveKeyOnly);
    bool undenyRegistryWrite(const QString& hiveAndKey);

    // ================= 3.1 注册表即时监视 + 自动回滚 =================
    // RegNotifyChangeKeyValue:内核在键变化时【立刻】唤醒我们,不是轮询。
    // 与既有 UserModeBehaviorSource::scanRegistryDelta 的分工:那个是周期性比对(默认若干秒
    // 一轮),本身就给了恶意软件一个「写进去再等我们发现」的窗口;这个把窗口压到一次线程唤醒。
    //
    // 回滚语义(重要):只回滚【我们有快照、且新值指向一个未加白路径】的变化。
    //   · 没有快照的新增值 -> 删除(那是我们开始监视之后新出现的);
    //   · 有快照的修改 -> 写回旧值;
    //   · 新值指向已加白路径 -> 不动,只记一行(用户自己装的程序会改这些键)。
    // 绝不「把整个键恢复成快照」:那会连带删掉监视期间正常软件写的东西。
    void watchKey(const QString& hiveAndKey);
    bool startWatching();
    void stopWatching();
    bool isWatching() const;
    struct RollbackRecord {
        QString keyPath;
        QString valueName;
        QString newData;      // 被回滚掉的那个值
        QString restoredTo;   // 回滚成什么(空 = 值被删除)
        QString whenUtcIso;
    };
    QVector<RollbackRecord> rollbacks() const;

signals:
    // 回滚发生时发出。main 接到后可写审计 / 推 UI,本类自己不碰 IPC(约束 1:零同步 IPC)。
    void rolledBack(const QString& keyPath, const QString& valueName, const QString& newData,
                    const QString& restoredTo);

private:
    struct Watched {
        QString hiveAndKey;
        QHash<QString, QString> snapshot;   // valueName -> data(仅字符串类值)
    };

    void watchLoop();
    bool reconcileKey(Watched& wk);

    mutable QMutex mx_;
    TrustProbeFn trustProbe_;
    QStringList deniedExec_;
    QVector<Watched> watched_;
    QVector<RollbackRecord> rollbacks_;
    void* stopEvent_ = nullptr;     // HANDLE
    void* thread_ = nullptr;        // std::thread*
    bool watching_ = false;
    Logger log_{QStringLiteral("bulwark.service.Hardening")};
};

} // namespace bulwark::service
