#pragma once
#include <QString>
#include <QStringList>
#include "bulwark/models/Enums.h"

// 进程「启动来源」溯源:一个进程到底是被谁拉起来的 —— 具体是哪个 Windows 服务、哪个计划任务。
//
// 为什么必须有这个:内核 / ETW 的进程事件只给得出「父进程」。而 Windows 上两条最常被滥用的
// 启动路径恰好都把父进程抹平成了无区分度的宿主:
//   · 服务:所有共享型服务都跑在 svchost.exe 里,父进程是 services.exe。看到
//     "services.exe -> svchost.exe" 完全不知道是哪个服务,更不知道那是不是攻击者刚装的服务。
//   · 计划任务:Win8+ 由任务计划程序服务(svchost 里的 Schedule)直接创建目标进程,
//     父进程就是那个 svchost.exe;Win7 是 taskeng.exe。溯源链到这里就断了。
// 于是「持久化 -> 落地执行」这条最关键的因果关系在日志上是看不见的。本解析器把它补回来。
//
// 判定策略(逐级降级,每一级都如实标注置信度,绝不猜完就当事实):
//   服务:1) SCM 权威快照(EnumServicesStatusEx + SERVICE_STATUS_PROCESS.dwProcessId)
//            —— PID 到服务名的直接映射,共享宿主里的多个服务全部列出;
//         2) 快照未命中且父进程是 services.exe(刚启动的服务存在竞态)-> 强制刷新一次;
//         3) 仍未命中 -> 注册表 \CurrentControlSet\Services 的 ImagePath 反查(服务注册
//            早于进程启动,故这条永远拿得到),命中唯一即中置信,多个则列候选。
//   计划任务:1) 先判定「是不是任务拉起的」(父进程为 taskeng.exe,或父进程是承载 Schedule
//               服务的 svchost.exe)—— 这一步不依赖任何猜测;
//             2) 再定名:任务计划程序 COM 的运行中任务列表按 EnginePID 精确匹配;
//             3) COM 不可用 -> 扫 %WINDIR%\System32\Tasks 的任务 XML,按映像路径反查候选。
//
// 性能:SCM 快照 / 注册表索引 / 任务索引 / 运行中任务列表全部带 TTL 缓存,且只有当进程
// 「看起来像服务或任务宿主派生」时才会走 COM 这条重路径。事件富化在热路径上调用,所以
// 任何一步失败都直接降级返回,绝不抛异常、绝不阻塞裁决。
namespace bulwark::service::monitoring {

struct ProcessOrigin {
    bulwark::ProcessOriginKind kind = bulwark::ProcessOriginKind::Unknown;
    QString serviceName;          // 服务名;共享宿主里多个时以 ", " 连接
    QString serviceDisplayName;   // 第一个服务的显示名
    QString taskPath;             // 计划任务完整路径,如 \Microsoft\Windows\Foo\Bar
    QString detail;               // 判定依据与置信度说明(会进事件证据链)
    bool highConfidence = false;  // true = 权威来源(SCM 快照 / COM EnginePID 精确匹配)

    bool resolved() const { return kind != bulwark::ProcessOriginKind::Unknown; }
};

class ProcessOriginResolver {
public:
    // 解析 pid 的启动来源。imagePath / parentPid / commandLine 传已知值可省掉重复系统调用
    // (事件富化路径上这些都是现成的);parentPid 传 -1 表示未知、由内部自行获取。
    static ProcessOrigin resolve(int pid, const QString& imagePath = QString(),
                                 int parentPid = -1, const QString& commandLine = QString());

    // 仅查「该 PID 宿主了哪些服务」(不做任何推断)。svchost 会返回多个。供进程管理页直接用。
    static QStringList servicesHostedBy(int pid);

    // 任务计划程序 COM 精确匹配开关。默认开;若某些精简系统上 Schedule 服务被裁掉导致
    // COM 调用总是失败,可由宿主关掉,只保留任务 XML 索引回退。
    inline static bool taskComEnabled = true;

    // 主动失效全部缓存(诊断 / 测试用)。
    static void invalidateCaches();
    // 仅失效「每 PID 结论备忘」(服务/任务注册变动后想立刻重判时用)。
    static void invalidateMemo();
};

} // namespace bulwark::service::monitoring
