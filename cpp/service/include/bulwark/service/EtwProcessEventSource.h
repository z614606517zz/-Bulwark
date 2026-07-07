#pragma once
#include <QVector>
#include <QMutex>
#include <memory>
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h" // EtwOptions

class QTimer;

namespace bulwark::service {

// 基于 krabsetw(微软官方 ETW C++ 封装,MIT 许可,header-only)的实时事件源,
// 取代原 .NET 的 WMI(Win32_ProcessStartTrace)方案。单个 user_trace 会话上挂载
// 多个提供程序(回调都在同一消费线程上串行触发):
//   - Microsoft-Windows-Kernel-Process:进程创建(核心源,始终开启);
//   - Microsoft-Windows-Kernel-Network:出站 TCP 连接(事件 12 = ConnectionAttempted)
//     -> NetworkConnect 事件,target="ip:port",供网络类规则/情报 IP 规则/外联速率/信标使用;
//   - Microsoft-Windows-DNS-Client:域名查询(事件 3006,字段 QueryName)-> DnsQuery 事件,
//     供 DGA 随机度分析使用;
//   - Microsoft-Windows-Kernel-Registry:注册表写(SetValue/DeleteKey/DeleteValue)-> RegistryWrite
//     事件,仅上报命中「持久化/受保护键」监视集的写(自启动/Winlogon/IFEO 等),供持久化分析/注册表规则。
//     键路径经 KeyObject->名 的关联缓存解析(create/open 事件填充),做法与 Velociraptor 一致;
//   - Microsoft-Windows-Kernel-File:CreateNewFile(30)-> FileWrite、DeletePath(26)-> FileDelete,
//     仅上报命中「受保护路径」监视集者(二者直接带路径,keyword 0x1400 只投递这两类,排除海量 open/read/
//     write;就地改写已存在文件需 FileObject 关联,为更重的后续增强,暂不覆盖)。
//
// 网络/DNS/注册表 属新增遥测(C# 侧由内核驱动提供,无 ETW 参考实现),故由 EtwOptions 分项开关
// 与限流(每进程每分钟上限 + (进程,目标) 去重窗口)约束,并跳过本进程 PID 避免自噪声。文件/注册表
// 若不加监视集过滤会形成事件洪泛,故只上报命中受保护路径/键的写(与驱动的受保护路径模型一致,
// 也符合「只对确有危险的行为动作」的产品原则)。事件 ID / 字段名依据公开 provider manifest
// (repnz/etw-providers-docs)与 Velociraptor 的 Windows.ETW.* 实现;krabs try_parse 解析失败会
// 静默跳过(不崩溃),故 schema 不符时最坏是「无该类事件」,不影响进程监控。需管理员权限方可收到
// 事件。注:微软 Kernel-Registry 提供程序本身并不完全可靠(可能漏事件),此为尽力而为的补充遥测。
//
// 消费模型:krabs 的 ProcessTrace 在后台线程阻塞消费;回调线程把事件推入互斥队列,
// 主线程 QTimer 出队并 emit eventProduced —— 避免跨线程信号的元类型注册。
// open()(StartTrace/OpenTrace)在主线程同步执行,非管理员会同步抛异常并被捕获,
// isAvailable() 返回 false,服务其余部分(IPC/规则)照常运行。
//
// 说明:各提供程序均不携带命令行/签名,actorPath 等留空,后续由 ProcessInspector 按 PID 回填。
class EtwProcessEventSource : public EventSource {
    Q_OBJECT
public:
    explicit EtwProcessEventSource(const EtwOptions& etw, QObject* parent = nullptr);
    ~EtwProcessEventSource() override;

    // 注册表/文件监视集(受保护键/路径 + 硬拦列表,子串大小写不敏感匹配)。只有命中监视集的
    // 写/删才会上报,避免全量事件洪泛。须在 start() 之前调用(回调在消费线程读取,启动前设置无竞争)。
    void setWatchLists(const QStringList& registryKeys, const QStringList& filePaths);

    void start() override;
    void stop() override;
    bool isAvailable() const override { return available_; }

private:
    void drain(); // 主线程:出队 -> emit eventProduced

    struct Impl;                     // pImpl:把 windows.h / krabs 细节挡在头文件外
    std::unique_ptr<Impl> d_;
    QTimer* drainTimer_ = nullptr;
    bool available_ = false;
};

} // namespace bulwark::service
