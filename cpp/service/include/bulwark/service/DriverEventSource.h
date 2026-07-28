#pragma once
#include <memory>
#include <QString>
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"

class QTimer;
class QByteArray;

namespace bulwark::service {

// 内核驱动事件源:通过 fltlib 连接 Bulwark.sys 的 Minifilter 通信端口(\BulwarkPort),
// 接收「行为发生前」被内核拦下并同步等待裁决的敏感操作(文件删除/重命名、注册表写/删、
// 结束进程),转成 SecurityEvent 交规则引擎/UI,拿到裁决后经 FilterReplyMessage 回写内核
// 放行或阻止。进程创建/映像加载/远程线程/自保/网络/内存防护等为「fire-and-forget」遥测
// (内核不等待回复),其中进程创建标记 userModeObserved,Block 时由 Worker 事后补偿。
//
// 这是真正的「行为前」主动防御,取代/补充 ETW 用户态观测。对应 .NET
// Bulwark.Service/Monitoring/DriverEventSource.cs —— C++ 直接 #include 驱动的 Protocol.h,
// 无需 DriverStructs/FilterApi 那层手工重声明,消除内存布局漂移风险。
//
// 线程模型(与 EtwProcessEventSource 一致):后台读取线程阻塞在 FilterGetMessage,
// 把「轻量映射 + NT 路径归一化」后的事件推入互斥队列;主线程 QTimer 出队并 emit
// eventProduced —— 昂贵的签名/哈希/命令行/祖先链富化由 Worker::enrich 集中完成。
class DriverEventSource : public EventSource {
    Q_OBJECT
public:
    explicit DriverEventSource(const BulwarkOptions& options, QObject* parent = nullptr);
    ~DriverEventSource() override;

    void start() override;                    // 连接 + 握手 + 下发配置 + 启动读取线程(同步,失败即降级)
    void stop() override;
    bool isAvailable() const override;        // 已连接并通过协议握手

    // 阻塞源:引擎裁决后需回写内核(放行/拦截)。
    bool wantsVerdict() const override { return true; }
    void submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) override;

    // ---- 运行时配置下发(可在连接后任意时刻调用;未连接时安全 no-op)----------
    void addProtectedPid(int pid);                        // 追加受保护进程 PID(自我保护,如 UI)
    void addBlockedIp(const QString& ip, quint16 port = 0); // 情报确认恶意后固化网络拦截
    bool blockModuleLoad(const QString& modulePath) override; // 已确认恶意侧载 DLL 加入内核禁止加载名单
    bool blockExecPath(const QString& imagePath) override;    // 已确认恶意可执行映像加入内核禁止执行名单(执行前拦截)
    // 加白对账:整表清空 + 从内核写的注册表基线权威读回(协议无查询命令,故读 \Policy 值)。
    bool clearExecBlock() override;
    bool clearModuleNoLoad() override;
    bool clearBannedProcesses() override;
    QStringList persistedExecBlockList() const override;
    QStringList persistedModuleNoLoadList() const override;
    bool hardenRegistryKey(const QString& keyOrValue) override; // 已清理的自启动项加入内核注册表硬拦(持久化反重建)

    // ---- 内核级足迹清理(v6):用户态因共享冲突 / 映像占用「打不开读」或「删不掉」时,委托内核以
    //      「忽略共享访问检查」读取(供做可逆金库副本)/ POSIX 强制删除。驱动为旧版(不支持该命令)
    //      或未连接时返回 false,调用方据此回退到用户态清理。----
    bool readLockedFile(const QString& path, QByteArray& out); // 内核读整文件(供金库副本)
    bool forceDeleteFile(const QString& path);                 // 内核强制删除被占用/已映射文件
    bool killProcess(int pid);                                 // 驱动级结束进程(BLW_CMD_KILL_PID)
    bool banProcess(int pid) override;                         // 封禁主体(BLW_CMD_ADD_BANNED):内核全维拒绝其行为

    bool isConnected() const;
    bool protocolMismatch() const;            // 因协议/结构体不一致而拒绝启用内核拦截(需长退避)

private:
    void drain();                             // 主线程:出队 -> emit eventProduced

    struct Impl;                              // pImpl:把 windows.h / fltuser.h / Protocol.h 挡在头外
    std::unique_ptr<Impl> d_;
    QTimer* drainTimer_ = nullptr;
};

} // namespace bulwark::service
