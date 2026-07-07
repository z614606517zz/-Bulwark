#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"

#include <QSet>

class QTimer;

namespace bulwark::service {

class DriverEventSource;
class UserModeBehaviorSource;

// 事件源协调器。始终运行一个用户态基础源(ETW/模拟)用于观测,并可在运行时按用户开关
// 动态启动/停止内核驱动源(Bulwark.sys);始终并行一个用户态持续行为源(自启动 + 勒索诱饵)。
// 三路事件合并后对外统一 emit,作为 Worker 的唯一事件源。
//
// 设计要点(移植 .NET Monitoring/EventSourceCoordinator.cs):
//  - 内核源默认不连接,仅当开关开启后才尝试连接;连不上则后台按退避自愈重试,期间降级为
//    用户态观测,绝不因内核不可用影响 IPC/规则链路;
//  - 内核连接后抑制基础源的进程创建/退出事件,避免与内核源重复上报;
//  - 裁决回写(submitVerdict)只路由到内核源(唯一支持回写的源);
//  - 记录已连接 UI 的 PID,内核源(重)启动时补发以维持自我保护。
class EventSourceCoordinator : public EventSource {
    Q_OBJECT
public:
    // base / behavior 由调用方(main)持有;driver 由本类懒创建并拥有(parent=this)。
    EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                           const BulwarkOptions& options, QObject* parent = nullptr);
    ~EventSourceCoordinator() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override;              // 取决于基础源
    bool wantsVerdict() const override { return true; } // 路由到产生事件的源
    void submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) override;

    // 运行时控制(由 main 据设置调用)。
    void setKernelEnabled(bool on);                 // 启停内核驱动源
    void configureBehaviorMonitor(bool enabled, bool canaryEnabled);
    void addProtectedUiPid(int pid);
    void addBlockedIp(const QString& ip, quint16 port = 0);

    // 状态(供设置页回报)。
    bool kernelConnected() const;
    bool kernelAttachFailed() const { return attachFailed_; }
    bool kernelProtocolMismatch() const;

private slots:
    void onBaseEvent(const bulwark::SecurityEvent& e);
    void onDriverEvent(const bulwark::SecurityEvent& e);
    void onBehaviorEvent(const bulwark::SecurityEvent& e);
    void onKernelRetry();

private:
    EventSource* base_ = nullptr;                // 基础源(ETW/模拟),非拥有
    UserModeBehaviorSource* behavior_ = nullptr; // 行为源,非拥有(可空)
    DriverEventSource* driver_ = nullptr;        // 内核源,拥有(懒创建)
    const BulwarkOptions& options_;
    QTimer* kernelRetry_ = nullptr;              // 内核连接自愈重试
    QSet<int> protectedPids_;                    // 待补发的受保护 UI PID
    bool kernelEnabled_ = false;
    bool attachFailed_ = false;
    bool started_ = false;
    Logger log_{QStringLiteral("bulwark.service.Coordinator")};
};

} // namespace bulwark::service
