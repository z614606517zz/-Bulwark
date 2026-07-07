 #pragma once
#include <QObject>
#include "bulwark/models/SecurityEvent.h"

class QTimer;

namespace bulwark::service {

// 事件源抽象:持续产出安全事件(Qt 信号驱动,无需后台线程)。
// 对应 .NET Monitoring/IEventSource.cs。
class EventSource : public QObject {
    Q_OBJECT
public:
    explicit EventSource(QObject* parent = nullptr) : QObject(parent) {}
    ~EventSource() override = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    // 源是否成功就绪(如 ETW 实时会话需管理员;失败时返回 false,服务其余部分照常)。
    virtual bool isAvailable() const { return true; }

    // ---- 同步裁决回写(仅内核驱动等「行为前」阻塞源需要)----------------------
    // 内核驱动在动作发生前同步等待用户态裁决:引擎判定后必须把 Allow/Block 回写内核
    // (FilterReplyMessage),否则内核超时兜底。纯观测源(ETW/WMI/模拟)无法在动作前
    // 阻断,保持默认空实现,拦截由 Worker 事后补偿(结束进程树)。
    // wantsVerdict()==true 时,Worker 会在得出终裁后调用 submitVerdict。
    virtual bool wantsVerdict() const { return false; }
    virtual void submitVerdict(const bulwark::SecurityEvent& /*e*/,
                               bulwark::VerdictAction /*action*/) {}

signals:
    void eventProduced(const bulwark::SecurityEvent& e);
};

// 模拟事件源(M1 打通 服务<->UI 链路,无需驱动即可演示完整流程)。
// 周期性产生若干代表性敏感行为事件。对应 .NET Monitoring/SimulatedEventSource.cs。
class SimulatedEventSource : public EventSource {
    Q_OBJECT
public:
    explicit SimulatedEventSource(QObject* parent = nullptr);
    void start() override;
    void stop() override;

private:
    void tick();
    QTimer* timer_ = nullptr;
    int index_ = 0;
};

} // namespace bulwark::service
