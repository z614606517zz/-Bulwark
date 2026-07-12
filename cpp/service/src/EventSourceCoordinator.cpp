#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"

#include "bulwark/models/Enums.h"

#include <QTimer>

namespace bulwark::service {

EventSourceCoordinator::EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                                               const BulwarkOptions& options, QObject* parent)
    : EventSource(parent), base_(base), behavior_(behavior), options_(options) {
    if (base_)
        connect(base_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBaseEvent);
    if (behavior_)
        connect(behavior_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBehaviorEvent);
    kernelRetry_ = new QTimer(this);
    kernelRetry_->setInterval(10000); // 内核连不上时每 10s 自愈重试
    connect(kernelRetry_, &QTimer::timeout, this, &EventSourceCoordinator::onKernelRetry);
}

EventSourceCoordinator::~EventSourceCoordinator() { stop(); }

void EventSourceCoordinator::start() {
    if (started_) return;
    started_ = true;
    if (base_) base_->start();
    if (behavior_) behavior_->start();
    // 内核开关由 main 在应用初始设置时调用 setKernelEnabled(...)。
}

void EventSourceCoordinator::stop() {
    if (kernelRetry_) kernelRetry_->stop();
    if (driver_) driver_->stop();
    if (behavior_) behavior_->stop();
    if (base_) base_->stop();
    started_ = false;
}

bool EventSourceCoordinator::isAvailable() const {
    return base_ && base_->isAvailable();
}

bool EventSourceCoordinator::kernelConnected() const {
    return driver_ && driver_->isConnected();
}

bool EventSourceCoordinator::kernelProtocolMismatch() const {
    return driver_ && driver_->protocolMismatch();
}

void EventSourceCoordinator::submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) {
    // 仅内核源支持「行为前」回写;其余源为观测,submitVerdict 对它们无意义。内核源的
    // submitVerdict 内部会判断该事件是否为其追踪的等待类事件(否则 no-op)。
    if (driver_ && driver_->wantsVerdict())
        driver_->submitVerdict(e, action);
}

void EventSourceCoordinator::setKernelEnabled(bool on) {
    if (on == kernelEnabled_) return;
    kernelEnabled_ = on;
    if (on) {
        if (!driver_) {
            driver_ = new DriverEventSource(options_, this);
            connect(driver_, &EventSource::eventProduced, this, &EventSourceCoordinator::onDriverEvent);
        }
        DriverControl::ensureLoaded();     // 按需注册 + 加载 Bulwark.sys(幂等)
        driver_->start();                  // 连接 + 握手(同步)
        for (int pid : protectedPids_)     // 补发受保护 UI PID
            driver_->addProtectedPid(pid);
        if (driver_->isAvailable()) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动事件源已连接(行为前拦截 + 用户态补偿)。"));
        } else {
            attachFailed_ = true;
            kernelRetry_->start();         // 后台自愈重试,期间降级为用户态观测
            log_.warning(QStringLiteral("内核驱动暂不可用,已降级为用户态观测,后台将持续重试。"));
        }
    } else {
        kernelRetry_->stop();
        attachFailed_ = false;
        if (driver_) driver_->stop();      // 释放通信端口(便于驱动卸载/重启)
        log_.info(QStringLiteral("内核驱动事件源已停用(切回用户态观测)。"));
    }
}

void EventSourceCoordinator::onKernelRetry() {
    if (!kernelEnabled_ || !driver_) { kernelRetry_->stop(); return; }
    if (driver_->isAvailable()) { kernelRetry_->stop(); attachFailed_ = false; return; }
    DriverControl::ensureLoaded();
    driver_->start();
    if (driver_->isAvailable()) {
        kernelRetry_->stop();
        attachFailed_ = false;
        for (int pid : protectedPids_)
            driver_->addProtectedPid(pid);
        log_.info(QStringLiteral("内核驱动连接已恢复。"));
    }
}

void EventSourceCoordinator::configureBehaviorMonitor(bool enabled, bool canaryEnabled) {
    if (!behavior_) return;
    behavior_->setEnabled(enabled);
    behavior_->setCanaryEnabled(canaryEnabled);
}

void EventSourceCoordinator::addProtectedUiPid(int pid) {
    if (pid <= 0) return;
    protectedPids_.insert(pid);
    if (driver_) driver_->addProtectedPid(pid);
}

void EventSourceCoordinator::addBlockedIp(const QString& ip, quint16 port) {
    if (driver_) driver_->addBlockedIp(ip, port);
}

bool EventSourceCoordinator::blockModuleLoad(const QString& modulePath) {
    return driver_ ? driver_->blockModuleLoad(modulePath) : false;
}

void EventSourceCoordinator::onBaseEvent(const bulwark::SecurityEvent& e) {
    // 内核已接管进程事件时,丢弃基础源的进程创建/退出,避免与内核源重复上报。
    if (kernelConnected() &&
        (e.type == bulwark::EventType::ProcessCreate || e.type == bulwark::EventType::ProcessTerminate))
        return;
    emit eventProduced(e);
}

void EventSourceCoordinator::onDriverEvent(const bulwark::SecurityEvent& e) {
    emit eventProduced(e); // 裁决回写经 submitVerdict 直接路由到 driver_
}

void EventSourceCoordinator::onBehaviorEvent(const bulwark::SecurityEvent& e) {
    emit eventProduced(e);
}

} // namespace bulwark::service
