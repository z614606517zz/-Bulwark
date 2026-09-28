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

QStringList EventSourceCoordinator::kernelMissingCapabilities() const {
    return driver_ ? driver_->missingCapabilities() : QStringList{};
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
        // 内存防护状态必须在 start() 【之前】补给内核源:start() 内的 pushInitialConfig 会调
        // initMemoryProtection,那时才读这个标志。放到 start() 之后就会先按默认(开)登记一遍,
        // 用户明明关着开关却仍被登记一次。
        driver_->setMemoryProtectionEnabled(memProtEnabled_);
        driver_->start();                  // 连接 + 握手(同步)
        for (int pid : protectedPids_)     // 补发受保护 UI PID
            driver_->addProtectedPid(pid);
        // 无论首次是否连上,都把看护定时器开起来(见 onKernelRetry 的说明):
        // 连上了它负责发现"中途掉线",没连上它负责持续重试。
        kernelRetry_->start();
        if (driver_->isAvailable()) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动事件源已连接(行为前拦截 + 用户态补偿)。"));
        } else {
            attachFailed_ = true;
            log_.warning(QStringLiteral("内核驱动暂不可用,已降级为用户态观测,后台将持续重试。"));
        }
    } else {
        kernelRetry_->stop();
        attachFailed_ = false;
        if (driver_) driver_->stop();      // 释放通信端口(便于驱动卸载/重启)
        log_.info(QStringLiteral("内核驱动事件源已停用(切回用户态观测)。"));
    }
}

// 内核连接看护。
//
// 【原实现连上就把定时器停了】—— 只能自愈"启动时没连上"这一种情况。一旦驱动在运行期间掉了
// (被 fltmc unload、被升级脚本卸载、驱动自身重载、或外部工具卸载),就再也没有人发现:
// 服务还活着、界面还显示"防护开启",但内核前置拦截已经没了,而且要等到下次重启服务才恢复。
// 这是「防护静默失效」——比服务直接挂掉更难察觉。
// 现在只要启用了内核驱动,这个定时器就一直跑;已连上时每轮只做一次极轻的句柄检查。
void EventSourceCoordinator::onKernelRetry() {
    if (!kernelEnabled_ || !driver_) { kernelRetry_->stop(); return; }
    if (driver_->isAvailable()) {
        // 连接正常:清掉失败标记但【不停表】,继续看护掉线。
        if (attachFailed_) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动连接已恢复。"));
        }
        return;
    }
    // 走到这里说明「本该有内核却没有」:要么从没连上,要么中途掉了。两种都按同一条路自愈。
    if (!attachFailed_) {
        attachFailed_ = true;
        log_.warning(QStringLiteral("内核驱动连接已断开(驱动被卸载或重载),正在尝试重新加载并接回。"));
    }
    DriverControl::ensureLoaded();
    driver_->setMemoryProtectionEnabled(memProtEnabled_); // 同上:必须早于 start()
    driver_->start();
    if (driver_->isAvailable()) {
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

void EventSourceCoordinator::setMemoryProtectionEnabled(bool on) {
    memProtEnabled_ = on;   // 记住:内核源可能还没创建(懒创建),届时由 setKernelEnabled 补发
    if (driver_)
        driver_->setMemoryProtectionEnabled(on);
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

bool EventSourceCoordinator::blockExecPath(const QString& imagePath) {
    return driver_ ? driver_->blockExecPath(imagePath) : false;
}

bool EventSourceCoordinator::clearExecBlock() {
    return driver_ ? driver_->clearExecBlock() : false;
}

bool EventSourceCoordinator::clearModuleNoLoad() {
    return driver_ ? driver_->clearModuleNoLoad() : false;
}

bool EventSourceCoordinator::clearBannedProcesses() {
    return driver_ ? driver_->clearBannedProcesses() : false;
}

QStringList EventSourceCoordinator::persistedExecBlockList() const {
    return driver_ ? driver_->persistedExecBlockList() : QStringList{};
}

QStringList EventSourceCoordinator::persistedModuleNoLoadList() const {
    return driver_ ? driver_->persistedModuleNoLoadList() : QStringList{};
}

bool EventSourceCoordinator::hardenRegistryKey(const QString& keyOrValue) {
    return driver_ ? driver_->hardenRegistryKey(keyOrValue) : false;
}

bool EventSourceCoordinator::readLockedFile(const QString& path, QByteArray& out) {
    return driver_ ? driver_->readLockedFile(path, out) : false;
}

bool EventSourceCoordinator::forceDeleteFile(const QString& path) {
    return driver_ ? driver_->forceDeleteFile(path) : false;
}

bool EventSourceCoordinator::killProcess(int pid) {
    return driver_ ? driver_->killProcess(pid) : false;
}

bool EventSourceCoordinator::banProcess(int pid) {
    return driver_ ? driver_->banProcess(pid) : false;
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
