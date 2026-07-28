#pragma once
#include <QList>
#include <QString>
#include <functional>
#include "bulwark/models/ProcessEntry.h"

// 在跑进程快照:进程管理页的数据源。
//
// 与「活动日志 / 拦截记录」互补 —— 日志说的是【发生过什么】,这里说的是【现在还有什么在跑】。
// 一次快照把定性所需的取证事实一次性凑齐:签名与发布者、映像路径与命令行、启动时间与内存、
// 会话与提权、以及最关键的启动来源(具体服务名 / 具体计划任务名,见 ProcessOriginResolver)。
//
// 只读:本类不做任何处置,连「建议处置」都不给。风险分与原因是纯静态提示(未签名、跑在用户
// 可写目录、伪装系统进程名…),按产品原则,这类软信号只用于排序与着色,绝不触发任何自动动作;
// 结束进程永远只由用户在 UI 上显式点击触发。
//
// 性能:首次快照要对每个映像验签(WinVerifyTrust),几百个进程可能耗时数秒,故【必须在后台
// 线程调用】,不要在 IPC / 事件裁决线程上直接调。ProcessInspector 按「路径|大小|修改时间」
// 缓存验签结果,所以后续刷新是毫秒级的。
namespace bulwark::service::monitoring {

class ProcessEnumerator {
public:
    struct Options {
        bool includeCommandLine = true; // 读 PEB 命令行(需要权限,略慢)
        bool resolveOrigin = true;      // 解析启动来源(服务 / 计划任务)
        bool verifySignature = true;    // 验签 + 取发布者(首次较慢,之后走缓存)
    };

    // isProtectedSelf:PID 是否本软件受保护组件(服务 / UI 自身),由宿主注入 —— 自我保护
    //                  必须由知道真实 PID 的一方判断,枚举器不自作聪明。
    // isTrustedImage:映像是否已命中用户信任名单,由宿主(引擎)注入。
    // 两个谓词都可为空,为空即该标记恒为 false。
    static QList<bulwark::ProcessEntry> snapshot(
        const Options& opt = Options{},
        const std::function<bool(int)>& isProtectedSelf = nullptr,
        const std::function<bool(const QString&)>& isTrustedImage = nullptr);
};

} // namespace bulwark::service::monitoring
