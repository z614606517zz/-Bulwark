#pragma once
#include <QList>
#include <QPair>
#include <QString>

namespace bulwark::service {

// 服务创建「真凶」追溯结果。
struct ServiceOriginator {
    int originatorPid = 0;                    // >0 = 高置信唯一发起者
    QString originatorPath;
    QList<QPair<int, QString>> candidates;    // 全部候选(展示/排障)
    bool highConfidence() const { return originatorPid > 0; }
};

// 服务创建「真凶」追溯器。创建服务经 RPC 交由 services.exe(SCM)代写注册表,内核回调
// 归因永远是 SCM 而非真实发起者。追溯思路:发起者用同步 RPC 调 SCM,其线程此刻阻塞在
// WrLpcReply;对全系统线程快照,找出「正等 LPC 回复、且非 SCM/系统/自身」的进程即候选;
// 恰好 1 个 -> 高置信发起者,否则仅收集候选、不指认(保守,绝不据此结束 services.exe)。
// 无需 ETW,纯 NtQuerySystemInformation 快照。对应 .NET Monitoring/ServiceControlTracer.cs。
namespace ServiceControlTracer {

// 目标是否为服务数据库键(...\CurrentControlSet\Services\... 等),仅此类写入才值得追溯。
bool isServiceDatabaseKey(const QString& targetPath);

// 给定内核归因到的 PID(应为 services.exe),追溯真正的 RPC 发起者。
ServiceOriginator trace(int scmPid);

} // namespace ServiceControlTracer

} // namespace bulwark::service
