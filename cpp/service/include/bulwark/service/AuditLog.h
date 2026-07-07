#pragma once
#include <QString>
#include <QJsonObject>
#include <QMutex>

namespace bulwark::service {

// 安全事件审计日志(落盘,与 UI 是否在线无关)。按天滚动到
// %ProgramData%\Bulwark\audit\audit-yyyyMMdd.jsonl(每行一条 JSON),带大小上限。
// 绝不抛出(审计失败不影响主防御流程)。对应 .NET Storage/AuditLog.cs。
class AuditLog {
public:
    AuditLog();
    void writeRecord(const QJsonObject& record);

private:
    QString currentFilePath();
    QString dir_;
    QMutex io_;
};

} // namespace bulwark::service
