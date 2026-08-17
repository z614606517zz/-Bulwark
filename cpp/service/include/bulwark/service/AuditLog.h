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
    // 当前应写入的审计文件。结果带缓存,只在跨天或写满时重新解析 —— 见 .cpp 里的说明。
    QString currentFilePath();

    QString dir_;
    QMutex io_;

    // 解析结果缓存(全部由 io_ 保护)。cachedBytes_ 是本进程视角下当前文件的大小,
    // 每写成功一条就自增,避免为了知道「写满了没有」而每条事件都去 stat 一次。
    QString cachedDay_;    // 缓存对应的日期戳(yyyyMMdd),跨天即失效
    QString cachedPath_;   // 空 = 尚未解析过
    qint64  cachedBytes_ = 0;
};

} // namespace bulwark::service
