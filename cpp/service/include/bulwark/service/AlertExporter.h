#pragma once
#include <QString>
#include <QMutex>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"

namespace bulwark::service {

// ECS 告警导出器:把事件+裁决渲染为 Elastic Common Schema JSON-lines,追加写入
// %ProgramData%\Bulwark\alerts\alerts-yyyyMMdd.jsonl(供 SIEM 采集)。默认关闭。
// 对应 .NET Storage/AlertExporter.cs。
class AlertExporter {
public:
    explicit AlertExporter(bool enabled);
    void exportAlert(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);

private:
    QString currentFilePath();
    bool enabled_;
    QString dir_;
    QMutex io_;
};

} // namespace bulwark::service
