#pragma once
#include <QDialog>

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/VtScanRecord.h"

class AiScanner;
class IpcClient;
class QLabel;
class QPlainTextEdit;
class QPushButton;

// "AI 智能清理" —— 从「云信誉详情」对某个判为恶意/可疑的文件发起:把该文件的行为画像
// (释放文件 / 外联 IP·域名 / 注册表 IOC + 结论)发送给大模型,由 AI 生成一份 PowerShell
// 清理方案,用户复核脚本内容后可一键(触发 UAC 提权)执行。清理逻辑走 UI 侧 AiScanner
// (与「设置」里的大模型接口/Key/模型同步),脚本执行前必须二次确认——绝不自动无声删除。
class AiCleanupDialog : public QDialog
{
    Q_OBJECT
public:
    AiCleanupDialog(const bulwark::VtScanRecord& record,
                    const bulwark::ipc::RemediationReportPayload& report,
                    IpcClient* ipc, AiScanner* ai, QWidget* parent = nullptr);

private:
    void startGeneration();
    void onScriptReady(const QString& script);
    void executeScript();

    IpcClient* m_ipc = nullptr;
    AiScanner* m_ai = nullptr;
    bulwark::ipc::RemediationReportPayload m_report;
    QString m_fileName;
    QString m_filePath;

    QLabel* m_status = nullptr;
    QPushButton* m_genBtn = nullptr;
    QPushButton* m_copyBtn = nullptr;
    QPushButton* m_runBtn = nullptr;
    QPlainTextEdit* m_scriptView = nullptr;
    bool m_awaiting = false;
};
