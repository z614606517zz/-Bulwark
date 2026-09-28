#pragma once
#include "design/Sheet.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/VtScanRecord.h"

class AiScanner;
class IpcClient;
class QCheckBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class Stepper;

// 「AI 智能清理」 — a three-step wizard, started from the cloud-reputation detail
// or the cleanup report for a file judged malicious / suspicious:
//
//   ① 行为画像   what is known about the sample (IOC counts; expand for items)
//   ② 生成方案   the model writes a PowerShell cleanup script (monospace, copyable)
//   ③ 执行       tick 「我已复核脚本」, then 「以管理员身份执行」 (UAC, visible window)
//
// The model only ever sees the behaviour profile (never the file). Nothing runs
// without the user reviewing and explicitly confirming — no silent deletion. This
// is the single script runner in the product (the cleanup report hands over to
// it): elevated via UAC, script written with a UTF-8 BOM so Chinese output reads.
class AiCleanupDialog : public Sheet
{
    Q_OBJECT
public:
    AiCleanupDialog(const bulwark::VtScanRecord& record,
                    const bulwark::ipc::RemediationReportPayload& report,
                    IpcClient* ipc, AiScanner* ai, QWidget* parent = nullptr);

private:
    QWidget* buildProfile(const bulwark::VtScanRecord& record);
    QWidget* buildScript();
    QWidget* buildRun();
    void goTo(int step);
    void syncNav();
    void startGeneration();
    void onScriptReady(const QString& script);
    void executeScript();

    IpcClient* m_ipc = nullptr;
    AiScanner* m_ai = nullptr;
    bulwark::ipc::RemediationReportPayload m_report;
    QString m_fileName;
    QString m_filePath;

    Stepper* m_steps = nullptr;
    QStackedWidget* m_pages = nullptr;
    QPushButton* m_back = nullptr;
    QPushButton* m_next = nullptr;
    QLabel* m_genStatus = nullptr;
    QPushButton* m_regen = nullptr;
    QPushButton* m_copy = nullptr;
    QPlainTextEdit* m_scriptView = nullptr;
    QCheckBox* m_ack = nullptr;
    QLabel* m_runStatus = nullptr;
    int m_step = 0;
    bool m_awaiting = false;
    bool m_hasScript = false;
    bool m_launched = false;
};
