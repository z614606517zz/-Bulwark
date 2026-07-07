#pragma once
class QWidget;
class IpcClient;
namespace bulwark { struct VtScanRecord; }

// Factory functions for the card / form pages, bound to live service data via
// the shared IpcClient.
namespace pages {

QWidget* reputation(IpcClient* ipc); // 云信誉 — source status + hash query + VT history
QWidget* aiScan(IpcClient* ipc);     // AI 研判 — AI connection + scan stats + recent scans
QWidget* settings(IpcClient* ipc);   // 设置 — load/save RuntimeSettings toggles + AI connection

// 弹出云信誉行为关系图详情窗口(查毒命中后自动弹出)。autoCloseMs>0 时到时自动关闭。
void showVtDetailWindow(QWidget* parent, const bulwark::VtScanRecord& r, IpcClient* ipc, int autoCloseMs = 0);

} // namespace pages
