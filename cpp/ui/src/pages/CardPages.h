#pragma once
class QWidget;
class IpcClient;
namespace bulwark { struct VtScanRecord; }

// Factory functions for the settings / intelligence pages, bound to live
// service data via the shared IpcClient. One file each under pages/.
namespace pages {

QWidget* reputation(IpcClient* ipc); // 云信誉 — query a file (drop / path / SHA-256) + cloud-scan records
QWidget* aiScan(IpcClient* ipc);     // AI 研判 — model status + manual research + records
QWidget* settings(IpcClient* ipc);   // 设置 — two columns: categories | sections; changes apply immediately

// 弹出云信誉行为关系图详情窗口(查毒命中后自动弹出)。autoCloseMs>0 时到时自动关闭。
void showVtDetailWindow(QWidget* parent, const bulwark::VtScanRecord& r, IpcClient* ipc, int autoCloseMs = 0);

} // namespace pages
