#pragma once
class QWidget;
class IpcClient;

// Factory functions for the list/table management pages. Each returns a ready
// page widget bound to live service data via the shared IpcClient: it requests
// its data on connect + on a manual refresh, and repopulates from the matching
// IpcClient signal. Mutations (add/delete/restore) are echoed back by the
// service as a fresh snapshot, so the table stays consistent automatically.
namespace pages {

QWidget* interceptions(IpcClient* ipc); // 拦截记录 — blocked malicious behaviour (event-log fed)
QWidget* activity(IpcClient* ipc);      // 活动日志 — all structured security events (event-log fed)
QWidget* rules(IpcClient* ipc);         // 防护规则 — allow / block policy
QWidget* trust(IpcClient* ipc);         // 信任名单 — trusted programs & directories
QWidget* quarantine(IpcClient* ipc);    // 隔离区 — quarantined threat files
QWidget* persistence(IpcClient* ipc);   // 自启动项 — autostart persistence audit

} // namespace pages
