#pragma once
class QWidget;
class IpcClient;

// Factory functions for the list pages. Each returns a ready page widget bound
// to live service data via the shared IpcClient: it requests its data on
// connect (and on the page's own refresh action) and repopulates from the
// matching IpcClient signal. Mutations (add / delete / restore …) are echoed
// back by the service as a fresh snapshot, and each page reports an outcome only
// once that snapshot (or the service's receipt) confirms it.
//
// Every page is a record list + inspector (design/ListShell.h); one file each
// under pages/. The header actions travel with the page (ui::setPageActions).
namespace pages {

// 事件记录 — all security events (block / ask / allow) with segments; these two
// entry points build the same page, differing only in the default segment when
// the user hasn't picked one yet (拦截 / 全部).
QWidget* interceptions(IpcClient* ipc);
QWidget* activity(IpcClient* ipc);
QWidget* timeline(IpcClient* ipc);      // 事件时间线 — 按时间窗 / 进程回溯历史 + 攻击图入口
QWidget* processes(IpcClient* ipc);     // 进程管理 — 在跑进程快照(含服务/计划任务溯源)+ 用户主动处置
QWidget* rules(IpcClient* ipc);         // 防护规则 — allow / block policy, intel / AI adoption
QWidget* trust(IpcClient* ipc);         // 信任名单 — trusted programs & folders
QWidget* quarantine(IpcClient* ipc);    // 隔离区 — quarantined threat files
QWidget* persistence(IpcClient* ipc);   // 自启动项 — autostart persistence audit + cleanup
QWidget* attackChain(IpcClient* ipc);   // 攻击链 — 组合表状态 + 命中记录(跨事件,故独立于事件记录页)

} // namespace pages
