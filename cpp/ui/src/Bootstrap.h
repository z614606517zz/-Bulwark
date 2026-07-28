#pragma once
#include <QString>

class QWidget;

// 「双击即用」自举:UI 启动时负责把后台服务 + 内核驱动带起来,用户不必再手工
// sc create / sc start / fltmc load。
//
// 设计要点(尽量不打扰用户):
//   - 常态(服务已开机自启)下管道已通 -> 立刻返回,零 UAC、零等待;
//   - 只有在管道不通时才提权一次,跑 bulwark_service.exe --bootstrap 干脏活;
//   - 用户拒绝提权或自举失败都不阻塞 UI —— 界面照常打开,只是显示「未连接」,
//     符合「这是正经安全工具,永远留一条用户可控的退路」的原则。
namespace bulwark::ui::bootstrap {

// 后台服务的控制管道是否已可连接(即防护是否已在运行)。
bool backendReachable(int timeoutMs = 300);

// 确保后台服务 + 内核驱动已就绪。返回 true 表示管道已通。
// parent 仅用于失败提示框的父窗口(可为 nullptr)。
bool ensureBackendRunning(QWidget* parent = nullptr);

// UI 关闭时停止后台服务 + 卸载内核驱动(与 ensureBackendRunning 对应)。
// 静默执行,不弹提示框。返回 true 表示已执行停止操作。
bool shutdownBackend();

} // namespace bulwark::ui::bootstrap
