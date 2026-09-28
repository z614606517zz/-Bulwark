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

// 登记「登录时自动启动托盘界面」(HKCU\...\CurrentVersion\Run,键名 Bulwark)。
//
// 为什么需要:后台服务是 SERVICE_AUTO_START,重启后防护本身会自己回来,但【界面不会】。
// 于是用户重启后看不到托盘图标、收不到行为提示弹窗,自然认为"防护失效了",只能手工再打开
// 一次 —— 这正是「重启就失效要重新打开」里用户实际感受到的那一半。
//
// 刻意用 HKCU 而不是 HKLM:
//   · 不需要管理员权限,UI 以普通用户运行就能写;
//   · 它会出现在「任务管理器 > 启动应用」里,用户可以自己一键禁用 ——
//     符合「这是正经安全工具,永远留一条用户可控的退路」的原则,不是偷偷扎根。
// 幂等:值一致时一个字节都不写(避免无谓的注册表写入,也避免触发自身的自启动项监控)。
// 返回 true 表示登记项已就位。
bool ensureUiAutoStart();

// 确保后台服务 + 内核驱动已就绪。返回 true 表示管道已通。
// parent 仅用于失败提示框的父窗口(可为 nullptr)。
bool ensureBackendRunning(QWidget* parent = nullptr);

// 【已移除 shutdownBackend()】它原本在 UI 退出时 stop BulwarkService + unload 驱动,
// 于是"关掉界面"等于"关掉防护"—— 这正是「服务无法常驻、重启就失效」的直接原因。
// 防护是后台常驻服务,生命周期不该跟前台界面绑定;这里刻意不再提供这个入口,免得
// 以后又被接回去。要停用防护有两条正当路径:界面「设置」里的防护总开关(可撤销),
// 或 `bulwark_service.exe --uninstall` 彻底卸载。

} // namespace bulwark::ui::bootstrap
