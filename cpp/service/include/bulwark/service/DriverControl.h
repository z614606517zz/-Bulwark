#pragma once
#include <QString>

namespace bulwark::service {

// 内核驱动(Bulwark.sys,minifilter,服务名 "Bulwark")按需注册 / 加载 / 卸载。
// 忠实移植 .NET Bulwark.Service/Monitoring/DriverService.cs:
//   - 驱动为 minifilter(type=filesys,依赖 FltMgr),demand 启动:开机不常驻,
//     由服务在「启用内核驱动」时主动加载、停用时卸载;
//   - 若内核服务尚未注册(sc query 返回 1060),自动 sc create + 写
//     Instances/DefaultInstance + <实例>\Altitude/Flags 注册表后再加载;
//   - 优先 fltmc load(minifilter 规范加载方式),失败回退 sc start。
//
// 全程经 sc.exe / fltmc.exe / reg.exe(QProcess)驱动,失败不抛出——降级为
// 用户态观测。注意:注册 / 加载内核驱动需管理员权限 + 测试签名模式(开发期
// `bcdedit /set testsigning on`);正式发布需 EV 证书 + WHQL/附件签名。
class DriverControl {
public:
    // 加载(必要时先注册)内核驱动。已在运行则直接成功。
    static bool ensureLoaded();

    // 卸载(停止)内核驱动。
    static bool tryStop();

    // 驱动服务当前是否在运行(sc query 输出含 RUNNING)。
    static bool isRunning();

    // 定位 Bulwark.sys:System32\drivers 优先,其次 C:\BulwarkDrv,再次可执行文件旁。
    // 找不到返回空串。
    static QString locateSys();
};

} // namespace bulwark::service
