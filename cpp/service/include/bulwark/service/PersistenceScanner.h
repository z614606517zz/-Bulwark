#pragma once
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

// 自启动持久化点枚举器(只读审计)。枚举系统常见自启动位置,逐项交 PersistenceAnalyzer
// 打分 + ATT&CK 标注,产出供 UI 展示的清单。覆盖:注册表 Run/RunOnce(HKLM+HKCU,64/32
// 视图)、启动文件夹、Windows 服务、映像劫持(IFEO Debugger)、Winlogon(Userinit/Shell)、
// AppInit_DLLs、计划任务(读 Tasks XML)。
//
// 纯只读:绝不修改任何自启动项;失败的源静默跳过并在 message 汇总,透明而非假装完整。
// 对应 .NET Bulwark.Service/Monitoring/PersistenceScanner.cs。
struct PersistenceScanner {
    static bulwark::ipc::PersistenceListResponsePayload scan();
};

} // namespace bulwark::service
