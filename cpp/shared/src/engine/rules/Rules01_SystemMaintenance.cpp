//
// 段 1 · 系统维护放行
//
// 只做一件事:抵消本库后续各段对 Windows 自身维护动作的【已知】误报。没有规则命中时,
// 签名健康的程序本来就会在步骤 9 被放行,所以这里不放行「一大类软件」—— 旧规则集里
// *\svchost.exe 这种仅文件名的 Allow,等于放行任何改名成 svchost.exe 的样本。
//
// 每条 Allow 同时满足:主体路径卷根锚定到 Windows 自己的位置 + requireSigned +
// 只覆盖本库确实会误伤的那几个事件维度。事件已带硬指标时内置 Allow 不生效
// (RuleEngine 步骤 6「只加强、不削弱」),不会替被劫持的系统进程挡掉启发式处置。
//
#include "RuleDsl.h"

namespace bulwark::engine::rules {

void addSystemMaintenanceRules(QVector<DefenseRule>& out) {
    Segment s(out, "系统维护");

    // Windows 模块安装程序(Windows Update):改服务键、IFEO 缓解选项、替换系统文件。
    const char* kTi  = "?:\\Windows\\servicing\\TrustedInstaller.exe";
    const char* kTiW = "?:\\Windows\\WinSxS\\*\\TiWorker.exe";
    s.reg(Allow, "TrustedInstaller 维护系统注册表(Windows 更新)").actor(kTi).signedOnly();
    s.file(Allow, "TrustedInstaller 维护系统文件(Windows 更新)").actor(kTi).signedOnly();
    s.del(Allow, "TrustedInstaller 清理系统文件(Windows 更新)").actor(kTi).signedOnly();
    s.reg(Allow, "TiWorker 维护系统注册表(Windows 更新)").actor(kTiW).signedOnly();
    s.file(Allow, "TiWorker 维护系统文件(Windows 更新)").actor(kTiW).signedOnly();
    s.del(Allow, "TiWorker 清理系统文件(Windows 更新)").actor(kTiW).signedOnly();

    // Defender 平台自更新:改写自身服务键。
    // 【刻意不放行】Defender 的 Exclusions / 策略键:Add-MpPreference 的写入主体正是 MsMpEng,
    // 放行它等于放行「给 Defender 加排除项」这一最常见的免杀动作(见段 3)。
    const char* kMpEng = "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe";
    s.reg(Allow, "Defender 平台自更新改写 WinDefend 服务配置")
        .actor(kMpEng).target("*\\Services\\WinDefend\\*").signedOnly();
    s.reg(Allow, "Defender 平台自更新改写 WdFilter/WdBoot/WdNisDrv 驱动配置")
        .actor(kMpEng).target("*\\Services\\Wd*").signedOnly();

    // Windows 更新编排器 / 设置同步:按计划改写 Run 与服务启动类型。
    s.reg(Allow, "更新编排器维护服务启动配置")
        .actor("?:\\Windows\\System32\\MoUsoCoreWorker.exe").target("*\\Services\\*").signedOnly();
    s.reg(Allow, "OneDrive 安装器维护自身开机项")
        .actor("?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\\OneDriveSetup.exe")
        .target("*\\CurrentVersion\\Run\\OneDrive*").signedOnly();
    s.reg(Allow, "OneDrive 维护自身开机项")
        .actor("?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
        .target("*\\CurrentVersion\\Run\\OneDrive*").signedOnly();
    s.reg(Allow, "OneDrive(全机安装)维护自身开机项")
        .actor("?:\\Program Files*\\Microsoft OneDrive\\*OneDrive*.exe")
        .target("*\\CurrentVersion\\Run\\OneDrive*").signedOnly();

    // 计划任务服务把任务定义落盘到 \System32\Tasks\(注册计划任务时的正常写入者就是它)。
    // 真正的「谁创建了任务」由段 2 的 schtasks / 任务 XML 规则按发起方判,不在这一层。
    s.file(Allow, "任务计划程序服务写入任务定义")
        .actor("?:\\Windows\\System32\\svchost.exe").target("*\\Windows\\System32\\Tasks\\*")
        .parent("?:\\Windows\\System32\\services.exe").signedOnly();

    // Windows 自带的系统还原 / 卷影维护(按计划删除过期还原点)。
    s.del(Allow, "卷影复制服务清理过期快照")
        .actor("?:\\Windows\\System32\\VSSVC.exe").signedOnly();
    s.del(Allow, "系统还原服务清理过期还原点")
        .actor("?:\\Windows\\System32\\srtasks.exe").signedOnly();
}

} // namespace bulwark::engine::rules
