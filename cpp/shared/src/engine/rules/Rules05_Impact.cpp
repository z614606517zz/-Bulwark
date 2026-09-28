//
// 段 5 · 勒索与破坏(T1490 / T1485 / T1561 / T1565 / T1222)
//
// 【分工】批量加密这件事本身由 RansomwareBehaviorMonitor 负责(蜜罐诱饵命中即无条件 Block,
// 批量改写按签名健康度抑制误报)。本段只管【勒索前置动作】—— 删卷影、删备份、关恢复、擦盘、
// 覆写引导扇区。这些动作的共同特征是:一旦成功就不可逆,而且正常软件没有理由做。所以这里
// 几乎全是 Block + hardOverride。
//
// 【刻意不写的东西】
//   · 勒索信文件名(*readme*.txt / *decrypt*):正常工程里 README 遍地,写了就是天天误报;
//   · 加密后缀(*.locked / *.encrypted):正常压缩与加密软件也产出这类后缀;
//   · shutdown /r 与 Restart-Computer:正常运维高频动作,没有互证条件时写了纯噪音。
// 这三类的检出交给 RansomwareBehaviorMonitor 的时序判据与蜜罐,那里有「批量」这个前提兜着。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addImpactRules(QVector<DefenseRule>& out) {
    Segment s(out, "勒索与破坏");

    // ------------------------------------------------------------------
    // 5.1 删除卷影副本(勒索最标准的前置动作)
    // ------------------------------------------------------------------
    s.proc(Block, "删除卷影副本(vssadmin delete shadows,毁掉本地恢复点,T1490)").hard()
        .actor("*\\vssadmin.exe").cmd("*delete*shadows*");
    // resize shadowstorage 到极小值会把已有快照挤掉,效果等同删除,是为了绕过只盯 delete 的检测。
    s.proc(Block, "压缩卷影存储空间以挤掉已有快照(vssadmin resize shadowstorage,T1490)").hard()
        .actor("*\\vssadmin.exe").cmd("*resize*shadowstorage*");
    s.proc(Block, "经 WMI 删除卷影副本(wmic shadowcopy delete,T1490)").hard()
        .actor("*\\wmic.exe").cmd("*shadowcopy*delete*");
    s.proc(Block, "经 PowerShell 删除卷影副本(Win32_Shadowcopy Delete,T1490)").hard()
        .cmd("*win32_shadowcopy*delete*");
    s.proc(Block, "经 PowerShell 删除卷影副本(Get-WmiObject ... Remove-WmiObject,T1490)").hard()
        .cmd("*shadowcopy*remove-wmiobject*");

    // ------------------------------------------------------------------
    // 5.2 删除系统备份 / 关闭恢复
    // ------------------------------------------------------------------
    s.proc(Block, "删除备份编录(wbadmin delete catalog,备份从此不可用,T1490)").hard()
        .actor("*\\wbadmin.exe").cmd("*delete*catalog*");
    s.proc(Block, "删除系统状态备份(wbadmin delete systemstatebackup,T1490)").hard()
        .actor("*\\wbadmin.exe").cmd("*delete*systemstatebackup*");
    s.proc(Block, "删除备份集(wbadmin delete backup,T1490)").hard()
        .actor("*\\wbadmin.exe").cmd("*delete*backup*");
    s.proc(Block, "关闭 Windows 恢复环境(bcdedit recoveryenabled no,T1490)").hard()
        .actor("*\\bcdedit.exe").cmd("*recoveryenabled*no*");
    s.proc(Block, "忽略引导失败以阻止自动修复(bcdedit bootstatuspolicy ignoreallfailures,T1490)").hard()
        .actor("*\\bcdedit.exe").cmd("*bootstatuspolicy*ignoreallfailures*");
    s.proc(Block, "删除系统还原点(Delete-ComputerRestorePoint / vssadmin,T1490)").hard()
        .cmd("*delete-computerrestorepoint*");
    s.proc(Ask, "重置 Windows 恢复分区配置(reagentc /disable,T1490)").cmd("*reagentc*/disable*");

    // ------------------------------------------------------------------
    // 5.3 擦除与磁盘破坏
    // ------------------------------------------------------------------
    // setzerodata 把文件区间置零 —— 这是 wiper 的实现方式,不是任何正常工具的用法。
    s.proc(Block, "将文件内容置零(fsutil file setzerodata,数据擦除,T1485)").hard()
        .cmd("*setzerodata*");
    // 【为什么只把 PhysicalDrive0 定为硬拦】裸盘设备名也出现在正常的 U 盘刻录 / 磁盘镜像工具
    // 命令行里,但那些工具操作的是 1/2 号盘;覆写引导扇区的 wiper 必须打 0 号盘(系统盘)。
    // 按盘号区分能同时留住检出与正常用途,比一刀切拦 "physicaldrive" 准得多。
    s.proc(Block, "直接写系统盘裸设备 PhysicalDrive0(覆写 MBR/引导扇区,T1561.002)").hard()
        .cmd("*physicaldrive0*");
    s.proc(Ask, "访问其它物理磁盘裸设备(镜像工具也用此形态,T1561)").cmd("*physicaldrive*");
    s.proc(Block, "经 dd/rawcopy 方式写裸卷设备(T1561.001)").hard()
        .cmd("*of=\\\\.\\*");
    s.proc(Ask, "调用 diskpart 脚本(可能清空分区表,T1561.002)").cmd("*diskpart*/s*");
    s.proc(Ask, "格式化卷(format /fs,T1485)").cmd("*format*/fs:*");
    s.proc(Ask, "清空卷(Clear-Disk / Format-Volume,T1485)").cmd("*clear-disk*");

    // ------------------------------------------------------------------
    // 5.4 备份文件与快照目录
    // ------------------------------------------------------------------
    s.del(Ask, "删除卷影/还原点存放目录内的项(T1490)").target("*\\System Volume Information\\*");
    static const char* kBackupExt[] = { "*.vhd", "*.vhdx", "*.vbk", "*.vib", "*.bak", "*.bkf", "*.tib" };
    for (const char* ext : kBackupExt) {
        const QString e = QString::fromUtf8(ext).mid(1);
        s.del(Ask, u("未签名程序删除备份文件 ") + e + u("(毁掉离线恢复手段,T1490)"))
            .target(ext).unsignedOnly();
    }
    // 数据库/虚拟机在线文件被未签名程序改写,是勒索加密整台宿主机的典型形态。
    static const char* kLiveData[] = { "*.vmdk", "*.vmx", "*.vdi", "*.mdf", "*.ldf", "*.edb" };
    for (const char* ext : kLiveData) {
        const QString e = QString::fromUtf8(ext).mid(1);
        s.file(Ask, u("未签名程序改写在线数据/虚拟机磁盘文件 ") + e + u("(T1486)"))
            .target(ext).unsignedOnly();
    }

    // ------------------------------------------------------------------
    // 5.5 篡改系统关键文件与权限
    // ------------------------------------------------------------------
    // hosts 在 ProtectedPaths 默认名单里,FileWrite 可靠。开发者与代理软件都会改它,故只 Ask;
    // 但脚本宿主改 hosts 基本只有两种目的:劫持安全软件的更新域名,或把 C2 域名指到本地。
    s.file(Ask, "修改 hosts 文件(可用于屏蔽安全软件更新域名,T1565.001)")
        .target("*\\drivers\\etc\\hosts");
    for (const QString& host : scriptHostActors())
        s.file(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 修改 hosts 文件(劫持域名解析,T1565.001)")).hard()
            .target("*\\drivers\\etc\\hosts").actor(host);
    // 替换 System32 里的可执行体。正常写入者只有 Windows 更新(段 1 已放行),未签名主体做这件事
    // 就是白加黑或系统二进制后门。
    s.file(Block, "未签名程序改写 System32 下的可执行文件(替换系统二进制,T1554)").hard()
        .target("*\\System32\\*.exe").unsignedOnly();
    s.file(Block, "未签名程序改写 System32 下的系统库(T1554)").hard()
        .target("*\\System32\\*.dll").unsignedOnly();
    s.proc(Ask, "递归接管系统目录所有权(takeown /f /r,为替换系统文件铺路,T1222.001)")
        .cmd("*takeown*/f*/r*");
    s.proc(Ask, "把系统对象权限开放给 Everyone(icacls grant everyone,T1222.001)")
        .cmd("*icacls*everyone*");
    s.proc(Ask, "递归修改目录权限(cacls/icacls /t /grant,T1222.001)").cmd("*icacls*/t*/grant*");

    // ------------------------------------------------------------------
    // 5.6 服务与启动破坏
    // ------------------------------------------------------------------
    s.del(Block, "未签名程序删除内核驱动文件(摘掉安全驱动或系统组件,T1485)").hard()
        .target("*\\System32\\drivers\\*.sys").unsignedOnly();
    s.proc(Ask, "禁用大批服务的启动类型(sc config start= disabled,T1489)")
        .cmd("*config*start=*disabled*");
    s.proc(Ask, "结束数据库/邮件等业务进程以便加密其文件(T1489)").cmd("*net*stop*sql*");
    s.proc(Ask, "结束 Exchange/Oracle 等业务服务以便加密其文件(T1489)").cmd("*net*stop*msexchange*");
}

} // namespace bulwark::engine::rules
