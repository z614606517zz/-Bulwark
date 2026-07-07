#include "bulwark/engine/AttackCatalog.h"
#include <QHash>

namespace bulwark::engine {

namespace {
const QHash<QString, AttackCatalog::Technique>& catalog() {
    static const QHash<QString, AttackCatalog::Technique> m = [] {
        QHash<QString, AttackCatalog::Technique> t;
        auto A = [&](const char* id, const char* name, const char* tactic) {
            t.insert(QString::fromLatin1(id),
                     { QString::fromLatin1(id), QString::fromUtf8(name), QString::fromUtf8(tactic) });
        };
        // 执行
        A("T1059.001", "PowerShell", "执行");
        A("T1047", "WMI", "执行");
        A("T1202", "间接命令执行", "执行");
        A("T1204", "用户执行", "执行");
        // 防御规避
        A("T1027", "混淆文件或信息", "防御规避");
        A("T1140", "去混淆/解码文件", "防御规避");
        A("T1197", "BITS 任务", "防御规避");
        A("T1220", "XSL 脚本处理", "防御规避");
        A("T1036.005", "伪装为合法名称/位置", "防御规避");
        A("T1036.007", "双重文件扩展名", "防御规避");
        A("T1564.004", "NTFS 备用数据流", "防御规避");
        A("T1218", "系统二进制代理执行", "防御规避");
        A("T1218.004", "InstallUtil 代理执行", "防御规避");
        A("T1218.005", "Mshta 代理执行", "防御规避");
        A("T1218.007", "Msiexec 代理执行", "防御规避");
        A("T1218.009", "Regsvcs/Regasm 代理执行", "防御规避");
        A("T1218.010", "Regsvr32 代理执行(Squiblydoo)", "防御规避");
        A("T1218.011", "Rundll32 代理执行", "防御规避");
        A("T1218.013", "Mavinject 代理执行", "防御规避");
        A("T1127.001", "MSBuild 可信工具代理执行", "防御规避");
        // 凭据访问
        A("T1003", "操作系统凭据转储", "凭据访问");
        A("T1003.001", "LSASS 内存转储", "凭据访问");
        A("T1003.002", "SAM 数据库(本地账户哈希)", "凭据访问");
        A("T1003.003", "NTDS 域控凭据库", "凭据访问");
        A("T1555.003", "浏览器存储凭据", "凭据访问");
        A("T1555.004", "Windows 凭据保管库", "凭据访问");
        // 命令与控制
        A("T1105", "工具传输/下载执行", "命令控制");
        A("T1071", "应用层协议外联", "命令控制");
        // 影响
        A("T1490", "抑制系统恢复(删卷影/备份)", "破坏影响");
        A("T1486", "数据加密勒索", "破坏影响");
        // 持久化
        A("T1547.001", "注册表 Run 键/启动文件夹", "持久化");
        A("T1547.004", "Winlogon 助手 DLL/Shell", "持久化");
        A("T1546.003", "WMI 事件订阅", "持久化");
        A("T1546.010", "AppInit_DLLs", "持久化");
        A("T1546.012", "映像劫持(IFEO Debugger)", "持久化");
        A("T1543.003", "Windows 服务", "持久化");
        A("T1053", "计划任务", "持久化");
        A("T1053.005", "计划任务(schtasks)", "持久化");
        // 进程注入
        A("T1055", "进程注入", "进程注入");
        return t;
    }();
    return m;
}
} // namespace

std::optional<AttackCatalog::Technique> AttackCatalog::lookup(const QString& id) {
    if (id.trimmed().isEmpty()) return std::nullopt;
    const QString key = id.toUpper();
    auto it = catalog().constFind(key);
    if (it != catalog().constEnd()) return it.value();

    const int dot = key.indexOf(QLatin1Char('.'));
    if (dot > 0) {
        auto pit = catalog().constFind(key.left(dot));
        if (pit != catalog().constEnd()) return pit.value();
    }
    return std::nullopt;
}

QString AttackCatalog::describe(const QString& id) {
    const auto t = lookup(id);
    return t.has_value() ? (id + QLatin1Char(' ') + t->name) : id;
}

} // namespace bulwark::engine
