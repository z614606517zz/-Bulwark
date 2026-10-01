#pragma once
#include <QString>
#include <QJsonObject>

namespace bulwark {

// 运行时可调设置。UI 经 IPC 读取/更新,服务据此调整引擎与防护行为。
// 对应 .NET Models/RuntimeSettings.cs。
struct RuntimeSettings {
    bool protectionEnabled = true;

    // 「退出界面即停止防护」——【默认关】,即防护常驻。
    //
    // 开启后语义变成:防护只在 bulwark_ui.exe 在跑的时候生效(最小化到托盘算在跑)。界面一退出,
    // 服务就地进入待机:停事件处理与处置、停 ETW 会话与诱饵、停兜底扫描、放开用户态独占句柄、
    // 清掉 WFP 出站封禁,并【卸载内核驱动】—— 内核那套「自足基线」(禁止执行 / 命令行硬拦 /
    // 已知恶意哈希)正是驱动在载时才生效的,所以只有把驱动卸掉才算真的停干净。界面再打开则整套回来。
    //
    // 【必须知道的代价,不要把这个开关当成纯便利项】
    //   · 界面没在跑的时段主机完全不受本软件保护:开机到登录之间、注销之后、界面崩了或被结束之后。
    //   · 于是「结束 bulwark_ui.exe」这一下就成了关闭整套防护的手段。驱动在载时内核自保护会护住
    //     已登记的 UI 进程(BLW_CMD_ADD_PID),但那层保护本身也随驱动卸载而消失 —— 待机期间没有它。
    //   · 待机【不回滚已经落地的东西】:此前给恶意文件加的「拒绝执行」ACE、已隔离的文件、
    //     已写进内核注册表基线的条目都保持原样(基线要等驱动下次加载才重新生效)。
    // 服务进程本身仍然常驻(不然界面下次打开就得再弹一次 UAC 才能把服务拉起来),但它在待机期间
    // 不做任何监控与处置。
    bool protectionFollowsUi = false;

    bool processProtection = true;
    bool fileProtection = true;
    bool registryProtection = true;
    bool selfProtection = true;
    bool networkProtection = true;

    bool memoryProtectionEnabled = true;
    bool memoryProtectionVtVerifyEnabled = true;

    bool trustSignedActors = true;
    bool defaultBlock = false;
    bool silentMode = false;

    // 攻击链命中的右下角通知。【独立于 silentMode】,默认开。
    //
    // 为什么要独立:静默模式的语义是「不要为决策打扰我」,它把询问降级成放行 —— 于是造出一个
    // 盲区:攻击链凑齐了 N 个动作、有真实样本作证,却被静默放行而用户毫不知情。这条通知不带
    // 处置按钮、自动消失、不抢焦点,是告知而非提问,不该被静默模式吞掉。
    // 但仍然留一个独立开关 —— 产品原则是尽量少打扰,一个完全关不掉的弹窗不可接受。
    bool attackChainToast = true;
    int  promptTimeoutSeconds = 30;

    bool virusTotalEnabled = false;
    bool malwareBazaarEnabled = false;
    bool otxEnabled = false;
    bool threatBookEnabled = false;
    bool threatBookNetworkIntelEnabled = false;
    bool metaDefenderEnabled = false;
    bool hybridAnalysisEnabled = false;

    // 各情报源 API Key(UI 可配置)。空 -> 服务端沿用 appsettings.json / 内置默认。
    QString virusTotalApiKey;
    QString malwareBazaarApiKey;
    QString otxApiKey;
    QString threatBookApiKey;
    QString metaDefenderApiKey;
    QString hybridAnalysisApiKey;

    // 双击云查杀 / 查杀期间挂起目标进程(VirusTotal / 中央服务器链路,与大模型无关)。
    // 名字里的 ai 是历史遗留;为保持 settings.json 与 IPC 线格式兼容,不改名。
    bool aiScanDoubleClickEnabled = true;
    bool aiScanSuspendDuringScan = true;

    // 威胁情报共享(默认关,须用户显式开启)。开启后:云查杀确认为恶意/可疑的样本,其
    // 「病毒信息 + 行为数据」在本机暂存,每天凌晨自动上传中央服务器,上传成功即删除本地暂存。
    // 只含哈希、判定、引擎计数、威胁名与沙箱行为 IOC(释放物名/哈希、注册表键、外联 IP/域名、
    // 服务名、互斥体);绝不含文件内容、本机文件路径、计算机名、用户名等任何个人隐私信息。
    // 关闭时立即清空本地暂存(用户撤回即刻生效,不留存已收集的数据)。
    bool cloudBehaviorUploadEnabled = false;

    // 大模型接口(UI 侧的「AI 生成规则」「AI 清理」与行为询问弹窗的「AI 解读」共用)。
    // 「AI 解读」自己的开关不在这里:它是纯界面行为,存当前 Windows 用户的 QSettings(见 AiScanner)。
    QString aiBaseUrl;
    QString aiApiKey;
    QString aiModel;

    bool kernelDriverEnabled = false;
    bool userModeBehaviorMonitor = true;
    bool ransomwareCanaryEnabled = true;
    bool behaviorBaselineEnabled = true;

    bool aiCreditGuardEnabled = true;
    qint64 aiMonthlyCreditBudget = 4100000000LL;

    QString eventSource = QStringLiteral("Wmi");
    bool kernelConnected = false;
    QString kernelStatus;

    // 【只读状态位,服务 -> UI】部署方在 appsettings 里选择了「本机不动用任何第三方情报源」
    //(ReputationProxy.ServerOnly):云端只向中央服务器查「这个哈希收录了吗」。为真时上面那六个
    // 情报源开关与 API Key 在服务端一律按关处理,UI 据此把它们禁掉并说明原因 —— 否则那些开关
    // 看着可点、点了却毫无效果,正是最难排查的一类「设置不生效」。UI 回传的值一律被服务忽略。
    bool cloudServerOnly = false;

    bool quarantineOnBlock = false;

    bool anyReputationEnabled() const {
        return virusTotalEnabled || malwareBazaarEnabled || otxEnabled ||
               threatBookEnabled || metaDefenderEnabled || hybridAnalysisEnabled;
    }
    bool aiConfigured() const { return !aiApiKey.trimmed().isEmpty(); }

    RuntimeSettings clone() const { return *this; }

    QJsonObject toJson() const;
    static RuntimeSettings fromJson(const QJsonObject& o);
};

} // namespace bulwark
