#pragma once
#include <QString>
#include <QJsonObject>

namespace bulwark {

// 运行时可调设置。UI 经 IPC 读取/更新,服务据此调整引擎与防护行为。
// 对应 .NET Models/RuntimeSettings.cs。
struct RuntimeSettings {
    bool protectionEnabled = true;

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

    bool aiScanDoubleClickEnabled = true;
    bool aiScanSuspendDuringScan = true;
    bool aiScanBlockOnFailure = false;

    // 威胁情报共享(默认关,须用户显式开启)。开启后:云查杀确认为恶意/可疑的样本,其
    // 「病毒信息 + 行为数据」在本机暂存,每天凌晨自动上传中央服务器,上传成功即删除本地暂存。
    // 只含哈希、判定、引擎计数、威胁名与沙箱行为 IOC(释放物名/哈希、注册表键、外联 IP/域名、
    // 服务名、互斥体);绝不含文件内容、本机文件路径、计算机名、用户名等任何个人隐私信息。
    // 关闭时立即清空本地暂存(用户撤回即刻生效,不留存已收集的数据)。
    bool cloudBehaviorUploadEnabled = false;

    QString aiBaseUrl;
    QString aiApiKey;
    QString aiModel;
    int aiScanScriptTextLimitKb = 12;
    int aiScanBinarySampleLimitMb = 4;
    int aiScanMaxStrings = 120;

    bool kernelDriverEnabled = false;
    bool userModeBehaviorMonitor = true;
    bool ransomwareCanaryEnabled = true;
    bool behaviorBaselineEnabled = true;
    bool aiGrayZoneConsultEnabled = false;

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
