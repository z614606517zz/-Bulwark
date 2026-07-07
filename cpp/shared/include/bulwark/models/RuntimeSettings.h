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
