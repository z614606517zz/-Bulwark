#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject RuntimeSettings::toJson() const {
    QJsonObject o;
    o["protectionEnabled"] = protectionEnabled;
    o["protectionFollowsUi"] = protectionFollowsUi;

    o["processProtection"] = processProtection;
    o["fileProtection"] = fileProtection;
    o["registryProtection"] = registryProtection;
    o["selfProtection"] = selfProtection;
    o["networkProtection"] = networkProtection;

    o["memoryProtectionEnabled"] = memoryProtectionEnabled;
    o["memoryProtectionVtVerifyEnabled"] = memoryProtectionVtVerifyEnabled;

    o["trustSignedActors"] = trustSignedActors;
    o["defaultBlock"] = defaultBlock;
    o["silentMode"] = silentMode;
    o["attackChainToast"] = attackChainToast;
    o["promptTimeoutSeconds"] = promptTimeoutSeconds;

    o["virusTotalEnabled"] = virusTotalEnabled;
    o["malwareBazaarEnabled"] = malwareBazaarEnabled;
    o["otxEnabled"] = otxEnabled;
    o["threatBookEnabled"] = threatBookEnabled;
    o["threatBookNetworkIntelEnabled"] = threatBookNetworkIntelEnabled;
    o["metaDefenderEnabled"] = metaDefenderEnabled;
    o["hybridAnalysisEnabled"] = hybridAnalysisEnabled;

    o["virusTotalApiKey"] = virusTotalApiKey;
    o["malwareBazaarApiKey"] = malwareBazaarApiKey;
    o["otxApiKey"] = otxApiKey;
    o["threatBookApiKey"] = threatBookApiKey;
    o["metaDefenderApiKey"] = metaDefenderApiKey;
    o["hybridAnalysisApiKey"] = hybridAnalysisApiKey;

    o["aiScanDoubleClickEnabled"] = aiScanDoubleClickEnabled;
    o["aiScanSuspendDuringScan"] = aiScanSuspendDuringScan;
    o["cloudBehaviorUploadEnabled"] = cloudBehaviorUploadEnabled;

    o["aiBaseUrl"] = aiBaseUrl;
    o["aiApiKey"] = aiApiKey;
    o["aiModel"] = aiModel;

    o["kernelDriverEnabled"] = kernelDriverEnabled;
    o["userModeBehaviorMonitor"] = userModeBehaviorMonitor;
    o["ransomwareCanaryEnabled"] = ransomwareCanaryEnabled;
    o["behaviorBaselineEnabled"] = behaviorBaselineEnabled;

    o["aiCreditGuardEnabled"] = aiCreditGuardEnabled;
    o["aiMonthlyCreditBudget"] = aiMonthlyCreditBudget;

    o["eventSource"] = eventSource;
    o["kernelConnected"] = kernelConnected;
    o["kernelStatus"] = kernelStatus;
    o["cloudServerOnly"] = cloudServerOnly; // 只读状态位(服务 -> UI),见 RuntimeSettings.h

    o["quarantineOnBlock"] = quarantineOnBlock;
    return o;
}

RuntimeSettings RuntimeSettings::fromJson(const QJsonObject& o) {
    RuntimeSettings s; // start from defaults so absent keys keep sensible values
    s.protectionEnabled = getBool(o, "protectionEnabled", s.protectionEnabled);
    // 老配置文件没有这个键 -> 取默认值 false(防护常驻)。这一条【必须】默认关:缺键时按开处理
    // 等于升级一次就把所有机器改成「界面不在跑就没有防护」,那是悄悄的防护降级。
    s.protectionFollowsUi = getBool(o, "protectionFollowsUi", s.protectionFollowsUi);

    s.processProtection = getBool(o, "processProtection", s.processProtection);
    s.fileProtection = getBool(o, "fileProtection", s.fileProtection);
    s.registryProtection = getBool(o, "registryProtection", s.registryProtection);
    s.selfProtection = getBool(o, "selfProtection", s.selfProtection);
    s.networkProtection = getBool(o, "networkProtection", s.networkProtection);

    s.memoryProtectionEnabled = getBool(o, "memoryProtectionEnabled", s.memoryProtectionEnabled);
    s.memoryProtectionVtVerifyEnabled = getBool(o, "memoryProtectionVtVerifyEnabled", s.memoryProtectionVtVerifyEnabled);

    s.trustSignedActors = getBool(o, "trustSignedActors", s.trustSignedActors);
    s.defaultBlock = getBool(o, "defaultBlock", s.defaultBlock);
    s.silentMode = getBool(o, "silentMode", s.silentMode);
    // 老配置文件没有这个键 -> 取默认值 true(开)。新增通知类开关按「默认开」处理:
    // 它的价值恰在于覆盖静默模式造成的盲区,默认关掉就等于白做。
    s.attackChainToast = getBool(o, "attackChainToast", s.attackChainToast);
    s.promptTimeoutSeconds = getInt(o, "promptTimeoutSeconds", s.promptTimeoutSeconds);

    s.virusTotalEnabled = getBool(o, "virusTotalEnabled", s.virusTotalEnabled);
    s.malwareBazaarEnabled = getBool(o, "malwareBazaarEnabled", s.malwareBazaarEnabled);
    s.otxEnabled = getBool(o, "otxEnabled", s.otxEnabled);
    s.threatBookEnabled = getBool(o, "threatBookEnabled", s.threatBookEnabled);
    s.threatBookNetworkIntelEnabled = getBool(o, "threatBookNetworkIntelEnabled", s.threatBookNetworkIntelEnabled);
    s.metaDefenderEnabled = getBool(o, "metaDefenderEnabled", s.metaDefenderEnabled);
    s.hybridAnalysisEnabled = getBool(o, "hybridAnalysisEnabled", s.hybridAnalysisEnabled);

    if (o.contains(QLatin1String("virusTotalApiKey")))    s.virusTotalApiKey = getStr(o, "virusTotalApiKey");
    if (o.contains(QLatin1String("malwareBazaarApiKey"))) s.malwareBazaarApiKey = getStr(o, "malwareBazaarApiKey");
    if (o.contains(QLatin1String("otxApiKey")))           s.otxApiKey = getStr(o, "otxApiKey");
    if (o.contains(QLatin1String("threatBookApiKey")))    s.threatBookApiKey = getStr(o, "threatBookApiKey");
    if (o.contains(QLatin1String("metaDefenderApiKey")))  s.metaDefenderApiKey = getStr(o, "metaDefenderApiKey");
    if (o.contains(QLatin1String("hybridAnalysisApiKey"))) s.hybridAnalysisApiKey = getStr(o, "hybridAnalysisApiKey");

    s.aiScanDoubleClickEnabled = getBool(o, "aiScanDoubleClickEnabled", s.aiScanDoubleClickEnabled);
    s.aiScanSuspendDuringScan = getBool(o, "aiScanSuspendDuringScan", s.aiScanSuspendDuringScan);
    // 缺失该键 -> 保持默认 false(关)。老配置升级后不会被悄悄打开。
    s.cloudBehaviorUploadEnabled = getBool(o, "cloudBehaviorUploadEnabled", s.cloudBehaviorUploadEnabled);

    // 已随 AI 研判一起移除的键(aiScanBlockOnFailure / aiGrayZoneConsultEnabled /
    // aiScanScriptTextLimitKb / aiScanBinarySampleLimitMb / aiScanMaxStrings)在旧配置里出现时直接忽略。
    if (o.contains(QLatin1String("aiBaseUrl"))) s.aiBaseUrl = getStr(o, "aiBaseUrl");
    if (o.contains(QLatin1String("aiApiKey"))) s.aiApiKey = getStr(o, "aiApiKey");
    if (o.contains(QLatin1String("aiModel"))) s.aiModel = getStr(o, "aiModel");

    s.kernelDriverEnabled = getBool(o, "kernelDriverEnabled", s.kernelDriverEnabled);
    s.userModeBehaviorMonitor = getBool(o, "userModeBehaviorMonitor", s.userModeBehaviorMonitor);
    s.ransomwareCanaryEnabled = getBool(o, "ransomwareCanaryEnabled", s.ransomwareCanaryEnabled);
    s.behaviorBaselineEnabled = getBool(o, "behaviorBaselineEnabled", s.behaviorBaselineEnabled);

    s.aiCreditGuardEnabled = getBool(o, "aiCreditGuardEnabled", s.aiCreditGuardEnabled);
    s.aiMonthlyCreditBudget = getI64(o, "aiMonthlyCreditBudget", s.aiMonthlyCreditBudget);

    if (o.contains(QLatin1String("eventSource"))) s.eventSource = getStr(o, "eventSource");
    s.kernelConnected = getBool(o, "kernelConnected", s.kernelConnected);
    if (o.contains(QLatin1String("kernelStatus"))) s.kernelStatus = getStr(o, "kernelStatus");
    s.cloudServerOnly = getBool(o, "cloudServerOnly", s.cloudServerOnly);

    s.quarantineOnBlock = getBool(o, "quarantineOnBlock", s.quarantineOnBlock);
    return s;
}

} // namespace bulwark
