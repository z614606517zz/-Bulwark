#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject RuntimeSettings::toJson() const {
    QJsonObject o;
    o["protectionEnabled"] = protectionEnabled;

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
    o["aiScanBlockOnFailure"] = aiScanBlockOnFailure;

    o["aiBaseUrl"] = aiBaseUrl;
    o["aiApiKey"] = aiApiKey;
    o["aiModel"] = aiModel;
    o["aiScanScriptTextLimitKb"] = aiScanScriptTextLimitKb;
    o["aiScanBinarySampleLimitMb"] = aiScanBinarySampleLimitMb;
    o["aiScanMaxStrings"] = aiScanMaxStrings;

    o["kernelDriverEnabled"] = kernelDriverEnabled;
    o["userModeBehaviorMonitor"] = userModeBehaviorMonitor;
    o["ransomwareCanaryEnabled"] = ransomwareCanaryEnabled;
    o["behaviorBaselineEnabled"] = behaviorBaselineEnabled;
    o["aiGrayZoneConsultEnabled"] = aiGrayZoneConsultEnabled;

    o["aiCreditGuardEnabled"] = aiCreditGuardEnabled;
    o["aiMonthlyCreditBudget"] = aiMonthlyCreditBudget;

    o["eventSource"] = eventSource;
    o["kernelConnected"] = kernelConnected;
    o["kernelStatus"] = kernelStatus;

    o["quarantineOnBlock"] = quarantineOnBlock;
    return o;
}

RuntimeSettings RuntimeSettings::fromJson(const QJsonObject& o) {
    RuntimeSettings s; // start from defaults so absent keys keep sensible values
    s.protectionEnabled = getBool(o, "protectionEnabled", s.protectionEnabled);

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
    s.aiScanBlockOnFailure = getBool(o, "aiScanBlockOnFailure", s.aiScanBlockOnFailure);

    if (o.contains(QLatin1String("aiBaseUrl"))) s.aiBaseUrl = getStr(o, "aiBaseUrl");
    if (o.contains(QLatin1String("aiApiKey"))) s.aiApiKey = getStr(o, "aiApiKey");
    if (o.contains(QLatin1String("aiModel"))) s.aiModel = getStr(o, "aiModel");
    s.aiScanScriptTextLimitKb = getInt(o, "aiScanScriptTextLimitKb", s.aiScanScriptTextLimitKb);
    s.aiScanBinarySampleLimitMb = getInt(o, "aiScanBinarySampleLimitMb", s.aiScanBinarySampleLimitMb);
    s.aiScanMaxStrings = getInt(o, "aiScanMaxStrings", s.aiScanMaxStrings);

    s.kernelDriverEnabled = getBool(o, "kernelDriverEnabled", s.kernelDriverEnabled);
    s.userModeBehaviorMonitor = getBool(o, "userModeBehaviorMonitor", s.userModeBehaviorMonitor);
    s.ransomwareCanaryEnabled = getBool(o, "ransomwareCanaryEnabled", s.ransomwareCanaryEnabled);
    s.behaviorBaselineEnabled = getBool(o, "behaviorBaselineEnabled", s.behaviorBaselineEnabled);
    s.aiGrayZoneConsultEnabled = getBool(o, "aiGrayZoneConsultEnabled", s.aiGrayZoneConsultEnabled);

    s.aiCreditGuardEnabled = getBool(o, "aiCreditGuardEnabled", s.aiCreditGuardEnabled);
    s.aiMonthlyCreditBudget = getI64(o, "aiMonthlyCreditBudget", s.aiMonthlyCreditBudget);

    if (o.contains(QLatin1String("eventSource"))) s.eventSource = getStr(o, "eventSource");
    s.kernelConnected = getBool(o, "kernelConnected", s.kernelConnected);
    if (o.contains(QLatin1String("kernelStatus"))) s.kernelStatus = getStr(o, "kernelStatus");

    s.quarantineOnBlock = getBool(o, "quarantineOnBlock", s.quarantineOnBlock);
    return s;
}

} // namespace bulwark
