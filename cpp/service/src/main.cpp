#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/SettingsStore.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/VtScanHistoryStore.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/PersistenceScanner.h"
#include "bulwark/service/Worker.h"

#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/reputation/HashReputationClients.h"
#include "bulwark/service/reputation/VirusTotalClient.h"
#include "bulwark/service/reputation/ThreatBookClient.h"
#include "bulwark/service/reputation/AggregateReputationService.h"
#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/service/reputation/ReputationCache.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/reputation/ThreatFoxFeed.h"

#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/DefaultRules.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <thread>
#include <QFileInfo>
#include <QTextStream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h> // SCM: StartServiceCtrlDispatcher / CreateService / SetServiceStatus

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <vector>

using namespace bulwark::service;

namespace {

// 诊断自检:仅跑取证(签名/哈希/发布者/证书画像/自身命令行),打印后立即退出。
// 只读、无副作用——不启动事件循环、不启用 ETW、不做任何处置。用于验证 ProcessInspector
// 在真实系统文件上的行为(例如 kernel32.dll 应为微软签名)。用法:--inspect <路径>
int runInspect(const QString& path) {
    using bulwark::service::monitoring::ProcessInspector;
    // 结果同时写 stdout 与临时文件(便于无控制台/重定向环境下取回结果)。
    QString buf;
    QTextStream out(&buf);
    out << "=== ProcessInspector self-test ===\n";
    out << "target: " << path << "\n";
    if (!path.isEmpty()) {
        out << "isSigned: " << (ProcessInspector::isSigned(path) ? "true" : "false") << "\n";
        out << "signatureMismatch: " << (ProcessInspector::isSignatureMismatch(path) ? "true" : "false") << "\n";
        out << "hasEmbedded: " << (ProcessInspector::hasEmbeddedSignature(path) ? "true" : "false") << "\n";
        out << "publisher: " << ProcessInspector::tryGetPublisher(path) << "\n";
        out << "sha256: " << ProcessInspector::tryComputeSha256(path) << "\n";
        const ProcessInspector::CertInfo ci = ProcessInspector::getCertInfo(path);
        out << "cert.thumbprint: " << ci.thumbprint << "\n";
        out << "cert.notBefore: "
            << (ci.notBeforeUtc.isValid() ? ci.notBeforeUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.notAfter: "
            << (ci.notAfterUtc.isValid() ? ci.notAfterUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.signingTime: "
            << (ci.signingTimeUtc.isValid() ? ci.signingTimeUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.signedAfterExpiry: " << (ci.signedAfterCertExpiry ? "true" : "false") << "\n";
        out << "cert.revoked: " << (ci.revoked ? "true" : "false") << "\n";
    }
    // 自身进程:验证 PEB 命令行读取 / 映像路径 / 父进程(只读)。
    const int selfPid = static_cast<int>(QCoreApplication::applicationPid());
    out << "--- self (pid " << selfPid << ") ---\n";
    out << "self.imagePath: " << ProcessInspector::tryGetProcessImagePath(selfPid) << "\n";
    out << "self.commandLine: " << ProcessInspector::tryGetCommandLine(selfPid) << "\n";
    out << "self.parentPid: " << ProcessInspector::tryGetParentPid(selfPid) << "\n";
    out.flush();

    // 落盘到临时目录,并回显到 stdout。
    const QString resultPath = QDir(QDir::tempPath()).filePath(QStringLiteral("bulwark_inspect_result.txt"));
    QFile rf(resultPath);
    if (rf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        rf.write(buf.toUtf8());
        rf.close();
    }
    QTextStream(stdout) << buf << "result written to: " << resultPath << "\n";
    return 0;
}

// 全局兜底:把未捕获的 C++ 异常写入 crash.log 再中止(对应 Program.cs 的 AppDomain 钩子)。
void onTerminate() {
    QString detail = QStringLiteral("std::terminate called");
    if (auto ex = std::current_exception()) {
        try { std::rethrow_exception(ex); }
        catch (const std::exception& e) { detail = QString::fromUtf8(e.what()); }
        catch (...) { detail = QStringLiteral("unknown exception"); }
    }
    writeCrashLog(QStringLiteral("Terminate"), detail);
    std::abort();
}

} // namespace

// 服务核心运行体:创建 QCoreApplication、装配全部组件、进入事件循环。既可由控制台
// (默认)直接调用,也可由 SCM 的 ServiceMain 调用(此时 --service 参数被 Qt 忽略)。
static int serviceRun(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("Bulwark Defense"));
    std::set_terminate(onTerminate);

    // 诊断自检(在任何服务初始化之前处理):只读取证并退出,绝不启动监控/处置。
    {
        const QStringList args = QCoreApplication::arguments();
        const int idx = args.indexOf(QStringLiteral("--inspect"));
        if (idx >= 0)
            return runInspect(idx + 1 < args.size() ? args.at(idx + 1) : QString());
    }

    startFileLog();
    Logger log(QStringLiteral("bulwark.service.Main"));
    log.info(QStringLiteral("Bulwark 服务启动中(C++/Qt 移植)。"));

    // 配置:绑定可执行文件旁的 appsettings.json 的 "Bulwark" 段。
    BulwarkOptions options;
    const QString appsettings =
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("appsettings.json"));
    if (!options.loadFromFile(appsettings))
        log.warning(QStringLiteral("appsettings.json 解析失败,使用默认值: %1").arg(appsettings));

    // 按配置决定证书吊销校验是否联网(默认 false:仅用本机缓存 CRL,绝不联网/阻塞富化)。
    monitoring::ProcessInspector::onlineRevocationCheck = options.OnlineCertRevocationCheck;

    // 存储层。
    SettingsStore settingsStore;
    RuleStore ruleStore;
    AuditLog audit;
    FirstSeenStore firstSeen; // 本机「首见」哈希库,供富化阶段判定低流行度
    QuarantineManager quarantine; // 隔离区(恶意载荷失活 + 可逆还原),供威胁清理使用
    VtScanHistoryStore vtHistory; // VirusTotal 扫描历史(去重 + 展示)
    EventHistoryStore eventHistory; // 结构化事件历史(内存环形 + JSONL 落盘,重启保留),供 UI 回填

    // 运行时设置:appsettings 默认值,若存在 settings.json 则覆盖。UI 经 IPC 读取/更新。
    bulwark::RuntimeSettings settings;
    settings.trustSignedActors = options.TrustSignedActors;
    settings.eventSource = options.EventSource;
    if (const auto rs = settingsStore.load()) {
        settings = *rs;
        settings.eventSource = options.EventSource; // 事件源只读,以实际运行为准
        log.info(QStringLiteral("已从 settings.json 载入运行时设置。"));
    }

    // 规则引擎:内置规则 + 用户持久化规则。
    bulwark::engine::RuleEngine engine;
    engine.trustSignedActors = settings.trustSignedActors;
    engine.enableBaseline = settings.behaviorBaselineEnabled;
    // 登记自身安装目录:本软件自身组件(bulwark_service.exe / bulwark_ui.exe 及旁置工具)
    // 无条件放行,不把自己的行为当第三方来评估。仅按映像名匹配可被同名程序冒用,故同时按
    // 安装目录前缀匹配(此前 addSelfDirectory 从未被调用,自身目录集恒为空)。
    engine.addSelfDirectory(QCoreApplication::applicationDirPath());
    QVector<bulwark::DefenseRule> rules = bulwark::engine::DefaultRules::build();
    // 内置规则以代码为准:丢弃持久化库中的旧内置副本(build() 已提供最新版),否则每次
    // 落盘 + 重启会让内置规则重复累积(现在 ThreatFox 情报刷新会周期性落盘,尤需如此)。
    // 用户 / 信任 / 情报规则(非 [内置] 备注)照常保留。对应 .NET Worker.MergeRules 的意图。
    const QString builtInTag = bulwark::engine::DefaultRules::builtInTag();
    for (const bulwark::DefenseRule& r : ruleStore.load())
        if (!r.note.startsWith(builtInTag))
            rules.append(r);
    engine.loadRules(rules);
    log.info(QStringLiteral("已加载 %1 条规则(内置 + 用户/信任/情报)。").arg(rules.size()));

    // 外部信誉:curl.exe 传输 + 分级缓存 + 限流。后台线程限流查询,同步只读缓存参与富化。
    // 现接入 VirusTotal(旗舰,内置默认 Key 开箱即用)+ 微步 ThreatBook + 4 个通用哈希源
    // (MalwareBazaar / OTX / MetaDefender / HybridAnalysis),各源按配置/密钥自行启用;
    // 未配置任何源时后台 worker 不启动(纯本地启发式照常)。
    reputation::ReputationCurl::proxyUrl = options.ProxyUrl;
    std::vector<std::unique_ptr<reputation::IHashReputationService>> repSources;
    // 保留 VT 客户端具体句柄:上传扫描(uploadAndScan)是接口外的 VT 专有方法,供双击/释放
    // 载荷病毒扫描直接调用(不经聚合器的哈希查询接口)。
    auto virusTotalClient = std::make_unique<reputation::VirusTotalClient>(options);
    reputation::VirusTotalClient* virusTotalPtr = virusTotalClient.get();
    repSources.push_back(std::move(virusTotalClient));
    // 保留微步客户端具体句柄:IP 信誉(scene/ip_reputation)是接口外的 ThreatBook 专有方法,
    // 供网络外联情报互证直接调用(不经聚合器的哈希查询接口)。
    auto threatBookClient = std::make_unique<reputation::ThreatBookClient>(options);
    reputation::ThreatBookClient* threatBookPtr = threatBookClient.get();
    repSources.push_back(std::move(threatBookClient));
    repSources.push_back(std::make_unique<reputation::MalwareBazaarClient>(options));
    repSources.push_back(std::make_unique<reputation::OtxClient>(options));
    repSources.push_back(std::make_unique<reputation::MetaDefenderClient>(options));
    repSources.push_back(std::make_unique<reputation::HybridAnalysisClient>(options));
    reputation::AggregateReputationService repAggregate(std::move(repSources));
    int cleanTtlDays = options.VirusTotal.CleanCacheTtlDays;
    if (cleanTtlDays < 1) cleanTtlDays = 7;
    reputation::ReputationCache repCache(static_cast<qint64>(cleanTtlDays) * 24LL * 3600LL * 1000LL);
    reputation::ReputationManager repManager(&repAggregate, &repCache);
    // 按运行时设置启用各信誉源(默认全关,由 UI 开启;VT 虽有内置 Key 也须用户显式启用)。
    // 与 .NET 一致:信誉查询是 opt-in,未启用任何源则后台 worker 不查询。
    repAggregate.setRuntimeEnabled(settings.virusTotalEnabled, settings.malwareBazaarEnabled,
                                   settings.otxEnabled, settings.threatBookEnabled,
                                   settings.metaDefenderEnabled, settings.hybridAnalysisEnabled);

    // 情报规则应用(共享:后台自动刷新回调 + IPC 手动刷新/采纳都复用)。按来源标记清理上一轮
    // 同源规则后灌入新规则并落盘,返回清理的旧规则数。均在主线程调用(feed 回调已编组回主线程)。
    std::function<int(const QVector<bulwark::DefenseRule>&)> applyIntelRules =
        [&engine, &ruleStore](const QVector<bulwark::DefenseRule>& newRules) -> int {
            const QString tag = ThreatFoxFeedOptions::ruleNoteTag();
            int removed = 0;
            for (const bulwark::DefenseRule& r : engine.getRules())
                if (r.note.startsWith(tag) && engine.removeRule(r.id))
                    ++removed;
            for (const bulwark::DefenseRule& r : newRules)
                engine.addRule(r);
            ruleStore.save(engine.getRules());
            return removed;
        };

    // ThreatFox(abuse.ch)情报 feed:定期拉取恶意 IOC 自动生成拦截规则(主动防护)。
    // 需在 appsettings 开启 ThreatFoxFeed.Enabled 且提供 abuse.ch Auth-Key(可复用 MalwareBazaar 的)。
    // 另建独立客户端供 IPC「立即刷新 / 预览」按需拉取(与后台 feed 服务内部客户端互不影响)。
    reputation::ThreatFoxFeedClient intelClient(options.ThreatFoxFeed, options.MalwareBazaar.AuthKey);
    reputation::IntelFeedService intelFeed(options.ThreatFoxFeed, options.MalwareBazaar.AuthKey);
    intelFeed.setRulesReady([applyIntelRules, &log](const QVector<bulwark::DefenseRule>& rules) {
        const int removed = applyIntelRules(rules);
        log.info(QStringLiteral("ThreatFox 情报刷新:清理旧规则 %1 条,注入新规则 %2 条。")
                     .arg(removed).arg(rules.size()));
    });

    // IPC 命名管道服务器(与 UI 通信)。
    IpcServer ipc;

    // 事件源协调器句柄(下方创建后赋值):供 settingsRequested 回报内核连接状态,
    // 供 settingsUpdated 运行时切换内核驱动开关 / 用户态行为监控开关。
    EventSourceCoordinator* coordinatorPtr = nullptr;

    // ---- 绑定 IPC 请求处理回调(对应 .NET Worker 里的 _ipc.* 绑定)----
    // 全部在主线程(Qt 事件循环)上调用,与事件处理串行;引擎内部另有读写锁。

    // UI 握手:把 UI 进程 PID 登记进内核驱动的自我保护名单,恶意软件便无法结束/篡改 UI 进程。
    // 该回调仅在 app.exec() 事件循环中(处理 Hello 帧时)触发,此时 coordinatorPtr 已完成赋值,
    // 无竞态;UI 每次(重)连接都会重发 Hello,内核(重)连接时协调器也会补发已登记的受保护 PID。
    ipc.uiProcessConnected = [&coordinatorPtr, &log](int pid) {
        if (coordinatorPtr) {
            coordinatorPtr->addProtectedUiPid(pid);
            log.info(QStringLiteral("UI 已连接(PID %1),已登记内核自我保护名单。").arg(pid));
        }
    };

    // 规则管理:查询 / 删除 / 新增(智能解析主体为精确路径 / 通配 / 裸文件名)。
    ipc.rulesRequested = [&engine] { return engine.getRules(); };
    ipc.ruleDeleteRequested = [&engine, &ruleStore](const QUuid& id) {
        if (engine.removeRule(id)) ruleStore.save(engine.getRules());
    };
    ipc.ruleAddRequested = [&engine, &ruleStore, &log](const bulwark::ipc::AddRulePayload& p) {
        bulwark::DefenseRule rule;
        const QString actor = p.actorPath.trimmed();
        if (!actor.isEmpty()) {
            const bool hasWild = actor.contains(QLatin1Char('*')) || actor.contains(QLatin1Char('?'));
            const bool rooted  = actor.contains(QStringLiteral(":\\")) || actor.startsWith(QStringLiteral("\\\\"));
            if (hasWild)      rule.actorPattern = actor;
            else if (rooted)  rule.actorPath = actor;
            else              rule.actorPattern = QStringLiteral("*\\") + actor; // 裸文件名 -> 任意目录同名
        }
        rule.type = p.type;
        rule.targetPattern = p.targetPattern.trimmed();
        rule.action = p.action;
        engine.addRule(rule);
        ruleStore.save(engine.getRules());
        log.info(QStringLiteral("已新增规则:%1 => %2")
                     .arg(rule.actorPath.isEmpty() ? rule.actorPattern : rule.actorPath,
                          bulwark::verdictActionToString(rule.action)));
    };

    // 运行时设置:查询(附只读内核/事件源状态)/ 更新(同步引擎 + 落盘)。
    ipc.settingsRequested = [&settings, &engine, &coordinatorPtr] {
        bulwark::RuntimeSettings snap = settings.clone();
        snap.trustSignedActors = engine.trustSignedActors;
        if (coordinatorPtr && coordinatorPtr->kernelConnected()) {
            snap.kernelConnected = true;
            snap.kernelStatus = QStringLiteral("内核驱动已连接 · 行为前拦截(进程/文件/注册表/自保/网络)");
        } else {
            snap.kernelConnected = false;
            snap.kernelStatus = (coordinatorPtr && coordinatorPtr->kernelProtocolMismatch())
                ? QStringLiteral("内核驱动协议不一致 · 已降级(请用同源编译的 Bulwark.sys)")
                : ((coordinatorPtr && coordinatorPtr->kernelAttachFailed())
                       ? QStringLiteral("内核驱动不可用 · 已降级为用户态观测(后台重试中)")
                       : QStringLiteral("用户态观测(ETW,内核驱动未启用)"));
        }
        return snap;
    };
    ipc.settingsUpdated = [&settings, &engine, &settingsStore, &repAggregate, &repManager, &coordinatorPtr, &log](
                              const bulwark::RuntimeSettings& s) {
        bulwark::RuntimeSettings updated = s;
        updated.eventSource = settings.eventSource; // 只读字段保持不变
        settings = updated;
        engine.trustSignedActors = settings.trustSignedActors;
        engine.enableBaseline = settings.behaviorBaselineEnabled;
        settingsStore.save(settings);
        // 运行时切换:内核驱动开关(热加载/卸载)+ 用户态持续行为监控 / 勒索诱饵开关。
        if (coordinatorPtr) {
            coordinatorPtr->setKernelEnabled(settings.kernelDriverEnabled);
            coordinatorPtr->configureBehaviorMonitor(settings.userModeBehaviorMonitor,
                                                     settings.ransomwareCanaryEnabled);
        }
        // 信誉源开关即时生效;若用户新启用了某源,(重)启动后台查询 worker(已运行则为空操作)。
        repAggregate.setRuntimeEnabled(settings.virusTotalEnabled, settings.malwareBazaarEnabled,
                                       settings.otxEnabled, settings.threatBookEnabled,
                                       settings.metaDefenderEnabled, settings.hybridAnalysisEnabled);
        // 情报源 API Key 热应用(UI 逐源填写,立即生效)。空 -> 禁用该源;VT 空则回退内置 Key。
        repAggregate.setApiKey(QStringLiteral("VirusTotal"),     settings.virusTotalApiKey);
        repAggregate.setApiKey(QStringLiteral("MalwareBazaar"),  settings.malwareBazaarApiKey);
        repAggregate.setApiKey(QStringLiteral("OTX"),            settings.otxApiKey);
        repAggregate.setApiKey(QStringLiteral("ThreatBook"),     settings.threatBookApiKey);
        repAggregate.setApiKey(QStringLiteral("MetaDefender"),   settings.metaDefenderApiKey);
        repAggregate.setApiKey(QStringLiteral("HybridAnalysis"), settings.hybridAnalysisApiKey);
        repManager.start();
        log.info(QStringLiteral("设置已更新:总开关=%1 默认动作=%2 信誉源=%3")
                     .arg(settings.protectionEnabled ? QStringLiteral("开") : QStringLiteral("关"),
                          settings.defaultBlock ? QStringLiteral("Block") : QStringLiteral("Allow"),
                          settings.anyReputationEnabled() ? QStringLiteral("开") : QStringLiteral("关")));
    };

    // 文件信任中心:信任条目本质是带信任标记的精确 Allow 规则。
    ipc.trustListRequested = [&engine] {
        QList<bulwark::DefenseRule> out;
        for (const auto& r : engine.getRules())
            if (r.isTrustEntry()) out.append(r);
        return out;
    };
    ipc.trustAddRequested = [&engine, &ruleStore, &log](const bulwark::ipc::AddTrustPayload& p) {
        const QString path = p.actorPath.trimmed();
        if (path.isEmpty()) return;
        if (p.isDirectory) {
            // 文件夹信任:目录下运行的所有程序无条件放行。引擎在威胁检测之前提前命中此类
            // 信任项(信任即完全不再检测)。按目录通配去重。
            const bulwark::DefenseRule rule = bulwark::DefenseRule::createTrustDirectory(path, p.note);
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && !r.actorPattern.isEmpty()
                    && r.actorPattern.compare(rule.actorPattern, Qt::CaseInsensitive) == 0) return;
            engine.addRule(rule);
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件夹信任:%1").arg(path));
        } else {
            for (const auto& r : engine.getRules()) // 去重
                if (r.isTrustEntry() && r.actorPath.compare(path, Qt::CaseInsensitive) == 0) return;
            engine.addRule(bulwark::DefenseRule::createTrust(path, p.note));
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件信任:%1").arg(path));
        }
    };
    ipc.trustRemoveRequested = [&engine, &ruleStore](const QUuid& id) {
        if (engine.removeRule(id)) ruleStore.save(engine.getRules());
    };

    // 隔离区:列表 / 还原 / 永久删除。
    ipc.quarantineListRequested = [&quarantine] {
        bulwark::ipc::QuarantineListResponsePayload payload;
        for (const auto& x : quarantine.list()) {
            bulwark::ipc::QuarantineItemPayload item;
            item.id = x.id; item.originalPath = x.originalPath; item.fileName = x.fileName;
            item.quarantinedUtc = x.quarantinedUtc; item.size = x.size; item.sha256 = x.sha256;
            item.reason = x.reason; item.actorPid = x.actorPid;
            payload.items.append(item);
        }
        return payload;
    };
    ipc.quarantineRestoreRequested = [&quarantine, &log](const QUuid& id) {
        const bool ok = quarantine.restore(id);
        if (ok) log.warning(QStringLiteral("用户从隔离区还原了条目 %1。").arg(id.toString(QUuid::WithoutBraces)));
        return bulwark::ipc::QuarantineActionResultPayload{
            id, ok, ok ? QStringLiteral("已还原到原始位置")
                       : QStringLiteral("还原失败(条目不存在或文件被占用)")};
    };
    ipc.quarantineDeleteRequested = [&quarantine, &log](const QUuid& id) {
        const bool ok = quarantine.purge(id);
        if (ok) log.info(QStringLiteral("用户永久删除了隔离条目 %1。").arg(id.toString(QUuid::WithoutBraces)));
        return bulwark::ipc::QuarantineActionResultPayload{
            id, ok, ok ? QStringLiteral("已永久删除") : QStringLiteral("删除失败(条目不存在)")};
    };

    // VT 扫描历史:UI 打开「VT 查询记录」视图时请求完整历史。
    ipc.vtHistoryRequested = [&vtHistory] {
        bulwark::ipc::VtHistoryResponsePayload payload;
        payload.records = vtHistory.getAll();
        return payload;
    };

    // 持久化审计:UI 打开「自启动项」视图时只读枚举 7 类自启动持久化点,逐项启发式打分 +
    // ATT&CK 标注返回。纯只读——绝不修改任何自启动项(清理走既有规则/隔离流程)。
    ipc.persistenceListRequested = [] { return PersistenceScanner::scan(); };

    // 结构化事件历史:UI 打开活动日志/拦截记录时回填最近若干条(重启后仍保留)。
    ipc.eventHistoryRequested = [&eventHistory] {
        bulwark::ipc::EventHistoryResponsePayload payload;
        payload.events = eventHistory.getRecent();
        return payload;
    };
    // 清空事件历史(UI「清空」按钮):清空内存 + 落盘文件,重启后不再回填。
    ipc.eventHistoryClearRequested = [&eventHistory] { eventHistory.clear(); };

    // 威胁情报 / VirusTotal:测试连接 / 按文件查询 / 用量统计(用户主动触发,阻塞可接受)。
    ipc.vtRequested = [&repAggregate, &repManager](const bulwark::ipc::VtRequestPayload& req)
        -> bulwark::ipc::VtResponsePayload {
        bulwark::ipc::VtResponsePayload res;
        res.requestId = req.requestId;
        switch (req.kind) {
            case bulwark::VtRequestKind::TestConnection: {
                const auto r = req.source.trimmed().isEmpty() ? repAggregate.testConnection()
                                                              : repAggregate.testConnection(req.source);
                res.success = r.first;
                res.message = r.second;
                break;
            }
            case bulwark::VtRequestKind::QueryFile: {
                const QString path = req.filePath.trimmed();
                if (path.isEmpty()) { res.success = false; res.message = QStringLiteral("未提供文件路径"); break; }
                const QString hash = monitoring::ProcessInspector::tryComputeSha256(path);
                if (hash.isEmpty()) { res.success = false; res.message = QStringLiteral("无法读取文件或计算哈希"); break; }
                const bulwark::FileReputation rep = repManager.queryNow(hash);
                res.reputation = rep;
                res.success = rep.querySucceeded || rep.verdict != bulwark::ReputationVerdict::Unknown;
                res.message = res.success ? QStringLiteral("查询完成")
                                          : QStringLiteral("未获结论(源不可用 / 超配额 / 未收录)");
                break;
            }
            case bulwark::VtRequestKind::UsageStats: {
                res.usages = repAggregate.getUsages();
                res.success = true;
                break;
            }
        }
        return res;
    };

    // 云信誉详情按需拉取(异步):后台线程拉 VT 完整报告(每引擎检出 + 元数据)+ 行为画像
    // (聚合 VT + HybridAnalysis),完成后编组回主线程经 sendVtDetail 回推 UI —— 不阻塞 IPC 线程。
    ipc.vtDetailRequested = [virusTotalPtr, &repManager, &ipc](const QUuid& reqId, const QString& sha256) {
        std::thread([virusTotalPtr, &repManager, &ipc, reqId, sha256] {
            bulwark::ipc::VtDetailResponsePayload p;
            if (virusTotalPtr)
                p = virusTotalPtr->fetchDetailReport(sha256);
            else
                p.message = QStringLiteral("VirusTotal 客户端不可用");
            const bulwark::ThreatBehaviorProfile prof = repManager.fetchBehaviorProfile(sha256);
            if (prof.fetched) {
                p.droppedFiles = prof.droppedFileNames;
                p.registryKeys = prof.registryKeysSet;
                p.contactedIps = prof.contactedIps;
                p.contactedDomains = prof.contactedDomains;
            }
            p.requestId = reqId;
            p.sha256 = sha256;
            QMetaObject::invokeMethod(&ipc, [&ipc, p] { ipc.sendVtDetail(p); }, Qt::QueuedConnection);
        }).detach();
    };

    // 手动强制隔离(清理报告「重试隔离」):失活磁盘载荷,可逆还原。
    ipc.manualQuarantineRequested = [&quarantine, &log](const QString& path) -> std::pair<bool, QString> {
        const QString p = path.trimmed();
        if (p.isEmpty()) return { false, QStringLiteral("路径为空") };
        if (!QFileInfo::exists(p)) return { false, QStringLiteral("文件不存在(可能已被移动或删除)") };
        const QString hash = QuarantineManager::tryComputeSha256(p);
        const auto entry = quarantine.quarantine(p, QStringLiteral("用户手动强制隔离(清理报告重试)"), 0, hash);
        if (entry.has_value()) {
            log.warning(QStringLiteral("手动强制隔离成功:") + p);
            return { true, QStringLiteral("已移入隔离区") };
        }
        return { false, QStringLiteral("隔离失败(文件可能被占用或权限不足)") };
    };

    // 情报订阅:立即刷新(预览仅生成不落地;否则清旧灌新并落盘)。用户主动触发,阻塞可接受。
    ipc.intelRefreshRequested = [&intelClient, applyIntelRules, &options, &log](
        const bulwark::ipc::IntelRefreshRequestPayload& req) -> bulwark::ipc::IntelRefreshResultPayload {
        bulwark::ipc::IntelRefreshResultPayload res;
        res.requestId = req.requestId;
        if (!intelClient.isEnabled()) {
            res.success = false;
            res.message = QStringLiteral("ThreatFox 未启用或未配置 Auth-Key");
            return res;
        }
        const QVector<reputation::ThreatFoxIoc> iocs = intelClient.fetchRecent();
        res.iocCount = static_cast<int>(iocs.size());
        const QVector<bulwark::DefenseRule> gen = reputation::generateIntelRules(iocs, options.ThreatFoxFeed);
        res.generatedRules = gen;
        if (req.previewOnly) {
            res.success = !gen.isEmpty();
            res.message = QStringLiteral("预览:拉取 %1 条 IOC,生成 %2 条规则(未落地)")
                              .arg(iocs.size()).arg(gen.size());
            return res;
        }
        const int removed = applyIntelRules(gen);
        res.rulesApplied = static_cast<int>(gen.size());
        res.success = true;
        res.message = QStringLiteral("已刷新:清理旧 %1 条,注入 %2 条").arg(removed).arg(gen.size());
        log.info(res.message);
        return res;
    };

    // 情报采纳:UI 复核确认后下发的一批规则,替换当前同源规则并落盘。
    ipc.intelApplyRequested = [applyIntelRules, &log](
        const bulwark::ipc::IntelApplyRequestPayload& req) -> bulwark::ipc::IntelRefreshResultPayload {
        bulwark::ipc::IntelRefreshResultPayload res;
        res.requestId = req.requestId;
        const int removed = applyIntelRules(req.rules);
        res.rulesApplied = static_cast<int>(req.rules.size());
        res.success = true;
        res.message = QStringLiteral("已采纳:清理旧 %1 条,注入 %2 条").arg(removed).arg(req.rules.size());
        log.info(res.message);
        return res;
    };

    if (!ipc.start())
        log.warning(QStringLiteral("IPC 控制管道监听失败;UI 将无法连接。"));

    // 基础用户态事件源(始终运行):ETW 实时观测源(进程/网络/DNS/注册表/文件)。
    // ETW 需管理员权限,不可用时降级但服务照常运行。
    std::unique_ptr<EventSource> baseSource;
    {
        auto etwSource = std::make_unique<EtwProcessEventSource>(options.Etw);
        // 注册表/文件 ETW 监视集:受保护键/路径 + 硬拦列表。只有命中监视集的写/删才上报,
        // 避免全量事件洪泛(与驱动的受保护路径模型一致)。空监视集则不产生该类事件。
        etwSource->setWatchLists(options.ProtectedRegistryKeys + options.RegistryHardBlocks,
                                 options.ProtectedPaths + options.FileHardBlocks);
        baseSource = std::move(etwSource);
        log.info(QStringLiteral("基础事件源 = ETW(Kernel-Process + 可选 Kernel-Network/DNS-Client/Kernel-Registry,实时)。"));
    }

    // 用户态持续行为源(自启动持久化 + 勒索诱饵):与基础源并行,弥补"运行之后"的事后盲区。
    auto behaviorSource = std::make_unique<UserModeBehaviorSource>(engine);

    // 协调器:合并 基础源 + 行为源 +(按开关热切换的)内核驱动源,作为 Worker 的统一事件源。
    // 裁决回写只路由到内核源;内核连接后抑制基础源重复的进程事件。
    auto coordinator = std::make_unique<EventSourceCoordinator>(baseSource.get(), behaviorSource.get(), options);
    coordinatorPtr = coordinator.get();

    // 编排:事件 -> 富化 -> 引擎 -> 裁决 -> IPC/处置/清理。
    Worker worker(&engine, &ipc, coordinator.get(), &ruleStore, &audit, &firstSeen, &quarantine, &repManager,
                  &settings);
    worker.setIpIntel(threatBookPtr); // 注入微步客户端并启动后台 IP 情报 worker(网络外联互证)
    worker.setVtScan(virusTotalPtr, &vtHistory); // 注入 VT 客户端 + 历史,启动后台双击/释放载荷病毒扫描
    worker.setEventHistory(&eventHistory);       // 注入结构化事件历史(落库,供 UI 回填)
    // 情报行为规则注入器:确认恶意后据 VT 行为画像 IOC 生成的拦截规则经此累加去重入库并落盘。
    // 在主线程(onReputationMalicious)侧调用——触碰引擎/规则库须在主线程,与其它规则变更串行。
    worker.setIntelRuleInjector(
        [&engine, &ruleStore, &log](const QVector<bulwark::DefenseRule>& newRules) -> int {
            const auto existing = engine.getRules();
            auto duplicate = [&existing](const bulwark::DefenseRule& nr) {
                for (const bulwark::DefenseRule& r : existing)
                    if (r.type == nr.type && r.action == nr.action
                        && r.targetPattern == nr.targetPattern && r.actorHashes == nr.actorHashes)
                        return true;
                return false;
            };
            int added = 0;
            for (const bulwark::DefenseRule& r : newRules) {
                if (duplicate(r)) continue;
                engine.addRule(r);
                ++added;
            }
            if (added > 0) {
                ruleStore.save(engine.getRules());
                log.info(QStringLiteral("情报行为规则:据确认恶意样本的行为画像新增主动拦截规则 %1 条。").arg(added));
            }
            return added;
        });

    // 情报源 API Key 应用:UI 设置里非空则用之,否则沿用 appsettings.json / 内置默认。先把
    // 「有效 Key」回填进 settings(供 settingsRequested 让 UI 掩码展示当前配置),再统一下发到
    // 各源(线程安全,可运行时热更)。VT 空则由客户端回退内置默认 Key。
    {
        auto seedKey = [](QString& dst, const QString& cfg) {
            if (dst.trimmed().isEmpty() && !cfg.trimmed().isEmpty()) dst = cfg.trimmed();
        };
        seedKey(settings.virusTotalApiKey,     options.VirusTotal.ApiKey);
        seedKey(settings.malwareBazaarApiKey,  options.MalwareBazaar.AuthKey);
        seedKey(settings.otxApiKey,            options.Otx.ApiKey);
        seedKey(settings.threatBookApiKey,     options.ThreatBook.ApiKey);
        seedKey(settings.metaDefenderApiKey,   options.MetaDefender.ApiKey);
        seedKey(settings.hybridAnalysisApiKey, options.HybridAnalysis.ApiKey);
        repAggregate.setApiKey(QStringLiteral("VirusTotal"),     settings.virusTotalApiKey);
        repAggregate.setApiKey(QStringLiteral("MalwareBazaar"),  settings.malwareBazaarApiKey);
        repAggregate.setApiKey(QStringLiteral("OTX"),            settings.otxApiKey);
        repAggregate.setApiKey(QStringLiteral("ThreatBook"),     settings.threatBookApiKey);
        repAggregate.setApiKey(QStringLiteral("MetaDefender"),   settings.metaDefenderApiKey);
        repAggregate.setApiKey(QStringLiteral("HybridAnalysis"), settings.hybridAnalysisApiKey);
    }

    repManager.start(); // 启动后台信誉查询 worker(无可用源时为空操作)
    intelFeed.start();  // 启动 ThreatFox 情报 feed(未启用/无 Key 时为空操作)
    // 先应用初始设置(用户态行为监控 / 勒索诱饵开关),再 start()——确保 start() 内的诱饵投放
    // 遵从当前开关,而不是先按默认(开)投放再被关闭。
    coordinator->configureBehaviorMonitor(settings.userModeBehaviorMonitor, settings.ransomwareCanaryEnabled);
    coordinator->start(); // 启动基础源 + 用户态行为源

    // 内核驱动开关(EventSource=Driver 或设置开启即启用)。
    const bool kernelInitial = options.EventSource.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0
                               || settings.kernelDriverEnabled;
    if (kernelInitial)
        coordinator->setKernelEnabled(true);

    if (!coordinator->isAvailable())
        log.warning(QStringLiteral("基础事件源(ETW)不可用(通常因未以管理员身份运行);"
                                   "无实时进程事件,IPC/规则 / 用户态行为监控仍照常工作。"));
    log.info(QStringLiteral("Bulwark 服务已就绪。"));

    const int rc = app.exec();

    intelFeed.stop();  // 先停情报 feed 后台线程
    repManager.stop(); // 先停后台信誉 worker(在 Worker 析构前 join,避免回调触及失效对象)
    coordinator->stop();
    ipc.stop();
    log.info(QStringLiteral("Bulwark 服务退出。"));
    stopFileLog();
    return rc;
}


// ==========================================================================
// Windows 服务(SCM)集成。默认控制台运行(便于调试);--service 由 SCM 托管后台运行;
// --install / --uninstall 自注册/注销为自动启动的 Windows 服务(SERVICE_WIN32_OWN_PROCESS)。
// 用户态服务名 "BulwarkService"(与内核驱动服务 "Bulwark" 区分,避免冲突)。
// 对应 .NET Program.cs 的 UseWindowsService。
// ==========================================================================
namespace {

const wchar_t* kSvcName = L"BulwarkService";
const wchar_t* kSvcDisplay = L"\u78D0\u5792\u4E3B\u52A8\u9632\u5FA1\u670D\u52A1"; // 磐垒主动防御服务

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
int g_svcArgc = 0;
char** g_svcArgv = nullptr;

void reportStatus(DWORD state, DWORD waitHint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_status.dwWin32ExitCode = 0;
    g_status.dwWaitHint = waitHint;
    static DWORD checkPoint = 1;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
    if (g_statusHandle) ::SetServiceStatus(g_statusHandle, &g_status);
}

void WINAPI serviceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        reportStatus(SERVICE_STOP_PENDING, 8000);
        if (auto* a = QCoreApplication::instance())
            QMetaObject::invokeMethod(a, "quit", Qt::QueuedConnection); // 干净退出事件循环
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_statusHandle = ::RegisterServiceCtrlHandlerW(kSvcName, serviceCtrlHandler);
    if (!g_statusHandle) return;
    reportStatus(SERVICE_START_PENDING, 8000);
    reportStatus(SERVICE_RUNNING);
    const int rc = serviceRun(g_svcArgc, g_svcArgv); // 阻塞在 app.exec(),STOP 时经 quit 返回
    reportStatus(SERVICE_STOPPED);
    (void)rc;
}

int installService() {
    wchar_t exe[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::wstring bin = L"\"" + std::wstring(exe) + L"\" --service";
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { std::fprintf(stderr, "OpenSCManager failed (%lu). 需管理员权限。\n", ::GetLastError()); return 1; }
    int rc = 0;
    SC_HANDLE svc = ::CreateServiceW(scm, kSvcName, kSvcDisplay, SERVICE_ALL_ACCESS,
                                     SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                     bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        const DWORD e = ::GetLastError();
        if (e == ERROR_SERVICE_EXISTS) std::printf("BulwarkService 已存在。\n");
        else { std::fprintf(stderr, "CreateService failed (%lu).\n", e); rc = 1; }
    } else {
        std::printf("BulwarkService 已安装(自动启动)。用 `sc start BulwarkService` 启动。\n");
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
    return rc;
}

int uninstallService() {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { std::fprintf(stderr, "OpenSCManager failed (%lu). 需管理员权限。\n", ::GetLastError()); return 1; }
    int rc = 0;
    SC_HANDLE svc = ::OpenServiceW(scm, kSvcName, SERVICE_STOP | DELETE);
    if (!svc) {
        std::fprintf(stderr, "OpenService failed (%lu)(可能未安装)。\n", ::GetLastError());
        rc = 1;
    } else {
        SERVICE_STATUS st = {};
        ::ControlService(svc, SERVICE_CONTROL_STOP, &st); // 尽力停止
        if (::DeleteService(svc)) std::printf("BulwarkService 已卸载。\n");
        else { std::fprintf(stderr, "DeleteService failed (%lu).\n", ::GetLastError()); rc = 1; }
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
    return rc;
}

} // namespace

int main(int argc, char** argv) {
    // 服务控制动词在创建 QCoreApplication 之前处理(无需 Qt)。
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--install") return installService();
        if (a == "--uninstall") return uninstallService();
        if (a == "--service") {
            g_svcArgc = argc;
            g_svcArgv = argv;
            SERVICE_TABLE_ENTRYW table[] = {
                { const_cast<LPWSTR>(kSvcName), serviceMain },
                { nullptr, nullptr },
            };
            if (!::StartServiceCtrlDispatcherW(table)) {
                // 不是被 SCM 拉起(如手动带 --service 运行)-> 退回控制台模式。
                return serviceRun(argc, argv);
            }
            return 0;
        }
    }
    // 默认:控制台前台运行(含 --inspect 自检)。
    return serviceRun(argc, argv);
}
