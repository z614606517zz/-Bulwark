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
#include "bulwark/service/IpcClientAuth.h"
#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/BaselineStore.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/PersistenceScanner.h"
#include "bulwark/service/JunkCleaner.h"
#include "bulwark/service/ForensicsService.h"
#include "bulwark/service/Worker.h"
#include "bulwark/service/AttackChainEngine.h"
#include "bulwark/service/UpdateService.h"
#include "bulwark/Version.h"

#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/monitoring/ProcessEnumerator.h"
#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/reputation/HashReputationClients.h"
#include "bulwark/service/reputation/VirusTotalClient.h"
#include "bulwark/service/reputation/ThreatBookClient.h"
#include "bulwark/service/reputation/AggregateReputationService.h"
#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/service/reputation/ReputationCache.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/reputation/ThreatFoxFeed.h"
#include "bulwark/service/reputation/ThreatIntelUploader.h"
#include "bulwark/service/ThreatIntelContribStore.h"
#include "bulwark/service/reputation/ProxyReputationService.h"

#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/DefaultRules.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <thread>
#include <QFileInfo>
#include <QProcess>
#include <QStringList>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QTemporaryDir>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h> // SCM: StartServiceCtrlDispatcher / CreateService / SetServiceStatus

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
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

// ============================ 垃圾清理:只读干跑 =============================
//
// --junk-scan
//
// 跑一次真实的垃圾扫描并把结果打出来,然后立即退出。【纯只读】:调的是 JunkCleaner::scan,
// 它一个字节都不删;也不启动事件循环 / ETW / 驱动 / IPC。
//
// 为什么值得有这个入口:垃圾清理是本产品里唯一会主动删用户文件的功能,它的正确性首先体现在
// 「它认为自己该动哪些位置」。有了这个模式,验证「范围对不对」就不必先起服务、开界面、点按钮
// —— 而且在真机上排查「为什么某类清不动」时,能直接看到是哪条根目录被护栏拒了(拒绝原因由
// JunkCleaner 写进服务日志)。
int runJunkScanDryRun(const BulwarkOptions& options) {
    QTextStream out(stdout);
    out << "=== JunkCleaner dry-run (read-only) ===\n";

    JunkCleanerPolicy pol;
    pol.enabled = options.DiskCleanup.Enabled;
    pol.minAgeHours = options.DiskCleanup.MinFileAgeHours;
    pol.maxFilesPerCategory = options.DiskCleanup.MaxFilesPerCategory;
    pol.maxSeconds = options.DiskCleanup.MaxSeconds;
    pol.excludes = options.DiskCleanup.ExcludePaths;
    pol.selfDir = QCoreApplication::applicationDirPath();
    // 诊断入口不接引擎,故不查用户信任名单(isUserTrusted 留空 = 不查)。这只影响
    // 「本来会被跳过的位置这里也算进来」,不会让它多删什么 —— 它根本不删。

    bulwark::ipc::JunkScanRequestPayload req;
    const bulwark::ipc::JunkScanResponsePayload res = JunkCleaner::scan(req, pol);

    out << "enabled: " << (res.enabled ? "true" : "false") << "\n";
    out << "minAgeHours: " << res.minAgeHours << "\n";
    out << "truncated: " << (res.truncated ? "true" : "false") << "\n";
    out << "elapsedMs: " << res.elapsedMs << "   unreadableDirs: " << res.unreadable << "\n";
    out << "message: " << res.message << "\n";
    out << "total: " << res.totalBytes << " bytes / " << res.totalFiles << " files\n\n";
    for (const bulwark::JunkCategoryResult& c : res.categories) {
        out << QStringLiteral("[%1] %2\n")
                   .arg(bulwark::junk::categoryKey(c.category), c.title);
        out << QStringLiteral("    risk=%1 available=%2 cleanable=%3 recommended=%4 elapsed=%5ms\n")
                   .arg(c.risk == bulwark::junk::Risk::Safe ? QStringLiteral("safe")
                                                            : QStringLiteral("caution"))
                   .arg(c.available).arg(c.cleanable).arg(c.recommended).arg(c.elapsedMs);
        out << QStringLiteral("    %1 bytes / %2 files / %3 skipped / %4 unreadable\n")
                   .arg(c.bytes).arg(c.fileCount).arg(c.skipped).arg(c.unreadable);
        if (!c.message.isEmpty())
            out << "    note: " << c.message << "\n";
        for (const bulwark::JunkLocation& loc : c.locations)
            out << QStringLiteral("      - %1  (%2 bytes / %3 files / %4 skipped / %5 unreadable)"
                                  "%6\n")
                       .arg(loc.path).arg(loc.bytes).arg(loc.fileCount).arg(loc.skipped)
                       .arg(loc.unreadable)
                       .arg(loc.note.isEmpty() ? QString()
                                               : QStringLiteral("  [%1]").arg(loc.note));
    }
    out.flush();
    return 0;
}

// ============================ 大文件查找:只读干跑 ============================
//
// --large-files [阈值MB]
//
// 与 --junk-scan 同样是纯只读的诊断入口。大文件查找本身就没有删除路径(见 LargeFileScanner
// 的说明),所以这个模式和生产路径做的是完全同一件事,只是把结果打到 stdout。
int runLargeFileScan(const BulwarkOptions& options, qint64 minBytes) {
    QTextStream out(stdout);
    out << "=== LargeFileScanner dry-run (read-only) ===\n";

    LargeFileScannerPolicy pol;
    pol.excludes = options.DiskCleanup.ExcludePaths;
    pol.selfDir = QCoreApplication::applicationDirPath();

    bulwark::ipc::LargeFileScanRequestPayload req;
    req.minBytes = minBytes;
    req.limit = 30;
    const bulwark::ipc::LargeFileScanResponsePayload res = LargeFileScanner::scan(req, pol);

    out << "minBytes: " << res.minBytes << "\n";
    out << "scannedFiles: " << res.scannedFiles << "   unreadableDirs: " << res.unreadable << "\n";
    out << "truncated: " << (res.truncated ? "true" : "false")
        << "   elapsedMs: " << res.elapsedMs << "\n";
    out << "message: " << res.message << "\n";
    out << "listed: " << res.files.size() << " files / " << res.totalBytes << " bytes\n\n";
    for (const bulwark::LargeFileEntry& f : res.files) {
        out << QStringLiteral("%1 MB  %2  [%3]\n")
                   .arg(f.bytes / (1024 * 1024), 6)
                   .arg(f.path)
                   .arg(f.suffix.isEmpty() ? QStringLiteral("-") : f.suffix);
    }
    out.flush();
    return 0;
}

// ============================ 攻击链回归测试 =================================
//
// --attackchain-selftest <table.json>
//
// 为什么需要它(而 --attackchain-check 顶不上):后者的表是从服务器现拉的。于是
//   * 服务器明天重挖出一张不同的表,数字就变了 —— 分不清「代码改坏了」还是「表变了」;
//   * 表里恰好没有 hard/strong 档时,降档逻辑一次都不会被触发,测了等于没测
//     (实测 v16 表 21 条全是 ask,降档机制装上后 capped 恒为 0);
//   * 离线 / CI 里根本跑不起来。
// 本模式改成从【固定的本地语料】装表,把上面三点全部消掉:同一份输入永远得到同一份结论。
//
// 状态隔离:引擎用临时目录(dataDirOverride),绝不碰 %ProgramData% 下真实的组合表缓存与
// 命中记录 —— 否则跑一次测试就把机器上的真表冲掉了。
// 配置也全部就地构造,不读 appsettings.json —— 否则有人改了本机配置,测试结论跟着变。
int runAttackChainSelfTest(const QString& tablePath) {
    QTextStream out(stdout);
    out << "=== AttackChain regression selftest ===\n";
    out << "fixture: " << tablePath << "\n";

    QFile f(tablePath);
    if (!f.open(QIODevice::ReadOnly)) {
        out << "FAIL: cannot open fixture\n";
        return 1;
    }
    const QByteArray raw = f.readAll();
    f.close();
    QJsonParseError perr{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        out << "FAIL: fixture is not valid JSON: " << perr.errorString() << "\n";
        return 1;
    }
    const QJsonObject payload = doc.object();
    const QJsonObject expect = payload.value(QLatin1String("_expect")).toObject();
    const QJsonObject covObj = payload.value(QLatin1String("_coverage")).toObject();

    int pass = 0, total = 0;
    const auto check = [&](bool ok, const QString& what) {
        ++total;
        if (ok) ++pass;
        out << (ok ? "  PASS " : "  FAIL ") << what << "\n";
    };
    const auto checkInt = [&](int got, const QJsonValue& want, const QString& what) {
        const int w = want.toInt(-987654);
        ++total;
        const bool ok = (got == w);
        if (ok) ++pass;
        out << (ok ? "  PASS " : "  FAIL ") << what << " = " << got;
        if (!ok) out << " (expected " << w << ")";
        out << "\n";
    };

    // ---- 就地构造配置:全确定,不受 appsettings 影响 ----
    AttackChainOptions opt;
    opt.Enabled = true;
    opt.DryRun = false;          // 必须强制模式,否则 applyHitToEvent 不产生分数,无从断言
    opt.MinGrade = QStringLiteral("ask");   // 全档收下,不在装载期就把语料过滤掉
    opt.LedgerRetentionMinutes = 30;
    opt.LedgerMaxProcesses = 4096;

    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        out << "FAIL: cannot create temp dir for state isolation\n";
        return 1;
    }
    AttackChainEngine engine(opt, tmp.path());

    if (!engine.applyTable(payload)) {
        out << "FAIL: applyTable rejected the fixture\n";
        return 1;
    }

    // ---- 覆盖面同样来自语料 ----
    CoverageProfile cov;
    cov.driverSource   = covObj.value(QLatin1String("driverSource")).toBool();
    cov.etwFileEvents  = covObj.value(QLatin1String("etwFileEvents")).toBool();
    cov.etwDns         = covObj.value(QLatin1String("etwDns")).toBool();
    cov.moduleSignature= covObj.value(QLatin1String("moduleSignature")).toBool();
    cov.cmdLineInBand  = covObj.value(QLatin1String("cmdLineInBand")).toBool();
    for (const QJsonValue& v : covObj.value(QLatin1String("registryWatch")).toArray())
        cov.registryWatch << v.toString();
    for (const QJsonValue& v : covObj.value(QLatin1String("fileWatch")).toArray())
        cov.fileWatch << v.toString();
    const int capped = engine.setCoverage(cov);

    // ---- 1) 装载期的剔除 ----
    out << "\n-- load-time filtering --\n";
    const ReachabilityReport rep = engine.analyzeReachability(cov);
    checkInt(rep.serverPatterns, expect.value(QLatin1String("server_patterns")), QStringLiteral("server_patterns"));
    checkInt(rep.droppedConflict, expect.value(QLatin1String("dropped_conflict")), QStringLiteral("dropped_conflict"));
    checkInt(rep.droppedRedundant, expect.value(QLatin1String("dropped_redundant")), QStringLiteral("dropped_redundant"));
    checkInt(engine.patternCount(), expect.value(QLatin1String("loaded")), QStringLiteral("loaded"));

    // ---- 2) 可观测性分类 ----
    out << "\n-- reachability --\n";
    checkInt(rep.reachable, expect.value(QLatin1String("reachable")), QStringLiteral("reachable"));
    checkInt(rep.sparse, expect.value(QLatin1String("sparse")), QStringLiteral("sparse"));
    checkInt(rep.dead, expect.value(QLatin1String("dead")), QStringLiteral("dead"));

    // ---- 3) 降档与打分 ----
    //
    // 分数不直接调 gradeScore,而是走【真实路径】applyHitToEvent -> 读 chainScore:
    // 那才是生产里决定处置的那条线。直接测内部函数会漏掉「打分用了 serverGrade 而不是
    // 生效 grade」这类接线错误 —— 而那正是让整套降档变成装饰的方式。
    out << "\n-- grade capping & scoring --\n";
    checkInt(capped, expect.value(QLatin1String("capped")), QStringLiteral("capped"));
    const QJsonObject wantPats = expect.value(QLatin1String("patterns")).toObject();
    const QVector<ChainPattern> pats = engine.patternSnapshot();
    check(pats.size() == wantPats.size(),
          QStringLiteral("每条装载的组合都有期望值(%1 条 vs 期望表 %2 项)")
              .arg(pats.size()).arg(wantPats.size()));
    for (const ChainPattern& p : pats) {
        if (!wantPats.contains(p.key)) {
            check(false, QStringLiteral("组合 %1 在期望表里没有条目").arg(p.key));
            continue;
        }
        const QJsonObject w = wantPats.value(p.key).toObject();
        check(p.grade == w.value(QLatin1String("grade")).toString(),
              QStringLiteral("%1 生效强度 %2(期望 %3)")
                  .arg(p.key, p.grade, w.value(QLatin1String("grade")).toString()));

        ChainHit hit;
        hit.pattern = p;
        hit.titles = p.markers;
        bulwark::SecurityEvent se;
        se.type = bulwark::EventType::ProcessCreate;
        se.actorPid = 990000;
        se.actorPath = QStringLiteral("C:\\x\\fixture.exe");
        se.actorSigned = true;   // 签名健康 -> 分数只可能来自组合命中
        engine.applyHitToEvent(se, hit);
        const int wantScore = w.value(QLatin1String("score")).toInt(-1);
        check(se.chainScore == wantScore,
              QStringLiteral("%1 分数 %2(期望 %3)").arg(p.key).arg(se.chainScore).arg(wantScore));
        check(se.chainHardIndicator, QStringLiteral("%1 置了硬指标").arg(p.key));
    }

    // ---- 4) 记账不再为「什么都没命中」的事件建账 ----
    //
    // 这一条钉住的是一个真实的泄漏:原实现一进 observe 就 ledger_[pid](QHash::operator[]
    // 会默认插入),于是每个产生过任意事件的 PID 都留下一条空账;而淘汰当时挂在函数末尾、
    // 两处 early-return 之后,只有【组合命中】时才跑 —— 命中是罕见事件,于是保留窗口与
    // 容量上限从未生效,记账表实际只增不减。
    out << "\n-- ledger hygiene --\n";
    {
        // 签名健康 + 主体不是 powershell/schtasks + 命令行不匹配 -> 一个 ProcessCreate 标记都不命中。
        for (int i = 0; i < 3000; ++i) {
            bulwark::SecurityEvent e;
            e.type = bulwark::EventType::ProcessCreate;
            e.actorPid = 100000 + i;                       // 每条一个新 PID
            e.actorPath = QStringLiteral("C:\\Windows\\System32\\notepad.exe");
            e.actorSigned = true;
            e.commandLine = QStringLiteral("notepad.exe readme.txt");
            engine.observe(e);
        }
        checkInt(engine.trackedProcessCount(), QJsonValue(0),
                 QStringLiteral("3000 条零命中事件后的记账进程数"));
    }

    // ---- 5) 命中只在凑齐时发生,且同一进程同一组合只报一次 ----
    out << "\n-- combo completion --\n";
    {
        const int pid = 200001;
        bulwark::SecurityEvent r;
        r.type = bulwark::EventType::RegistryWrite;
        r.actorPid = pid;
        r.actorPath = QStringLiteral("C:\\x\\dropper.exe");
        r.target = QStringLiteral("\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil");
        r.actorSigned = true;
        check(!engine.observe(r).has_value(), QStringLiteral("只置位 m_run 时不应命中(组合还缺一个动作)"));
        checkInt(engine.trackedProcessCount(), QJsonValue(1), QStringLiteral("命中了标记 -> 建账 1 条"));

        bulwark::SecurityEvent d;
        d.type = bulwark::EventType::DnsQuery;
        d.actorPid = pid;
        d.actorPath = r.actorPath;
        d.target = QStringLiteral("evil.example.com");
        d.actorSigned = true;
        const auto hit = engine.observe(d);
        check(hit.has_value(), QStringLiteral("补齐 m_dns 后应当命中"));
        if (hit)
            check(hit->pattern.key == expect.value(QLatin1String("hit_pattern_key")).toString(),
                  QStringLiteral("命中的是期望的那条组合:%1").arg(hit->pattern.key));

        // 再来一条同类事件:同一进程同一组合只报一次(firedPatterns 去重)。
        bulwark::SecurityEvent d2 = d;
        d2.target = QStringLiteral("evil2.example.com");
        check(!engine.observe(d2).has_value(), QStringLiteral("同一进程同一组合不重复上报"));
    }

    // ---- 6) PID 复用必须清账 ----
    //
    // Windows 会回收 PID。若不清账,前一个进程的动作会被算到新进程头上 —— 那是最典型的
    // 误报来源。这里先用 PID X 置位 m_run,再让同一个 PID 换成另一个映像去置位 m_dns:
    // 旧账若没清掉,组合就会「凑齐」并误报。
    out << "\n-- PID reuse --\n";
    {
        const int pid = 200002;
        bulwark::SecurityEvent r;
        r.type = bulwark::EventType::RegistryWrite;
        r.actorPid = pid;
        r.actorPath = QStringLiteral("C:\\x\\first.exe");
        r.target = QStringLiteral("\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\a");
        r.actorSigned = true;
        engine.observe(r);

        bulwark::SecurityEvent d;
        d.type = bulwark::EventType::DnsQuery;
        d.actorPid = pid;
        d.actorPath = QStringLiteral("C:\\x\\second.exe");   // 同 PID、换了映像 = PID 被复用
        d.target = QStringLiteral("other.example.com");
        d.actorSigned = true;
        check(!engine.observe(d).has_value(),
              QStringLiteral("PID 复用后旧账已清,不应凭上一个进程的动作凑齐组合"));
    }

    // ---- 7) 确定性:同一份语料重放两次必须得到同一结论 ----
    //
    // Qt6 的 QHash 每进程随机化种子,而装载期的分桶/索引都走 QHash。这一条防的是
    // 「结论依赖容器迭代顺序」——那种缺陷平时全绿,换台机器或换次运行才炸。
    out << "\n-- determinism --\n";
    {
        QTemporaryDir tmp2;
        AttackChainEngine e2(opt, tmp2.path());
        e2.applyTable(payload);
        const int capped2 = e2.setCoverage(cov);
        QStringList a, b;
        for (const ChainPattern& p : pats)
            a << (p.key + QLatin1Char('=') + p.grade);
        for (const ChainPattern& p : e2.patternSnapshot())
            b << (p.key + QLatin1Char('=') + p.grade);
        a.sort();
        b.sort();
        check(capped2 == capped && a == b, QStringLiteral("二次装载得到完全相同的组合与档位"));
    }

    out << "\n=== " << pass << "/" << total << " passed ===\n";
    out.flush();
    return (pass == total) ? 0 : 2;
}

// 攻击链组合表自检(--attackchain-check)。只读:拉一次组合表、解析、打印统计与前几条组合,然后退出。
// 【不启动】事件循环 / ETW / 内核驱动 / IPC / 任何处置 —— 所以在装着运行中驱动的真机上也能安全执行。
// 用途:上线前验证「配置解析 -> 端点连通 -> 回包解析 -> 标记与组合装载」这条链路真的通。
int runAttackChainCheck() {
    QTextStream out(stdout);
    BulwarkOptions options;
    const QString appsettings =
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("appsettings.json"));
    if (!options.loadFromFile(appsettings)) {
        out << "appsettings.json parse FAILED: " << appsettings << "\n";
        return 1;
    }
    const AttackChainOptions& ac = options.AttackChainEngine;
    out << "=== AttackChain self-check ===\n";
    out << "Enabled: " << (ac.Enabled ? "true" : "false")
        << "   DryRun: " << (ac.DryRun ? "true" : "false")
        << "   MinGrade: " << ac.MinGrade << "\n";
    const QString base = ac.BaseUrl.trimmed().isEmpty() ? options.ReputationProxy.resolveBaseUrl()
                                                        : ac.BaseUrl.trimmed();
    out << "Endpoint: " << ReputationProxyOptions::maskUrl(base) << "\n";
    if (!ac.Enabled) { out << "-> disabled, nothing to do\n"; return 0; }
    if (base.trimmed().isEmpty()) { out << "-> no endpoint resolved\n"; return 1; }

    reputation::ReputationCurl::proxyUrl = options.ProxyUrl;
    AttackChainEngine engine(ac);
    AttackChainFeed feed(ac, base);
    out << "\nfetching table ...\n";
    out.flush();

    // 直接同步拉一次(不起后台线程):setTableReady 的回调本会被编组到主线程,
    // 而自检模式没有事件循环,故这里改为「拉完立刻在本线程装载」。
    bool loaded = false;
    feed.setTableReady([&](const QJsonObject& payload) { loaded = engine.applyTable(payload); });
    if (!feed.fetchOnceForCheck())
        out << "fetch FAILED (see service.log for the HTTP status)\n";

    // 拉取失败 / 服务器回 unchanged 时退回磁盘缓存。
    //
    // 【这一步是自检能不能在现场用起来的关键】。原实现只在「本次拉取成功且内容有变化」时
    // 才往下走,否则打一行 applyTable returned false 就退出 —— 而最需要这份诊断的场合恰恰是
    // 「虚拟机里没有出网 / 服务器暂时不可达」。那时服务本身照常用磁盘缓存的表在工作,
    // 自检却什么都不报,等于在最该说话的时候沉默。
    if (!loaded && engine.loadFromDisk()) {
        out << "(fell back to the on-disk cached table)\n";
        loaded = true;
    }
    if (!loaded) {
        out << "no usable table (fetch failed / unchanged, and no on-disk cache)\n";
        out.flush();
        return 1;
    }

    out << "table loaded OK\n";
    out << "  version : " << engine.version() << "\n";
    out << "  patterns: " << engine.patternCount() << "\n";
    out << "  markers : " << engine.markerCount() << "\n";

    // 覆盖面与定档。必须【在自检之前】做,顺序也必须与 serviceRun 里一致:
    //   补齐前的覆盖面 -> 派生受关注键 -> 加进覆盖面 -> setCoverage 定档
    // 否则自检打印的档位和服务实际生效的档位是两回事,而这份报告的全部价值就在于「所见即所行」。
    const CoverageProfile cov = CoverageProfile::fromOptions(options);
    // derivedRegistryWatch 必须用【补齐前】的覆盖面算 —— 它找的正是「因为键不在名单里而
    // 结构性死掉」的标记,拿补齐后的去算会一个都找不到。
    const QStringList derived = engine.derivedRegistryWatch(cov);
    CoverageProfile covLive = cov;
    covLive.registryWatch += derived;
    const int capped = engine.setCoverage(covLive);
    out << "  capped  : " << capped << " 条组合按本机情况降档(正常语料命中 / 依赖稀疏事件)\n";

    // 合成事件走一遍「标记置位 -> 累积 -> 组合命中」。实机触发靠不住(驱动对文件写入
    // 1/32 采样),这一步才是对组合逻辑的确定性验证。
    QStringList detail;
    const QPair<int, int> st = engine.selfTest(&detail);
    out << "\n=== combo logic self-test ===\n";
    for (const QString& d : detail)
        out << d << "\n";

    // 第二段:命中【之后】那份贡献能不能活到裁决闸门。组合逻辑全绿但贡献被 analyze
    // 擦掉的情况真实发生过(组合表上线后一次都没生效),故必须单独验。
    QStringList vdetail;
    const QPair<int, int> vt = engine.verdictPathSelfTest(&vdetail);
    out << "\n=== verdict path self-test ===\n";
    for (const QString& d : vdetail)
        out << d << "\n";

    // 第三段:实机可达性。上面两段全绿也只说明「逻辑对」,说明不了「真机上点得亮」——
    // 标记依赖的事件维度本身是有条件才上报的(受关注注册表键名单 / 文件写入采样 /
    // 模块加载位置过滤 / 命令行靠读 PEB)。这一段把差距量化出来。
    out << "\n=== live reachability ===\n";
    out << "  event source   : " << (cov.driverSource ? "Driver (kernel + ETW)" : "user-mode (ETW only)") << "\n";
    out << "  registry watch : " << cov.registryWatch.size() << " entries\n";
    out << "  new-file watch : " << cov.fileWatch.size() << " entries\n";

    // 【为什么要报两遍】原实现只用 cov(补齐【前】的覆盖面)算一次可达性,然后把 derived
    // 另起一行打出来。于是自检报的可达率并不是服务真正达到的可达率 —— 实测 24 条下发里
    // 有 4 条被判「结构性死路」,全都因为同一个标记要 *\SystemCertificates\* 而该键不在名单里;
    // 可 derivedRegistryWatch 恰好就会为它派生出 \SystemCertificates\,服务一启动那 4 条就活了。
    // 结果是:自检说 62.5%,服务实际是 79.2%。这个诊断本来就是「判断本引擎是否真实有用的
    // 唯一客观标尺」,标尺自己偏一截,读的人会照着一个不存在的问题去查。
    // 故:补齐前的数字仍然报(它说明「不派生的话会损失多少」),但【以补齐后为准】。
    const ReachabilityReport rr = engine.analyzeReachability(cov);
    if (derived.isEmpty()) {
        for (const QString& d : rr.lines)
            out << d << "\n";
        out << "  derived registry watch additions: (none needed)\n";
    } else {
        out << "  -- 按当前 appsettings 的名单(尚未派生补齐)--\n";
        for (const QString& d : rr.lines)
            out << d << "\n";
        out << "  derived registry watch additions: " << derived.join(QStringLiteral(", ")) << "\n";

        const ReachabilityReport rrAfter = engine.analyzeReachability(covLive);
        out << "  -- 服务启动补齐这 " << derived.size() << " 个键之后(这才是实际运行时的口径)--\n";
        for (const QString& d : rrAfter.lines)
            out << d << "\n";
    }

    const bool comboOk = (st.first == st.second && st.second > 0);
    const bool verdictOk = (vt.first == vt.second && vt.second > 0);
    out.flush();
    return (comboOk && verdictOk) ? 0 : 2;
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

    // 控制台代码页对齐到 UTF-8。诊断入口(--inspect / --attackchain-check / --junk-scan /
    // --large-files)的结论文案是中文,而 QTextStream(stdout) 在 Qt6 里固定按 UTF-8 编码;
    // 中文版 Windows 的控制台默认是 936(GBK),于是每一行中文都渲染成乱码 —— 一个「给人看的
    // 诊断输出」看不懂,就等于没有。
    //
    // 只影响控制台【渲染】:输出被重定向到文件或管道时,拿到的本来就是原始 UTF-8 字节,这行
    // 改不到它。以服务身份运行时没有控制台,调用直接失败返回,无副作用 —— 所以不需要先判断
    // 是否附着控制台。
    ::SetConsoleOutputCP(CP_UTF8);

    // 诊断自检(在任何服务初始化之前处理):只读取证并退出,绝不启动监控/处置。
    {
        const QStringList args = QCoreApplication::arguments();
        const int idx = args.indexOf(QStringLiteral("--inspect"));
        if (idx >= 0)
            return runInspect(idx + 1 < args.size() ? args.at(idx + 1) : QString());
        if (args.contains(QStringLiteral("--attackchain-check")))
            return runAttackChainCheck();
        // 回归测试:从固定语料装表并逐项比对。离线、确定、状态隔离(见 runAttackChainSelfTest)。
        const int sidx = args.indexOf(QStringLiteral("--attackchain-selftest"));
        if (sidx >= 0) {
            if (sidx + 1 >= args.size()) {
                QTextStream(stdout) << "usage: --attackchain-selftest <table.json>\n";
                return 1;
            }
            return runAttackChainSelfTest(args.at(sidx + 1));
        }
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

    // 垃圾清理的只读干跑。放在这里(而不是上面那个诊断块)是因为它要用真实的 appsettings 配置;
    // 放在存储层与事件源初始化【之前】,所以它不会碰规则库、不会起 ETW / 驱动 / IPC。
    //
    // ⚠ 必须显式 stopFileLog():此处已经在 startFileLog() 之后,而文件日志是一条后台写入线程。
    // 直接 return 会让它在全局析构期间还活着,进程退出时以 0xC0000409(STATUS_STACK_BUFFER_OVERRUN)
    // 收场 —— 结果全都打印对了、退出码却是崩溃。上面那两个诊断入口(--inspect /
    // --attackchain-selftest)在 startFileLog() 【之前】就返回了,所以它们没有这个问题;
    // 任何以后加在这个位置的诊断入口都得记得停日志线程。
    if (QCoreApplication::arguments().contains(QStringLiteral("--junk-scan"))) {
        const int rc = runJunkScanDryRun(options);
        stopFileLog();
        return rc;
    }
    // 同上,也必须显式 stopFileLog()(见上面那段关于 0xC0000409 的说明)。
    {
        const QStringList args = QCoreApplication::arguments();
        const int li = args.indexOf(QStringLiteral("--large-files"));
        if (li >= 0) {
            qint64 minBytes = 0;   // 0 = 用 LargeFileScanner 的默认阈值(100 MB)
            if (li + 1 < args.size()) {
                bool ok = false;
                const qint64 mb = args.at(li + 1).toLongLong(&ok);
                if (ok && mb > 0)
                    minBytes = mb * 1024 * 1024;
            }
            const int rc = runLargeFileScan(options, minBytes);
            stopFileLog();
            return rc;
        }
    }

    // 存储层。
    SettingsStore settingsStore;
    RuleStore ruleStore;
    AuditLog audit;
    FirstSeenStore firstSeen; // 本机「首见」哈希库,供富化阶段判定低流行度
    QuarantineManager quarantine; // 隔离区(恶意载荷失活 + 可逆还原),供威胁清理使用
    VtScanHistoryStore vtHistory; // VirusTotal 扫描历史(去重 + 展示)
    // 威胁情报共享的本机暂存队列(默认关;仅在用户开启开关后才会有数据进来)。
    ThreatIntelContribStore intelContrib;
    EventHistoryStore eventHistory; // 结构化事件历史(内存环形 + JSONL 落盘,重启保留),供 UI 回填
    BaselineStore baselineStore;  // 行为基线画像持久化(baseline.json,原子写)
    // ECS/SIEM 告警导出(默认关)。构造即按 ExportEcsAlerts 决定是否真正写盘;
    // 此前该配置项与 AlertExporter / EcsAlertFormatter 整条链从未被接入产品。
    AlertExporter alertExporter(options.ExportEcsAlerts);

    // 运行时设置:appsettings 默认值,若存在 settings.json 则覆盖。UI 经 IPC 读取/更新。
    bulwark::RuntimeSettings settings;
    settings.trustSignedActors = options.TrustSignedActors;
    settings.eventSource = options.EventSource;
    // appsettings 的 DefaultAction 作为「默认拦截未知行为」的初值。此前该配置项只被解析、
    // 从无消费点;而它对应的运行时开关 defaultBlock 现在真正决定弹窗超时的兜底方向
    //(见 Worker::resolvePromptByDefault),所以这个部署期初值才有了意义。
    // settings.json 存在时以用户在 UI 里的选择为准(下面的 load 会整体覆盖)。
    settings.defaultBlock = (options.DefaultAction == bulwark::VerdictAction::Block);
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

    // appsettings 的 TrustedDirectories:整目录信任。此前该配置项只被 bindStrList 解析一次就
    // 没人读 —— 目录信任功能本身是活的(UI 加白走 DefenseRule::createTrustDirectory),
    // 但这个「部署时预置信任目录」的入口是死的。现在按同一种信任项生成,语义与 UI 加白完全一致
    //(引擎在威胁检测【之前】命中即放行,并跳过全部后台扫描)。
    {
        int seeded = 0;
        for (const QString& raw : options.TrustedDirectories) {
            const QString dir = raw.trimmed();
            if (dir.isEmpty())
                continue;
            const bulwark::DefenseRule tr = bulwark::DefenseRule::createTrustDirectory(
                dir, QStringLiteral("appsettings 预置信任目录"));
            bool dup = false;
            for (const bulwark::DefenseRule& r : rules)
                if (r.isTrustEntry() && !r.actorPattern.isEmpty()
                    && r.actorPattern.compare(tr.actorPattern, Qt::CaseInsensitive) == 0) {
                    dup = true;
                    break;
                }
            if (!dup) { rules.append(tr); ++seeded; }
        }
        if (seeded > 0)
            log.info(QStringLiteral("已从 appsettings 预置 %1 个信任目录(该目录下程序直接放行)。").arg(seeded));
    }
    engine.loadRules(rules);
    log.info(QStringLiteral("已加载 %1 条规则(内置 + 用户/信任/情报)。").arg(rules.size()));

    // 行为基线画像:从磁盘灌回上次的画像,使「偏离自身历史基线」这条检测【跨重启保留学习成果】。
    // 此前 BaselineStore 从未被构造,基线纯内存 —— 每次服务重启都要重新经历学习期,期间该维度
    // 实际不产出任何信号。灌回失败(首次运行 / 文件损坏)时静默降级为空画像,与原行为一致。
    if (const auto snap = baselineStore.load()) {
        engine.importBaseline(*snap);
        log.info(QStringLiteral("已载入行为基线画像:%1 个程序。").arg(snap->programs.size()));
    } else {
        log.info(QStringLiteral("无历史行为基线画像(首次运行或文件缺失),从空画像开始学习。"));
    }

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
    // 中央信誉代理(可选,opt-in via appsettings ReputationProxy.Enabled):启用时哈希查询
    // 优先走服务端共享缓存 + 服务端持有的 API Key;任何失败(未启用 / 网络 / HTTP / 权威未成功)
    // 透明回退到本地直连聚合器,保护绝不退化。查询仍经 ReputationManager 走本地 ReputationCache,
    // 故命中结果本地分级 TTL 缓存自动覆盖代理结论(重复查询零往返)。
    reputation::ProxyReputationService repProxyFirst(options, &repAggregate);
    // 预热中央代理健康缓存:后台探测一次,待 UI 连接查询状态灯时即有真实结论(而非「检测中」)。
    (void)repProxyFirst.healthCheckNonBlocking();
    // 把查毒的取数路径写进日志 —— 这是最容易被误解的一环(到底走服务器还是本地),明确记一行。
    // 端点一律以掩码形式记录(https://***:port),绝不在日志里泄露服务器地址(便携包隐藏端点意图)。
    if (options.ReputationProxy.ServerOnly) {
        // 这一条要压在最前面:它决定了「这台机器会不会拿本机密钥外发到第三方」,是排查取数路径
        // 时最先要看的一句。它与下面几条互斥,不能让「未收录即改用本机密钥直连」那句同时出现。
        const QString ep = options.ReputationProxy.resolveBaseUrl().trimmed();
        const bool usable = options.ReputationProxy.Enabled && !ep.isEmpty();
        log.info(QStringLiteral("[Aggregate] 哈希信誉取数:【本机不动用任何第三方情报源】—— 云端只向中央服务器 %1 "
                                "查询「是否已收录」;不用本机密钥查 VirusTotal/MalwareBazaar/OTX/微步/"
                                "MetaDefender/HybridAnalysis,不拉行为画像,不上传文件。"
                                "未收录 => 无云端结论(只剩本地启发式/规则/内核基线兜底)。%2")
                     .arg(usable ? ReputationProxyOptions::maskUrl(ep) : QStringLiteral("(未配置)"))
                     .arg(usable ? QString()
                                 : QStringLiteral("⚠ 中央服务器未启用/未配置 —— 当前【完全没有】云端信誉。")));
    } else if (options.ReputationProxy.Enabled && !options.ReputationProxy.resolveBaseUrl().trimmed().isEmpty()) {
        const int freshCap = options.ReputationProxy.FreshQueriesPerDay;
        if (options.ReputationProxy.LookupOnly) {
            // 「只查收录」模式:别再讲「每日新鲜查询上限」——那条预算在这个模式下压根不生效,
            // 日志里出现一个用不掉的数字只会让人以为还有别的路径在花服务器配额。
            log.info(QStringLiteral("[Aggregate] 哈希信誉取数:仅向中央服务器 %1 查询「是否已收录」"
                                    "(超时 %2s,永不请求服务器查询它的上游情报源);未收录即改用"
                                    "本机密钥直连各情报源;服务器不可用时同样走本地,"
                                    "离线期间熔断跳过,每 60s 半开重试一次。")
                         .arg(ReputationProxyOptions::maskUrl(options.ReputationProxy.resolveBaseUrl()))
                         .arg(options.ReputationProxy.QueryTimeoutSeconds));
        } else {
            log.info(QStringLiteral("[Aggregate] 哈希信誉取数:优先中央服务器 %1(超时 %2s,每日新鲜查询上限 %3),"
                                    "服务器缓存命中不限次;超额或不可用自动回退本地直连聚合器;"
                                    "离线期间熔断跳过,每 60s 半开重试一次。")
                         .arg(ReputationProxyOptions::maskUrl(options.ReputationProxy.resolveBaseUrl()))
                         .arg(options.ReputationProxy.QueryTimeoutSeconds)
                         .arg(freshCap > 0 ? QString::number(freshCap) : QStringLiteral("不限")));
        }
    } else {
        log.info(QStringLiteral("[Aggregate] 哈希信誉取数:仅本地直连各情报源(中央服务器未配置/未启用)。"));
    }
    int cleanTtlDays = options.VirusTotal.CleanCacheTtlDays;
    if (cleanTtlDays < 1) cleanTtlDays = 7;
    reputation::ReputationCache repCache(static_cast<qint64>(cleanTtlDays) * 24LL * 3600LL * 1000LL);
    reputation::ReputationManager repManager(&repProxyFirst, &repCache);
    // 按运行时设置启用各信誉源(默认全关,由 UI 开启;VT 虽有内置 Key 也须用户显式启用)。
    // 与 .NET 一致:信誉查询是 opt-in,未启用任何源则后台 worker 不查询。
    //
    // 【本机不动用任何第三方情报源】(ReputationProxy.ServerOnly)时一律置为全关,并且 UI 的
    // 逐源开关也不能把它们再打开 —— 否则这条策略就成了「一点就破」:用户在设置页拨一下开关,
    // 本机密钥就又开始直连第三方了,而他并不知道那和 appsettings 里的策略是矛盾的。
    // 开关本身照旧保存(设置页不撒谎地显示用户的选择),只是在这个模式下不生效。
    // 初始化与「设置变更」两处共用这一份实现,免得两边各写一份而慢慢跑偏。
    const bool serverOnlyMode = options.ReputationProxy.ServerOnly;
    std::function<void(const bulwark::RuntimeSettings&)> applyIntelSourceToggles =
        [&repAggregate, serverOnlyMode](const bulwark::RuntimeSettings& s) {
            if (serverOnlyMode) {
                repAggregate.setRuntimeEnabled(false, false, false, false, false, false);
                return;
            }
            repAggregate.setRuntimeEnabled(s.virusTotalEnabled, s.malwareBazaarEnabled,
                                           s.otxEnabled, s.threatBookEnabled,
                                           s.metaDefenderEnabled, s.hybridAnalysisEnabled);
        };
    applyIntelSourceToggles(settings);

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

    // 攻击链组合引擎:服务器从每日采集的真实样本沙箱记录里数出「哪几个动作凑一起就是病毒」,
    // 客户端下载该表并给每个进程记账,凑齐即定性。端点默认复用中央信誉代理(同一台服务器)。
    // 默认 dry-run —— 只记录不影响裁决,先在真机观察有无误伤,确认后再在 appsettings 关掉。
    AttackChainEngine attackChain(options.AttackChainEngine);
    AttackChainFeed attackChainFeed(options.AttackChainEngine,
                                    options.ReputationProxy.resolveBaseUrl());
    if (options.AttackChainEngine.Enabled) {
        // 先吃磁盘缓存:断网 / 服务器不可达时仍按上一次的表工作,不必等首次拉取成功。
        if (attackChain.loadFromDisk())
            // 日志里一律用【展示版本号】。内部整数只用于 setCurrentVersion 的下载判据 ——
            // 同一件事在日志里出现两个不同的版本号,读的人会以为哪里不一致。
            log.info(QStringLiteral("攻击链组合表已从本地缓存载入(版本 %1,组合 %2 条)。")
                         .arg(attackChain.versionLabel()).arg(attackChain.patternCount()));
        attackChainFeed.setCurrentVersion(attackChain.version());
        attackChainFeed.setTableReady([&attackChain, &attackChainFeed, &log](const QJsonObject& payload) {
            if (attackChain.applyTable(payload)) {
                // 记住新版本号:下次拉取带 since=,版本未变时服务器就不再下发规则体。
                attackChainFeed.setCurrentVersion(attackChain.version());
                log.info(QStringLiteral("攻击链组合表已更新:版本 %1,组合 %2 条。")
                             .arg(attackChain.versionLabel()).arg(attackChain.patternCount()));
            }
        });

        // ---- 让「注册表类标记」不会因为键不在监视名单里而静默失效 ----
        //
        // 注册表事件是【命中受关注键名单才上报】的(驱动 RegistryMonitor 与 ETW Kernel-Registry
        // 两侧同一模型)。于是服务器每天新挖出的组合里,只要有一个标记盯的键不在本机名单内,
        // 那条组合就永远凑不齐 —— 而界面上的组合计数照常显示它已装载,日志里也没有任何异常。
        // 这类退化只能靠对账发现,不能靠人记得去改 appsettings。
        //
        // 故在此按当前表反推:哪些注册表标记「结构性不可观测」,就为它们补上恰好够用的键片段。
        // 自限:覆盖已经够的标记一个字都不加(表没变化时这里返回空,机器上的事件量与之前逐条相同)。
        //
        // 【必须在这个位置】—— 下面的 DriverEventSource 会在构造时快照 options.ProtectedRegistryKeys,
        // ETW 源也在 start() 前一次性 setWatchLists。改在此处,两个消费者自动都拿到,
        // 不需要给任何一方新开一个运行时追加接口。
        //
        // 局限(如实记下):表在运行期更新后新增的键要到下次启动才生效。不在此做热追加是因为
        // ETW 的监视集由消费线程读取、须在 start 之前设定,为它加锁只为覆盖「当天新挖出的键」
        // 这一极低频场合,不值得在事件热路径上付代价。
        const QStringList derivedReg =
            attackChain.derivedRegistryWatch(CoverageProfile::fromOptions(options));
        if (!derivedReg.isEmpty()) {
            options.ProtectedRegistryKeys += derivedReg;
            log.info(QStringLiteral("攻击链:为 %1 个原本不可观测的注册表标记补充受关注键 —— %2"
                                    "(仅上报、不拦截;不补则这些标记所在的组合永远凑不齐)。")
                         .arg(derivedReg.size())
                         .arg(derivedReg.join(QStringLiteral(", "))));
        }

        // ---- 按本机实际观测能力给组合定档(只降不升)----
        //
        // 【必须在派生键补进 options 之后】。覆盖面是定档的输入,而它要等上面那一步做完才是
        // 最终值 —— 早一行调用,那些刚被救活的注册表标记还会被算成不可观测。
        //
        // 定档做两件事:正常软件语料里出现过的组合不许「不问就拦」;依赖本机稀疏事件
        //(驱动偏移 0 写的全局 1/32 采样、模块加载只在 \Temp\ 与 \Users\Public\ 才上报)
        // 的组合降一档 —— 服务器给的强度隐含假设动作会被可靠观测到,而本机能不能可靠看到
        // 是本地事实。降档一律从服务器原始强度算起,故与运行期的表更新重复调用无副作用。
        attackChain.setCoverage(CoverageProfile::fromOptions(options));
    }

    // 威胁情报共享:夜间把本机暂存的「病毒信息 + 行为数据」批量上传中央服务器,成功即删本地。
    // 端点/令牌与中央信誉代理同源(同一台服务器)。默认关 —— setEnabled 由运行时开关驱动,
    // 用户不开则既不收集也不上传。
    ThreatIntelUploader intelUploader(&intelContrib,
                                      options.ReputationProxy.resolveBaseUrl(),
                                      options.ReputationProxy.resolveToken(),
                                      options.ReputationProxy.ContributionUploadHour,
                                      options.ReputationProxy.QueryTimeoutSeconds);
    intelUploader.setEnabled(settings.cloudBehaviorUploadEnabled);
    // 开关处于关闭态时,清掉可能残留的暂存(上次开过又关掉、或关掉后异常退出未清)。
    if (!settings.cloudBehaviorUploadEnabled) {
        const int purged = intelContrib.purgeAll();
        if (purged > 0)
            log.info(QStringLiteral("威胁情报共享已关闭,已清除残留的本地暂存 %1 条。").arg(purged));
    }

    // IPC 命名管道服务器(与 UI 通信)。
    IpcServer ipc;

    //
    // 控制管道客户端认证策略。必须在 ipc.start() 之前注入 —— 一旦开始监听,第一个连接
    // 可能立刻到达(UI 早已在跑并处于重连循环中),那时策略若还是空的,强制层会因为
    // installDir 为空而拒绝掉合法 UI。
    //
    // 管道上能下发的都是最高权限动作(关总开关 / 加白任意路径 / 结束任意进程树 / 还原隔离区),
    // 在此之前服务对任何连入者零校验,任意本地低权限进程都能一条消息关掉整套防护。
    // 强制层(安装目录 + 映像名)不可配置、不依赖签名;签名加固由 EnforceUiClientSignature 控制。
    {
        IpcClientAuth::Policy authPolicy;
        authPolicy.installDir = QCoreApplication::applicationDirPath();
        authPolicy.allowedImageNames = { QStringLiteral("bulwark_ui.exe") };
        authPolicy.enforceSignature = options.EnforceUiClientSignature;
        authPolicy.allowedThumbprints = options.UiClientAllowedThumbprints;
        authPolicy.allowedPublishers = options.UiClientAllowedPublishers;
        IpcClientAuth::configure(authPolicy);
    }

    // 事件源协调器句柄(下方创建后赋值):供 settingsRequested 回报内核连接状态,
    // 供 settingsUpdated 运行时切换内核驱动开关 / 用户态行为监控开关。
    EventSourceCoordinator* coordinatorPtr = nullptr;

    // ---- 绑定 IPC 请求处理回调(对应 .NET Worker 里的 _ipc.* 绑定)----
    // 全部在主线程(Qt 事件循环)上调用,与事件处理串行;引擎内部另有读写锁。

    // 已连接的 UI 进程 PID。除了内核自我保护名单,进程管理页也要用它做「不许从这里结束
    // 磐垒自身组件」的护栏 —— 一个能一键结束自家服务的进程管理器等于给恶意软件递刀。
    // 只在主线程(IPC 回调)读写;后台线程用时先在主线程拷一份快照。
    auto uiPids = std::make_shared<QSet<int>>();

    // UI 握手:把 UI 进程 PID 登记进内核驱动的自我保护名单,恶意软件便无法结束/篡改 UI 进程。
    // 该回调仅在 app.exec() 事件循环中(处理 Hello 帧时)触发,此时 coordinatorPtr 已完成赋值,
    // 无竞态;UI 每次(重)连接都会重发 Hello,内核(重)连接时协调器也会补发已登记的受保护 PID。
    ipc.uiProcessConnected = [&coordinatorPtr, uiPids, &log](int pid) {
        if (pid > 0)
            uiPids->insert(pid);
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
    ipc.settingsRequested = [&settings, &engine, &coordinatorPtr, serverOnlyMode] {
        bulwark::RuntimeSettings snap = settings.clone();
        snap.trustSignedActors = engine.trustSignedActors;
        // 只读策略位:让设置页知道「本机不动用第三方情报源」已生效,好把那六个源的开关禁掉并
        // 说明原因(它们在服务端一律按关处理,见 applyIntelSourceToggles)。
        snap.cloudServerOnly = serverOnlyMode;
        if (coordinatorPtr && coordinatorPtr->kernelConnected()) {
            snap.kernelConnected = true;
            // 不能一律显示「行为前拦截」:协议版本自 v9 起刻意锁死(见 Protocol.h),所以一个比
            // 服务旧的 Bulwark.sys 照样握手通过,而命令行硬拦 / 封禁主体 / 自保足迹等维度会被它
            // 的 default 分支静默拒掉。原文案在这种情况下是失真的 —— 用户以为反勒索的删卷影
            // 执行前阻断在生效,其实根本没下发成功。故按实测能力如实分档。
            const QStringList missing = coordinatorPtr->kernelMissingCapabilities();
            if (missing.isEmpty()) {
                snap.kernelStatus =
                    QStringLiteral("内核驱动已连接 · 行为前拦截(进程/文件/注册表/自保/网络)");
            } else {
                snap.kernelStatus =
                    QStringLiteral("内核驱动已连接,但驱动版本偏旧 · 以下 %1 个维度未生效:%2 —— "
                                   "请用与本服务同源编译的 Bulwark.sys 替换后重新加载")
                        .arg(missing.size())
                        .arg(missing.join(QStringLiteral("、")));
            }
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
    // 情报共享的每日上传时刻,仅用于日志文案。按值捕获一个 int,免得为一句日志把整个
    // options 拖进 settingsUpdated 的捕获列表。
    const int contribUploadHour = options.ReputationProxy.ContributionUploadHour;
    ipc.settingsUpdated = [&settings, &engine, &settingsStore, &repAggregate, &repManager,
                           &applyIntelSourceToggles, &coordinatorPtr, &intelUploader,
                           &intelContrib, contribUploadHour, serverOnlyMode, &log](
                              const bulwark::RuntimeSettings& s) {
        const bool wasContribOn = settings.cloudBehaviorUploadEnabled;
        bulwark::RuntimeSettings updated = s;
        updated.eventSource = settings.eventSource; // 只读字段保持不变
        updated.cloudServerOnly = serverOnlyMode;   // 同上:策略来自 appsettings,UI 改不了
        settings = updated;
        engine.trustSignedActors = settings.trustSignedActors;
        engine.enableBaseline = settings.behaviorBaselineEnabled;
        settingsStore.save(settings);
        // 运行时切换:内核驱动开关(热加载/卸载)+ 用户态持续行为监控 / 勒索诱饵开关。
        if (coordinatorPtr) {
            coordinatorPtr->setKernelEnabled(settings.kernelDriverEnabled);
            coordinatorPtr->configureBehaviorMonitor(settings.userModeBehaviorMonitor,
                                                     settings.ransomwareCanaryEnabled);
            // 内存防护总开关:此前该设置在服务端从未被读取(设置页开关 + 仪表盘指示灯都是摆设,
            // 真实反注入只由 appsettings 的 MemoryProtectionTargets 驱动)。现在它真正生效。
            coordinatorPtr->setMemoryProtectionEnabled(settings.memoryProtectionEnabled);
        }
        // 信誉源开关即时生效;若用户新启用了某源,(重)启动后台查询 worker(已运行则为空操作)。
        // ServerOnly 时这一步会把各源一律按关处理(见 applyIntelSourceToggles 的说明)。
        applyIntelSourceToggles(settings);
        // 情报源 API Key 热应用(UI 逐源填写,立即生效)。空 -> 禁用该源;VT 空则回退内置 Key。
        repAggregate.setApiKey(QStringLiteral("VirusTotal"),     settings.virusTotalApiKey);
        repAggregate.setApiKey(QStringLiteral("MalwareBazaar"),  settings.malwareBazaarApiKey);
        repAggregate.setApiKey(QStringLiteral("OTX"),            settings.otxApiKey);
        repAggregate.setApiKey(QStringLiteral("ThreatBook"),     settings.threatBookApiKey);
        repAggregate.setApiKey(QStringLiteral("MetaDefender"),   settings.metaDefenderApiKey);
        repAggregate.setApiKey(QStringLiteral("HybridAnalysis"), settings.hybridAnalysisApiKey);
        repManager.start();
        // 威胁情报共享开关热生效。关闭时【立即清空本地暂存】—— 用户撤回同意就该当场生效,
        // 不能把已收集的数据继续留在盘上等下一晚(那等于撤回无效)。
        intelUploader.setEnabled(settings.cloudBehaviorUploadEnabled);
        if (wasContribOn && !settings.cloudBehaviorUploadEnabled) {
            const int purged = intelContrib.purgeAll();
            log.info(QStringLiteral("威胁情报共享已关闭:停止收集,并清除本地暂存 %1 条。").arg(purged));
        } else if (!wasContribOn && settings.cloudBehaviorUploadEnabled) {
            log.info(QStringLiteral("威胁情报共享已开启:仅收集病毒信息与沙箱行为数据"
                                    "(哈希/判定/引擎数/威胁名/释放物名与哈希/注册表键/外联IP与域名/"
                                    "服务名/互斥体),不含文件内容、本机路径、计算机名或用户名;"
                                    "每天 %1:00 上传后即删除本地暂存。")
                         .arg(contribUploadHour, 2, 10, QLatin1Char('0')));
        }
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
    // 加白后与内核名单对账的钩子。Worker 要到后面(所有依赖就绪后)才构造,而 IPC 回调在此处接线,
    // 故先留一个空钩子、构造 Worker 后再填 —— 未填时调用是安全的 no-op。
    std::function<void()> trustAddedHook;
    ipc.trustAddRequested = [&engine, &ruleStore, &log, &trustAddedHook](const bulwark::ipc::AddTrustPayload& p) {
        const QString path = p.actorPath.trimmed();
        if (path.isEmpty()) return;
        // 加白后必须与内核名单对账:内核「禁止执行 / 禁止加载」由内核写回注册表持久化、跨重启续拦,
        // 只在用户态加白是无效的(内核在进程创建/映像加载回调就地拒绝,事件到不了引擎)。
        // 无论本次是新增还是命中去重都要对账 —— 用户重复点加白往往正是因为「加了但还在拦」。
        const auto reconcile = [&trustAddedHook] { if (trustAddedHook) trustAddedHook(); };
        if (p.isDirectory) {
            // 文件夹信任:目录下运行的所有程序无条件放行。引擎在威胁检测之前提前命中此类
            // 信任项(信任即完全不再检测)。按目录通配去重。
            const bulwark::DefenseRule rule = bulwark::DefenseRule::createTrustDirectory(path, p.note);
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && !r.actorPattern.isEmpty()
                    && r.actorPattern.compare(rule.actorPattern, Qt::CaseInsensitive) == 0) {
                    reconcile(); // 已存在该信任项:仍对账一次(用户重复加白多半就是因为内核还在拦)
                    return;
                }
            engine.addRule(rule);
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件夹信任:%1").arg(path));
            reconcile();
        } else {
            for (const auto& r : engine.getRules()) // 去重
                if (r.isTrustEntry() && r.actorPath.compare(path, Qt::CaseInsensitive) == 0) {
                    reconcile();
                    return;
                }
            engine.addRule(bulwark::DefenseRule::createTrust(path, p.note));
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件信任:%1").arg(path));
            reconcile();
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

    // ---- 攻击链「组合表状态 + 命中记录」查询(UI 攻击链页面)----
    // 读的都是内存态(表统计 + 有上限的命中环),微秒级,直接在 IPC 线程同步返回。
    ipc.attackChainRequested = [&attackChain, &options] {
        bulwark::ipc::AttackChainResponsePayload p;
        p.enabled = attackChain.isEnabled();
        p.dryRun = attackChain.isDryRun();
        p.version = attackChain.version();
      p.versionLabel = attackChain.versionLabel();
        p.patterns = attackChain.patternCount();
        p.markers = attackChain.markerCount();
        p.trackedProcesses = attackChain.trackedProcessCount();
        // 端点一律掩码:延续「绝不把服务器明文地址泄露到 UI / 日志」的既有约定。
        const AttackChainOptions& ac = options.AttackChainEngine;
        const QString base = ac.BaseUrl.isEmpty() ? options.ReputationProxy.resolveBaseUrl()
                                                  : ac.BaseUrl;
        p.endpoint = ReputationProxyOptions::maskUrl(base);
        p.updateSchedule = ac.DailyUpdateHour >= 0
            ? QStringLiteral("每天 %1:00 自动更新").arg(ac.DailyUpdateHour, 2, 10, QLatin1Char('0'))
            : (ac.RefreshIntervalHours > 0
                   ? QStringLiteral("每 %1 小时更新一次").arg(ac.RefreshIntervalHours)
                   : QStringLiteral("仅启动时更新"));
        for (const ChainHitRecord& r : attackChain.recentHits()) {
            bulwark::ipc::AttackChainHitPayload h;
            h.whenUtc = r.whenUtc;
            h.actorPath = r.actorPath;
            h.actorPid = r.actorPid;
            h.titles = r.titles;
            h.grade = r.grade;
            h.maxLevel = r.maxLevel;
            h.support = r.support;
            h.families = r.families;
            h.dryRun = r.dryRun;
            h.action = r.action;
            h.eventType = r.eventType;
            p.hits.append(h);
        }
        return p;
    };
    ipc.attackChainClearRequested = [&attackChain] { attackChain.clearHits(); };

    // ================= 在线更新:检查 / 下载 =================
    //
    // 两者都走网络(检查一次往返可达 15s,下载是几 MB),所以与取证查询同一处置:丢后台线程,
    // 算完用 QMetaObject::invokeMethod 编组回主线程再经管道回推。
    //
    // UpdateService 用 shared_ptr 持有,而不是本函数栈上的局部量:后台线程可能比这段栈活得久
    // (停机时正好在途),按引用捕获栈对象就是 use-after-file —— 这份代码里的信誉回传和健康
    // 探测都因为这个坑吃过教训。
    //
    // 计数器【刻意复用】forensicsInflight:那是停机路径(app.exec() 之后)真正会去等的那一个。
    // 另起一个语义更贴切但没人等的计数器,只会让停机时在途的更新线程写到已析构的 ipc 上。
    // 名字不够准确是小事,漏等一个持有引用的线程不是。
    //
    // 声明提到这里(原本在下面的取证回溯段里):在线更新的绑定在它之前,不提前声明就编译不过。
    // 取证那两个绑定继续用同一个对象,停机等待因此同时覆盖三类后台查询。
    auto forensicsInflight = std::make_shared<std::atomic<int>>(0);

    auto updateSvc = std::make_shared<UpdateService>(options);
    auto lastUpdate = std::make_shared<UpdateInfo>();
    auto lastStagingDir = std::make_shared<QString>();
    auto updateMx = std::make_shared<std::mutex>();
    auto updateBusy = std::make_shared<std::atomic<bool>>(false);
    log.info(QStringLiteral("在线更新:%1(端点 %2,通道 %3)")
                 .arg(updateSvc->isConfigured() ? QStringLiteral("已启用") : QStringLiteral("未配置"),
                      updateSvc->maskedEndpoint(), options.Update.Channel));

    // 「检查一次更新」这个动作抽成一份共享的可调用对象,而不是在「用户点检查」和
    // 「启动后自动检查」两处各写一遍。两条路径必须产出【完全一样】的载荷:如果自动
    // 检查说有新版本、手动检查说没有(或反过来),用户没有办法判断该信哪一个,而这种
    // 分歧恰恰会在两段代码各自演化之后出现。
    auto runUpdateCheck = std::make_shared<std::function<void()>>();
    *runUpdateCheck = [&ipc, updateSvc, lastUpdate, updateMx, forensicsInflight] {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, updateSvc, lastUpdate, updateMx, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };

            UpdateInfo info;
            try {
                info = updateSvc->check();
            } catch (...) {
                info.ok = false;
                info.error = QStringLiteral("检查更新时发生未预期的错误。");
            }
            {   // 记下这次结论,下载请求据此知道要取哪个版本
                std::lock_guard<std::mutex> lk(*updateMx);
                *lastUpdate = info;
            }
            bulwark::ipc::UpdateCheckResponsePayload res;
            res.ok = info.ok;
            res.available = info.available;
            res.error = info.error;
            res.currentVersion = bulwark::version::current();
            res.version = info.version;
            res.label = info.label;
            res.notes = info.notes;
            res.publishedUtc = info.publishedUtc;
            res.endpointMasked = updateSvc->maskedEndpoint(); // 掩码,绝不回真实地址
            res.totalBytes = info.totalBytes;
            for (const UpdateFileInfo& f : info.files) {
                bulwark::ipc::UpdateFileBrief b;
                b.name = f.name;
                b.size = f.size;
                res.files.append(b);
            }
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendUpdateCheck(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };
    ipc.updateCheckRequested = [runUpdateCheck] { (*runUpdateCheck)(); };

    ipc.updateDownloadRequested = [&ipc, updateSvc, lastUpdate, lastStagingDir, updateMx, updateBusy,
                                   forensicsInflight] {
        // 并发下载守卫。UI 上用户连点两下「下载」是常态,而两个线程同时往同一个暂存目录写
        // 同名文件,得到的是一个哈希对不上的混合物 —— 而失败原因看起来会像「服务器发错了」。
        bool expected = false;
        if (!updateBusy->compare_exchange_strong(expected, true)) {
            bulwark::ipc::UpdateDownloadResponsePayload res;
            res.ok = false;
            res.error = QStringLiteral("已有一个下载正在进行中。");
            ipc.sendUpdateDownloadResult(res);
            return;
        }
        UpdateInfo info;
        {
            std::lock_guard<std::mutex> lk(*updateMx);
            info = *lastUpdate;
        }
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, updateSvc, info, updateBusy, forensicsInflight, updateMx, lastStagingDir] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                std::shared_ptr<std::atomic<bool>> busy;
                ~Guard() { busy->store(false); c->fetch_sub(1); }
            } guard{ forensicsInflight, updateBusy };

            UpdateDownloadResult r;
            try {
                r = updateSvc->download(info, [&ipc](int done, int total, QString name, QString stage) {
                    bulwark::ipc::UpdateProgressPayload p;
                    p.done = done;
                    p.total = total;
                    p.fileName = name;
                    p.stage = stage;
                    QMetaObject::invokeMethod(&ipc, [&ipc, p] { ipc.sendUpdateProgress(p); },
                                              Qt::QueuedConnection);
                });
            } catch (...) {
                r.ok = false;
                r.error = QStringLiteral("下载更新时发生未预期的错误。");
            }
            // 记下暂存目录:应用请求是另一条 IPC 消息,那时得知道文件下到哪了。
            // 不让 UI 把路径传回来 —— 那等于让「要替换安装目录里哪些文件」由管道对面
            // 决定,而这条链路的终点是以 SYSTEM 写安装目录并加载内核驱动。
            {
                std::lock_guard<std::mutex> lk(*updateMx);
                *lastStagingDir = r.stagingDir;
            }
            bulwark::ipc::UpdateDownloadResponsePayload res;
            res.ok = r.ok;
            res.error = r.error;
            res.version = info.version;
            res.stagingDir = r.stagingDir;
            res.verified = r.verified;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendUpdateDownloadResult(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    // ---- 就地应用已下载的更新 ------------------------------------------------
    // 由服务自己替换文件,不再由 UI 拉起提权脚本。为什么换掉脚本方案,见
    // UpdateService::apply() 的说明:脚本是外部进程,会被本产品的自我保护逐项挡下,
    // 而且 Stop-Process 那种失败是静默的,脚本会以为自己成功了。
    //
    // 同样丢后台线程:要重算三个 PE 的 SHA-256 并验签名,是秒级操作,不能占住 IPC 线程。
    // 复用 updateBusy:下载与应用互斥 —— 一边替换一边往同一个暂存目录写,得到的是混合物。
    ipc.updateApplyRequested = [&ipc, updateSvc, lastUpdate, lastStagingDir, updateMx, updateBusy,
                                forensicsInflight] {
        bool expected = false;
        if (!updateBusy->compare_exchange_strong(expected, true)) {
            bulwark::ipc::UpdateApplyResponsePayload res;
            res.ok = false;
            res.needsRestart = false;
            res.error = QStringLiteral("上一次下载或安装还在进行中,请稍候。");
            ipc.sendUpdateApplyResult(res);
            return;
        }

        UpdateInfo info;
        QString staging;
        {
            std::lock_guard<std::mutex> lk(*updateMx);
            info = *lastUpdate;
            staging = *lastStagingDir;
        }
        // lastStagingDir 只活在本次服务生命周期里,而「下载完 -> 点安装」中间完全可能
        // 隔着一次服务重启(用户关掉界面过一会儿再开、机器重启过)。此时载荷其实还躺在
        // 暂存目录里,却因为这个内存变量空了而被拒成「还没有下载好的更新」—— 用户看到的
        // 就是「明明下载过,却怎么点都装不上」,只能重下一遍。
        //
        // 下载目录名是确定的(stagingRoot()/<版本>,见 download()),所以直接重建它。
        // 这不是放宽信任:apply() 在取用的那一刻会把每个文件的哈希与钉死签名重验一遍,
        // 并强制版本只许前进 —— 保证来自校验,而不是来自「这个路径是我们自己记下来的」。
        if (info.available && staging.isEmpty()) {
            const QString guess = QDir(UpdateService::stagingRoot()).filePath(info.version);
            if (QDir(guess).exists())
                staging = guess;
        }
        if (!info.available || staging.isEmpty()) {
            updateBusy->store(false);
            bulwark::ipc::UpdateApplyResponsePayload res;
            res.ok = false;
            res.needsRestart = false;
            res.error = QStringLiteral("还没有下载好的更新,请先检查更新并下载。");
            ipc.sendUpdateApplyResult(res);
            return;
        }

        forensicsInflight->fetch_add(1);
        std::thread([&ipc, updateSvc, info, staging, updateBusy, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                std::shared_ptr<std::atomic<bool>> b;
                ~Guard() { c->fetch_sub(1); b->store(false); }
            } guard{ forensicsInflight, updateBusy };

            UpdateApplyResult a;
            try {
                a = updateSvc->apply(info, staging);
            } catch (...) {
                a.ok = false;
                a.needsRestart = false;
                a.error = QStringLiteral("应用更新时发生未预期的错误。");
            }
            bulwark::ipc::UpdateApplyResponsePayload res;
            res.ok = a.ok;
            res.error = a.error;
            res.version = info.version;
            res.replaced = a.replaced;
            res.rolledBack = a.rolledBack;
            res.needsRestart = a.needsRestart;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendUpdateApplyResult(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    // ---- 启动后静默检查一次(Update.AutoCheckDelayMinutes,0 = 关闭)-------------
    //
    // 只【检查】,绝不自动下载、更不自动安装:安装要停防护、换内核驱动、可能要求重启,
    // 那必须是用户按下按钮才发生的事。这里做的全部事情是把「有新版本」这个事实告诉界面。
    //
    // 为什么要延迟:开机那几分钟是最忙的,而且此时网络往往还没真正通。立刻查一次的
    // 典型结果是查失败,然后这一个服务生命周期里再也不查了 —— 比不查更糟。
    //
    // 为什么还要等界面接上:结论是靠管道推给界面的,界面没连上时这次检查就白做了。
    // 而常驻模式下服务开机就起、界面可能过很久才打开,「到点就查」在那种模式下几乎
    // 必然落空。所以到点先看有没有界面在听:没有就先不查,等界面接上再查。
    if (updateSvc->isConfigured() && options.Update.AutoCheckDelayMinutes > 0) {
        const int delayMs = options.Update.AutoCheckDelayMinutes * 60 * 1000;
        auto delayElapsed = std::make_shared<std::atomic<bool>>(false);
        auto haveClient   = std::make_shared<std::atomic<bool>>(ipc.clientCount() > 0);
        auto autoDone     = std::make_shared<std::atomic<bool>>(false);

        // 每个服务生命周期只自动查一次。界面反复开关会反复触发 clientCountChanged,
        // 少了这个闸门就变成「每次打开界面都查一次」—— 那已经不是「启动后检查一次」,
        // 而是把我们自己的服务器当成了心跳目标。
        auto fireOnce = [runUpdateCheck, autoDone] {
            bool expected = false;
            if (!autoDone->compare_exchange_strong(expected, true)) return;
            (*runUpdateCheck)();
        };

        QObject::connect(&ipc, &IpcServer::clientCountChanged, &ipc,
                         [haveClient, delayElapsed, fireOnce](int n) {
                             haveClient->store(n > 0);
                             if (n > 0 && delayElapsed->load()) fireOnce();
                         });
        QTimer::singleShot(delayMs, &ipc, [delayElapsed, haveClient, fireOnce] {
            delayElapsed->store(true);
            if (haveClient->load()) fireOnce();
        });
        log.info(QStringLiteral("在线更新:启动 %1 分钟后自动检查一次(界面接入后才发起)")
                     .arg(options.Update.AutoCheckDelayMinutes));
    }

    // ================= 取证回溯:事件时间线 + 攻击图 =================
    //
    // 两者都要扫落盘的 events.jsonl(可达数万条)并解析 JSON,耗时可到秒级 —— 绝不能在 IPC
    // 线程上同步做,否则「点一下时间线,整个服务的事件处理停几秒」。故一律丢后台线程,算完用
    // QMetaObject::invokeMethod 编组回主线程再经管道回推(与云信誉详情同一套路)。
    //
    // 后台线程按引用捕获了本函数栈上的 ipc / eventHistory,所以必须纳入停机等待,否则停机时
    // 在途的查询会写到已析构的对象上(见 app.exec() 之后的等待)。
    //
    // forensicsInflight 已在上面的「在线更新」段声明(那一段的绑定在此之前,必须先有它)。
    // 三类后台查询(时间线 / 攻击图 / 在线更新)共用同一个计数器,停机等待一并覆盖。

    ipc.timelineRequested = [&ipc, &eventHistory, forensicsInflight](
                                const bulwark::ipc::TimelineRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &eventHistory, req, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::TimelineResponsePayload res;
            try {
                res = ForensicsService::queryTimeline(eventHistory, req);
            } catch (...) {
                res.requestId = req.requestId;
                res.message = QStringLiteral("时间线查询失败(历史文件可能损坏)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendTimeline(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    ipc.attackGraphRequested = [&ipc, &eventHistory, forensicsInflight](
                                   const bulwark::ipc::AttackGraphRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &eventHistory, req, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::AttackGraphResponsePayload res;
            try {
                res = ForensicsService::buildAttackGraph(eventHistory, req);
            } catch (...) {
                res.success = false;
                res.message = QStringLiteral("攻击图构建失败(历史文件可能损坏)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendAttackGraph(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    // ================= 磁盘垃圾清理 =================
    //
    // 与取证查询同一套路(后台线程 + forensicsInflight 计数 + invokeMethod 编组回主线程),
    // 理由也相同:遍历 %TEMP% / 浏览器缓存动辄数万文件,秒级到十几秒,绝不能占着 IPC 线程。
    //
    // 清理范围【不】来自请求:JunkCleaner 内部有一份编译期写死的类别/根目录表,请求里只有
    // 类别序号。这里唯一从配置读的是「要不要开、留多久、上限多少、额外排除哪些」这类旋钮,
    // 它们只能让清理范围变小。详见 JunkCleaner.h 顶部的七道护栏。
    //
    // 用户信任名单在这里接进去:用户显式信任过的路径连「它是不是垃圾」都不由我们判断。查询
    // 走 engine.trustNoteForPath —— 它内部自带读锁,后台线程调用是安全的(与兜底扫描同样用法)。
    auto junkPolicy = [&options, &engine]() {
        JunkCleanerPolicy pol;
        pol.enabled = options.DiskCleanup.Enabled;
        pol.minAgeHours = options.DiskCleanup.MinFileAgeHours;
        pol.maxFilesPerCategory = options.DiskCleanup.MaxFilesPerCategory;
        pol.maxSeconds = options.DiskCleanup.MaxSeconds;
        pol.excludes = options.DiskCleanup.ExcludePaths;
        pol.selfDir = QCoreApplication::applicationDirPath();
        pol.isUserTrusted = [&engine](const QString& path) {
            return engine.trustNoteForPath(path).has_value();
        };
        return pol;
    };

    ipc.junkScanRequested = [&ipc, junkPolicy, forensicsInflight](
                                const bulwark::ipc::JunkScanRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        const JunkCleanerPolicy pol = junkPolicy();
        std::thread([&ipc, req, pol, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            auto progress = [&ipc](const bulwark::ipc::JunkProgressPayload& p) {
                QMetaObject::invokeMethod(&ipc, [&ipc, p] { ipc.sendJunkProgress(p); },
                                          Qt::QueuedConnection);
            };
            bulwark::ipc::JunkScanResponsePayload res;
            try {
                res = JunkCleaner::scan(req, pol, progress);
            } catch (...) {
                res.message = QStringLiteral("垃圾扫描失败(目录访问异常)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendJunkScan(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    ipc.junkCleanRequested = [&ipc, junkPolicy, &log, forensicsInflight](
                                 const bulwark::ipc::JunkCleanRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        const JunkCleanerPolicy pol = junkPolicy();
        // 删除动作必须留痕:谁请求的、清了哪几类。逐类别的明细由 JunkCleaner 自己写日志。
        QStringList keys;
        for (int c : req.categories)
            keys << bulwark::junk::categoryKey(static_cast<bulwark::junk::Category>(c));
        log.info(QStringLiteral("垃圾清理请求:%1 类(%2),保留时长 %3 小时")
                     .arg(req.categories.size())
                     .arg(keys.join(QStringLiteral(", ")))
                     .arg(req.minAgeHours > 0 ? req.minAgeHours : pol.minAgeHours));
        std::thread([&ipc, req, pol, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            auto progress = [&ipc](const bulwark::ipc::JunkProgressPayload& p) {
                QMetaObject::invokeMethod(&ipc, [&ipc, p] { ipc.sendJunkProgress(p); },
                                          Qt::QueuedConnection);
            };
            bulwark::ipc::JunkCleanResponsePayload res;
            try {
                res = JunkCleaner::clean(req, pol, progress);
            } catch (...) {
                res.success = false;
                res.message = QStringLiteral("垃圾清理失败(目录访问异常)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendJunkClean(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    // 大文件查找。纯只读,所以【没有】对应的删除回调 —— 界面只提供「打开所在位置」。
    // 遍历整块磁盘比垃圾扫描更久,同样丢后台线程并纳入停机等待。
    ipc.largeFileScanRequested = [&ipc, &options, forensicsInflight](
                                     const bulwark::ipc::LargeFileScanRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        LargeFileScannerPolicy pol;
        // 排除表沿用垃圾清理的那一份:部署方列进去的位置,在两个功能里都该被绕开。
        pol.excludes = options.DiskCleanup.ExcludePaths;
        pol.selfDir = QCoreApplication::applicationDirPath();
        std::thread([&ipc, req, pol, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            auto progress = [&ipc](const bulwark::ipc::JunkProgressPayload& p) {
                QMetaObject::invokeMethod(&ipc, [&ipc, p] { ipc.sendJunkProgress(p); },
                                          Qt::QueuedConnection);
            };
            bulwark::ipc::LargeFileScanResponsePayload res;
            try {
                res = LargeFileScanner::scan(req, pol, progress);
            } catch (...) {
                res.message = QStringLiteral("大文件查找失败(目录访问异常)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendLargeFileScan(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    // ================= 进程管理 =================
    //
    // 「本软件自身组件」判定:自身 PID + 已连接的 UI PID + 映像位于安装目录。进程管理页是
    // 用户主动处置的入口,但它绝不能变成把防护自己关掉的开关 —— 卸载走正常的卸载流程。
    const int ownPid = static_cast<int>(QCoreApplication::applicationPid());
    const QString appDir = QDir::toNativeSeparators(QCoreApplication::applicationDirPath()).toLower();
    auto isSelfComponent = [ownPid, uiPids, appDir](int pid, const QString& imagePath) {
        if (pid == ownPid || uiPids->contains(pid))
            return true;
        if (appDir.isEmpty() || imagePath.isEmpty())
            return false;
        const QString lower = QDir::toNativeSeparators(imagePath).toLower();
        const QString name = QFileInfo(lower).fileName();
        return lower.startsWith(appDir)
            && (name == QStringLiteral("bulwark_service.exe") || name == QStringLiteral("bulwark_ui.exe"));
    };

    // 进程快照:枚举 + 验签 + 溯源在后台线程(首次要对几百个映像验签,可能数秒),回到主线程
    // 才补「是否已加白 / 是否自身组件」—— 加白判定要碰引擎规则集,那必须在主线程做。
    ipc.processListRequested = [&ipc, &engine, forensicsInflight, isSelfComponent](
                                   const bulwark::ipc::ProcessListRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &engine, req, forensicsInflight, isSelfComponent] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::ProcessListResponsePayload res;
            res.requestId = req.requestId;
            try {
                monitoring::ProcessEnumerator::Options opt;
                opt.includeCommandLine = req.includeCommandLine;
                opt.resolveOrigin = req.resolveOrigin;
                res.processes = monitoring::ProcessEnumerator::snapshot(opt);
                res.message = QStringLiteral("共 %1 个进程").arg(res.processes.size());
            } catch (...) {
                res.message = QStringLiteral("进程枚举失败");
            }
            res.snapshotUtc = QDateTime::currentDateTimeUtc();
            QMetaObject::invokeMethod(&ipc, [&ipc, &engine, res, isSelfComponent]() mutable {
                for (bulwark::ProcessEntry& p : res.processes) {
                    p.isProtectedSelf = isSelfComponent(p.pid, p.imagePath);
                    if (!p.imagePath.isEmpty() && engine.trustNoteForPath(p.imagePath).has_value()) {
                        p.isTrusted = true;
                        p.riskScore = 0;
                        p.riskReasons = QStringList{ QStringLiteral("已在用户信任名单(该程序不再被检测)") };
                    }
                }
                ipc.sendProcessList(res);
            }, Qt::QueuedConnection);
        }).detach();
    };

    // 进程处置:全部由用户在 UI 显式点击触发。三道护栏,任一命中即如实拒绝(绝不静默成功):
    //   ① PID <= 4(Idle/System);② 本软件自身组件(自我保护);③ 关键系统进程(结束会 0xEF 蓝屏)。
    ipc.processActionRequested =
        [&engine, &ruleStore, &quarantine, &log, &trustAddedHook, isSelfComponent](
            const bulwark::ipc::ProcessActionRequestPayload& req)
        -> bulwark::ipc::ProcessActionResultPayload {
        using Kind = bulwark::ipc::ProcessActionKind;
        bulwark::ipc::ProcessActionResultPayload res;
        res.requestId = req.requestId;
        res.kind = req.kind;
        res.pid = req.pid;

        QString imagePath = req.imagePath.trimmed();
        if (imagePath.isEmpty() && req.pid > 0)
            imagePath = monitoring::ProcessInspector::tryGetProcessImagePath(req.pid);

        // 只读动作:算哈希,不受处置护栏限制。
        if (req.kind == Kind::ComputeHash) {
            if (imagePath.isEmpty() || !QFileInfo::exists(imagePath)) {
                res.message = QStringLiteral("无法读取映像文件(路径未知或已不存在)");
                return res;
            }
            res.sha256 = monitoring::ProcessInspector::tryComputeSha256(imagePath);
            res.success = !res.sha256.isEmpty();
            res.message = res.success ? QStringLiteral("已计算 SHA-256")
                                      : QStringLiteral("计算失败(文件过大或被独占锁定)");
            return res;
        }

        // 加白:不涉及结束进程,但要与内核禁运名单对账(否则加白后内核仍会拦)。
        if (req.kind == Kind::TrustImage) {
            if (imagePath.isEmpty()) {
                res.message = QStringLiteral("该进程没有可解析的映像路径,无法加入信任名单");
                return res;
            }
            bool exists = false;
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && r.actorPath.compare(imagePath, Qt::CaseInsensitive) == 0) {
                    exists = true;
                    break;
                }
            if (!exists) {
                engine.addRule(bulwark::DefenseRule::createTrust(
                    imagePath, QStringLiteral("从进程管理信任")));
                ruleStore.save(engine.getRules());
                log.info(QStringLiteral("已从进程管理加入文件信任:%1").arg(imagePath));
            }
            if (trustAddedHook) trustAddedHook();
            res.success = true;
            res.message = exists ? QStringLiteral("该程序已在信任名单中")
                                 : QStringLiteral("已加入信任名单(此后其全部行为直接放行)");
            return res;
        }

        // ---- 以下都是处置动作,过三道护栏 ----
        if (req.pid <= 4) {
            res.message = QStringLiteral("PID 无效(系统空闲/内核进程不可处置)");
            return res;
        }
        if (isSelfComponent(req.pid, imagePath)) {
            res.message = QStringLiteral("自我保护:不允许从进程管理结束磐垒自身组件。"
                                         "如需停止防护,请在设置里关闭总开关,或走正常卸载流程。");
            log.warning(QStringLiteral("进程管理请求处置本软件组件(PID %1),已拒绝。").arg(req.pid));
            return res;
        }
        const bool critical = monitoring::ProcessInspector::isCriticalProcess(req.pid);
        if (critical && req.kind != Kind::Resume) {
            res.message = QStringLiteral("关键系统进程:结束或挂起会导致系统崩溃(0xEF),已拒绝。");
            return res;
        }

        switch (req.kind) {
        case Kind::Terminate:
            res.success = monitoring::ProcessInspector::tryTerminateProcess(req.pid);
            res.message = res.success
                ? QStringLiteral("已结束进程")
                : QStringLiteral("结束失败(进程已退出 / 受保护 / 权限不足)");
            break;
        case Kind::TerminateTree: {
            const int killed = monitoring::ProcessInspector::terminateProcessTree(req.pid);
            res.success = killed > 0;
            res.message = res.success ? QStringLiteral("已结束进程树,共 %1 个进程").arg(killed)
                                      : QStringLiteral("结束失败(进程已退出 / 受保护 / 权限不足)");
            break;
        }
        case Kind::Suspend:
            res.success = monitoring::ProcessInspector::trySuspend(req.pid);
            res.message = res.success ? QStringLiteral("已挂起(全部线程冻结)")
                                      : QStringLiteral("挂起失败(权限不足或进程已退出)");
            break;
        case Kind::Resume:
            res.success = monitoring::ProcessInspector::tryResume(req.pid);
            res.message = res.success ? QStringLiteral("已恢复运行")
                                      : QStringLiteral("恢复失败(权限不足或进程已退出)");
            break;
        case Kind::QuarantineImage: {
            if (imagePath.isEmpty() || !QFileInfo::exists(imagePath)) {
                res.message = QStringLiteral("无法定位映像文件,已放弃隔离(未做任何处置)");
                break;
            }
            const int killed = monitoring::ProcessInspector::terminateProcessTree(req.pid);
            const QString hash = QuarantineManager::tryComputeSha256(imagePath);
            const auto entry = quarantine.quarantine(
                imagePath, QStringLiteral("用户从进程管理手动隔离"), req.pid, hash);
            res.success = entry.has_value();
            if (res.success) {
                log.warning(QStringLiteral("用户从进程管理隔离了映像:%1(同时结束 %2 个进程)")
                                .arg(imagePath).arg(killed));
                res.message = QStringLiteral("已结束 %1 个进程并把映像移入隔离区(可还原)").arg(killed);
            } else {
                res.message = killed > 0
                    ? QStringLiteral("已结束 %1 个进程,但隔离失败(文件被占用或权限不足)").arg(killed)
                    : QStringLiteral("隔离失败(文件被占用或权限不足),进程也未能结束");
            }
            break;
        }
        default:
            res.message = QStringLiteral("不支持的动作");
            break;
        }
        return res;
    };

    // 威胁情报 / VirusTotal:测试连接 / 按文件查询 / 用量统计(用户主动触发,阻塞可接受)。
    ipc.vtRequested = [&repAggregate, &repManager, &repProxyFirst,
                       serverOnlyMode](const bulwark::ipc::VtRequestPayload& req)
        -> bulwark::ipc::VtResponsePayload {
        bulwark::ipc::VtResponsePayload res;
        res.requestId = req.requestId;
        switch (req.kind) {
            case bulwark::VtRequestKind::TestConnection: {
                const QString src = req.source.trimmed();
                std::pair<bool, QString> r;
                if (src == QStringLiteral("ReputationProxy"))
                    r = repProxyFirst.healthCheckNonBlocking(); // 中央代理健康(非阻塞,供 UI 状态灯)
                else if (serverOnlyMode)
                    // 逐源「测试连接」会真的拿本机密钥向第三方发一次请求 —— ServerOnly 下不发。
                    // 如实说明,而不是回一个「连接失败」让人以为是网络问题。
                    r = { false, QStringLiteral("本机不动用第三方情报源(仅向中央服务器查收录),该源未启用") };
                else if (src.isEmpty())
                    r = repAggregate.testConnection();
                else
                    r = repAggregate.testConnection(src);
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
    //
    // 这个线程是 detach 出去的,却按引用捕获了本函数栈上的对象(ipc / repManager / virusTotalPtr)。
    // 拉 VT 完整报告可能耗时数十秒,一旦停机时它还在途,就会写到已销毁的对象上 —— 偶发的
    // 停机崩溃。用一个共享的在途计数把它纳入停机等待(见 app.exec() 之后)。
    auto vtDetailInflight = std::make_shared<std::atomic<int>>(0);
    ipc.vtDetailRequested = [virusTotalPtr, &repManager, &ipc, vtDetailInflight,
                             serverOnlyMode](const QUuid& reqId, const QString& sha256) {
        vtDetailInflight->fetch_add(1);
        std::thread([virusTotalPtr, &repManager, &ipc, reqId, sha256, vtDetailInflight,
                     serverOnlyMode] {
            // 无论中途出什么岔子,计数都必须回落,否则停机时会白等满超时。
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ vtDetailInflight };
            bulwark::ipc::VtDetailResponsePayload p;
            // ServerOnly:完整报告要拿本机密钥去问 VirusTotal —— 正是这个模式禁止的事。
            // 如实回一句「按策略没查」,绝不为了补一张详情图而破掉策略。
            if (serverOnlyMode)
                p.message = QStringLiteral("本机不动用第三方情报源(仅向中央服务器查收录),无法获取完整报告");
            else if (virusTotalPtr)
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
    // 实现走 ThreatRemediator::forceQuarantine(经 Worker 转发)—— 这里原来内联了一份逐行相同的
    // 逻辑,而那个方法反倒没有任何调用者。Worker 要到后面才构造,故先留空钩子、构造后再填。
    std::function<std::pair<bool, QString>(const QString&)> forceQuarantineHook;
    ipc.manualQuarantineRequested = [&forceQuarantineHook](const QString& path) -> std::pair<bool, QString> {
        const QString p = path.trimmed();
        if (p.isEmpty()) return { false, QStringLiteral("路径为空") };
        if (!forceQuarantineHook) return { false, QStringLiteral("服务尚未就绪,请稍后重试") };
        return forceQuarantineHook(p);
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
        // 出队节拍与内核源共用一个旋钮(见 BulwarkOptions::EventDrainIntervalMs):它是
        // 「行为发生 -> 被拦下/弹窗」这段延迟的地板,两个源必须一起调。
        etwSource->setDrainIntervalMs(options.EventDrainIntervalMs);
        baseSource = std::move(etwSource);
        log.info(QStringLiteral("基础事件源 = ETW(Kernel-Process + 可选 Kernel-Network/DNS-Client/Kernel-Registry,实时)。"));
    }

    // 用户态持续行为源(自启动持久化 + 勒索诱饵):与基础源并行,弥补"运行之后"的事后盲区。
    auto behaviorSource = std::make_unique<UserModeBehaviorSource>(engine);

    // 协调器:合并 基础源 + 行为源 +(按开关热切换的)内核驱动源,作为 Worker 的统一事件源。
    // 裁决回写只路由到内核源;内核连接后抑制基础源重复的进程事件。
    auto coordinator = std::make_unique<EventSourceCoordinator>(baseSource.get(), behaviorSource.get(), options);
    coordinatorPtr = coordinator.get();

    // 内核级足迹清理:把「读被占用文件(做可逆金库副本)/ 强制删除」委托接到协调器 —— 内核连接时
    // 转发到 Bulwark.sys(以「忽略共享访问检查」打开、POSIX 强制删除被占用/已映射的文件),否则
    // 返回 false 让 QuarantineManager 回退到用户态清理。这使恶意足迹清理在原文件被独占锁定 / 已
    // 映射为运行镜像(用户态打不开读、删不掉)时也不再失败,同时仍保住可逆隔离(金库副本)。
    quarantine.setKernelAssist(
        [coordinatorPtr](const QString& p, QByteArray& out) {
            return coordinatorPtr ? coordinatorPtr->readLockedFile(p, out) : false;
        },
        [coordinatorPtr](const QString& p) {
            return coordinatorPtr ? coordinatorPtr->forceDeleteFile(p) : false;
        });

    // 编排:事件 -> 富化 -> 引擎 -> 裁决 -> IPC/处置/清理。
    Worker worker(&engine, &ipc, coordinator.get(), &ruleStore, &audit, &firstSeen, &quarantine, &repManager,
                  &settings);
    // 事件热路径上同步云查的等待预算。这是单条事件能拖慢整条流水线的硬上限 ——
    // 没有它的话,一次缓存未命中(代理端口不可达 / 情报源超时)就能让富化、裁决、IPC、
    // 弹窗超时巡检一起停摆二十多秒,内核事件在队列里堆到丢弃。见 Worker::enrich 第 6 步。
    worker.setInlineReputationBudgetMs(options.InlineReputationBudgetMs);
    worker.setIpIntel(threatBookPtr); // 注入微步客户端并启动后台 IP 情报 worker(网络外联互证)
    worker.setVtScan(virusTotalPtr, &vtHistory); // 注入 VT 客户端 + 历史,启动后台双击/释放载荷病毒扫描
    // 云扫描分级链路:本地缓存 -> 中央服务器(只问、不回退)-> VirusTotal -> 其他情报源(排除 VT)
    // -> 上传整文件扫描;末端把「服务器当时没有、本地新查到」的结论回传服务器供机队共享。
    worker.setCloudScanChain(&repProxyFirst, &repAggregate);
    worker.setIntelContribStore(&intelContrib); // 威胁情报共享暂存(默认关,开关见运行时设置)
    worker.setEventHistory(&eventHistory);       // 注入结构化事件历史(落库,供 UI 回填)
    if (options.AttackChainEngine.Enabled)
        worker.setAttackChainEngine(&attackChain); // 注入攻击链组合引擎(未启用则不注入,零开销)
    worker.setAlertExporter(&alertExporter);     // 注入 ECS 告警导出(未启用时其 exportAlert 自身为空操作)
    // 补齐加白对账钩子(声明在上面的 IPC 接线处):UI 每次加白后,清掉内核「禁止执行 / 禁止加载」
    // 名单里会挡住该目标的条目并重下发其余条目 —— 否则内核那份注册表持久化名单会让加白形同无效。
    trustAddedHook = [&worker] { worker.reconcileKernelBlocksAfterTrust(); };
    forceQuarantineHook = [&worker](const QString& p) { return worker.forceQuarantine(p); };
    // 自启动项清理:此前 IpcMessageType 里留了消息号、ThreatRemediator 也把 8 类持久化点的清理
    // 动作全实现了,但两端都没有接线,那些代码一行都到不了。现在接上(带加白 / 自身组件护栏)。
    ipc.persistenceCleanupRequested =
        [&worker](const bulwark::ipc::PersistenceCleanupRequestPayload& req) {
            return worker.cleanupPersistence(req);
        };
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
    attackChainFeed.start(); // 启动攻击链组合表刷新(未启用/无端点时为空操作)
    intelUploader.start();   // 启动威胁情报夜间上传(无端点时为空操作;是否上传看运行时开关)
    // 先应用初始设置(用户态行为监控 / 勒索诱饵开关),再 start()——确保 start() 内的诱饵投放
    // 遵从当前开关,而不是先按默认(开)投放再被关闭。
    coordinator->configureBehaviorMonitor(settings.userModeBehaviorMonitor, settings.ransomwareCanaryEnabled);
    // 内存防护总开关同样要在内核源启动前落定(setKernelEnabled 会在 start 前把它补给内核源)。
    coordinator->setMemoryProtectionEnabled(settings.memoryProtectionEnabled);
    coordinator->start(); // 启动基础源 + 用户态行为源

    // 内核驱动开关(EventSource=Driver 或设置开启即启用)。
    const bool kernelInitial = options.EventSource.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0
                               || settings.kernelDriverEnabled;
    if (kernelInitial)
        coordinator->setKernelEnabled(true);

    if (!coordinator->isAvailable())
        log.warning(QStringLiteral("基础事件源(ETW)不可用(通常因未以管理员身份运行);"
                                   "无实时进程事件,IPC/规则 / 用户态行为监控仍照常工作。"));

    // 兜底扫描:实时链路(内核/ETW 遥测)可能漏检【已确认恶意】进程 —— 遥测丢包、云端确认迟到、
    // 或进程在防护启动前就已在跑。启动后台线程周期复查在跑进程,按已确认恶意情报(记忆哈希 +
    // 信誉缓存判恶意)比对,漏网的补封禁+结束+隔离。纯用户态,不改驱动。
    worker.startMaliciousSweep();

    // 行为基线周期落盘(5 分钟)。只在停机时存一次是不够的:服务被强杀 / 机器断电时基线全丢,
    // 而基线的价值恰恰来自长期积累。5 分钟是折中 —— 画像是有界的(maxProfiles 8192),
    // 一次序列化开销很小,而丢失窗口足够短。
    QTimer baselineSaveTimer;
    baselineSaveTimer.setInterval(5 * 60 * 1000);
    QObject::connect(&baselineSaveTimer, &QTimer::timeout, [&engine, &baselineStore] {
        baselineStore.save(engine.exportBaseline());
    });
    baselineSaveTimer.start();

    log.info(QStringLiteral("Bulwark 服务已就绪。"));

    const int rc = app.exec();

    // 停机前再存一次,保住最后一个周期内新学到的画像。
    baselineSaveTimer.stop();
    baselineStore.save(engine.exportBaseline());
    log.info(QStringLiteral("行为基线画像已落盘。"));

    // 停机第一步:等 UI 触发的「云信誉详情」异步查询收尾。它是 detach 线程且按引用捕获了本
    // 函数栈上的 ipc / repManager,必须在这些对象析构【之前】等它退出,否则就是 use-after-free。
    // 有上限地等(20s),超时只如实记一条日志 —— 停机绝不能被一个网络请求无限期拖住。
    for (int i = 0; i < 200 && vtDetailInflight->load() > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (const int left = vtDetailInflight->load(); left > 0)
        log.warning(QStringLiteral("停机时仍有 %1 个云信誉详情查询在途(已等待 20s),不再等待。").arg(left));

    // 同理:时间线 / 攻击图 / 进程快照的后台线程也按引用捕获了 ipc / eventHistory / engine。
    // 它们全是本机计算(扫历史文件、枚举进程验签),秒级即可收尾,等 10s 足够。
    for (int i = 0; i < 100 && forensicsInflight->load() > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (const int left = forensicsInflight->load(); left > 0)
        log.warning(QStringLiteral("停机时仍有 %1 个取证查询/进程快照在途(已等待 10s),不再等待。").arg(left));

    intelUploader.stop();   // 停威胁情报夜间上传线程(它按指针持有 intelContrib)
    attackChainFeed.stop(); // 停攻击链组合表刷新线程(其回调按引用捕获了 attackChain)
    intelFeed.stop();  // 先停情报 feed 后台线程
    // 先停信誉的两条后台线程 —— 后台限流队列 worker 与事件热路径的内联查询车道。
    // 必须在 Worker 析构【之前】join:两者都会经 MaliciousCallback 回调进 Worker
    // (confirmReputationMaliciousAsync),Worker 先没了就是 use-after-free。
    // 两条线程同时收到停止信号、join 只是依次确认退出,故最坏等待仍是「单次查询超时」而非其和。
    repManager.stop();
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

// ── 失败自动恢复(SCM FailureActions)────────────────────────────────────────
//
// 这是【安全产品必须有】的一条:进程一旦异常终止(访问违规 / 被恶意样本打死),原先 SCM
// 只会记一条「服务意外停止」然后就此不管 —— 实测事件日志里累计 23 次,每次都要人手动
// `sc start` 才回来。在那之前主机是完全没有防护的,这比崩溃本身严重。
//
// 语义上刻意只覆盖【异常终止】:FailureActions 的默认行为(fFailureActionsOnNonCrashFailures
// 保持 FALSE)是仅当服务进程终止而【没有】上报 SERVICE_STOPPED 时才触发。用户从服务管理器
// 或 `sc stop` 正常停止时,serviceMain 会上报 SERVICE_STOPPED,SCM 不会把它拉起来 ——
// 「随时可停、可卸」这条底线不受影响,不存在「关不掉」。
//
// 策略:第 1/2 次失败 5 秒后重启,之后每次 60 秒后重启;计数 24 小时清零(避免长期运行中
// 偶发一次就永久停留在 60 秒档)。
bool applyFailureActions(SC_HANDLE svc) {
    SC_ACTION actions[3] = {};
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART; actions[2].Delay = 60000;

    SERVICE_FAILURE_ACTIONSW fa = {};
    fa.dwResetPeriod = 86400;      // 24h 无失败则计数清零
    fa.lpRebootMsg = nullptr;      // 绝不重启系统
    fa.lpCommand = nullptr;        // 不跑外部命令
    fa.cActions = 3;
    fa.lpsaActions = actions;

    // 先比对再写:内核自保护对 \Services\Bulwark* 有注册表硬拦,常态下不该有任何多余写入。
    std::vector<char> buf(4096);
    DWORD needed = 0;
    if (::QueryServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS,
                               reinterpret_cast<LPBYTE>(buf.data()),
                               static_cast<DWORD>(buf.size()), &needed)) {
        const auto* cur = reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(buf.data());
        bool same = cur->dwResetPeriod == fa.dwResetPeriod && cur->cActions == fa.cActions
                    && cur->lpsaActions != nullptr;
        for (DWORD i = 0; same && i < fa.cActions; ++i)
            same = cur->lpsaActions[i].Type == actions[i].Type
                   && cur->lpsaActions[i].Delay == actions[i].Delay;
        if (same) return true;     // 已是期望配置,一个字节都不写
    }
    return ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa) != FALSE;
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
        const bool fa = applyFailureActions(svc);
        std::printf("BulwarkService 已安装(自动启动%s)。用 `sc start BulwarkService` 启动。\n",
                    fa ? " + 异常终止自动恢复" : "");
        if (!fa)
            std::fprintf(stderr, "提示:配置失败自动恢复未成功(错误 %lu),"
                                 "服务异常终止后需手动启动。\n", ::GetLastError());
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

// ───────────────────────── 一键自举(--bootstrap) ─────────────────────────
// 目的:让用户「双击 bulwark_ui.exe」就能把后台服务 + 内核驱动一起带起来,不再手工
// sc create / sc start / fltmc load。由 UI 在检测到控制管道不通时以管理员身份调用。
//
// 全程幂等 —— 每步先查状态,已就绪就跳过;任一步失败只记录原因并继续下一步:
// 驱动起不来时服务仍能以 ETW 用户态观测降级运行(符合「绝不把用户锁在外面」的原则)。
//
// 注意:内核对 \Services\Bulwark* 有注册表硬拦(自保护)。因此改服务配置前先比对,
// 只在确实不一致时才写 —— 常态下一次都不写,不会撞上自己的自保护。

// 自举过程写一行行人类可读状态,供 UI 在失败时直接展示给用户。
QStringList g_bootstrapNotes;

void note(const QString& s) {
    g_bootstrapNotes << s;
    std::printf("%s\n", s.toLocal8Bit().constData());
}

// 数据目录(与 Logger 同一套解析规则),自举状态文件落在这里。
QString dataDir() {
    QString dir = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    if (dir.isEmpty()) {
        QString base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        dir = base + QStringLiteral("/Bulwark");
    }
    return dir;
}

// 测试签名模式是否开启(驱动为测试签名,关闭时内核拒绝加载)。仅用于失败时给出可操作提示。
bool testSigningOn() {
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(QStringLiteral("bcdedit.exe"), { QStringLiteral("/enum"), QStringLiteral("{current}") });
    if (!p.waitForStarted(5000) || !p.waitForFinished(10000))
        return true; // 查不到就不误报
    const QString out = QString::fromLocal8Bit(p.readAll());
    for (const QString& line : out.split(QLatin1Char('\n'))) {
        if (line.contains(QStringLiteral("testsigning"), Qt::CaseInsensitive))
            return line.contains(QStringLiteral("Yes"), Qt::CaseInsensitive)
                || line.contains(QString::fromUtf8("\xE6\x98\xAF")); // 是
    }
    return false;
}

// 把随程序分发的 Bulwark.sys 放到 System32\drivers(缺失才复制;已存在可能正被加载,不覆盖)。
void stageDriverBinary() {
    const QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString dst = QDir(sysRoot).filePath(QStringLiteral("System32/drivers/Bulwark.sys"));
    if (QFileInfo::exists(dst))
        return; // 已就位
    const QString src = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Bulwark.sys"));
    if (!QFileInfo::exists(src)) {
        note(QString::fromUtf8("驱动文件 Bulwark.sys 不在程序目录,内核前拦截不可用(将以 ETW 用户态观测运行)。"));
        return;
    }
    if (QFile::copy(src, dst))
        note(QString::fromUtf8("已部署内核驱动到 %1。").arg(QDir::toNativeSeparators(dst)));
    else
        note(QString::fromUtf8("复制 Bulwark.sys 到 System32\\drivers 失败(需管理员权限)。"));
}

// 注册(或修正)+ 启动 BulwarkService。返回是否已进入 RUNNING。
bool ensureServiceRunning() {
    wchar_t exe[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::wstring bin = L"\"" + std::wstring(exe) + L"\" --service";

    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        note(QString::fromUtf8("打开服务管理器失败(错误 %1)——请以管理员身份运行。").arg(::GetLastError()));
        return false;
    }

    SC_HANDLE svc = ::OpenServiceW(scm, kSvcName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG
                                                      | SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) {
        svc = ::CreateServiceW(scm, kSvcName, kSvcDisplay, SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                               bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            note(QString::fromUtf8("注册服务失败(错误 %1)。").arg(::GetLastError()));
            ::CloseServiceHandle(scm);
            return false;
        }
        note(QString::fromUtf8("已注册后台服务(开机自动启动)。"));
        if (!applyFailureActions(svc))
            note(QString::fromUtf8("配置「异常终止后自动恢复」失败(错误 %1)——服务若被打死需手动启动。")
                     .arg(::GetLastError()));
    } else {
        // 已注册:只在「程序被挪过位置」或「不是自动启动」时才改配置,避免无谓写注册表。
        std::vector<char> buf(8192);
        DWORD needed = 0;
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (::QueryServiceConfigW(svc, cfg, static_cast<DWORD>(buf.size()), &needed)) {
            const bool pathStale = cfg->lpBinaryPathName == nullptr
                                   || ::_wcsicmp(cfg->lpBinaryPathName, bin.c_str()) != 0;
            const bool notAuto = cfg->dwStartType != SERVICE_AUTO_START;
            if (pathStale || notAuto) {
                if (::ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                           pathStale ? bin.c_str() : nullptr,
                                           nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
                    note(QString::fromUtf8("已修正服务配置(%1%2)。")
                             .arg(pathStale ? QString::fromUtf8("程序路径 ") : QString(),
                                  notAuto ? QString::fromUtf8("开机自启") : QString()));
                } else {
                    note(QString::fromUtf8("修正服务配置失败(错误 %1)——可能被内核自保护挡住,"
                                           "如需改动请先在界面里关闭内核驱动。")
                             .arg(::GetLastError()));
                }
            }
        }
        // 老版本装出来的服务没有失败恢复配置(异常终止后就一直停着)。这里补上;
        // applyFailureActions 内部会先比对,已配置好的情况下不写注册表。
        if (!applyFailureActions(svc))
            note(QString::fromUtf8("配置「异常终止后自动恢复」失败(错误 %1)——"
                                   "可能被内核自保护挡住,可先关闭内核驱动后重试。")
                     .arg(::GetLastError()));
    }

    // 启动并等待进入 RUNNING(服务启动里包含驱动加载 + ETW 会话,给足 40 秒)。
    if (!::StartServiceW(svc, 0, nullptr)) {
        const DWORD e = ::GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            note(QString::fromUtf8("启动服务失败(错误 %1)。").arg(e));
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return false;
        }
    }

    bool running = false;
    for (int i = 0; i < 80; ++i) {
        SERVICE_STATUS_PROCESS st = {};
        DWORD n = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st),
                                   sizeof(st), &n)) {
            if (st.dwCurrentState == SERVICE_RUNNING) { running = true; break; }
            if (st.dwCurrentState == SERVICE_STOPPED) break;
        }
        ::Sleep(500);
    }
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);

    if (running) note(QString::fromUtf8("后台服务已运行。"));
    else         note(QString::fromUtf8("后台服务未能进入运行状态,详见 service.log。"));
    return running;
}

int runBootstrap(int argc, char** argv) {
    QCoreApplication app(argc, argv); // DriverControl/QProcess/applicationDirPath 需要
    QCoreApplication::setApplicationName(QStringLiteral("Bulwark Bootstrap"));

    stageDriverBinary();

    // 驱动:先于服务加载,这样服务一起来就能连上内核端口(拿到行为前拦截能力)。
    if (DriverControl::isRunning()) {
        note(QString::fromUtf8("内核驱动已加载。"));
    } else if (DriverControl::ensureLoaded()) {
        note(QString::fromUtf8("内核驱动已加载(行为前拦截已启用)。"));
    } else if (!testSigningOn()) {
        note(QString::fromUtf8("内核驱动加载失败:系统未开启测试签名模式。"
                               "以管理员运行 `bcdedit /set testsigning on` 后重启即可;"
                               "在此之前防护以 ETW 用户态观测运行。"));
    } else {
        note(QString::fromUtf8("内核驱动加载失败,防护将以 ETW 用户态观测运行。"));
    }

    const bool ok = ensureServiceRunning();

    // 状态落盘,UI 失败时直接展示给用户(免得让人去翻日志)。
    const QString dir = dataDir();
    QDir().mkpath(dir);
    QFile f(QDir(dir).filePath(QStringLiteral("bootstrap-status.txt")));
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(g_bootstrapNotes.join(QLatin1Char('\n')).toUtf8());

    return ok ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    // 服务控制动词在创建 QCoreApplication 之前处理(无需 Qt)。
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--install") return installService();
        if (a == "--uninstall") return uninstallService();
        // 构建期辅助:把明文端点转成 BaseUrlObfuscated 值(与运行时解码同一套 XOR+base64 密钥)。
        // 打包脚本用它生成写进便携包 appsettings.json 的混淆串,使服务器地址不以明文落盘。
        // stdout 只输出密文;stderr 打印回环自校验与掩码形式。无需 QCoreApplication。
        if (a == "--obfuscate-url") {
            const QString plain = (i + 1 < argc) ? QString::fromLocal8Bit(argv[i + 1]).trimmed() : QString();
            if (plain.isEmpty()) { std::fprintf(stderr, "用法: --obfuscate-url <url>\n"); return 2; }
            const QString obf = ReputationProxyOptions::obfuscateUrl(plain);
            const QString back = ReputationProxyOptions::deobfuscateUrl(obf);
            std::printf("%s\n", obf.toLocal8Bit().constData());
            std::fprintf(stderr, "roundtrip=%s masked=%s\n", back == plain ? "ok" : "MISMATCH",
                         ReputationProxyOptions::maskUrl(plain).toLocal8Bit().constData());
            return back == plain ? 0 : 1;
        }
        if (a == "--bootstrap") return runBootstrap(argc, argv);
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
