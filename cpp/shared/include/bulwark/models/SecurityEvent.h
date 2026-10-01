#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QUuid>
#include <QVector>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/models/Evidence.h"
#include "bulwark/models/FileReputation.h"
#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/Clock.h"

namespace bulwark {

// 一次需要裁决的安全事件。由监控层产生,经规则引擎处理得到 Verdict。
// 对应 .NET Models/SecurityEvent.cs(字段一一对应,camelCase 上线)。
struct SecurityEvent {
    QUuid id = QUuid::createUuid();
    QDateTime timestampUtc = nowUtc();
    EventType type = EventType::ProcessCreate;

    int actorPid = 0;
    QString actorPath;
    QString actorHash;                    // 可空
    bool actorSigned = false;
    // 内嵌了签名但【本机校验不过】。注意它把三件事混在一起:文件被改过 / 本机没有签发者的
    // 根证书 / 文件读不出来。信任判定(TrustPolicy)用它是对的 —— 三者都不该给信任;但
    // 【打分不能用它单独定罪】,区分用下面的 signatureTampered。
    bool signatureMismatch = false;
    //
    // 签名摘要【确实】与文件内容不符 = 签名之后这个文件被改过。这才是恶意证据。
    //
    // 分出这个字段的原因是一次高频误报:signatureMismatch 为真的绝大多数情况不是篡改。
    // 自保护的安全软件不让别人读自己的映像,验签必然失败;企业内部 CA / 自签 / 部分国内
    // 厂商的链在干净机器上就是「根不受信」。原先 ThreatDetector 对 signatureMismatch 直接
    // 计 45 分【硬指标】,于是卡巴斯基的 avp.exe / avpsus.exe 在两天里产生了 7434 次
    // 「数字签名校验失败(疑似篡改或盗用证书)」的询问 —— 而那两个文件完好无损。
    // 由 Worker::enrich 从 ProcessInspector 的 TRUST_E_BAD_DIGEST 状态码回填。
    bool signatureTampered = false;
    qint64 actorFileSize = 0;
    QString actorPublisher;               // 可空
    QString actorCertThumbprint;          // 可空
    std::optional<QDateTime> certNotAfterUtc;
    std::optional<QDateTime> signingTimeUtc;
    bool certRevoked = false;
    bool signedAfterCertExpiry = false;
    bool isFirstSeen = false;
    std::optional<FileReputation> reputation;

    int originatorPid = 0;                // RPC 真凶 PID(0=无)
    QString originatorPath;               // 可空
    int parentPid = 0;
    QString parentPath;

    // ---- 启动来源溯源(服务 / 计划任务 / 交互式…)。仅用于溯源展示与取证,不参与评分。----
    // 解决「父进程是 svchost.exe 就再也追不下去」的盲区:把宿主进程还原成【具体】的服务名
    // 或计划任务名。由 ProcessOriginResolver 在事件富化阶段填充。
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originService;                // 服务名(svchost 共享宿主里可能多个,以 ", " 连接)
    QString originServiceDisplay;         // 服务显示名(第一个服务)
    QString originTask;                   // 计划任务完整路径(如 \Microsoft\Windows\Foo\Bar)
    QString originDetail;                 // 判定说明(含置信度/依据,可空)
    QString commandLine;                  // 可空
    QString target;                       // 目标:进程/文件/注册表键/远端地址
    QString detail;                       // 可空:端口/值名等

    // ---- 目标文件【自身】的签名(目前只对 ImageLoad 有意义)-------------------
    //
    // 【为什么必须和 actorSigned 分开】ImageLoad 事件里 actorPath 是【宿主进程】(用户态模块
    // 加载)或伪串「内核(驱动加载)」(内核模块加载),于是 actorSigned 说的是宿主、不是被加载
    // 的那个模块 —— 而「这个模块自己有没有可信签名」才是侧载 / BYOVD 判据真正要看的东西。
    // 段 7 的规则注释长期把 actorSigned 当成模块签名在用,那是误解(见规则段顶部说明)。
    //
    // 真实事故:内置规则「从可写目录 \programdata\ 加载内核驱动」原来不看任何签名,无条件
    // Block + hardOverride。卡巴斯基把带 AO Kaspersky Lab 有效签名的 klids.sys 放在
    // \ProgramData\ 下,于是每次加载都被判成 BYOVD —— 硬拦的排序高于「已安装安全软件共存
    // 放行」,共存那一层根本轮不到。现在那两条规则改按本字段分档。
    //
    // 由 Worker::enrich 在富化阶段填写(只对 ImageLoad 求值,事件量本来就小且按文件身份缓存)。
    // 序列化:旧报文缺这两个键 = 未签名,与本字段加入之前的行为一致。
    bool targetSigned = false;            // 目标文件持有【可信】签名
    bool targetSignatureMismatch = false; // 目标文件内嵌了签名但校验不过(篡改 / 盗证书)

    int riskScore = 0;
    QStringList riskReasons;
    QVector<Evidence> evidenceChain;
    QStringList techniques;               // 命中的 ATT&CK 技战术(去重)

    bool hasThreatIndicator = false;      // 是否出现"硬"恶意指标
    QString matchedRuleNote;              // 可空:命中规则说明
    bool userModeObserved = false;        // 用户态观测源产生(需事后补偿处置)
    bool kernelBlocked = false;           // 该事件对应的操作已被内核在【发生前】真正阻断
                                          //(STATUS_ACCESS_DENIED / 剥权 / WFP BLOCK / 禁止加载),
                                          // 用于如实区分「真前拦」与「事后处置」,避免假拦截显示。
    bool userTrusted = false;             // 运行时:命中用户明确信任(文件/文件夹)或内置良性厂商应用白名单,
                                          // 引擎在检测前放行,Worker 据此跳过全部后台扫描(VT/IP)。运行时标记,不序列化。
    bool memoryInjection = false;         // 内存防护(反注入)命中
    QString fileDescription;              // 可空:FileDescription

    // ---- 攻击链组合引擎的贡献 ------------------------------------------------
    // 必须【单独存放】,不能直接写 riskScore / hasThreatIndicator。
    // 原因:ThreatDetector::analyze 位于裁决流水线第 3 步,它会
    //   · 开头把 hasThreatIndicator 复位为 false;
    //   · 结尾用【赋值】(而非累加)把自己算出的分写进 riskScore。
    // 而攻击链在 Worker 里、evaluate 之【前】就完成了匹配。于是它写的那两个字段全被无声擦掉 ——
    // 实测后果:组合表上线后一次都没有生效过,连 hard 级组合也一样被擦成放行。
    // 现在改为放在这里,由 analyze 显式并入,顺序依赖变成一处明确的契约而不是隐式假设。
    // 运行时标记,不序列化。
    int chainScore = 0;                   // 组合命中该加的分(按服务器给的强度换算)
    bool chainHardIndicator = false;      // 组合命中即互证,按硬指标登记

    // ---- 侧载模块篡改(「白加黑」)---------------------------------------------
    // 与主体自身的 signatureMismatch 分开:那个说「这个 exe 的签名不对」,这个说
    // 「这个 exe 的签名没问题,但它目录里有个模块签名后被改过」。
    //
    // 补的是一处实测漏检:一套 AOMEI 正规签名的 DigitalUnit.exe 放在
    // C:\ProgramData\NVI_v4_arm64\,同目录 QtCore4.dll 是 HashMismatch(签名后被篡改),
    // 外加一个 7.4MB 伪装成 router.json 的混淆载荷,靠计划任务每 19 分钟拉起。
    // 因为白壳签名健康,TrustPolicy::isHealthySigned 在流水线第 9 步就放行,每次风险分只有 5;
    // 而被篡改的那个 DLL 从未进入裁决 —— 内核的 ImageLoad 上报只覆盖 \Temp\ 与 \Users\Public\
    // (刻意为之,防事件风暴),ProgramData 下的侧载看不见。
    //
    // 由 Worker::detectSideloadedTamperedModule 在富化阶段填写,ThreatDetector::analyze 消费。
    // 同样【不能】直接写 riskScore / hasThreatIndicator —— 理由与上面攻击链那段完全一致。
    // 运行时标记,不序列化。
    QString tamperedModulePath;           // 非空 = 主体目录内存在「签名后被篡改」的模块

    // ---- 白加黑侧载:签名壳 + 同目录【完全未签名】的系统同名 DLL --------------
    //
    // 与上面 tamperedModulePath 的区别:那个要求模块【内嵌了签名但校验不过】(被改过的正规
    // 模块);而银狐 2026 的主流形态是模块【根本没有签名】—— 带签名的正规程序(字节跳动
    // SodaMusicLauncher.exe、Zeon 的 ConvertToPDF.exe 等)旁边放一个新写的 powrprof.dll /
    // wsc.dll / version.dll。那种模块 isSignatureMismatch 恒为假,所以上面那条判据一条都不命中。
    //
    // 单靠「同目录有未签名 DLL」会把一大批绿色软件误判(解压即用的工具天然带一堆自研 DLL,
    // 且多数不签名),故必须叠加互证,二者取其一:
    //   · 该 DLL 最近才落地(进程链的「最近写入」表里有记录)—— 投递刚发生;
    //   · 该 DLL 用的是【系统 DLL 的名字】(sideloadProneModuleNames)—— 正常应用不会在自己
    //     目录里放一个叫 powrprof.dll / version.dll 的私有模块,那是搜索顺序劫持的标准做法。
    //
    // 由 Worker::detectSideloadedTamperedModule 在富化阶段填写,ThreatDetector::analyze 消费。
    // 同样【不能】直接写 riskScore / hasThreatIndicator —— 理由与上面攻击链那段完全一致。
    // 运行时标记,不序列化。
    QString sideloadedUnsignedModulePath; // 非空 = 主体目录内存在「未签名 + 已互证」的可疑模块
    QString sideloadedUnsignedModuleWhy;  // 互证理由(供证据链如实显示是哪一条凑成的)

    // ---- 脚本【文件正文】判据 --------------------------------------------------
    //
    // 补的盲区:脚本宿主的命令行里只有一个文件路径(`cmd.exe /c "C:\...\x.bat"`),
    // 正文一个字节都不在里面。于是一个 1.9MB 的混淆加载器在检测侧和 `echo hello`
    // 完全一样 —— 实测那批样本里 4 个 .bat / 2 个 WSH .js / 1 个 .ps1 全部如此。
    //
    // 由 Worker::scanScriptFileBody 在富化阶段填写(它负责有界读盘 + 调纯函数
    // ScriptAnalyzer::analyzeScriptFile),ThreatDetector::analyze 消费。
    //
    // 【为什么存结论而不存正文】正文上限 256KB,而 SecurityEvent 会被复制、入队、
    // 进 chainContext。把正文挂在事件上等于给每条脚本事件加一次几十万字节的拷贝。
    // 分析本身是纯函数,在富化阶段调一次、只留下这几个小字段最省。
    //
    // 同样【不能】直接写 riskScore / hasThreatIndicator —— 理由与上面攻击链那段完全一致。
    // 运行时标记,不序列化。
    QString scriptFilePath;               // 非空 = 本次宿主要执行的脚本文件(证据链显示用)
    int scriptFileScore = 0;             // 正文判据总分(已在分析器内封顶 100)
    bool scriptFileHardIndicator = false; // 命中行为级判据 —— 按硬指标登记
    QStringList scriptFileHits;          // 命中判据的稳定标识(如 "self-copy-persist")
    QStringList scriptFileReasons;       // 人类可读理由(逐条进证据链)

    QVector<ChainEventInfo> chainContext; // 进程链上下文

    // 记录一条结构化证据,并(默认)同步追加到 riskReasons 保持兼容。
    void addEvidence(const QString& source, EvidenceKind kind,
                     const QString& description, int scoreDelta = 0,
                     bool alsoReason = true);

    // 启动来源的可读标签(如 "服务:Schedule (Task Scheduler)" / "计划任务:\Microsoft\..."),
    // 无判定则返回空串。UI / 攻击图 / 溯源链共用一份措辞。
    QString originLabel() const;

    QJsonObject toJson() const;
    static SecurityEvent fromJson(const QJsonObject& o);
};

} // namespace bulwark
