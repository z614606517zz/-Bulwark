#pragma once
#include <QString>
#include <QStringList>
#include <QList>
#include <QDateTime>
#include <QUuid>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

// 攻击图(关联图)模型。
//
// 「活动日志」是一条条孤立的行为记录,看不出一次入侵的形状:谁拉起了谁、谁落了哪个盘、
// 哪一步才是真正的转折点。攻击图把一段时间窗内属于【同一进程树 / 同一会话】的事件还原成
// 一张有向图:
//   · 节点(Node)= 参与实体:进程、文件、注册表键、远端地址/域名、服务、计划任务;
//   · 边(Edge)  = 一次具体行为:创建进程 / 注入 / 写文件 / 写注册表 / 外联 / 加载模块…,
//                  边上带时间、风险分、裁决与实际处置结果。
//
// 图由服务端从事件历史构建(AttackGraphBuilder),经 IPC 整体下发给 UI 绘制 —— UI 不做
// 任何关联推断,只负责画,保证「界面看到的关系」与「引擎实际依据的关系」完全一致。
enum class AttackNodeKind {
    Process = 0,     // 进程
    File,            // 文件(写入/删除/释放载荷)
    Registry,        // 注册表键
    Network,         // 远端地址(ip:port)
    Domain,          // 域名(DNS 解析)
    Module,          // 被加载的模块 / 驱动
    Service,         // Windows 服务(启动来源或被创建的服务)
    ScheduledTask,   // 计划任务(启动来源)
};

QString attackNodeKindToString(AttackNodeKind k);
AttackNodeKind attackNodeKindFromString(const QString& s);

// 图节点。id 在一张图内唯一(进程用 "p:<pid>:<首见时间戳>",其它用 "<kind>:<规范化目标>")。
struct AttackGraphNode {
    QString id;
    AttackNodeKind kind = AttackNodeKind::Process;
    QString label;             // 展示名(进程 = 映像文件名;文件 = 文件名;网络 = ip:port)
    QString detail;            // 次要信息(完整路径 / 完整目标)
    int pid = 0;               // 仅进程节点
    int parentPid = 0;         // 仅进程节点
    QString path;              // 仅进程节点:映像完整路径
    QString commandLine;       // 仅进程节点(可空,已截断)
    bool signedActor = false;  // 仅进程节点:是否带可信签名
    QString publisher;         // 仅进程节点
    int riskScore = 0;         // 该节点相关事件的最高风险分
    bool blocked = false;      // 该节点相关行为中出现过「已真正拦截」
    bool isSeed = false;       // 是否为本次查询的种子(触发查看的那条事件的主体)
    bool isRoot = false;       // 是否为图的根(最上游祖先)
    int depth = 0;             // 距根的层数(仅进程节点有意义;供 UI 分层布局)
    // 启动来源(进程节点):服务 / 计划任务 等,已在服务端解析成可读标签。
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originLabel;
    int eventCount = 0;        // 以该节点为主体的事件数
    QDateTime firstSeenUtc;
    QDateTime lastSeenUtc;

    QJsonObject toJson() const;
    static AttackGraphNode fromJson(const QJsonObject& o);
};

// 图边 = 一次具体行为。fromId 通常是进程节点,toId 是被作用的实体。
struct AttackGraphEdge {
    QUuid eventId;
    QString fromId;
    QString toId;
    EventType type = EventType::ProcessCreate;
    QString label;             // 行为措辞(如 "创建进程" / "写入文件")
    QString detail;            // 目标补充(端口 / 值名 等)
    QDateTime timestampUtc;
    int riskScore = 0;
    VerdictAction action = VerdictAction::Allow;
    EnforcementOutcome enforcement = EnforcementOutcome::NotApplicable;
    bool hasThreatIndicator = false;
    QStringList techniques;    // 该行为命中的 ATT&CK 技战术
    bool inferred = false;     // true = 由父子关系推导(非直接观测到的事件),UI 用虚线画

    QJsonObject toJson() const;
    static AttackGraphEdge fromJson(const QJsonObject& o);
};

struct AttackGraph {
    QUuid seedEventId;         // 种子事件(从哪条事件展开)
    int rootPid = 0;           // 图根进程 PID
    QString rootLabel;         // 图根展示名
    QList<AttackGraphNode> nodes;
    QList<AttackGraphEdge> edges;
    QStringList techniques;    // 全图去重后的 ATT&CK 技战术
    QDateTime firstUtc;        // 时间跨度
    QDateTime lastUtc;
    int maxRiskScore = 0;
    int eventCount = 0;        // 纳入本图的事件总数
    bool truncated = false;    // 是否因上限截断
    QString summary;           // 一句话概述(服务端生成,如 "3 个进程 · 7 次行为 · 已拦截 2 次")

    bool isEmpty() const { return nodes.isEmpty(); }

    QJsonObject toJson() const;
    static AttackGraph fromJson(const QJsonObject& o);
};

} // namespace bulwark
