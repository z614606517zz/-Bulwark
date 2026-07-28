#pragma once
#include <QList>
#include <QUuid>
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 攻击图构建器:把一堆孤立的已处置事件还原成「一次入侵的形状」。
//
// 输入是事件历史里的一段(调用方按时间窗筛过),外加一个种子(用户在日志里双击的那条事件
// 或一个 PID)。输出是一张以【进程树】为骨架的有向图,骨架之外挂上这些进程碰过的文件 /
// 注册表键 / 远端地址 / 域名 / 模块,以及把它们拉起来的服务 / 计划任务。
//
// 关键取舍:
//  · 关联范围 = 「种子的祖先链(限层数)+ 种子自身 + 种子的全部后代」。不取祖先的兄弟分支 ——
//    否则从 explorer.exe 往下能把用户开的所有程序都拽进来,图会失去意义。
//  · 边按 (起点, 终点, 行为类型) 去重,合并时保留【最严重】的那次(风险分优先,其次 Block
//    优于 Allow,再次时间更晚)。逐条时序细节由「事件时间线」页负责,图负责结构。
//  · 只做关联与呈现,不做任何判定:风险分、裁决、实际处置全部沿用事件里引擎已经给出的结论,
//    绝不在这里二次评分 —— 图上看到的每个结论都能在事件详情里对上。
class AttackGraphBuilder {
public:
    // 一条输入事件:事件本体 + 引擎裁决 + 实际处置结果(与 ipc::EventLogPayload 同构,
    // 但不依赖 IPC 层,保持 engine 对 ipc 的零依赖)。
    struct Input {
        bulwark::SecurityEvent event;
        bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
        bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    };

    struct Options {
        int maxAncestorDepth = 4;   // 向上回溯的祖先层数上限
        int maxNodes = 160;         // 节点上限(超出即截断并置 truncated)
        int maxEdges = 320;         // 边上限
    };

    // seedEventId 命中不到时,退化为「以 rootPid 最近一条事件为种子」;两者都给不出时返回空图。
    static bulwark::AttackGraph build(const QList<Input>& events, const QUuid& seedEventId,
                                      int rootPid, const Options& opt = Options{});
};

} // namespace bulwark::engine
