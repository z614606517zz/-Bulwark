#pragma once
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

class EventHistoryStore;

// 取证查询:事件时间线 + 攻击图。两者都只【读】事件历史,不碰引擎、不做处置、不改任何状态。
//
// 放在服务端而不是 UI 侧的理由:
//  1) 历史落在服务的 ProgramData 目录里,UI 不该也不能直接读;
//  2) 关联逻辑必须只有一份 —— 如果 UI 自己再推一遍进程树,界面上画出来的关系就可能和引擎
//     实际依据的关系不一致,那是排查事故时最要命的一类偏差。
//
// 两个函数都可能解析数万条 JSON,【必须在后台线程调用】。
namespace ForensicsService {

// 时间线查询:条件过滤后按时间升序返回(参数与上限见 TimelineRequestPayload)。
bulwark::ipc::TimelineResponsePayload queryTimeline(EventHistoryStore& history,
                                                    const bulwark::ipc::TimelineRequestPayload& req);

// 攻击图:以某条事件(优先)或某 PID 为种子,取其时间窗内的事件交给 AttackGraphBuilder 关联成图。
bulwark::ipc::AttackGraphResponsePayload buildAttackGraph(
    EventHistoryStore& history, const bulwark::ipc::AttackGraphRequestPayload& req);

} // namespace ForensicsService

} // namespace bulwark::service
