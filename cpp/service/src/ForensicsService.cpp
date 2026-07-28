#include "bulwark/service/ForensicsService.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/engine/AttackGraphBuilder.h"

#include <algorithm>

namespace bulwark::service::ForensicsService {

using bulwark::engine::AttackGraphBuilder;

bulwark::ipc::TimelineResponsePayload queryTimeline(EventHistoryStore& history,
                                                    const bulwark::ipc::TimelineRequestPayload& req)
{
    return history.query(req);
}

bulwark::ipc::AttackGraphResponsePayload buildAttackGraph(
    EventHistoryStore& history, const bulwark::ipc::AttackGraphRequestPayload& req)
{
    bulwark::ipc::AttackGraphResponsePayload res;
    res.requestId = req.requestId;

    // ---- 1) 定位种子:优先按事件 id;没给或找不到就退到「该 PID 最近一条事件」。----
    std::optional<bulwark::ipc::EventLogPayload> seed;
    if (!req.seedEventId.isNull())
        seed = history.findById(req.seedEventId);

    QDateTime anchor;
    int rootPid = req.rootPid;
    if (seed.has_value()) {
        anchor = seed->event.timestampUtc;
        if (rootPid <= 0)
            rootPid = seed->event.actorPid;
    }
    if (!anchor.isValid())
        anchor = QDateTime::currentDateTimeUtc();

    // ---- 2) 取时间窗内的事件。窗口取种子时间【前后】各 window 秒:攻击的上游(谁把它拉起来)
    //         在种子之前,下游(它接着干了什么)在种子之后,只看单侧会把一半的因果丢掉。----
    const int window = std::clamp(req.windowSeconds <= 0 ? 3600 : req.windowSeconds, 60, 24 * 3600);
    const QDateTime from = anchor.addSecs(-window);
    const QDateTime to = anchor.addSecs(window);
    const QList<bulwark::ipc::EventLogPayload> raw = history.eventsInWindow(from, to, 3000);

    if (raw.isEmpty() && !seed.has_value()) {
        res.success = false;
        res.message = req.seedEventId.isNull()
            ? QString::fromUtf8("该时间窗内没有与此进程相关的历史事件,无法构建关系图")
            : QString::fromUtf8("未在事件历史中找到该事件(可能已被清空或超出保留范围)");
        return res;
    }

    // ---- 3) 交给共享层的构建器关联。种子本身可能不在窗口结果里(例如历史刚被裁剪),
    //         补进去,保证「用户点的那条」一定在图上。----
    QList<AttackGraphBuilder::Input> inputs;
    inputs.reserve(raw.size() + 1);
    bool seedIncluded = false;
    for (const bulwark::ipc::EventLogPayload& p : raw) {
        if (seed.has_value() && p.event.id == seed->event.id)
            seedIncluded = true;
        inputs.append({p.event, p.action, p.enforcement});
    }
    if (seed.has_value() && !seedIncluded)
        inputs.append({seed->event, seed->action, seed->enforcement});

    AttackGraphBuilder::Options opt;
    res.graph = AttackGraphBuilder::build(inputs, seed.has_value() ? seed->event.id : QUuid(),
                                          rootPid, opt);
    res.success = !res.graph.isEmpty();
    res.message = res.success
        ? res.graph.summary
        : (req.seedEventId.isNull()
               ? QString::fromUtf8("该进程在最近的事件历史里没有留下记录,无法构建关系图")
               : QString::fromUtf8("该事件没有可关联的进程上下文(主体 PID 未知或历史里只有它自己)"));
    return res;
}

} // namespace bulwark::service::ForensicsService
