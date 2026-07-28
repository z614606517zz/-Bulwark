#pragma once
#include <QList>
#include <QDateTime>
#include <QUuid>
#include <memory>
#include <optional>
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

// 结构化事件历史存储:内存环形缓冲(最近 N 条,供快速回读)+ 后台线程 JSONL 落盘
// %ProgramData%\Bulwark\history\events.jsonl,重启保留。线程安全。
// 注:原 C++ 头已丢失,此处按 EventHistoryStore.cpp 用法重建。
class EventHistoryStore {
public:
    EventHistoryStore();
    ~EventHistoryStore();

    void add(const bulwark::ipc::EventLogPayload& payload);
    QList<bulwark::ipc::EventLogPayload> getRecent();
    void clear(); // 清空内存缓冲 + 落盘文件(活动日志/拦截记录「清空」)

    // ---- 时间线 / 攻击图的取证查询(只读,直接扫落盘 JSONL)----
    //
    // 为什么不走内存环形缓冲:缓冲只留最近 500 条,而落盘文件能存到 24MB(数万条)。
    // 「回看昨天那次可疑外联」正需要这份更深的历史。
    //
    // 三个方法都是【纯读】且可能耗时(解析数万条 JSON),必须在后台线程调用,
    // 不要在 IPC / 事件裁决线程上直接调,否则会卡住服务的事件循环。
    // 与写线程并发是安全的:文件只追加,读到半行会解析失败并被跳过。

    // 按条件查询时间线。返回的 events 按时间【升序】,数量受 req.limit 限制(硬上限 5000)。
    bulwark::ipc::TimelineResponsePayload query(const bulwark::ipc::TimelineRequestPayload& req);

    // 取某时间窗内的全部事件(升序,受 maxEvents 上限)。供攻击图做进程树关联。
    QList<bulwark::ipc::EventLogPayload> eventsInWindow(const QDateTime& fromUtc,
                                                       const QDateTime& toUtc, int maxEvents);

    // 按事件 id 精确取一条(先查内存缓冲,未命中再倒序扫落盘)。攻击图据此定位种子事件。
    std::optional<bulwark::ipc::EventLogPayload> findById(const QUuid& id);

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace bulwark::service
