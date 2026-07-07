#pragma once
#include <QList>
#include <memory>
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

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace bulwark::service
