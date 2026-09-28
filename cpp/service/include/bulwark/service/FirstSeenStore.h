#pragma once
#include <QString>
#include <QSet>
#include <QMutex>

namespace bulwark::service {

// 「首见」哈希记录(SHA-256,大小写不敏感)。用于识别本机首次出现的可执行体。
// 内存集合 + 追加写盘 %ProgramData%\Bulwark\seen_hashes.txt。对应 .NET Storage/FirstSeenStore.cs。
class FirstSeenStore {
public:
    FirstSeenStore();
    // 记录并返回是否「首次出现」。首见 true(同时落盘),之后 false;空哈希返回 false。
    bool markAndCheckFirstSeen(const QString& hash);

private:
    void load();
    void compactLocked();   // 调用方须已持有 lock_(或处于 ctor 无并发阶段)

    // 内存集合与落盘文件的条目上限。二者原先都【无上限】:每个新出现的可执行体一条,
    // 长期运行会累积到几十万条,且启动时整份读进内存。超限即压实到一半(见 compactLocked
    // 里关于"为什么可以任意丢一半"的取舍说明)。
    static constexpr int kMaxEntries = 200000;

    QString path_;
    QSet<QString> seen_;   // 统一存大写以实现大小写不敏感
    QMutex lock_;
};

} // namespace bulwark::service
