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
    QString path_;
    QSet<QString> seen_;   // 统一存大写以实现大小写不敏感
    QMutex lock_;
};

} // namespace bulwark::service
