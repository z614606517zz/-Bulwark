#pragma once
#include <optional>
#include <QString>
#include <QMutex>
#include "bulwark/engine/BaselineAnalyzer.h"

namespace bulwark::service {

// 行为基线画像持久化(JSON)。%ProgramData%\Bulwark\baseline.json。原子保存(tmp+替换)。
// 损坏/缺失降级为空画像。对应 .NET Storage/BaselineStore.cs。
class BaselineStore {
public:
    BaselineStore();
    std::optional<bulwark::engine::BaselineSnapshot> load();
    void save(const bulwark::engine::BaselineSnapshot& snapshot);

private:
    QString path_;
    QMutex io_;
};

} // namespace bulwark::service
