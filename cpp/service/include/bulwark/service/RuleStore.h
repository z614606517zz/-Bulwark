#pragma once
#include <QString>
#include <QVector>
#include <QMutex>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::service {

// 规则持久化(JSON)。%ProgramData%\Bulwark\rules.json。加载丢弃已到期规则;
// 保存仅落盘「非会话且未到期」的规则。对应 .NET Storage/RuleStore.cs。
class RuleStore {
public:
    RuleStore();
    QVector<bulwark::DefenseRule> load();
    void save(const QVector<bulwark::DefenseRule>& rules);

private:
    QString path_;
    QMutex io_;
};

} // namespace bulwark::service
