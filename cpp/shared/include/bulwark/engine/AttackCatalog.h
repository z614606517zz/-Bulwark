#pragma once
#include <QString>
#include <optional>

namespace bulwark::engine {

// MITRE ATT&CK 技战术精简目录:编号 -> (中文名 + 战术阶段)。查表,零运行时成本。
// 对应 .NET Engine/AttackCatalog.cs。
struct AttackCatalog {
    struct Technique {
        QString id;
        QString name;
        QString tactic;
    };

    // 查找;支持父技战术兜底(T1218.999 未收录时回退 T1218)。
    static std::optional<Technique> lookup(const QString& id);
    // "T1218.010 Regsvr32 代理执行(Squiblydoo)" 形式的可读标签;未收录回退裸编号。
    static QString describe(const QString& id);
};

} // namespace bulwark::engine
