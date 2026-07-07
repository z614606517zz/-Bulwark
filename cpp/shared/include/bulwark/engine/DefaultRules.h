#pragma once
#include <QString>
#include <QVector>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::engine {

// 内置防护规则库 + 开发/CI 白名单辅助。build() 返回全部内置规则(备注以
// builtInTag() "[内置]" 开头)。对应 .NET Engine/DefaultRules.cs。
struct DefaultRules {
    static QString builtInTag();                 // "[内置]"
    static QVector<DefenseRule> build();         // 全部内置规则

    static bool isDevTool(const QString& processPath);
    static bool isCiCdEnvironment();
    static bool hasLongEncodedContent(const QString& commandLine);
    static bool isTrustedInstaller(const QString& processPath);
};

} // namespace bulwark::engine
