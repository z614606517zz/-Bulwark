#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::engine {

// 内置防护规则库 + 开发/CI 白名单辅助。build() 返回全部内置规则(备注以
// builtInTag() "[内置]" 开头;分段源文件见 src/engine/rules/)。对应 .NET Engine/DefaultRules.cs。
struct DefaultRules {
    static QString builtInTag();                 // "[内置]"
    static QVector<DefenseRule> build();         // 全部内置规则(稳定 id、固定创建时刻)

    // 内置注册表规则所需的受关注键片段(键级子串,仅上报不拦截)。服务启动时并入
    // ProtectedRegistryKeys,否则名单外的键不产生事件,对应规则结构性永不命中。
    static QStringList registryWatchFragments();

    static bool isDevTool(const QString& processPath);
    static bool isCiCdEnvironment();
    static bool hasLongEncodedContent(const QString& commandLine);
    static bool isTrustedInstaller(const QString& processPath);
};

} // namespace bulwark::engine
