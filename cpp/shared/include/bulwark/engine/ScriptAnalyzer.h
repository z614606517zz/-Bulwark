#pragma once
#include <QString>
#include <optional>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// 脚本类型(内部使用,不上线;顺序对应 .NET 枚举)。
enum class ScriptType {
    Unknown = 0,
    PowerShell,
    Vbscript,
    Javascript,
    Batch,
    Shell,
};

// 脚本内容静态分析器:对 PowerShell/VBS/JS/Batch 脚本体做危险命令 / 混淆 / 编码 /
// 网络特征检测。只有能拿到真正脚本体(如 -EncodedCommand 解码后)时才分类,
// 否则返回 Unknown 交由命令行/混淆分析器处理。对应 .NET Engine/ScriptAnalyzer.cs。
struct ScriptAnalyzer {
    struct Extracted {
        std::optional<QString> content;
        ScriptType type = ScriptType::Unknown;
    };

    static ScoreResult analyzeScript(const QString& scriptContent, ScriptType scriptType);
    static Extracted extractScriptFromCommandLine(const QString& commandLine);
};

} // namespace bulwark::engine
