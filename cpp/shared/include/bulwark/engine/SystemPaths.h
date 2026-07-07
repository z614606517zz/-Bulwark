#pragma once
#include <QString>

namespace bulwark::engine {

// 路径工具。注:原 .NET SystemPaths.cs 源已缺失,此处按 ThreatDetector 的用法重建。
struct SystemPaths {
    // 卷相对路径:去掉盘符(和 \\?\ / \\.\ 前缀),返回以 '\' 开头的卷内路径。
    // 例:"c:\\windows\\system32\\svchost.exe" -> "\\windows\\system32\\svchost.exe"。
    static QString volumeRelative(const QString& path);
};

} // namespace bulwark::engine
