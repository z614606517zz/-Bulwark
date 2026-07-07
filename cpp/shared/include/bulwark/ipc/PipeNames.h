#pragma once
#include <QString>

namespace bulwark::ipc {

// UI 与服务之间的命名管道名称。与 .NET PipeNames.ControlPipe 一致。
// Qt 的 QLocalSocket/QLocalServer 在 Windows 上以此名映射到 \\.\pipe\Bulwark.Control,
// 因此能与 .NET NamedPipeServerStream("Bulwark.Control") 互通(strangler 过渡期用)。
inline QString controlPipe() { return QStringLiteral("Bulwark.Control"); }

} // namespace bulwark::ipc
