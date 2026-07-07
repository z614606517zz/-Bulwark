#pragma once
#include <QString>
#include <QJsonObject>
#include <optional>
#include "bulwark/ipc/IpcMessageType.h"

namespace bulwark::ipc {

// UI 与服务之间通过命名管道传输的统一消息信封。Payload 为对应类型的 JSON 文本
// (双重编码:整个信封是 JSON,其中 payload 字段本身是一段被转义的 JSON 字符串)。
// 帧格式:按行(\n)分隔的紧凑 JSON —— 与 .NET Ipc/IpcMessage.cs 完全一致。
// 传输层负责在 serialize() 结果后补 '\n'(与 .NET 客户端一致),本类不含换行。
struct IpcMessage {
    IpcMessageType type = IpcMessageType::Hello;
    QString payload;

    // 以一个已构造的 payload JSON 对象封装消息。
    static IpcMessage create(IpcMessageType type, const QJsonObject& payloadObj);
    // 纯字符串负载(如 LogEntry:payload 直接是文本,非 JSON 对象)。
    static IpcMessage createRaw(IpcMessageType type, const QString& rawPayload);

    // 便捷:任意带 toJson() 的模型直接封装。
    template <class T>
    static IpcMessage from(IpcMessageType type, const T& p) {
        return create(type, p.toJson());
    }

    // 序列化为一行紧凑 JSON(不含结尾换行)。
    QString serialize() const;

    // 将 payload 解析回 JSON 对象(payload 非对象时返回空对象)。
    QJsonObject payloadObject() const;

    // 便捷:把 payload 解析为具体模型(要求 T::fromJson(QJsonObject))。
    template <class T>
    T payloadAs() const { return T::fromJson(payloadObject()); }

    // 解析一行文本为消息;空白/非法返回 nullopt(与 C# 返回 null 一致)。
    static std::optional<IpcMessage> deserialize(const QString& line);
};

} // namespace bulwark::ipc
