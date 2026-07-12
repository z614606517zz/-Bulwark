#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QUuid>
#include <QVector>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/models/Evidence.h"
#include "bulwark/models/FileReputation.h"
#include "bulwark/models/ChainEventInfo.h"

namespace bulwark {

// 一次需要裁决的安全事件。由监控层产生,经规则引擎处理得到 Verdict。
// 对应 .NET Models/SecurityEvent.cs(字段一一对应,camelCase 上线)。
struct SecurityEvent {
    QUuid id = QUuid::createUuid();
    QDateTime timestampUtc = QDateTime::currentDateTimeUtc();
    EventType type = EventType::ProcessCreate;

    int actorPid = 0;
    QString actorPath;
    QString actorHash;                    // 可空
    bool actorSigned = false;
    bool signatureMismatch = false;
    qint64 actorFileSize = 0;
    QString actorPublisher;               // 可空
    QString actorCertThumbprint;          // 可空
    std::optional<QDateTime> certNotAfterUtc;
    std::optional<QDateTime> signingTimeUtc;
    bool certRevoked = false;
    bool signedAfterCertExpiry = false;
    bool isFirstSeen = false;
    std::optional<FileReputation> reputation;

    int originatorPid = 0;                // RPC 真凶 PID(0=无)
    QString originatorPath;               // 可空
    int parentPid = 0;
    QString parentPath;
    QString commandLine;                  // 可空
    QString target;                       // 目标:进程/文件/注册表键/远端地址
    QString detail;                       // 可空:端口/值名等

    int riskScore = 0;
    QStringList riskReasons;
    QVector<Evidence> evidenceChain;
    QStringList techniques;               // 命中的 ATT&CK 技战术(去重)

    bool hasThreatIndicator = false;      // 是否出现"硬"恶意指标
    QString matchedRuleNote;              // 可空:命中规则说明
    bool userModeObserved = false;        // 用户态观测源产生(需事后补偿处置)
    bool kernelBlocked = false;           // 该事件对应的操作已被内核在【发生前】真正阻断
                                          //(STATUS_ACCESS_DENIED / 剥权 / WFP BLOCK / 禁止加载),
                                          // 用于如实区分「真前拦」与「事后处置」,避免假拦截显示。
    bool userTrusted = false;             // 运行时:命中用户明确信任(文件/文件夹),引擎在检测前放行,
                                          // Worker 据此跳过全部后台扫描(VT/IP/AI)。运行时标记,不序列化。
    bool memoryInjection = false;         // 内存防护(反注入)命中
    QString fileDescription;              // 可空:FileDescription
    QVector<ChainEventInfo> chainContext; // 进程链上下文

    // 记录一条结构化证据,并(默认)同步追加到 riskReasons 保持兼容。
    void addEvidence(const QString& source, EvidenceKind kind,
                     const QString& description, int scoreDelta = 0,
                     bool alsoReason = true);

    QJsonObject toJson() const;
    static SecurityEvent fromJson(const QJsonObject& o);
};

} // namespace bulwark
