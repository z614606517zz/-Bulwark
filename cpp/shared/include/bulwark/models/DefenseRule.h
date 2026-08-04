#pragma once
#include <QString>
#include <QDateTime>
#include <QUuid>
#include <QSet>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/Clock.h"

namespace bulwark {

struct SecurityEvent; // fwd

// 一条持久化防护规则。多个可选条件全部满足才命中(未设置视为「任意」)。
// 对应 .NET Models/DefenseRule.cs,含通配匹配 / 命中判定 / 具体度评分。
struct DefenseRule {
    // 「文件信任中心」生成的放行规则备注以此标记开头。
    static QString trustNoteTag();

    QUuid id = QUuid::createUuid();
    QString actorPath;              // 精确主体路径(大小写不敏感),空=不限
    QString actorPattern;           // 主体路径通配(*),空=不限
    std::optional<EventType> type;  // 事件类型,nullopt=所有类型
    QString targetPattern;          // 目标通配(*),空=不限
    QString commandLinePattern;     // 命令行通配(*),空=不限
    QString parentPattern;          // 父进程通配(*),空=不限
    bool requireUnsigned = false;   // 仅当主体无可信签名才命中
    bool exemptTrustedOsComponent = false; // 命中后可被强可信 OS 组件豁免
    bool hardOverride = false;      // 确定性恶意硬拦截(排序最高优先级)
    QSet<QString> actorHashes;      // 哈希黑/白名单(SHA-256),空=不限
    VerdictAction action = VerdictAction::Allow;
    QString note;                   // 备注/来源说明
    QDateTime createdUtc = nowUtc();
    std::optional<QDateTime> expiresUtc; // 到期时间,nullopt=永久
    bool sessionOnly = false;       // 仅本次会话有效(不落盘)
    bool enabled = true;

    bool isExpired(const QDateTime& nowUtc) const {
        return expiresUtc.has_value() && *expiresUtc <= nowUtc;
    }
    bool isTrustEntry() const {
        return !note.isEmpty() && note.startsWith(trustNoteTag());
    }

    // 命中判定:所有已设置条件均需满足。
    bool matches(const SecurityEvent& e) const;
    // 规则具体度(越大越优先)。
    int specificityScore() const;

    // 工厂:文件信任 / 目录信任(命中即放行该主体的所有行为)。
    static DefenseRule createTrust(const QString& actorPath, const QString& note = QString());
    static DefenseRule createTrustDirectory(const QString& dirPath, const QString& note = QString());

    // 极简通配匹配,支持 '*'(任意长度)与 '?';大小写不敏感。
    static bool wildcardMatch(const QString& pattern, const QString& input);

    QJsonObject toJson() const;
    static DefenseRule fromJson(const QJsonObject& o);
};

} // namespace bulwark
