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
    //
    // 仅当主体持有【健康签名】(有效签名 + 未失配 / 未吊销 / 未在证书过期后签名)才命中。
    // 与 requireUnsigned 对称,专为「按厂商程序放行」这类 Allow 规则而加。
    //
    // 【为什么需要它】有一批内置 Allow 规则只能按文件名匹配主体,因为目标程序的安装位置
    // 天然多变(浏览器可装 Program Files 也可装 %LOCALAPPDATA%;国内安全软件的目录随 OEM
    // 定制而变),没法像系统组件那样锚定到唯一路径。而「仅文件名 + Allow」等于给任何改名成
    // chrome.exe / 360tray.exe 的样本发放通行证 —— 那是 C2 外联最省事的绕过方式。
    // 加上这个条件后,冒名者因为拿不到目标厂商的有效签名而无法命中,而真程序照常放行。
    //
    // 注意它与 requireUnsigned 互斥:两个都置 true 的规则永不命中(会被 loadRules 的护栏记下)。
    bool requireSigned = false;
    //
    // ---- 按【目标文件自身】的签名门控(与上面两个按主体门控的对称)-------------
    //
    // 上面两个读的是 SecurityEvent::actorSigned —— 也就是【发起方】。对 ImageLoad 来说发起方是
    // 宿主进程(内核模块加载时甚至只是个伪串),而要判的往往是「被加载的这个模块自己有没有可信
    // 签名」。那是 targetSigned / targetSignatureMismatch,与 actorSigned 完全两回事。
    //
    // 目前只有 ImageLoad 事件会被富化出这两个字段;其它事件类型上这两个条件恒为「未签名」,
    // 所以【不要】把它们用在非 ImageLoad 规则上(requireTargetSigned 会永不命中)。
    //
    // 与主体侧同理:两个都置 true 的规则永不命中,由 loadRules 的护栏记下。
    bool requireTargetUnsigned = false; // 仅当目标文件没有可信签名才命中
    bool requireTargetSigned = false;   // 仅当目标文件持有可信且未失配的签名才命中
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
