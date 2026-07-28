#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

namespace bulwark::service {

RuleStore::RuleStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("rules.json"));
}

QVector<bulwark::DefenseRule> RuleStore::load() {
    QMutexLocker lk(&io_);
    QVector<bulwark::DefenseRule> out;
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return out;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) return out;

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QJsonArray arr = doc.array();
    out.reserve(arr.size());
    for (const QJsonValue& v : arr) {
        if (!v.isObject()) continue;
        const bulwark::DefenseRule r = bulwark::DefenseRule::fromJson(v.toObject());
        if (!r.isExpired(now)) out.append(r); // 加载时丢弃已到期规则
    }
    return out;
}

void RuleStore::save(const QVector<bulwark::DefenseRule>& rules) {
    QMutexLocker lk(&io_);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QJsonArray arr;
    for (const bulwark::DefenseRule& r : rules) {
        // 仅持久化「非会话且未到期」的规则。
        if (r.sessionOnly || r.isExpired(now)) continue;
        arr.append(r.toJson());
    }
    // 原子落盘:规则库里有用户的加白项,一次截断写就能把它们全弄丢(见 AtomicFile.h)。
    // 环境性写入失败(权限/占用)不应崩溃:内存规则仍生效,仅本次不落盘。
    writeFileAtomically(path_, QJsonDocument(arr).toJson(QJsonDocument::Indented),
                        QStringLiteral("规则库"));
}

} // namespace bulwark::service
