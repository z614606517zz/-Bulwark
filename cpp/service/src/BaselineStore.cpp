#include "bulwark/service/BaselineStore.h"
#include "bulwark/service/Logger.h"
#include "bulwark/json/JsonSupport.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace bulwark::service {
using namespace bulwark::json;
using bulwark::engine::BaselineSnapshot;
using bulwark::engine::BaselineProgram;

namespace {
QJsonObject programToJson(const BaselineProgram& p) {
    QJsonObject o;
    o["key"] = p.key;
    o["firstSeenUtc"] = dateTimeToIso(p.firstSeenUtc);
    o["lastSeenUtc"] = dateTimeToIso(p.lastSeenUtc);
    o["childObs"] = p.childObs;
    o["hostObs"] = p.hostObs;
    o["writeObs"] = p.writeObs;
    o["children"] = strListToJson(p.children);
    o["hosts"] = strListToJson(p.hosts);
    o["writeDirs"] = strListToJson(p.writeDirs);
    return o;
}
BaselineProgram programFromJson(const QJsonObject& o) {
    BaselineProgram p;
    p.key = getStr(o, "key");
    p.firstSeenUtc = dateTimeFromIso(getStr(o, "firstSeenUtc"));
    p.lastSeenUtc = dateTimeFromIso(getStr(o, "lastSeenUtc"));
    p.childObs = getInt(o, "childObs");
    p.hostObs = getInt(o, "hostObs");
    p.writeObs = getInt(o, "writeObs");
    p.children = getStrList(o, "children");
    p.hosts = getStrList(o, "hosts");
    p.writeDirs = getStrList(o, "writeDirs");
    return p;
}
} // namespace

BaselineStore::BaselineStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("baseline.json"));
}

std::optional<BaselineSnapshot> BaselineStore::load() {
    QMutexLocker lk(&io_);
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return std::nullopt;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return std::nullopt;

    BaselineSnapshot snap;
    const QJsonArray progs = doc.object().value(QLatin1String("programs")).toArray();
    for (const QJsonValue& v : progs)
        if (v.isObject()) snap.programs.append(programFromJson(v.toObject()));
    return snap;
}

void BaselineStore::save(const BaselineSnapshot& snapshot) {
    QMutexLocker lk(&io_);
    QJsonArray progs;
    for (const BaselineProgram& p : snapshot.programs) progs.append(programToJson(p));
    QJsonObject root;
    root["programs"] = progs;
    const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);

    // 原子保存:先写 .tmp 再替换,避免中途崩溃留下半截文件。
    const QString tmp = path_ + QStringLiteral(".tmp");
    QFile tf(tmp);
    if (!tf.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    tf.write(bytes);
    tf.close();
    QFile::remove(path_);
    if (!QFile::rename(tmp, path_)) QFile::remove(tmp);
}

} // namespace bulwark::service
