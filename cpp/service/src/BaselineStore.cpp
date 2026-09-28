#include "bulwark/service/BaselineStore.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/AtomicFile.h"
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

    // 真正的原子保存。原实现的注释说的是「先写 .tmp 再替换」,做的却是
    //   write(tmp) -> remove(path_) -> rename(tmp, path_)
    // 也就是【先把好文件删掉】,再指望改名成功;改名失败时还顺手把 tmp 也删了,两份都没。
    // 而且 tf.write() 的返回值没人看,磁盘满 / 配额不足时会静默写出半截 JSON,下次启动
    // 解析失败 = 基线清零,「偏离自身历史基线」这条检测要重新经历学习期。
    // 这个函数每 5 分钟被定时器调一次、退出时还要再调一次,不是边角路径。
    if (!writeFileAtomically(path_, bytes, QStringLiteral("行为基线")))
        Logger(QStringLiteral("bulwark.service.BaselineStore"))
            .warning(QStringLiteral("行为基线落盘失败,内存态仍有效:%1").arg(path_));
}

} // namespace bulwark::service
