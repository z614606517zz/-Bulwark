#include "bulwark/service/SettingsStore.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

namespace bulwark::service {

SettingsStore::SettingsStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("settings.json"));
}

std::optional<bulwark::RuntimeSettings> SettingsStore::load() {
    QMutexLocker lk(&io_);
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return std::nullopt;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return std::nullopt;
    bulwark::RuntimeSettings s = bulwark::RuntimeSettings::fromJson(doc.object());
    // kernelConnected / kernelStatus 是【实时派生】的展示字段(由 main.cpp 按协调器现状填),
    // 不是配置。以前它们被一并写进 settings.json 又读回来,于是启动早期会把上一次运行的陈旧
    // 状态当真 —— 最坏情况是驱动其实没起来,面板却照着旧值说"内核驱动已连接",把没有防护
    // 说成有防护。这里读入即丢弃,只认运行时的真实状态。
    s.kernelConnected = false;
    s.kernelStatus.clear();
    return s;
}

void SettingsStore::save(const bulwark::RuntimeSettings& settings) {
    QMutexLocker lk(&io_);
    // 落盘前剔除实时派生的展示字段(理由同 load()):它们经 IPC 发给 UI 没问题,但写进
    // 配置文件就会变成误导人的陈旧快照。toJson() 是 IPC 与落盘共用的,所以在这里剥。
    QJsonObject o = settings.toJson();
    o.remove(QStringLiteral("kernelConnected"));
    o.remove(QStringLiteral("kernelStatus"));
    // 原子落盘:一次截断写就能把用户的全部设置清空(见 AtomicFile.h)。
    writeFileAtomically(path_, QJsonDocument(o).toJson(QJsonDocument::Indented),
                        QStringLiteral("运行时设置"));
}

} // namespace bulwark::service
