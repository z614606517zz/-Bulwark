#include "bulwark/service/SettingsStore.h"
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
    return bulwark::RuntimeSettings::fromJson(doc.object());
}

void SettingsStore::save(const bulwark::RuntimeSettings& settings) {
    QMutexLocker lk(&io_);
    QFile f(path_);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    f.write(QJsonDocument(settings.toJson()).toJson(QJsonDocument::Indented));
    f.close();
}

} // namespace bulwark::service
