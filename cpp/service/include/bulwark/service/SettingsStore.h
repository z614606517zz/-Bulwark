#pragma once
#include <optional>
#include <QString>
#include <QMutex>
#include "bulwark/models/RuntimeSettings.h"

namespace bulwark::service {

// 运行时设置持久化(JSON)。%ProgramData%\Bulwark\settings.json。
// 不存在返回 nullopt,由调用方用 appsettings.json 默认值初始化。对应 .NET Storage/SettingsStore.cs。
class SettingsStore {
public:
    SettingsStore();
    std::optional<bulwark::RuntimeSettings> load();
    void save(const bulwark::RuntimeSettings& settings);

private:
    QString path_;
    QMutex io_;
};

} // namespace bulwark::service
