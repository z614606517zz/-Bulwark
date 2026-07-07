#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/Logger.h"
#include "bulwark/engine/EcsAlertFormatter.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>

namespace bulwark::service {

namespace {
constexpr qint64 kMaxFileBytes = 32LL * 1024 * 1024;
}

AlertExporter::AlertExporter(bool enabled) : enabled_(enabled) {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("alerts"));
    if (enabled_) QDir().mkpath(dir_);
}

void AlertExporter::exportAlert(const bulwark::SecurityEvent& e, const bulwark::Verdict& v) {
    if (!enabled_) return;

    const QJsonObject doc = bulwark::engine::EcsAlertFormatter::format(e, v);
    const QByteArray line = QJsonDocument(doc).toJson(QJsonDocument::Compact) + "\n";

    QMutexLocker lk(&io_);
    QFile f(currentFilePath());
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(line);
        f.close();
    }
    // 导出失败不影响主防御。
}

QString AlertExporter::currentFilePath() {
    const QString baseName = QStringLiteral("alerts-") +
        QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"));
    QString path = QDir(dir_).filePath(baseName + QStringLiteral(".jsonl"));
    int seq = 1;
    while (QFileInfo(path).exists() && QFileInfo(path).size() >= kMaxFileBytes)
        path = QDir(dir_).filePath(QStringLiteral("%1.%2.jsonl").arg(baseName).arg(seq++));
    return path;
}

} // namespace bulwark::service
