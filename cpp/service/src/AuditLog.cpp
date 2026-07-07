#include "bulwark/service/AuditLog.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>

namespace bulwark::service {

namespace {
constexpr qint64 kMaxFileBytes = 16LL * 1024 * 1024;
}

AuditLog::AuditLog() {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("audit"));
    QDir().mkpath(dir_);
}

void AuditLog::writeRecord(const QJsonObject& record) {
    const QByteArray line = QJsonDocument(record).toJson(QJsonDocument::Compact) + "\r\n";

    QMutexLocker lk(&io_);
    const QString path = currentFilePath();
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(line);
        f.close();
    }
    // 写入失败(磁盘满/权限)绝不影响主流程。
}

QString AuditLog::currentFilePath() {
    const QString baseName = QStringLiteral("audit-") +
        QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"));
    QString path = QDir(dir_).filePath(baseName + QStringLiteral(".jsonl"));
    int seq = 1;
    while (QFileInfo(path).exists() && QFileInfo(path).size() >= kMaxFileBytes)
        path = QDir(dir_).filePath(QStringLiteral("%1.%2.jsonl").arg(baseName).arg(seq++));
    return path;
}

} // namespace bulwark::service
