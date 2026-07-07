#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QTextStream>

namespace bulwark::service {

FirstSeenStore::FirstSeenStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("seen_hashes.txt"));
    load();
}

void FirstSeenStore::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString h = in.readLine().trimmed();
        if (!h.isEmpty()) seen_.insert(h.toUpper());
    }
    f.close();
}

bool FirstSeenStore::markAndCheckFirstSeen(const QString& hash) {
    if (hash.isEmpty()) return false;
    const QString key = hash.toUpper();

    QMutexLocker lk(&lock_);
    if (seen_.contains(key)) return false; // 已见过
    seen_.insert(key);

    // 落盘失败不影响判定结果(仍视为首见)。
    QFile f(path_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text)) {
        f.write(hash.toUtf8());
        f.write("\r\n");
        f.close();
    }
    return true;
}

} // namespace bulwark::service
