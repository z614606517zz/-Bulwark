#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QTextStream>

namespace bulwark::service {

namespace {
// 一条 SHA-256 十六进制串必须正好 64 个十六进制字符。落盘文件是纯文本、可被外部改动,
// 读入时不校验就会把任意垃圾行灌进内存集合(白占内存,还会让"首见"判定出现假阴性)。
bool isSha256Hex(const QString& s) {
    if (s.size() != 64) return false;
    for (const QChar qc : s) {
        const char c = qc.toLatin1();
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}
} // namespace

FirstSeenStore::FirstSeenStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("seen_hashes.txt"));
    load();
}

void FirstSeenStore::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    int skipped = 0;
    while (!in.atEnd()) {
        const QString h = in.readLine().trimmed().toUpper();
        if (h.isEmpty()) continue;
        if (!isSha256Hex(h)) { ++skipped; continue; }
        seen_.insert(h);
        // 读入阶段也要设界:文件是只增不减的,机器跑久了它就是一份无上限的清单,
        // 而它会被整份读进内存常驻。超过上限就停止读入,余下的留给下面的 compact()。
        if (seen_.size() >= kMaxEntries) break;
    }
    f.close();
    if (skipped > 0)
        Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
            .warning(QStringLiteral("首见哈希文件中有 %1 行不是合法的 SHA-256,已忽略:%2")
                         .arg(skipped).arg(path_));
    if (seen_.size() >= kMaxEntries)
        compactLocked();   // ctor 期间无并发,直接压实
}

bool FirstSeenStore::markAndCheckFirstSeen(const QString& hash) {
    if (hash.isEmpty()) return false;
    const QString key = hash.toUpper();
    if (!isSha256Hex(key)) return false;   // 非法哈希不参与"首见"判定,也不落盘

    QMutexLocker lk(&lock_);
    if (seen_.contains(key)) return false; // 已见过
    seen_.insert(key);

    // 到上限就整份重写(而不是继续追加)。这份文件与内存集合原本都是【无上限】增长的:
    // 每个新出现的可执行体一条,长期运行的机器上会累积到几十万条,启动时还要全部读进内存。
    if (seen_.size() > kMaxEntries) {
        compactLocked();
        return true;
    }

    // 落盘失败不影响判定结果(仍视为首见)。
    QFile f(path_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text)) {
        f.write(key.toUtf8());
        f.write("\r\n");
        f.close();
    }
    return true;
}

// 把内存集合截到上限的一半并整份重写文件。
//
// 「留哪一半」这里没有可用的时间信息(文件里只有哈希,没有时间戳),所以只能任意留 —— 这是
// 刻意接受的取舍:被丢掉的哈希下次出现时会再被判成"首见"一次,而"首见"按产品设计只是
// 一个【软信号】(单独绝不触发拦截或询问,只加分且需要硬指标互证),所以代价是可控的;
// 而无上限增长的代价是内存与启动耗时随使用时间单调上升。
void FirstSeenStore::compactLocked() {
    const int keep = kMaxEntries / 2;
    QSet<QString> trimmed;
    trimmed.reserve(keep);
    for (const QString& h : seen_) {
        if (trimmed.size() >= keep) break;
        trimmed.insert(h);
    }
    seen_.swap(trimmed);

    QFile f(path_);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
            .warning(QStringLiteral("首见哈希文件压实失败(仅内存已压实):%1").arg(path_));
        return;
    }
    QByteArray out;
    out.reserve(seen_.size() * 66);
    for (const QString& h : seen_) {
        out += h.toUtf8();
        out += "\r\n";
    }
    f.write(out);
    f.close();
    Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
        .info(QStringLiteral("首见哈希已压实至 %1 条(上限 %2)").arg(seen_.size()).arg(kMaxEntries));
}

} // namespace bulwark::service
