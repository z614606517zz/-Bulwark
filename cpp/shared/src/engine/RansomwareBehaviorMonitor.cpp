#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include <QVector>
#include <algorithm>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

const QStringList& ransomNoteHints() {
    static const QStringList s = {
        "how_to_decrypt", "how-to-decrypt", "how_to_recover", "how-to-recover",
        "recover_files", "recover-files", "recover_your_files",
        "decrypt_instruction", "decryption_instruction", "restore_files",
        "restore-my-files", "readme_for_decrypt", "files_encrypted",
        "your_files_are_encrypted", "decrypt-files", "_openme", "_help_decrypt",
    };
    return s;
}

const QSet<QString>& knownEncryptedExts() {
    static const QSet<QString> s = {
        ".locked", ".crypt", ".crypted", ".encrypted", ".enc", ".lock",
        ".wcry", ".wncry", ".locky", ".cerber", ".zepto", ".odin",
        ".aaa", ".xtbl", ".ecc", ".kkk", ".micro", ".ttt", ".pzdc",
    };
    return s;
}

//
// 「扩展名同化」判据必须排除的扩展名:安装器 / 解压器 / 编译器 / 同步工具产出的中间文件。
//
// 判据本身是「短时间内大量文件统一成同一个扩展名」—— 对勒索来说那是加密后缀,但对
// 下面这些扩展名来说,统一恰恰是它们的工作方式,与加密毫无关系:
//   · .tmp  —— Inno Setup 把整个安装模块解包成 %TEMP%\is-XXXX.tmp\*.tmp;NSIS 用 nsXXXX.tmp。
//             实测 innosetup-6.7.3.tmp 一次写出 116 个文件、其中 110 个是 .tmp,被判
//             「疑似勒索加密 + 扩展名同化」,随后静默模式升级为拦截并结束进程树 ——
//             官方安装包(winget 装的)装不上去。
//   · .part / .crdownload / .download —— 浏览器与下载器的未完成文件。
//   · .log / .etl / .dmp —— 日志与转储轮转。
//   · .bak / .old —— 备份工具。
//   · .pyc / .obj / .o / .pdb / .ilk / .lastbuildstate —— 编译中间产物(本项目自己构建时就会刷一大片)。
//   · .json / .db / .db-journal / .ldb / .sqlite-journal —— 浏览器 / Electron 应用的本地状态。
//   · .cache / .idx / .pack —— 缓存与 git 对象。
// 真勒索的后缀不在这张表里,而且它另有三条不受本表影响的硬判据:已知勒索扩展名(×3)、
// 勒索说明文件、蜜罐诱饵 —— 后者是无条件拦截。
//
const QSet<QString>& toolchainExts() {
    static const QSet<QString> s = {
        ".tmp", ".temp", ".part", ".crdownload", ".download", ".partial",
        ".log", ".etl", ".dmp", ".bak", ".old", ".~tmp",
        ".pyc", ".pyo", ".obj", ".o", ".pdb", ".ilk", ".lastbuildstate", ".tlog",
        ".json", ".db", ".db-journal", ".ldb", ".sqlite-journal", ".journal",
        ".cache", ".idx", ".pack", ".manifest", ".res",
    };
    // 刻意不收 .lock:它在 knownEncryptedExts() 里,且那一支(已知勒索扩展名)排在前面、
    // 门槛更低(×3 即硬指标)。两张表重叠会让这里读起来自相矛盾。
    return s;
}

// Path.GetExtension 等价:返回最后一段的最后一个 '.' 起(含点),小写;无则空。
QString getExtension(const QString& path) {
    const int sep = qMax(path.lastIndexOf(QLatin1Char('\\')), path.lastIndexOf(QLatin1Char('/')));
    const QString name = sep >= 0 ? path.mid(sep + 1) : path;
    const int dot = name.lastIndexOf(QLatin1Char('.'));
    if (dot < 0) return QString();
    return name.mid(dot).toLower();
}

} // namespace

void RansomwareBehaviorMonitor::ProcState::addCounts(const QString& path, const QString& ext) {
    pathOccur[path] = pathOccur.value(path, 0) + 1;
    if (ext.isEmpty()) return;
    QHash<QString, int>& m = extPaths[ext];
    m[path] = m.value(path, 0) + 1;
}

void RansomwareBehaviorMonitor::ProcState::removeCounts(const QString& path, const QString& ext) {
    auto it = pathOccur.find(path);
    if (it != pathOccur.end()) {
        if (it.value() <= 1) pathOccur.erase(it);
        else it.value() = it.value() - 1;
    }
    if (ext.isEmpty()) return;
    auto mit = extPaths.find(ext);
    if (mit != extPaths.end()) {
        QHash<QString, int>& m = mit.value();
        auto pit = m.find(path);
        if (pit != m.end()) {
            if (pit.value() <= 1) m.erase(pit);
            else pit.value() = pit.value() - 1;
        }
        if (m.isEmpty()) extPaths.erase(mit);
    }
}

void RansomwareBehaviorMonitor::ProcState::touch(const QString& path, const QDateTime& at, int windowSecs) {
    const QString ext = getExtension(path);
    writes.append({ path, at, ext });
    addCounts(path, ext);

    const QDateTime cutoff = at.addSecs(-windowSecs);
    int i = 0;
    while (i < writes.size() && writes.at(i).at < cutoff) {
        removeCounts(writes.at(i).path, writes.at(i).ext);
        ++i;
    }
    if (i > 0) writes.remove(0, i);

    constexpr int hardCap = 4096;
    if (writes.size() > hardCap) {
        const int excess = writes.size() - hardCap;
        for (int k = 0; k < excess; ++k) removeCounts(writes.at(k).path, writes.at(k).ext);
        writes.remove(0, excess);
    }
}

int RansomwareBehaviorMonitor::ProcState::sameExtensionCount(const QString& ext) const {
    auto it = extPaths.constFind(ext);
    return it != extPaths.constEnd() ? it.value().size() : 0;
}

RansomwareBehaviorMonitor::RansomwareBehaviorMonitor(int windowSeconds, int burstThreshold, int maxPids) {
    windowSecs_ = windowSeconds > 0 ? windowSeconds : 10;
    burstThreshold_ = qMax(5, burstThreshold);
    maxPids_ = qMax(64, maxPids);
}

void RansomwareBehaviorMonitor::addCanaryFile(const QString& path) {
    if (path.trimmed().isEmpty()) return;
    QString p = path.trimmed().toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QMutexLocker locker(&gate_);
    canaryPaths_.insert(p);
}

RansomwareBehaviorMonitor::Result RansomwareBehaviorMonitor::observe(const SecurityEvent& e) {
    Result r;
    if (e.actorPid <= 0) return r;
    if (e.type != EventType::FileWrite && e.type != EventType::FileDelete) return r;

    QString target = e.target.toLower();
    target.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (target.isEmpty()) return r;

    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    int score = 0;
    bool hardSignal = false;

    QMutexLocker locker(&gate_);

    if (canaryPaths_.contains(target)) {
        r.reasons << u("触碰蜜罐诱饵文件(几乎可确认勒索/批量加密)");
        r.score = 100;
        r.canaryHit = true;
        r.hardSignal = true;
        return r;
    }

    ProcState& st = byPid_[e.actorPid];
    st.lastActivityUtc = now;
    st.touch(target, now, windowSecs_);

    const int distinct = st.distinctFilesInWindow();
    if (distinct >= burstThreshold_) {
        const int over = distinct - burstThreshold_;
        score += 30 + qMin(over, 20) * 2;
        r.reasons << (QString::number(windowSecs_) + u("秒内批量改写 ") + QString::number(distinct) +
                      u(" 个文件(疑似勒索加密)"));
    }

    const QString ext = getExtension(target);
    if (!ext.isEmpty()) {
        const bool knownBad = knownEncryptedExts().contains(ext);
        const int sameExt = st.sameExtensionCount(ext);
        if (knownBad && sameExt >= 3) {
            score += 40;
            hardSignal = true;
            r.reasons << (u("批量产生已知勒索扩展名 ") + ext + u("(×") + QString::number(sameExt) + u(")"));
        } else if (sameExt >= qMax(8, burstThreshold_) && !toolchainExts().contains(ext)) {
            score += 25;
            r.reasons << (u("扩展名同化:大量文件统一为 ") + ext + u("(×") + QString::number(sameExt) + u(",疑似加密)"));
        }
    }

    const QString fileName = fileNameLower(target);
    for (const QString& h : ransomNoteHints()) {
        if (fileName.contains(h)) {
            ++st.ransomNoteCount;
            score += 20;
            hardSignal = true;
            r.reasons << (u("写入疑似勒索说明文件(") + fileName + u(")"));
            if (st.ransomNoteCount >= 3) {
                score += 25;
                r.reasons << (u("在多处写入勒索信(×") + QString::number(st.ransomNoteCount) + u(",强勒索特征)"));
            }
            break;
        }
    }

    evictIfNeeded(now);
    r.score = qMin(score, 100);
    r.hardSignal = hardSignal;
    return r;
}

void RansomwareBehaviorMonitor::forget(int pid) {
    QMutexLocker locker(&gate_);
    byPid_.remove(pid);
}

int RansomwareBehaviorMonitor::trackedProcessCount() {
    QMutexLocker locker(&gate_);
    return byPid_.size();
}

void RansomwareBehaviorMonitor::evictIfNeeded(const QDateTime& now) {
    const QDateTime stale = now.addSecs(-static_cast<qint64>(windowSecs_) * 4);
    for (auto it = byPid_.begin(); it != byPid_.end(); ) {
        if (it.value().lastActivityUtc < stale) it = byPid_.erase(it);
        else ++it;
    }
    if (byPid_.size() > maxPids_) {
        QVector<QPair<QDateTime, int>> byAge;
        byAge.reserve(byPid_.size());
        for (auto it = byPid_.constBegin(); it != byPid_.constEnd(); ++it)
            byAge.append({ it.value().lastActivityUtc, it.key() });
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        const int toRemove = byPid_.size() - maxPids_;
        for (int i = 0; i < toRemove; ++i) byPid_.remove(byAge.at(i).second);
    }
}

} // namespace bulwark::engine
