#include "bulwark/engine/BaselineAnalyzer.h"
#include <QRegularExpression>
#include <QStringList>
#include <QVector>
#include <algorithm>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

//
// 把路径里【每次都不一样】的目录名折叠成固定占位符。
//
// 为什么必需:基线按完整路径字符串做 key,而大量正常程序每次操作都新建一个随机名目录,
// 于是「首次写入该目录」永远成立 —— 基线【永远收敛不了】,每一次正常运行都产出一条
// 「偏离历史基线」。实测 360 浏览器自己的更新器 360ceupdate.exe 就是这样,它每次更新都写
//     ...\Chrome\User Data\v3update\download\{17dbc974-e3ab-475b-9f84-e8a831c494a2}
// GUID 每次不同,累计刷出 13 条偏离证据,把风险分一路顶到 70 并被拦。
//
// 折叠之后这 13 条塌成同一条 ...\v3update\download\{guid},第二次更新起就是「已知目录」。
// 这不但消除误报,还让判据更有意义:真正值得关注的是「写进了哪一类位置」,而不是那串随机名。
//
// 覆盖实测见过的几种易变命名(都换成语义占位符,彼此不混淆):
//   {8-4-4-4-12} / 裸 GUID        -> {guid}
//   _MEI<数字>(PyInstaller 解包)  -> {pyinstaller}
//   is-XXXXX.tmp(Inno Setup)      -> {innosetup}
//   ns<随机>.tmp(NSIS)            -> {nsis}
//   纯十六进制且长度 >= 8           -> {hex}
//   纯数字且长度 >= 4(按 PID 命名)  -> {num}
//
QString collapseVolatileSegments(const QString& lowerPath) {
    static const QRegularExpression reGuidBraced(
        QStringLiteral("^\\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\}?$"));
    static const QRegularExpression reMei(QStringLiteral("^_mei\\d+$"));
    static const QRegularExpression reInno(QStringLiteral("^is-[0-9a-z]{5,}\\.tmp$"));
    static const QRegularExpression reNsis(QStringLiteral("^ns[0-9a-z]{3,}\\.tmp$"));
    static const QRegularExpression reHex(QStringLiteral("^[0-9a-f]{8,}$"));
    static const QRegularExpression reNum(QStringLiteral("^\\d{4,}$"));

    QStringList segs = lowerPath.split(QLatin1Char('\\'));
    for (QString& s : segs) {
        if (s.isEmpty()) continue;
        if (reGuidBraced.match(s).hasMatch())   { s = QStringLiteral("{guid}");        continue; }
        if (reMei.match(s).hasMatch())          { s = QStringLiteral("{pyinstaller}"); continue; }
        if (reInno.match(s).hasMatch())         { s = QStringLiteral("{innosetup}");   continue; }
        if (reNsis.match(s).hasMatch())         { s = QStringLiteral("{nsis}");        continue; }
        if (reHex.match(s).hasMatch())          { s = QStringLiteral("{hex}");         continue; }
        if (reNum.match(s).hasMatch())          { s = QStringLiteral("{num}");         continue; }
    }
    return segs.join(QLatin1Char('\\'));
}

QString normalizeProgram(const QString& path) {
    if (path.trimmed().isEmpty()) return QString();
    QString p = path.trimmed().toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    // 主体路径也要折叠:PyInstaller 打包的程序每次运行都在 _MEI<pid> 下解包,不折叠的话
    // 每启动一次就新建一份 profile,基线同样永远建立不起来(而且白占 maxProfiles_ 额度)。
    return collapseVolatileSegments(p);
}
QString dirOf(const QString& target) {
    if (target.trimmed().isEmpty()) return QString();
    QString t = target.trimmed();
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const int slash = t.lastIndexOf(QLatin1Char('\\'));
    if (slash < 0) return QString();
    return collapseVolatileSegments(t.left(slash).toLower());
}
QString normalizeRemote(const QString& target) {
    if (target.isEmpty()) return QStringLiteral("?");
    QString t = target.trimmed().toLower();
    const int colon = t.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && colon < t.size() - 1) {
        bool allDigits = true;
        for (int i = colon + 1; i < t.size(); ++i)
            if (!t.at(i).isDigit()) { allDigits = false; break; }
        if (allDigits) t = t.left(colon);
    }
    return t;
}
QString shortName(const QString& programKey) { return fileNameLower(programKey); }
} // namespace

QSet<QString>& BaselineAnalyzer::Profile::setFor(Dim d) {
    switch (d) {
        case Dim::Child: return children;
        case Dim::Host:  return hosts;
        default:         return writeDirs;
    }
}
int BaselineAnalyzer::Profile::obsFor(Dim d) const {
    switch (d) {
        case Dim::Child: return childObs;
        case Dim::Host:  return hostObs;
        default:         return writeObs;
    }
}
void BaselineAnalyzer::Profile::incObs(Dim d) {
    switch (d) {
        case Dim::Child: ++childObs; break;
        case Dim::Host:  ++hostObs; break;
        default:         ++writeObs; break;
    }
}

BaselineAnalyzer::BaselineAnalyzer(int minObservationsToEstablish, int promiscuousThreshold,
                                   int maxProfiles, int maxSetSize) {
    minObs_ = qMax(4, minObservationsToEstablish);
    promiscuous_ = qMax(16, promiscuousThreshold);
    maxProfiles_ = qMax(128, maxProfiles);
    maxSetSize_ = qMax(32, maxSetSize);
}

BaselineAnalyzer::Result BaselineAnalyzer::observe(const SecurityEvent& e) {
    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();

    switch (e.type) {
        case EventType::ProcessCreate: {
            const QString parent = normalizeProgram(e.parentPath);
            const QString child = fileNameLower(e.actorPath);
            if (parent.isEmpty() || child.isEmpty()) return Result{};
            return score(parent, Dim::Child, child, now, 20,
                         u("程序 ") + shortName(parent) + u(" 首次派生子进程 ") + child +
                         u("(偏离历史行为基线)"));
        }
        case EventType::NetworkConnect: {
            const QString actor = normalizeProgram(e.actorPath);
            const QString host = normalizeRemote(e.target);
            if (actor.isEmpty() || host.isEmpty() || host == QLatin1String("?")) return Result{};
            return score(actor, Dim::Host, host, now, 15,
                         u("程序 ") + shortName(actor) + u(" 首次外联到 ") + host +
                         u("(偏离历史外联基线)"));
        }
        case EventType::FileWrite:
        case EventType::FileDelete: {
            const QString actor = normalizeProgram(e.actorPath);
            const QString dir = dirOf(e.target);
            if (actor.isEmpty() || dir.isEmpty()) return Result{};
            return score(actor, Dim::WriteDir, dir, now, 12,
                         u("程序 ") + shortName(actor) + u(" 首次写入目录 ") + dir +
                         u("(偏离历史写入基线)"));
        }
        default:
            return Result{};
    }
}

BaselineAnalyzer::Result BaselineAnalyzer::score(const QString& programKey, Dim dim, const QString& value,
                                                 const QDateTime& now, int deviationScore,
                                                 const QString& deviationText) {
    QMutexLocker locker(&gate_);

    auto it = profiles_.find(programKey);
    if (it == profiles_.end()) {
        Profile p;
        p.firstSeenUtc = now;
        it = profiles_.insert(programKey, p);
    }
    Profile& p = it.value();
    p.lastSeenUtc = now;

    QSet<QString>& set = p.setFor(dim);
    const int obs = p.obsFor(dim);
    const bool established = obs >= minObs_;
    const bool promiscuous = set.size() >= promiscuous_;
    const bool known = set.contains(value);

    p.incObs(dim);
    if (!known && set.size() < maxSetSize_) set.insert(value);

    evictIfNeeded(now);

    if (!established || promiscuous || known) return Result{};

    Result r;
    r.reasons << deviationText;
    r.score = qMin(deviationScore, 100);
    r.deviation = true;
    return r;
}

int BaselineAnalyzer::trackedProgramCount() {
    QMutexLocker locker(&gate_);
    return profiles_.size();
}

void BaselineAnalyzer::evictIfNeeded(const QDateTime& now) {
    Q_UNUSED(now);
    if (profiles_.size() <= maxProfiles_) return;
    QVector<QPair<QDateTime, QString>> byAge;
    byAge.reserve(profiles_.size());
    for (auto it = profiles_.constBegin(); it != profiles_.constEnd(); ++it)
        byAge.append({ it.value().lastSeenUtc, it.key() });
    std::sort(byAge.begin(), byAge.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    const int toRemove = profiles_.size() - maxProfiles_;
    for (int i = 0; i < toRemove; ++i) profiles_.remove(byAge.at(i).second);
}

BaselineSnapshot BaselineAnalyzer::exportSnapshot() {
    QMutexLocker locker(&gate_);
    BaselineSnapshot snap;
    snap.programs.reserve(profiles_.size());
    for (auto it = profiles_.constBegin(); it != profiles_.constEnd(); ++it) {
        const Profile& p = it.value();
        BaselineProgram bp;
        bp.key = it.key();
        bp.firstSeenUtc = p.firstSeenUtc;
        bp.lastSeenUtc = p.lastSeenUtc;
        bp.childObs = p.childObs;
        bp.hostObs = p.hostObs;
        bp.writeObs = p.writeObs;
        bp.children = QStringList(p.children.values());
        bp.hosts = QStringList(p.hosts.values());
        bp.writeDirs = QStringList(p.writeDirs.values());
        snap.programs.append(bp);
    }
    return snap;
}

void BaselineAnalyzer::importSnapshot(const BaselineSnapshot& snapshot) {
    QMutexLocker locker(&gate_);
    profiles_.clear();
    // 局部变量改名以避让 bulwark::nowUtc():原名恰好与函数同名,会构成自引用初始化。
    const QDateTime importedAt = bulwark::nowUtc();
    for (const BaselineProgram& prog : snapshot.programs) {
        if (prog.key.isEmpty()) continue;
        Profile p;
        p.firstSeenUtc = prog.firstSeenUtc.isValid() ? prog.firstSeenUtc : importedAt;
        p.lastSeenUtc = prog.lastSeenUtc.isValid() ? prog.lastSeenUtc : importedAt;
        p.childObs = qMax(0, prog.childObs);
        p.hostObs = qMax(0, prog.hostObs);
        p.writeObs = qMax(0, prog.writeObs);
        for (const QString& c : prog.children) p.children.insert(c);
        for (const QString& h : prog.hosts) p.hosts.insert(h);
        for (const QString& d : prog.writeDirs) p.writeDirs.insert(d);
        profiles_.insert(prog.key, p);
    }
}

} // namespace bulwark::engine
