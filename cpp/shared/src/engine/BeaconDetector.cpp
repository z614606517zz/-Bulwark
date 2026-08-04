#include "bulwark/engine/BeaconDetector.h"
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <cmath>
#include <limits>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

constexpr double kCvRegular = 0.15;
constexpr double kCvSemiRegular = 0.28;
constexpr double kMinPeriodSec = 2.0;
constexpr double kMaxPeriodSec = 3600.0;
//
// 低抖动档可以【单独定性】的周期上限。超过它仍然计分,但只作软信号。
//
// 依据:C2 的 sleep 通常在秒级到几分钟(Cobalt Strike 默认 60s),因为操作员需要交互响应;
// 而十几分钟、半小时一次的规整外联,基本都是更新检查 / 心跳 / 订阅拉取这类计划轮询。
// 实测误报正是落在这一段:GameViewerServer(网易签名)1799.5s、360ChromeX 900s,CV 都是 0.00。
// 另外在这种节奏下,凑满判定所需样本要花一两个小时,用 3 个样本就硬性定罪本身也不严肃。
//
constexpr double kHardMaxPeriodSec = 600.0;
constexpr int kMaxKeep = 64;

const QSet<QString>& scriptHosts() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    };
    return s;
}

//
// 远端地址是否【不可能是 C2】:回环 / 私网 / 链路本地 / CGNAT / 组播 / 未指定。
//
// 为什么必须过滤:本检测器原来完全不看目标地址,只看「周期是否规整」,于是进程与本机上
// 另一个进程的定时 IPC 被判成「疑似 C2 回连」并直接置硬指标。实测三例全是对 127.0.0.1:
//   · Widgets.exe(Microsoft Windows 签名)1260s
//   · OpenCode.exe 60s
//   · dnplayer.exe(雷电模拟器)60s
// Electron 的主/渲染进程、模拟器的前后端、Windows 小组件都靠本地端口通信,而对自己 loopback
// 的「命令控制」在定义上不存在 —— 真正的 C2 必须能出网。
//
// shared 层只链 Qt6::Core(不能用 QHostAddress),故手工解析点分四段;非 IPv4 的形式只单独
// 认 IPv6 回环(::1 / 0:0:...:1),其余保持原样参与检测,不误伤真实的 IPv6 C2。
//
bool isNonRoutableRemote(const QString& host) {
    if (host.isEmpty()) return false;

    if (host.contains(QLatin1Char(':'))) {
        // IPv6:只挑回环。去掉可能的方括号后判断。
        QString h = host;
        h.remove(QLatin1Char('[')).remove(QLatin1Char(']'));
        if (h == QLatin1String("::1")) return true;
        // 0:0:0:0:0:0:0:1 这类完整写法
        const QStringList g = h.split(QLatin1Char(':'));
        if (g.size() == 8) {
            bool allZeroButLast = true;
            for (int i = 0; i < 7; ++i)
                if (g.at(i).toInt(nullptr, 16) != 0) { allZeroButLast = false; break; }
            if (allZeroButLast && g.at(7).toInt(nullptr, 16) == 1) return true;
        }
        return false;
    }

    const QStringList parts = host.split(QLatin1Char('.'));
    if (parts.size() != 4) return false;   // 域名或其它形式:照常检测
    int b[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 4; ++i) {
        bool ok = false;
        b[i] = parts.at(i).toInt(&ok);
        if (!ok || b[i] < 0 || b[i] > 255) return false;   // 不是 IPv4 字面量
    }
    if (b[0] == 127) return true;                                   // 回环
    if (b[0] == 10) return true;                                    // 私网 10/8
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;       // 私网 172.16/12
    if (b[0] == 192 && b[1] == 168) return true;                    // 私网 192.168/16
    if (b[0] == 169 && b[1] == 254) return true;                    // 链路本地
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;      // CGNAT
    if (b[0] == 0) return true;                                     // 未指定
    if (b[0] >= 224) return true;                                   // 组播 / 保留
    return false;
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

// C# "0.#":最多 1 位小数,去掉末尾 .0。
QString fmt1opt(double x) {
    QString v = QString::number(x, 'f', 1);
    if (v.endsWith(QLatin1String(".0"))) v.chop(2);
    return v;
}

} // namespace

void BeaconDetector::Series::add(const QDateTime& at) {
    times.append(at);
    lastUtc = at;
    ++count;
    if (times.size() > kMaxKeep)
        times.remove(0, times.size() - kMaxKeep);
}

QVector<double> BeaconDetector::Series::intervalsSeconds() const {
    QVector<double> result;
    for (int i = 1; i < times.size(); ++i) {
        const double sec = times.at(i - 1).msecsTo(times.at(i)) / 1000.0;
        if (sec >= 0) result.append(sec);
    }
    return result;
}

BeaconDetector::BeaconDetector(int minSamples, int maxSeries, qint64 retentionSecs) {
    minSamples_ = qMax(3, minSamples);
    maxSeries_ = qMax(64, maxSeries);

    const qint64 floor = static_cast<qint64>(kMaxPeriodSec * 1.5);
    retentionSecs_ = retentionSecs > 0 ? retentionSecs : static_cast<qint64>(kMaxPeriodSec * 2);
    if (retentionSecs_ < floor) retentionSecs_ = floor;
}

std::pair<double, double> BeaconDetector::meanAndCv(const QVector<double>& intervals) {
    if (intervals.isEmpty()) return { 0.0, std::numeric_limits<double>::max() };
    double sum = 0.0;
    for (double x : intervals) sum += x;
    const double mean = sum / intervals.size();
    if (mean <= 0) return { 0.0, std::numeric_limits<double>::max() };
    double var = 0.0;
    for (double x : intervals) var += (x - mean) * (x - mean);
    var /= intervals.size();
    return { mean, std::sqrt(var) / mean };
}

ScoreResult BeaconDetector::observe(const SecurityEvent& e) {
    ScoreResult r;
    if (e.type != EventType::NetworkConnect || e.actorPid <= 0)
        return r;

    const QString remote = normalizeRemote(e.target);
    // 不可能是 C2 的目标(回环 / 私网 / 链路本地 …)直接不进序列 —— 连时间序列都不建,
    // 免得占着 maxSeries_ 的额度把真实外联的序列挤掉(见 isNonRoutableRemote 的说明)。
    if (isNonRoutableRemote(remote))
        return r;
    const QString key = QString::number(e.actorPid) + QLatin1Char('|') + remote;
    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();

    QMutexLocker locker(&gate_);

    auto it = series_.find(key);
    if (it == series_.end()) {
        Series s;
        s.actorPath = e.actorPath;
        s.remote = remote;
        it = series_.insert(key, s);
    }
    Series& s = it.value();
    s.add(now);

    evictIfNeeded(now);

    const QVector<double> intervals = s.intervalsSeconds();
    if (intervals.size() < minSamples_ - 1)
        return r; // 样本不足

    const auto [mean, cv] = meanAndCv(intervals);
    if (mean < kMinPeriodSec || mean > kMaxPeriodSec)
        return r; // 周期不在信标区间

    //
    // ===== 档位必须显式上报,绝不能让调用方从最终分数反推 =====
    //
    // 两档的语义完全不同:低抖动档(CV <= 0.15)几乎只有程序化回连才有这种规律,可以单独定性;
    // 近周期档(CV <= 0.28)对正常软件的定时轮询必然误报 —— 代理客户端拉订阅、更新器查版本、
    // 云盘同步全是几分钟一次的准周期外联(实测 clash-win64 每 ≈160s 拉一次订阅即被判 C2 回连),
    // 故它只能算软信号、必须靠互证升格。
    //
    // 而下面还要按「未签名 +15」「脚本宿主 +20」继续加分,于是【最终分数无法区分档位】:
    // 近周期档 35 + 脚本宿主 20 = 55,与低抖动档的基线分完全相同。调用方若按 `score >= 55`
    // 判断硬指标,任何脚本宿主(powershell / cmd / rundll32 / mshta / certutil ...)的准周期
    // 轮询都会被误升格为硬指标 —— 正是本注释想排除的那一档,而且这类主体的准周期外联在真实
    // 系统上极常见(计划任务里的 PowerShell 巡检脚本)。
    //
    // 因此这里直接置 ScoreResult::hardSignal(该字段本就是为此存在,RansomwareBehaviorMonitor
    // 也是这么用的),把档位判定权留在唯一知道 CV 的地方。RuleEngine 读这个标志,不再看分数。
    //
    int score = 0;
    if (cv <= kCvRegular && mean <= kHardMaxPeriodSec) {
        score = 55;
        r.hardSignal = true;   // 低抖动 + C2 量级周期:可单独作为硬恶意指标
        r.reasons << (u("周期性外联信标:间隔≈") + fmt1opt(mean) + u("s 抖动极低(CV=") +
                      QString::number(cv, 'f', 2) + u(",疑似 C2 回连)"));
    } else if (cv <= kCvRegular) {
        //
        // 低抖动但【长周期】:计分不定罪。
        //
        // 「规整」这件事本身并不指向恶意 —— 恰恰相反,由 QTimer / 计划任务驱动的正常轮询
        // CV 就是 0.00,而真实 C2 普遍【故意加抖动】来躲周期检测。所以在这一档上
        // 「抖动极低」更像是计划轮询的特征,不是 C2 的特征;能定性的只有「周期落在 C2
        // 需要的交互量级内」那一段(见 kHardMaxPeriodSec)。
        //
        // 分值给得比准周期档还低:半小时一次的规整外联在正常系统上太普遍(更新检查、心跳、
        // 订阅拉取),给高分只会把它顶到询问线以上。需要它起作用时,靠与硬指标互证。
        //
        score = 20;
        r.reasons << (u("长周期规整外联:间隔≈") + fmt1opt(mean) + u("s(CV=") +
                      QString::number(cv, 'f', 2) + u(",多为计划轮询,需互证)"));
    } else if (cv <= kCvSemiRegular) {
        score = 35;
        // hardSignal 保持 false:近周期档仅加分,需与其它硬指标互证才升格。
        r.reasons << (u("近周期性外联:间隔≈") + fmt1opt(mean) + u("s(CV=") +
                      QString::number(cv, 'f', 2) + u(",疑似带抖动的 C2 信标)"));
    } else {
        return r; // 间隔不规律
    }

    if (!e.actorSigned) {
        score += 15;
        r.reasons << u("信标主体无可信签名");
    }
    const QString actor = fileNameLower(e.actorPath);
    if (scriptHosts().contains(actor)) {
        score += 20;
        r.reasons << (u("脚本解释器(") + actor + u(")周期性外联(强 C2 特征)"));
    }

    r.reasons << (u("目标 ") + remote + u(",已累计 ") + QString::number(s.count) + u(" 次外联"));
    r.score = qMin(score, 100);
    return r;
}

void BeaconDetector::forget(int pid) {
    QMutexLocker locker(&gate_);
    const QString prefix = QString::number(pid) + QLatin1Char('|');
    for (auto it = series_.begin(); it != series_.end(); ) {
        if (it.key().startsWith(prefix)) it = series_.erase(it);
        else ++it;
    }
}

int BeaconDetector::trackedSeriesCount() {
    QMutexLocker locker(&gate_);
    return series_.size();
}

void BeaconDetector::evictIfNeeded(const QDateTime& now) {
    const QDateTime cutoff = now.addSecs(-retentionSecs_);
    for (auto it = series_.begin(); it != series_.end(); ) {
        if (it.value().lastUtc < cutoff) it = series_.erase(it);
        else ++it;
    }

    if (series_.size() > maxSeries_) {
        QVector<QPair<QDateTime, QString>> byAge;
        byAge.reserve(series_.size());
        for (auto it = series_.constBegin(); it != series_.constEnd(); ++it)
            byAge.append({ it.value().lastUtc, it.key() });
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        const int toRemove = series_.size() - maxSeries_;
        for (int i = 0; i < toRemove; ++i) series_.remove(byAge.at(i).second);
    }
}

} // namespace bulwark::engine
