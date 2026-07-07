#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/engine/CommandObfuscationAnalyzer.h"
#include <QStringList>

namespace bulwark::engine {
using detail::u;

namespace {

constexpr int kMinLabelLength = 8;
constexpr double kEntropyHigh = 3.6;
constexpr double kEntropyVeryHigh = 4.0;
constexpr double kVowelRatioLow = 0.26;
constexpr double kVowelRatioVeryLow = 0.18;
constexpr int kLongConsonantRun = 6;

bool isVowel(QChar c) {
    static const QString vowels = QStringLiteral("aeiouy");
    return vowels.contains(c);
}

const QStringList& benignSuffixes() {
    static const QStringList s = {
        ".cloudfront.net", ".akamai.net", ".akamaihd.net", ".azureedge.net",
        ".windows.net", ".windowsupdate.com", ".cloudflare.net", ".fastly.net",
        ".amazonaws.com", ".googleusercontent.com", ".gvt1.com", ".azure.com",
        ".edgekey.net", ".edgesuite.net", ".llnwd.net", ".cdn.cloudflare.net",
        ".1e100.net", ".gstatic.com", ".office.com", ".office365.com",
        ".sharepoint.com", ".live.com", ".microsoft.com", ".apple.com",
        ".icloud.com", ".github.io", ".githubusercontent.com",
    };
    return s;
}

// 从 "host" / "host:port" / "scheme://host/path" 中提取主机名。
QString extractHost(const QString& target) {
    QString t = target.trimmed();
    const int scheme = t.indexOf(QLatin1String("://"));
    if (scheme >= 0) t = t.mid(scheme + 3);
    const int slash = t.indexOf(QLatin1Char('/'));
    if (slash >= 0) t = t.left(slash);
    const int colon = t.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && colon < t.size() - 1) {
        bool allDigits = true;
        for (int i = colon + 1; i < t.size(); ++i)
            if (!t.at(i).isDigit()) { allDigits = false; break; }
        if (allDigits) t = t.left(colon);
    }
    return t;
}

// IPv4 点分四段 / 含冒号视为 IPv6(shared 仅链 Qt6::Core,不用 QHostAddress)。
bool isIpAddress(const QString& host) {
    if (host.contains(QLatin1Char(':'))) return true;
    const QStringList parts = host.split(QLatin1Char('.'));
    if (parts.size() != 4) return false;
    for (const QString& p : parts) {
        bool ok = false;
        const int n = p.toInt(&ok);
        if (!ok || n < 0 || n > 255) return false;
    }
    return true;
}

// 取「主标签」:去顶级后缀,取剩余最后一段(example.co.uk -> example)。
QString registrableLabel(const QString& host) {
    const QStringList parts = host.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (parts.size() <= 1) return host;
    int idx = parts.size() - 2;
    if (parts.size() >= 3 && parts.last().size() == 2 && parts.at(parts.size() - 2).size() <= 3)
        idx = parts.size() - 3; // 双段国家后缀(co.uk / com.cn)
    return idx >= 0 ? parts.at(idx) : parts.last();
}

double vowelRatio(const QString& s) {
    if (s.isEmpty()) return 0.0;
    int letters = 0, vowels = 0;
    for (const QChar c : s) {
        if (!c.isLetter()) continue;
        ++letters;
        if (isVowel(c)) ++vowels;
    }
    return letters == 0 ? 0.0 : static_cast<double>(vowels) / letters;
}

int longestConsonantRun(const QString& s) {
    int longest = 0, cur = 0;
    for (const QChar c : s) {
        const bool isConsonant = c.isLetter() && !isVowel(c);
        if (isConsonant) { ++cur; if (cur > longest) longest = cur; }
        else cur = 0;
    }
    return longest;
}

int digitLetterAlternations(const QString& s) {
    int count = 0;
    for (int i = 1; i < s.size(); ++i)
        if (s.at(i - 1).isDigit() != s.at(i).isDigit()) ++count;
    return count;
}

QString f1(double x) { return QString::number(x, 'f', 1); }
QString pct0(double ratio) { return QString::number(ratio * 100.0, 'f', 0) + QStringLiteral("%"); }

} // namespace

ScoreResult DgaDomainAnalyzer::analyze(const QString& target) {
    ScoreResult r;
    if (target.trimmed().isEmpty()) return r;

    const QString host = extractHost(target);
    if (host.isEmpty() || isIpAddress(host)) return r;

    const QString lower = host.toLower();
    for (const QString& suf : benignSuffixes())
        if (lower.endsWith(suf)) return r;

    const QString label = registrableLabel(lower);
    if (label.size() < kMinLabelLength) return r;

    QString core;
    core.reserve(label.size());
    for (const QChar c : label)
        if (c.isLetterOrNumber()) core.append(c);
    if (core.size() < kMinLabelLength) return r;

    int score = 0;

    const double entropy = CommandObfuscationAnalyzer::shannonEntropy(core);
    if (entropy >= kEntropyVeryHigh) {
        score += 30;
        r.reasons << (u("域名标签熵极高(") + f1(entropy) + u(",疑似 DGA 随机域名)"));
    } else if (entropy >= kEntropyHigh) {
        score += 18;
        r.reasons << (u("域名标签熵偏高(") + f1(entropy) + u(",疑似算法生成)"));
    }

    const double vr = vowelRatio(core);
    if (vr <= kVowelRatioVeryLow) {
        score += 24;
        r.reasons << (u("域名元音比例极低(") + pct0(vr) + u(",非可读单词)"));
    } else if (vr <= kVowelRatioLow) {
        score += 12;
        r.reasons << (u("域名元音比例偏低(") + pct0(vr) + u(")"));
    }

    const int maxCons = longestConsonantRun(core);
    if (maxCons >= kLongConsonantRun) {
        score += 16;
        r.reasons << (u("含 ") + QString::number(maxCons) + u(" 个连续辅音(非自然拼写)"));
    }

    int digits = 0;
    for (const QChar c : core) if (c.isDigit()) ++digits;
    const double digitRatio = static_cast<double>(digits) / core.size();
    const int alternations = digitLetterAlternations(core);
    if (digitRatio > 0.2 && alternations >= 3) {
        score += 12;
        r.reasons << (u("数字字母高频交错(") + QString::number(alternations) + u(" 次,疑似算法生成)"));
    }

    if (core.size() >= 14 && entropy >= kEntropyHigh) {
        score += 8;
        r.reasons << (u("超长高熵标签(") + QString::number(core.size()) + u(" 字符)"));
    }

    r.score = qMin(score, 100);
    return r;
}

} // namespace bulwark::engine
