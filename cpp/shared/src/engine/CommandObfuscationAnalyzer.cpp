#include "bulwark/engine/CommandObfuscationAnalyzer.h"
#include <QHash>
#include <QVector>
#include <cmath>

namespace bulwark::engine {
using detail::u;

namespace {

struct Sig { const char* token; int score; const char* reason; };

const QVector<Sig>& structuralSignals() {
    static const QVector<Sig> s = {
        { "`", 12, "命令行含反引号转义(PowerShell 混淆)" },
        { "[char]", 20, "字符码强转拼接([char],混淆)" },
        { "[convert]::", 18, "Convert 解码调用(混淆/解码执行)" },
        { "-join", 14, "字符数组拼接(-join,混淆)" },
        { "[string]::join", 16, "字符串拼接(String.Join,混淆)" },
        { ".invoke(", 16, "反射式调用(.Invoke,混淆执行)" },
        { "[scriptblock]", 20, "动态脚本块(ScriptBlock,混淆执行)" },
        { "-replace", 10, "运行时字符替换(-replace,混淆)" },
        { "-f ", 8, "格式化拼接(-f 运算符,混淆)" },
        { "[reflection.assembly]", 22, "反射加载程序集(内存执行)" },
        { "frombase64string", 18, "Base64 解码(混淆载荷)" },
        { "^", 8, "命令行含 ^ 转义(cmd 混淆)" },
        { ":~", 16, "环境变量子串截取(%var:~%,混淆)" },
        { "set /a", 8, "算术求值拼接(set /a,混淆)" },
        { "[array]::reverse", 18, "字符串反转(Array.Reverse,混淆)" },
        { "::new(", 10, "反射式构造(::new,混淆执行)" },
    };
    return s;
}

constexpr double kEntropyHigh = 4.5;
constexpr double kEntropyVeryHigh = 5.2;
constexpr double kSymbolRatioHigh = 0.28;
constexpr int kMinLength = 24;

int countOccurrences(const QString& haystack, const QString& needle) {
    if (needle.isEmpty()) return 0;
    int count = 0, idx = 0;
    while ((idx = haystack.indexOf(needle, idx)) >= 0) { ++count; idx += needle.size(); }
    return count;
}

double symbolRatio(const QString& s) {
    if (s.isEmpty()) return 0.0;
    int symbols = 0;
    for (const QChar c : s) {
        if (c.isLetterOrNumber()) continue;
        const ushort u16 = c.unicode();
        if (u16 == '\\' || u16 == '/' || u16 == ':' || u16 == '.' ||
            u16 == '-' || u16 == '_' || u16 == '"') continue;
        ++symbols;
    }
    return static_cast<double>(symbols) / s.size();
}

int longestBase64Run(const QString& s) {
    int longest = 0, cur = 0;
    for (const QChar qc : s) {
        const ushort c = qc.unicode();
        const bool isB64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (isB64) { ++cur; if (cur > longest) longest = cur; }
        else cur = 0;
    }
    return longest;
}

QString f1(double x) { return QString::number(x, 'f', 1); }
QString pct0(double r) { return QString::number(r * 100.0, 'f', 0) + QStringLiteral("%"); }

} // namespace

double CommandObfuscationAnalyzer::shannonEntropy(const QString& s) {
    if (s.isEmpty()) return 0.0;
    QHash<QChar, int> freq;
    for (const QChar c : s) freq[c] = freq.value(c, 0) + 1;
    const double len = s.size();
    double entropy = 0.0;
    for (auto it = freq.constBegin(); it != freq.constEnd(); ++it) {
        const double p = it.value() / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

ScoreResult CommandObfuscationAnalyzer::analyze(const QString& commandLine) {
    ScoreResult r;
    if (commandLine.trimmed().isEmpty() || commandLine.size() < kMinLength) return r;

    const QString lower = commandLine.toLower();
    int score = 0;

    int structuralHits = 0;
    for (const Sig& sig : structuralSignals()) {
        const int occurrences = countOccurrences(lower, QLatin1String(sig.token));
        if (occurrences > 0) {
            ++structuralHits;
            const int add = sig.score + qMin(occurrences - 1, 3) * (sig.score / 4);
            score += add;
            r.reasons << u(sig.reason);
        }
    }

    QString compact;
    compact.reserve(commandLine.size());
    for (const QChar c : commandLine) if (!c.isSpace()) compact.append(c);

    const double entropy = shannonEntropy(compact);
    if (entropy >= kEntropyVeryHigh) {
        score += 28;
        r.reasons << (u("命令行信息熵极高(") + f1(entropy) + u(",疑似编码/加密载荷)"));
    } else if (entropy >= kEntropyHigh) {
        score += 16;
        r.reasons << (u("命令行信息熵偏高(") + f1(entropy) + u(",疑似混淆)"));
    }

    const double sr = symbolRatio(compact);
    if (sr >= kSymbolRatioHigh) {
        score += 14;
        r.reasons << (u("命令行符号占比异常(") + pct0(sr) + u(",疑似拼接/转义混淆)"));
    }

    const int longestB64 = longestBase64Run(commandLine);
    if (longestB64 >= 220) {
        score += 26;
        r.reasons << (u("含超长 Base64 块(") + QString::number(longestB64) + u(" 字符,疑似编码载荷)"));
    } else if (longestB64 >= 120) {
        score += 14;
        r.reasons << (u("含较长 Base64 块(") + QString::number(longestB64) + u(" 字符)"));
    }

    if (structuralHits >= 3) {
        score += 18;
        r.reasons << (u("叠加 ") + QString::number(structuralHits) + u(" 种混淆手法(高度可疑)"));
    }

    r.score = score; // 不封顶(由 ThreatDetector 汇总后统一封顶 100)
    return r;
}

} // namespace bulwark::engine
