#include "ai/StaticFeatureExtractor.h"

#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>

#include <array>
#include <cmath>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr qint64 kMaxRead        = 12 * 1024 * 1024; // cap: read at most 12 MB for parsing
constexpr int    kMinStrLen      = 5;                // shortest printable run we keep
constexpr int    kMaxRunsScanned = 60000;            // guard: stop collecting runs past this
constexpr int    kScriptCapBytes = 16 * 1024;        // script source snippet cap
constexpr double kPackedEntropy  = 7.2;              // section entropy above this ~ packed/encrypted
constexpr int    kMaxApis        = 30;
constexpr int    kMaxSusStrings  = 30;

// ---- bounds-safe little-endian readers (untrusted input) -------------------
quint16 rd16(const QByteArray& b, qint64 off)
{
    if (off < 0 || off + 2 > b.size()) return 0;
    const auto* p = reinterpret_cast<const quint8*>(b.constData() + off);
    return quint16(p[0] | (p[1] << 8));
}
quint32 rd32(const QByteArray& b, qint64 off)
{
    if (off < 0 || off + 4 > b.size()) return 0;
    const auto* p = reinterpret_cast<const quint8*>(b.constData() + off);
    return quint32(p[0] | (p[1] << 8) | (p[2] << 16) | (quint32(p[3]) << 24));
}

// Shannon entropy (bits/byte, 0..8) over a byte range.
double shannonEntropy(const char* data, qint64 len)
{
    if (len <= 0) return 0.0;
    std::array<qint64, 256> freq{};
    const auto* p = reinterpret_cast<const quint8*>(data);
    for (qint64 i = 0; i < len; ++i) ++freq[p[i]];
    double e = 0.0;
    for (qint64 f : freq) {
        if (!f) continue;
        const double pr = double(f) / double(len);
        e -= pr * std::log2(pr);
    }
    return e;
}

// Dangerous Win32 API base names (match A/W variants via substring) grouped by
// capability. Import names are stored as ASCII in the PE, so a raw substring
// search over the file bytes surfaces them without walking the import table.
struct ApiEntry { const char* name; const char* tag; };
const ApiEntry kApiWatch[] = {
    {"VirtualAllocEx", "进程注入"}, {"WriteProcessMemory", "进程注入"},
    {"CreateRemoteThread", "进程注入"}, {"NtCreateThreadEx", "进程注入"},
    {"RtlCreateUserThread", "进程注入"}, {"QueueUserAPC", "进程注入"},
    {"NtQueueApcThread", "进程注入"}, {"SetThreadContext", "进程注入"},
    {"NtMapViewOfSection", "进程注入"}, {"NtUnmapViewOfSection", "进程注入"},
    {"NtWriteVirtualMemory", "进程注入"}, {"VirtualProtectEx", "进程注入"},
    {"IsDebuggerPresent", "反调试反分析"}, {"CheckRemoteDebuggerPresent", "反调试反分析"},
    {"NtQueryInformationProcess", "反调试反分析"}, {"OutputDebugString", "反调试反分析"},
    {"SetWindowsHookEx", "键盘钩子"}, {"GetAsyncKeyState", "键盘钩子"},
    {"GetKeyboardState", "键盘钩子"}, {"RegisterRawInputDevices", "键盘钩子"},
    {"CryptEncrypt", "加密勒索"}, {"CryptGenKey", "加密勒索"},
    {"CryptDeriveKey", "加密勒索"}, {"CryptImportKey", "加密勒索"}, {"BCryptEncrypt", "加密勒索"},
    {"URLDownloadToFile", "网络下载"}, {"InternetOpenUrl", "网络下载"},
    {"InternetConnect", "网络下载"}, {"HttpSendRequest", "网络下载"},
    {"WinHttpConnect", "网络下载"}, {"InternetReadFile", "网络下载"},
    {"WSAStartup", "网络下载"}, {"WSASocket", "网络下载"},
    {"AdjustTokenPrivileges", "提权令牌"}, {"OpenProcessToken", "提权令牌"},
    {"LookupPrivilegeValue", "提权令牌"},
    {"CreateToolhelp32Snapshot", "进程发现"}, {"Process32First", "进程发现"},
    {"Process32Next", "进程发现"}, {"EnumProcesses", "进程发现"},
    {"RegSetValueEx", "持久化"}, {"CreateServiceA", "持久化"}, {"CreateServiceW", "持久化"},
    {"WinExec", "命令执行"}, {"ShellExecuteEx", "命令执行"},
};

// Suspicious command / IOC tokens (case-insensitive substring in printable text).
const char* kTokenWatch[] = {
    "powershell", "-enc", "-encodedcommand", "-nop", "-windowstyle hidden", "-w hidden",
    "invoke-expression", "iex(", "iex ", "downloadstring", "downloadfile", "webclient",
    "frombase64string", "rundll32", "regsvr32", "mshta", "certutil", "-decode", "-urlcache",
    "schtasks", "bitsadmin", "vssadmin", "delete shadows", "bcdedit", "wbadmin",
    "mimikatz", "sekurlsa", "lsass", "net user", "net localgroup", "reg add",
    "\\currentversion\\run", "attrib +h", "taskkill /f", "cmd /c", "cmd.exe /c",
    ".onion", "bitcoin", "monero", "ransom", "your files have been", "decrypt",
};

} // namespace

namespace {

// Collect printable runs (ASCII + UTF-16LE), each >= kMinStrLen chars. Capped so
// a huge file can't blow up memory. Used for URL/IP/token scanning.
QStringList collectPrintableStrings(const QByteArray& buf)
{
    QStringList out;
    const auto* p = reinterpret_cast<const quint8*>(buf.constData());
    const qint64 n = buf.size();
    auto printable = [](quint8 c) { return c >= 0x20 && c <= 0x7E; };

    // ASCII runs.
    QByteArray cur;
    for (qint64 i = 0; i < n && out.size() < kMaxRunsScanned; ++i) {
        if (printable(p[i])) {
            cur.append(char(p[i]));
        } else {
            if (cur.size() >= kMinStrLen) out.append(QString::fromLatin1(cur));
            cur.clear();
        }
    }
    if (cur.size() >= kMinStrLen && out.size() < kMaxRunsScanned)
        out.append(QString::fromLatin1(cur));

    // UTF-16LE runs: printable byte followed by 0x00, repeated.
    QString wcur;
    for (qint64 i = 0; i + 1 < n && out.size() < kMaxRunsScanned; i += 2) {
        if (printable(p[i]) && p[i + 1] == 0x00) {
            wcur.append(QChar(p[i]));
        } else {
            if (wcur.size() >= kMinStrLen) out.append(wcur);
            wcur.clear();
        }
    }
    if (wcur.size() >= kMinStrLen && out.size() < kMaxRunsScanned)
        out.append(wcur);

    return out;
}

// Scan collected strings for URLs / IPv4 / suspicious tokens -> f.suspiciousStrings.
void scanSuspicious(const QStringList& strings, StaticFeatures& f)
{
    static const QRegularExpression reUrl(
        QStringLiteral("(?:https?|ftp)://[^\\s\"'<>()]{4,}"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression reIp(
        QStringLiteral("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"));

    QSet<QString> seen;
    auto add = [&](const QString& s) {
        const QString t = s.trimmed();
        if (t.isEmpty() || seen.contains(t) || f.suspiciousStrings.size() >= kMaxSusStrings) return;
        seen.insert(t);
        f.suspiciousStrings.append(t.left(160)); // clip very long lines
    };

    for (const QString& s : strings) {
        if (f.suspiciousStrings.size() >= kMaxSusStrings) break;

        // URLs (skip the ubiquitous benign schema/namespace URLs).
        auto mu = reUrl.match(s);
        if (mu.hasMatch()) {
            const QString url = mu.captured(0);
            const QString low = url.toLower();
            if (!low.contains(QStringLiteral("w3.org")) && !low.contains(QStringLiteral("schemas.microsoft"))
                && !low.contains(QStringLiteral("verisign")) && !low.contains(QStringLiteral("digicert"))
                && !low.contains(QStringLiteral("sectigo")) && !low.contains(QStringLiteral("microsoft.com/pkiops")))
                add(u("URL: ") + url);
        }

        // IPv4 (skip 0.0.0.0 / 127.* loopback / 255.* broadcast noise).
        auto mi = reIp.match(s);
        if (mi.hasMatch()) {
            const QString ip = mi.captured(0);
            if (!ip.startsWith(QStringLiteral("127.")) && ip != QStringLiteral("0.0.0.0")
                && !ip.startsWith(QStringLiteral("255.")))
                add(u("IP: ") + ip);
        }

        // Suspicious tokens.
        const QString low = s.toLower();
        for (const char* tok : kTokenWatch) {
            if (low.contains(QLatin1String(tok))) { add(s); break; }
        }
    }
}

} // namespace

namespace {

// Parse PE header basics + per-section entropy. All reads are range-checked, so
// a malformed/hostile file yields partial info + a note rather than a crash.
void parsePe(const QByteArray& buf, StaticFeatures& f)
{
    if (buf.size() < 0x40 || quint8(buf[0]) != 'M' || quint8(buf[1]) != 'Z')
        return; // not a PE

    const qint64 peOff = rd32(buf, 0x3C);
    if (rd32(buf, peOff) != 0x00004550) { // "PE\0\0"
        f.notes.append(u("PE 签名缺失或损坏"));
        return;
    }
    f.isPe = true;
    f.kind = u("PE 可执行");

    const qint64 coff = peOff + 4;
    const quint16 machine       = rd16(buf, coff + 0);
    quint16       numSections   = rd16(buf, coff + 2);
    const quint16 sizeOfOptHdr  = rd16(buf, coff + 16);
    const quint16 characteristics = rd16(buf, coff + 18);

    const qint64  opt  = coff + 20;
    const quint16 magic = rd16(buf, opt); // 0x10b PE32 / 0x20b PE32+
    const bool    is64  = (machine == 0x8664) || (magic == 0x20b);

    f.arch  = is64 ? u("x64") : (machine == 0x14c ? u("x86") : u("其他"));
    f.isDll = (characteristics & 0x2000) != 0;

    switch (rd16(buf, opt + 68)) { // Subsystem
    case 2:  f.subsystem = u("GUI"); break;
    case 3:  f.subsystem = u("控制台"); break;
    default: f.subsystem = u("其它"); break;
    }

    // .NET: DataDirectory[14] (CLR runtime header) present.
    const qint64 dirBase = opt + (magic == 0x20b ? 112 : 96);
    f.isDotNet = rd32(buf, dirBase + 14 * 8) != 0;

    // Per-section entropy (cap section count against malformed headers).
    const qint64 secStart = opt + sizeOfOptHdr;
    if (numSections > 96) { numSections = 96; f.notes.append(u("节区数异常,已截断")); }
    f.sectionCount = numSections;
    for (quint16 i = 0; i < numSections; ++i) {
        const qint64 sec = secStart + qint64(i) * 40;
        const quint32 rawPtr  = rd32(buf, sec + 20);
        quint32       rawSize = rd32(buf, sec + 16);
        if (rawSize == 0 || rawPtr == 0) continue;
        if (qint64(rawPtr) >= buf.size()) continue;
        if (qint64(rawPtr) + rawSize > buf.size())      // clip to what we actually read
            rawSize = quint32(buf.size() - rawPtr);
        const double e = shannonEntropy(buf.constData() + rawPtr, rawSize);
        if (e > f.maxSectionEntropy) f.maxSectionEntropy = e;
        if (e > kPackedEntropy) ++f.packedSections;
    }
}

} // namespace

namespace {

bool isScriptExt(const QString& suffix)
{
    static const QSet<QString> kScript = {
        "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "hta", "py", "sh", "php", "pl", "lnk"
    };
    return kScript.contains(suffix.toLower());
}

QString decodeSnippet(const QByteArray& head)
{
    if (head.size() >= 2 && quint8(head[0]) == 0xFF && quint8(head[1]) == 0xFE)
        return QString::fromUtf16(reinterpret_cast<const char16_t*>(head.constData() + 2),
                                  (head.size() - 2) / 2);
    return QString::fromUtf8(head);
}

} // namespace

StaticFeatures extractStaticFeatures(const QString& path)
{
    StaticFeatures f;
    const QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
        return f;
    f.fileSize = fi.size();

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        f.notes.append(u("无法读取文件(可能被占用或权限不足)"));
        return f;
    }
    const QByteArray buf = file.read(kMaxRead);
    file.close();
    f.readable = true;
    if (f.fileSize > kMaxRead)
        f.notes.append(u("文件较大,仅分析前 %1 MB").arg(kMaxRead / (1024 * 1024)));

    const bool looksPe = buf.size() >= 2 && quint8(buf[0]) == 'M' && quint8(buf[1]) == 'Z';
    if (isScriptExt(fi.suffix()) && !looksPe) {
        f.kind = u("脚本/文本");
        f.scriptSnippet = decodeSnippet(buf.left(kScriptCapBytes));
    } else if (looksPe) {
        parsePe(buf, f); // sets kind = "PE 可执行" on success
    }
    if (f.kind.isEmpty())
        f.kind = u("其他");

    // Dangerous API presence (exact ASCII bytes anywhere in the image).
    for (const ApiEntry& a : kApiWatch) {
        if (f.dangerousApis.size() >= kMaxApis) break;
        if (buf.contains(a.name)) {
            const QString name = QString::fromLatin1(a.name);
            if (!f.dangerousApis.contains(name)) f.dangerousApis.append(name);
            const QString tag = u(a.tag);
            if (!f.capabilityTags.contains(tag)) f.capabilityTags.append(tag);
        }
    }

    // URLs / IPs / suspicious tokens from printable strings.
    scanSuspicious(collectPrintableStrings(buf), f);

    return f;
}

QString StaticFeatures::toPromptText() const
{
    if (!readable)
        return u("(无法读取文件内容进行静态分析)");

    QStringList lines;

    if (isPe) {
        QString head = u("文件类型: PE 可执行 (") + arch;
        if (!subsystem.isEmpty()) head += u(", ") + subsystem + u("子系统");
        if (isDll) head += u(", DLL");
        head += u(")  ·  .NET: ") + (isDotNet ? u("是") : u("否"));
        lines << head;
        if (sectionCount > 0) {
            QString sec = u("节区: %1, 最高节区熵 %2")
                              .arg(sectionCount)
                              .arg(QString::number(maxSectionEntropy, 'f', 2));
            if (packedSections > 0)
                sec += u("  (%1 个节区高熵,疑似加壳/加密)").arg(packedSections);
            lines << sec;
        }
    } else {
        lines << u("文件类型: ") + kind;
    }

    if (!dangerousApis.isEmpty())
        lines << u("命中危险 API: ") + dangerousApis.join(QStringLiteral(", "));
    if (!capabilityTags.isEmpty())
        lines << u("能力标签: ") + capabilityTags.join(QStringLiteral(" / "));

    if (!suspiciousStrings.isEmpty()) {
        lines << u("可疑字符串 / IOC:");
        for (const QString& s : suspiciousStrings)
            lines << u("  - ") + s;
    }

    if (kind == u("脚本/文本") && !scriptSnippet.isEmpty()) {
        lines << u("脚本源码(节选):");
        lines << scriptSnippet.left(4000); // keep the prompt bounded
    }

    if (!notes.isEmpty())
        lines << u("解析备注: ") + notes.join(QStringLiteral("; "));

    // The extractor's own read on concrete evidence — a hint, the model decides.
    lines << (hasConcreteIndicator()
                  ? u("本地静态特征: 发现具体可疑/恶意指标(见上)。")
                  : u("本地静态特征: 未发现任何具体恶意指标(仅存在软信号,如未签名/路径/首见)。"));

    return lines.join(QLatin1Char('\n'));
}
