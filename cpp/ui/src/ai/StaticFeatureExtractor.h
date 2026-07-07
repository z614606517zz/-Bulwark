#pragma once
#include <QString>
#include <QStringList>

// Bounds-safe STATIC analysis of a file, to give the AI verdict real content to
// reason about instead of only soft signals (unsigned / path / first-seen).
// Nothing is executed. For a PE it reads header basics + per-section Shannon
// entropy (packing), and scans printable strings (ASCII + UTF-16LE) for
// dangerous Win32 API names, URLs/IPs and suspicious tokens — import names live
// as ASCII inside the binary, so a string scan surfaces them without a full
// import-table walk. For scripts it captures a source snippet + the same scan.
//
// The input file is UNTRUSTED (a possible malware sample), so every read is
// range-checked; a malformed file yields partial features + a note, never a crash.
struct StaticFeatures {
    bool readable = false;
    qint64 fileSize = 0;
    QString kind;                  // "PE 可执行" / "脚本/文本" / "其他"

    // ---- PE ----
    bool isPe = false;
    QString arch;                  // x64 / x86 / 其他
    bool isDll = false;
    bool isDotNet = false;
    QString subsystem;             // GUI / 控制台 / 其它
    int sectionCount = 0;
    double maxSectionEntropy = 0.0;
    int packedSections = 0;        // sections with entropy > 7.2 (compressed/encrypted)

    // ---- content scan ----
    QStringList dangerousApis;     // matched Win32 API names present in the binary
    QStringList capabilityTags;    // 进程注入 / 反调试 / 键盘钩子 / 加密勒索 / 网络下载 / 持久化 / 提权 / 进程发现 / 命令执行
    QStringList suspiciousStrings; // URLs / IPs / Run keys / suspicious command tokens
    QString scriptSnippet;         // capped source text for script files
    QStringList notes;             // parse caveats (truncation, unparsed, ...)

    // True when at least one concrete (non-soft) malicious-leaning indicator was
    // found. Soft signals (signature/path/first-seen) are deliberately NOT here.
    bool hasConcreteIndicator() const {
        return !dangerousApis.isEmpty() || packedSections > 0 || !suspiciousStrings.isEmpty();
    }

    // Human-readable block for the AI user prompt (the "静态内容特征" section).
    QString toPromptText() const;
};

// Extract static features from a file on disk. Safe to call on any path; if the
// file can't be read, returns readable=false.
StaticFeatures extractStaticFeatures(const QString& path);
