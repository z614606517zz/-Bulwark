#pragma once
#include <QString>
#include <QStringList>
#include <optional>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// 脚本类型(内部使用,不上线;顺序对应 .NET 枚举)。
enum class ScriptType {
    Unknown = 0,
    PowerShell,
    Vbscript,
    Javascript,
    Batch,
    Shell,
};

// 脚本内容静态分析器:对 PowerShell/VBS/JS/Batch 脚本体做危险命令 / 混淆 / 编码 /
// 网络特征检测。只有能拿到真正脚本体(如 -EncodedCommand 解码后)时才分类,
// 否则返回 Unknown 交由命令行/混淆分析器处理。对应 .NET Engine/ScriptAnalyzer.cs。
struct ScriptAnalyzer {
    struct Extracted {
        std::optional<QString> content;
        ScriptType type = ScriptType::Unknown;
    };

    static ScoreResult analyzeScript(const QString& scriptContent, ScriptType scriptType);
    static Extracted extractScriptFromCommandLine(const QString& commandLine);

    // ======================== 脚本【文件正文】分析 ========================
    //
    // 上面那两个只看命令行。脚本宿主的命令行里通常只有一个文件路径
    //(`cmd.exe /c "C:\...\x.bat"`),正文一个字节都不在里面 —— 于是一个 1.9MB 的混淆
    // 加载器在检测侧和 `echo hello` 长得一模一样。下面这组补的就是这个盲区。
    //
    // 分工仍然遵守「引擎层不做 I/O」:正文由 Worker::enrich 有界读入后传进来。

    // 扩展名 -> 脚本类型。无法识别返回 Unknown。
    static ScriptType scriptTypeFromPath(const QString& path);

    // 从脚本宿主的命令行里抠出【被执行的脚本文件路径】。
    // 按 token 扫描(尊重双引号),返回第一个扩展名属于已知脚本类型的 token;
    // 跳过与宿主自身同路径的 token(`powershell.exe` 本身不是脚本)。
    // 找不到返回空串。
    static QString extractScriptFilePath(const QString& commandLine);

    // 脚本正文的判据命中结果。
    //
    // 与 ScoreResult 分开是因为多了 `hits`:判据名是稳定的 ASCII 标识,
    // 供快照测试与审计逐条断言,而 reasons 是给人看的中文措辞(会改)。
    //
    // 【字段别叫 signals】那是 Qt 的宏(`#define signals public:`),
    // 写成 `QStringList signals;` 会展开成 `QStringList public:;`。
    struct FileScan {
        int score = 0;
        QStringList reasons;
        // 命中了「行为级」判据 —— 单独即可定罪。见 analyzeScriptFile 实现处的取值依据。
        bool hardSignal = false;
        QStringList hits;      // 命中判据的稳定标识(如 "self-copy-persist")
        bool empty() const { return score == 0 && hits.isEmpty(); }
    };

    // 整文件的【结构统计】。
    //
    // 为什么单独做成流式:行为级判据都落在正文前缀里(实测最远 7,770 字节),但结构统计
    // 不是 —— 实测那个 3.6MB 的 JScript 投递器,它 1,566,938 字符的超长行【起点在偏移
    // 240,662】,只读 256KB 前缀就只能看到这行的前 15KB,长行判据必然落空。
    //
    // 所以这两个量由调用方流式喂入:顺序读、O(1) 内存、不缓冲整个文件。
    // 只在「已知是超大 WSH 脚本」这条罕见路径上才值得付这次完整读取。
    class StreamStats {
    public:
        void feed(const char* data, qsizetype len);  // 可多次调用,喂入连续分块
        void finish();                               // 收尾:结算最后一行
        int longestLine() const { return longestLine_; }
        int longestBase64Run() const { return longestB64_; }
    private:
        int longestLine_ = 0, curLine_ = 0;
        int longestB64_ = 0,  curB64_ = 0;
    };

    // 分析脚本文件正文。
    //
    //   body       已读入的正文【前缀】(调用方负责有界读取;见 kScanPrefixBytes)
    //   type       按扩展名判定的脚本类型
    //   fileSize   文件【完整】大小(可能远大于 body.size(),体积判据要用它)
    //   wshHosted  宿主是否为 WSH(wscript.exe / cscript.exe)
    //   stats      整文件结构统计;传 nullptr 表示调用方没做流式统计,
    //              此时退化为只看正文前缀(小文件下二者等价)
    //
    // 【wshHosted 为什么必须由调用方给,而不是从扩展名推】体积 + 长行 + 大编码块这三个
    // 统计量在「浏览器 / Node 打包出来的 .js」上大量出现(实测本机 4003 个打包 JS 里
    // wasm-*.js 有一段 622,148 字符的 Base64、约 90 个文件单行超 64KB),单看扩展名就用
    // 它们必然误报。而 WSH 宿主【不会】去跑打包 JS —— 那是 node / 浏览器的活。所以这几条
    // 统计判据只在宿主确实是 WSH 时才有判别力,这个前提只有调用方知道。
    static FileScan analyzeScriptFile(const QString& body, ScriptType type,
                                      qint64 fileSize, bool wshHosted,
                                      const StreamStats* stats = nullptr);

    // 正文读取上限。实测 7 个真实样本的全部行为级判据都落在 7,770 字节以内,
    // 256KB 已是很宽的余量;再大只会把主线程的同步裁决路径拖慢。
    static constexpr qint64 kScanPrefixBytes = 256 * 1024;

    // 「超大 WSH 脚本」门槛。Windows 自带最大的 WSH 脚本是 winrm.vbs(204,072 字节)
    // 与 slmgr.vbs(145,712),300KB 把它们都留在门槛之下。
    // 调用方据此决定「值不值得为结构统计再完整读一遍文件」。
    static constexpr qint64 kOversizedWshBytes = 300 * 1024;

    // 该类型是否由 WSH 宿主执行(.js/.jse/.vbs/.vbe/.wsf/.hta)。
    // 体积 / 长行 / 编码块这组统计判据【只】对这些类型校准过。
    static bool isWshScriptType(ScriptType t) {
        return t == ScriptType::Javascript || t == ScriptType::Vbscript;
    }
};

} // namespace bulwark::engine
