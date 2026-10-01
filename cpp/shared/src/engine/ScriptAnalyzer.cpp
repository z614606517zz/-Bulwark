#include "bulwark/engine/ScriptAnalyzer.h"
#include <QVector>
#include <QByteArray>
#include <QRegularExpression>
#include <QStringView>
#include <iterator>   // std::size(数组长度,用于判据关键字表)
#include <limits>

namespace bulwark::engine {
using detail::u;

namespace {

struct Sig { const char* pattern; int score; const char* reason; };

const QVector<Sig>& psDangerous() {
    static const QVector<Sig> s = {
        { "invoke-expression", 35, "PowerShell 动态执行(Invoke-Expression)" },
        { "iex ", 35, "PowerShell 动态执行(IEX 别名)" },
        { "iex(", 35, "PowerShell 动态执行(IEX 别名)" },
        { "invoke-command", 25, "PowerShell 远程命令执行(Invoke-Command)" },
        { "invoke-item", 15, "PowerShell 执行文件(Invoke-Item)" },
        { "start-process", 20, "PowerShell 启动进程(Start-Process)" },
        { "downloadstring", 40, "PowerShell 内存下载执行(DownloadString)" },
        { "downloadfile", 35, "PowerShell 远程下载文件" },
        { "invoke-webrequest", 30, "PowerShell HTTP 请求(Invoke-WebRequest)" },
        { "iwr ", 25, "PowerShell HTTP 请求(IWR 别名)" },
        { "net.webclient", 35, "PowerShell 网络下载(Net.WebClient)" },
        { "system.net.webclient", 35, "PowerShell 网络下载(System.Net.WebClient)" },
        { "bitsadmin", 30, "BITS 后台下载" },
        { "start-bitstransfer", 30, "BITS 后台传输" },
        { "frombase64string", 30, "Base64 解码" },
        { "tobase64string", 20, "Base64 编码" },
        { "-encodedcommand", 35, "PowerShell 编码命令" },
        { "-enc ", 35, "PowerShell 编码命令(缩写)" },
        { "[convert]::", 25, "类型转换(常用于解码)" },
        { "[system.convert]", 25, "系统转换类" },
        { "[reflection.assembly]", 30, "反射加载程序集(内存执行)" },
        { "reflection.assembly]::load", 30, "反射加载程序集" },
        { "[system.reflection]", 25, "反射操作" },
        { "assembly]::load(", 30, "动态加载程序集" },
        { "add-type", 25, "动态添加类型(可能加载恶意代码)" },
        { "-executionpolicy bypass", 35, "绕过执行策略" },
        { "-ep bypass", 35, "绕过执行策略(缩写)" },
        { "-windowstyle hidden", 30, "隐藏窗口运行" },
        { "-w hidden", 30, "隐藏窗口运行(缩写)" },
        { "-noprofile", 20, "跳过配置文件" },
        { "-noninteractive", 15, "非交互模式" },
        { "process]::start(", 25, "启动进程" },
        { "diagnostics.process", 25, "进程诊断操作" },
        { "get-process", 10, "获取进程信息" },
        { "stop-process", 20, "停止进程" },
        { "remove-item", 15, "删除文件/目录" },
        { "del ", 15, "删除命令" },
        { "rmdir", 15, "删除目录" },
        { "set-itemproperty", 20, "设置注册表/环境变量" },
        { "new-itemproperty", 20, "新建注册表属性" },
        { "remove-itemproperty", 20, "删除注册表属性" },
        { "hklm:\\", 25, "操作本地机器注册表" },
        { "hkcu:\\", 20, "操作当前用户注册表" },
        { "get-credential", 25, "获取凭据" },
        { "convertto-securestring", 25, "转换为安全字符串" },
        { "convertfrom-securestring", 25, "从安全字符串转换" },
        { "system.security.cryptography", 25, "加密操作" },
        { "new-scheduledtask", 30, "创建计划任务" },
        { "register-scheduledtask", 30, "注册计划任务" },
        { "new-service", 25, "创建服务" },
        { "-join", 15, "字符串拼接(-join)" },
        { "-replace", 10, "字符串替换(-replace)" },
        { "-split", 10, "字符串分割(-split)" },
        { "-f ", 10, "格式化字符串(-f)" },
        { "[char]", 20, "字符码转换([char])" },
        { "[string]", 15, "字符串类型转换" },
        { "[array]", 10, "数组操作" },
    };
    return s;
}

const QVector<Sig>& psObfuscation() {
    static const QVector<Sig> s = {
        { "'+'", 15, "字符串拼接('+')" },
        { "\"+\"", 15, "字符串拼接(\"+\")" },
        { "' & '", 15, "字符串连接(' & ')" },
        { "[char]0x", 25, "十六进制字符码([char]0x)" },
        { "[char]([int]", 25, "整数字符转换" },
        { "`", 12, "反引号转义(混淆)" },
        { "${", 10, "变量扩展(${})" },
        { "[int]", 10, "整数类型转换" },
        { "[byte]", 10, "字节类型转换" },
        { "@(", 10, "数组表达式" },
        { "@{", 10, "哈希表表达式" },
        { "$(", 10, "子表达式$()" },
        { "{", 5, "脚本块{}" },
    };
    return s;
}

const QVector<Sig>& vbsJsDangerous() {
    static const QVector<Sig> s = {
        { "wscript.shell", 35, "WScript.Shell 对象(命令执行)" },
        { "shell.application", 35, "Shell.Application 对象" },
        { "cmd.exe", 30, "调用命令行" },
        { "cmd /c", 30, "执行命令" },
        { "powershell", 35, "调用 PowerShell" },
        { "scripting.filesystemobject", 25, "文件系统对象" },
        { "filesystemobject", 25, "文件系统对象" },
        { "createobject", 20, "创建 COM 对象" },
        { "getobject", 20, "获取 COM 对象" },
        { "msxml2.xmlhttp", 35, "XMLHTTP 网络请求" },
        { "microsoft.xmlhttp", 35, "XMLHTTP 网络请求" },
        { "winhttp.winhttprequest", 35, "WinHTTP 网络请求" },
        { "serverxmlhttp", 30, "服务器 XMLHTTP" },
        { "regread", 25, "读取注册表" },
        { "regwrite", 30, "写入注册表" },
        { "regdelete", 30, "删除注册表" },
        { "wscript.sleep", 10, "脚本延迟执行" },
        { "run ", 20, "执行命令" },
        { "exec ", 25, "执行命令" },
        { "chr(", 15, "字符码转换(chr)" },
        { "asc(", 10, "字符转 ASCII 码" },
        { "eval(", 30, "动态执行(eval)" },
        { "execute(", 30, "动态执行(execute)" },
        { "executeglobal", 35, "全局执行(executeGlobal)" },
        { "urlmon.dll", 35, "URL 监视器库(下载)" },
        { "urldownloadtofile", 35, "下载文件到本地" },
        { "wininet.dll", 30, "Windows Internet 库" },
        { "cscript.exe", 25, "CScript 脚本宿主" },
        { "wscript.exe", 25, "WScript 脚本宿主" },
        { "mshta.exe", 35, "MSHTA 执行(常用于绕过)" },
        { "environment", 15, "环境变量操作" },
        { "specialfolders", 15, "特殊文件夹访问" },
        { "currentdirectory", 15, "当前目录操作" },
    };
    return s;
}

const QVector<Sig>& batchDangerous() {
    static const QVector<Sig> s = {
        { "powershell", 35, "调用 PowerShell" },
        { "cmd.exe /c", 25, "执行命令" },
        { "certutil", 30, "证书工具(常用于下载)" },
        { "bitsadmin", 30, "BITS 后台下载" },
        { "reg add", 25, "修改注册表" },
        { "reg delete", 25, "删除注册表" },
        { "schtasks", 25, "计划任务操作" },
        { "net user", 20, "用户管理" },
        { "net localgroup", 20, "用户组管理" },
        { "attrib", 15, "文件属性修改" },
        { "icacls", 20, "权限修改" },
        { "takeown", 20, "获取所有权" },
    };
    return s;
}

int countMatches(const QRegularExpression& re, const QString& s) {
    int n = 0;
    auto it = re.globalMatch(s);
    while (it.hasNext()) { it.next(); ++n; }
    return n;
}

constexpr int kMinContentLength = 50;

void analyzePowerShell(const QString& content, const QString& lower, ScoreResult& r) {
    for (const Sig& sig : psDangerous())
        if (lower.contains(QLatin1String(sig.pattern))) { r.score += sig.score; r.reasons << u(sig.reason); }
    for (const Sig& sig : psObfuscation())
        if (content.contains(QLatin1String(sig.pattern))) { r.score += sig.score; r.reasons << u(sig.reason); }

    static const QRegularExpression base64Re(QStringLiteral("[A-Za-z0-9+/]{50,}={0,2}"));
    auto it = base64Re.globalMatch(content);
    while (it.hasNext()) {
        const auto m = it.next();
        if (m.capturedLength() >= 100) {
            r.score += 20;
            r.reasons << (u("发现长 Base64 字符串(") + QString::number(m.capturedLength()) + u(" 字符)"));
        }
    }
    static const QRegularExpression hexRe(QStringLiteral("0x[A-Fa-f0-9]{8,}|\\\\x[A-Fa-f0-9]{2,}"));
    const int hexCount = countMatches(hexRe, content);
    if (hexCount > 3) {
        r.score += 15;
        r.reasons << (u("发现多个十六进制字符串(") + QString::number(hexCount) + u(" 个)"));
    }
}

void analyzeVbsJs(const QString& content, const QString& lower, ScoreResult& r) {
    for (const Sig& sig : vbsJsDangerous())
        if (lower.contains(QLatin1String(sig.pattern))) { r.score += sig.score; r.reasons << u(sig.reason); }

    if (lower.contains(QLatin1String("chr(")) && lower.contains(QLatin1Char('&'))) {
        r.score += 20;
        r.reasons << u("字符拼接混淆(chr + &)");
    }
    static const QRegularExpression concatRe(QStringLiteral("&\\s*\""));
    if (countMatches(concatRe, content) > 5) {
        r.score += 15;
        r.reasons << u("频繁字符串拼接(混淆)");
    }
}

void analyzeBatch(const QString& /*content*/, const QString& lower, ScoreResult& r) {
    for (const Sig& sig : batchDangerous())
        if (lower.contains(QLatin1String(sig.pattern))) { r.score += sig.score; r.reasons << u(sig.reason); }

    if (lower.contains(QLatin1String("%comspec%")) || lower.contains(QLatin1String("%windir%"))) {
        r.score += 10;
        r.reasons << u("环境变量引用(可能用于混淆)");
    }
}

void analyzeCommon(const QString& content, const QString& lower, ScoreResult& r) {
    static const QRegularExpression urlRe(QStringLiteral("https?://[^\\s]+"));
    const int urlCount = countMatches(urlRe, content);
    if (urlCount > 0) {
        r.score += 15;
        r.reasons << (u("发现 URL 引用(") + QString::number(urlCount) + u(" 个)"));
    }
    static const QRegularExpression ipRe(QStringLiteral("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"));
    const int ipCount = countMatches(ipRe, content);
    if (ipCount > 0) {
        r.score += 10;
        r.reasons << (u("发现 IP 地址(") + QString::number(ipCount) + u(" 个)"));
    }

    static const QVector<Sig> fileOps = {
        { "filesystemobject", 15, "文件系统操作" },
        { "createobject", 10, "创建 COM 对象" },
        { "shell.application", 25, "Shell 应用程序" },
        { "wscript.shell", 25, "WScript.Shell" },
    };
    for (const Sig& sig : fileOps)
        if (lower.contains(QLatin1String(sig.pattern))) { r.score += sig.score; r.reasons << u(sig.reason); }

    if (lower.contains(QLatin1String("base64")) || lower.contains(QLatin1String("frombase64string"))) {
        r.score += 15;
        r.reasons << u("Base64 编码/解码操作");
    }

    if (content.size() > 1000) {
        int printable = 0;
        for (const QChar c : content) {
            const ushort u16 = c.unicode();
            if (u16 >= 32 && u16 <= 126) ++printable;
        }
        const double density = static_cast<double>(printable) / content.size();
        if (density > 0.9) {
            r.score += 10;
            r.reasons << u("高密度可打印字符(可能包含编码内容)");
        }
    }
}

QString extractEncodedCommand(const QString& commandLine) {
    static const QRegularExpression res[] = {
        QRegularExpression(QStringLiteral("-EncodedCommand\\s+([A-Za-z0-9+/=]+)"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("-enc\\s+([A-Za-z0-9+/=]+)"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("-e\\s+([A-Za-z0-9+/=]+)"), QRegularExpression::CaseInsensitiveOption),
    };
    for (const auto& re : res) {
        const auto m = re.match(commandLine);
        if (m.hasMatch()) return m.captured(1);
    }
    return QString();
}

} // namespace

ScoreResult ScriptAnalyzer::analyzeScript(const QString& scriptContent, ScriptType scriptType) {
    ScoreResult r;
    if (scriptContent.trimmed().isEmpty() || scriptContent.size() < kMinContentLength) return r;

    const QString lower = scriptContent.toLower();
    switch (scriptType) {
        case ScriptType::PowerShell: analyzePowerShell(scriptContent, lower, r); break;
        case ScriptType::Vbscript:
        case ScriptType::Javascript: analyzeVbsJs(scriptContent, lower, r); break;
        case ScriptType::Batch:      analyzeBatch(scriptContent, lower, r); break;
        default: break;
    }
    analyzeCommon(scriptContent, lower, r);
    return r;
}

ScriptAnalyzer::Extracted ScriptAnalyzer::extractScriptFromCommandLine(const QString& commandLine) {
    Extracted ex;
    if (commandLine.trimmed().isEmpty()) return ex;

    const QString cmd = commandLine.trimmed();
    const QString lower = cmd.toLower();

    // 仅 -EncodedCommand 能拿到真正的脚本内容(Base64 解码后即代码体)。
    if (lower.contains(QLatin1String("-encodedcommand")) || lower.contains(QLatin1String("-enc "))) {
        const QString encoded = extractEncodedCommand(cmd);
        if (!encoded.isEmpty()) {
            const auto dec = QByteArray::fromBase64Encoding(
                encoded.toLatin1(),
                QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
            if (dec && !dec.decoded.isEmpty()) {
                // -EncodedCommand 的字节流为 UTF-16LE。
                const QByteArray& b = dec.decoded;
                const QString decoded = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(b.constData()), b.size() / 2);
                ex.content = decoded;
                ex.type = ScriptType::PowerShell;
                return ex;
            }
        }
    }

    // mshta 内联脚本(javascript:/vbscript:)。
    if (lower.contains(QLatin1String("mshta")) &&
        (lower.contains(QLatin1String("javascript:")) || lower.contains(QLatin1String("vbscript:")))) {
        ex.content = cmd;
        ex.type = ScriptType::Javascript;
        return ex;
    }

    return ex; // {nullopt, Unknown}
}

// ============================================================================
// 脚本【文件正文】分析
// ============================================================================
//
// 判据的取舍全部由实测决定,不是凭经验列的。语料:
//   · 恶意:某目录下 7 个真实脚本样本(4 个 .bat / 2 个 WSH .js / 1 个 .ps1);
//   · 良性 A:本仓库自己的 66 个 .ps1/.bat(启动、停止、重建、打包、部署、诊断脚本)
//             + Windows 自带的 System32 脚本;
//   · 良性 B:本机 Kiro / Node 附带的 4003 个打包 / 压缩后的 .js。
//
// 【被实测否掉的判据 —— 不要再加回来】
//   · 「混用多种互不相关的文字系统」(以为是填充混淆):`mermaid-*.js` 得 29 分、
//     `serverWorkerMain.js` 得 29 分,而最差的那个恶意样本只有 15 —— i18n / locale 表
//     天然混用几十种文字。这条判据比无用更糟,方向是反的。
//   · 「单行 ≥64KB」单独用:4003 个打包 JS 里约 90 个命中。
//   · 「Base64 连续段 ≥2048 字符」单独用:`wasm-*.js` 有一段 622,148 字符。
//   · 「powershell -ep bypass / -w hidden」:69 个良性脚本里 23 个命中,其中 15 个
//     是【本仓库自己的脚本】。只能当互证,永远不能单独定罪。
//   · 「写 CurrentVersion\Run」:恶意样本 0 命中、良性 5 命中。在这个语料上是反指标。
//
// 留下的 5 条行为级判据在全部 4069 个良性文件上【零命中】,且覆盖 7 个样本中的 5 个。
// 它们的共同点是语义明确 —— 描述的是「只有加载器才会做的动作」,而不是统计量。
//
namespace {

// ---- 行为级判据(hard:单独即可定罪)------------------------------------

// 脚本把【自己】复制进常驻目录。正常脚本没有任何理由这么做。
// 形态:`copy /y "%~f0" "%APPDATA%\Microsoft\Windows.bat"`(实测样本原文)。
bool hitSelfCopyPersist(const QString& lower) {
    static const QRegularExpression re(
        QStringLiteral("(copy\\s+/y\\s+\"?%~f0|xcopy\\s+\"?%~f0"
                       "|copy-item[^\\n]{0,80}\\$(pscommandpath|myinvocation))"
                       "[^\\n]{0,160}(%appdata%|%programdata%|%userprofile%"
                       "|\\$env:appdata|\\\\startup\\\\)"),
        QRegularExpression::CaseInsensitiveOption);
    return re.match(lower).hasMatch();
}

// certutil 当解码器用。`certutil -decode` 把伪装成证书的 Base64 还原成可执行载荷,
// 是标准 LOLBin 手法(T1140 + T1027);实测样本用它解出第二级 .bat 再 call。
bool hitCertutilDecode(const QString& lower) {
    static const QRegularExpression re(QStringLiteral("certutil[^\\n]{0,120}-decode"),
                                       QRegularExpression::CaseInsensitiveOption);
    return re.match(lower).hasMatch();
}

// .bat / .cmd 里出现 PEM 封套。批处理没有任何正当理由内嵌证书 ——
// 那是拿来装载荷的容器(实测样本用 `-----BEGIN CERTIFICATE-----` 和
// 伪造的 `-----BEGIN X509 CRL-----` 各装了一份)。
//
// 【必须限定 .bat/.cmd】.ps1 处理证书是本职工作,JS 加密库也常带测试证书 ——
// 不限定的话这条立刻在良性语料上误报。
bool hitPemArmourInBatch(const QString& body, ScriptType type) {
    if (type != ScriptType::Batch) return false;
    static const QRegularExpression re(
        QStringLiteral("-----BEGIN (CERTIFICATE|X509 CRL|RSA PRIVATE KEY)-----"),
        QRegularExpression::CaseInsensitiveOption);
    return re.match(body).hasMatch();
}

// cmd 的「空变量拆词」混淆:把关键字用未定义的 %var% 逐字拆开,
// 形如 `i%すってo%f% %n%o%t% e%x%i%s%t`。cmd 展开空变量后还原成 `if not exist`,
// 而任何按字符串找关键字的检测都会落空。
//
// 判据是【单行内出现在词内部的 %..% 展开 ≥6 次】—— 正常批处理引用变量是整词引用
//(`%TEMP%\x`),不会把变量插在字母中间,更不会一行插六次以上。
bool hitVarSplitObfuscation(const QString& body, ScriptType type) {
    if (type != ScriptType::Batch) return false;
    static const QRegularExpression re(QStringLiteral("[A-Za-z]%[^%\\n]{1,40}%[A-Za-z]"));
    // 逐行匹配(计数必须是【单行内】的:整份文件累加会把正常批处理也算进来)。
    // 不切分成容器,避免为一份 256KB 的正文额外分配上万个字符串。
    int from = 0;
    const int n = body.size();
    while (from <= n) {
        int nl = body.indexOf(QLatin1Char('\n'), from);
        if (nl < 0) nl = n;
        int hits = 0;
        auto it = re.globalMatchView(QStringView{body}.mid(from, nl - from));
        while (it.hasNext()) {
            it.next();
            if (++hits >= 6) return true;
        }
        from = nl + 1;
    }
    return false;
}

// 「解密后执行」三件套同时出现:对称加密 / 解压 + Base64 解码 + 动态执行。
// 三者齐备就是 crypter 的定义本身,不是巧合 —— 实测样本是
// AES-256-CBC -> GZip -> IEX,三级套娃。
bool hitDecryptThenExecute(const QString& lower) {
    static const char* kCrypto[] = { "aesmanaged", "aes]::create", "createdecryptor",
                                     "gzipstream", "deflatestream", "rijndaelmanaged",
                                     "tripledescryptoserviceprovider" };
    static const char* kBase64[] = { "frombase64string", "convert]::frombase64" };
    static const char* kDynExec[] = { "invoke-expression", "iex(", "iex ", "assembly]::load",
                                      ".entrypoint", "reflection.assembly", "executeglobal" };
    const auto any = [&lower](const char* const* arr, size_t n) {
        for (size_t i = 0; i < n; ++i)
            if (lower.contains(QLatin1String(arr[i]))) return true;
        return false;
    };
    return any(kCrypto, std::size(kCrypto))
        && any(kBase64, std::size(kBase64))
        && any(kDynExec, std::size(kDynExec));
}

// ---- 统计判据(soft:只提分 / 只当互证,单独绝不定罪)---------------------

inline bool isBase64Char(ushort c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

// 退化路径:调用方没做流式统计时,只在已读入的前缀内统计。
int longestBase64RunIn(const QString& body) {
    int best = 0, cur = 0;
    for (const QChar c : body) {
        if (isBase64Char(c.unicode())) { if (++cur > best) best = cur; }
        else cur = 0;
    }
    return best;
}

int longestLineIn(const QString& body) {
    int best = 0, cur = 0;
    for (const QChar c : body) {
        if (c == QLatin1Char('\n')) { if (cur > best) best = cur; cur = 0; }
        else ++cur;
    }
    return qMax(best, cur);
}

} // namespace

void ScriptAnalyzer::StreamStats::feed(const char* data, qsizetype len) {
    for (qsizetype i = 0; i < len; ++i) {
        const auto b = static_cast<unsigned char>(data[i]);
        if (b == '\n') {
            if (curLine_ > longestLine_) longestLine_ = curLine_;
            curLine_ = 0;
        } else if (curLine_ < std::numeric_limits<int>::max()) {
            ++curLine_;
        }
        if (isBase64Char(b)) {
            if (curB64_ < std::numeric_limits<int>::max()) ++curB64_;
            if (curB64_ > longestB64_) longestB64_ = curB64_;
        } else {
            curB64_ = 0;
        }
    }
}

void ScriptAnalyzer::StreamStats::finish() {
    if (curLine_ > longestLine_) longestLine_ = curLine_;
    curLine_ = 0;
    curB64_ = 0;
}

ScriptType ScriptAnalyzer::scriptTypeFromPath(const QString& path) {
    const QString name = detail::fileNameLower(path);
    const int dot = name.lastIndexOf(QLatin1Char('.'));
    if (dot < 0) return ScriptType::Unknown;
    const QString ext = name.mid(dot + 1);
    if (ext == QLatin1String("ps1") || ext == QLatin1String("psm1")) return ScriptType::PowerShell;
    if (ext == QLatin1String("bat") || ext == QLatin1String("cmd"))  return ScriptType::Batch;
    if (ext == QLatin1String("vbs") || ext == QLatin1String("vbe"))  return ScriptType::Vbscript;
    if (ext == QLatin1String("js")  || ext == QLatin1String("jse"))  return ScriptType::Javascript;
    // .wsf / .hta 是容器(XML / HTML 里嵌 VBS 或 JS)。按 JS 的判据集扫,
    // 两者的危险 API 表在 analyzeVbsJs 里本来就是同一份。
    if (ext == QLatin1String("wsf") || ext == QLatin1String("hta"))  return ScriptType::Javascript;
    return ScriptType::Unknown;
}

QString ScriptAnalyzer::extractScriptFilePath(const QString& commandLine) {
    if (commandLine.trimmed().isEmpty()) return QString();

    // 按空白切 token,双引号内的空白不算分隔符。cmd 的 `/c "..."` 形态里整条子命令
    // 会被引号包住,所以引号内的内容还要再切一次 —— 用同一个切分器递归一层即可。
    const auto tokenize = [](const QString& s) {
        QStringList out;
        QString cur;
        bool inQuote = false;
        for (const QChar c : s) {
            if (c == QLatin1Char('"')) { inQuote = !inQuote; continue; }
            if (!inQuote && (c == QLatin1Char(' ') || c == QLatin1Char('\t'))) {
                if (!cur.isEmpty()) { out << cur; cur.clear(); }
                continue;
            }
            cur += c;
        }
        if (!cur.isEmpty()) out << cur;
        return out;
    };

    const QStringList tokens = tokenize(commandLine);
    bool first = true;
    for (const QString& tok : tokens) {
        // 第一个 token 是宿主自己(cmd.exe / powershell.exe / wscript.exe),跳过:
        // 它是 .exe,本来也不会被 scriptTypeFromPath 认成脚本,但显式跳过更清楚。
        if (first) { first = false; continue; }
        if (tok.startsWith(QLatin1Char('/')) || tok.startsWith(QLatin1Char('-')))
            continue;   // 开关(/c、-ep、-File、//e:jscript …)
        if (scriptTypeFromPath(tok) != ScriptType::Unknown)
            return tok;
    }
    return QString();
}

ScriptAnalyzer::FileScan ScriptAnalyzer::analyzeScriptFile(const QString& body, ScriptType type,
                                                           qint64 fileSize, bool wshHosted,
                                                           const StreamStats* stats) {
    FileScan fs;
    if (type == ScriptType::Unknown || body.isEmpty()) return fs;

    const QString lower = body.toLower();
    const auto add = [&fs](const char* id, int score, const QString& reason, bool hard) {
        fs.hits << QString::fromLatin1(id);
        fs.score += score;
        fs.reasons << reason;
        if (hard) fs.hardSignal = true;
    };

    // ---- 行为级(hard)----
    if (hitSelfCopyPersist(lower))
        add("self-copy-persist", 55,
            u("脚本把自身复制到常驻目录(加载器落地驻留,T1547)"), true);
    if (hitCertutilDecode(lower))
        add("certutil-decode", 50,
            u("脚本用 certutil -decode 还原载荷(LOLBin 解码,T1140)"), true);
    if (hitPemArmourInBatch(body, type))
        add("pem-armour-in-batch", 55,
            u("批处理内嵌伪造的 PEM 封套(用证书格式伪装载荷,T1027)"), true);
    if (hitVarSplitObfuscation(body, type))
        add("var-split-obfuscation", 55,
            u("批处理用空变量逐字拆开关键字(规避字符串检测,T1027.010)"), true);
    if (hitDecryptThenExecute(lower))
        add("decrypt-then-execute", 60,
            u("脚本内含「解密/解压 + Base64 + 动态执行」完整链(crypter,T1140+T1059)"), true);

    // ---- 统计量(soft;只有 WSH 宿主这一前提下才有判别力,理由见头文件)----
    //
    // 三重前提,缺一不可:
    //   · 宿主确实是 WSH —— 打包 JS 的大量长行 / 大编码块就是靠这一条排除掉的;
    //   · 类型确实是 WSH 会跑的类型 —— 体积门槛是拿 winrm.vbs / slmgr.vbs 校准的,
    //     对 .bat 没有校准过(1.8MB 的 .bat 同样离谱,但那不是本判据该管的,
    //     那几个样本本来就已被行为级判据定罪);
    //   · 体积过门槛。
    if (wshHosted && isWshScriptType(type) && fileSize >= kOversizedWshBytes) {
        // 优先用整文件的流式统计;没有就退回前缀内统计(小文件下两者等价)。
        const int b64run = stats ? stats->longestBase64Run() : longestBase64RunIn(body);
        const int maxLine = stats ? stats->longestLine() : longestLineIn(body);
        const bool bigBlob = b64run >= 2048;
        const bool hugeLine = maxLine >= 65536;

        // 体积单独【不】定罪 —— 大不等于恶意。需要一条互证,取法与
        // Worker::detectSideloadedTamperedModule 形态 2 一致(未签名 + 互证其一)。
        const bool corroborated = bigBlob || hugeLine;
        add("oversized-wsh-script", corroborated ? 45 : 25,
            u("WSH 宿主运行超大脚本文件(%1 KB;系统自带 WSH 脚本最大约 200KB)")
                .arg(fileSize / 1024),
            corroborated);
        if (bigBlob)
            add("embedded-encoded-blob", 10,
                u("脚本内含长 Base64 连续段(%1 字符)").arg(b64run), false);
        if (hugeLine)
            add("single-huge-line", 10,
                u("脚本存在超长单行(%1 字符,压缩 / 混淆产物)").arg(maxLine), false);
    }

    // ---- 复用既有关键字表,但【必须封顶,且只当互证】----
    //
    // 两个限制,各有实测依据:
    //
    // 1) 封顶。analyzeScript 是按命令行长度的文本调好的:analyzePowerShell 里那个
    //    `while (it.hasNext())` 对每一段 ≥100 字符的 Base64 都 +20,不设上限。
    //    直接拿它扫整份正文,分数会失控(实测 crypted_test.ps1 原始分 160)。
    //
    // 2) 只在【已有其它判据命中】时才计入。实测把它无条件计入的后果:本仓库自己的
    //    143 个脚本里 137 个拿到非零分,Windows 自带 77 个里 74 个,打包 JS 2500 个里
    //    1623 个 —— 也就是说「脚本里有危险关键字」在真实语料上几乎恒为真,单独毫无信息量。
    //    留着它只会给每条脚本事件垫一层底分,把别处触发的 Ask 悄悄顶成 Block
    //    (裁决末步是 `riskScore>=高危 ? Block : Ask`)。
    //    有其它判据托底时它才有意义:那时它说明的是「这个已经可疑的脚本还很密集地用危险 API」。
    if (!fs.hits.isEmpty()) {
        const ScoreResult kw = analyzeScript(body, type);
        if (kw.score > 0) {
            constexpr int kKeywordCap = 25;
            const int capped = qMin(kw.score, kKeywordCap);
            fs.hits << QStringLiteral("keyword-density");
            fs.score += capped;
            fs.reasons << u("脚本正文命中 %1 项危险特征(原始 %2 分,计入上限 %3 分)")
                            .arg(kw.reasons.size()).arg(kw.score).arg(capped);
        }
    }

    // 总分封顶:分数只用来在「硬指标已成立」之后区分 Block / Ask(见 RuleEngine 末步),
    // 无上限的累加只会让阈值失去意义。
    fs.score = qMin(fs.score, 100);
    return fs;
}

} // namespace bulwark::engine
