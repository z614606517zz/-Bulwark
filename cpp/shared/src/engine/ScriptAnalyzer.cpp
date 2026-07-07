#include "bulwark/engine/ScriptAnalyzer.h"
#include <QVector>
#include <QByteArray>
#include <QRegularExpression>

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

} // namespace bulwark::engine
