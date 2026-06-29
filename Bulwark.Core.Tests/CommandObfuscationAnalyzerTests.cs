using Bulwark.Core.Engine;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="CommandObfuscationAnalyzer"/>:从统计/结构特征识别"被刻意混淆"的命令行,
/// 而非匹配明文 token。核心是降误报(正常长命令行 0 分)+ 抓混淆(高分)。
/// </summary>
public class CommandObfuscationAnalyzerTests
{
    [Theory]
    // 正常命令行不应判为混淆
    [InlineData(@"C:\Program Files\App\app.exe --config ""C:\ProgramData\App\settings.json"" --verbose")]
    [InlineData(@"git commit -m ""fix: resolve null reference in parser""")]
    [InlineData(@"dotnet build MySolution.sln -c Release --no-restore")]
    public void Normal_CommandLines_ScoreZeroOrLow(string cmd)
    {
        var (score, _) = CommandObfuscationAnalyzer.Analyze(cmd);
        Assert.True(score < 30, $"正常命令行应低分,实际 {score}");
    }

    [Fact]
    public void PowerShell_BacktickAndCharObfuscation_IsFlagged()
    {
        // g`et-i`tem + [char] 拼接 + -join,多种混淆叠加
        var cmd = "powershell -nop i`e`x ([char]105+[char]101+[char]120) -join ('a','b','c')";
        var (score, reasons) = CommandObfuscationAnalyzer.Analyze(cmd);
        Assert.True(score >= 30, $"混淆命令应高分,实际 {score}");
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void LongBase64Payload_IsFlagged()
    {
        var b64 = new string('A', 130) + "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" + new string('Z', 120);
        var cmd = "powershell -e " + b64;
        var (score, reasons) = CommandObfuscationAnalyzer.Analyze(cmd);
        Assert.True(score >= 14, $"含长 Base64 应加分,实际 {score}");
        Assert.Contains(reasons, r => r.Contains("Base64"));
    }

    [Fact]
    public void EnvVarSubstringObfuscation_IsFlagged()
    {
        // cmd 环境变量子串截取混淆:%comspec:~0,1% 等
        var cmd = @"cmd /c set x=powershell&& %x:~0,4%.exe -w hidden -enc ZQBjAGgAbwA";
        var (score, _) = CommandObfuscationAnalyzer.Analyze(cmd);
        Assert.True(score > 0);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    public void NullOrShort_ReturnsZero(string? cmd)
    {
        var (score, reasons) = CommandObfuscationAnalyzer.Analyze(cmd);
        Assert.Equal(0, score);
        Assert.Empty(reasons);
    }

    [Fact]
    public void ShannonEntropy_RandomHigherThanRepetitive()
    {
        double repetitive = CommandObfuscationAnalyzer.ShannonEntropy("aaaaaaaaaa");
        double random = CommandObfuscationAnalyzer.ShannonEntropy("a7Bz9Kq2Xp");
        Assert.True(random > repetitive);
    }
}
