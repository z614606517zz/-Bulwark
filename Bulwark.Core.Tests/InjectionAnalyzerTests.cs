using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="InjectionAnalyzer"/>:进程注入 / DLL 侧载检测。
/// 注入敏感进程或由未签名/LOLBin 发起 => 硬指标;合法签名一般注入 => 仅软信号;自注入 => 0。
/// </summary>
public class InjectionAnalyzerTests
{
    private static SecurityEvent RemoteThread(string actor, string target, bool signed = false)
        => new()
        {
            Type = EventType.RemoteThread,
            ActorPath = actor,
            ActorSigned = signed,
            Target = target
        };

    private static SecurityEvent ImageLoad(string loader, string module, bool moduleSigned)
        => new()
        {
            Type = EventType.ImageLoad,
            ActorPath = loader,
            Target = module,
            ActorSigned = moduleSigned // ImageLoad 事件中 ActorSigned 表示被加载模块的签名
        };

    [Fact]
    public void InjectIntoLsass_IsHardIndicator()
    {
        var e = RemoteThread(@"C:\Temp\x.exe", @"C:\Windows\System32\lsass.exe", signed: false);
        var (score, reasons, hard) = InjectionAnalyzer.Analyze(e);
        Assert.True(hard);
        Assert.True(score >= 70);
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void InjectIntoCriticalProcess_IsHardIndicator()
    {
        var e = RemoteThread(@"C:\app\tool.exe", @"C:\Windows\System32\winlogon.exe", signed: true);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.True(hard, "注入关键系统进程无论签名都应为硬指标");
        Assert.True(score >= 60);
    }

    [Fact]
    public void UnsignedCrossProcessInjection_IsHardIndicator()
    {
        var e = RemoteThread(@"C:\Users\u\Downloads\game.exe", @"C:\Program Files\App\app.exe", signed: false);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.True(hard, "未签名进程跨进程注入应为硬指标");
        Assert.True(score > 0);
    }

    [Fact]
    public void LolbinInjection_IsHardIndicator()
    {
        var e = RemoteThread(@"C:\Windows\System32\rundll32.exe", @"C:\Program Files\App\app.exe", signed: true);
        var (_, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.True(hard, "LOLBin 发起的注入应为硬指标");
    }

    [Fact]
    public void SignedNonLolbinCrossInjection_IsSoftOnly()
    {
        // 合法签名、非 LOLBin、注入普通应用(如反作弊/录屏):仅软信号,不置硬指标。
        var e = RemoteThread(@"C:\Program Files\AntiCheat\ac.exe", @"C:\Games\game.exe", signed: true);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.False(hard);
        Assert.True(score > 0, "应仍累加软信号分");
    }

    [Fact]
    public void SelfInjection_NotScored()
    {
        var e = RemoteThread(@"C:\app\a.exe", @"C:\app\a.exe", signed: false);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.Equal(0, score);
        Assert.False(hard);
    }

    [Fact]
    public void UnsignedModuleFromTemp_IsSideloadHardIndicator()
    {
        var e = ImageLoad(@"C:\Program Files\App\app.exe",
            @"C:\Users\u\AppData\Local\Temp\evil.dll", moduleSigned: false);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.True(hard, "高危目录加载未签名模块应判为侧载硬指标");
        Assert.True(score >= 30);
    }

    [Fact]
    public void SignedModuleFromTemp_NotFlagged()
    {
        var e = ImageLoad(@"C:\Program Files\App\app.exe",
            @"C:\Users\u\AppData\Local\Temp\legit.dll", moduleSigned: true);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.Equal(0, score);
        Assert.False(hard);
    }

    [Fact]
    public void UnsignedModuleFromInstallDir_NotFlagged()
    {
        // 从安装目录加载自带未签名 DLL 是常见合法行为,不应误报。
        var e = ImageLoad(@"C:\Program Files\App\app.exe",
            @"C:\Program Files\App\plugin.dll", moduleSigned: false);
        var (score, _, hard) = InjectionAnalyzer.Analyze(e);
        Assert.Equal(0, score);
        Assert.False(hard);
    }
}
