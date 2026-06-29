using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 知名安全软件共存放行:消除「对方自我保护致签名读不到 → 误判篡改 + 清理自身 Temp 被当勒索」
/// 这类 AV 互踩误报;同时验证「进程名 + 受保护目录」双重判定能挡住用户目录下的同名伪造。
/// </summary>
public class SecurityProductTrustTests
{
    [Fact]
    public void Kaspersky_DeletingOwnTemp_WithSignatureMismatch_IsAllowed()
    {
        // 复刻真实误报:avp.exe 位于 Program Files,签名校验失败(自我保护),批量删自己的 Temp。
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.FileDelete,
            ActorPath = @"C:\Program Files (x86)\Kaspersky Lab\KES.14.0.0\avp.exe",
            ActorSigned = false,
            SignatureMismatch = true, // 自我保护导致 WinVerifyTrust 失败被误判为失配
            Target = @"C:\ProgramData\Kaspersky Lab\KES.14.0\Temp\tempio\PR123"
        };

        var verdict = engine.Evaluate(e);

        Assert.Equal(VerdictAction.Allow, verdict.Action);
        Assert.False(e.HasThreatIndicator); // 放行在最前端,根本不跑启发式
        Assert.Contains(e.EvidenceChain, ev => ev.Kind == EvidenceKind.Trust && ev.Description.Contains("安全软件"));
    }

    [Fact]
    public void SpoofedAvpInUserTemp_IsNotTrusted()
    {
        // 恶意软件在用户可写目录伪造 avp.exe —— 不在受保护安装目录,不得被放行。
        Assert.False(TrustPolicy.IsTrustedSecurityProduct(new SecurityEvent
        {
            ActorPath = @"C:\Users\me\AppData\Local\Temp\avp.exe"
        }, out _));
    }

    [Fact]
    public void DefenderInSystem32_IsTrusted()
    {
        Assert.True(TrustPolicy.IsTrustedSecurityProduct(new SecurityEvent
        {
            ActorPath = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
        }, out var reason));
        Assert.Contains("安全软件", reason);
    }

    [Fact]
    public void NonSecurityProcess_IsNotTrustedByThisPath()
    {
        Assert.False(TrustPolicy.IsTrustedSecurityProduct(new SecurityEvent
        {
            ActorPath = @"C:\Program Files\App\app.exe"
        }, out _));
    }
}
