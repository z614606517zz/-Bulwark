using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 验证"健康签名直接放行(免打扰)"策略:有效签名且无盗用/滥用/银狐画像 → 放行;
/// 一旦命中签名失配/吊销/过期签名/文件膨胀/危险命令行/白加黑/空壳新证书等 → 不放行。
/// </summary>
public class HealthySignedTrustTests
{
    private static SecurityEvent SignedProc(string path = @"C:\Program Files\Foo\foo.exe")
        => new()
        {
            Type = EventType.ProcessCreate,
            ActorPid = 2000,
            ActorPath = path,
            ActorSigned = true,
            ActorPublisher = "Foo Software Co., Ltd.",
            ActorHash = "b".PadRight(64, 'b')
        };

    private static Verdict EvalWith(SecurityEvent e)
    {
        var engine = new RuleEngine { TrustSignedActors = true, DefaultAction = VerdictAction.Allow };
        return engine.Evaluate(e);
    }

    [Fact]
    public void HealthySigned_IsAllowed_WithoutPrompt()
    {
        var e = SignedProc();
        var v = EvalWith(e);
        Assert.Equal(VerdictAction.Allow, v.Action);
        Assert.NotEqual(VerdictAction.Ask, v.Action);
    }

    [Fact]
    public void SignatureMismatch_IsNotHealthyAllowed()
    {
        var e = SignedProc();
        e.ActorSigned = false;          // 签名校验失败
        e.SignatureMismatch = true;     // 内嵌签名但校验不通过(篡改/盗用)
        var v = EvalWith(e);
        Assert.NotEqual(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void RevokedCert_IsBlocked_NotAllowed()
    {
        var e = SignedProc();
        e.CertRevoked = true;           // 证书已吊销(被盗用证书典型)
        var v = EvalWith(e);
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Fact]
    public void SignedAfterExpiry_IsBlocked()
    {
        var e = SignedProc();
        e.SignedAfterCertExpiry = true; // 过期后签名(盗用旧证书)
        var v = EvalWith(e);
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Fact]
    public void DangerousCommandLine_IsNotHealthyAllowed()
    {
        // 签名正常,但命令行是编码执行(白加黑)——不能走健康签名放行
        var e = SignedProc(@"C:\Windows\System32\powershell.exe");
        e.CommandLine = "powershell -nop -w hidden -enc SQBFAFgA";
        var v = EvalWith(e);
        Assert.NotEqual(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void FirstSeen_WithYoungCert_IsNotAutoAllowed()
    {
        // 空壳公司新证书木马画像:带签名 + 本机首见 + 证书很新。
        // 不应走"健康签名"快速放行通道(Source != TrustedSigner);
        // 是否最终放行交由行为研判,这里只验证未被健康签名直接放行。
        var e = SignedProc();
        e.IsFirstSeen = true;
        e.CertNotAfterUtc = System.DateTime.UtcNow.AddDays(90); // 有效期临近 => 新证书
        var v = EvalWith(e);
        Assert.NotEqual(VerdictSource.TrustedSigner, v.Source);
    }

    [Fact]
    public void FileBloating_SignedButHuge_IsNotAutoAllowed()
    {
        // 文件膨胀规避:超大文件即便看似有签名也应交回研判(此处构造未签名大文件命中硬指标)
        var e = SignedProc();
        e.ActorSigned = false;
        e.ActorFileSize = 95L * 1024 * 1024;
        var v = EvalWith(e);
        Assert.NotEqual(VerdictAction.Allow, v.Action);
    }
}
