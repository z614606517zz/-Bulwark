using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="RuleEngine.Evaluate"/> 决策顺序:
/// 命中规则 > 信任策略 > 高危(Block) > 可疑(Ask) > 未签名低风险(Ask) > 默认放行。
/// 这些是核心安全行为,必须锁定防回归。
/// </summary>
public class RuleEngineTests
{
    private static RuleEngine NewEngine(bool trustSigned = true) => new()
    {
        TrustSignedActors = trustSigned,
        DefaultAction = VerdictAction.Allow
    };

    [Fact]
    public void ExplicitBlockRule_TakesPriority()
    {
        var engine = NewEngine();
        engine.AddRule(new DefenseRule
        {
            Type = EventType.ProcessTerminate,
            TargetPattern = @"*\lsass.exe",
            Action = VerdictAction.Block
        });

        var e = new SecurityEvent
        {
            Type = EventType.ProcessTerminate,
            ActorPath = @"C:\evil.exe",
            Target = @"C:\Windows\System32\lsass.exe"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Block, v.Action);
        Assert.Equal(VerdictSource.Rule, v.Source);
    }

    [Fact]
    public void SpecificAllowRule_OverridesBroadBlockRule()
    {
        var engine = NewEngine();
        // 宽泛拦截:任意未签名进程外联
        engine.AddRule(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            RequireUnsigned = true,
            Action = VerdictAction.Block
        });
        // 用户为某具体程序加白(更具体:含 ActorPath)
        engine.AddRule(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPath = @"C:\app\trusted.exe",
            Action = VerdictAction.Allow
        });

        var e = new SecurityEvent
        {
            Type = EventType.NetworkConnect,
            ActorPath = @"C:\app\trusted.exe",
            ActorSigned = false,
            Target = "1.2.3.4:443"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Allow, v.Action);
        Assert.Equal(VerdictSource.Rule, v.Source);
    }

    [Fact]
    public void BenignPublisher_IsAllowed_WhenNoRuleHits()
    {
        var engine = NewEngine();
        // 大厂签名且签名健康、无任何恶意画像:走"健康签名"快速放行通道(免打扰),
        // 直接放行且 Source=TrustedSigner。这是"有合法证书即免打扰"策略的体现。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Program Files\Google\Chrome\chrome.exe",
            ActorSigned = true,
            ActorPublisher = "Google LLC"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Allow, v.Action);
        Assert.Equal(VerdictSource.TrustedSigner, v.Source);
    }

    [Fact]
    public void StronglyTrusted_MicrosoftSystemDir_UsesTrustedSigner()
    {
        var engine = NewEngine();
        // 微软签名 + 系统目录 = 强可信,直接放行(TrustedSigner)。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\notepad.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Allow, v.Action);
        Assert.Equal(VerdictSource.TrustedSigner, v.Source);
    }

    [Fact]
    public void RevokedCert_IsBlocked_EvenForBigVendor()
    {
        var engine = NewEngine();
        // 大厂发行商 + 系统目录,但证书已吊销(盗用证书典型)-> 直接阻止。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\evil.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CertRevoked = true
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Block, v.Action);
        Assert.NotEqual(VerdictSource.TrustedSigner, v.Source);
    }

    [Fact]
    public void SignedAfterCertExpiry_IsBlocked()
    {
        var engine = NewEngine();
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Program Files\App\app.exe",
            ActorSigned = true,
            ActorPublisher = "Some Vendor",
            SignedAfterCertExpiry = true
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Fact]
    public void TrustedSigner_NotApplied_WhenDangerousCommandLine()
    {
        var engine = NewEngine();
        // 即便是受信任发行商签名,带攻击命令行也不放行(防白加黑)
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "powershell -enc ZQBjAGgA -w hidden downloadstring"
        };

        var v = engine.Evaluate(e);
        Assert.NotEqual(VerdictSource.TrustedSigner, v.Source);
        // 高危命令行累计应触发 Block
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Fact]
    public void HighRiskHeuristic_Blocks_WithoutRule()
    {
        var engine = NewEngine();
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentPath = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ActorSigned = true,
            CommandLine = "powershell -nop -w hidden -enc ZQBjAGgA"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Block, v.Action);
        Assert.Equal(VerdictSource.Heuristic, v.Source);
    }

    [Fact]
    public void UnsignedPlain_IsAllowed_NotAsked()
    {
        var engine = NewEngine();
        // 仅"无签名"、普通目录、无任何可疑行为。"没签名"不等于恶意:
        // 大量绿色软件/开源工具/自编译程序都没签名 -> 默认放行,不打扰。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Tools\portable\mytool.exe",
            ActorSigned = false
        };

        var v = engine.Evaluate(e);
        Assert.False(e.HasThreatIndicator, "仅缺签名不应被视为硬恶意指标");
        Assert.Equal(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void UnsignedFromSuspiciousDir_IsAllowed_WithoutDangerousBehavior()
    {
        var engine = NewEngine();
        // 无签名 + 从可疑目录(Temp)运行,但没有任何真实恶意行为特征。
        // 新原则:位置/签名是软信号,不构成拦截理由 -> 放行(仅记录)。
        // 注:实际部署中"从 Temp 执行未签名程序"由内置规则单独判定;此处测纯启发式路径。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\u\AppData\Local\Temp\portable.exe",
            ActorSigned = false
        };

        var v = engine.Evaluate(e);
        Assert.False(e.HasThreatIndicator, "仅位置+无签名不应是硬恶意指标");
        Assert.Equal(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void UnsignedWithDangerousCommandLine_IsHandled()
    {
        var engine = NewEngine();
        // 无签名 + 危险命令行(硬指标)-> 不静默放行(询问或拦截)。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Tools\x.exe",
            ActorSigned = false,
            CommandLine = "x.exe -enc ZQBjAGgA downloadstring http://evil/p"
        };

        var v = engine.Evaluate(e);
        Assert.True(e.HasThreatIndicator);
        Assert.NotEqual(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void SignedUnknownVendor_LowRisk_IsAllowed()
    {
        var engine = NewEngine();
        // 小厂签名、标准目录、无可疑特征 -> 不打扰,放行
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Program Files\SmallVendor\app.exe",
            ActorSigned = true,
            ActorPublisher = "Small Vendor LLC"
        };

        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void SignedUnknownVendor_SoftSignalsOnly_IsAllowed_NotAsked()
    {
        var engine = NewEngine();
        // 陌生发行商 + 非标准目录 + 本机首见 + 新证书:全是"软信号",有分但无恶意行为特征。
        // 这类是真正安全的进程(如装在 %LOCALAPPDATA%\Programs 的正规签名应用),应默认放行,
        // 不再因低风险软信号反复打扰用户。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\u\AppData\Local\Programs\App\app.exe",
            ActorSigned = true,
            ActorPublisher = "Unknown Vendor LLC",
            IsFirstSeen = true,
            CertNotAfterUtc = System.DateTime.UtcNow.AddDays(90)
        };

        var v = engine.Evaluate(e);
        Assert.True(e.RiskScore > 0, "应累计了软信号分数");
        Assert.False(e.HasThreatIndicator, "不应有硬恶意指标");
        Assert.Equal(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void SignedUnknownVendor_WithHardIndicator_AsksOrBlocks()
    {
        var engine = NewEngine();
        // 陌生发行商但带危险命令行(硬指标)-> 必须打扰用户(询问或更强处置),绝不静默放行。
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\u\AppData\Local\Programs\App\app.exe",
            ActorSigned = true,
            ActorPublisher = "Unknown Vendor LLC",
            CommandLine = "app.exe downloadstring http://evil/x"
        };

        var v = engine.Evaluate(e);
        Assert.True(e.HasThreatIndicator, "危险命令行应标记硬指标");
        Assert.NotEqual(VerdictAction.Allow, v.Action);
    }

    [Fact]
    public void CreateRuleFrom_PersistsDecision()
    {
        var engine = NewEngine();
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\app\x.exe",
            Target = "t"
        };

        var rule = engine.CreateRuleFrom(e, VerdictAction.Block);
        Assert.Contains(engine.GetRules(), r => r.Id == rule.Id);

        // 之后同类事件应命中该规则
        var v = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Block, v.Action);
        Assert.Equal(VerdictSource.Rule, v.Source);
    }

    [Fact]
    public void LoadRules_ReplacesExisting()
    {
        var engine = NewEngine();
        engine.AddRule(new DefenseRule { Type = EventType.ProcessCreate, Action = VerdictAction.Block });
        engine.LoadRules(new[] { new DefenseRule { Type = EventType.NetworkConnect, Action = VerdictAction.Allow } });
        Assert.Single(engine.GetRules());
    }

    [Fact]
    public void RemoveRule_Works()
    {
        var engine = NewEngine();
        var rule = new DefenseRule { Type = EventType.ProcessCreate, Action = VerdictAction.Block };
        engine.AddRule(rule);
        Assert.True(engine.RemoveRule(rule.Id));
        Assert.Empty(engine.GetRules());
    }
}
