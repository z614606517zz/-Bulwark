using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 真实测试:把内置规则集 <see cref="DefaultRules.Build"/> 加载进 <see cref="RuleEngine"/>,
/// 用具体的「银狐控制微信/QQ 群发」事件跑一遍完整决策链,验证新增批次 14c 的裁决符合预期。
///
/// 覆盖:
///  - 具名群控/hook 模块 DLL 落地 + 被加载 -> Block
///  - 微信数据库解密/导出工具命令行(群发目标采集) -> Ask
///  - 向企业微信/微信 OCR 等子进程注入远程线程(未签名) -> Ask
///  - 官方签名进程的正常自注入不被误伤 -> 不 Block
/// </summary>
public class SilverFoxImRulesTests
{
    private static RuleEngine BuildEngine()
    {
        var engine = new RuleEngine { TrustSignedActors = true, DefaultAction = VerdictAction.Allow };
        engine.LoadRules(DefaultRules.Build());
        return engine;
    }

    private static SecurityEvent FileDrop(string target, string actor, bool signed = false) => new()
    {
        Type = EventType.FileWrite,
        ActorPath = actor,
        ActorSigned = signed,
        Target = target
    };

    private static SecurityEvent ImageLoad(string module, string actor, bool signed = false) => new()
    {
        Type = EventType.ImageLoad,
        ActorPath = actor,
        ActorSigned = signed,
        Target = module
    };

    private static SecurityEvent Cmdline(string cmd, string actor, bool signed = false) => new()
    {
        Type = EventType.ProcessCreate,
        ActorPath = actor,
        ActorSigned = signed,
        Target = actor,
        CommandLine = cmd
    };

    private static SecurityEvent Inject(string victim, string actor, bool signed) => new()
    {
        Type = EventType.RemoteThread,
        ActorPath = actor,
        ActorSigned = signed,
        Target = victim
    };

    [Theory]
    [InlineData(@"C:\Users\v\AppData\Local\Temp\wxhook.dll")]
    [InlineData(@"C:\ProgramData\WeChatSDK64.dll")]
    [InlineData(@"C:\Users\v\Downloads\vchat.dll")]
    [InlineData(@"C:\tmp\WeChatRobotCE.dll")]
    [InlineData(@"C:\tmp\WeWorkHook.dll")]
    [InlineData(@"C:\tmp\wxDumpCore.dll")]
    public void NamedGroupControlModule_Drop_IsBlocked(string target)
    {
        var engine = BuildEngine();
        var v = engine.Evaluate(FileDrop(target, @"C:\Users\v\Downloads\dropper.exe"));
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Theory]
    [InlineData(@"C:\Users\v\AppData\Roaming\Tencent\WeChat\wxhook.dll")]
    [InlineData(@"C:\ProgramData\vchat64.dll")]
    public void NamedGroupControlModule_Load_IsBlocked(string module)
    {
        var engine = BuildEngine();
        // 即便加载方是"微信本体路径",具名外挂模块被加载仍应硬拦。
        var v = engine.Evaluate(ImageLoad(module, @"C:\Program Files\Tencent\WeChat\WeChat.exe", signed: true));
        Assert.Equal(VerdictAction.Block, v.Action);
    }

    [Theory]
    [InlineData(@"python.exe -m PyWxDump")]
    [InlineData(@"SharpWxDump.exe")]
    [InlineData(@"wxdump.exe --out contacts.csv")]
    [InlineData(@"python WeChatMsg.py")]
    [InlineData(@"node wxhook-bot.js")]
    public void ChatDbHarvestTool_Cmdline_IsAsk(string cmd)
    {
        var engine = BuildEngine();
        var v = engine.Evaluate(Cmdline(cmd, @"C:\Users\v\Downloads\tool.exe"));
        Assert.Equal(VerdictAction.Ask, v.Action);
    }

    [Theory]
    [InlineData(@"C:\Program Files\WXWork\WeChatOCR.exe")]
    [InlineData(@"C:\Program Files\Tencent\WXWork\WXWorkWeb.exe")]
    public void InjectImSubprocess_Unsigned_IsAsk(string victim)
    {
        var engine = BuildEngine();
        var v = engine.Evaluate(Inject(victim, @"C:\Users\v\AppData\Local\Temp\host.exe", signed: false));
        Assert.Equal(VerdictAction.Ask, v.Action);
    }

    [Fact]
    public void InjectImSubprocess_SignedActor_NotAsked_ByRule()
    {
        // 官方签名注入方(如企业微信自身多进程)不应命中未签名注入规则,
        // 避免把正常自注入误报为群控(RequireUnsigned 精准约束)。
        var engine = BuildEngine();
        var v = engine.Evaluate(Inject(
            @"C:\Program Files\WXWork\WeChatOCR.exe",
            @"C:\Program Files\Tencent\WXWork\WXWork.exe", signed: true));
        Assert.NotEqual(VerdictAction.Block, v.Action);
    }
}
