using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 把一次安全事件 + 裁决格式化为 ECS(Elastic Common Schema)风格的结构化告警。
///
/// 目的:让磐垒可作为「传感器」接入 SIEM(Elastic / Splunk / OpenSearch 等)。
/// 输出为嵌套字典,序列化后即一条 ECS 兼容的 JSON 文档,字段遵循 ECS 命名约定:
///   @timestamp / event.* / process.* / process.code_signature.* / destination.* /
///   rule.* / threat.technique[] / threat.tactic[],并在 bulwark.* 下保留证据链等扩展。
///
/// 纯函数、无副作用、平台无关,便于单测。由服务端在事件处置后导出。
/// </summary>
public static class EcsAlertFormatter
{
    public const string EcsVersion = "8.11.0";

    /// <summary>构造一条 ECS 风格告警(嵌套字典)。</summary>
    public static Dictionary<string, object?> Format(SecurityEvent e, Verdict v)
    {
        var doc = new Dictionary<string, object?>
        {
            ["@timestamp"] = (e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc)
                .ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            ["ecs"] = new Dictionary<string, object?> { ["version"] = EcsVersion },
            ["event"] = BuildEvent(e, v),
            ["message"] = BuildMessage(e, v),
            ["process"] = BuildProcess(e),
        };

        // 网络外联 -> destination
        if (e.Type == EventType.NetworkConnect && !string.IsNullOrEmpty(e.Target))
            doc["destination"] = BuildDestination(e.Target);

        // 命中规则 -> rule
        if (!string.IsNullOrEmpty(e.MatchedRuleNote))
            doc["rule"] = new Dictionary<string, object?> { ["name"] = e.MatchedRuleNote };

        // ATT&CK -> threat
        var threat = BuildThreat(e);
        if (threat is not null) doc["threat"] = threat;

        // 扩展命名空间:保留证据链与磐垒特有字段
        doc["bulwark"] = BuildBulwark(e, v);

        return doc;
    }

    private static Dictionary<string, object?> BuildEvent(SecurityEvent e, Verdict v)
    {
        string action = v.Action switch
        {
            VerdictAction.Block => "blocked",
            VerdictAction.Ask => "prompted",
            _ => "allowed"
        };
        // 阻止 = 拦截成功;其余视为放行/询问的处理成功
        var categories = new List<string>();
        if (e.HasThreatIndicator || v.Action == VerdictAction.Block)
            categories.Add("intrusion_detection");
        categories.Add(e.Type == EventType.NetworkConnect ? "network" : "process");

        return new Dictionary<string, object?>
        {
            ["kind"] = e.HasThreatIndicator || v.Action == VerdictAction.Block ? "alert" : "event",
            ["category"] = categories,
            ["action"] = action,
            ["type"] = new[] { EventTypeToEcs(e.Type) },
            ["outcome"] = "success",
            ["risk_score"] = e.RiskScore,
            ["severity"] = SeverityOf(e.RiskScore),
            ["provider"] = "Bulwark",
            ["module"] = e.Type.ToString(),
            ["reason"] = v.Source.ToString()
        };
    }

    private static Dictionary<string, object?> BuildProcess(SecurityEvent e)
    {
        var proc = new Dictionary<string, object?>
        {
            ["executable"] = e.ActorPath,
            ["name"] = SafeName(e.ActorPath),
            ["pid"] = e.ActorPid,
        };
        if (!string.IsNullOrEmpty(e.CommandLine)) proc["command_line"] = e.CommandLine;
        if (!string.IsNullOrEmpty(e.ActorHash))
            proc["hash"] = new Dictionary<string, object?> { ["sha256"] = e.ActorHash };

        proc["code_signature"] = new Dictionary<string, object?>
        {
            ["exists"] = e.ActorSigned || e.SignatureMismatch,
            ["trusted"] = e.ActorSigned && !e.SignatureMismatch && !e.CertRevoked && !e.SignedAfterCertExpiry,
            ["valid"] = e.ActorSigned && !e.SignatureMismatch,
            ["subject_name"] = e.ActorPublisher,
            ["status"] = SignatureStatus(e)
        };

        if (e.ParentPid != 0 || !string.IsNullOrEmpty(e.ParentPath))
        {
            proc["parent"] = new Dictionary<string, object?>
            {
                ["executable"] = e.ParentPath,
                ["name"] = SafeName(e.ParentPath),
                ["pid"] = e.ParentPid
            };
        }
        return proc;
    }

    private static Dictionary<string, object?> BuildDestination(string target)
    {
        var dest = new Dictionary<string, object?>();
        string host = target;
        int colon = target.LastIndexOf(':');
        if (colon > 0 && colon < target.Length - 1 && target.Skip(colon + 1).All(char.IsDigit))
        {
            host = target.Substring(0, colon);
            if (int.TryParse(target.Substring(colon + 1), out var port)) dest["port"] = port;
        }
        dest["address"] = host;
        if (System.Net.IPAddress.TryParse(host, out _)) dest["ip"] = host;
        else dest["domain"] = host;
        return dest;
    }

    private static Dictionary<string, object?>? BuildThreat(SecurityEvent e)
    {
        // 从证据链取去重的技战术(优先用已注解的 Technique 字段)
        var techIds = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ev in e.EvidenceChain)
            if (!string.IsNullOrEmpty(ev.Technique) && seen.Add(ev.Technique!))
                techIds.Add(ev.Technique!);

        if (techIds.Count == 0) return null;

        var techniques = new List<object>();
        var tactics = new List<object>();
        var tacticSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in techIds)
        {
            var t = AttackCatalog.Lookup(id);
            techniques.Add(new Dictionary<string, object?>
            {
                ["id"] = id,
                ["name"] = t?.Name ?? id
            });
            if (t is not null && tacticSeen.Add(t.Tactic))
                tactics.Add(new Dictionary<string, object?> { ["name"] = t.Tactic });
        }

        return new Dictionary<string, object?>
        {
            ["framework"] = "MITRE ATT&CK",
            ["technique"] = techniques,
            ["tactic"] = tactics
        };
    }

    private static Dictionary<string, object?> BuildBulwark(SecurityEvent e, Verdict v)
    {
        return new Dictionary<string, object?>
        {
            ["event_id"] = e.Id.ToString(),
            ["verdict"] = v.Action.ToString(),
            ["verdict_source"] = v.Source.ToString(),
            ["has_threat_indicator"] = e.HasThreatIndicator,
            ["user_mode_observed"] = e.UserModeObserved,
            ["reasons"] = e.RiskReasons.ToList(),
            ["techniques"] = e.Techniques.ToList(),
            ["evidence"] = e.EvidenceChain.Select(ev => new Dictionary<string, object?>
            {
                ["source"] = ev.Source,
                ["kind"] = ev.Kind.ToString(),
                ["description"] = ev.Description,
                ["score_delta"] = ev.ScoreDelta,
                ["technique"] = ev.Technique
            }).Cast<object>().ToList()
        };
    }

    private static string BuildMessage(SecurityEvent e, Verdict v)
    {
        string act = v.Action switch
        {
            VerdictAction.Block => "拦截",
            VerdictAction.Ask => "询问",
            _ => "放行"
        };
        return $"[{act}] {e.Type} {SafeName(e.ActorPath)}(pid={e.ActorPid}) -> {e.Target} (风险 {e.RiskScore})";
    }

    /// <summary>ECS event.severity:0-21 区间常用映射;这里按风险分粗分四级。</summary>
    private static int SeverityOf(int risk) => risk switch
    {
        >= 80 => 3, // critical/high
        >= 50 => 2, // medium
        > 0 => 1,   // low
        _ => 0
    };

    private static string SignatureStatus(SecurityEvent e)
    {
        if (!e.ActorSigned && !e.SignatureMismatch) return "unsigned";
        if (e.SignatureMismatch) return "tampered";
        if (e.CertRevoked) return "revoked";
        if (e.SignedAfterCertExpiry) return "expired";
        return "valid";
    }

    private static string EventTypeToEcs(EventType t) => t switch
    {
        EventType.ProcessCreate => "start",
        EventType.ProcessTerminate => "end",
        EventType.NetworkConnect => "connection",
        EventType.FileWrite => "change",
        EventType.FileDelete => "deletion",
        EventType.RegistryWrite => "change",
        EventType.ImageLoad => "info",
        EventType.RemoteThread => "access",
        _ => "info"
    };

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path); }
        catch { return path; }
    }
}
