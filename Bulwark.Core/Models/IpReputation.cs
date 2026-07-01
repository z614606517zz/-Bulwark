namespace Bulwark.Core.Models;

/// <summary>
/// 远端 IP / 域名信誉结论(来自网络威胁情报源,如微步 ThreatBook 场景 API)。
/// 与 <see cref="FileReputation"/> 类似,是「锦上添花」的情报加分项:
/// 情报源不可用 / 无结论时一律返回 <see cref="ReputationVerdict.Unknown"/>,绝不影响实时防护(fail-open)。
/// </summary>
public sealed class IpReputation
{
    /// <summary>被查询的资源(IPv4 点分十进制,或域名)。</summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>信誉判定。</summary>
    public ReputationVerdict Verdict { get; set; } = ReputationVerdict.Unknown;

    /// <summary>威胁标签 / 情报标签(如 "C2"、"Botnet"、"Zombie"),可空。</summary>
    public string? ThreatLabel { get; set; }

    /// <summary>置信度(0-100,情报源提供时填充;无则 0)。</summary>
    public int Confidence { get; set; }

    /// <summary>查询是否成功完成(可缓存)。false 表示失败/超时/超配额,应下次重试。</summary>
    public bool QuerySucceeded { get; set; }

    /// <summary>结论获取时间(UTC)。</summary>
    public System.DateTime FetchedUtc { get; set; } = System.DateTime.UtcNow;
}
