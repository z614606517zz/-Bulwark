using System.Collections.Concurrent;
using System.Text.Json;
using Bulwark.Core.Models;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 文件信誉缓存(按 SHA-256)。内存字典 + 落盘持久化(JSONL,每行一条记录)。
/// 进程重启不丢,使"VT 慢查一次,之后永远命中本地"成为可能。
///
/// 缓存策略(分级 TTL):
///  - 恶意结论:永久有效(恶意不会变干净)。
///  - 干净结论:带 TTL(默认 7 天)。
///  - 可疑结论:独立较短 TTL(默认 ≤1 天),更快重新校验(可疑更易升级为已知恶意)。
///  - Unknown(VT 未收录/查询失败):短期负缓存(默认 1 天),避免对同一文件反复浪费配额。
///
/// 离线兜底:<see cref="TryGetForEnrichment"/> 在 TTL 过期后仍返回最近一次的干净/可疑/恶意结论,
/// 使断网时富化仍可用「上一次已知信誉」;新鲜度由 <see cref="TryGet"/> 驱动的后台重查负责。
///
/// 持久化于 %ProgramData%\Bulwark\reputation.jsonl。线程安全。
/// </summary>
public sealed class ReputationCache
{
    private readonly string _path;
    private readonly ConcurrentDictionary<string, FileReputation> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly object _writeLock = new();
    private readonly TimeSpan _cleanTtl;

    /// <summary>可疑结论的有效期。通常应短于干净结论 —— 可疑样本更可能在短期内升级为已知恶意。</summary>
    private readonly TimeSpan _suspiciousTtl;

    /// <summary>Unknown(未收录/查询失败)结论的负缓存有效期。避免反复查同一未收录文件。</summary>
    private readonly TimeSpan _unknownTtl;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public ReputationCache(TimeSpan cleanTtl, TimeSpan? unknownTtl = null, TimeSpan? suspiciousTtl = null)
    {
        _cleanTtl = cleanTtl;
        _unknownTtl = unknownTtl ?? TimeSpan.FromDays(1);
        // 默认取干净 TTL 与 1 天中的较小值:可疑不应比干净缓存得更久。
        _suspiciousTtl = suspiciousTtl ?? (cleanTtl < TimeSpan.FromDays(1) ? cleanTtl : TimeSpan.FromDays(1));
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "reputation.jsonl");
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            foreach (var line in File.ReadLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var rep = JsonSerializer.Deserialize<FileReputation>(line, Json);
                    if (rep is not null && !string.IsNullOrEmpty(rep.Sha256))
                        _cache[rep.Sha256] = rep; // 后写覆盖先写(最新结论生效)
                }
                catch { /* 跳过损坏行 */ }
            }
        }
        catch { /* 首次运行 / 读取失败:视为空 */ }
    }

    /// <summary>
    /// 查缓存。命中且未过期返回结论;未命中或已过期返回 null(调用方据此决定是否查 VT)。
    /// </summary>
    public FileReputation? TryGet(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return null;
        if (!_cache.TryGetValue(sha256, out var rep)) return null;

        // 恶意结论永久有效。
        if (rep.Verdict == ReputationVerdict.Malicious) return rep;

        // Unknown(未收录/失败):负缓存,按较短 TTL 过期。
        if (rep.Verdict == ReputationVerdict.Unknown)
            return (DateTime.UtcNow - rep.FetchedUtc > _unknownTtl) ? null : rep;

        // 可疑结论按其独立(较短)TTL 过期。
        if (rep.Verdict == ReputationVerdict.Suspicious)
            return (DateTime.UtcNow - rep.FetchedUtc > _suspiciousTtl) ? null : rep;

        // 干净结论按 TTL 过期。
        if (DateTime.UtcNow - rep.FetchedUtc > _cleanTtl) return null;

        return rep;
    }

    /// <summary>
    /// 富化专用读取(同步裁决路径):返回「最近一次已知结论」,即便已过 TTL 也照返(陈旧兜底)。
    ///
    /// 理由:信誉只是「锦上添花」的加/减分,绝不单独处置;断网或查询失败时,用上一次的
    /// 干净/可疑/恶意结论富化,远好于退回「完全无信息」。新鲜度由 <see cref="TryGet"/>
    /// 驱动的后台重查负责刷新 —— 二者分工:这里保证可用性,那里保证新鲜度。
    /// Unknown(本就是「无信息」)不做陈旧兜底,返回 null。
    /// </summary>
    public FileReputation? TryGetForEnrichment(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return null;
        if (!_cache.TryGetValue(sha256, out var rep)) return null;
        return rep.Verdict == ReputationVerdict.Unknown ? null : rep;
    }

    /// <summary>
    /// 写入一条信誉结论并落盘。仅缓存"查询成功"的权威结果
    /// (含收录检测结论,以及 VT 明确未收录的 404 负结果);
    /// 查询失败(TLS/网络/超时/鉴权/限流/解析异常,QuerySucceeded=false)的结果一律不缓存,
    /// 以便下次重新查询。
    /// </summary>
    public void Store(FileReputation rep)
    {
        if (rep is null || string.IsNullOrEmpty(rep.Sha256)) return;

        // 查询失败的结果不缓存——避免一次失败就长时间不再重试。
        if (!rep.QuerySucceeded) return;

        _cache[rep.Sha256] = rep;
        try
        {
            var line = JsonSerializer.Serialize(rep, Json);
            lock (_writeLock)
            {
                File.AppendAllText(_path, line + Environment.NewLine);
            }
        }
        catch { /* 落盘失败不影响内存缓存 */ }
    }
}
