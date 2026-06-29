using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 进程链关联跟踪器。把孤立的安全事件按进程树聚合,使得对单个事件做研判时
/// 能拿到「同一攻击会话」的上下文(祖先进程做过什么、自己派生的子进程做过什么)。
///
/// 典型攻击链:winword.exe → powershell.exe(下载)→ dropper.exe(写 Temp)→ 改注册表启动项。
/// 单看每一步可能都不足以定性,串起来则是一次完整入侵。本类负责把这条链还原出来,
/// 交给 <see cref="ThreatDetector"/> / 大模型做整体判断。
///
/// 线程安全:所有公共方法用单锁串行化。事件量级为「需裁决/已处置事件」,非高频,
/// 单锁足够;并带容量上限与过期清理,避免长时间运行内存膨胀。
/// </summary>
public sealed class ProcessChainTracker
{
    private readonly object _gate = new();

    /// <summary>每个进程(PID)记录的事件,按时间升序。</summary>
    private readonly Dictionary<int, List<ChainEventInfo>> _byPid = new();

    /// <summary>子 PID -> 父 PID,用于向上回溯祖先链。</summary>
    private readonly Dictionary<int, int> _parent = new();

    /// <summary>记录每个 PID 的首次出现时间,用于过期清理。</summary>
    private readonly Dictionary<int, DateTime> _firstSeen = new();

    /// <summary>
    /// 最近被写入/落地的可执行文件路径(规范化小写)-> 写入时间(UTC)。
    /// 用于识别「释放器把 PE 写到磁盘后立即拉起」的 dropper 模式 —— 即便落地目录不可疑
    /// (如提权后写 Program Files),只要"刚被写出来就被执行",即视为可疑载荷需 AI 研判。
    /// </summary>
    private readonly Dictionary<string, DateTime> _recentExeWrites = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>被视为可执行/可加载的落地文件扩展名(命中才记入最近写入表)。</summary>
    private static readonly HashSet<string> ExecutableWriteExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv",
        ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".jar"
    };

    private readonly int _maxEventsPerPid;
    private readonly int _maxPids;
    private readonly TimeSpan _retention;

    public ProcessChainTracker(
        int maxEventsPerPid = 64,
        int maxPids = 4096,
        TimeSpan? retention = null)
    {
        _maxEventsPerPid = Math.Max(4, maxEventsPerPid);
        _maxPids = Math.Max(64, maxPids);
        _retention = retention ?? TimeSpan.FromMinutes(30);
    }

    /// <summary>
    /// 记录一个事件到进程链。会同时登记 PID→父 PID 映射(用于回溯祖先)。
    /// 应在事件被处理时调用(无论裁决结果如何)。
    /// </summary>
    public void Record(SecurityEvent e)
    {
        if (e is null || e.ActorPid <= 0) return;
        var info = ChainEventInfo.From(e);

        lock (_gate)
        {
            // 维护父子关系(以最近一次非零父 PID 为准)
            if (e.ParentPid > 0)
                _parent[e.ActorPid] = e.ParentPid;

            if (!_byPid.TryGetValue(e.ActorPid, out var list))
            {
                list = new List<ChainEventInfo>();
                _byPid[e.ActorPid] = list;
                _firstSeen[e.ActorPid] = DateTime.UtcNow;
            }

            list.Add(info);
            // 单进程事件上限:超出丢弃最旧的(保留最近行为)
            if (list.Count > _maxEventsPerPid)
                list.RemoveRange(0, list.Count - _maxEventsPerPid);

            // 记录"可执行文件落地":用于后续识别 dropper「写 PE → 立即执行」。
            if (e.Type == EventType.FileWrite
                && !string.IsNullOrEmpty(e.Target))
            {
                try
                {
                    var ext = System.IO.Path.GetExtension(e.Target);
                    if (!string.IsNullOrEmpty(ext) && ExecutableWriteExt.Contains(ext))
                        _recentExeWrites[NormalizePath(e.Target)] = DateTime.UtcNow;
                }
                catch { /* 路径异常忽略 */ }
            }

            EvictIfNeeded();
        }
    }

    /// <summary>
    /// 判断某可执行文件是否在最近 <paramref name="within"/> 时间窗内被(其他进程)写入/释放过。
    /// 用于识别 dropper:释放器把载荷写到磁盘后立即执行,该载荷的 ProcessCreate 命中此条件。
    /// </summary>
    public bool WasRecentlyWritten(string? path, TimeSpan within)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var key = NormalizePath(path);
        lock (_gate)
        {
            if (_recentExeWrites.TryGetValue(key, out var when))
                return DateTime.UtcNow - when <= within;
            return false;
        }
    }

    private static string NormalizePath(string path)
    {
        try { return System.IO.Path.GetFullPath(path).TrimEnd('\\').ToLowerInvariant(); }
        catch { return path.Trim().ToLowerInvariant(); }
    }

    /// <summary>
    /// 为某个事件构建进程链上下文:祖先链上的事件 + 自身事件 + 直接子进程的事件,
    /// 全部按时间升序合并去重,并截断到 <paramref name="maxEvents"/> 条(保留最近的)。
    /// 包含传入事件本身(即便它尚未 Record)。
    /// </summary>
    public List<ChainEventInfo> BuildContext(SecurityEvent e, int maxEvents = 12)
    {
        if (e is null) return new List<ChainEventInfo>();
        maxEvents = Math.Max(1, maxEvents);

        lock (_gate)
        {
            var pids = new HashSet<int>();
            if (e.ActorPid > 0) pids.Add(e.ActorPid);

            // 向上回溯祖先(防环:限制深度并记录已访问)
            int cur = e.ActorPid > 0 ? e.ActorPid : e.ParentPid;
            if (e.ParentPid > 0) pids.Add(e.ParentPid);
            int depth = 0;
            var visited = new HashSet<int>();
            while (cur > 0 && depth < 16 && visited.Add(cur))
            {
                if (_parent.TryGetValue(cur, out var p) && p > 0)
                {
                    pids.Add(p);
                    cur = p;
                }
                else break;
                depth++;
            }

            // 向下纳入直接子进程
            foreach (var kv in _parent)
            {
                if (e.ActorPid > 0 && kv.Value == e.ActorPid)
                    pids.Add(kv.Key);
            }

            var merged = new List<ChainEventInfo>();
            foreach (var pid in pids)
                if (_byPid.TryGetValue(pid, out var list))
                    merged.AddRange(list);

            // 纳入事件自带的链上下文(如事件源在富化时种入的「完整父进程祖先链」)。
            // 这保证即便跟踪器无历史记录(刚开机/首个事件),溯源链也完整。
            if (e.ChainContext is { Count: > 0 })
                merged.AddRange(e.ChainContext);

            // 把当前事件本身也纳入(它可能尚未被 Record)
            merged.Add(ChainEventInfo.From(e));

            // 去重(同 PID+类型+目标+时间戳视为同一条),按时间升序,保留最近 maxEvents 条
            var ordered = merged
                .GroupBy(c => (c.ActorPid, c.Type, c.Target, c.TimestampUtc))
                .Select(g => g.First())
                .OrderBy(c => c.TimestampUtc)
                .ToList();

            if (ordered.Count > maxEvents)
                ordered = ordered.GetRange(ordered.Count - maxEvents, maxEvents);

            return ordered;
        }
    }

    /// <summary>当前跟踪的进程数(用于诊断/测试)。</summary>
    public int TrackedProcessCount
    {
        get { lock (_gate) return _byPid.Count; }
    }

    /// <summary>
    /// 收集以 <paramref name="rootPid"/> 为根的整棵进程树(含自身与所有后代)曾记录的全部事件,
    /// 按时间升序返回。用于「确定恶意后的足迹清理」:据此删除其释放的文件、回退其写入的
    /// 注册表持久化项等。与 <see cref="BuildContext"/> 不同,这里不截断、不向上回溯祖先,
    /// 只向下纳入后代,聚焦「这个恶意进程及其子孙到底动过什么」。
    /// </summary>
    public List<ChainEventInfo> CollectTreeEvents(int rootPid)
    {
        var result = new List<ChainEventInfo>();
        if (rootPid <= 0) return result;

        lock (_gate)
        {
            // 广度优先纳入所有后代 PID(防环:已访问集合 + 迭代上限)。
            var pids = new HashSet<int> { rootPid };
            bool grew = true;
            int guard = 0;
            while (grew && guard++ < 64)
            {
                grew = false;
                foreach (var kv in _parent)
                {
                    if (pids.Contains(kv.Value) && pids.Add(kv.Key))
                        grew = true;
                }
            }

            foreach (var pid in pids)
                if (_byPid.TryGetValue(pid, out var list))
                    result.AddRange(list);
        }

        return result.OrderBy(c => c.TimestampUtc).ToList();
    }

    /// <summary>移除某进程的链记录(可在进程退出时调用,可选)。</summary>
    public void Forget(int pid)
    {
        lock (_gate)
        {
            _byPid.Remove(pid);
            _parent.Remove(pid);
            _firstSeen.Remove(pid);
        }
    }

    /// <summary>按保留期与容量上限清理过期/超量记录。需在持锁状态调用。</summary>
    private void EvictIfNeeded()
    {
        var now = DateTime.UtcNow;

        // 1) 过期清理
        if (_firstSeen.Count > 0)
        {
            List<int>? expired = null;
            foreach (var kv in _firstSeen)
            {
                if (now - kv.Value > _retention)
                    (expired ??= new List<int>()).Add(kv.Key);
            }
            if (expired is not null)
                foreach (var pid in expired) RemovePid(pid);
        }

        // 2) 容量上限:超出则按首次出现时间淘汰最旧
        if (_byPid.Count > _maxPids)
        {
            var oldest = _firstSeen.OrderBy(kv => kv.Value)
                .Take(_byPid.Count - _maxPids)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var pid in oldest) RemovePid(pid);
        }

        // 3) 最近写入表:清理超过保留期的条目,并限制总量(防膨胀)。
        if (_recentExeWrites.Count > 0)
        {
            List<string>? staleWrites = null;
            foreach (var kv in _recentExeWrites)
            {
                if (now - kv.Value > _retention)
                    (staleWrites ??= new List<string>()).Add(kv.Key);
            }
            if (staleWrites is not null)
                foreach (var k in staleWrites) _recentExeWrites.Remove(k);

            // 仍超量则按时间淘汰最旧。
            if (_recentExeWrites.Count > _maxPids)
            {
                var drop = _recentExeWrites.OrderBy(kv => kv.Value)
                    .Take(_recentExeWrites.Count - _maxPids)
                    .Select(kv => kv.Key)
                    .ToList();
                foreach (var k in drop) _recentExeWrites.Remove(k);
            }
        }
    }

    private void RemovePid(int pid)
    {
        _byPid.Remove(pid);
        _parent.Remove(pid);
        _firstSeen.Remove(pid);
    }
}
