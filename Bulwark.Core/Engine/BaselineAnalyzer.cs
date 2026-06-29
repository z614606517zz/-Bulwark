using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 行为基线 / 异常检测器(独创·有状态画像)。
///
/// 现有检测多为「规则 / 特征 / 时序」驱动:它们描述"什么样的行为是坏的"。
/// 本分析器换一个角度 —— 为每个程序建立**正常行为画像(基线)**,描述"这个程序平时怎么做",
/// 当它出现**显著偏离自身历史**的行为时升分。三个维度:
///   · 子进程:某程序平时派生哪些子进程(按子进程映像名);
///   · 外联目标:某程序平时连向哪些远端主机;
///   · 写入目录:某程序平时往哪些目录写文件。
///
/// 典型价值:一个一直只连自家更新服务器的程序,某天突然连向陌生主机并派生 powershell,
/// 即便单看每一步都不命中硬规则,"偏离自身基线"也是有意义的可疑信号(被劫持 / 被注入 /
/// 供应链投毒 / DLL 侧载后行为突变)。
///
/// 严守全局低误报原则:
///   1) **学习期**:某维度观测次数未达 <see cref="MinObservationsToEstablish"/> 前只学习、不评分;
///   2) 偏离基线产出的恒为**软信号**(SoftSignal),<b>单独绝不</b>置位
///      <see cref="SecurityEvent.HasThreatIndicator"/> 或直接处置,仅累加 RiskScore,
///      需与硬指标互证后由调用方升格;
///   3) **高基数豁免**:浏览器 / 下载器这类天然连接/派生海量不同目标的程序,基数超过
///      <see cref="PromiscuousThreshold"/> 后停止对该维度评分,避免持续误报。
///
/// 状态可通过 <see cref="Export"/> / <see cref="Import"/> 快照持久化,跨重启保留画像。
/// 线程安全:单锁串行化,带容量 / 过期治理。
/// </summary>
public sealed class BaselineAnalyzer
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Profile> _profiles = new(StringComparer.OrdinalIgnoreCase);

    private readonly int _minObs;
    private readonly int _promiscuous;
    private readonly int _maxProfiles;
    private readonly int _maxSetSize;

    /// <summary>某维度达到此观测次数后才视为「基线已建立」,之前只学习不评分。</summary>
    public int MinObservationsToEstablish => _minObs;

    /// <summary>某维度的已知集合大小超过此值视为「高基数(promiscuous)」,停止对该维度评分。</summary>
    public int PromiscuousThreshold => _promiscuous;

    public BaselineAnalyzer(
        int minObservationsToEstablish = 12,
        int promiscuousThreshold = 60,
        int maxProfiles = 8192,
        int maxSetSize = 256)
    {
        _minObs = Math.Max(4, minObservationsToEstablish);
        _promiscuous = Math.Max(16, promiscuousThreshold);
        _maxProfiles = Math.Max(128, maxProfiles);
        _maxSetSize = Math.Max(32, maxSetSize);
    }

    /// <summary>
    /// 观测一个事件,更新对应程序画像并研判是否偏离基线。
    /// 返回 (Score, Reasons, IsDeviation)。Score 永远是软信号贡献,调用方决定证据类别 / 是否升格。
    /// 对无法归因到稳定程序身份的事件(空路径等)返回零分。
    /// </summary>
    public (int Score, List<string> Reasons, bool IsDeviation) Observe(SecurityEvent e)
    {
        var reasons = new List<string>();
        if (e is null) return (0, reasons, false);

        var now = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc;

        switch (e.Type)
        {
            case EventType.ProcessCreate:
            {
                // 子进程派生:画像归属于「父进程」,记录的值是「子进程映像名」。
                string parent = NormalizeProgram(e.ParentPath);
                string child = SafeName(e.ActorPath);
                if (parent.Length == 0 || child.Length == 0) return (0, reasons, false);
                return Score(parent, Dim.Child, child, now,
                    deviationScore: 20,
                    deviationText: $"程序 {ShortName(parent)} 首次派生子进程 {child}(偏离历史行为基线)");
            }
            case EventType.NetworkConnect:
            {
                string actor = NormalizeProgram(e.ActorPath);
                string host = NormalizeRemote(e.Target);
                if (actor.Length == 0 || host.Length == 0 || host == "?") return (0, reasons, false);
                return Score(actor, Dim.Host, host, now,
                    deviationScore: 15,
                    deviationText: $"程序 {ShortName(actor)} 首次外联到 {host}(偏离历史外联基线)");
            }
            case EventType.FileWrite:
            case EventType.FileDelete:
            {
                string actor = NormalizeProgram(e.ActorPath);
                string dir = DirOf(e.Target);
                if (actor.Length == 0 || dir.Length == 0) return (0, reasons, false);
                return Score(actor, Dim.WriteDir, dir, now,
                    deviationScore: 12,
                    deviationText: $"程序 {ShortName(actor)} 首次写入目录 {dir}(偏离历史写入基线)");
            }
            default:
                return (0, reasons, false);
        }
    }

    private (int Score, List<string> Reasons, bool IsDeviation) Score(
        string programKey, Dim dim, string value, DateTime now, int deviationScore, string deviationText)
    {
        var reasons = new List<string>();
        lock (_gate)
        {
            if (!_profiles.TryGetValue(programKey, out var p))
            {
                p = new Profile { FirstSeenUtc = now };
                _profiles[programKey] = p;
            }
            p.LastSeenUtc = now;

            var set = p.SetFor(dim);
            int obs = p.ObsFor(dim);
            bool established = obs >= _minObs;
            bool promiscuous = set.Count >= _promiscuous;
            bool known = set.Contains(value);

            // 学习:计数 +1,加入已知集合(带容量上限,避免无界膨胀)。
            p.IncObs(dim);
            if (!known && set.Count < _maxSetSize) set.Add(value);

            EvictIfNeeded(now);

            // 评分前置条件:基线已建立、非高基数程序、且本次是「新值」。
            if (!established || promiscuous || known)
                return (0, reasons, false);

            reasons.Add(deviationText);
            return (Math.Min(deviationScore, 100), reasons, true);
        }
    }

    /// <summary>进程退出时无需清理:画像按程序身份(路径)而非 PID 聚合,跨进程实例累积。</summary>
    public int TrackedProgramCount
    {
        get { lock (_gate) return _profiles.Count; }
    }

    private void EvictIfNeeded(DateTime now)
    {
        if (_profiles.Count <= _maxProfiles) return;
        var oldest = _profiles.OrderBy(kv => kv.Value.LastSeenUtc)
            .Take(_profiles.Count - _maxProfiles)
            .Select(kv => kv.Key).ToList();
        foreach (var k in oldest) _profiles.Remove(k);
    }

    // ===== 持久化快照 =====

    /// <summary>导出当前所有画像为可序列化快照(供宿主落盘)。</summary>
    public BaselineSnapshot Export()
    {
        lock (_gate)
        {
            return new BaselineSnapshot
            {
                Programs = _profiles.Select(kv => new BaselineProgram
                {
                    Key = kv.Key,
                    FirstSeenUtc = kv.Value.FirstSeenUtc,
                    LastSeenUtc = kv.Value.LastSeenUtc,
                    ChildObs = kv.Value.ChildObs,
                    HostObs = kv.Value.HostObs,
                    WriteObs = kv.Value.WriteObs,
                    Children = kv.Value.Children.ToList(),
                    Hosts = kv.Value.Hosts.ToList(),
                    WriteDirs = kv.Value.WriteDirs.ToList(),
                }).ToList()
            };
        }
    }

    /// <summary>从快照恢复画像(覆盖当前状态)。容错:空快照 / 空字段安全跳过。</summary>
    public void Import(BaselineSnapshot? snapshot)
    {
        if (snapshot?.Programs is null) return;
        lock (_gate)
        {
            _profiles.Clear();
            foreach (var prog in snapshot.Programs)
            {
                if (string.IsNullOrEmpty(prog.Key)) continue;
                var p = new Profile
                {
                    FirstSeenUtc = prog.FirstSeenUtc == default ? DateTime.UtcNow : prog.FirstSeenUtc,
                    LastSeenUtc = prog.LastSeenUtc == default ? DateTime.UtcNow : prog.LastSeenUtc,
                    ChildObs = Math.Max(0, prog.ChildObs),
                    HostObs = Math.Max(0, prog.HostObs),
                    WriteObs = Math.Max(0, prog.WriteObs),
                };
                if (prog.Children is not null) foreach (var c in prog.Children) p.Children.Add(c);
                if (prog.Hosts is not null) foreach (var h in prog.Hosts) p.Hosts.Add(h);
                if (prog.WriteDirs is not null) foreach (var d in prog.WriteDirs) p.WriteDirs.Add(d);
                _profiles[prog.Key] = p;
            }
        }
    }

    // ===== 归一化辅助 =====

    private static string NormalizeProgram(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        return path.Trim().ToLowerInvariant().Replace('/', '\\');
    }

    private static string ShortName(string programKey)
    {
        try { return System.IO.Path.GetFileName(programKey); }
        catch { return programKey; }
    }

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }

    private static string DirOf(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return string.Empty;
        try
        {
            var dir = System.IO.Path.GetDirectoryName(target.Trim());
            if (string.IsNullOrEmpty(dir)) return string.Empty;
            return dir.ToLowerInvariant().Replace('/', '\\');
        }
        catch { return string.Empty; }
    }

    private static string NormalizeRemote(string? target)
    {
        if (string.IsNullOrEmpty(target)) return "?";
        var t = target.Trim().ToLowerInvariant();
        int colon = t.LastIndexOf(':');
        if (colon > 0 && colon < t.Length - 1 && t.Skip(colon + 1).All(char.IsDigit))
            t = t.Substring(0, colon);
        return t;
    }

    private enum Dim { Child, Host, WriteDir }

    /// <summary>单个程序的行为画像。</summary>
    private sealed class Profile
    {
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public int ChildObs;
        public int HostObs;
        public int WriteObs;
        public readonly HashSet<string> Children = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> WriteDirs = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> SetFor(Dim d) => d switch
        {
            Dim.Child => Children,
            Dim.Host => Hosts,
            _ => WriteDirs
        };

        public int ObsFor(Dim d) => d switch
        {
            Dim.Child => ChildObs,
            Dim.Host => HostObs,
            _ => WriteObs
        };

        public void IncObs(Dim d)
        {
            switch (d)
            {
                case Dim.Child: ChildObs++; break;
                case Dim.Host: HostObs++; break;
                default: WriteObs++; break;
            }
        }
    }
}

/// <summary>行为基线持久化快照(整体)。</summary>
public sealed class BaselineSnapshot
{
    public List<BaselineProgram> Programs { get; set; } = new();
}

/// <summary>单个程序画像的可序列化形态。</summary>
public sealed class BaselineProgram
{
    public string Key { get; set; } = string.Empty;
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int ChildObs { get; set; }
    public int HostObs { get; set; }
    public int WriteObs { get; set; }
    public List<string> Children { get; set; } = new();
    public List<string> Hosts { get; set; } = new();
    public List<string> WriteDirs { get; set; } = new();
}
