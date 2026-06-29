using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 勒索行为监视器(独创·有状态时序检测)。
///
/// 勒索软件的本质特征不是某个文件或签名,而是**短时间内对大量文件的批量改写**,
/// 并伴随扩展名同化(全改成 .locked/.crypt 等)、写入勒索信、触碰诱饵文件。
/// 单次"文件写入"事件无害,但把同一进程在滑动时间窗内的行为聚合起来,
/// 高速批量改写 + 扩展名同化就是勒索的强信号 —— 这是签名/规则无法捕捉的。
///
/// 本监视器为每个进程维护一个滑动窗口状态,实时统计:
///   · 改写速率(窗口内不同文件数 / 秒);
///   · 扩展名同化(大量文件被改成同一可疑新扩展名);
///   · 蜜罐诱饵触碰(改写了部署在常见目录的诱饵文件 —— 几乎可确认勒索);
///   · 勒索信写入(同名说明文件在多个目录重复出现)。
///
/// 命中后返回 (score, reasons, canaryHit)。canaryHit 为 true 时调用方应直接 Block。
/// 线程安全:单锁串行化。带容量上限与过期清理,防内存膨胀。
/// </summary>
public sealed class RansomwareBehaviorMonitor
{
    private readonly object _gate = new();
    private readonly Dictionary<int, ProcState> _byPid = new();
    private readonly TimeSpan _window;
    private readonly int _maxPids;

    /// <summary>滑动窗口内"改写文件数"达到此值即判定为批量改写。</summary>
    private readonly int _burstThreshold;

    /// <summary>蜜罐诱饵文件名(小写,可由宿主注入实际部署的诱饵路径)。</summary>
    private readonly HashSet<string> _canaryPaths =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 常被勒索软件写入的"勒索信"文件名片段。
    /// 仅保留**高特异性**短语,剔除 "unlock" / "ransom" / "!!!" / 裸 "readme" 等
    /// 会与正常文件(README、解锁说明、版本说明)冲突的泛化词,避免误报。
    /// </summary>
    private static readonly string[] RansomNoteHints =
    {
        "how_to_decrypt", "how-to-decrypt", "how_to_recover", "how-to-recover",
        "recover_files", "recover-files", "recover_your_files",
        "decrypt_instruction", "decryption_instruction", "restore_files",
        "restore-my-files", "readme_for_decrypt", "files_encrypted",
        "your_files_are_encrypted", "decrypt-files", "_openme", "_help_decrypt"
    };

    /// <summary>典型加密后扩展名(同化特征)。空集合时只看"同一扩展名的数量突增"。</summary>
    private static readonly string[] KnownEncryptedExts =
    {
        ".locked", ".crypt", ".crypted", ".encrypted", ".enc", ".lock",
        ".wcry", ".wncry", ".locky", ".cerber", ".zepto", ".odin",
        ".aaa", ".xtbl", ".ecc", ".kkk", ".micro", ".ttt", ".pzdc"
    };

    public RansomwareBehaviorMonitor(
        TimeSpan? window = null,
        int burstThreshold = 12,
        int maxPids = 2048)
    {
        _window = window ?? TimeSpan.FromSeconds(10);
        _burstThreshold = Math.Max(5, burstThreshold);
        _maxPids = Math.Max(64, maxPids);
    }

    /// <summary>注册一个蜜罐诱饵文件路径。触碰这些文件几乎可确认为勒索行为。</summary>
    public void AddCanaryFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        lock (_gate) _canaryPaths.Add(path.Trim().ToLowerInvariant().Replace('/', '\\'));
    }

    /// <summary>
    /// 观测一个文件写入/删除事件并更新进程状态,返回当前研判结论。
    /// 仅对 <see cref="EventType.FileWrite"/> / <see cref="EventType.FileDelete"/> 有意义,
    /// 其它事件类型直接返回 0 分。
    /// </summary>
    public (int Score, List<string> Reasons, bool CanaryHit, bool HardSignal) Observe(SecurityEvent e)
    {
        var reasons = new List<string>();
        if (e is null || e.ActorPid <= 0)
            return (0, reasons, false, false);
        if (e.Type != EventType.FileWrite && e.Type != EventType.FileDelete)
            return (0, reasons, false, false);

        string target = (e.Target ?? string.Empty).ToLowerInvariant().Replace('/', '\\');
        if (string.IsNullOrEmpty(target))
            return (0, reasons, false, false);

        var now = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc;
        int score = 0;
        // "加密确证"信号:已知勒索扩展名批量产生 / 勒索信写入 / 蜜罐触碰。
        // 仅有"高速批量改写""未知扩展名同化"等软信号时保持 false,避免误伤浏览器/同步盘/编译器。
        bool hardSignal = false;

        lock (_gate)
        {
            // 0) 蜜罐诱饵触碰 —— 最强信号,优先判定
            if (_canaryPaths.Contains(target))
            {
                reasons.Add("触碰蜜罐诱饵文件(几乎可确认勒索/批量加密)");
                return (100, reasons, true, true);
            }

            if (!_byPid.TryGetValue(e.ActorPid, out var st))
            {
                st = new ProcState();
                _byPid[e.ActorPid] = st;
            }

            st.LastActivityUtc = now;
            st.Touch(target, now, _window);

            // 1) 批量改写速率(O(1):窗口内不同文件数由增量计数器维护)
            int distinct = st.DistinctFilesInWindow();
            if (distinct >= _burstThreshold)
            {
                int over = distinct - _burstThreshold;
                score += 30 + Math.Min(over, 20) * 2;
                reasons.Add($"{_window.TotalSeconds:0}秒内批量改写 {distinct} 个文件(疑似勒索加密)");
            }

            // 2) 扩展名同化:窗口内大量文件被改成同一新扩展名
            string ext = SafeExt(target);
            if (!string.IsNullOrEmpty(ext))
            {
                bool knownBad = KnownEncryptedExts.Contains(ext);
                int sameExt = st.SameExtensionCount(ext);
                if (knownBad && sameExt >= 3)
                {
                    score += 40;
                    hardSignal = true;
                    reasons.Add($"批量产生已知勒索扩展名 {ext}(×{sameExt})");
                }
                else if (sameExt >= Math.Max(8, _burstThreshold))
                {
                    score += 25;
                    reasons.Add($"扩展名同化:大量文件统一为 {ext}(×{sameExt},疑似加密)");
                }
            }

            // 3) 勒索信写入
            string fileName = SafeFileName(target);
            if (RansomNoteHints.Any(h => fileName.Contains(h)))
            {
                st.RansomNoteCount++;
                score += 20;
                hardSignal = true;
                reasons.Add($"写入疑似勒索说明文件({fileName})");
                if (st.RansomNoteCount >= 3)
                {
                    score += 25;
                    reasons.Add($"在多处写入勒索信(×{st.RansomNoteCount},强勒索特征)");
                }
            }

            EvictIfNeeded(now);
        }

        return (Math.Min(score, 100), reasons, false, hardSignal);
    }

    /// <summary>进程退出时清理其状态(可选)。</summary>
    public void Forget(int pid)
    {
        lock (_gate) _byPid.Remove(pid);
    }

    /// <summary>当前跟踪进程数(诊断/测试用)。</summary>
    public int TrackedProcessCount
    {
        get { lock (_gate) return _byPid.Count; }
    }

    private void EvictIfNeeded(DateTime now)
    {
        // 过期清理:超过 2 个窗口无活动的进程移除
        var stale = now - TimeSpan.FromTicks(_window.Ticks * 4);
        List<int>? dead = null;
        foreach (var kv in _byPid)
            if (kv.Value.LastActivityUtc < stale)
                (dead ??= new List<int>()).Add(kv.Key);
        if (dead is not null)
            foreach (var pid in dead) _byPid.Remove(pid);

        // 容量上限:淘汰最久未活动者
        if (_byPid.Count > _maxPids)
        {
            var oldest = _byPid.OrderBy(kv => kv.Value.LastActivityUtc)
                .Take(_byPid.Count - _maxPids)
                .Select(kv => kv.Key).ToList();
            foreach (var pid in oldest) _byPid.Remove(pid);
        }
    }

    private static string SafeExt(string path)
    {
        try { return Path.GetExtension(path).ToLowerInvariant(); }
        catch { return string.Empty; }
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path; }
    }

    /// <summary>单进程的滑动窗口状态。</summary>
    private sealed class ProcState
    {
        public DateTime LastActivityUtc;
        public int RansomNoteCount;

        // (文件路径, 时间, 扩展名) 的最近写入记录,按时间升序;过期自动裁剪。
        private readonly List<(string Path, DateTime At, string Ext)> _writes = new();

        // 增量计数器(随 _writes 的增删同步维护),使窗口内统计为 O(1):
        //   _pathOccur:窗口内每个文件路径的出现次数 —— 不同文件数 = 键数;
        //   _extPaths :扩展名 -> (该扩展名下每个文件路径的出现次数)—— 同扩展名文件数 = 内层键数。
        // 旧实现每个事件都对 _writes 做 LINQ Distinct 全扫,勒索瞬时改写成百上千文件时
        // 退化为 O(n²) —— 恰在最需要快速响应时变慢。改为增量维护后,Observe 全程 O(1) 摊还。
        private readonly Dictionary<string, int> _pathOccur = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Dictionary<string, int>> _extPaths =
            new(StringComparer.OrdinalIgnoreCase);

        public void Touch(string path, DateTime at, TimeSpan window)
        {
            string ext = SafeExtOf(path);
            _writes.Add((path, at, ext));
            AddCounts(path, ext);

            // 裁剪窗口外的旧记录(只保留最近 window 内的;同时设硬上限),同步回退计数器。
            var cutoff = at - window;
            int i = 0;
            while (i < _writes.Count && _writes[i].At < cutoff)
            {
                RemoveCounts(_writes[i].Path, _writes[i].Ext);
                i++;
            }
            if (i > 0) _writes.RemoveRange(0, i);

            const int hardCap = 4096;
            if (_writes.Count > hardCap)
            {
                int excess = _writes.Count - hardCap;
                for (int k = 0; k < excess; k++)
                    RemoveCounts(_writes[k].Path, _writes[k].Ext);
                _writes.RemoveRange(0, excess);
            }
        }

        /// <summary>窗口内不同文件数(O(1))。</summary>
        public int DistinctFilesInWindow() => _pathOccur.Count;

        /// <summary>窗口内被改成指定扩展名的不同文件数(O(1))。</summary>
        public int SameExtensionCount(string ext)
            => _extPaths.TryGetValue(ext, out var m) ? m.Count : 0;

        private void AddCounts(string path, string ext)
        {
            _pathOccur[path] = _pathOccur.TryGetValue(path, out var n) ? n + 1 : 1;
            if (string.IsNullOrEmpty(ext)) return;
            if (!_extPaths.TryGetValue(ext, out var m))
                _extPaths[ext] = m = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            m[path] = m.TryGetValue(path, out var k) ? k + 1 : 1;
        }

        private void RemoveCounts(string path, string ext)
        {
            if (_pathOccur.TryGetValue(path, out var n))
            {
                if (n <= 1) _pathOccur.Remove(path);
                else _pathOccur[path] = n - 1;
            }
            if (string.IsNullOrEmpty(ext)) return;
            if (_extPaths.TryGetValue(ext, out var m))
            {
                if (m.TryGetValue(path, out var k))
                {
                    if (k <= 1) m.Remove(path);
                    else m[path] = k - 1;
                }
                if (m.Count == 0) _extPaths.Remove(ext);
            }
        }

        private static string SafeExtOf(string path)
        {
            try { return Path.GetExtension(path).ToLowerInvariant(); }
            catch { return string.Empty; }
        }
    }
}
