using System;

namespace Bulwark.Core.Models;

/// <summary>
/// 一条持久化的防护规则。引擎按多个可选条件(全部满足才命中)匹配事件:
/// 主体(精确或通配)、事件类型、目标、命令行、父进程、是否未签名。
/// 未设置的条件视为「任意」。
/// </summary>
public sealed class DefenseRule
{
    /// <summary>「文件信任中心」生成的放行规则,其备注以此标记开头,便于与普通/内置规则区分。</summary>
    public const string TrustNoteTag = "[信任]";

    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>匹配的主体进程路径(精确,大小写不敏感)。为空表示不限。</summary>
    public string? ActorPath { get; set; }

    /// <summary>匹配的主体进程路径/名(通配符 *)。为空表示不限。比 ActorPath 灵活。</summary>
    public string? ActorPattern { get; set; }

    /// <summary>匹配的事件类型。null 表示匹配所有类型。</summary>
    public EventType? Type { get; set; }

    /// <summary>目标匹配模式(通配符 *)。为空表示不限。例:"*\\CurrentVersion\\Run\\*"。</summary>
    public string? TargetPattern { get; set; }

    /// <summary>命令行匹配模式(通配符 *,大小写不敏感)。为空表示不限。例:"*-enc *"。</summary>
    public string? CommandLinePattern { get; set; }

    /// <summary>父进程路径/名匹配模式(通配符 *)。为空表示不限。例:"*\\winword.exe"。</summary>
    public string? ParentPattern { get; set; }

    /// <summary>为 true 时,仅当主体「无可信签名」才命中(降低对合法签名程序的误伤)。</summary>
    public bool RequireUnsigned { get; set; }

    /// <summary>
    /// 为 true 时,本规则命中后可被「强可信操作系统组件」豁免(由引擎在命中后判定):
    /// 当主体是微软签名 + 系统目录、签名健康、无任何硬恶意指标、且不是脚本宿主/LOLBin
    /// (reg/powershell/cmd/rundll32 等)时,放行而不弹窗。
    ///
    /// 仅用于「敏感但合法 OS 组件也会做」的 Ask 级规则(如调整/重置 UAC 提权确认级别,
    /// 由 RuntimeBroker/设置中心等触发)。绝不可用于 Block 级硬恶意规则(如关闭 UAC/Defender)。
    /// 引擎在判定豁免时已显式排除 LOLBin,防止「恶意脚本借 reg.exe 改 UAC」被误放行。
    /// </summary>
    public bool ExemptTrustedOsComponent { get; set; }

    /// <summary>
    /// 「确定性恶意」硬拦截规则标记。置 true 时,该规则在引擎排序中享有最高优先级:
    /// 即便存在更「具体」的灰区规则(如按 Temp 路径命中的 Ask),也不会把它降级。
    /// 适用于正常软件几乎从不触发、命中即可确认恶意的模式 ——
    /// 双扩展名伪装(.pdf.exe)、回收站启动、BYOVD 脆弱驱动、IFEO 登录后门等。
    ///
    /// 注意:用户为某程序新增的「精确加白」规则(指定了 <see cref="ActorPath"/> 或 ActorHashes)
    /// 仍优先于本标记,确保用户可信任覆盖始终生效,不会被内置硬拦截规则挡住。
    /// </summary>
    public bool HardOverride { get; set; }

    /// <summary>
    /// 哈希黑/白名单(SHA-256,大写十六进制)。非空时,事件的 <see cref="SecurityEvent.ActorHash"/>
    /// 必须在此集合内才命中。用于 BYOVD 脆弱驱动按哈希拦截(改名规避无效),
    /// 以及精确锁定已知样本。大小写不敏感。
    /// </summary>
    public System.Collections.Generic.HashSet<string>? ActorHashes { get; set; }

    /// <summary>命中后执行的动作(仅 Allow/Block)。</summary>
    public VerdictAction Action { get; set; }

    /// <summary>规则备注/来源说明(如内置规则的用途、对应的攻击手法)。</summary>
    public string? Note { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 规则到期时间(UTC)。null = 永久有效。到期后不再命中(并由存储在保存/加载时清理)。
    /// 用于「临时放行/拦截 N 分钟/小时」,降低「记住」产生永久误放行的风险。
    /// </summary>
    public DateTime? ExpiresUtc { get; set; }

    /// <summary>
    /// 仅本次服务会话有效:不持久化到磁盘,服务重启即失效。
    /// 用于「这一次先放行,别永久记住」。与 <see cref="ExpiresUtc"/> 可叠加。
    /// </summary>
    public bool SessionOnly { get; set; }

    /// <summary>规则是否启用。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>规则是否已到期(到期即视为失效,不参与匹配)。</summary>
    public bool IsExpired(DateTime nowUtc) => ExpiresUtc is { } exp && exp <= nowUtc;

    /// <summary>是否为「文件信任中心」生成的信任规则。</summary>
    public bool IsTrustEntry => !string.IsNullOrEmpty(Note)
        && Note.StartsWith(TrustNoteTag, StringComparison.Ordinal);

    /// <summary>
    /// 创建一条「文件信任」规则:命中后该文件(主体)的所有行为一律放行,不再弹窗。
    /// 通过 <see cref="ActorPath"/> 精确锁定文件;Type 为 null 表示对所有事件类型生效。
    /// </summary>
    public static DefenseRule CreateTrust(string actorPath, string? note = null) => new()
    {
        ActorPath = actorPath?.Trim(),
        Type = null,
        Action = VerdictAction.Allow,
        Note = string.IsNullOrWhiteSpace(note)
            ? $"{TrustNoteTag} 文件信任中心"
            : $"{TrustNoteTag} {note.Trim()}"
    };

    /// <summary>判断事件是否命中此规则(所有已设置条件均需满足)。</summary>
    public bool Matches(SecurityEvent e)
    {
        if (!Enabled) return false;

        // 到期规则视为失效,不再命中(存储侧也会清理,这里是运行时兜底)。
        if (ExpiresUtc is { } exp && exp <= DateTime.UtcNow) return false;

        if (Type.HasValue && Type.Value != e.Type) return false;

        if (RequireUnsigned && e.ActorSigned) return false;

        if (ActorHashes is { Count: > 0 })
        {
            if (string.IsNullOrEmpty(e.ActorHash) || !ActorHashes.Contains(e.ActorHash))
                return false;
        }

        if (!string.IsNullOrEmpty(ActorPath) &&
            !string.Equals(ActorPath, e.ActorPath, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrEmpty(ActorPattern) &&
            !WildcardMatch(ActorPattern, e.ActorPath))
            return false;

        if (!string.IsNullOrEmpty(CommandLinePattern) &&
            !WildcardMatch(CommandLinePattern, e.CommandLine ?? string.Empty))
            return false;

        if (!string.IsNullOrEmpty(ParentPattern) &&
            !WildcardMatch(ParentPattern, e.ParentPath ?? string.Empty))
            return false;

        if (!string.IsNullOrEmpty(TargetPattern))
        {
            bool matchTarget = WildcardMatch(TargetPattern, e.Target);

            // 仅对进程创建事件,允许 TargetPattern 回退匹配主体路径:
            // ProcessCreate 的 Target 往往只是进程名,完整路径在 ActorPath,
            // 故两者都试一次以提升命中率。
            //
            // 但对于「主体与目标是两个不同真实进程」的事件(远程线程注入 RemoteThread、
            // 结束进程 ProcessTerminate),绝不能把 TargetPattern 套到主体上 ——
            // 否则像「向 svchost 注入」这类按受害进程书写的规则会错误命中
            // 「svchost 作为发起方」的正常系统行为(如 svchost 拉起 WerFault),造成误报。
            bool allowActorFallback = e.Type == EventType.ProcessCreate;
            bool matchActor = allowActorFallback &&
                              !string.IsNullOrEmpty(e.ActorPath) &&
                              WildcardMatch(TargetPattern, e.ActorPath);

            if (!matchTarget && !matchActor) return false;
        }

        return true;
    }

    /// <summary>该规则设置了多少个具体条件(用于规则优先级:越具体越优先)。</summary>
    public int SpecificityScore()
    {
        int s = 0;
        if (!string.IsNullOrEmpty(ActorPath)) s += 3;
        if (!string.IsNullOrEmpty(ActorPattern)) s += 2;
        if (!string.IsNullOrEmpty(CommandLinePattern)) s += 2;
        if (!string.IsNullOrEmpty(ParentPattern)) s += 2;
        if (!string.IsNullOrEmpty(TargetPattern)) s += 1;
        if (Type.HasValue) s += 1;
        if (RequireUnsigned) s += 1;
        if (ActorHashes is { Count: > 0 }) s += 4; // 哈希精确匹配,最具体
        return s;
    }

    /// <summary>极简通配符匹配,只支持 '*'(任意长度)与 '?'。大小写不敏感。</summary>
    public static bool WildcardMatch(string pattern, string input)
    {
        if (string.IsNullOrEmpty(pattern)) return true;
        input ??= string.Empty;

        int p = 0, s = 0, star = -1, mark = 0;
        while (s < input.Length)
        {
            if (p < pattern.Length &&
                (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(input[s])))
            {
                p++; s++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++; mark = s;
            }
            else if (star != -1)
            {
                p = star + 1; s = ++mark;
            }
            else
            {
                return false;
            }
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
