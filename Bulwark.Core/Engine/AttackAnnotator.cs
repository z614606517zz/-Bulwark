using System.Collections.Generic;
using System.Text.RegularExpressions;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// ATT&CK 技战术标注器:从证据链各条目的描述里提取 MITRE ATT&CK 技战术编号
/// (形如 T1059 / T1218.010),用 <see cref="AttackCatalog"/> 解析为「编号 + 名称」,
/// 写回到每条证据的 <see cref="Evidence.Technique"/>,并在事件上汇总去重的
/// <see cref="SecurityEvent.Techniques"/>。
///
/// 采用"从原因文本提取"的方式:多个分析器(LolbinAnalyzer 等)已在原因里标注了 T 编号,
/// 这样无需逐个改造分析器即可统一产出结构化技战术标签。零额外检测逻辑,纯标注。
/// </summary>
public static class AttackAnnotator
{
    private static readonly Regex TechniqueRegex =
        new(@"T\d{4}(?:\.\d{3})?", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>扫描事件证据链,填充每条证据的技战术字段并汇总到 <see cref="SecurityEvent.Techniques"/>。</summary>
    public static void Annotate(SecurityEvent e)
    {
        if (e.EvidenceChain is not { Count: > 0 }) return;

        // 保持首次出现顺序的去重集合
        var seen = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var techniques = new List<string>();

        foreach (var ev in e.EvidenceChain)
        {
            if (string.IsNullOrEmpty(ev.Description)) continue;

            var m = TechniqueRegex.Match(ev.Description);
            if (!m.Success) continue;

            string id = m.Value.ToUpperInvariant();
            var t = AttackCatalog.Lookup(id);

            // 把(子编号优先的)规范编号与名称写回证据
            string canonicalId = t?.Id ?? id;
            ev.Technique ??= canonicalId;
            ev.TechniqueName ??= t?.Name;

            // 用原始命中的编号做去重键,保留子技战术粒度
            if (seen.Add(id))
                techniques.Add(AttackCatalog.Describe(id));
        }

        if (techniques.Count > 0)
            e.Techniques = techniques;
    }
}
