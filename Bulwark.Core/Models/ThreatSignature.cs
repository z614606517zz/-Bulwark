using System;
using System.Collections.Generic;

namespace Bulwark.Core.Models;

/// <summary>
/// 特征类型。决定 <see cref="ThreatSignature.Pattern"/> 字段的解释方式。
/// </summary>
public enum SignatureKind
{
    /// <summary>文件哈希精确匹配(SHA-256 / SHA-1 / MD5,十六进制)。命中即确定恶意。</summary>
    Hash = 0,

    /// <summary>
    /// 字节模式匹配(YARA-lite)。Pattern 为十六进制字节串,支持 <c>??</c> 通配单字节,
    /// 如 <c>6A 40 68 00 30 00 00 ?? E8</c>。在文件内容中扫描,命中即视为含已知恶意片段。
    /// </summary>
    BytePattern = 1,

    /// <summary>
    /// 文本/字符串模式。Pattern 为明文(忽略大小写),在文件内容(按 Latin1 解释)中查找。
    /// 适合抓特定字符串常量(如内置 C2 域名、勒索信标志串、特定 mutex 名)。
    /// </summary>
    Text = 2,
}

/// <summary>
/// 严重级别。命中后由引擎换算为风险分与处置倾向。
/// </summary>
public enum SignatureSeverity
{
    /// <summary>低:仅作提示加分(疑似)。</summary>
    Low = 0,

    /// <summary>中:可疑,提级到"询问"区间。</summary>
    Medium = 1,

    /// <summary>高:确定性恶意,直接顶到"拦截"区间。</summary>
    High = 2,
}

/// <summary>
/// 一条特征码定义。可从特征库文件(JSON)加载,可热更新。
///
/// 设计:特征引擎走"确定性匹配"路线——命中已知恶意特征即高可信结论,
/// 与启发式/行为引擎(<see cref="Engine.ThreatDetector"/>)互补:
///   · 特征引擎:对【已知】恶意样本快、准、可解释;
///   · 启发式引擎:对【未知/变种】靠行为兜底。
/// </summary>
public sealed class ThreatSignature
{
    /// <summary>特征唯一标识(库内不重复),用于命中溯源与去重。</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>威胁名称(如 "Trojan.Win32.SilverFox.gen"),命中时展示给用户。</summary>
    public string Name { get; set; } = string.Empty;

    public SignatureKind Kind { get; set; } = SignatureKind.Hash;

    public SignatureSeverity Severity { get; set; } = SignatureSeverity.High;

    /// <summary>
    /// 特征内容。语义随 <see cref="Kind"/>:
    ///   Hash        -> 十六进制哈希(40=SHA1 / 64=SHA256 / 32=MD5),大小写不敏感;
    ///   BytePattern -> 十六进制字节串,空格可选,<c>??</c> 表示通配单字节;
    ///   Text        -> 明文字符串(匹配时忽略大小写)。
    /// </summary>
    public string Pattern { get; set; } = string.Empty;

    /// <summary>可选描述/家族说明。</summary>
    public string? Description { get; set; }

    /// <summary>是否启用。便于临时停用某条误报特征而不删除。</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// 特征库(可序列化为 JSON 持久化/分发)。包含版本号便于更新管理。
/// </summary>
public sealed class SignatureDatabase
{
    /// <summary>库版本(如 "2026.06.17.1"),用于显示与增量更新判断。</summary>
    public string Version { get; set; } = string.Empty;

    /// <summary>特征列表。</summary>
    public List<ThreatSignature> Signatures { get; set; } = new();
}
