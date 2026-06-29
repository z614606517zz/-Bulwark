using System;

namespace Bulwark.Core.Models;

/// <summary>
/// VirusTotal 上传扫描的进度阶段。服务端在「双击上传扫描」过程中逐阶段推送给 UI,
/// 驱动进度卡片与「VT 查询记录」视图的实时状态显示。
/// </summary>
public enum VtScanStage
{
    /// <summary>排队中(等待限流令牌)。</summary>
    Queued = 0,
    /// <summary>正在按哈希查询 VT 是否已收录。</summary>
    Querying,
    /// <summary>正在上传文件到 VT(配合 <see cref="VtScanRecord.Percent"/> 显示百分比)。</summary>
    Uploading,
    /// <summary>已上传,VT 云端多引擎分析中(轮询结果)。</summary>
    Analyzing,
    /// <summary>已完成(得到结论)。</summary>
    Completed,
    /// <summary>失败/超时/不可用。</summary>
    Error
}

/// <summary>VT 扫描的最终结论(用于记录与展示)。</summary>
public enum VtScanOutcome
{
    /// <summary>尚未出结论(进行中)。</summary>
    Pending = 0,
    /// <summary>干净。</summary>
    Clean,
    /// <summary>可疑(少量引擎检出)。</summary>
    Suspicious,
    /// <summary>恶意(达到阈值)。</summary>
    Malicious,
    /// <summary>未知(未收录且未上传 / 无结论)。</summary>
    Unknown,
    /// <summary>错误(网络/限流/超时/不可用)。</summary>
    Error
}

/// <summary>
/// 一条 VirusTotal 扫描记录。既用作服务端 -> UI 的实时进度推送负载(随阶段多次推送,以
/// <see cref="Id"/> 关联同一次扫描),也用作「VT 查询记录」视图的持久化条目。
/// </summary>
public sealed class VtScanRecord
{
    /// <summary>关联的扫描 Id(双击扫描时等于触发事件的 Id;手动扫描时为新 Guid)。</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>文件 SHA-256(小写十六进制)。用于去重:同哈希已扫过则复用结论不重复扫。</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>文件完整路径。</summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>文件名(展示用)。</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>当前阶段。</summary>
    public VtScanStage Stage { get; set; } = VtScanStage.Queued;

    /// <summary>上传进度百分比(0~100),仅 <see cref="Stage"/>=Uploading 时有意义。</summary>
    public int Percent { get; set; }

    /// <summary>最终结论。</summary>
    public VtScanOutcome Outcome { get; set; } = VtScanOutcome.Pending;

    /// <summary>检出为恶意/可疑的引擎数。</summary>
    public int Malicious { get; set; }

    /// <summary>参与分析的引擎总数。</summary>
    public int TotalEngines { get; set; }

    /// <summary>威胁名称标签(可空)。</summary>
    public string? ThreatLabel { get; set; }

    /// <summary>一句话说明(进度/结论/错误原因,展示用)。</summary>
    public string? Message { get; set; }

    /// <summary>是否经过了「上传」(true 表示曾上传文件;false 表示仅哈希命中)。</summary>
    public bool Uploaded { get; set; }

    /// <summary>触发来源:双击 / Dropper / 手动。</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>记录/更新时间(UTC)。</summary>
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    /// <summary>是否为终态(已完成或错误)。</summary>
    public bool IsTerminal => Stage is VtScanStage.Completed or VtScanStage.Error;

    public VtScanRecord Clone() => (VtScanRecord)MemberwiseClone();
}
