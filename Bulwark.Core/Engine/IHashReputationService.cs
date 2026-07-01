using System.Threading;
using System.Threading.Tasks;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 文件哈希信誉服务抽象。按 SHA-256 查询外部威胁情报(如 VirusTotal),
/// 给出 <see cref="FileReputation"/> 结论。
///
/// 实现约定:
///  - 必须自带限流(尊重外部服务配额)与超时;
///  - 网络/配额/未收录等任何失败都返回 Unknown 结论,绝不抛断主流程;
///  - 仅供后台异步调用,不应阻塞裁决同步路径。
/// </summary>
public interface IHashReputationService
{
    /// <summary>服务是否启用(未配置 API Key 或被关闭时为 false)。</summary>
    bool IsEnabled { get; }

    /// <summary>
    /// 按 SHA-256 查询文件信誉。失败/未收录/超配额时返回 Verdict=Unknown 的结果。
    /// </summary>
    Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default);

    /// <summary>
    /// 测试连接 / API Key 有效性。返回是否成功及可读说明。
    /// 与 <see cref="QueryAsync"/> 不同,本方法能区分"鉴权失败"与"文件未收录"。
    /// </summary>
    Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default);

    /// <summary>
    /// 返回该源的实时用量快照(今日已用 / 配额),供「情报源连接」页展示。纯展示,不影响裁决。
    /// </summary>
    ReputationUsage GetUsage();
}
