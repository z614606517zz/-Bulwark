using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

public class VirusScanResult
{
    public string FilePath { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public bool IsMalicious { get; set; }
    public string Summary { get; set; } = string.Empty;
    public VerdictAction? Recommendation { get; set; }
    public string? Confidence { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
}

public interface IVirusScanner
{
    bool IsUsable { get; }
    Task<VirusScanResult> ScanFileAsync(string filePath, CancellationToken token = default);
}

public sealed class VirusScanner : IVirusScanner
{
    public delegate Task<string?> AiProfileDelegate(string path, bool signed, string? publisher, CancellationToken token);

    private AiProfileDelegate? _aiProfile;
    private readonly Action<string>? _diagLogger;

    public event Action<EventArgs>? ScanStarted;
    public event Action<EventArgs>? ScanProgressChanged;
    public event Action<EventArgs>? ScanCompleted;

    public VirusScanner(AiProfileDelegate? aiProfile = null, Action<string>? diagLogger = null)
    {
        _aiProfile = aiProfile;
        _diagLogger = diagLogger;
    }

    public void SetAiProfileDelegate(AiProfileDelegate? aiProfile)
    {
        _aiProfile = aiProfile;
    }

    public bool IsUsable => _aiProfile != null;

    public async Task<VirusScanResult> ScanFileAsync(string filePath, CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return new VirusScanResult { Success = false, Error = "文件路径为空" };

        if (!File.Exists(filePath))
            return new VirusScanResult { Success = false, Error = "文件不存在" };

        try
        {
            string hash = ComputeSha256(filePath);
            if (string.IsNullOrEmpty(hash))
                return new VirusScanResult { Success = false, Error = "无法计算文件哈希" };

            var result = new VirusScanResult
            {
                FilePath = filePath,
                FileHash = hash,
                Success = true
            };

            if (_aiProfile != null)
            {
                var profileResult = await _aiProfile(filePath, false, null, token);
                if (!string.IsNullOrWhiteSpace(profileResult))
                {
                    result.Summary = profileResult;
                    // 简单判断:如果AI返回的内容包含恶意关键词则判定为恶意
                    var lower = profileResult.ToLowerInvariant();
                    if (lower.Contains("恶意") || lower.Contains("malware") || lower.Contains("virus"))
                    {
                        result.IsMalicious = true;
                        result.Recommendation = VerdictAction.Block;
                        result.Confidence = "高";
                    }
                    else
                    {
                        result.IsMalicious = false;
                        result.Recommendation = VerdictAction.Allow;
                        result.Confidence = "中";
                    }
                }
            }
            else
            {
                result.Summary = "AI 扫描不可用";
                result.Error = "AI 未配置";
            }

            return result;
        }
        catch (Exception ex)
        {
            return new VirusScanResult { Success = false, Error = ex.Message };
        }
    }

    private static string ComputeSha256(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return Convert.ToHexString(hash).ToUpperInvariant();
        }
        catch
        {
            return string.Empty;
        }
    }
}
