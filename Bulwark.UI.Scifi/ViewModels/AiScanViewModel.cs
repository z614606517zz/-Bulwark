using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>AI 病毒扫描页 VM:选文件/文件夹 → 提取特征 → 大模型研判。</summary>
public sealed class AiScanViewModel : ObservableObject
{
    public ObservableCollection<AiFileVerdict> Results { get; } = new();

    private bool _scanning;
    public bool Scanning { get => _scanning; set { if (Set(ref _scanning, value)) OnPropertyChanged(nameof(NotScanning)); } }
    public bool NotScanning => !_scanning;

    private string _status = "选择文件或文件夹开始 AI 病毒扫描。";
    public string Status { get => _status; set => Set(ref _status, value); }

    private int _totalFiles;
    public int TotalFiles { get => _totalFiles; set => Set(ref _totalFiles, value); }

    private int _scannedFiles;
    public int ScannedFiles { get => _scannedFiles; set => Set(ref _scannedFiles, value); }

    private int _cleanCount;
    public int CleanCount { get => _cleanCount; set => Set(ref _cleanCount, value); }

    private int _suspiciousCount;
    public int SuspiciousCount { get => _suspiciousCount; set => Set(ref _suspiciousCount, value); }

    private int _maliciousCount;
    public int MaliciousCount { get => _maliciousCount; set => Set(ref _maliciousCount, value); }

    private bool _hasResults;
    public bool HasResults { get => _hasResults; set => Set(ref _hasResults, value); }

    private CancellationTokenSource? _cts;

    /// <summary>扫描单个文件。</summary>
    public void ScanFile(string path) => _ = ScanAsync(new[] { path });

    /// <summary>扫描文件夹中的可执行文件。</summary>
    public void ScanFolder(string folder)
    {
        try
        {
            var files = Directory.EnumerateFiles(folder, "*.*", SearchOption.AllDirectories)
                .Where(FileInspector.LooksExecutable)
                .Take(100) // 限制避免过多
                .ToArray();
            _ = ScanAsync(files);
        }
        catch (Exception ex)
        {
            Status = $"扫描失败: {ex.Message}";
        }
    }

    public void Cancel()
    {
        _cts?.Cancel();
        Status = "扫描已取消。";
        Scanning = false;
    }

    private async Task ScanAsync(IReadOnlyList<string> files)
    {
        if (files.Count == 0)
        {
            Status = "未找到可执行文件。";
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Scanning = true;
        Results.Clear();
        TotalFiles = files.Count;
        ScannedFiles = 0;
        CleanCount = 0;
        SuspiciousCount = 0;
        MaliciousCount = 0;
        HasResults = false;
        Status = $"正在扫描 {files.Count} 个文件…";

        try
        {
            foreach (var file in files)
            {
                if (token.IsCancellationRequested) break;

                Status = $"[{ScannedFiles + 1}/{TotalFiles}] 正在分析: {Path.GetFileName(file)}";

                // 提取特征(在线程池执行,避免冻结 UI)
                var opts = App.Ai.FileScanOptions;
                var snapshot = await Task.Run(() => FileInspector.Inspect(file, opts), token);

                if (snapshot.Error != null)
                {
                    var errorResult = new AiFileVerdict
                    {
                        Path = file,
                        Available = false,
                        Error = snapshot.Error
                    };
                    await Dispatcher.UIThread.InvokeAsync(() => Results.Add(errorResult));
                    ScannedFiles++;
                    continue;
                }

                // AI 研判
                var verdict = await App.Ai.ScanFileAsync(snapshot, token, "手动扫描");

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    Results.Add(verdict);
                    ScannedFiles++;
                    HasResults = true;
                    if (verdict.Available)
                    {
                        switch (verdict.Verdict)
                        {
                            case AiVerdict.Clean: CleanCount++; break;
                            case AiVerdict.Suspicious: SuspiciousCount++; break;
                            case AiVerdict.Malicious: MaliciousCount++; break;
                        }
                    }
                });
            }

            Status = token.IsCancellationRequested
                ? "扫描已取消。"
                : $"扫描完成:共 {TotalFiles} 文件,安全 {CleanCount},可疑 {SuspiciousCount},恶意 {MaliciousCount}。";
        }
        catch (OperationCanceledException)
        {
            Status = "扫描已取消。";
        }
        catch (Exception ex)
        {
            Status = $"扫描异常: {ex.Message}";
        }
        finally
        {
            Scanning = false;
        }
    }
}
