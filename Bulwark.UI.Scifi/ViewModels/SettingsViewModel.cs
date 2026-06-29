using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>设置页 VM:读取 / 提交运行时设置。</summary>
public sealed class SettingsViewModel : ObservableObject
{
    private readonly IpcClient _ipc;
    private bool _suppressSave;

    public SettingsViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.SettingsReceived += OnSettingsReceived;
        _ipc.ConnectionChanged += connected => { if (connected) Refresh(); };
    }

    public void Refresh() => _ = _ipc.RequestSettingsAsync();

    private void OnSettingsReceived(RuntimeSettings s)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _suppressSave = true;
            ProtectionEnabled = s.ProtectionEnabled;
            ProcessProtection = s.ProcessProtection;
            FileProtection = s.FileProtection;
            RegistryProtection = s.RegistryProtection;
            SelfProtection = s.SelfProtection;
            NetworkProtection = s.NetworkProtection;
            TrustSignedActors = s.TrustSignedActors;
            DefaultBlock = s.DefaultBlock;
            SilentMode = s.SilentMode;
            QuarantineOnBlock = s.QuarantineOnBlock;
            KernelDriverEnabled = s.KernelDriverEnabled;
            KernelConnected = s.KernelConnected;
            KernelStatus = string.IsNullOrEmpty(s.KernelStatus) ? "未知" : s.KernelStatus;
            EventSource = s.EventSource;
            VirusTotalEnabled = s.VirusTotalEnabled;
            AiScanDoubleClickEnabled = s.AiScanDoubleClickEnabled;
            AiScanSuspendDuringScan = s.AiScanSuspendDuringScan;
            AiScanBlockOnFailure = s.AiScanBlockOnFailure;
            AiGrayZoneConsultEnabled = s.AiGrayZoneConsultEnabled;
            AiCreditGuardEnabled = s.AiCreditGuardEnabled;
            AiMonthlyCreditYi = (decimal)(s.AiMonthlyCreditBudget / 100_000_000.0);
            UserModeBehaviorMonitor = s.UserModeBehaviorMonitor;
            RansomwareCanaryEnabled = s.RansomwareCanaryEnabled;
            BehaviorBaselineEnabled = s.BehaviorBaselineEnabled;
            // AI:服务端为空时回退到 UI 内置默认值(开箱即用)。
            AiBaseUrl = string.IsNullOrWhiteSpace(s.AiBaseUrl) ? AiClient.BuiltInBaseUrl : s.AiBaseUrl;
            AiApiKey = (string.IsNullOrWhiteSpace(s.AiApiKey) || AiClient.IsRetiredKey(s.AiApiKey))
                ? AiClient.BuiltInApiKey : s.AiApiKey;
            AiModel = string.IsNullOrWhiteSpace(s.AiModel) ? AiClient.BuiltInModel : s.AiModel;
            AiScanScriptTextLimitKb = s.AiScanScriptTextLimitKb;
            AiScanBinarySampleLimitMb = s.AiScanBinarySampleLimitMb;
            AiScanMaxStrings = s.AiScanMaxStrings;
            _suppressSave = false;
        });
    }

    private RuntimeSettings Build() => new()
    {
        ProtectionEnabled = ProtectionEnabled,
        ProcessProtection = ProcessProtection,
        FileProtection = FileProtection,
        RegistryProtection = RegistryProtection,
        SelfProtection = SelfProtection,
        NetworkProtection = NetworkProtection,
        TrustSignedActors = TrustSignedActors,
        DefaultBlock = DefaultBlock,
        SilentMode = SilentMode,
        QuarantineOnBlock = QuarantineOnBlock,
        KernelDriverEnabled = KernelDriverEnabled,
        EventSource = EventSource,
        VirusTotalEnabled = VirusTotalEnabled,
        AiScanDoubleClickEnabled = AiScanDoubleClickEnabled,
        AiScanSuspendDuringScan = AiScanSuspendDuringScan,
        AiScanBlockOnFailure = AiScanBlockOnFailure,
        AiGrayZoneConsultEnabled = AiGrayZoneConsultEnabled,
        AiCreditGuardEnabled = AiCreditGuardEnabled,
        AiMonthlyCreditBudget = (long)(AiMonthlyCreditYi * 100_000_000m),
        UserModeBehaviorMonitor = UserModeBehaviorMonitor,
        RansomwareCanaryEnabled = RansomwareCanaryEnabled,
        BehaviorBaselineEnabled = BehaviorBaselineEnabled,
        AiBaseUrl = AiBaseUrl,
        AiApiKey = AiApiKey,
        AiModel = AiModel,
        AiScanScriptTextLimitKb = AiScanScriptTextLimitKb,
        AiScanBinarySampleLimitMb = AiScanBinarySampleLimitMb,
        AiScanMaxStrings = AiScanMaxStrings
    };

    private void Save()
    {
        if (_suppressSave) return;
        _ = _ipc.UpdateSettingsAsync(Build());
    }

    // ===== 绑定属性(每次改动即保存) =====
    private bool _protectionEnabled = true;
    public bool ProtectionEnabled { get => _protectionEnabled; set { if (Set(ref _protectionEnabled, value)) Save(); } }

    private bool _processProtection = true;
    public bool ProcessProtection { get => _processProtection; set { if (Set(ref _processProtection, value)) Save(); } }

    private bool _fileProtection = true;
    public bool FileProtection { get => _fileProtection; set { if (Set(ref _fileProtection, value)) Save(); } }

    private bool _registryProtection = true;
    public bool RegistryProtection { get => _registryProtection; set { if (Set(ref _registryProtection, value)) Save(); } }

    private bool _selfProtection = true;
    public bool SelfProtection { get => _selfProtection; set { if (Set(ref _selfProtection, value)) Save(); } }

    private bool _networkProtection = true;
    public bool NetworkProtection { get => _networkProtection; set { if (Set(ref _networkProtection, value)) Save(); } }

    private bool _trustSignedActors = true;
    public bool TrustSignedActors { get => _trustSignedActors; set { if (Set(ref _trustSignedActors, value)) Save(); } }

    private bool _defaultBlock;
    public bool DefaultBlock { get => _defaultBlock; set { if (Set(ref _defaultBlock, value)) Save(); } }

    private bool _silentMode;
    public bool SilentMode { get => _silentMode; set { if (Set(ref _silentMode, value)) Save(); } }

    private bool _quarantineOnBlock;
    public bool QuarantineOnBlock { get => _quarantineOnBlock; set { if (Set(ref _quarantineOnBlock, value)) Save(); } }

    private bool _kernelDriverEnabled;
    public bool KernelDriverEnabled { get => _kernelDriverEnabled; set { if (Set(ref _kernelDriverEnabled, value)) Save(); } }

    private string _kernelStatus = "未知";
    public string KernelStatus { get => _kernelStatus; set => Set(ref _kernelStatus, value); }

    private string _eventSource = "Wmi";
    public string EventSource { get => _eventSource; set => Set(ref _eventSource, value); }

    // ===== 威胁情报 (VirusTotal) =====
    private bool _virusTotalEnabled;
    /// <summary>VirusTotal 后台信誉查询总开关。改动即保存(由服务端以管理员权限持久化)。</summary>
    public bool VirusTotalEnabled { get => _virusTotalEnabled; set { if (Set(ref _virusTotalEnabled, value)) Save(); } }

    private bool _vtBusy;
    public bool VtBusy { get => _vtBusy; set { if (Set(ref _vtBusy, value)) OnPropertyChanged(nameof(VtNotBusy)); } }
    public bool VtNotBusy => !_vtBusy;

    private string _vtResult = "尚未查询。可测试连接,或选择文件查询其哈希信誉。";
    public string VtResult { get => _vtResult; set => Set(ref _vtResult, value); }

    private string _vtFilePath = string.Empty;
    public string VtFilePath { get => _vtFilePath; set => Set(ref _vtFilePath, value); }

    /// <summary>测试威胁情报源(VirusTotal)连接 / API Key 有效性。</summary>
    public async void TestConnection()
    {
        VtBusy = true;
        VtResult = "正在测试连接…";
        try
        {
            var resp = await _ipc.TestVirusTotalAsync();
            VtResult = resp.Success ? $"✓ 连接正常 · {resp.Message}" : $"✕ 连接失败 · {resp.Message}";
        }
        catch (System.Exception ex) { VtResult = $"✕ 异常:{ex.Message}"; }
        finally { VtBusy = false; }
    }

    /// <summary>按 SHA-256 查询指定文件的 VirusTotal 信誉。</summary>
    public async void QueryFile()
    {
        var path = VtFilePath?.Trim();
        if (string.IsNullOrWhiteSpace(path)) { VtResult = "请先选择要查询的文件。"; return; }

        VtBusy = true;
        VtResult = $"正在查询:{path} …";
        try
        {
            var resp = await _ipc.QueryFileReputationAsync(path);
            if (!resp.Success) { VtResult = $"✕ 查询失败 · {resp.Message}"; return; }

            var rep = resp.Reputation;
            if (rep is null) { VtResult = $"已完成 · {resp.Message}(无信誉数据)"; return; }

            var verdict = rep.Verdict switch
            {
                ReputationVerdict.Clean => "干净",
                ReputationVerdict.Suspicious => "可疑",
                ReputationVerdict.Malicious => "恶意",
                _ => "未知/未收录"
            };
            VtResult = $"结论:{verdict}  ·  检出 {rep.Malicious}/{rep.TotalEngines}"
                     + (string.IsNullOrEmpty(rep.ThreatLabel) ? "" : $"  ·  {rep.ThreatLabel}")
                     + $"\nSHA-256: {rep.Sha256}";
        }
        catch (System.Exception ex) { VtResult = $"✕ 异常:{ex.Message}"; }
        finally { VtBusy = false; }
    }

    // ===== AI (大模型) =====

    private bool _aiScanDoubleClickEnabled = true;
    public bool AiScanDoubleClickEnabled { get => _aiScanDoubleClickEnabled; set { if (Set(ref _aiScanDoubleClickEnabled, value)) Save(); } }

    private bool _aiScanSuspendDuringScan = true;
    public bool AiScanSuspendDuringScan { get => _aiScanSuspendDuringScan; set { if (Set(ref _aiScanSuspendDuringScan, value)) Save(); } }

    private bool _aiScanBlockOnFailure;
    public bool AiScanBlockOnFailure { get => _aiScanBlockOnFailure; set { if (Set(ref _aiScanBlockOnFailure, value)) Save(); } }

    private bool _aiGrayZoneConsultEnabled;
    public bool AiGrayZoneConsultEnabled { get => _aiGrayZoneConsultEnabled; set { if (Set(ref _aiGrayZoneConsultEnabled, value)) Save(); } }

    private bool _aiCreditGuardEnabled = true;
    public bool AiCreditGuardEnabled { get => _aiCreditGuardEnabled; set { if (Set(ref _aiCreditGuardEnabled, value)) Save(); } }

    private decimal _aiMonthlyCreditYi = 41m;
    /// <summary>月度 Credits 额度(单位:亿)。Lite=41 / Standard=110 / Pro=380 / Max=820。</summary>
    public decimal AiMonthlyCreditYi { get => _aiMonthlyCreditYi; set { if (Set(ref _aiMonthlyCreditYi, value)) Save(); } }

    private static readonly UiLocalConfig.Data _local = UiLocalConfig.Load();

    private bool _mimoUsageEnabled = _local.MimoUsageEnabled;
    public bool MimoUsageEnabled { get => _mimoUsageEnabled; set { if (Set(ref _mimoUsageEnabled, value)) { SaveMimoLocal(); OfficialUsageConfigChanged?.Invoke(); } } }

    private string _mimoUsageCookie = _local.MimoUsageCookie;
    public string MimoUsageCookie { get => _mimoUsageCookie; set { if (Set(ref _mimoUsageCookie, value)) SaveMimoLocal(); } }

    /// <summary>
    /// 官方用量配置(开关切换 / Cookie 测试成功)发生变化时触发,通知仪表盘【立即】重新拉取官方用量,
    /// 不必等仪表盘那 5 分钟的定时刷新 —— 解决「刚粘贴并测试成功后仪表盘仍显示旧值/本地估算」的问题。
    /// </summary>
    public event System.Action? OfficialUsageConfigChanged;

    private string _mimoUsageTestResult = string.Empty;
    public string MimoUsageTestResult { get => _mimoUsageTestResult; set => Set(ref _mimoUsageTestResult, value); }

    /// <summary>官方用量配置存到 UI 本地(不经服务、不进 ProgramData)。</summary>
    private void SaveMimoLocal()
        => UiLocalConfig.Save(new UiLocalConfig.Data
        {
            MimoUsageEnabled = _mimoUsageEnabled,
            MimoUsageCookie = _mimoUsageCookie
        });

    /// <summary>测试官方用量获取(用当前填写的 Cookie),把结果显示在设置页。</summary>
    public async System.Threading.Tasks.Task TestMimoUsageAsync()
    {
        MimoUsageTestResult = "查询中…";
        try
        {
            var r = await App.MimoUsage.FetchAsync(MimoUsageCookie);
            if (r.Ok)
            {
                MimoUsageTestResult = $"成功:已用 {r.Used / 1e8:0.##} / {r.Total / 1e8:0.#} 亿 Credits";
                // Cookie 已验证可用:立即通知仪表盘重新拉取官方用量(不必等 5 分钟定时刷新)。
                OfficialUsageConfigChanged?.Invoke();
            }
            else
            {
                MimoUsageTestResult = "失败:" + r.Message;
            }
        }
        catch (System.Exception ex)
        {
            MimoUsageTestResult = "异常:" + ex.Message;
        }
    }

    private bool _userModeBehaviorMonitor = true;
    public bool UserModeBehaviorMonitor { get => _userModeBehaviorMonitor; set { if (Set(ref _userModeBehaviorMonitor, value)) Save(); } }

    private bool _ransomwareCanaryEnabled = true;
    public bool RansomwareCanaryEnabled { get => _ransomwareCanaryEnabled; set { if (Set(ref _ransomwareCanaryEnabled, value)) Save(); } }

    private bool _behaviorBaselineEnabled = true;
    public bool BehaviorBaselineEnabled { get => _behaviorBaselineEnabled; set { if (Set(ref _behaviorBaselineEnabled, value)) Save(); } }

    private string _aiBaseUrl = string.Empty;
    public string AiBaseUrl { get => _aiBaseUrl; set { if (Set(ref _aiBaseUrl, value)) Save(); } }

    private string _aiApiKey = string.Empty;
    public string AiApiKey { get => _aiApiKey; set { if (Set(ref _aiApiKey, value)) Save(); } }

    private string _aiModel = string.Empty;
    public string AiModel { get => _aiModel; set { if (Set(ref _aiModel, value)) Save(); } }

    // ===== AI 文件扫描内容上限(可配置) =====
    private int _aiScanScriptTextLimitKb = 32;
    public int AiScanScriptTextLimitKb { get => _aiScanScriptTextLimitKb; set { if (Set(ref _aiScanScriptTextLimitKb, value)) Save(); } }

    private int _aiScanBinarySampleLimitMb = 4;
    public int AiScanBinarySampleLimitMb { get => _aiScanBinarySampleLimitMb; set { if (Set(ref _aiScanBinarySampleLimitMb, value)) Save(); } }

    private int _aiScanMaxStrings = 400;
    public int AiScanMaxStrings { get => _aiScanMaxStrings; set { if (Set(ref _aiScanMaxStrings, value)) Save(); } }

    private bool _aiBusy;
    public bool AiBusy { get => _aiBusy; set { if (Set(ref _aiBusy, value)) OnPropertyChanged(nameof(AiNotBusy)); } }
    public bool AiNotBusy => !_aiBusy;

    private string _aiTestResult = "尚未测试。填写 API Key 后可测试连接。";
    public string AiTestResult { get => _aiTestResult; set => Set(ref _aiTestResult, value); }

    /// <summary>测试 AI 大模型连接。</summary>
    public async void TestAiConnection()
    {
        AiBusy = true;
        AiTestResult = "正在测试 AI 连接…";
        try
        {
            // 确保 AiClient 用最新配置
            App.Ai.Configure(Build());
            var (ok, msg) = await App.Ai.TestConnectionAsync();
            AiTestResult = ok ? $"✓ {msg}" : $"✕ {msg}";
        }
        catch (System.Exception ex) { AiTestResult = $"✕ 异常:{ex.Message}"; }
        finally { AiBusy = false; }
    }

    // ===== 驱动连接状态（只读展示） =====
    private bool _kernelConnected;
    public bool KernelConnected { get => _kernelConnected; set => Set(ref _kernelConnected, value); }
}
