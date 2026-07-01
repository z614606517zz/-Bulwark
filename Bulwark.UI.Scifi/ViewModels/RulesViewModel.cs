using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>规则管理页 VM:请求规则列表、新增、删除、AI 生成。</summary>
public sealed class RulesViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    public ObservableCollection<RuleRowViewModel> Rules { get; } = new();
    public ObservableCollection<AiRuleSuggestion> AiSuggestions { get; } = new();

    /// <summary>情报刷新生成、经 AI 复核后待用户确认的候选规则。</summary>
    public ObservableCollection<IntelRuleReview> IntelSuggestions { get; } = new();

    private bool _isLoading;
    public bool IsLoading { get => _isLoading; set => Set(ref _isLoading, value); }

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    private bool _aiGenerating;
    public bool AiGenerating { get => _aiGenerating; set { if (Set(ref _aiGenerating, value)) OnPropertyChanged(nameof(AiNotGenerating)); } }
    public bool AiNotGenerating => !_aiGenerating;

    private bool _hasSuggestions;
    public bool HasSuggestions { get => _hasSuggestions; set => Set(ref _hasSuggestions, value); }

    private string _aiStatus = string.Empty;
    public string AiStatus { get => _aiStatus; set { if (Set(ref _aiStatus, value)) OnPropertyChanged(nameof(HasAiStatus)); } }

    /// <summary>是否有 AI 状态文本可展示。</summary>
    public bool HasAiStatus => !string.IsNullOrEmpty(_aiStatus);

    private bool _intelRefreshing;
    public bool IntelRefreshing { get => _intelRefreshing; set { if (Set(ref _intelRefreshing, value)) OnPropertyChanged(nameof(IntelNotRefreshing)); } }
    public bool IntelNotRefreshing => !_intelRefreshing;

    private string _intelStatus = string.Empty;
    public string IntelStatus { get => _intelStatus; set { if (Set(ref _intelStatus, value)) OnPropertyChanged(nameof(HasIntelStatus)); } }

    /// <summary>是否有情报刷新状态文本可展示。</summary>
    public bool HasIntelStatus => !string.IsNullOrEmpty(_intelStatus);

    private bool _hasIntelSuggestions;
    /// <summary>是否有(经 AI 复核的)情报候选规则待用户确认。</summary>
    public bool HasIntelSuggestions { get => _hasIntelSuggestions; set => Set(ref _hasIntelSuggestions, value); }

    public RulesViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.RulesReceived += OnRulesReceived;
        // 链路(重新)连通即自动拉取,避免「页面在断线时加载 → 永远空白」。
        _ipc.ConnectionChanged += connected => { if (connected) Refresh(); };
    }

    /// <summary>请求服务返回最新规则列表(排除信任条目,信任在专门页面展示)。</summary>
    public void Refresh()
    {
        IsLoading = true;
        _ = _ipc.RequestRulesAsync();
    }

    private void OnRulesReceived(List<DefenseRule> rules)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Rules.Clear();
            foreach (var r in rules.Where(r => !r.IsTrustEntry))
                Rules.Add(new RuleRowViewModel(r));
            IsLoading = false;
            IsEmpty = Rules.Count == 0;
        });
    }

    public void Delete(DefenseRule rule) => _ = _ipc.DeleteRuleAsync(rule.Id);

    public void Add(string? actorPath, EventType? type, string? targetPattern, VerdictAction action)
        => _ = _ipc.AddRuleAsync(new Bulwark.Core.Ipc.AddRulePayload
        {
            ActorPath = actorPath,
            Type = type,
            TargetPattern = targetPattern,
            Action = action
        });

    /// <summary>调用 AI 大模型,根据用户用自然语言给出的「要求/条件」生成规则建议;用户确认后再添加。</summary>
    public async void GenerateAiRulesFromRequirement(string requirement)
    {
        if (!App.Ai.IsConfigured)
        {
            AiStatus = "✕ 未配置 AI:请到「设置」页填写 API Key 后再试。";
            return;
        }

        if (string.IsNullOrWhiteSpace(requirement))
        {
            AiStatus = "请先描述你的规则要求或条件(例如:禁止 wscript 创建子进程)。";
            return;
        }

        AiGenerating = true;
        AiStatus = "AI 正在根据你的要求生成规则建议…";
        AiSuggestions.Clear();
        HasSuggestions = false;

        try
        {
            var suggestions = await App.Ai.GenerateRulesFromRequirementAsync(requirement);
            Dispatcher.UIThread.Post(() =>
            {
                AiSuggestions.Clear();
                foreach (var s in suggestions)
                    AiSuggestions.Add(s);
                HasSuggestions = AiSuggestions.Count > 0;
                AiStatus = HasSuggestions
                    ? $"AI 根据你的要求生成了 {AiSuggestions.Count} 条规则,确认无误后点击「采纳」添加到规则库"
                    : "AI 未能从你的描述中生成有效规则(可尝试把要求描述得更具体)。";
            });
        }
        catch (Exception ex)
        {
            AiStatus = $"✕ AI 规则生成失败: {ex.Message}";
        }
        finally
        {
            AiGenerating = false;
        }
    }

    /// <summary>采纳一条 AI 建议规则,添加到规则引擎。</summary>
    public void AcceptSuggestion(AiRuleSuggestion s)
    {
        _ = _ipc.AddRuleAsync(new Bulwark.Core.Ipc.AddRulePayload
        {
            ActorPath = s.ActorPattern,
            Type = s.ParseType(),
            TargetPattern = s.TargetPattern,
            Action = s.ParseAction()
        });
        AiSuggestions.Remove(s);
        HasSuggestions = AiSuggestions.Count > 0;
    }

    /// <summary>
    /// 立即从情报源(ThreatFox)拉取最近威胁,生成候选规则 →<b>不直接落地</b>,
    /// 先交 AI 大模型复核确定 → 展示给用户,由用户逐条(或一键)决定是否采纳。
    /// </summary>
    public async void RefreshIntelRules()
    {
        if (IntelRefreshing) return;
        IntelRefreshing = true;
        IntelSuggestions.Clear();
        HasIntelSuggestions = false;
        IntelStatus = "正在从情报源拉取最近威胁并生成候选规则…";
        try
        {
            // 1) 服务端仅生成候选规则(预览,不落地)。
            var r = await _ipc.RefreshIntelRulesAsync(TimeSpan.FromSeconds(60));
            if (!r.Success)
            {
                IntelStatus = $"✕ {r.Message}";
                return;
            }
            if (r.GeneratedRules.Count == 0)
            {
                IntelStatus = "本次未生成任何候选规则(可能无达标 IOC)。";
                return;
            }

            // 2) 交 AI 大模型复核 IOC 规则(剔除过宽/异常/低置信);AI 不可用时 fail-open 交用户判断。
            IntelStatus = $"已生成 {r.GeneratedRules.Count} 条候选规则,正在请 AI 复核并合成行为规则…";

            // 并行:a) 复核 IOC 规则; b) 由情报语境合成「行为类」防护规则(进程/注册表/注入等)。
            var vetTask = App.Ai.VetIntelRulesAsync(r.GeneratedRules);
            var behaviorTask = App.Ai.GenerateBehaviorRulesFromIntelAsync(r.ThreatContext);
            await Task.WhenAll(vetTask, behaviorTask);

            var reviews = vetTask.Result;
            var behaviorRules = behaviorTask.Result;

            var kept = reviews.Where(x => x.Keep).ToList();
            int dropped = reviews.Count - kept.Count;

            Dispatcher.UIThread.Post(() =>
            {
                IntelSuggestions.Clear();
                foreach (var x in kept)
                    IntelSuggestions.Add(x);
                foreach (var b in behaviorRules)
                    IntelSuggestions.Add(b);
                HasIntelSuggestions = IntelSuggestions.Count > 0;

                var parts = new List<string>();
                if (kept.Count > 0) parts.Add($"IOC 规则 {kept.Count} 条");
                if (behaviorRules.Count > 0) parts.Add($"AI 合成行为规则 {behaviorRules.Count} 条");
                if (dropped > 0) parts.Add($"剔除低质量 {dropped} 条");

                IntelStatus = HasIntelSuggestions
                    ? $"AI 复核完成:{string.Join("、", parts)}。请确认后点击「采纳」或「全部采纳」。"
                    : $"AI 复核后无推荐规则(剔除 {dropped} 条),未添加任何规则。";
            });
        }
        catch (Exception ex)
        {
            IntelStatus = $"✕ 情报刷新失败: {ex.Message}";
        }
        finally
        {
            IntelRefreshing = false;
        }
    }

    /// <summary>采纳一条(经 AI 复核的)情报候选规则:下发服务端应用,并从待确认列表移除。</summary>
    public async void AcceptIntelSuggestion(IntelRuleReview review)
    {
        if (review is null) return;
        var res = await _ipc.ApplyIntelRulesAsync(new List<DefenseRule> { review.Rule });
        Dispatcher.UIThread.Post(() =>
        {
            IntelSuggestions.Remove(review);
            HasIntelSuggestions = IntelSuggestions.Count > 0;
            IntelStatus = res.Success ? $"✓ {res.Message}" : $"✕ {res.Message}";
            if (res.Success) Refresh();
        });
    }

    /// <summary>一键采纳当前所有(经 AI 复核的)情报候选规则。</summary>
    public async void AcceptAllIntelSuggestions()
    {
        if (IntelSuggestions.Count == 0) return;
        var rules = IntelSuggestions.Select(x => x.Rule).ToList();
        var res = await _ipc.ApplyIntelRulesAsync(rules);
        Dispatcher.UIThread.Post(() =>
        {
            IntelSuggestions.Clear();
            HasIntelSuggestions = false;
            IntelStatus = res.Success ? $"✓ {res.Message}" : $"✕ {res.Message}";
            if (res.Success) Refresh();
        });
    }
}
