using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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
}
