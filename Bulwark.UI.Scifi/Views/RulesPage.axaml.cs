using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.Core.Models;
using Bulwark.UI.Services;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class RulesPage : UserControl
{
    private RulesViewModel? Vm => DataContext as RulesViewModel;

    public RulesPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Vm?.Refresh();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e) => Vm?.Refresh();

    private async void Add_Click(object? sender, RoutedEventArgs e)
    {
        var dlg = new RuleEditorWindow();
        var owner = this.VisualRoot as Avalonia.Controls.Window;
        if (owner is not null)
        {
            await dlg.ShowDialog(owner);
            if (dlg.Confirmed && Vm is not null)
                Vm.Add(dlg.ActorPath, dlg.SelectedType, dlg.TargetPattern, dlg.SelectedAction);
        }
    }

    private void Delete_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is Guid id && Vm is not null)
        {
            // 从 VM 找规则
            foreach (var r in Vm.Rules)
            {
                if (r.Id == id) { Vm.Delete(r.Rule); break; }
            }
        }
    }

    private async void AiGenerate_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;

        var dlg = new AiRuleRequirementWindow();
        var owner = this.VisualRoot as Avalonia.Controls.Window;
        if (owner is null) return;

        await dlg.ShowDialog(owner);
        if (dlg.Confirmed && !string.IsNullOrWhiteSpace(dlg.Requirement))
            Vm.GenerateAiRulesFromRequirement(dlg.Requirement);
    }

    private void AcceptSuggestion_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is AiRuleSuggestion suggestion && Vm is not null)
            Vm.AcceptSuggestion(suggestion);
    }
}
