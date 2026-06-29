using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.Core.Models;

namespace Bulwark.UI.Scifi.Views;

public partial class RuleEditorWindow : Window
{
    public bool Confirmed { get; private set; }
    public string? ActorPath { get; private set; }
    public EventType? SelectedType { get; private set; }
    public string? TargetPattern { get; private set; }
    public VerdictAction SelectedAction { get; private set; } = VerdictAction.Block;

    public RuleEditorWindow()
    {
        InitializeComponent();

        var typeBox = this.FindControl<ComboBox>("TypeBox")!;
        typeBox.ItemsSource = new object[]
        {
            "(任意)",
            EventType.ProcessCreate,
            EventType.RemoteThread,
            EventType.ImageLoad,
            EventType.FileWrite,
            EventType.FileDelete,
            EventType.RegistryWrite,
            EventType.NetworkConnect,
            EventType.SelfProtect
        };
        typeBox.SelectedIndex = 0;

        var actionBox = this.FindControl<ComboBox>("ActionBox")!;
        actionBox.ItemsSource = new object[] { VerdictAction.Block, VerdictAction.Allow };
        actionBox.SelectedIndex = 0;
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Confirm_Click(object? sender, RoutedEventArgs e)
    {
        var actor = this.FindControl<TextBox>("ActorPathBox")!.Text;
        var target = this.FindControl<TextBox>("TargetBox")!.Text;
        var typeSel = this.FindControl<ComboBox>("TypeBox")!.SelectedItem;
        var actionSel = this.FindControl<ComboBox>("ActionBox")!.SelectedItem;

        ActorPath = string.IsNullOrWhiteSpace(actor) ? null : actor.Trim();
        TargetPattern = string.IsNullOrWhiteSpace(target) ? null : target.Trim();
        SelectedType = typeSel is EventType t ? t : null;
        SelectedAction = actionSel is VerdictAction a ? a : VerdictAction.Block;

        Confirmed = true;
        Close();
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e)
    {
        Confirmed = false;
        Close();
    }
}
