using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace Bulwark.UI.Scifi.Views;

/// <summary>让用户用自然语言描述规则要求/条件,供 AI 生成规则。</summary>
public partial class AiRuleRequirementWindow : Window
{
    public bool Confirmed { get; private set; }
    public string? Requirement { get; private set; }

    public AiRuleRequirementWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Confirm_Click(object? sender, RoutedEventArgs e)
    {
        var text = this.FindControl<TextBox>("RequirementBox")!.Text;
        if (string.IsNullOrWhiteSpace(text))
            return; // 空内容不生成

        Requirement = text.Trim();
        Confirmed = true;
        Close();
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e)
    {
        Confirmed = false;
        Close();
    }
}
