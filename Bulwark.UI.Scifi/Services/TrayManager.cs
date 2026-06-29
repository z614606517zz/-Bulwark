using System;
using System.Drawing;
using System.Windows.Forms;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;

namespace Bulwark.UI.Scifi.Services;

/// <summary>
/// Windows 系统托盘管理(基于 WinForms NotifyIcon)。
/// 最小化时隐藏主窗口到托盘,双击托盘恢复。
/// </summary>
public sealed class TrayManager : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly Window _mainWindow;

    public TrayManager(Window mainWindow)
    {
        _mainWindow = mainWindow;

        _icon = new NotifyIcon
        {
            Text = "磐垒主动防御 · BULWARK",
            Visible = true,
            Icon = LoadAppIcon() ?? SystemIcons.Shield
        };

        // 双击托盘图标:恢复窗口
        _icon.DoubleClick += (_, _) => ShowMainWindow();

        // 右键菜单
        var menu = new ContextMenuStrip();
        menu.Items.Add("显示主面板", null, (_, _) => ShowMainWindow());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("退出", null, (_, _) => Exit());
        _icon.ContextMenuStrip = menu;
    }

    /// <summary>
    /// 从 Avalonia 资源加载应用图标(bulwark.ico),用于系统托盘。
    /// 加载失败时返回 null,调用方回退到系统盾牌图标。
    /// </summary>
    private static Icon? LoadAppIcon()
    {
        try
        {
            var uri = new Uri("avares://Bulwark.UI.Scifi/Assets/bulwark.ico");
            using var stream = Avalonia.Platform.AssetLoader.Open(uri);
            return new Icon(stream);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>显示托盘气泡通知。</summary>
    public void ShowBalloon(string title, string text, ToolTipIcon tipIcon = ToolTipIcon.Info)
    {
        _icon.ShowBalloonTip(3000, title, text, tipIcon);
    }

    private void ShowMainWindow()
    {
        Dispatcher.UIThread.Post(() =>
        {
            _mainWindow.Show();
            _mainWindow.WindowState = WindowState.Normal;
            _mainWindow.Activate();
        });
    }

    private void Exit()
    {
        Dispatcher.UIThread.Post(() =>
        {
            // 标记允许真正关闭,避免主窗口 Closing 处理把退出当成"隐藏到托盘"。
            if (_mainWindow is Views.MainWindow mw) mw.ForceClose = true;
            if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
                desktop.Shutdown();
        });
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
