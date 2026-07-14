using System.Drawing;
using System.Windows.Forms;
using TurkmenGuard.Core;

namespace TurkmenGuard.Services;

/// <summary>
/// System tray icon, balloon notifications, and context menu.
/// </summary>
public class NotificationService : IDisposable
{
    private NotifyIcon? _trayIcon;
    private ContextMenuStrip? _contextMenu;

    public event Action? ShowMainWindowRequested;
    public event Action? ExitRequested;

    public void Initialize()
    {
        DisposeTray();
        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Visible = true,
            Text = LocalizationService.AppTitle
        };
        _trayIcon.DoubleClick += OnTrayDoubleClick;
        BuildContextMenu();
        _trayIcon.ContextMenuStrip = _contextMenu;
    }

    private void BuildContextMenu()
    {
        _contextMenu?.Dispose();
        _contextMenu = new ContextMenuStrip();

        var openItem = new ToolStripMenuItem(LocalizationService.Get("TrayOpen"));
        openItem.Click += (_, _) => ShowMainWindowRequested?.Invoke();
        _contextMenu.Items.Add(openItem);

        _contextMenu.Items.Add(new ToolStripSeparator());

        var exitItem = new ToolStripMenuItem(LocalizationService.Get("TrayExit"));
        exitItem.Click += (_, _) => ExitRequested?.Invoke();
        _contextMenu.Items.Add(exitItem);
    }

    private void OnTrayDoubleClick(object? sender, EventArgs e) =>
        ShowMainWindowRequested?.Invoke();

    public void ShowThreat(ThreatInfo threat)
    {
        RunOnUiThread(() =>
        {
            if (_trayIcon == null) return;
            _trayIcon.ShowBalloonTip(5000,
                LocalizationService.Get("ThreatDetected"),
                $"{threat.ThreatName}\n{Path.GetFileName(threat.FilePath)}",
                ToolTipIcon.Warning);
        });
    }

    public void ShowInfo(string title, string message) =>
        RunOnUiThread(() =>
            _trayIcon?.ShowBalloonTip(3000, title, message, ToolTipIcon.Info));

    public void Dispose() => DisposeTray();

    private static void RunOnUiThread(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            action();
            return;
        }

        dispatcher.BeginInvoke(action);
    }

    private void DisposeTray()
    {
        if (_trayIcon != null)
        {
            _trayIcon.DoubleClick -= OnTrayDoubleClick;
            _trayIcon.ContextMenuStrip = null;
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        _contextMenu?.Dispose();
        _contextMenu = null;
    }
}
