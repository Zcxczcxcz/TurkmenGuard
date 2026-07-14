using Microsoft.Win32;

namespace TurkmenGuard.Security;

/// <summary>
/// Windows autostart via HKCU Run registry key.
/// Launches with --tray so the app starts in the system tray.
/// </summary>
public static class AutoStartService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "TurkmenGuard";
    public const string TrayArgument = "--tray";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, false);
            return key?.GetValue(AppName) != null;
        }
        catch
        {
            return false;
        }
    }

    public static string? GetStartupCommand()
    {
        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath))
                return null;
            return $"\"{exePath}\" {TrayArgument}";
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Ensures registry matches settings (re-adds if user or malware removed the key).
    /// </summary>
    public static void SyncEnabled(bool shouldBeEnabled)
    {
        if (shouldBeEnabled && !IsRegistryCorrect())
            SetEnabled(true);
        else if (!shouldBeEnabled && IsEnabled())
            SetEnabled(false);
    }

    public static bool IsRegistryCorrect()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, false);
            var value = key?.GetValue(AppName) as string;
            var expected = GetStartupCommand();
            return !string.IsNullOrEmpty(value) &&
                   !string.IsNullOrEmpty(expected) &&
                   value.Equals(expected, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static void SetEnabled(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            if (key == null) return;

            if (enabled)
            {
                var command = GetStartupCommand();
                if (!string.IsNullOrEmpty(command))
                    key.SetValue(AppName, command);
            }
            else
            {
                key.DeleteValue(AppName, false);
            }

            Services.Logger.Info($"Autostart {(enabled ? "enabled" : "disabled")}");
        }
        catch (Exception ex)
        {
            Services.Logger.Error($"Autostart failed: {ex.Message}");
        }
    }
}
