using System.Reflection;

namespace TurkmenGuard.Services;

public static class PathHelper
{
    public static string AppDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TurkmenGuard");

    public static string DataDir => FindSubDir("Data") ?? Path.Combine(AppContext.BaseDirectory, "Data");
    public static string HashDatabasePath => Path.Combine(AppDataDir, "hash-signatures.db");
    public static string EmbeddedHashDatabasePath => Path.Combine(DataDir, "hash-signatures.db");
    public static string SettingsPath => Path.Combine(AppDataDir, "settings.json");
    public static string LogsDir => Path.Combine(AppDataDir, "logs");
    public static string QuarantineDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TurkmenGuard", "Quarantine");
    public static string RulesDir => FindSubDir("Rules") ?? Path.Combine(AppContext.BaseDirectory, "Rules");

    // Bundled ClamAV engine (portable x64 + CVD databases)
    public static string ClamAvDir => FindSubDir("ClamAV") ?? Path.Combine(AppContext.BaseDirectory, "ClamAV");
    public static string ClamDatabaseDir => Path.Combine(ClamAvDir, "database");
    public static string ClamLogDir => Path.Combine(AppDataDir, "clamav");
    public static string ClamScanExe => Path.Combine(ClamAvDir, "clamscan.exe");
    public static string ClamdExe => Path.Combine(ClamAvDir, "clamd.exe");
    public static string ClamdScanExe => Path.Combine(ClamAvDir, "clamdscan.exe");
    public static string FreshClamExe => Path.Combine(ClamAvDir, "freshclam.exe");
    public static string ClamdConf => Path.Combine(ClamAvDir, "clamd.conf");
    public static string ClamdScanConf => Path.Combine(ClamAvDir, "clamdscan.conf");
    public static string ClamScanConf => Path.Combine(ClamAvDir, "clamscan.conf");
    public static string FreshClamConf => Path.Combine(ClamAvDir, "freshclam.conf");

    private static string? FindSubDir(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, name);
            if (Directory.Exists(candidate))
                return candidate;
            var parent = Directory.GetParent(dir);
            if (parent == null) break;
            dir = parent.FullName;
        }
        return null;
    }

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(AppDataDir);
        Directory.CreateDirectory(LogsDir);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(ClamLogDir);
        Directory.CreateDirectory(Path.Combine(AppDataDir, "scratch"));
    }

    public static string GetVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "3.2.0";

    public static List<string> GetDefaultMonitoredFolders()
    {
        var folders = GetQuickScanPaths();
        AddIfExists(folders, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        return folders.Distinct().ToList();
    }

    /// <summary>Wide Quick Scan coverage — user profile, programs, temp, appdata.</summary>
    public static List<string> GetQuickScanPaths()
    {
        var paths = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        AddIfExists(paths, Path.Combine(userProfile, "Downloads"));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        AddIfExists(paths, Path.Combine(userProfile, "AppData", "Local"));
        AddIfExists(paths, Path.Combine(userProfile, "AppData", "Roaming"));
        AddIfExists(paths, Path.Combine(userProfile, "AppData", "Local", "Temp"));
        AddIfExists(paths, Path.GetTempPath());
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        AddIfExists(paths, Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        AddIfExists(paths, Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static List<string> GetFullScanPaths() =>
        DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

    /// <summary>
    /// High-risk folders scanned first on Full (faster threat discovery; same coverage overall).
    /// Drive roots are scanned afterward with these trees skipped to avoid double work.
    /// </summary>
    public static List<string> GetFullScanPriorityPaths()
    {
        var paths = new List<string>();
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        AddIfExists(paths, Path.Combine(user, "Downloads"));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        AddIfExists(paths, Path.Combine(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        AddIfExists(paths, Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        AddIfExists(paths, Path.Combine(user, "AppData", "Local", "Temp"));
        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static bool IsUnderPath(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root))
            return false;
        try
        {
            var prefix = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            var full = Path.GetFullPath(path);
            return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                   || string.Equals(full.TrimEnd('\\'), prefix.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static IEnumerable<string> EnumerateFilesSafe(string directory, Func<string, bool>? skipDirectory = null)
    {
        if (skipDirectory?.Invoke(directory) == true)
            yield break;

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(directory); }
        catch { yield break; }

        foreach (var file in files)
        {
            string? safePath = null;
            try { safePath = file; }
            catch { continue; }

            if (safePath != null)
                yield return safePath;
        }

        IEnumerable<string> dirs;
        try { dirs = Directory.EnumerateDirectories(directory); }
        catch { yield break; }

        foreach (var sub in dirs)
        {
            if (skipDirectory?.Invoke(sub) == true)
                continue;

            try
            {
                if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0)
                    continue;
            }
            catch { continue; }

            foreach (var f in EnumerateFilesSafe(sub, skipDirectory))
                yield return f;
        }
    }

    private static void AddIfExists(List<string> list, string path)
    {
        if (Directory.Exists(path))
            list.Add(path);
    }
}
