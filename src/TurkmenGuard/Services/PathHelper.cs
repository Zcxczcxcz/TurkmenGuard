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
    }

    public static string GetVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "3.2.0";

    public static List<string> GetDefaultMonitoredFolders()
    {
        var folders = GetQuickScanPaths();
        AddIfExists(folders, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        return folders.Distinct().ToList();
    }

    public static List<string> GetQuickScanPaths()
    {
        var paths = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        AddIfExists(paths, Path.Combine(userProfile, "Downloads"));
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        AddIfExists(paths, Path.GetTempPath());
        AddIfExists(paths, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        return paths;
    }

    public static List<string> GetFullScanPaths() =>
        DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

    public static IEnumerable<string> EnumerateFilesSafe(string directory)
    {
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
            foreach (var f in EnumerateFilesSafe(sub))
                yield return f;
        }
    }

    private static void AddIfExists(List<string> list, string path)
    {
        if (Directory.Exists(path))
            list.Add(path);
    }
}
