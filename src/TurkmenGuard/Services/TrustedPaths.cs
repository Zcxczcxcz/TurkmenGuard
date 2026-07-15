namespace TurkmenGuard.Services;

/// <summary>
/// Protects the antivirus engine from self-quarantine — not a software whitelist.
/// Only AppData/Quarantine/ClamAV and own binaries/assets under the install folder.
/// User/test samples next to the exe (e.g. samples\*.js) remain scannable.
/// </summary>
public static class TrustedPaths
{
    public static bool IsTrusted(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        try
        {
            var full = Path.GetFullPath(path);

            if (IsUnder(full, PathHelper.AppDataDir) ||
                IsUnder(full, PathHelper.QuarantineDir) ||
                IsUnder(full, PathHelper.ClamAvDir))
                return true;

            var baseDir = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDir) || !IsUnder(full, baseDir))
                return false;

            // Engine assets shipped beside the exe
            if (IsUnder(full, Path.Combine(baseDir, "ClamAV")) ||
                IsUnder(full, Path.Combine(baseDir, "Data")) ||
                IsUnder(full, Path.Combine(baseDir, "Rules")))
                return true;

            var fileName = Path.GetFileName(full);
            if (fileName.StartsWith("TurkmenGuard", StringComparison.OrdinalIgnoreCase))
                return true;

            // Root-level dependencies only (MaterialDesign*.dll etc.), not samples\malware.exe
            var parent = Path.GetDirectoryName(full);
            if (parent != null &&
                string.Equals(
                    Path.GetFullPath(parent).TrimEnd('\\'),
                    Path.GetFullPath(baseDir).TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase))
            {
                if (fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".config", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsUnder(string fullPath, string? root)
    {
        if (string.IsNullOrWhiteSpace(root))
            return false;

        try
        {
            if (!Directory.Exists(root) && !File.Exists(root))
            {
                // BaseDirectory always exists; other roots may be created later
                if (!string.Equals(root, AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            var prefix = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            var full = Path.GetFullPath(fullPath);
            return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                   || string.Equals(full.TrimEnd('\\'), prefix.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
