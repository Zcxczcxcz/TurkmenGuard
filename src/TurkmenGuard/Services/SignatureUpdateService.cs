using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;
using TurkmenGuard.Core;

namespace TurkmenGuard.Services;

/// <summary>
/// Downloads hash DB and YARA rule updates from a signature backend endpoint.
/// Network is used only here — scanning remains fully offline.
/// </summary>
public sealed class SignatureUpdateService : IDisposable
{
    public const string DefaultEndpoint = "https://signatures.turkmenguard.local/v1/manifest.json";

    private readonly AppSettings _settings;
    private readonly ScannerEngine _scanner;
    private readonly HttpClient _http;
    private readonly System.Timers.Timer _weeklyTimer;
    private int _updateRunning;

    public event Action<string>? StatusChanged;

    public SignatureUpdateService(AppSettings settings, ScannerEngine scanner)
    {
        _settings = settings;
        _scanner = scanner;
        _http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        _weeklyTimer = new System.Timers.Timer(TimeSpan.FromDays(7).TotalMilliseconds)
        {
            AutoReset = true,
            Enabled = false
        };
        _weeklyTimer.Elapsed += (_, _) => _ = TryUpdateAsync(force: false);
    }

    public void Start()
    {
        if (!_settings.SignatureUpdatesEnabled)
            return;

        _weeklyTimer.Enabled = _settings.SignatureUpdateSchedule == "weekly";

        Task.Run(async () =>
        {
            if (_settings.CheckUpdatesOnStartup)
                await TryUpdateAsync(force: false);
        });
    }

    public async Task<(bool Success, string Message)> UpdateNowAsync()
        => await TryUpdateAsync(force: true);

    private async Task<(bool Success, string Message)> TryUpdateAsync(bool force)
    {
        if (!_settings.SignatureUpdatesEnabled)
            return (false, LocalizationService.Get("UpdatesDisabled"));

        if (Interlocked.CompareExchange(ref _updateRunning, 1, 0) != 0)
            return (false, LocalizationService.Get("UpdateInProgress"));

        if (!force && !IsUpdateDue())
        {
            Interlocked.Exchange(ref _updateRunning, 0);
            return (false, LocalizationService.Get("UpdateNotDue"));
        }

        try
        {
            Report(LocalizationService.Get("UpdateChecking"));
            var manifest = await FetchManifestAsync();
            if (manifest == null)
                return (false, LocalizationService.Get("UpdateFailed"));

            if (!force && !string.IsNullOrEmpty(_settings.LastSignatureVersion) &&
                string.Equals(_settings.LastSignatureVersion, manifest.Version, StringComparison.OrdinalIgnoreCase))
            {
                Report(LocalizationService.Get("UpdateUpToDate"));
                return (true, LocalizationService.Get("UpdateUpToDate"));
            }

            Report(LocalizationService.Get("UpdateDownloading"));

            if (!string.IsNullOrWhiteSpace(manifest.HashDbUrl))
            {
                var tempDb = Path.Combine(PathHelper.AppDataDir, "hash-signatures.new.db");
                if (!await DownloadFileAsync(manifest.HashDbUrl, tempDb))
                    return (false, LocalizationService.Get("UpdateFailed"));

                if (!string.IsNullOrWhiteSpace(manifest.HashDbSha256))
                {
                    var hash = HashChecker.ComputeSha256(tempDb);
                    if (!hash.Equals(manifest.HashDbSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Delete(tempDb);
                        return (false, LocalizationService.Get("UpdateHashMismatch"));
                    }
                }

                _scanner.CloseHashDatabase();
                File.Copy(tempDb, PathHelper.HashDatabasePath, overwrite: true);
                File.Delete(tempDb);
                _scanner.ReloadHashDatabase();
            }

            if (!string.IsNullOrWhiteSpace(manifest.RulesPackUrl))
            {
                var tempZip = Path.Combine(PathHelper.AppDataDir, "rules-update.zip");
                if (await DownloadFileAsync(manifest.RulesPackUrl, tempZip))
                {
                    ExtractRulesPack(tempZip, PathHelper.RulesDir);
                    File.Delete(tempZip);
                    _scanner.ReloadYaraRules();
                }
            }

            _settings.LastSignatureVersion = manifest.Version;
            _settings.LastSignatureUpdate = DateTime.UtcNow;
            SettingsService.Save(_settings);
            TryUpdateClamAvDatabase();

            var msg = LocalizationService.Format("UpdateSuccess", manifest.Version);
            Report(msg);
            Logger.Info($"Signature update applied: {manifest.Version}");
            return (true, msg);
        }
        catch (Exception ex)
        {
            Logger.Error($"Signature update failed: {ex.Message}");
            return (false, LocalizationService.Get("UpdateFailed"));
        }
        finally
        {
            Interlocked.Exchange(ref _updateRunning, 0);
        }
    }

    private bool IsUpdateDue()
    {
        if (_settings.LastSignatureUpdate == null)
            return true;

        return _settings.SignatureUpdateSchedule == "weekly" &&
               DateTime.UtcNow - _settings.LastSignatureUpdate.Value >= TimeSpan.FromDays(7);
    }

    private async Task<SignatureManifest?> FetchManifestAsync()
    {
        var url = string.IsNullOrWhiteSpace(_settings.SignatureUpdateEndpoint)
            ? DefaultEndpoint
            : _settings.SignatureUpdateEndpoint;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            Logger.Warn($"Manifest fetch blocked (HTTPS only): {url}");
            return null;
        }

        var json = await _http.GetStringAsync(url);
        return JsonSerializer.Deserialize<SignatureManifest>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private async Task<bool> DownloadFileAsync(string url, string destination)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            Logger.Warn($"Download blocked (HTTPS only): {url}");
            return false;
        }

        try
        {
            var dir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            using (var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead))
            {
                response.EnsureSuccessStatusCode();
                using (var fs = File.Create(destination))
                    await response.Content.CopyToAsync(fs);
            }

            return true;
        }
        catch (Exception ex)
        {
            Logger.Warn($"Download failed [{url}]: {ex.Message}");
            return false;
        }
    }

    private static void ExtractRulesPack(string zipPath, string rulesDir)
    {
        Directory.CreateDirectory(rulesDir);
        var fullRulesDir = Path.GetFullPath(rulesDir);
        if (!fullRulesDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            fullRulesDir += Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
                continue;

            var dest = Path.GetFullPath(Path.Combine(rulesDir, entry.FullName));
            if (!dest.StartsWith(fullRulesDir, StringComparison.OrdinalIgnoreCase))
            {
                Logger.Warn($"Zip slip blocked: {entry.FullName}");
                continue;
            }

            entry.ExtractToFile(dest, overwrite: true);
        }
    }

    private void TryUpdateClamAvDatabase()
    {
        if (!File.Exists(PathHelper.FreshClamExe))
            return;

        try
        {
            Report(LocalizationService.Get("UpdateDownloading"));
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = PathHelper.FreshClamExe,
                Arguments = $"--config-file=\"{PathHelper.FreshClamConf}\"",
                WorkingDirectory = PathHelper.ClamAvDir,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit(300_000);
            _scanner.ReloadClamAvDatabase();
        }
        catch (Exception ex)
        {
            Logger.Warn($"freshclam update skipped: {ex.Message}");
        }
    }

    private void Report(string message) => StatusChanged?.Invoke(message);

    public void Restart()
    {
        _weeklyTimer.Stop();
        Start();
    }

    public void Dispose()
    {
        _weeklyTimer.Stop();
        _weeklyTimer.Dispose();
        _http.Dispose();
    }

    private sealed class SignatureManifest
    {
        public string Version { get; set; } = "";
        public string? HashDbUrl { get; set; }
        public string? HashDbSha256 { get; set; }
        public string? RulesPackUrl { get; set; }
    }
}
