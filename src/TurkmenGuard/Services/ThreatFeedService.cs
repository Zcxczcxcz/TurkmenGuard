using TurkmenGuard.Core;

namespace TurkmenGuard.Services;

public enum ThreatSource
{
    Scan,
    RealTime,
    ProcessMonitor,
    Scheduled
}

public class ThreatFeedEntry
{
    public string Id { get; init; } = Guid.NewGuid().ToString();
    public ThreatInfo Threat { get; init; } = new();
    public ThreatSource Source { get; init; }
    public string ActionTaken { get; set; } = "";
    public DateTime DetectedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Unified live threat feed for Scan UI — all sources (scan, RT, process monitor).
/// </summary>
public class ThreatFeedService
{
    private readonly object _lock = new();
    private readonly List<ThreatFeedEntry> _entries = [];
    private const int MaxEntries = 500;

    public event Action? FeedChanged;

    public IReadOnlyList<ThreatFeedEntry> Entries
    {
        get { lock (_lock) return _entries.ToList(); }
    }

    public ThreatFeedEntry Add(ThreatInfo threat, ThreatSource source, string actionTaken = "")
    {
        lock (_lock)
        {
            var key = $"{threat.FilePath}|{threat.ThreatName}";
            var recent = _entries.FirstOrDefault(e =>
                string.Equals($"{e.Threat.FilePath}|{e.Threat.ThreatName}", key, StringComparison.OrdinalIgnoreCase) &&
                (DateTime.UtcNow - e.DetectedAt).TotalSeconds < 45);
            if (recent != null)
            {
                if (!string.IsNullOrWhiteSpace(actionTaken) &&
                    recent.ActionTaken.IndexOf(actionTaken, StringComparison.OrdinalIgnoreCase) < 0)
                    recent.ActionTaken = string.IsNullOrWhiteSpace(recent.ActionTaken)
                        ? actionTaken
                        : $"{recent.ActionTaken}; {actionTaken}";
                FeedChanged?.Invoke();
                return recent;
            }

            var entry = new ThreatFeedEntry
            {
                Threat = threat,
                Source = source,
                ActionTaken = actionTaken
            };
            _entries.Insert(0, entry);
            while (_entries.Count > MaxEntries)
                _entries.RemoveAt(_entries.Count - 1);
            FeedChanged?.Invoke();
            return entry;
        }
    }

    public void UpdateAction(string entryId, string action)
    {
        lock (_lock)
        {
            var entry = _entries.FirstOrDefault(e => e.Id == entryId);
            if (entry == null) return;
            entry.ActionTaken = string.IsNullOrWhiteSpace(entry.ActionTaken)
                ? action
                : $"{entry.ActionTaken}; {action}";
            FeedChanged?.Invoke();
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
            FeedChanged?.Invoke();
        }
    }
}
