using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OTS.Firewall79X.Core;

// An accidental-corruption checksum, NOT a publisher signature or protection against a local administrator.
public sealed record EvidenceEnvelope(int Version, DateTimeOffset CapturedUtc, string Sha256, Dashboard Data);
public static class ForensicSnapshots
{
    public static string Capture(string directory, Dashboard data, int maxRetained = 20)
    {
        if (maxRetained < 1 || maxRetained > 100) throw new ArgumentOutOfRangeException(nameof(maxRetained));
        Directory.CreateDirectory(directory);
        var payload = JsonSerializer.SerializeToUtf8Bytes(data, Wire.Json);
        if (payload.Length > 3 * 1024 * 1024) throw new InvalidDataException("Forensic snapshot exceeds 3 MiB");
        var envelope = new EvidenceEnvelope(1, DateTimeOffset.UtcNow, Convert.ToHexString(SHA256.HashData(payload)), data);
        var target = Path.Combine(directory, $"forensic-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fffffff}-{Guid.NewGuid():N}.json");
        var temp = target + ".partial";
        try
        {
            using (var f = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(f, envelope, Wire.Json);
                f.Flush(true);
            }
            Verify(temp);
            File.Move(temp, target);
            // Retain damaged evidence rather than silently deleting it. Only verified older snapshots expire.
            foreach (var old in Directory.EnumerateFiles(directory, "forensic-*.json")
                         .OrderByDescending(Path.GetFileName, StringComparer.Ordinal).Skip(maxRetained))
            {
                try { Verify(old); File.Delete(old); }
                catch (InvalidDataException) { /* preserve corrupted evidence for investigation */ }
            }
            return target;
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    public static EvidenceEnvelope Verify(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (f.Length > 4 * 1024 * 1024) throw new InvalidDataException("Snapshot size exceeds limit");
        EvidenceEnvelope envelope;
        try { envelope = JsonSerializer.Deserialize<EvidenceEnvelope>(f, Wire.Json) ?? throw new InvalidDataException("Empty evidence"); }
        catch (JsonException ex) { throw new InvalidDataException("Malformed evidence JSON", ex); }
        if (envelope.Version != 1 || envelope.Data is null) throw new InvalidDataException("Unsupported evidence format");
        var actual = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(envelope.Data, Wire.Json));
        if (!Convert.ToHexString(actual).Equals(envelope.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Evidence checksum mismatch");
        return envelope;
    }
}

public sealed record DailyPosture(DateTimeOffset RecordedUtc, int Score, double Confidence, long Events, long Blocks,
    int HealthyLayers = 0, int UnavailableLayers = 0, int RecentHighAlerts = 0, string[]? Recommendations = null);
public static class QuarterlyHistory
{
    public static DateTimeOffset QuarterStart(DateTimeOffset when)
        => new(when.Year, ((when.Month - 1) / 3) * 3 + 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static IReadOnlyList<DailyPosture> Load(string path)
    {
        if (!File.Exists(path)) return [];
        var info = new FileInfo(path);
        if (info.Length > 1024 * 1024) throw new InvalidDataException("Posture history is oversized");
        var data = JsonSerializer.Deserialize<List<DailyPosture>>(File.ReadAllText(path), Wire.Json)
                   ?? throw new InvalidDataException("Missing history");
        if (data.Count > 500 || data.Any(d => d.Score is < 0 or > 100 || d.Confidence is < 0 or > 100
                      || double.IsNaN(d.Confidence) || d.Events < 0 || d.Blocks < 0 || d.HealthyLayers < 0 || d.HealthyLayers > 79 || d.UnavailableLayers < 0 || d.UnavailableLayers > 79 || d.RecentHighAlerts < 0 || d.Recommendations?.Length > 5))
            throw new InvalidDataException("Invalid stored posture sample");
        return data.OrderBy(x => x.RecordedUtc).ToArray();
    }

    public static void Observe(string path, Dashboard d)
    {
        if (!d.Enabled) return;
        var prior = Load(path).ToList();
        var date = d.Time.UtcDateTime.Date;
        // A single day's last completed observation replaces that day's previous sample.
        prior.RemoveAll(x => x.RecordedUtc.UtcDateTime.Date == date);
        prior.Add(new DailyPosture(d.Time.ToUniversalTime(), d.Score, d.Confidence, d.TotalEvents, d.BlockedEvents,
            d.Layers.Count(x => x.Healthy), d.Layers.Count(x => x.Mode == LayerMode.Unavailable),
            d.Events.Count(x => x.Severity is "High" or "Critical"),
            PostureAdvice.Recommend(d.Layers, 5).ToArray()));
        var history = prior.OrderBy(x => x.RecordedUtc).TakeLast(400).ToList();
        AtomicFile.Write(path, JsonSerializer.Serialize(history, Wire.Json));
    }

    public static string Generate(DateTimeOffset quarter, IEnumerable<DailyPosture> all)
    {
        var start = QuarterStart(quarter);
        var end = start.AddMonths(3);
        var samples = all.Where(s => s.RecordedUtc >= start && s.RecordedUtc < end).OrderBy(s => s.RecordedUtc).ToArray();
        if (samples.Length == 0) throw new InvalidOperationException("A report needs actual samples");
        var b = new StringBuilder();
        b.AppendLine("# OTS Firewall79X quarterly posture history");
        b.AppendLine($"Period: {start:yyyy-MM-dd} through {end.AddDays(-1):yyyy-MM-dd} UTC");
        b.AppendLine($"Observed days: {samples.Length}; gaps are not extrapolated.");
        b.AppendLine($"Capability score (observed days): min {samples.Min(x => x.Score)}, max {samples.Max(x => x.Score)}, mean {samples.Average(x => x.Score):F1}/100.");
        b.AppendLine($"Mean telemetry confidence: {samples.Average(x => x.Confidence):F1}%. Not a security effectiveness probability.");
        b.AppendLine("Event counters are observations from the current service store; no inferred cross-restart deltas.");
        b.AppendLine();
        b.AppendLine("| UTC day | Capability score | Confidence | Healthy layers | Unavailable layers | Recent high/critical alerts* | Event counter | OTS block counter |");
        b.AppendLine("|---|---:|---:|---:|---:|---:|---:|---:|");
        foreach (var sample in samples)
            b.AppendLine($"| {sample.RecordedUtc:yyyy-MM-dd} | {sample.Score} | {sample.Confidence:F1}% | {sample.HealthyLayers} | {sample.UnavailableLayers} | {sample.RecentHighAlerts} | {sample.Events} | {sample.Blocks} |");
        b.AppendLine("\n*Alerts are those visible in each sampled dashboard window, not an authoritative quarterly total.");
        b.AppendLine("\n## Recommended improvements at last observed sample");
        foreach (var recommendation in samples[^1].Recommendations ?? []) b.AppendLine("- " + Wire.Clean(recommendation, 200));
        b.AppendLine("\nMissing days, unavailable sensors, optional capabilities, and hardware-specific limits require direct review. Historical scores do not certify protection.");
        return b.ToString();
    }

    // Executes after reboot as soon as the monitoring engine next runs, including missed quarter boundaries.
    public static IReadOnlyList<string> CreateDue(string historyPath, string reportDirectory, DateTimeOffset now)
    {
        var history = Load(historyPath);
        var current = QuarterStart(now);
        Directory.CreateDirectory(reportDirectory);
        List<string> created = [];
        foreach (var quarter in history.Select(s => QuarterStart(s.RecordedUtc)).Distinct().Order().Where(q => q < current).TakeLast(8))
        {
            string target = Path.Combine(reportDirectory, $"quarter-{quarter:yyyy}-Q{(quarter.Month + 2) / 3}.md");
            if (File.Exists(target)) continue;
            AtomicFile.Write(target, Generate(quarter, history));
            created.Add(target);
        }
        return created;
    }
}

public static class PostureAdvice
{
    public static IReadOnlyList<string> Recommend(IEnumerable<LayerResult> layers, int max = 12)
        => layers.Where(l => !l.Healthy || l.Mode is LayerMode.Unavailable or LayerMode.Idle)
            .OrderByDescending(l => Posture.Weight(l.Id)).ThenBy(l => l.Id)
            .Take(max).Select(l =>
            {
                var name = Catalog.All.FirstOrDefault(c => c.Id == l.Id)?.Name ?? "Unknown";
                return $"Layer {l.Id} ({name}): {Wire.Clean(l.Evidence, 180)}; mode={l.Mode}.";
            }).ToArray();
}

public static class SecurityDossier
{
    public static string Generate(Dashboard d)
    {
        var b = new StringBuilder();
        b.AppendLine("# OTS Firewall79X — operational security documentation");
        b.AppendLine($"Generated from observed service state: {d.Time:O}");
        b.AppendLine($"Application enabled: {d.Enabled}; protection label: {d.Protection}.");
        b.AppendLine($"Capability score: {d.Score}/100; checked-sensor confidence: {d.Confidence:F1}%. These are not claims of threat immunity.");
        b.AppendLine($"Confirmed OTS blocks: {d.BlockedEvents}; observed events: {d.TotalEvents}. Source: active service status.");
        b.AppendLine("\n## Priority review items");
        foreach (var recommendation in PostureAdvice.Recommend(d.Layers)) b.AppendLine("- " + recommendation);
        b.AppendLine("\n## Transparent scoring breakdown");
        b.AppendLine("Weight 3: layers 1, 6, 46, 53, 55, 57, 59, 65 and 76. All other layers: weight 1.");
        b.AppendLine("Unavailable and idle layers receive no points; Not Applicable excludes a verified non-applicable capability; monitoring is not blocking.");
        b.AppendLine("The per-category figures are capability-health summaries, NOT independent exposure ratings.");
        b.AppendLine("| Category | Score | Applicable weight | Healthy weight | Unavailable or idle |");
        b.AppendLine("|---|---:|---:|---:|---:|");
        foreach (var category in Catalog.All.GroupBy(x => x.Category))
        {
            var list = category.Select(def => d.Layers.FirstOrDefault(x => x.Id == def.Id)
                ?? new LayerResult(def.Id,LayerMode.Unavailable,false,"No observation")).ToArray();
            var included = list.Where(x => x.Mode != LayerMode.NotApplicable).ToArray();
            int possible = included.Sum(x => Posture.Weight(x.Id));
            int good = included.Where(x => x.Healthy && x.Mode is LayerMode.Enforcing or LayerMode.Monitoring or LayerMode.Auditing)
                               .Sum(x => Posture.Weight(x.Id));
            int misses = included.Count(x => x.Mode is LayerMode.Idle or LayerMode.Unavailable);
            b.AppendLine($"| {category.Key.Replace("|","/")} | {(possible == 0 ? "Not Applicable" : Math.Round(100.0*good/possible).ToString("F0")+"%")} | {possible} | {good} | {misses} |");
        }
        b.AppendLine("\n## Catalog and live capability evidence");
        b.AppendLine("| ID | Layer | Category | Mode | Healthy within declared limits | Last checked (UTC) | Evidence | Limits |");
        b.AppendLine("|---|---|---|---|---|---|---|---|");
        foreach (var def in Catalog.All)
        {
            var s = d.Layers.FirstOrDefault(x => x.Id == def.Id);
            string esc(string? x) => Wire.Clean(x).Replace("|", "\\|").Replace("\n", " ");
            b.AppendLine($"| {def.Id} | {esc(def.Name)} | {esc(def.Category)} | {s?.Mode.ToString() ?? "Unavailable"} | {s?.Healthy == true} | {s?.CheckedAt?.ToString("O") ?? "Never"} | {esc(s?.Evidence ?? "No result")} | {esc(s?.Limitation ?? "Missing observation")} |");
        }
        b.AppendLine("\n## Evidence provenance and limitations");
        b.AppendLine("Entries are readings from locally available Windows sensors and program self-reporting; this document is not an independently verified penetration test or system attestation.");
        b.AppendLine("Not Applicable and Unavailable must not be interpreted as enabled protection. A monitoring-only layer is not an enforcing layer.");
        b.AppendLine("Missing Windows audits, privileges, drivers, updates, or supported hardware can reduce visibility. See LAYER_COVERAGE.md and KNOWN_LIMITATIONS.md for declared gaps.");
        b.AppendLine("No arbitrary recovery action or change to third-party firewall settings is performed by documentation generation.");
        return b.ToString();
    }
}
