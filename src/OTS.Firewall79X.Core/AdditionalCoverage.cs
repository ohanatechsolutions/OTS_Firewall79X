using System.Globalization;
using System.Text.RegularExpressions;

namespace OTS.Firewall79X.Core;

/// <summary>Strict parser for a dated URLhaus-format host list. Format validation is not feed signing.</summary>
public static class MaliciousDomainIntelligence
{
    public sealed record Snapshot(DateTimeOffset UpdatedUtc, IReadOnlySet<string> Domains, int Rejected);
    private static readonly Regex Timestamp = new(@"^#\s*Last updated:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\(UTC\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex OnlineTimestamp = new(@"^#\s*Updated:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    // Explicit exclusions are defense-in-depth, not a substitute for checking feed provenance.
    private static readonly string[] ProtectedSuffixes =
    ["microsoft.com","windows.com","windowsupdate.com","office.com","live.com","github.com","githubusercontent.com",
     "google.com","apple.com","icloud.com","amazonaws.com","cloudflare.com","localhost","local","internal","test","example","invalid"];
    public static bool ValidDomain(string? text)
    {
        if (text is null || text.Length is < 4 or > 253 || text != text.Trim() || text.EndsWith('.')) return false;
        if (text.Any(c => c > 127 || char.IsWhiteSpace(c))) return false;
        var parts = text.Split('.');
        if (parts.Length < 2 || parts.Any(p => p.Length is < 1 or > 63 || p[0] == '-' || p[^1] == '-' || p.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))) return false;
        if (parts[^1].Length < 2 || !parts[^1].Any(char.IsLetter)) return false;
        return !ProtectedSuffixes.Any(s => text.Equals(s, StringComparison.OrdinalIgnoreCase) || text.EndsWith("." + s, StringComparison.OrdinalIgnoreCase));
    }
    public static Snapshot Parse(string body)
    {
        if (body.Length is < 40 or > 1_000_000 ||
            !(body.Contains("abuse.ch URLhaus Host file", StringComparison.OrdinalIgnoreCase) ||
              (body.Contains("# Title: Online Malicious Hosts Blocklist", StringComparison.Ordinal) &&
               body.Contains("# Source: https://urlhaus.abuse.ch/api/", StringComparison.Ordinal))))
            throw new InvalidDataException("Unrecognized or oversized URLhaus format");
        DateTimeOffset? stamp = null;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int rejected = 0, lines = 0;
        foreach (var raw in body.Split('\n'))
        {
            if (++lines > 25000) throw new InvalidDataException("Domain feed line budget exceeded");
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('#'))
            {
                var match = Timestamp.Match(line);
                if (!match.Success) match = OnlineTimestamp.Match(line);
                if (match.Success)
                {
                    if (stamp != null) throw new InvalidDataException("Duplicate feed timestamp");
                    if (!DateTime.TryParseExact(match.Groups[1].Value, new[] { "yyyy-MM-dd HH:mm:ss", "yyyy-MM-ddTHH:mm:ssZ" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                        throw new InvalidDataException("Invalid feed timestamp");
                    stamp = new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc));
                }
                continue;
            }
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 2 || (fields[0] != "127.0.0.1" && fields[0] != "0.0.0.0") || !ValidDomain(fields[1])) { rejected++; continue; }
            names.Add(fields[1].ToLowerInvariant());
        }
        if (stamp is null || names.Count == 0 || rejected > Math.Max(20, names.Count / 10))
            throw new InvalidDataException("Missing publication time, empty data, or excessive invalid indicators");
        return new(stamp.Value, names, rejected);
    }
    public static bool IsFresh(Snapshot snap, DateTimeOffset now) => snap.UpdatedUtc <= now.AddMinutes(10) && now - snap.UpdatedUtc <= TimeSpan.FromHours(12);
}

/// <summary>Pure, conservative owned-section editing. Never alters lines owned by others.</summary>
public static class ManagedHostsSection
{
    public const string Begin = "# BEGIN OTS Firewall79X DOMAIN BLOCKS";
    public const string End = "# END OTS Firewall79X DOMAIN BLOCKS";
    private static string WithoutOwnedSection(string original)
    {
        if (original.Length > 1024 * 1024 || original.IndexOf('\0') >= 0) throw new InvalidDataException("Hosts file too large or binary");
        var normalized = original.Replace("\r\n", "\n");
        int start = normalized.IndexOf(Begin, StringComparison.Ordinal);
        int end = normalized.IndexOf(End, StringComparison.Ordinal);
        if (start < 0 && end < 0) return normalized;
        if (start < 0 || end < start || normalized.IndexOf(Begin, start + Begin.Length, StringComparison.Ordinal) >= 0
            || normalized.IndexOf(End, end + End.Length, StringComparison.Ordinal) >= 0)
            throw new InvalidDataException("Conflicting OTS hosts markers; manual recovery required");
        bool startsOnLine = start == 0 || normalized[start - 1] == '\n';
        int afterMarker = end + End.Length;
        bool endsOnLine = afterMarker == normalized.Length || normalized[afterMarker] == '\n';
        if (!startsOnLine || !endsOnLine) throw new InvalidDataException("Managed block markers are not independent lines");
        // Require that only expected sinkhole mappings are contained inside the managed section.
        string inside = normalized[(start + Begin.Length)..end];
        foreach (var candidate in inside.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = candidate.Trim();
            if (line.Length == 0) continue;
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || (parts[0] != "0.0.0.0" && parts[0] != "::") || !ValidManagedName(parts[1]))
                throw new InvalidDataException("OTS hosts region was modified externally");
        }
        int suffix = afterMarker < normalized.Length ? afterMarker + 1 : afterMarker;
        return normalized[..start] + normalized[suffix..];
    }
    private static bool ValidManagedName(string s) => MaliciousDomainIntelligence.ValidDomain(s);
    public static string Remove(string original)
    {
        if (!original.Contains(Begin, StringComparison.Ordinal) && !original.Contains(End, StringComparison.Ordinal))
            return original; // No ownership: byte-equivalent content must remain untouched.
        var clean = WithoutOwnedSection(original);
        return original.Contains("\r\n", StringComparison.Ordinal) ? clean.Replace("\n", "\r\n") : clean;
    }
    public static string Apply(string original, IEnumerable<string> requested, IEnumerable<string>? allowlist = null, int max = 1000)
    {
        if (max is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(max));
        var ignored = new HashSet<string>(allowlist ?? [], StringComparer.OrdinalIgnoreCase);
        if (ignored.Any(x => !MaliciousDomainIntelligence.ValidDomain(x))) throw new InvalidDataException("Invalid allowlist entry");
        var names = requested.Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(MaliciousDomainIntelligence.ValidDomain)
            .Where(x => !ignored.Any(a => x.Equals(a, StringComparison.OrdinalIgnoreCase) || x.EndsWith("." + a, StringComparison.OrdinalIgnoreCase)))
            .Order(StringComparer.Ordinal).Take(max).ToArray();
        if (names.Length == 0) throw new InvalidDataException("No validated domains after exclusions");
        string clean = WithoutOwnedSection(original);
        if (clean.Length > 900_000) throw new InvalidDataException("Hosts content exceeds safe edit budget");
        string extra = Begin + "\n" + string.Join("", names.Select(x => "0.0.0.0 " + x + "\n:: " + x + "\n")) + End + "\n";
        if (clean.Length > 0 && !clean.EndsWith('\n')) clean += "\n";
        string result = clean + extra;
        if (result.Length > 1024 * 1024) throw new InvalidDataException("Hosts file exceeds safe size");
        return original.Contains("\r\n", StringComparison.Ordinal) ? result.Replace("\n", "\r\n") : result;
    }
}

/// <summary>Distinct-file, rename and deletion focused ransomware telemetry; heuristic only.</summary>
public sealed class RansomwareActivity
{
    private readonly Queue<(DateTimeOffset Time, string Path, WatcherChangeTypes Kind)> events = new();
    private readonly Dictionary<string, DateTimeOffset> last = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset lastAlert;
    public bool Observe(string path, WatcherChangeTypes kind, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        while (events.Count > 0 && (now - events.Peek().Time).TotalSeconds > 15) events.Dequeue();
        if (last.TryGetValue(path, out var prior) && now - prior < TimeSpan.FromMilliseconds(750)) return false;
        last[path] = now;
        if (last.Count > 4096) last.Clear();
        events.Enqueue((now, path, kind));
        if (events.Count > 512) events.Dequeue();
        if (now - lastAlert < TimeSpan.FromMinutes(2)) return false;
        int distinct = events.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        int destructive = events.Count(e => e.Kind is WatcherChangeTypes.Renamed or WatcherChangeTypes.Deleted);
        if (distinct < 35 || destructive < 12) return false;
        lastAlert = now;
        return true;
    }
}

/// <summary>Conservative timing classifier. This is a traffic indicator, not a malicious verdict.</summary>
public static class BeaconAnalysis
{
    private static readonly HashSet<string> CommonBackground = new(StringComparer.OrdinalIgnoreCase)
    { "svchost", "system", "msedge", "chrome", "firefox", "onedrive", "teams", "outlook", "searchhost" };
    public static bool Suspicious(string process, IReadOnlyList<DateTimeOffset> times)
    {
        if (CommonBackground.Contains(process) || times.Count < 9) return false;
        var samples = times.TakeLast(16).ToArray();
        var gaps = samples.Zip(samples.Skip(1), (a, b) => (b-a).TotalSeconds).ToArray();
        if (gaps.Any(g => g <= 0)) return false;
        double mean = gaps.Average();
        if (mean < 30 || mean > 1800 || gaps.Sum() < 8*60) return false;
        var deviation = Math.Sqrt(gaps.Average(g => (g - mean)*(g - mean)));
        return deviation/mean < 0.12;
    }
}
