using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Public URLhaus-derived filter; fail closed if it is stale, malformed or unreachable.</summary>
public sealed class MaliciousDomainFeed : IDisposable
{
    // Official URLhaus bulk exports currently require authentication; this public redistribution is not independently signed.
    private const string Source = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt";
    private readonly HttpClient http = new(new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None })
        { Timeout = TimeSpan.FromSeconds(12) };
    private MaliciousDomainIntelligence.Snapshot? active;
    private DateTimeOffset nextCheck;
    private string message = "No domain intelligence retrieved";
    public MaliciousDomainIntelligence.Snapshot? Active
    {
        get
        {
            var value = Volatile.Read(ref active);
            return value != null && MaliciousDomainIntelligence.IsFresh(value, DateTimeOffset.UtcNow) ? value : null;
        }
    }
    public string Status => Active is { } feed
        ? $"Public URLhaus-derived mirror: {feed.Domains.Count} current exact hostnames; timestamp {feed.UpdatedUtc:O}; unsigned, observe-only by default"
        : "Domain intelligence unavailable/stale: " + message;
    public bool IsListed(string name)
    {
        var intel = Active;
        return intel != null && intel.Domains.Contains(name.Trim().TrimEnd('.'));
    }
    public async Task RefreshIfDueAsync(CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow < nextCheck) return;
        nextCheck = DateTimeOffset.UtcNow.AddMinutes(30);
        try
        {
            using var result = await http.GetAsync(Source, HttpCompletionOption.ResponseHeadersRead, ct);
            if (result.StatusCode != HttpStatusCode.OK) throw new InvalidDataException("Domain mirror HTTP " + (int)result.StatusCode);
            if (result.Content.Headers.ContentLength is long size && size > 1_000_000) throw new InvalidDataException("Domain mirror exceeds size budget");
            await using var stream = await result.Content.ReadAsStreamAsync(ct);
            using var body = new MemoryStream();
            byte[] chunk = new byte[8192]; int n;
            while ((n = await stream.ReadAsync(chunk, ct)) != 0)
            {
                if (body.Length + n > 1_000_000) throw new InvalidDataException("Domain mirror exceeds streaming budget");
                body.Write(chunk, 0, n);
            }
            var bytes = body.ToArray();
            var feed = MaliciousDomainIntelligence.Parse(new UTF8Encoding(false, true).GetString(bytes));
            if (!MaliciousDomainIntelligence.IsFresh(feed, DateTimeOffset.UtcNow) || feed.Domains.Count < 10)
                throw new InvalidDataException("Domain mirror is stale, unexpectedly small or has a future publication time");
            Volatile.Write(ref active, feed);
            message = $"HTTPS fetch verified format/time; body SHA-256 {Convert.ToHexString(SHA256.HashData(bytes))}; not cryptographically authenticated";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or TaskCanceledException or DecoderFallbackException)
        {
            Volatile.Write(ref active, null);
            message = Wire.Clean(ex.Message, 256);
        }
    }
    public void Dispose() => http.Dispose();
}

/// <summary>Administrator-authorized exact-hostname sinkhole with an owned reversible hosts section.</summary>
public sealed class DomainHostsProtection
{
    private readonly string hosts;
    private readonly EventStore? events;
    private readonly object gate = new();
    private bool applied;
    private string evidence = "No managed hosts block installed";
    public bool Applied { get { lock (gate) return applied; } }
    public string Status { get { lock (gate) return evidence; } }
    public DomainHostsProtection(EventStore? events, string? hostsFile = null)
    {
        this.events = events;
        hosts = hostsFile ?? Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
    }
    private string Read()
    {
        var info = new FileInfo(hosts);
        if (!info.Exists || info.Length > 1024 * 1024 || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Hosts file missing, linked or above safety budget");
        // Fail rather than silently corrupt a hosts file in an unsupported encoding.
        return new UTF8Encoding(false, true).GetString(File.ReadAllBytes(hosts));
    }
    private void Write(string expected, string replacement)
    {
        var directory = Path.GetDirectoryName(hosts)!;
        if ((new DirectoryInfo(directory).Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Linked hosts directory rejected");
        var temp = Path.Combine(directory, "ots-hosts-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(temp, replacement, new UTF8Encoding(false));
            if (Read() != expected) throw new IOException("Hosts file changed during a managed transaction");
            File.Replace(temp, hosts, null, true);
            if (Read() != replacement) throw new IOException("Hosts file replacement failed validation");
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public void Enable(MaliciousDomainIntelligence.Snapshot? feed)
    {
        lock (gate)
        {
            if (feed == null || !MaliciousDomainIntelligence.IsFresh(feed, DateTimeOffset.UtcNow))
                throw new InvalidOperationException("Fresh validated domain data required; no blocks installed");
            if (applied) return;
            string[] allowlist = [];
            var file = Paths.At("domain-allowlist.txt");
            if (File.Exists(file))
            {
                var content = File.ReadAllText(file);
                if (content.Length > 32_768) throw new InvalidDataException("Domain allowlist too large");
                allowlist = content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(x => !x.StartsWith('#')).ToArray();
            }
            var current = Read();
            if (current.Contains(ManagedHostsSection.Begin, StringComparison.Ordinal))
                throw new IOException("Previous OTS hosts region exists; restore it before applying another block");
            string updated = ManagedHostsSection.Apply(current, feed.Domains, allowlist, 1000);
            Write(current, updated);
            applied = true;
            evidence = $"Opt-in: {Math.Min(1000, feed.Domains.Count)} or fewer exact hostnames sinkholed; unsigned mirror; cache/DoH may bypass; rollback on OFF";
            events?.Add(75, "Info", "Domain sinkhole enabled", "Administrator explicitly enabled the owned Windows hosts block; DNS-over-HTTPS and subdomains may bypass");
        }
    }
    public void Restore()
    {
        lock (gate)
        {
            if (!File.Exists(hosts))
            {
                applied = false;
                evidence = "Windows hosts file absent; no OTS domain blocks remain";
                return;
            }
            var current = Read();
            var clean = ManagedHostsSection.Remove(current);
            if (current != clean)
            {
                Write(current, clean);
                events?.Add(75, "Info", "Domain sinkhole removed", "OTS-owned entries removed; unrelated hosts lines preserved");
            }
            applied = false;
            evidence = "No managed hosts block installed";
        }
    }
}
