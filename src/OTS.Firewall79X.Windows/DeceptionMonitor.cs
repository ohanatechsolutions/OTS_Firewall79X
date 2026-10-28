using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>
/// Section B: local-only deception service. No remote listener, real credentials,
/// outbound canary callback, traffic interception, or automatic firewall ban.
/// </summary>
public sealed class DeceptionMonitor : IDisposable
{
    private const int MaxRequestBytes = 2048;
    private const int MaxConcurrentClients = 6;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(2);
    private readonly EventStore events;
    private readonly string folder;
    private readonly string credentials;
    private readonly string urlFile;
    private readonly string dnsFile;
    private readonly string ownershipFile;
    private readonly Dictionary<string, string> expected = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> lastAlert = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTimeOffset> recentConnections = new();
    private readonly object sync = new();
    private readonly CancellationTokenSource stop = new();
    private readonly SemaphoreSlim slots = new(MaxConcurrentClients);
    private readonly TcpListener listener;
    private readonly FileSystemWatcher watcher;
    private readonly Task server;
    private readonly Task verifier;
    private readonly string pathToken;
    private readonly FileSystemAuditRule auditRule = new(
        new SecurityIdentifier(WellKnownSidType.WorldSid, null),
        FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.Delete,
        AuditFlags.Success);
    private volatile bool watcherError;
    private bool disposed;
    private bool auditReady;
    private string auditStatus = "Audit configuration not attempted";
    private int auditedReads;
    private int canaryHits;
    private int decoyHits;
    private int dnsHits;

    public int Port { get; }
    public string DnsCanary { get; }
    public string CanaryPath => "/canary/" + pathToken;
    public bool FileMonitorHealthy => !disposed && !watcherError
        && watcher.EnableRaisingEvents && !verifier.IsFaulted && !verifier.IsCompleted;
    public bool ListenerHealthy => !disposed && !server.IsFaulted && !server.IsCompleted;
    public bool AuditReady => auditReady;
    public string AuditStatus => auditStatus;
    public int AuditedReads => Volatile.Read(ref auditedReads);
    public int CanaryHits => Volatile.Read(ref canaryHits);
    public int DecoyHits => Volatile.Read(ref decoyHits);
    public int DnsHits => Volatile.Read(ref dnsHits);

    public DeceptionMonitor(EventStore events)
    {
        this.events = events;
        folder = Paths.At("canaries");
        Paths.SecureDirectory(folder);
        credentials = Path.Combine(folder, "decoy-credentials.txt");
        urlFile = Path.Combine(folder, "canary-url.txt");
        dnsFile = Path.Combine(folder, "canary-dns.txt");
        ownershipFile = Path.Combine(folder, "audit-ownership.txt");

        // Prepare a strictly loopback endpoint first. Bind failures are real startup errors.
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(8);
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        pathToken = Guid.NewGuid().ToString("N");

        try
        {
            if (!File.Exists(credentials))
                File.WriteAllText(credentials,
                    "OTS Firewall79X HONEYTOKEN - not valid for any service.\n" +
                    "username=OTS-CANARY-NONFUNCTIONAL\npassword=NOT-A-REAL-CREDENTIAL\n");
            // URL is regenerated because the loopback port is assigned dynamically.
            File.WriteAllText(urlFile, $"http://127.0.0.1:{Port}{CanaryPath}\n");
            if (!File.Exists(dnsFile))
                File.WriteAllText(dnsFile, "ots-" + Guid.NewGuid().ToString("N") + ".invalid\n");
            string hostname = File.ReadAllText(dnsFile).Trim();
            if (!DeceptionRules.IsGeneratedCanaryDnsName(hostname))
            {
                events.Add(11, "High", "Canary DNS file tampered",
                    "Unexpected DNS canary format; replacing only the owned decoy value");
                hostname = "ots-" + Guid.NewGuid().ToString("N") + ".invalid";
                File.WriteAllText(dnsFile, hostname + "\n");
            }
            DnsCanary = hostname;

            foreach (string file in new[] { credentials, urlFile, dnsFile })
                expected[file] = Digest(file);
            TryConfigureNarrowFileAudit();

            watcher = new FileSystemWatcher(folder)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                IncludeSubdirectories = false
            };
            watcher.Changed += OnFileChange;
            watcher.Created += OnFileChange;
            watcher.Deleted += OnFileChange;
            watcher.Renamed += (_, e) =>
            {
                if (expected.ContainsKey(e.OldFullPath))
                    EmitOnce(11, "High", "Canary renamed", Path.GetFileName(e.OldFullPath));
                CheckIntegrity(e.FullPath);
            };
            watcher.Error += (_, e) =>
            {
                watcherError = true;
                events.Add(11, "High", "Canary watcher unavailable",
                    Wire.Clean(e.GetException().Message, 160));
            };
            watcher.EnableRaisingEvents = true;
            server = ServeAsync(stop.Token);
            verifier = VerifyPeriodicallyAsync(stop.Token);
        }
        catch
        {
            listener.Stop();
            stop.Cancel();
            throw;
        }
    }

    private static string Digest(string file)
    {
        var info = new FileInfo(file);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            return "REPARSE_POINT";
        if (info.Length > 64 * 1024) return "OVERSIZE";
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private void EmitOnce(int layer, string severity, string kind, string detail,
        int throttleSeconds = 20)
    {
        string key = layer + ":" + kind + ":" + detail;
        lock (sync)
        {
            var now = DateTimeOffset.UtcNow;
            if (lastAlert.TryGetValue(key, out var last) && now - last < TimeSpan.FromSeconds(throttleSeconds)) return;
            if (lastAlert.Count >= 1024) lastAlert.Clear();
            lastAlert[key] = now;
        }
        events.Add(layer, severity, kind, Wire.Clean(detail, 200));
    }

    private void OnFileChange(object? sender, FileSystemEventArgs e) => CheckIntegrity(e.FullPath);

    private void CheckIntegrity(string fullPath)
    {
        if (disposed || !expected.TryGetValue(fullPath, out var baseline)) return;
        try
        {
            if (!File.Exists(fullPath))
            {
                EmitOnce(11, "High", "Canary removed", Path.GetFileName(fullPath));
                return;
            }
            if (Digest(fullPath) != baseline)
                EmitOnce(11, "High", "Canary content tampered", Path.GetFileName(fullPath));
        }
        catch (IOException) { /* A concurrent write can be transient; the verifier retries. */ }
        catch (UnauthorizedAccessException)
        {
            EmitOnce(11, "High", "Canary verification denied", Path.GetFileName(fullPath));
        }
    }

    private async Task VerifyPeriodicallyAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
                foreach (string path in expected.Keys) CheckIntegrity(path);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            watcherError = true;
            events.Add(11, "High", "Canary verification failed", Wire.Clean(ex.Message, 160));
        }
    }

    // Requires the existing Windows Audit File System success policy; never enables
    // system-wide auditing. The SACL is installed only on our three owned decoy files.
    private void TryConfigureNarrowFileAudit()
    {
        try
        {
            if (!AuditPolicy.Coverage(31).Enabled)
            {
                auditStatus = "Windows Audit File System successes disabled; reads unavailable";
                return;
            }

            // The recovery marker lets a new service instance remove its exact audit
            // entries after a crash. No other file, folder, or global audit policy changes.
            var owned = File.Exists(ownershipFile)
                ? File.ReadAllLines(ownershipFile).ToHashSet(StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in expected.Keys)
            {
                var file = new FileInfo(path);
                var security = file.GetAccessControl(AccessControlSections.Audit);
                bool exists = security.GetAuditRules(true, false, typeof(SecurityIdentifier))
                    .OfType<FileSystemAuditRule>()
                    .Any(r => r.IdentityReference.Equals(auditRule.IdentityReference)
                        && r.FileSystemRights == auditRule.FileSystemRights
                        && r.AuditFlags == auditRule.AuditFlags);
                if (!exists)
                {
                    // Persist intent before the protected SACL write for crash recovery.
                    owned.Add(path);
                    File.WriteAllLines(ownershipFile, owned);
                    security.AddAuditRule(auditRule);
                    file.SetAccessControl(security);
                }
            }
            auditReady = true;
            auditStatus = "Narrow canary-file SACL installed; Windows Security 4663 attribution conditional on emitted events";
        }
        catch (Exception ex)
        {
            auditReady = false;
            auditStatus = "Windows file-read auditing unavailable: " + Wire.Clean(ex.Message, 130);
            events.Add(11, "Warning", "Canary read-audit unavailable", auditStatus);
        }
    }

    /// <summary>Only accepts actual Windows Security Event 4663 file evidence.</summary>
    public void ObserveFileAudit(string? objectType, string? path, string? mask,
        string? processName, string? processId, string? user)
    {
        if (disposed || !auditReady || path is null) return;
        if (!expected.ContainsKey(path)) return;
        var access = DeceptionRules.ClassifyFileAudit(objectType, path, path, mask);
        if (!access.Read && !access.Changed) return;

        // Suppress only this service's own necessary file reads; never hide other
        // SYSTEM processes merely because they run with the same identity.
        var pidText = processId?.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true
            ? processId[2..] : processId;
        if (uint.TryParse(pidText, System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out var pid)
            && pid == Environment.ProcessId) return;

        var exe = Wire.Clean(Path.GetFileName(processName ?? ""), 80);
        string detail = $"{Path.GetFileName(path)}; process={exe}; pid={Wire.Clean(processId, 18)}; " +
            $"account={Wire.Clean(user, 64)}; observed Windows Security 4663";
        if (access.Read)
        {
            Interlocked.Increment(ref auditedReads);
            EmitOnce(11, "High", "Audited canary file read", detail, 60);
        }
        if (access.Changed)
            EmitOnce(11, "High", "Audited canary file modification", detail, 60);
    }

    /// <summary>Match an actual DNS-Client event, not a guess about remote DNS.</summary>
    public void ObserveDnsQuery(string? query)
    {
        if (disposed || !DeceptionRules.IsCanaryDnsQuery(query, DnsCanary)) return;
        Interlocked.Increment(ref dnsHits);
        EmitOnce(12, "High", "Local DNS canary queried",
            $"Windows DNS Client observed lookup of {DnsCanary}; no external visibility claimed", 60);
    }

    private async Task ServeAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                bool permitted;
                lock (sync)
                {
                    var now = DateTimeOffset.UtcNow;
                    while (recentConnections.Count > 0
                        && recentConnections.Peek() < now.AddMinutes(-1))
                        recentConnections.Dequeue();
                    permitted = recentConnections.Count < 120;
                    if (permitted) recentConnections.Enqueue(now);
                }
                if (!permitted)
                {
                    client.Dispose();
                    EmitOnce(13, "Warning", "Honeypot connection-rate limit",
                        "Loopback decoy rejected traffic beyond 120 requests per minute", 60);
                    continue;
                }
                if (!slots.Wait(0))
                {
                    client.Dispose();
                    EmitOnce(13, "Warning", "Honeypot concurrency limit",
                        "Decoy rejected a connection above its six-client limit", 60);
                    continue;
                }
                _ = HandleClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (ct.IsCancellationRequested) { }
        catch (SocketException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            EmitOnce(13, "High", "Decoy listener stopped", Wire.Clean(ex.Message, 120), 60);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(RequestTimeout);
                var stream = client.GetStream();
                var buffer = new byte[MaxRequestBytes];
                int count = 0;
                while (count < buffer.Length)
                {
                    int next = await stream.ReadAsync(buffer.AsMemory(count), timeout.Token);
                    if (next == 0) break;
                    count += next;
                    if (buffer.AsSpan(0, count).IndexOf((byte)'\n') >= 0) break;
                }
                var line = Encoding.ASCII.GetString(buffer, 0, count)
                    .Split('\n', 2)[0].TrimEnd('\r');
                bool canary = DeceptionRules.IsCanaryHttpRequest(line, CanaryPath);
                if (canary)
                {
                    Interlocked.Increment(ref canaryHits);
                    EmitOnce(12, "High", "Local canary URL contacted",
                        "A process requested the unique loopback canary path; not externally reachable", 20);
                }
                else
                {
                    Interlocked.Increment(ref decoyHits);
                    string remote = client.Client.RemoteEndPoint?.ToString() ?? "unavailable";
                    string attribution = ClientAttribution(client);
                    EmitOnce(13, "Warning", "Decoy service connection",
                        $"Loopback-only listener {Port}; peer {Wire.Clean(remote, 64)}; {attribution}; no remote intrusion claimed", 20);
                }
                // Static, nonfunctional response; never execute client input or reflect it.
                var response = canary
                    ? "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
                    : "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), timeout.Token);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (OperationCanceledException)
        {
            EmitOnce(13, "Info", "Decoy connection timed out",
                "A loopback client exceeded the two-second request budget", 60);
        }
        catch (IOException) { /* Peer closed the connection; the accept loop stays alive. */ }
        catch (SocketException) { /* Peer closed the connection. */ }
        catch (Exception ex) { EmitOnce(13, "Warning", "Decoy request failure", Wire.Clean(ex.Message, 120)); }
        finally { try { slots.Release(); } catch (ObjectDisposedException) { } }
    }

    private string ClientAttribution(TcpClient client)
    {
        try
        {
            if (client.Client.RemoteEndPoint is not IPEndPoint peer)
                return "owning process unavailable";
            // Best-effort native IP Helper snapshot. Never infer an owner when
            // the exact client-local and decoy-remote TCP ports do not match.
            var owner = NetworkTables.Connections().FirstOrDefault(c =>
                c.State == "Established"
                && c.Local.EndsWith("]:" + peer.Port, StringComparison.Ordinal)
                && c.Remote.EndsWith("]:" + Port, StringComparison.Ordinal));
            return owner == null
                ? "owning process unavailable (connection may be short-lived)"
                : $"observed PID {owner.Pid}; process={Wire.Clean(owner.Process, 64)}";
        }
        catch { return "owning process unavailable (IP Helper query failed)"; }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        stop.Cancel();
        listener.Stop();
        watcher.Dispose();
        try { Task.WaitAll(new[] { server, verifier }, TimeSpan.FromSeconds(3)); }
        catch (AggregateException) { /* Best-effort cancellation; never block OFF. */ }

        // Compare before restoring only the exact canary audit entries we own.
        try
        {
            if (File.Exists(ownershipFile))
            {
                foreach (var path in File.ReadAllLines(ownershipFile))
                {
                    if (!expected.ContainsKey(path) || !File.Exists(path)) continue;
                    var file = new FileInfo(path);
                    var security = file.GetAccessControl(AccessControlSections.Audit);
                    security.RemoveAuditRuleSpecific(auditRule);
                    file.SetAccessControl(security);
                }
                File.Delete(ownershipFile);
            }
        }
        catch (Exception ex)
        {
            events.Add(11, "Warning", "Canary audit rollback incomplete",
                "The service could not remove its owned canary audit rule: " + Wire.Clean(ex.Message, 120));
        }
        stop.Dispose();
        slots.Dispose();
    }
}
