using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>
/// Explicit, administrator-configured resilience jobs. No remote copy or backup is scheduled by
/// default. The machine-DPAPI protected passphrase is readable only by the privileged service;
/// keep an independent copy of the passphrase for recovery on another machine.
/// </summary>
public sealed class ResilienceJobs
{
    private sealed record Profile(string Source, string Destination, string ProtectedPassphrase,
        DateTimeOffset? LastSuccessUtc = null, string? LastError = null);
    private sealed record Settings(Profile? Backup = null, Profile? Export = null, string[]? ObservedLogSegments = null);
    private readonly object gate = new();
    private readonly string settingsPath = Paths.At("resilience-jobs.json");
    private readonly string queue = Paths.At("log-export-queue");
    private readonly Action<int, string, string, string> eventSink;
    private Settings settings;
    private DateTimeOffset lastPulse = DateTimeOffset.MinValue;
    private const int MaxTrackedSegments = 512;

    public ResilienceJobs(Action<int, string, string, string> eventSink)
    {
        this.eventSink = eventSink;
        settings = Read();
    }

    private Settings Read()
    {
        if (!File.Exists(settingsPath)) return new Settings();
        if (new FileInfo(settingsPath).Length > 256 * 1024)
            throw new InvalidDataException("Resilience configuration exceeds size budget");
        var result = JsonSerializer.Deserialize<Settings>(File.ReadAllText(settingsPath), Wire.Json)
                     ?? throw new InvalidDataException("Invalid resilience configuration");
        if (result.ObservedLogSegments?.Length > MaxTrackedSegments)
            throw new InvalidDataException("Log source index outside size budget");
        return result;
    }

    private void Save() => AtomicFile.Write(settingsPath, JsonSerializer.Serialize(settings, Wire.Json));

    public void Configure(string kind, string? source, string? destination, string? passphrase)
    {
        if (kind is not ("backup" or "export")) throw new ArgumentException("Unknown job type");
        if (string.IsNullOrWhiteSpace(destination) || !OffDeviceLogExport.IsOffDeviceDestination(destination))
            throw new IOException("Select an existing, mounted removable or network folder. Fixed internal disks are not independent backup destinations.");
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length is < 12 or > 512)
            throw new ArgumentException("Set a recovery passphrase of 12–512 characters and preserve it independently.");
        string resolvedSource;
        if (kind == "backup")
        {
            resolvedSource = Path.GetFullPath(source ?? "");
            if (!Directory.Exists(resolvedSource)) throw new DirectoryNotFoundException("Backup source is unavailable");
            if (new DirectoryInfo(resolvedSource).Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Linked backup sources are not accepted");
        }
        else resolvedSource = Paths.At("logs");
        var dest = Path.GetFullPath(destination);
        if (dest.StartsWith(resolvedSource.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                            StringComparison.OrdinalIgnoreCase))
            throw new IOException("Destination cannot be under the protected source");
        var secretBytes = Encoding.UTF8.GetBytes(passphrase);
        string protectedSecret;
        try { protectedSecret = Convert.ToBase64String(ProtectedData.Protect(secretBytes, null, DataProtectionScope.LocalMachine)); }
        finally { CryptographicOperations.ZeroMemory(secretBytes); }
        lock (gate)
        {
            var current = new Profile(resolvedSource, dest, protectedSecret);
            // Reset the previously shipped-source index only when the external destination changes.
            settings = kind == "backup" ? settings with { Backup = current }
                     : settings with { Export = current,
                         ObservedLogSegments = settings.Export?.Destination.Equals(dest, StringComparison.OrdinalIgnoreCase) == true
                            ? settings.ObservedLogSegments : [] };
            Save();
        }
        eventSink(kind == "backup" ? 68 : 70, "Info", "Encrypted resilience job configured",
            "Optional scheduled job enabled with a separately recoverable passphrase. Plaintext credentials are not logged.");
    }

    public void Disable(string kind)
    {
        lock (gate)
        {
            if (kind == "backup") settings = settings with { Backup = null };
            else if (kind == "export") settings = settings with { Export = null };
            else throw new ArgumentException("Unknown job type");
            Save();
        }
        eventSink(kind == "backup" ? 68 : 70, "Info", "Optional resilience job disabled",
            "Previously generated encrypted archives and configuration evidence were not destroyed.");
    }

    public (bool Enabled, bool Healthy, string Summary) Status(string kind)
    {
        lock (gate)
        {
            var job = kind == "backup" ? settings.Backup : settings.Export;
            if (job == null) return (false, false, "Optional off-device job not configured");
            var age = job.LastSuccessUtc == null ? "Never completed" : "Last verified success " + job.LastSuccessUtc.Value.ToString("O");
            var failed = string.IsNullOrWhiteSpace(job.LastError) ? "" : "; last failure: " + Wire.Clean(job.LastError, 180);
            return (true, job.LastSuccessUtc != null && string.IsNullOrWhiteSpace(job.LastError),
                age + "; destination: external removable/network volume" + failed);
        }
    }

    private static string Reveal(Profile p)
    {
        byte[] encrypted = Convert.FromBase64String(p.ProtectedPassphrase);
        if (encrypted.Length is < 32 or > 2048) throw new InvalidDataException("Invalid DPAPI credential envelope");
        var clear = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        try { return Encoding.UTF8.GetString(clear); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    private void Record(string kind, Profile original, bool ok, string? error)
    {
        lock (gate)
        {
            var current = kind == "backup" ? settings.Backup : settings.Export;
            if (current == null || current.ProtectedPassphrase != original.ProtectedPassphrase
                || current.Destination != original.Destination) return; // reconfigured while running
            var next = current with
            {
                LastSuccessUtc = ok ? DateTimeOffset.UtcNow : current.LastSuccessUtc,
                LastError = ok ? null : Wire.Clean(error, 250)
            };
            settings = kind == "backup" ? settings with { Backup = next } : settings with { Export = next };
            Save();
        }
    }

    public void Pulse(DateTimeOffset now)
    {
        Profile? backup, export;
        lock (gate)
        {
            if (now - lastPulse < TimeSpan.FromMinutes(10)) return;
            lastPulse = now;
            backup = settings.Backup;
            export = settings.Export;
        }
        if (backup != null && (backup.LastSuccessUtc == null || now - backup.LastSuccessUtc > TimeSpan.FromHours(24)))
        {
            try
            {
                if (!OffDeviceLogExport.IsOffDeviceDestination(backup.Destination))
                    throw new IOException("Scheduled backup external volume is unavailable");
                var archive = Path.Combine(backup.Destination,
                    $"OTS-Firewall79X-{now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.otsfolder");
                var password = Reveal(backup);
                var result = FolderBackup.Create(backup.Source, archive, password);
                FolderBackup.Verify(archive, password);
                Record("backup", backup, true, null);
                eventSink(68, "Info", "Scheduled encrypted backup verified",
                    $"{result.Files} files, {result.Bytes} bytes. Backup location is not disclosed in event logs.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException
                                              or CryptographicException or ArgumentException)
            {
                Record("backup", backup, false, ex.Message);
                eventSink(68, "Warning", "Scheduled encrypted backup failed", Wire.Clean(ex.Message, 180));
            }
        }
        if (export == null) return;
        try
        {
            if (!OffDeviceLogExport.IsOffDeviceDestination(export.Destination))
                throw new IOException("Encrypted log shipping destination is unavailable");
            // Only closed rotated segments. Never open/copy active mutable JSONL streams.
            if (Directory.Exists(export.Source))
            {
                var tracked = (settings.ObservedLogSegments ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var file in Directory.EnumerateFiles(export.Source, "*.gz").OrderBy(x => x).TakeLast(64))
                {
                    var item = new FileInfo(file);
                    if (item.Length is < 1 or > 16*1024*1024 || item.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                    var id = item.Name + ":" + item.Length + ":" + item.LastWriteTimeUtc.Ticks;
                    if (tracked.Contains(id)) continue;
                    var passphrase = Reveal(export);
                    OffDeviceLogExport.Enqueue(queue, file, passphrase);
                    tracked.Add(id);
                    // Commit the index after a durable encrypted queue entry exists.
                    lock (gate)
                    {
                        if (settings.Export?.ProtectedPassphrase != export.ProtectedPassphrase) return;
                        settings = settings with { ObservedLogSegments = tracked.TakeLast(MaxTrackedSegments).ToArray() };
                        Save();
                    }
                }
            }
            int sent = OffDeviceLogExport.RetryPending(queue, export.Destination,
                message => eventSink(70, "Warning", "Encrypted log shipping retry failed", message));
            Record("export", export, true, null);
            if (sent > 0) eventSink(70, "Info", "Encrypted log archives delivered",
                $"{sent} verified encrypted segments copied to configured external destination");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException
                                          or CryptographicException or ArgumentException)
        {
            Record("export", export, false, ex.Message);
            eventSink(70, "Warning", "Encrypted log export failed", Wire.Clean(ex.Message, 180));
        }
    }
}
