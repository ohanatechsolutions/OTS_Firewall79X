using System.Diagnostics;
using System.Management;
using System.Threading.Channels;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Service-backed, bounded file and removable-device observation; no input-device blocking.</summary>
public sealed class AdditionalHostMonitor : IDisposable
{
    private readonly EventStore events;
    private readonly object sync = new();
    private readonly List<FileSystemWatcher> watchers = [];
    private readonly HashSet<string> watched = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> devices = new(StringComparer.OrdinalIgnoreCase);
    private readonly RansomwareActivity activity = new();
    private readonly Channel<string> scanQueue = Channel.CreateBounded<string>(
        new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true, SingleWriter = false });
    private readonly CancellationTokenSource stopped = new();
    private ManagementEventWatcher? deviceWatcher;
    private ManagementEventWatcher? volumeWatcher;
    private Task? scannerTask;
    private DateTimeOffset lastRefresh;
    private int scans, skipped, drops, fileEvents, deviceEvents, watchErrors;
    private bool deviceEventsActive;
    private bool devicesInitialized;
    private readonly string? defender;
    private string lastScanner = "No scan has completed";
    public AdditionalHostMonitor(EventStore events)
    {
        this.events = events;
        try { defender = FindDefender(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            events.Add(76, "Warning", "Defender discovery unavailable", ex.GetType().Name);
        }
        try { Refresh(); }
        catch (Exception ex)
        {
            events.Add(77, "Warning", "Initial device scan unavailable", Wire.Clean(ex.Message, 160));
        }
        try
        {
            deviceWatcher = new ManagementEventWatcher(@"root\cimv2", "SELECT * FROM Win32_DeviceChangeEvent");
            deviceWatcher.EventArrived += (_, _) => { try { SnapshotDevices(); } catch (Exception ex) { events.Add(77, "Warning", "Device event failed", ex.Message); } };
            deviceWatcher.Start();
            deviceEventsActive = true;
        }
        catch (Exception ex) { events.Add(77, "Warning", "USB event channel unavailable", ex.Message); }
        try
        {
            volumeWatcher = new ManagementEventWatcher(@"root\cimv2", "SELECT * FROM Win32_VolumeChangeEvent");
            volumeWatcher.EventArrived += (_, _) => { try { Refresh(); } catch (Exception ex) { events.Add(76, "Warning", "Drive watch refresh failed", ex.Message); } };
            volumeWatcher.Start();
        }
        catch (Exception ex) { events.Add(76, "Warning", "Volume event channel unavailable", ex.Message); }
        scannerTask = Task.Run(ScanLoop);
    }
    private static string? FindDefender()
    {
        var home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(home))
        {
            foreach (var dir in Directory.GetDirectories(home).OrderDescending())
            {
                var exe = Path.Combine(dir, "MpCmdRun.exe");
                if (File.Exists(exe)) return exe;
            }
        }
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }
    public void Refresh()
    {
        lock (sync)
        {
            if (stopped.IsCancellationRequested || DateTimeOffset.UtcNow-lastRefresh < TimeSpan.FromSeconds(15)) return;
            lastRefresh = DateTimeOffset.UtcNow;
            SnapshotDevices();
            // A SYSTEM service sees SYSTEM's profile: use the Windows profile root, not that user's home.
            var windowsUsers = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "Users");
            if (Directory.Exists(windowsUsers))
            {
                foreach (var profile in Directory.EnumerateDirectories(windowsUsers).Take(48))
                {
                    if ((File.GetAttributes(profile) & FileAttributes.ReparsePoint) != 0) continue;
                    TryWatch(Path.Combine(profile, "Downloads"), true);
                    TryWatch(Path.Combine(profile, "AppData", "Local", "Temp"), true);
                    TryWatch(Path.Combine(profile, "Documents"), false);
                }
            }
            foreach (var drive in DriveInfo.GetDrives())
            {
                try { if (drive.DriveType == DriveType.Removable && drive.IsReady) TryWatch(drive.RootDirectory.FullName, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { skipped++; }
            }
        }
    }
    private void TryWatch(string path, bool scan)
    {
        if (watchers.Count >= 128) { skipped++; return; }
        if (watched.Contains(path) || !Directory.Exists(path)) return;
        try
        {
            var dir = new DirectoryInfo(path);
            if (dir.Attributes.HasFlag(FileAttributes.ReparsePoint)) { skipped++; return; }
            var w = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                InternalBufferSize = 32768,
                EnableRaisingEvents = false
            };
            w.Created += (_, e) => OnFile(e.FullPath, WatcherChangeTypes.Created, scan);
            w.Changed += (_, e) => OnFile(e.FullPath, WatcherChangeTypes.Changed, scan);
            w.Deleted += (_, e) => OnFile(e.FullPath, WatcherChangeTypes.Deleted, false);
            w.Renamed += (_, e) => OnFile(e.FullPath, WatcherChangeTypes.Renamed, scan);
            w.Error += (_, e) =>
            {
                Interlocked.Increment(ref watchErrors);
                events.Add(78, "Warning", "Filesystem event coverage lost", Wire.Clean(e.GetException().Message, 200));
            };
            w.EnableRaisingEvents = true;
            watchers.Add(w); watched.Add(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            skipped++;
            events.Add(76, "Warning", "Folder watch unavailable", Wire.Clean(ex.GetType().Name + ": " + Path.GetFileName(path), 120));
        }
    }
    private void OnFile(string path, WatcherChangeTypes change, bool scan)
    {
        Interlocked.Increment(ref fileEvents);
        try
        {
            if (Path.GetFileName(path).Equals("OTS-Firewall79X-Canary.txt", StringComparison.OrdinalIgnoreCase))
                events.Add(78, "High", "Protected canary touched", "User-profile ransomware canary was modified or removed; verify application activity");
            lock (activity)
            {
                if (activity.Observe(path, change, DateTimeOffset.UtcNow))
                    events.Add(78, "Warning", "Destructive file-operation burst", "35 distinct files and 12 renames/deletions in 15 seconds; backups and bulk organization can be benign");
            }
            if (scan && change is WatcherChangeTypes.Created or WatcherChangeTypes.Changed or WatcherChangeTypes.Renamed && !scanQueue.Writer.TryWrite(path))
            {
                Interlocked.Increment(ref drops);
                events.Add(76, "Warning", "Malware scan backlog", "File arrival events exceeded scanner capacity; scan coverage is incomplete");
            }
        }
        catch (Exception ex) { events.Add(78, "Warning", "File event rejected", ex.GetType().Name); }
    }
    private void SnapshotDevices()
    {
        // Processed only after an initial snapshot: boot enumeration is not a new USB event.
        var inventory = SystemQueries.Wmi("root\\cimv2",
            "SELECT Name,PNPDeviceID,PNPClass FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'",
            "Name", "PNPDeviceID", "PNPClass");
        var next = inventory.Select(d => d.GetValueOrDefault("PNPDeviceID", "")).Where(s => s.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        lock (devices)
        {
            if (devicesInitialized)
                foreach (var entry in inventory.Where(d => next.Contains(d.GetValueOrDefault("PNPDeviceID", "")) && !devices.Contains(d.GetValueOrDefault("PNPDeviceID", ""))))
                {
                    var type = entry.GetValueOrDefault("PNPClass", "") switch
                    {
                        "Keyboard" or "Mouse" or "HIDClass" => "input/HID",
                        "DiskDrive" or "USB" or "Volume" => "storage/USB",
                        _ => "peripheral/unknown"
                    };
                    Interlocked.Increment(ref deviceEvents);
                    events.Add(77, "Info", "New USB device observed", $"{type}: {Wire.Clean(entry.GetValueOrDefault("Name", "unknown"), 96)}; device not blocked");
                }
            devices.Clear();
            foreach (var id in next.Take(4096)) devices.Add(id);
            devicesInitialized = true;
        }
    }
    private async Task ScanLoop()
    {
        var last = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await foreach (var path in scanQueue.Reader.ReadAllAsync(stopped.Token))
            {
                if (defender == null) continue;
                if (last.TryGetValue(path, out var at) && DateTimeOffset.UtcNow - at < TimeSpan.FromMinutes(2)) continue;
                if (last.Count > 2048) last.Clear();
                last[path] = DateTimeOffset.UtcNow;
                await Task.Delay(1500, stopped.Token);
                try
                {
                    var file = new FileInfo(path);
                    if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint) || file.Length > 128L * 1024 * 1024 || file.Length == 0)
                    { Interlocked.Increment(ref skipped); continue; }
                    if (DateTimeOffset.UtcNow - file.LastWriteTimeUtc < TimeSpan.FromSeconds(1))
                    { Interlocked.Increment(ref skipped); continue; }
                    var start = new ProcessStartInfo(defender) { UseShellExecute = false, CreateNoWindow = true };
                    foreach (var arg in new[] { "-Scan", "-ScanType", "3", "-File", path }) start.ArgumentList.Add(arg);
                    using var process = Process.Start(start) ?? throw new IOException("Defender executable did not start");
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopped.Token);
                    timeout.CancelAfter(TimeSpan.FromMinutes(3));
                    try { await process.WaitForExitAsync(timeout.Token); }
                    catch (OperationCanceledException) { if (!process.HasExited) process.Kill(true); throw; }
                    Interlocked.Increment(ref scans);
                    lastScanner = $"Microsoft Defender scan process exit {process.ExitCode} at {DateTimeOffset.UtcNow:O}; review Protection History";
                    if (process.ExitCode != 0) events.Add(76, "Warning", "Native malware scan requires review", $"Defender reported exit {process.ExitCode}; inspect Windows Security Protection History");
                }
                catch (OperationCanceledException) when (stopped.IsCancellationRequested) { break; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException or OperationCanceledException)
                {
                    Interlocked.Increment(ref skipped);
                    lastScanner = "Scan unavailable: " + Wire.Clean(ex.Message, 120);
                    events.Add(76, "Warning", "Defender scan did not complete", lastScanner);
                }
            }
        }
        catch (OperationCanceledException) when (stopped.IsCancellationRequested) { }
    }
    public LayerResult Check(int layer)
    {
        Refresh();
        if (layer == 76)
        {
            if (defender == null) return new(76, LayerMode.Unavailable, false, "Microsoft Defender command-line scanner not installed");
            if (watchers.Count == 0) return new(76, LayerMode.Unavailable, false, "No supported Downloads, temporary or removable locations were watched");
            return new(76, LayerMode.Monitoring, Volatile.Read(ref scans) > 0,
                $"{watchers.Count} folder watchers; native scan processes completed={scans}; dropped={drops}; skipped={skipped}; {lastScanner}",
                "Defender handles verdict/quarantine/recovery. OTS does not quarantine files. Files can change before scanning; inaccessible, empty, linked and >128 MiB files are skipped. Full OS real-time AV coverage depends on Defender.");
        }
        if (layer == 77)
        {
            if (!deviceEventsActive) return new(77, LayerMode.Unavailable, false, "Device events unavailable; polling fallback only",
                "Windows device notification source failed; live plug/unplug testing remains required");
            return new(77, LayerMode.Monitoring, true,
                $"WMI USB device events active; current device IDs={devices.Count}; new observations={deviceEvents}",
                "Class assignment from PNPClass is approximate. No keyboard, mouse or storage device is blocked. Driver and hardware event delivery may vary.");
        }
        return watchers.Count == 0
            ? new(78, LayerMode.Unavailable, false, "No user directories watched for ransomware-like file activity")
            : new(78, LayerMode.Monitoring, watchErrors == 0,
                $"Background file watchers={watchers.Count}; event observations={fileEvents}; watcher errors={watchErrors}",
                "15-second 35-distinct/12-rename-delete heuristic plus named canary access. FileSystemWatcher is lossy and does not identify the responsible process; no termination or rollback is attempted.");
    }
    public void Dispose()
    {
        stopped.Cancel();
        scanQueue.Writer.TryComplete();
        try { deviceWatcher?.Stop(); } catch (ManagementException) { }
        try { volumeWatcher?.Stop(); } catch (ManagementException) { }
        deviceWatcher?.Dispose(); volumeWatcher?.Dispose();
        lock (sync) { foreach (var w in watchers) w.Dispose(); watchers.Clear(); }
        stopped.Dispose();
    }
}
