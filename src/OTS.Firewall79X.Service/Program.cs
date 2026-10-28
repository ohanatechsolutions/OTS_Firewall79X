using System.Diagnostics;
using System.ServiceProcess;
using OTS.Firewall79X.Core;
using OTS.Firewall79X.Windows;

namespace OTS.Firewall79X.Service;

internal sealed class FirewallService : ServiceBase
{
    private CancellationTokenSource? stop;
    private Engine? engine;
    private Task? task;
    public FirewallService() { ServiceName = "OTSFirewall79X"; CanStop = true; CanShutdown = true; AutoLog = true; }
    protected override void OnStart(string[] args)
    {
        stop = new CancellationTokenSource();
        engine = new Engine();
        task = Task.WhenAll(engine.RunAsync(stop.Token),
            Ipc.ServeAsync(engine.Handle,
                ex => SafeLog(EventLog, "IPC request failed: " + ex.GetType().Name, EventLogEntryType.Warning),
                stop.Token));
        _ = task.ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                SafeLog(EventLog, "Security service terminated unexpectedly: " +
                    t.Exception!.GetBaseException().GetType().Name, EventLogEntryType.Error);
                Environment.Exit(1); // SCM bounded recovery policy, never an unbounded inline restart.
            }
        }, TaskScheduler.Default);
    }
    protected override void OnStop()
    {
        stop?.Cancel();
        try { task?.Wait(TimeSpan.FromSeconds(10)); }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException)) { }
        engine?.Dispose();
        stop?.Dispose();
    }
    protected override void OnShutdown() => OnStop();

    internal static void SafeLog(EventLog log, string message, EventLogEntryType kind)
    {
        try { log.WriteEntry(Wire.Clean(message, 512), kind); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    public static void Main(string[] args)
    {
        if (args.Contains("--version")) { Console.WriteLine("OTS Firewall79X 0.1.0 development"); return; }
        ServiceBase.Run(args.Contains("--watchdog", StringComparer.OrdinalIgnoreCase)
            ? new WatchdogService() : new FirewallService());
    }
}

/// <summary>
/// Independent process, registered as a separate Windows service. SCM handles bounded
/// crash restarts of the primary service; watchdog only reports and never changes
/// host firewall or service configuration. Windows Event Log retains alerts without UI.
/// </summary>
internal sealed class WatchdogService : ServiceBase
{
    private CancellationTokenSource? stop;
    private Task? monitoring;
    public WatchdogService() { ServiceName = "OTSFirewall79XWatchdog"; CanStop = true; CanShutdown = true; AutoLog = true; }
    protected override void OnStart(string[] args)
    {
        stop = new CancellationTokenSource();
        monitoring = MonitorAsync(stop.Token);
    }
    private async Task MonitorAsync(CancellationToken ct)
    {
        int failures = 0;
        bool incidentOpen = false;
        await Task.Delay(TimeSpan.FromSeconds(20), ct); // Grace for service installation/startup.
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                var response = await Ipc.SendAsync("status", timeout.Token);
                if (!response.Ok || response.Dashboard is null)
                    throw new IOException("Authenticated status probe was unavailable");
                if (response.Dashboard.Enabled && HeartbeatPolicy.IsStale(
                    response.Dashboard.Time, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(8)))
                    throw new IOException("Security monitor telemetry is stale");
                failures = 0;
                if (incidentOpen)
                    FirewallService.SafeLog(EventLog, "Authenticated protection health recovered",
                        EventLogEntryType.Information);
                incidentOpen = false;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                failures++;
                if (failures >= 3 && !incidentOpen)
                {
                    incidentOpen = true;
                    FirewallService.SafeLog(EventLog,
                        "Independent watchdog: OTS protection service is unresponsive or stale (" +
                        ex.GetType().Name + "). Windows SCM recovery remains responsible for restarts.",
                        EventLogEntryType.Error);
                }
            }
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
        }
    }
    protected override void OnStop()
    {
        stop?.Cancel();
        try { monitoring?.Wait(TimeSpan.FromSeconds(10)); }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException)) { }
        stop?.Dispose();
    }
    protected override void OnShutdown() => OnStop();
}
