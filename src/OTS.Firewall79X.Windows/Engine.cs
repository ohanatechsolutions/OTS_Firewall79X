using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Text.Json;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class Engine : IDisposable
{
    private sealed record Persisted(bool Enabled,DateTimeOffset? ResumeAt);
    private readonly object gate=new();private readonly EventStore events;private readonly ChangeJournal journal;private readonly WindowsSettings settings=new();private readonly LayerChecks checks;
    private EventSensors? sensors;private TemporaryFirewallGuard? networkGuard;private DeceptionMonitor? deception;private readonly FeodoThreatFeed feed=new();private bool enabled;private DateTimeOffset? resumeAt;private Dashboard cached;
    private DateTimeOffset lastCycle=DateTimeOffset.MinValue;private DateTimeOffset nextReport;private TimeSpan lastCpu;private DateTimeOffset lastCpuAt=DateTimeOffset.UtcNow;
    private string? recoveryError;private int epoch;
    private ResourceBudget.Decision governor=ResourceBudget.Evaluate(false,0,0,long.MaxValue,0);
    private static bool WatchdogRunning(){using var svc=new ServiceController("OTSFirewall79XWatchdog");return svc.Status==ServiceControllerStatus.Running;}
    private readonly Dictionary<int,LayerResult> inventoryCache=[];
    private static readonly HashSet<int> InventoryLayers=[25,26,33,35,37,39,40,44,46,51,52];
    public Engine()
    {
        Paths.SecureDirectory(Paths.Root);events=new(Paths.At("logs"));
        journal=new(Paths.At("changes.json"),settings);checks=new(events){ThreatFeed=feed};
        cached=new(false,"Not Protected",0,0,DateTimeOffset.UtcNow,null,IdleResults(),[],[],0,0,0,null,"No validated intelligence feeds configured");
        // Recover durable intent first; never reapply a stale transaction over newer system settings.
        var conflicts=journal.Restore();if(conflicts.Count>0)events.Add(59,"Warning","Recovery preserved external changes",string.Join(", ",conflicts));
        nextReport=NextQuarter(DateTimeOffset.UtcNow);
        try{if(File.Exists(Paths.At("state.json"))){var s=JsonSerializer.Deserialize<Persisted>(File.ReadAllText(Paths.At("state.json")),Wire.Json);if(s!=null){resumeAt=s.ResumeAt;if(s.Enabled&&(resumeAt==null||resumeAt<=DateTimeOffset.UtcNow))Enable();}}}
        catch(Exception ex){events.Add(53,"Warning","Startup state rejected",ex.Message);enabled=false;resumeAt=null;}
    }
    private static DateTimeOffset NextQuarter(DateTimeOffset d)=>new DateTimeOffset(d.Year,((d.Month-1)/3)*3+1,1,0,0,0,TimeSpan.Zero).AddMonths(3);
    private static List<LayerResult> IdleResults()=>Catalog.All.Select(l=>new LayerResult(l.Id,LayerMode.Idle,false,"OTS stack is off; existing Windows protection is unaffected")).ToList();
    private void Save()=>AtomicFile.Write(Paths.At("state.json"),JsonSerializer.Serialize(new Persisted(enabled||resumeAt!=null,resumeAt),Wire.Json));
    public Response Handle(Request r)
    {
        if(r.Command=="status")return new(true,"Live service status",cached with {Events=events.Recent(),TotalEvents=events.Total,BlockedEvents=events.Blocked});
        lock(gate)
        {
            try
            {
                switch(r.Command)
                {
                    case "status":return new(true,"Live service status",cached with {Events=events.Recent(),TotalEvents=events.Total,BlockedEvents=events.Blocked});
                    case "on":Enable();return new(true,"Protection started; capability checks are in progress");
                    case "off":Disable(null);return new(true,"OTS stack stopped; journaled changes restored where still owned");
                    case "pause":Disable(DateTimeOffset.UtcNow.AddMinutes(15));return new(true,"Paused for 15 minutes");
                    case "restore":Disable(null);return new(true,"Restoration completed; external changes were preserved");
                    case "report":return new(true,Reports.Generate(cached));
                    case "selftest":return new(Catalog.All.Count==79&&journal.Entries.All(e=>e.Key==WindowsSettings.AutoRun),"Catalog and journal schema verified; this is not a full protection regression test");
                    default:return new(false,"Unsupported command");
                }
            }
            catch(Exception ex){events.Add(53,"High","Operation failed",ex.Message);return new(false,Wire.Clean(ex.Message));}
        }
    }
    private void Enable()
    {
        if(enabled)return;
        AtomicFile.Write(Paths.At("pre-activation.json"),JsonSerializer.Serialize(new{Time=DateTimeOffset.UtcNow,AutoRun=settings.Read(WindowsSettings.AutoRun)},Wire.Json));
        try
        {
            journal.Apply(WindowsSettings.AutoRun,"255");networkGuard=new(events);networkGuard.Start();checks.NetworkGuard=networkGuard;sensors=new(events,networkGuard);sensors.Start();checks.Sensors=sensors;deception=new(events);
            enabled=true;epoch++;inventoryCache.Clear();resumeAt=null;Save();lastCycle=DateTimeOffset.MinValue;
            cached=cached with{Enabled=true,Protection="Partially Protected",Layers=IdleResults(),ResumeAt=null,Time=DateTimeOffset.UtcNow};
            events.Add(47,"Info","Protection activated","Narrow AutoRun hardening applied with rollback; system firewall policy preserved");
        }
        catch{enabled=false;deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;networkGuard?.Dispose();networkGuard=null;checks.NetworkGuard=null;journal.Restore();throw;}
    }
    private void Disable(DateTimeOffset? resume)
    {
        enabled=false;epoch++;resumeAt=resume;Save();deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;networkGuard?.Dispose();networkGuard=null;checks.NetworkGuard=null;
        var conflicts=journal.Restore();if(conflicts.Count>0)events.Add(59,"Warning","External settings preserved",string.Join(", ",conflicts));
        cached=cached with{Enabled=false,Protection="Not Protected",Score=0,Confidence=0,Layers=IdleResults(),ResumeAt=resume,Time=DateTimeOffset.UtcNow};
        events.Add(59,"Info","Stack disabled","Existing Windows protection and unrelated settings preserved");
    }
    [StructLayout(LayoutKind.Sequential)] private struct PowerStatus {public byte AcLine,BatteryFlag,BatteryPercent,Reserved;public uint LifeTime,FullLifeTime;}
    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out PowerStatus status);
    public async Task RunAsync(CancellationToken ct)
    {
        while(!ct.IsCancellationRequested)
        {
            try
            {
                lock(gate){if(!enabled&&resumeAt!=null&&resumeAt<=DateTimeOffset.UtcNow)Enable();}
                bool active;lock(gate)active=enabled;
                if(active){await feed.RefreshIfDueAsync(ct);networkGuard?.Sweep(DateTimeOffset.UtcNow,feed.Active!=null);}
                bool battery=GetSystemPowerStatus(out var power)&&power.AcLine==0;
                // Resource governor uses measured service pressure and real free disk space.
                long free=long.MaxValue,capacity=0;
                try
                {
                    var volume=new DriveInfo(Path.GetPathRoot(Paths.Root)!);
                    free=volume.AvailableFreeSpace;capacity=volume.TotalSize;
                }
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or ArgumentException)
                { recoveryError="Disk capacity query unavailable: "+ex.GetType().Name; }
                governor=ResourceBudget.Evaluate(battery,cached.CpuPercent??0,cached.ServiceMemoryMb,free,capacity);
                var interval=governor.CycleInterval;
                if(active&&DateTimeOffset.UtcNow-lastCycle>=interval)
                {
                    // Serialize lifecycle and collection. Bounded individual sensors limit expensive work;
                    // cached status is published after a cycle so no partly constructed state is exposed.
                    await Task.Run(()=>Cycle(battery),ct);lastCycle=DateTimeOffset.UtcNow;
                }
            }
            catch(Exception ex){recoveryError=ex.Message;events.Add(53,"High","Monitor cycle failed",ex.Message);}
            await Task.Delay(1000,ct);
        }
    }
    private void Cycle(bool battery)
    {
        int version;lock(gate){if(!enabled)return;version=epoch;}
        {
            checks.Prepare();List<LayerResult> results=[];
            foreach(var definition in Catalog.All)
            {
                lock(gate)
                {
                    if(!enabled||epoch!=version)return;
                    if(InventoryLayers.Contains(definition.Id)&&inventoryCache.TryGetValue(definition.Id,out var previous)&&previous.CheckedAt is DateTimeOffset observed&&DateTimeOffset.UtcNow-observed<governor.InventoryInterval)
                    {results.Add(previous);continue;}
                }
                var timer=Stopwatch.StartNew();LayerResult r;
                try{LayerResult? infra;lock(gate){if(!enabled||epoch!=version)return;infra=Infrastructure(definition.Id,battery);}r=infra??checks.Check(definition.Id);}catch(Exception ex){r=new(definition.Id,LayerMode.Unavailable,false,Wire.Clean(ex.Message));events.Add(definition.Id,"Warning","Layer check failed",ex.Message);}
                r=r with{CheckedAt=DateTimeOffset.UtcNow,DurationMs=Math.Round(timer.Elapsed.TotalMilliseconds,2)};
                results.Add(r);if(InventoryLayers.Contains(definition.Id))lock(gate){if(epoch==version)inventoryCache[definition.Id]=r;}
            }
            using var process=Process.GetCurrentProcess();var now=DateTimeOffset.UtcNow;double cpu=(process.TotalProcessorTime-lastCpu).TotalSeconds/Math.Max((now-lastCpuAt).TotalSeconds,1)/Environment.ProcessorCount*100;lastCpu=process.TotalProcessorTime;lastCpuAt=now;
            var score=Posture.Calculate(results,true);
            lock(gate){if(!enabled||epoch!=version)return;
            cached=new(true,"Partially Protected",score.Score,score.Confidence,now,resumeAt,results,events.Recent(),checks.Connections.Take(2000).ToList(),events.Total,events.Blocked,process.WorkingSet64/1048576.0,cpu,feed.Summary);
            if(!governor.DeferNonessentialDiskWork&&events.ConsumeSnapshotRequest())
            {
                var folder=Paths.At("snapshots");Paths.SecureDirectory(folder);
                AtomicFile.Write(Path.Combine(folder,$"snapshot-{now:yyyyMMdd-HHmmss}.json"),JsonSerializer.Serialize(cached,Wire.Json));
                foreach(var old in Directory.GetFiles(folder,"snapshot-*.json").OrderByDescending(File.GetLastWriteTimeUtc).Skip(10))File.Delete(old);
            }
            // Never claim full coverage while required catalog capabilities remain unavailable or limited.
            if(now>=nextReport&&!governor.DeferNonessentialDiskWork){AtomicFile.Write(Paths.At($"report-{now:yyyy-MM-dd}.md"),Reports.Generate(cached));nextReport=NextQuarter(now);events.Add(72,"Info","Quarterly report created","Saved in protected local storage");}
            }
        }
    }
    private LayerResult? Infrastructure(int id,bool battery)
    {
        LayerResult Good(string text,LayerMode mode=LayerMode.Monitoring,string limit="")=>new(id,mode,true,text,limit);
        switch(id)
        {
            case 11:return deception?.Healthy==true?Good("Protected decoy-file modification watcher is active",limit:"Modification, rename, and deletion detection only; reads are not observed."):new(id,LayerMode.Unavailable,false,"Canary monitor unavailable");
            case 12:case 13:return deception?.Healthy==true?Good($"Loopback-only HTTP decoy listening on 127.0.0.1:{deception.Port}",limit:"Local connections only; no external DNS/URL canary service or off-machine detection."):new(id,LayerMode.Unavailable,false,"Decoy listener unavailable");
            case 53:
                return WatchdogRunning()
                    ?Good("Independent watchdog Windows service is running; primary SCM recovery policy configured",limit:"Crash-loop throttling is SCM-controlled; physical failure injection and recovery evidence are still required.")
                    :new(id,LayerMode.Unavailable,false,"Independent watchdog service is stopped or unavailable", "Primary service SCM recovery may still operate.");
            case 54:
                return WatchdogRunning()
                    ?Good("Independent watchdog probes authenticated service status every 20 seconds and records sustained failures in Windows Event Log",limit:"Detects three failed probes or stale active monitoring. Cannot report while Windows is powered off; independent logging and hardware failure tests pending.")
                    :new(id,LayerMode.Unavailable,false,"Independent dead-man watchdog is not running");
            case 55:case 65:return Good("Service IPC uses local interactive-user ACL, network deny, and impersonated administrator checks for every mutation",LayerMode.Enforcing,"UI is unprivileged; protected operations run in a UAC-elevated helper.");
            case 56:return Good("Strict bounded IPC schema, framed JSON, XML DTD prohibition, and bounded event fields",LayerMode.Enforcing,"Broader parser and network-input coverage still requires Windows fuzz and hostile-input qualification.");
            case 57:return new(id,LayerMode.Unavailable,false,"Pinned ECDSA signed-manifest verification is implemented but automatic trusted updates remain disabled until a publisher key and signed release are provisioned","Hash-only or unsigned downloads are not accepted as an authenticated software update. No executable dependencies download at launch.");
            case 58:return File.Exists(Path.Combine(AppContext.BaseDirectory,"SBOM.json"))?Good("Installed package includes a build SBOM",LayerMode.Auditing,"SBOM presence is inventory evidence, not an independent integrity or vulnerability guarantee."):new(id,LayerMode.Unavailable,false,"Build SBOM not present beside service");
            case 59:
                var active=journal.Entries.Where(e=>e.State=="applied").ToArray();
                bool intact=active.All(e=>settings.Read(e.Key)==e.Applied);
                bool firewallSafe=networkGuard?.Operational==true &&
                    !networkGuard.Health.Contains("preserved",StringComparison.OrdinalIgnoreCase) &&
                    !networkGuard.Health.Contains("failed",StringComparison.OrdinalIgnoreCase);
                return intact&&firewallSafe
                    ?Good($"{active.Length} journaled settings match OTS-owned values; temporary firewall guard verifies exact rule properties before cleanup",LayerMode.Monitoring,
                        "Third-party rule changes are preserved rather than forcefully reverted; full WFP policy precedence and external rule ownership require further audit.")
                    :new(id,LayerMode.Auditing,false,
                        $"Rule safety requires attention: journal matched={intact}; guard={networkGuard?.Health??"unavailable"}",
                        "No broad rollback is attempted against unknown or modified firewall rules.");
            case 60:return Good("Bounded event history persists without the WPF UI; high-severity incidents also attempt Windows Application Event Log delivery",
                limit:"Desktop notifications require an interactive session. Off-device delivery, disk-full and native Event Log reliability testing remain incomplete.");
            case 61:if(events.LastError!=null)return new(id,LayerMode.Unavailable,false,"Persistent logging or integrity degraded: "+events.LastError,"Stored logs require administrator review; in-memory events are bounded.");
                return events.LegacyChainGaps>0
                    ?new(id,LayerMode.Auditing,false,$"{events.VerifiedRetainedEvents} authenticated records; {events.LegacyChainGaps} gaps in retained history", "Historical continuity cannot be established; protected event log inspection recommended.")
                    :Good($"HMAC-authenticated retained log entries: {events.VerifiedRetainedEvents}; historical counters restored on restart",limit:"Encrypted DPAPI integrity key is machine-local; finite retention and local administrator control remain trust limitations.");
            case 62:return Good($"Measured resource governor: {governor.CycleInterval.TotalSeconds:0}s cycle, {governor.InventoryInterval.TotalMinutes:0}m inventory. {governor.Reason}",limit:"Low disk defers optional snapshots and quarterly reports; urgent event logging remains enabled. Full battery, memory, and disk stress qualification still required.");
            case 63:return feed.Active is { } intel
                ?new(id,LayerMode.Auditing,false,
                    $"Feodo HTTPS publication timestamp {intel.UpdatedUtc:O} is within the freshness window; {intel.Addresses.Count} parsed indicators; publisher signature is NOT verified",
                    "HTTPS and a source timestamp are not a cryptographic feed signature. Observed matches may trigger temporary rules under other layers; broader authenticated feed coverage remains incomplete.")
                :new(id,LayerMode.Unavailable,false,feed.Summary,
                    "No valid current feed available. Previous intelligence-based rules are removed during normal maintenance; independent signed feed authenticity is not configured.");
            case 64:return Good("Log-integrity key is encrypted by machine DPAPI in administrator/SYSTEM-only storage",LayerMode.Enforcing,"Local administrators remain trusted; DPAPI is not off-device protection.");
            case 66:return Good("High-severity events request a protected JSON snapshot on the next completed health cycle",LayerMode.Monitoring,"Preserves available layer health, recent events and process-associated TCP metadata; bounded to 10 snapshots. No full memory dump or guaranteed capture after abrupt power loss.");
            case 67:return Good("Weighted capability-health score; unavailable/idle layers receive zero; not-applicable layers excluded",LayerMode.Auditing,"Score measures declared checks, not immunity or independently measured security effectiveness.");
            case 68:return new(id,LayerMode.Idle,false,"Desktop supports verified encrypted, versioned selected-folder backups and report archives","User selection required; 5,000-file/60 MiB limit; no empty-directory, symlink, ACL or full-system image preservation. Same-machine backups are not independent protection.");
            case 69:return Good("Separate UAC recovery executable and bundled offline recovery instructions",LayerMode.Auditing,"Not bootable recovery media; WinRE/boot media creation requires additional integration.");
            case 70:return new(id,LayerMode.Idle,false,"Local bounded log archives; encrypted desktop report export available","Off-device shipping is not configured or implemented.");
            case 71:return new(id,LayerMode.Idle,false,"Build-time regression suite; installed catalog/journal self-check available","Automatic post-update behavioral regression suite is not implemented.");
            case 72:return Good($"Next automatic local report due {nextReport:yyyy-MM-dd}",LayerMode.Monitoring,"Service must be running; durable historical posture trends are incomplete.");
            case 74:return Good("Desktop report generator includes all 79 layer states, evidence, limitations, and recent events",LayerMode.Auditing);
            default:return null;
        }
    }
    public void Dispose(){deception?.Dispose();sensors?.Dispose();networkGuard?.Dispose();feed.Dispose();}
}
