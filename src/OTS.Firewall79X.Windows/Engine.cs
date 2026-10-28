using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Text.Json;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class Engine : IDisposable
{
    private sealed record Persisted(bool Enabled,DateTimeOffset? ResumeAt);
    private readonly object gate=new();private readonly EventStore events;private readonly ChangeJournal journal;private readonly WindowsSettings settings=new();private readonly LayerChecks checks;private readonly ResilienceJobs resilience;
    private EventSensors? sensors;private TemporaryFirewallGuard? networkGuard;private DeceptionMonitor? deception;private AdditionalHostMonitor? hostMonitor;private readonly FeodoThreatFeed feed=new();
    private readonly MaliciousDomainFeed domainFeed=new();private readonly DomainHostsProtection domainHosts;private bool enabled;private DateTimeOffset? resumeAt;private Dashboard cached;
    private DateTimeOffset lastCycle=DateTimeOffset.MinValue;private DateTimeOffset nextReport;private DateTime historyObservedOn=DateTime.MinValue;private TimeSpan lastCpu;private DateTimeOffset lastCpuAt=DateTimeOffset.UtcNow;
    private string? recoveryError;private int epoch;
    private ResourceBudget.Decision governor=ResourceBudget.Evaluate(false,0,0,long.MaxValue,0);
    private static bool WatchdogRunning(){using var svc=new ServiceController("OTSFirewall79XWatchdog");return svc.Status==ServiceControllerStatus.Running;}
    private readonly Dictionary<int,LayerResult> inventoryCache=[];
    private static readonly HashSet<int> InventoryLayers=[25,26,33,35,37,39,40,44,46,51,52];
    public Engine()
    {
        Paths.SecureDirectory(Paths.Root);events=new(Paths.At("logs"));
        resilience=new ResilienceJobs((id,severity,kind,detail)=>events.Add(id,severity,kind,detail));
        journal=new(Paths.At("changes.json"),settings);domainHosts=new(events);checks=new(events){ThreatFeed=feed,DomainFeed=domainFeed,DomainBlocks=domainHosts};
        try{domainHosts.Restore();}catch(Exception ex){events.Add(75,"Warning","Domain recovery requires attention",ex.Message);}
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
                    case "report":return new(true,Reports.Generate(cached)+"\n\n"+SecurityDossier.Generate(cached));
                    case "configure-backup":resilience.Configure("backup",r.Source,r.Destination,r.Secret);return new(true,"Scheduled encrypted off-device folder backups enabled. Preserve the passphrase independently.");
                    case "configure-export":resilience.Configure("export",null,r.Destination,r.Secret);return new(true,"Optional encrypted rotated-log shipping enabled. Preserve the passphrase independently.");
                    case "disable-backup":resilience.Disable("backup");return new(true,"Scheduled backups disabled; existing archives were preserved.");
                    case "disable-export":resilience.Disable("export");return new(true,"Off-device log shipping disabled; retained encrypted archives were preserved.");
                    case "authguard-on":
                    {
                        if(!enabled||networkGuard?.SetAuthenticationProtection(true)!=true)
                            return new(false,"Enable OTS protection and verify the Windows firewall rule manager first");
                        cached=cached with{AuthenticationProtectionEnabled=true};
                        events.Add(41,"Info","Optional RDP login restrictions armed",
                            "Administrator explicitly authorized temporary TCP 3389 restrictions for high-confidence nonexistent-account attacks.");
                        return new(true,"Optional RDP-only attack guard enabled; 32 invalid-user RDP failures against five distinct nonexistent accounts required.");
                    }
                    case "authguard-off":
                    {
                        if(networkGuard!=null&&!networkGuard.SetAuthenticationProtection(false))
                            return new(false,"Authentication guard cleanup failed; recovery may be required: "+networkGuard.Health);
                        cached=cached with{AuthenticationProtectionEnabled=false};
                        return new(true,"Optional RDP source restrictions disabled and removed.");
                    }
                    case "selftest":return new(Catalog.All.Count==79&&journal.Entries.All(e=>WindowsSettings.SafeHardeningKeys.Contains(e.Key)),"Catalog and journal schema verified; this is not a full protection regression test");
                    case "domains-on":
                        if(!enabled)return new(false,"Turn on OTS monitoring before enabling optional domain blocking");
                        domainHosts.Enable(domainFeed.Active);return new(true,domainHosts.Status);
                    case "domains-off":domainHosts.Restore();return new(true,"Optional domain blocking removed; other hosts entries preserved");
                    default:return new(false,"Unsupported command");
                }
            }
            catch(Exception ex){events.Add(53,"High","Operation failed",ex.Message);return new(false,Wire.Clean(ex.Message));}
        }
    }
    private void Enable()
    {
        if(enabled)return;
        AtomicFile.Write(Paths.At("pre-activation.json"),JsonSerializer.Serialize(new{Time=DateTimeOffset.UtcNow,AutoRun=settings.Read(WindowsSettings.AutoRun),NoAutorun=settings.Read(WindowsSettings.NoAutorun),NonVolumeAutoPlay=settings.Read(WindowsSettings.NoAutoplayNonVolume),SmartScreen=settings.Read(WindowsSettings.SmartScreen)},Wire.Json));
        try
        {
            journal.Apply(WindowsSettings.AutoRun,"255");journal.Apply(WindowsSettings.NoAutorun,"1");journal.Apply(WindowsSettings.NoAutoplayNonVolume,"1");journal.Apply(WindowsSettings.SmartScreen,"1");networkGuard=new(events);networkGuard.Start();checks.NetworkGuard=networkGuard;deception=new(events);sensors=new(events,networkGuard){Deception=deception,Domains=domainFeed};sensors.Start();checks.Sensors=sensors;
            hostMonitor=new(events);checks.HostMonitor=hostMonitor;
            enabled=true;epoch++;inventoryCache.Clear();resumeAt=null;Save();lastCycle=DateTimeOffset.MinValue;
            try
            {
                var kit=Paths.At("recovery-kit");Paths.SecureDirectory(kit);
                RecoveryKit.Create(kit,AppContext.BaseDirectory,Paths.Root);
            }
            catch(Exception ex){events.Add(69,"Warning","Local recovery kit generation failed",ex.Message);}
            cached=cached with{Enabled=true,Protection="Partially Protected",Layers=IdleResults(),ResumeAt=null,Time=DateTimeOffset.UtcNow,AuthenticationProtectionEnabled=false};
            events.Add(47,"Info","Protection activated","Four allowlisted AutoRun/AutoPlay and shell SmartScreen policies journaled; existing firewall policy preserved");
        }
        catch{enabled=false;hostMonitor?.Dispose();hostMonitor=null;checks.HostMonitor=null;deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;networkGuard?.Dispose();networkGuard=null;checks.NetworkGuard=null;journal.Restore();throw;}
    }
    private void Disable(DateTimeOffset? resume)
    {
        enabled=false;epoch++;resumeAt=resume;Save();hostMonitor?.Dispose();hostMonitor=null;checks.HostMonitor=null;deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;networkGuard?.Dispose();networkGuard=null;checks.NetworkGuard=null;
        domainHosts.Restore();
        var conflicts=journal.Restore();if(conflicts.Count>0)events.Add(59,"Warning","External settings preserved",string.Join(", ",conflicts));
        cached=cached with{Enabled=false,Protection="Not Protected",Score=0,Confidence=0,Layers=IdleResults(),ResumeAt=resume,Time=DateTimeOffset.UtcNow,AuthenticationProtectionEnabled=false};
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
                if(active)
                {
                    await feed.RefreshIfDueAsync(ct);
                    networkGuard?.Sweep(DateTimeOffset.UtcNow,feed.Active!=null);
                    await domainFeed.RefreshIfDueAsync(ct);
                    if(domainHosts.Applied && domainFeed.Active==null)
                    {
                        lock(gate)domainHosts.Restore();
                        events.Add(75,"Warning","Expired domain protection removed","Domain feed unavailable or stale; managed hosts entries removed");
                    }
                    if(!governor.DeferNonessentialDiskWork)await Task.Run(()=>resilience.Pulse(DateTimeOffset.UtcNow),ct);
                }
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
            cached=new(true,"Partially Protected",score.Score,score.Confidence,now,resumeAt,results,events.Recent(),checks.Connections.Take(2000).ToList(),events.Total,events.Blocked,process.WorkingSet64/1048576.0,cpu,feed.Summary+" | "+domainFeed.Status,networkGuard?.AuthenticationProtectionEnabled==true);
            if(!governor.DeferNonessentialDiskWork&&events.ConsumeSnapshotRequest())
            {
                try
                {
                    var folder=Paths.At("snapshots");Paths.SecureDirectory(folder);
                    var evidence=ForensicSnapshots.Capture(folder,cached);
                    events.Add(66,"Info","Integrity-checked forensic snapshot",Path.GetFileName(evidence));
                }
                catch(Exception ex){events.Add(66,"Warning","Forensic capture failed",ex.Message);}
            }
            if(!governor.DeferNonessentialDiskWork&&historyObservedOn!=now.UtcDateTime.Date)
            {
                try
                {
                    var folder=Paths.At("reports");Paths.SecureDirectory(folder);
                    var history=Path.Combine(folder,"daily-posture.json");
                    QuarterlyHistory.Observe(history,cached);
                    historyObservedOn=now.UtcDateTime.Date;
                    foreach(var report in QuarterlyHistory.CreateDue(history,folder,now))
                        events.Add(72,"Info","Quarterly posture report created",Path.GetFileName(report));
                    nextReport=NextQuarter(now);
                }
                catch(Exception ex){events.Add(72,"Warning","Posture history or quarterly report failed",ex.Message);}
            }
            }
        }
    }
    private LayerResult? Infrastructure(int id,bool battery)
    {
        LayerResult Good(string text,LayerMode mode=LayerMode.Monitoring,string limit="")=>new(id,mode,true,text,limit);
        switch(id)
        {
            case 11:
                if(deception?.FileMonitorHealthy != true)
                    return new(id,LayerMode.Unavailable,false,"Canary filesystem watcher or independent hash verifier unavailable");
                bool fileAudit = deception.AuditReady
                    && sensors?.Has("Security")==true;
                return Good($"Three isolated decoy files monitored with SHA-256 checks; audited 4663 reads={deception.AuditedReads}; read-audit setup: {deception.AuditStatus}",
                    LayerMode.Monitoring,
                    fileAudit
                        ? "Windows Security 4663 access attribution is conditional on real events, audit policy and effective SACLs. Silent file reads cannot be proven absent."
                        : "File tamper monitoring is active, but file-read attribution is unavailable: " + deception.AuditStatus);
            case 12:
                if(deception?.ListenerHealthy != true)
                    return new(id,LayerMode.Unavailable,false,"Local canary URL listener unavailable");
                return Good($"Unique local URL canary active on loopback port {deception.Port}; URL hits={deception.CanaryHits}; observed canary DNS events={deception.DnsHits}",
                    LayerMode.Monitoring,
                    sensors?.Has("Microsoft-Windows-DNS-Client/Operational")==true
                        ? "Local DNS queries are monitored when Windows emits relevant DNS Client events. No off-machine endpoint exists, and no remote detection is claimed."
                        : "Windows DNS Client event channel is unavailable: only the loopback canary URL is monitored. No external canary endpoint is configured.");
            case 13:
                return deception?.ListenerHealthy == true
                    ? Good($"Loopback-only decoy HTTP listener on 127.0.0.1:{deception.Port}; observed service probes={deception.DecoyHits}; concurrency limit=6, request cap=2 KiB, timeout=2 seconds",
                        LayerMode.Monitoring,
                        "No public interface, vulnerable backend, remote-source enforcement or source bans. Local probes are evidence, not proof of compromise.")
                    : new(id,LayerMode.Unavailable,false,"Decoy service unavailable or listener stopped");
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
                    :Good($"HMAC-authenticated retained log entries: {events.VerifiedRetainedEvents}; current protected key version {events.IntegrityKeyVersion}; retained key versions {events.RetainedIntegrityKeys}",limit:"Encrypted DPAPI integrity key is machine-local; finite retention and local administrator control remain trust limitations.");
            case 62:return Good($"Measured resource governor: {governor.CycleInterval.TotalSeconds:0}s cycle, {governor.InventoryInterval.TotalMinutes:0}m inventory. {governor.Reason}",limit:"Low disk defers optional snapshots and quarterly reports; urgent event logging remains enabled. Full battery, memory, and disk stress qualification still required.");
            case 63:return feed.Active is { } intel
                ?new(id,LayerMode.Auditing,false,
                    $"Feodo HTTPS publication timestamp {intel.UpdatedUtc:O} is within the freshness window; {intel.Addresses.Count} parsed indicators; publisher signature is NOT verified",
                    "HTTPS and a source timestamp are not a cryptographic feed signature. Observed matches may trigger temporary rules under other layers; broader authenticated feed coverage remains incomplete.")
                :new(id,LayerMode.Unavailable,false,feed.Summary,
                    "No valid current feed available. Previous intelligence-based rules are removed during normal maintenance; independent signed feed authenticity is not configured.");
            case 64:return Good($"Machine-DPAPI protected log key ring active: key version {events.IntegrityKeyVersion}, {events.RetainedIntegrityKeys} retained keys; 90-day rotation supported",LayerMode.Enforcing,"Prior versions are retained for authenticated log replay; old-key retirement, protected off-device recovery and independent ACL tests remain release gates.");
            case 66:return Good("High-severity events request bounded, SHA-256-verified forensic snapshots on the next completed health cycle",LayerMode.Monitoring,"20 retained verified evidence files maximum; checksums detect damage but do not authenticate writer identity. Abrupt power loss may prevent capture.");
            case 67:return Good("Weighted capability-health score, checked-sensor confidence and prioritized remediation in the dossier",LayerMode.Auditing,"Heuristic weights are not independently verified security effectiveness or risk probabilities.");
            case 68:
                var backupStatus=resilience.Status("backup");
                return backupStatus.Enabled
                    ?new(id,backupStatus.Healthy?LayerMode.Monitoring:LayerMode.Auditing,backupStatus.Healthy,
                        backupStatus.Summary,"Explicit opt-in to daily AES-GCM external backups using machine-DPAPI-wrapped passphrase; 60 MiB limit, no ACL/empty-directory preservation. Last-run failure must be reviewed.")
                    :new(id,LayerMode.Idle,false,"Optional scheduled external backups not configured; manual encrypted versions remain available",
                        "User-selected folder and recoverable passphrase needed. No backups run without explicit authorization.");
            case 69:
                var kitPath=Paths.At("recovery-kit");
                return File.Exists(Path.Combine(kitPath,"MANIFEST.md"))&&File.Exists(Path.Combine(kitPath,"RECOVERY_INSTRUCTIONS.md"))
                    ?Good("Protected local recovery kit contains checked-copy manifest, printable instructions and OTS-owned config exports",LayerMode.Auditing,
                        "Not bootable media. The executable may not be co-located with the service; use the installed UAC recovery shortcut.")
                    :new(id,LayerMode.Unavailable,false,"Recovery kit manifest was not generated; installed standalone recovery tool may remain available.");
            case 70:
                var exportStatus=resilience.Status("export");
                return exportStatus.Enabled
                    ?new(id,exportStatus.Healthy?LayerMode.Monitoring:LayerMode.Auditing,exportStatus.Healthy,
                        exportStatus.Summary,"Ships only closed rotated gzip segments. Successful local scheduling alone is not end-to-end delivery confirmation; removable/network destination must remain accessible.")
                    :new(id,LayerMode.Idle,false,"Optional encrypted off-device log shipping not configured",
                        "No remote destination is contacted until an administrator explicitly enables export.");
            case 71:return new(id,LayerMode.Idle,false,"Build-time corruption, encrypted-export, recovery, overlap and backup regression tests; installed narrow self-check","Not every layer has independent Windows hardware/integration tests or post-update behavioral verification. Production gate remains open.");
            case 72:
                try
                {
                    var samples=QuarterlyHistory.Load(Path.Combine(Paths.At("reports"),"daily-posture.json"));
                    return samples.Count>0?Good($"{samples.Count} daily historical posture readings; next quarter boundary {nextReport:yyyy-MM-dd}",LayerMode.Monitoring,"A running active service is required; missed days remain gaps and quarterly reports catch up on the next active cycle.")
                        :new(id,LayerMode.Idle,false,"No completed historical reading yet","First active monitoring cycle will record a persistent sample.");
                }
                catch(Exception ex){return new(id,LayerMode.Unavailable,false,"Historical posture storage error: "+Wire.Clean(ex.Message));}
            case 74:return Good("On-demand dossier contains all 79 layers, operational modes, evidence timestamps, limits and prioritized review items",LayerMode.Auditing,"This is service self-reporting, not independent hardware attestation.");
            default:return null;
        }
    }
    public void Dispose(){hostMonitor?.Dispose();deception?.Dispose();sensors?.Dispose();networkGuard?.Dispose();
        try{if(domainHosts.Applied)domainHosts.Restore();}catch(Exception ex){events.Add(75,"Warning","Domain restore failed on shutdown",ex.Message);}
        domainFeed.Dispose();feed.Dispose();checks.Dispose();}
}
