using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class Engine : IDisposable
{
    private sealed record Persisted(bool Enabled,DateTimeOffset? ResumeAt);
    private readonly object gate=new();private readonly EventStore events;private readonly ChangeJournal journal;private readonly WindowsSettings settings=new();private readonly LayerChecks checks;
    private EventSensors? sensors;private DeceptionMonitor? deception;private readonly FeodoThreatFeed feed=new();private bool enabled;private DateTimeOffset? resumeAt;private Dashboard cached;
    private DateTimeOffset lastCycle=DateTimeOffset.MinValue;private DateTimeOffset nextReport;private DateTime historyObservedOn=DateTime.MinValue;private TimeSpan lastCpu;private DateTimeOffset lastCpuAt=DateTimeOffset.UtcNow;
    private string? recoveryError;private int epoch;
    private readonly Dictionary<int,LayerResult> inventoryCache=[];
    private static readonly HashSet<int> InventoryLayers=[25,26,33,35,37,39,44,46,51,52];
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
                    case "report":return new(true,Reports.Generate(cached)+"\n\n"+SecurityDossier.Generate(cached));
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
            journal.Apply(WindowsSettings.AutoRun,"255");sensors=new(events);sensors.Start();checks.Sensors=sensors;deception=new(events);
            enabled=true;epoch++;inventoryCache.Clear();resumeAt=null;Save();lastCycle=DateTimeOffset.MinValue;
            cached=cached with{Enabled=true,Protection="Partially Protected",Layers=IdleResults(),ResumeAt=null,Time=DateTimeOffset.UtcNow};
            events.Add(47,"Info","Protection activated","Narrow AutoRun hardening applied with rollback; system firewall policy preserved");
        }
        catch{enabled=false;deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;journal.Restore();throw;}
    }
    private void Disable(DateTimeOffset? resume)
    {
        enabled=false;epoch++;resumeAt=resume;Save();deception?.Dispose();deception=null;sensors?.Dispose();sensors=null;checks.Sensors=null;
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
                if(active)await feed.RefreshIfDueAsync(ct);
                bool battery=GetSystemPowerStatus(out var power)&&power.AcLine==0;
                var interval=TimeSpan.FromSeconds(battery?90:30);
                // Back off after observed high service CPU/memory without inventing per-layer attribution.
                if((cached.CpuPercent??0)>10||cached.ServiceMemoryMb>256)interval=TimeSpan.FromSeconds(battery?180:60);
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
                    if(InventoryLayers.Contains(definition.Id)&&inventoryCache.TryGetValue(definition.Id,out var previous)&&previous.CheckedAt is DateTimeOffset observed&&DateTimeOffset.UtcNow-observed<TimeSpan.FromMinutes(battery?15:5))
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
            if(events.ConsumeSnapshotRequest())
            {
                try
                {
                    var folder=Paths.At("snapshots");Paths.SecureDirectory(folder);
                    var evidence=ForensicSnapshots.Capture(folder,cached);
                    events.Add(66,"Info","Integrity-checked forensic snapshot",Path.GetFileName(evidence));
                }
                catch(Exception ex){events.Add(66,"Warning","Forensic capture failed",ex.Message);}
            }
            // Daily observations are durable. Catch up missed quarters after a restart, without inventing unobserved days.
            if(historyObservedOn!=now.UtcDateTime.Date)
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
            case 11:return deception?.Healthy==true?Good("Protected decoy-file modification watcher is active",limit:"Modification, rename, and deletion detection only; reads are not observed."):new(id,LayerMode.Unavailable,false,"Canary monitor unavailable");
            case 12:case 13:return deception?.Healthy==true?Good($"Loopback-only HTTP decoy listening on 127.0.0.1:{deception.Port}",limit:"Local connections only; no external DNS/URL canary service or off-machine detection."):new(id,LayerMode.Unavailable,false,"Decoy listener unavailable");
            case 53:return Good("Service monitor cycle running; SCM failure-restart policy configured by installer",limit:recoveryError??"Independent watchdog process is not implemented; SCM owns service recovery.");
            case 54:return Good("Desktop detects stale service snapshots and connection failures",limit:"Cannot report off-machine when the entire computer or UI is stopped.");
            case 55:case 65:return Good("Service IPC uses local interactive-user ACL, network deny, and impersonated administrator checks for every mutation",LayerMode.Enforcing,"UI is unprivileged; protected operations run in a UAC-elevated helper.");
            case 56:return Good("Length-limited framed JSON; XML DTDs disabled; bounded event fields",LayerMode.Enforcing,"Full parser fuzzing and isolation of all telemetry processing are incomplete.");
            case 57:return new(id,LayerMode.Unavailable,false,"Automatic trusted updates are blocked until a trusted publisher/signing identity is provisioned","No executable dependencies are downloaded at launch.");
            case 58:return File.Exists(Path.Combine(AppContext.BaseDirectory,"SBOM.json"))?Good("Installed package includes a build SBOM",LayerMode.Auditing,"SBOM presence is inventory evidence, not an independent integrity or vulnerability guarantee."):new(id,LayerMode.Unavailable,false,"Build SBOM not present beside service");
            case 59:
                var active=journal.Entries.Where(e=>e.State=="applied").ToArray();bool intact=active.All(e=>settings.Read(e.Key)==e.Applied);
                return intact?Good($"{active.Length} journaled settings still match OTS-applied values",LayerMode.Monitoring):new(id,LayerMode.Auditing,false,"An owned setting changed externally; it will be preserved on restore");
            case 60:return Good("Severity-labelled, deduplicated event history connected to dashboard",limit:"Desktop notifications require the running interactive application; external messaging is not configured.");
            case 61:if(events.LastError!=null)return new(id,LayerMode.Unavailable,false,"Persistent logging or integrity degraded: "+events.LastError,"Stored logs require administrator review; in-memory events are bounded.");
                return Good($"HMAC-authenticated retained log entries: {events.VerifiedRetainedEvents}; legacy chain discontinuities: {events.LegacyChainGaps}",limit:"Stored records are individually authenticated on service startup; chain links are continued across new restarts. Older builds restarted their chains, so historical end-to-end continuity cannot be guaranteed. Compressed segments rotate after 20; local administrators remain trusted.");
            case 62:return Good(battery?"Battery mode: 90-second normal telemetry, 15-minute heavy inventory":"AC mode: 30-second normal telemetry, 5-minute heavy inventory",limit:"Backoff follows measured service CPU/memory pressure. Bounded tables and serial audits; adaptive disk scheduling remains incomplete. Cached samples retain their true observation time.");
            case 63:return feed.Active is { } intel
                ?Good($"Official Feodo C2 IP source timestamp {intel.UpdatedUtc:O}; {intel.Addresses.Count} current indicators",LayerMode.Monitoring,"HTTPS transport and dated source are verified, but the feed is not cryptographically signed. Domain feeds and ruleset validation remain missing.")
                :new(id,LayerMode.Unavailable,false,feed.Summary,"No stale or unverified indicators are used. No blocking policies are installed.");
            case 64:return Good("Log-integrity key is encrypted by machine DPAPI in administrator/SYSTEM-only storage",LayerMode.Enforcing,"Local administrators remain trusted; DPAPI is not off-device protection.");
            case 66:return Good("High-severity events request a bounded, SHA-256-verified forensic snapshot on the next completed health cycle",LayerMode.Monitoring,"20 retained verified evidence files maximum; checksums detect damage but are not cryptographic attestations against administrators. Abrupt power loss may prevent capture.");
            case 67:return Good("Weighted capability-health score, checked-sensor confidence, and prioritized unverified-layer review items",LayerMode.Auditing,"Weighting is a policy heuristic; results are not independent security effectiveness, malware resistance, or risk probabilities.");
            case 68:return new(id,LayerMode.Idle,false,"Desktop supports verified encrypted, non-overwriting folder backup versions including last-modified timestamps","User selection required; no scheduled credential vault yet; 5,000-file/60 MiB limit; empty folders, symlinks, ACLs and full-system images are not preserved.");
            case 69:return Good("Separate UAC recovery executable and bundled offline recovery instructions",LayerMode.Auditing,"Not bootable recovery media; WinRE/boot media creation requires additional integration.");
            case 70:return new(id,LayerMode.Idle,false,"Encrypted log export queue supports verified copy, optional removable/network destinations and retry","No off-device destination or recoverable passphrase is configured by default; service auto-shipping requires explicit administrator opt-in and remains inactive.");
            case 71:return new(id,LayerMode.Idle,false,"Build-time positive, negative, corruption, encrypted-export, backup and recovery regressions; installed narrow self-check", "Not every layer has independent Windows hardware/integration tests or post-update behavioral verification. Production gate remains open.");
            case 72:
                try
                {
                    var path=Paths.At("reports","daily-posture.json");
                    var samples=QuarterlyHistory.Load(path);
                    return samples.Count>0?Good($"{samples.Count} historical daily posture samples; next completed-quarter report after {nextReport:yyyy-MM-dd}",LayerMode.Monitoring,"Samples require a running active service; missing days remain gaps and quarterly aggregation occurs upon next active monitor cycle.")
                        :new(id,LayerMode.Idle,false,"No completed daily history sample exists yet","First active monitoring cycle will attempt persistent sampling.");
                }
                catch(Exception ex){return new(id,LayerMode.Unavailable,false,"Historical report storage failed: "+Wire.Clean(ex.Message));}
            case 74:return Good("On-demand operational dossier includes all 79 catalog entries, modes, evidence timestamps, limitations, and prioritized review items",LayerMode.Auditing,"Machine observations are self-reported, not independent device attestation or certification.");
            default:return null;
        }
    }
    public void Dispose(){deception?.Dispose();sensors?.Dispose();feed.Dispose();}
}
