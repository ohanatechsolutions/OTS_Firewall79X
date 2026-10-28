using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using OTS.Firewall79X.Core;
using OTS.Firewall79X.Windows;

if(!OperatingSystem.IsWindows())return 2;
bool admin=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
try
{
    if(args.Contains("--impostor"))
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")throw new Exception("Impostor probe is restricted to disposable CI");
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var fake=new NamedPipeServerStream(Ipc.PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
        var connect=fake.WaitForConnectionAsync(timeout.Token);
        var client=Ipc.SendAsync("status",timeout.Token);
        await connect;
        try{await client;throw new Exception("Client accepted an endpoint not owned by the registered service");}
        catch(UnauthorizedAccessException){return 0;}
    }
    var status=await Ipc.SendAsync("status");if(!status.Ok||status.Dashboard?.Layers.Count!=79)throw new Exception("Status/catalog unavailable");
    if(args.Contains("--unprivileged"))
    {
        if(admin)throw new Exception("This probe must use a nonadministrator token");
        foreach(var command in new[]{"on","off","pause","restore","report","selftest","domains-on","domains-off"}){var r=await Ipc.SendAsync(command);if(r.Ok||!r.Message.Contains("Administrator"))throw new Exception("Privilege boundary failed for "+command);}
        var protectedKey=Path.Combine(Paths.Root,"logs","integrity.dpapi");
        try{_ = File.ReadAllBytes(protectedKey);throw new Exception("Unprivileged user read the protected integrity key");}
        catch(UnauthorizedAccessException) { /* expected least-privilege boundary */ }
        return 0;
    }
    if(!admin)throw new Exception("Administrative integration probe expected");
    // Real Win32 File.Replace test on an isolated fixture, never on the live Windows hosts file.
    var testRoot=Path.Combine(Path.GetTempPath(),"OTS-domain-test-"+Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(testRoot);
    try
    {
        var hostFile=Path.Combine(testRoot,"hosts");
        var original="# unrelated admin-managed mapping\n10.0.0.2 internal.corp\n";
        File.WriteAllText(hostFile,original);
        var names=Enumerable.Range(0,12).Select(i=>$"malware-{i}.example.net").ToHashSet();
        var feed=new MaliciousDomainIntelligence.Snapshot(DateTimeOffset.UtcNow,names,0);
        var blocks=new DomainHostsProtection(null,hostFile);
        blocks.Enable(feed);
        if(!blocks.Applied || !File.ReadAllText(hostFile).Contains("0.0.0.0 malware-0.example.net"))
            throw new Exception("Domain fixture did not install exact hostname blocks");
        File.AppendAllText(hostFile,"# externally added comment\n");
        blocks.Restore();
        if(blocks.Applied || File.ReadAllText(hostFile)!=original+"# externally added comment\n")
            throw new Exception("Domain rollback failed to preserve external fixture changes");
        blocks.Restore(); // idempotence
    }
    finally { Directory.Delete(testRoot,true); }



    if(!status.Dashboard.Enabled)throw new Exception("Protection expected enabled");
    var started=DateTimeOffset.UtcNow;
    while(status.Dashboard.Time<started.AddSeconds(-5)||!status.Dashboard.Layers.Any(l=>l.CheckedAt!=null))
    {
        if(DateTimeOffset.UtcNow-started>TimeSpan.FromMinutes(3))throw new Exception("No completed health cycle within three minutes");
        await Task.Delay(2000);status=await Ipc.SendAsync("status");if(status.Dashboard==null)throw new Exception("Status response missing dashboard");
    }
    Directory.CreateDirectory("artifacts");File.WriteAllText("artifacts/windows-observed-status.json",JsonSerializer.Serialize(status.Dashboard,new JsonSerializerOptions(Wire.Json){WriteIndented=true}));
    if(status.Dashboard.Protection!="Partially Protected"||status.Dashboard.BlockedEvents!=0)throw new Exception("Preview overstates protection or blocks");
    var applied=new WindowsSettings().Read(WindowsSettings.AutoRun);if(applied!="255")throw new Exception("Journaled hardening was not applied");
    var windowsSettings=new WindowsSettings();
    if(windowsSettings.Read(WindowsSettings.NoAutorun)!="1"||
       windowsSettings.Read(WindowsSettings.NoAutoplayNonVolume)!="1"||
       windowsSettings.Read(WindowsSettings.SmartScreen)!="1")
        throw new Exception("Extended hardening registry policy was not applied");
    if(WindowsSettings.SafeHardeningKeys.Count!=4)
        throw new Exception("Unexpected hardening allowlist mutation");
    if(!SectionFAudits.IsManagementPort("[::]:5985")||
       SectionFAudits.IsManagementPort("[::1]:443")||
       SectionFAudits.NonLoopbackListener("[::1]:5985")||
       !SectionFAudits.NonLoopbackListener("0.0.0.0:5985"))
        throw new Exception("Management listener classification failed");
    var hostEvidence=SectionFAudits.HostEvidence();
    if(!hostEvidence.Contains("ASLR")||!hostEvidence.Contains("password policy",StringComparison.OrdinalIgnoreCase))
        throw new Exception("Host hardening supplemental evidence missing");
    var exposure=SectionFAudits.Exposure(new[]{"127.0.0.1:1234","0.0.0.0:5985"});
    if(!exposure.Contains("1 on common management ports")||!exposure.Contains("NOT prove"))
        throw new Exception("Local-vs-public exposure disclaimer missing");
    var update=WindowsMissingUpdateAudit.Latest(out var updateState);
    if(string.IsNullOrWhiteSpace(updateState))
        throw new Exception("Missing-update audit does not expose provider status");
    var everyone=new System.Security.AccessControl.RawSecurityDescriptor("D:(A;;FA;;;WD)");
    var administrators=new System.Security.AccessControl.RawSecurityDescriptor("D:(A;;FA;;;BA)");
    var readOnly=new System.Security.AccessControl.RawSecurityDescriptor("D:(A;;FR;;;WD)");
    if(!SectionFPermissionsAudit.HasPotentialBroadWriteAce(everyone) ||
       SectionFPermissionsAudit.HasPotentialBroadWriteAce(administrators) ||
       SectionFPermissionsAudit.HasPotentialBroadWriteAce(readOnly))
        throw new Exception("Potential insecure file ACL heuristic failed deterministic fixtures");
    var aclEvidence=SectionFPermissionsAudit.Read("program",AppContext.BaseDirectory);
    if(string.IsNullOrEmpty(aclEvidence.Evidence))
        throw new Exception("Sensitive ACL audit returned no explicit evidence");
    var audit=HostHardeningAudit.Read();
    if(!audit.Summary.Contains("UAC=")||!audit.Summary.Contains("DEP=")||!audit.Summary.Contains("SMBv1"))throw new Exception("Hardening audit evidence missing");
    var integrity=status.Dashboard.Layers.Single(l=>l.Id==61);
    if(integrity.Mode==LayerMode.Unavailable || !integrity.Evidence.Contains("HMAC-authenticated"))
        throw new Exception("Stored log-integrity verification not operational: "+integrity.Evidence);
    // Verify the DPAPI keyring survives process restart and preserves records
    // from both key generations. No real host security policy is modified.
    var logTest=Path.Combine(Paths.Root,"ci-integrity-"+Guid.NewGuid().ToString("N"));
    try
    {
        var initial=new EventStore(logTest);
        initial.Add(61,"Info","Test baseline","before rotation");
        initial.RotateIntegrityKey();
        initial.Add(61,"Info","Test rotation","after rotation");
        var reopened=new EventStore(logTest);
        if(reopened.LastError!=null||reopened.IntegrityKeyVersion!=1 ||
            reopened.RetainedIntegrityKeys!=2||reopened.VerifiedRetainedEvents!=2||
            reopened.Total!=2||reopened.LegacyChainGaps!=0)
            throw new Exception("Key rotation did not preserve authenticated event history: "+reopened.LastError);
        // A corrupted protected ring must fail closed instead of re-keying history.
        var ringFile=Path.Combine(logTest,"keyring.dpapi");
        var corrupted=File.ReadAllBytes(ringFile);corrupted[^1]^=0x80;
        File.WriteAllBytes(ringFile,corrupted);
        bool rejected=false;
        try{_ = new EventStore(logTest);}
        catch(System.Security.Cryptography.CryptographicException){rejected=true;}
        catch(InvalidDataException){rejected=true;}
        if(!rejected)throw new Exception("Corrupted DPAPI key ring was accepted");
    }
    finally {if(Directory.Exists(logTest))Directory.Delete(logTest,true);}
    var hardware=SecurityDeviceAudit.Read();
    if(!hardware.Evidence.Contains("TPM:")||!hardware.Evidence.Contains("OS drive protection:"))
        throw new Exception("Hardware security evidence unavailable even as an explicit unknown");
    var policy=new TemporaryFirewallGuard(new EventStore(Path.Combine(Path.GetTempPath(),"ots-network-guard-ci-"+Guid.NewGuid().ToString("N"))));
    policy.Start();
    if(policy.BlockObservedIntelligence("127.0.0.1",DateTimeOffset.UtcNow) ||
       policy.BlockObservedIntelligence("192.0.2.10",DateTimeOffset.UtcNow) ||
       policy.BlockObservedIntelligence("::ffff:8.8.8.8",DateTimeOffset.UtcNow))
       throw new Exception("Invalid intelligence destination passed allowlist");
    if(!policy.Operational)throw new Exception("Windows Firewall source rule manager startup check failed: "+policy.Health);
    if(policy.ActiveRules!=0)throw new Exception("Unexpected temporary restrictions on fresh startup");
    policy.Dispose();
    if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true")
    {
        // Integration regression: an attacker or external administrator may create a
        // reserved-name rule. A prefix is not sufficient authority to delete it.
        dynamic firewall=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        var spoofName=OwnedFirewallRule.InboundPrefix+"9.9.9.9";
        dynamic spoof=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        try
        {
            spoof.Name=spoofName;
            spoof.Description="External rule: never delete solely by reserved name";
            spoof.Direction=1;spoof.Action=0;spoof.Protocol=256;
            spoof.RemoteAddresses="9.9.9.9";spoof.Profiles=int.MaxValue;spoof.Enabled=true;
            firewall.Rules.Add(spoof);
            using(var guarded=new TemporaryFirewallGuard(new EventStore(
                Path.Combine(Path.GetTempPath(),"ots-rule-preservation-ci-"+Guid.NewGuid().ToString("N")))))
            {
                guarded.Start();
                if(!guarded.Operational)throw new Exception("Guard failed to initialize");
            }
            dynamic? stillPresent=firewall.Rules.Item(spoofName);
            if(stillPresent==null)throw new Exception("Modified reserved-name rule was deleted by cleanup");
            System.Runtime.InteropServices.Marshal.ReleaseComObject(stillPresent);
        }
        finally
        {
            try{firewall.Rules.Remove(spoofName);}
            finally
            {
                System.Runtime.InteropServices.Marshal.ReleaseComObject(spoof);
                System.Runtime.InteropServices.Marshal.ReleaseComObject(firewall);
            }
        }
    }
    var udp=NetworkTables.UdpSockets();if(udp.Any(c=>c.State!="UDP Bound"))throw new Exception("Non-UDP entry in UDP table");
    var conns=NetworkTables.Connections();if(conns.Count==0)throw new Exception("TCP table unexpectedly empty on CI host");
    using(var pipe=new NamedPipeClientStream(".",Ipc.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous))
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));await pipe.ConnectAsync(timeout.Token);await Wire.WriteAsync(pipe,new Request("run-arbitrary-command"),timeout.Token);var unknown=await Wire.ReadAsync<Response>(pipe,4096,timeout.Token);if(unknown.Ok)throw new Exception("Unknown command accepted");
    }
    using(var pipe=new NamedPipeClientStream(".",Ipc.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous))
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));await pipe.ConnectAsync(timeout.Token);await pipe.WriteAsync(BitConverter.GetBytes(int.MaxValue),timeout.Token);await pipe.FlushAsync(timeout.Token);var b=new byte[1];int count=await pipe.ReadAsync(b,timeout.Token);if(count!=0)throw new Exception("Malformed frame not rejected");
    }
    if(!(await Ipc.SendAsync("status")).Ok)throw new Exception("Service unhealthy after malformed message");
    // Exercise the installed service, not a mocked canary listener. These tests
    // run only inside the disposable Windows CI environment.
    var canaryFolder=Paths.At("canaries");
    var urlPath=Path.Combine(canaryFolder,"canary-url.txt");
    var credentialsPath=Path.Combine(canaryFolder,"decoy-credentials.txt");
    var dnsPath=Path.Combine(canaryFolder,"canary-dns.txt");
    if(!File.Exists(urlPath)||!File.Exists(credentialsPath)||!File.Exists(dnsPath))
        throw new Exception("Section B canary files were not deployed");
    var canaryUrl=new Uri(File.ReadAllText(urlPath).Trim());
    if(canaryUrl.Host!="127.0.0.1"||canaryUrl.Scheme!="http"
        ||!canaryUrl.AbsolutePath.StartsWith("/canary/"))
        throw new Exception("Local canary escaped the loopback security boundary");
    using(var http=new HttpClient(new HttpClientHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(5)})
    {
        var canaryResponse=await http.GetAsync(canaryUrl);
        if(canaryResponse.StatusCode!=System.Net.HttpStatusCode.NoContent)
            throw new Exception("Exact canary URL did not return 204");
        var decoyResponse=await http.GetAsync(new Uri($"http://127.0.0.1:{canaryUrl.Port}/unrecognized-probe"));
        if(decoyResponse.StatusCode!=System.Net.HttpStatusCode.NotFound)
            throw new Exception("Decoy service did not return safe 404");
    }
    // A non-canary file in the same folder must not be treated as a honeytoken.
    var beforeNegative=(await Ipc.SendAsync("status")).Dashboard!.Events.Count(e=>
        e.Layer==11 && e.Kind=="Canary content tampered");
    var unrelatedPath=Path.Combine(canaryFolder,"not-an-ots-decoy.txt");
    try
    {
        File.WriteAllText(unrelatedPath,"unrelated test file");
        await Task.Delay(400);
        var afterNegative=(await Ipc.SendAsync("status")).Dashboard!.Events.Count(e=>
            e.Layer==11 && e.Kind=="Canary content tampered");
        if(afterNegative!=beforeNegative)
            throw new Exception("Unrelated file produced a canary tamper false positive");
    }
    finally { File.Delete(unrelatedPath); }
    // Use true Security 4663 telemetry for read attribution, not a synthetic
    // event. Conditional because the service never changes machine audit policy.
    var canaryStatus=(await Ipc.SendAsync("status")).Dashboard?.Layers.Single(x=>x.Id==11);
    bool systemAuditEnabled=false;
    try { systemAuditEnabled=AuditPolicy.Coverage(31).Enabled; }
    catch { /* Unsupported/inaccessible audit-policy query is an unavailable capability. */ }
    bool canaryReadAuditing=systemAuditEnabled
        && canaryStatus?.Evidence.Contains("read-audit setup: Narrow canary-file SACL installed") == true;
    if(canaryReadAuditing)
    {
        var prior=(await Ipc.SendAsync("status")).Dashboard!.Events.Count(e=>
            e.Layer==11 && e.Kind=="Audited canary file read");
        // Read in this separate Windows integration-test process so it cannot
        // be mistaken for the service's own integrity-verifier reads.
        _ = File.ReadAllText(credentialsPath);
        bool readFound=false;
        for(int attempt=0;attempt<15;attempt++)
        {
            await Task.Delay(400);
            var observed=(await Ipc.SendAsync("status")).Dashboard!.Events.Count(e=>
                e.Layer==11 && e.Kind=="Audited canary file read");
            if(observed>prior){readFound=true;break;}
        }
        if(!readFound)
            throw new Exception("Enabled canary audit policy/SACL failed to attribute a genuine file read");
    }
    var originalCanary=File.ReadAllText(credentialsPath);
    try
    {
        File.AppendAllText(credentialsPath,"\nOTS-INTEGRATION-TAMPER");
        await Task.Delay(1200);
        var after=await Ipc.SendAsync("status");
        var observed=after.Dashboard?.Events??[];
        if(!observed.Any(e=>e.Layer==11&&e.Kind=="Canary content tampered")
            || !observed.Any(e=>e.Layer==12&&e.Kind=="Local canary URL contacted")
            || !observed.Any(e=>e.Layer==13&&e.Kind=="Decoy service connection"))
            throw new Exception("Expected Section B tamper, URL and honeypot events not observed");
    }
    finally { File.WriteAllText(credentialsPath,originalCanary); }
    var sections=(await Ipc.SendAsync("status")).Dashboard?.Layers;
    if(sections is null||sections.Any(x=>x.Id is 11 or 12 or 13 && x.Mode==LayerMode.Enforcing))
        throw new Exception("Deception layers falsely claimed network enforcement");

    return 0;
}
catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
