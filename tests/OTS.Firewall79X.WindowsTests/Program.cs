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
        foreach(var command in new[]{"on","off","pause","restore","report","selftest"}){var r=await Ipc.SendAsync(command);if(r.Ok||!r.Message.Contains("Administrator"))throw new Exception("Privilege boundary failed for "+command);}
        return 0;
    }
    if(!admin)throw new Exception("Administrative integration probe expected");
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
    var audit=HostHardeningAudit.Read();
    if(!audit.Summary.Contains("UAC=")||!audit.Summary.Contains("DEP=")||!audit.Summary.Contains("SMBv1"))throw new Exception("Hardening audit evidence missing");
    var integrity=status.Dashboard.Layers.Single(l=>l.Id==61);
    if(integrity.Mode==LayerMode.Unavailable || !integrity.Evidence.Contains("HMAC-authenticated"))
        throw new Exception("Stored log-integrity verification not operational: "+integrity.Evidence);
    var hardware=SecurityDeviceAudit.Read();
    if(!hardware.Evidence.Contains("TPM:")||!hardware.Evidence.Contains("OS drive protection:"))
        throw new Exception("Hardware security evidence unavailable even as an explicit unknown");
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
