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
    var policy=new TemporaryFirewallGuard(new EventStore(Path.Combine(Path.GetTempPath(),"ots-network-guard-ci-"+Guid.NewGuid().ToString("N"))));
    policy.Start();
    if(!policy.Operational)throw new Exception("Windows Firewall source rule manager startup check failed: "+policy.Health);
    if(policy.ActiveRules!=0)throw new Exception("Unexpected temporary restrictions on fresh startup");
    policy.Dispose();
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
    return 0;
}
catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
