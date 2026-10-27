using System.ServiceProcess;
using OTS.Firewall79X.Windows;

namespace OTS.Firewall79X.Service;
internal sealed class FirewallService : ServiceBase
{
    private CancellationTokenSource? stop;private Engine? engine;private Task? task;
    public FirewallService(){ServiceName="OTSFirewall79X";CanStop=true;CanShutdown=true;AutoLog=true;}
    protected override void OnStart(string[] args)
    {
        stop=new();engine=new();
        task=Task.WhenAll(engine.RunAsync(stop.Token),Ipc.ServeAsync(engine.Handle,ex=>EventLog.WriteEntry($"IPC request failed: {ex.GetType().Name}",System.Diagnostics.EventLogEntryType.Warning),stop.Token));
        _=task.ContinueWith(t=>{if(t.IsFaulted){EventLog.WriteEntry(t.Exception!.GetBaseException().Message,System.Diagnostics.EventLogEntryType.Error);Environment.Exit(1);}},TaskScheduler.Default);
    }
    protected override void OnStop(){stop?.Cancel();try{task?.Wait(TimeSpan.FromSeconds(10));}catch(AggregateException ex)when(ex.InnerExceptions.All(e=>e is OperationCanceledException)){}engine?.Dispose();}
    protected override void OnShutdown()=>OnStop();
    public static void Main(string[] args)
    {
        if(args.Contains("--version")){Console.WriteLine("OTS Firewall79X 0.1.0 development");return;}
        ServiceBase.Run(new FirewallService());
    }
}
