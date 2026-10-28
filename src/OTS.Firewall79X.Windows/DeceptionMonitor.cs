using System.Net;
using System.Net.Sockets;
using System.Text;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class DeceptionMonitor : IDisposable
{
    private readonly FileSystemWatcher watcher;private readonly TcpListener listener;private readonly CancellationTokenSource stop=new();private readonly Task server;
    public int Port {get;}
    public DeceptionMonitor(EventStore events)
    {
        var directory=Paths.At("canaries");Paths.SecureDirectory(directory);
        var file=Path.Combine(directory,"decoy-credentials.txt");
        if(!File.Exists(file))File.WriteAllText(file,"OTS Firewall79X canary. These values are nonfunctional.\nuser=OTS-DECOY\npassword=NOT-A-REAL-CREDENTIAL\n");
        watcher=new(directory){NotifyFilter=NotifyFilters.LastWrite|NotifyFilters.FileName|NotifyFilters.Size};
        watcher.Changed+=(_,e)=>events.Add(11,"High","Canary modified",Path.GetFileName(e.FullPath));
        watcher.Deleted+=(_,e)=>events.Add(11,"High","Canary deleted",Path.GetFileName(e.FullPath));
        watcher.Renamed+=(_,e)=>events.Add(11,"High","Canary renamed",Path.GetFileName(e.FullPath));
        watcher.Error+=(_,e)=>events.Add(11,"Warning","Canary watcher error",e.GetException().Message);watcher.EnableRaisingEvents=true;
        listener=new TcpListener(IPAddress.Loopback,0);listener.Start(8);Port=((IPEndPoint)listener.LocalEndpoint).Port;
        server=Serve(events,stop.Token);
    }
    private async Task Serve(EventStore events,CancellationToken ct)
    {
        while(!ct.IsCancellationRequested)
        {
            try
            {
                using var client=await listener.AcceptTcpClientAsync(ct);events.Add(12,"Warning","Local canary URL contacted",$"Loopback port {Port}; no remote reachability claimed");events.Add(13,"Warning","Decoy listener connection","A local process connected to the loopback-only decoy service");
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(1));
                await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),timeout.Token);
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){break;}
            catch(Exception ex){if(!ct.IsCancellationRequested)events.Add(13,"Warning","Decoy listener error",ex.Message);}
        }
    }
    public bool Healthy=>!server.IsCompleted;
    public void Dispose(){stop.Cancel();listener.Stop();watcher.Dispose();}
}
