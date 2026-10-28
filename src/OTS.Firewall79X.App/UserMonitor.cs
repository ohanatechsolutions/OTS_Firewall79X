using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.App;

internal sealed class UserMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> watchers=[];private readonly Queue<DateTimeOffset> changes=[];private readonly Queue<SecurityEvent> events=[];private readonly Dictionary<string,string> baseline=[];
    private readonly Channel<string> scans=Channel.CreateBounded<string>(new BoundedChannelOptions(64){FullMode=BoundedChannelFullMode.Wait,SingleReader=true});private readonly CancellationTokenSource stop=new();
    private readonly DispatcherTimer timer;private readonly object gate=new();private string? lastAddressHash;private DateTimeOffset addressAt;private string? defender;private int scansCompleted;private bool scanVerified;private string scanHealth="No scan run yet; scanner capability is unverified";
    private string currentUserScreenLock="Current-user screen-lock settings have not yet been examined";
    private DateTimeOffset nextScreenLockAudit=DateTimeOffset.MinValue;
    private BrowserSecurityAudit.Result browserAudit=new(0,0,0,0,0,0,"Browser audit has not completed");
    private DateTimeOffset nextBrowserAudit=DateTimeOffset.MinValue;
    private int browserAuditRunning;
    public bool Active {get;private set;}
    public UserMonitor()
    {
        var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);Directory.CreateDirectory(Path.Combine(local,"Ohana Tech Solutions","Firewall79X"));
        var documents=Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);var downloads=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Downloads");
        if(Directory.Exists(downloads))Watch(downloads,true);
        if(Directory.Exists(documents))
        {
            var canary=Path.Combine(documents,"OTS-Firewall79X-Canary.txt");if(!File.Exists(canary))File.WriteAllText(canary,"OTS Firewall79X ransomware canary. Contains no personal data.\n");Watch(documents,false);
        }
        var platform=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Microsoft","Windows Defender","Platform");
        if(Directory.Exists(platform))defender=Directory.GetDirectories(platform).OrderByDescending(Path.GetFileName,StringComparer.OrdinalIgnoreCase).Select(d=>Path.Combine(d,"MpCmdRun.exe")).FirstOrDefault(File.Exists);
        defender??=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Windows Defender","MpCmdRun.exe");
        if(!File.Exists(defender))defender=null;
        _=Task.Run(ScanLoop);timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(2)};timer.Tick+=Tick;timer.Start();Active=true;
    }
    private void Add(int layer,string severity,string kind,string detail)
    {lock(gate){events.Enqueue(new(DateTimeOffset.UtcNow,layer,severity,kind,Wire.Clean(detail)));while(events.Count>150)events.Dequeue();}}
    public List<SecurityEvent> Events(){lock(gate)return events.Reverse().ToList();}
    public List<LayerResult> Results()
    {
        var now=DateTimeOffset.UtcNow;
        return [new(46,LayerMode.Auditing,false,currentUserScreenLock,"Interactive HKCU snapshot only; does not prove an active session lock, Group Policy enforcement or all-user compliance.",now),new(28,LayerMode.Monitoring,Active,"Observes current-user camera/microphone ConsentStore timestamps","Privacy registry telemetry is incomplete and can lag; absence of an event is not proof of no device use.",now),new(32,LayerMode.Monitoring,Active,"Detects rapid changes between address-like clipboard strings","Address-format heuristic only; no attribution to a malicious process. Clipboard is never logged.",now),new(48,browserAudit.Profiles>0?LayerMode.Auditing:LayerMode.Unavailable,Active&&browserAudit.Profiles>0&&browserAudit.RiskyExtensions==0&&browserAudit.SafeBrowsingDisabled==0&&browserAudit.Unreadable==0&&browserAudit.UnknownPolicies==0,browserAudit.Evidence,"Read-only manifest/registry/profile heuristic; high-impact permissions are not proof of malware. User browser policy, Firefox signed-extension state and externally installed browser packages require further verification.",now),new(76,defender!=null?LayerMode.Monitoring:LayerMode.Unavailable,defender!=null&&scanVerified,$"Downloads scan requests completed: {scansCompleted}; {scanHealth}","Microsoft Defender must be installed and usable. Scan completion does not independently establish a detection verdict; see Protection History.",now),new(78,LayerMode.Monitoring,Active,"Documents/Downloads mass-change heuristic and named canary modification alerts","May miss read access, rapid events on buffer overflow, and changes outside watched folders. No automatic process termination.",now)];
    }
    private void Watch(string dir,bool download)
    {
        var w=new FileSystemWatcher(dir){IncludeSubdirectories=true,NotifyFilter=NotifyFilters.FileName|NotifyFilters.LastWrite|NotifyFilters.Size,InternalBufferSize=16384};
        void Changed(string path)
        {
            if(Path.GetFileName(path)=="OTS-Firewall79X-Canary.txt")Add(78,"High","Ransomware canary changed",Path.GetFileName(path));
            lock(gate){var now=DateTimeOffset.UtcNow;changes.Enqueue(now);while(changes.Count>0&&(changes.Peek()<now.AddSeconds(-10)||changes.Count>200))changes.Dequeue();if(changes.Count==40)Add(78,"Warning","High file-change rate","40 filesystem notifications in 10 seconds; normal sync/install operations can cause this");}
            if(download&&File.Exists(path)&&!scans.Writer.TryWrite(path)){scanHealth="Scan queue full; some files were not scanned";Add(76,"Warning","Scan queue full","New file scan was not queued");}
        }
        w.Created+=(_,e)=>Changed(e.FullPath);w.Changed+=(_,e)=>Changed(e.FullPath);w.Deleted+=(_,e)=>Changed(e.FullPath);w.Renamed+=(_,e)=>Changed(e.FullPath);
        w.Error+=(_,e)=>{Active=false;Add(78,"Warning","Filesystem watcher degraded",e.GetException().Message);};w.EnableRaisingEvents=true;watchers.Add(w);
    }
    private async Task ScanLoop()
    {
        var recent=new Dictionary<string,DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await foreach(var path in scans.Reader.ReadAllAsync(stop.Token))
            {
                if(defender==null){scanHealth="Defender scanner not available";continue;}
                if(recent.TryGetValue(path,out var last)&&DateTimeOffset.UtcNow-last<TimeSpan.FromMinutes(1))continue;
                if(recent.Count>2000)recent.Clear();recent[path]=DateTimeOffset.UtcNow;
                await Task.Delay(1500,stop.Token);
                try
                {
                    var info=new FileInfo(path);if(!info.Exists||info.Length>128*1024*1024||info.Attributes.HasFlag(FileAttributes.ReparsePoint)){scanHealth="Skipped missing, linked, or over-budget file";continue;}
                    var start=new ProcessStartInfo(defender){UseShellExecute=false,CreateNoWindow=true};foreach(var arg in new[]{"-Scan","-ScanType","3","-File",path,"-DisableRemediation"})start.ArgumentList.Add(arg);
                    using var p=Process.Start(start)??throw new IOException("Unable to start Defender scanner");using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);timeout.CancelAfter(TimeSpan.FromMinutes(2));
                    try{await p.WaitForExitAsync(timeout.Token);}catch(OperationCanceledException){p.Kill(true);throw;}
                    scansCompleted++;scanVerified=p.ExitCode==0;scanHealth=$"Last native scanner exit: {p.ExitCode}";Add(76,p.ExitCode==0?"Info":"Warning","Defender scan completed",$"{Path.GetFileName(path)}; exit {p.ExitCode}. Consult Windows Security for verdict.");
                }
                catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
                catch(Exception ex){scanVerified=false;scanHealth=ex.Message;Add(76,"Warning","File scan failed",ex.Message);}
            }
        }
        catch(OperationCanceledException)when(stop.IsCancellationRequested){}
    }
    private void Tick(object? sender,EventArgs e)
    {
        try
        {
            if(DateTimeOffset.UtcNow>=nextBrowserAudit&&Interlocked.CompareExchange(ref browserAuditRunning,1,0)==0)
            {
                nextBrowserAudit=DateTimeOffset.UtcNow.AddMinutes(5);
                _=Task.Run(()=>
                {
                    try {browserAudit=BrowserSecurityAudit.Read();}
                    catch(Exception ex) {Add(48,"Warning","Browser security audit unavailable",ex.GetType().Name);}
                    finally {Interlocked.Exchange(ref browserAuditRunning,0);}
                });
            }
            Track(48,"Browser security inventory",browserAudit.Evidence);
            if(DateTimeOffset.UtcNow>=nextScreenLockAudit)
            {
                nextScreenLockAudit=DateTimeOffset.UtcNow.AddMinutes(1);
                try
                {
                    using var saver=Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop");
                    using var policy=Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\Control Panel\Desktop");
                    using var restrictions=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System");
                    static string Val(RegistryKey? prefer,RegistryKey? fallback,string name)=>
                        (prefer?.GetValue(name)??fallback?.GetValue(name))?.ToString()??"unknown";
                    currentUserScreenLock="Current-user screen saver active="+Val(policy,saver,"ScreenSaveActive")+
                        "; password on resume="+Val(policy,saver,"ScreenSaverIsSecure")+
                        "; timeout seconds="+Val(policy,saver,"ScreenSaveTimeOut")+
                        "; disable workstation lock="+(restrictions?.GetValue("DisableLockWorkstation")?.ToString()??"unknown");
                    Track(46,"Current-user screensaver and workstation lock policy",currentUserScreenLock);
                }
                catch(Exception ex)when(ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
                {currentUserScreenLock="Current-user screen-lock configuration unavailable: "+ex.GetType().Name;}
            }
        {
            var text=BoundedClipboard.ReadAddressCandidate();
            if(text!=null)
            {
                if(text.Length<200&&Regex.IsMatch(text,@"^(?:0x[0-9a-fA-F]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(50)))
                {
                    var hash=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));var now=DateTimeOffset.UtcNow;
                    if(lastAddressHash!=null&&lastAddressHash!=hash&&now-addressAt<TimeSpan.FromSeconds(10))Add(32,"Warning","Possible address substitution","Clipboard changed between two payment-address-like strings; verify before pasting");
                    if(lastAddressHash!=hash)addressAt=now;lastAddressHash=hash;
                }
                else lastAddressHash=null;
            }
            else lastAddressHash=null;
            foreach(var capability in new[]{"webcam","microphone"})
            {
                using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\"+capability+@"\NonPackaged");
                if(key==null)continue;
                foreach(var app in key.GetSubKeyNames().Take(1000)){using var k=key.OpenSubKey(app);var state=$"{k?.GetValue("LastUsedTimeStart")}:{k?.GetValue("LastUsedTimeStop")}";Track(28,$"{capability}:{app}",state);}
            }
            using(var proxy=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))Track(33,"User proxy configuration",$"{proxy?.GetValue("ProxyEnable")}:{proxy?.GetValue("ProxyServer")}");
            foreach(var relative in new[]{@"Google\Chrome\User Data\Default\Extensions",@"Microsoft\Edge\User Data\Default\Extensions"}){var path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),relative);if(Directory.Exists(path))Track(48,relative,string.Join(";",Directory.GetDirectories(path).Select(Path.GetFileName).Order()));}
        }
        catch(System.Runtime.InteropServices.COMException){Add(32,"Info","Clipboard busy","A sample was skipped; retrying on the next timer tick");}
        catch(Exception ex){Add(28,"Warning","Interactive sensor error",ex.Message);}
    }
    private void Track(int layer,string key,string value){if(baseline.TryGetValue(key,out var old)&&old!=value)Add(layer,"Info","User configuration/activity changed",key);baseline[key]=value;}
    public void Dispose(){Active=false;timer.Stop();stop.Cancel();foreach(var w in watchers)w.Dispose();scans.Writer.TryComplete();lastAddressHash=null;}
}
