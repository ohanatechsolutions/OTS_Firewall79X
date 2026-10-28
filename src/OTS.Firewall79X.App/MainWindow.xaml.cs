using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
using OTS.Firewall79X.Windows;
namespace OTS.Firewall79X.App;

public partial class MainWindow : Window
{
    private sealed record Row(int Id,string Name,string Category,string Mode,string Health,string Evidence,double? Duration);
    private DesktopNotifications? notifications;private DateTimeOffset lastAlert=DateTimeOffset.UtcNow,lastNotification=DateTimeOffset.MinValue;
    private Dashboard? dashboard;private List<Row> rows=[];private bool refreshing;private UserMonitor? userMonitor;private ExternalExposureAudit.Result? exposureResult;private PackageVulnerabilityAudit.Result? nugetAuditResult;private readonly DispatcherTimer timer;private bool ready;
    private static readonly HttpClient http=new(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false})
    {Timeout=TimeSpan.FromSeconds(20),MaxResponseContentBufferSize=1024*1024};
    public MainWindow()
    {
        InitializeComponent();SourceInitialized+=(_,_)=>NativeChrome.Apply(this);ready=true;timer=new(){Interval=TimeSpan.FromSeconds(5)};timer.Tick+=async(_,_)=>await Refresh();timer.Start();Loaded+=async(_,_)=>{FitWindowToDisplay();notifications=new(this);await Refresh();};Closed+=(_,_)=>{timer.Stop();userMonitor?.Dispose();notifications?.Dispose();};
    }
    private void FitWindowToDisplay()
    {
        // WPF device-independent working-area bounds; avoid covering the taskbar
        // or launching taller than a 768p display. Content panels already scroll.
        var work=SystemParameters.WorkArea;
        if(work.Width<640||work.Height<480)return;
        MinWidth=Math.Min(MinWidth,work.Width*0.94);
        MinHeight=Math.Min(MinHeight,work.Height*0.94);
        Width=Math.Max(MinWidth,Math.Min(Width,work.Width*0.94));
        Height=Math.Max(MinHeight,Math.Min(Height,work.Height*0.92));
        Left=work.Left+(work.Width-Width)/2;
        Top=work.Top+(work.Height-Height)/2;
    }
    private async Task Refresh()
    {
        if(refreshing)return;refreshing=true;
        try
        {
            var response=await Ipc.SendAsync("status");if(!response.Ok||response.Dashboard==null)throw new InvalidOperationException(response.Message);
            dashboard=response.Dashboard;
            bool stale=dashboard.Enabled&&DateTimeOffset.UtcNow-dashboard.Time>TimeSpan.FromMinutes(4);
            if(dashboard.Enabled&&UserMonitoring.IsChecked==true&&userMonitor==null){try{userMonitor=new();}catch(Exception ex){StatusLine.Text="Interactive monitor failed: "+ex.Message;UserMonitoring.IsChecked=false;}}
            if(!dashboard.Enabled&&userMonitor!=null){userMonitor.Dispose();userMonitor=null;}
            if(userMonitor!=null)
            {
                var overlay=userMonitor.Results().Where(l=>l.Id is 28 or 32 or 46 or 48).ToDictionary(l=>l.Id);var layers=dashboard.Layers.Select(l=>
                {
                    if(!overlay.TryGetValue(l.Id,out var user))return l;
                    if(l.Id!=46)return user;
                    return l with{Evidence=l.Evidence+"; "+user.Evidence,
                        Limitation=l.Limitation+"; "+user.Limitation,
                        Healthy=false};
                }).ToList();var score=Posture.Calculate(layers,dashboard.Enabled);
                dashboard=dashboard with{Layers=layers,Score=score.Score,Confidence=score.Confidence,Events=dashboard.Events.Concat(userMonitor.Events()).OrderByDescending(e=>e.Time).Take(300).ToList()};
            }
            if(exposureResult is { } evidence&&DateTimeOffset.UtcNow-evidence.ObservedAt<TimeSpan.FromHours(1))
            {
                dashboard=dashboard with{Layers=dashboard.Layers.Select(l=>l.Id==49
                    ?l with{Evidence=l.Evidence+"; "+evidence.Evidence,
                             Limitation=l.Limitation+"; "+evidence.Limitation}
                    :l).ToList()};
            }
            if(nugetAuditResult is { } osv&&dashboard.Enabled)
            {
                dashboard=dashboard with{Layers=dashboard.Layers.Select(l=>l.Id==52
                    ?l with{Evidence=l.Evidence+"; "+osv.Evidence,
                             Limitation=l.Limitation+"; "+osv.Limitation}
                    :l).ToList()};
            }
            ProtectionText.Text=stale?"Protection status stale — service health requires attention":dashboard.Protection;
            AuthGuardToggle.IsEnabled=dashboard.Enabled;
            AuthGuardToggle.Content=dashboard.AuthenticationProtectionEnabled?"Disable optional RDP guard":"Enable optional RDP guard";
            Toggle.Content=dashboard.Enabled?"Turn OFF":"Turn ON";ScoreText.Text=stale?"Unknown":$"{dashboard.Score} / 100";ConfidenceText.Text=$"Observed data: {dashboard.Confidence:F1}%";
            BlockedText.Text=dashboard.BlockedEvents.ToString("N0");EventCountText.Text=dashboard.TotalEvents.ToString("N0");
            ResourceText.Text=$"Service working set: {dashboard.ServiceMemoryMb:F1} MB • CPU across all cores: {dashboard.CpuPercent?.ToString("F1")??"unknown"}% • last cycle {dashboard.Time.ToLocalTime():g}";
            FeedText.Text=dashboard.FeedStatus;
            var unavailable=dashboard.Layers.Count(l=>l.Mode==LayerMode.Unavailable);HealthSummary.Text=$"{unavailable} unavailable layers. Review each layer’s evidence and limitations. A healthy audit does not mean a complete protection mechanism.";
            SystemHealthText.Text=$"Service responded at {DateTimeOffset.Now:g}. "+(dashboard.ResumeAt.HasValue?$"Automatic resume: {dashboard.ResumeAt.Value.ToLocalTime():g}":"");
            if(notifications!=null&&!notifications.Ready)SystemHealthText.Text+=" Desktop notification registration is unavailable; use Threat Activity for alerts.";
            rows=dashboard.Layers.Select(l=>{var def=Catalog.All.Single(d=>d.Id==l.Id);return new Row(l.Id,def.Name,def.Category,l.Mode.ToString(),l.Healthy?"Operational":"Attention / idle",l.Evidence+(l.Limitation.Length>0?" — "+l.Limitation:""),l.DurationMs);}).ToList();Filter();
            EventGrid.ItemsSource=dashboard.Events;RecentEvents.ItemsSource=dashboard.Events.Take(5).ToArray();
            RecentEmpty.Visibility=ActivityEmpty.Visibility=dashboard.Events.Count==0?Visibility.Visible:Visibility.Collapsed;
            ShieldState.Text=stale?"STALE":dashboard.Enabled?"LIMITED":"OFF";
            NetworkGrid.ItemsSource=dashboard.Connections;
            var high=dashboard.Events.Where(e=>e.Severity=="High"&&e.Time>lastAlert).OrderByDescending(e=>e.Time).FirstOrDefault();
            if(high!=null)
            {
                lastAlert=high.Time;
                if(DateTimeOffset.UtcNow-lastNotification>TimeSpan.FromMinutes(2)){notifications?.Show("OTS Firewall79X security alert",high.Kind+". Open Threat Activity for details.");lastNotification=DateTimeOffset.UtcNow;}
            }
            StatusLine.Text=stale?"Service has not completed a recent health cycle. Do not rely on the displayed score.":"Connected to local service. Administrator approval is requested only for protected operations.";
        }
        catch(Exception ex){ShieldState.Text="UNAVAILABLE";ProtectionText.Text="Service unavailable — protection status unknown";ScoreText.Text="Unknown";StatusLine.Text=ex.Message+". Use Recovery if the service cannot start.";}
        finally{refreshing=false;}
    }
    private async void AuthGuardClick(object sender,RoutedEventArgs e)
    {
        if(dashboard?.Enabled!=true)return;
        if(!dashboard.AuthenticationProtectionEnabled)
        {
            var answer=MessageBox.Show(
                "This opt-in feature can temporarily reject legitimate RDP sessions from shared/public source addresses. It never changes Windows account lockout policy and affects TCP 3389 only. Do not enable it if you depend on remote desktop access to this PC. Enable for the current OTS service activation?",
                "Temporary RDP source restrictions",MessageBoxButton.YesNo,MessageBoxImage.Warning);
            if(answer!=MessageBoxResult.Yes)return;
        }
        await Command(dashboard.AuthenticationProtectionEnabled?"authguard-off":"authguard-on");
    }
    private async Task Command(string command)
    {
        try
        {
            Toggle.IsEnabled=false;var exe=Path.Combine(AppContext.BaseDirectory,"recovery","OTS.Firewall79X.Recovery.exe");
            var start=new ProcessStartInfo(exe){UseShellExecute=true,Verb="runas"};start.ArgumentList.Add("--"+command);start.ArgumentList.Add("--quiet");using var p=Process.Start(start)??throw new IOException("Could not start authorization helper");await p.WaitForExitAsync();if(p.ExitCode!=0)throw new InvalidOperationException("Operation failed or administrator authorization was declined. Use Recovery for details.");await Refresh();
        }
        catch(Exception ex){MessageBox.Show(ex.Message,"OTS Firewall79X",MessageBoxButton.OK,MessageBoxImage.Warning);}
        finally{Toggle.IsEnabled=true;}
    }
    private async void ToggleClick(object sender,RoutedEventArgs e)=>await Command(dashboard?.Enabled==true?"off":"on");
    private async void PauseClick(object sender,RoutedEventArgs e)=>await Command("pause");
    private async void RestoreClick(object sender,RoutedEventArgs e)=>await Command("restore");
    private async void SelfTestClick(object sender,RoutedEventArgs e)=>await Command("selftest");
    private async void DomainsOnClick(object sender,RoutedEventArgs e)
    {
        var confirmed=MessageBox.Show("Enable Windows hosts-file blocking for up to 1,000 exact hostnames from an unsigned public threat-feed mirror?\n\nThis is optional and can block legitimate sites. DNS-over-HTTPS may bypass it. OTS will restore its managed entries when protection stops, on reboot, or if the feed expires. Continue?","Confirm optional domain blocking",MessageBoxButton.YesNo,MessageBoxImage.Warning);
        if(confirmed==MessageBoxResult.Yes)await Command("domains-on");
    }
    private async void DomainsOffClick(object sender,RoutedEventArgs e)=>await Command("domains-off");
    private async void RefreshClick(object sender,RoutedEventArgs e)=>await Refresh();
    private void LayerSearchChanged(object sender,TextChangedEventArgs e){if(ready){Filter();if(LayerSearch.Text.Length>0)MainTabs.SelectedIndex=1;}}
    private void Filter(){var q=LayerSearch.Text.Trim();LayerGrid.ItemsSource=rows.Where(r=>$"{r.Id} {r.Name} {r.Category} {r.Evidence}".Contains(q,StringComparison.OrdinalIgnoreCase)).ToArray();}
    private void LayerSelected(object sender,SelectionChangedEventArgs e){if(LayerGrid.SelectedItem is Row r)StatusLine.Text=$"Layer {r.Id}: {r.Evidence}";}
    private void SecurityClick(object sender,RoutedEventArgs e){try{Process.Start(new ProcessStartInfo("windowsdefender:"){UseShellExecute=true});}catch(Exception ex){MessageBox.Show(ex.Message);}}
    private async void UserMonitoringChanged(object sender,RoutedEventArgs e){if(!ready)return;if(UserMonitoring.IsChecked!=true){userMonitor?.Dispose();userMonitor=null;}await Refresh();}
    private string? Report()=>dashboard==null?null:Reports.Generate(dashboard);
    private void ReportClick(object sender,RoutedEventArgs e)
    {
        var report=Report();if(report==null){MessageBox.Show("No service report available yet.");return;}
        var save=new SaveFileDialog{Filter="Markdown report|*.md",FileName=$"OTS-Firewall79X-Report-{DateTime.Now:yyyyMMdd}.md"};if(save.ShowDialog()==true)try{File.WriteAllText(save.FileName,report);StatusLine.Text="Report saved.";}catch(Exception ex){MessageBox.Show(ex.Message);}
    }
    private async void ExternalExposureClick(object sender,RoutedEventArgs e)
    {
        const string notice="This optional lookup discloses your current public IPv4 address to api4.ipify.org and Shodan InternetDB. The external provider may retain the request. Its previously observed ports are NOT a live or complete scan, and a missing record does NOT prove safety. Continue?";
        if(MessageBox.Show(notice,"Optional external exposure intelligence",MessageBoxButton.YesNo,MessageBoxImage.Information)!=MessageBoxResult.Yes)
            return;
        if(sender is System.Windows.Controls.Button button)button.IsEnabled=false;
        try
        {
            ExternalExposureResult.Text="Checking outside-observed historical port intelligence…";
            using var ct=new CancellationTokenSource(TimeSpan.FromSeconds(25));
            exposureResult=await ExternalExposureAudit.LookupAsync(http,ct.Token);
            ExternalExposureResult.Text=exposureResult.Evidence+" "+exposureResult.Limitation;
            await Refresh();
        }
        catch(Exception ex)
        {
            exposureResult=null;
            ExternalExposureResult.Text="External lookup unavailable: "+ex.GetType().Name+
                ". Local listeners do not demonstrate external reachability. No safety conclusion can be drawn.";
        }
        finally {if(sender is System.Windows.Controls.Button restoreButton)restoreButton.IsEnabled=true;}
    }
    private async void NuGetAdvisoryClick(object sender,RoutedEventArgs e)
    {
        var select=new OpenFileDialog
        {
            Title="Select a NuGet packages.lock.json that you authorize OTS to inspect",
            Filter="NuGet lockfiles (packages.lock.json)|packages.lock.json",
            Multiselect=false
        };
        if(select.ShowDialog()!=true)return;
        const string notice="This check reads the selected NuGet packages.lock.json and sends package names and exact resolved versions to the public OSV.dev vulnerability API. No source code, credentials or local file paths are transmitted. Published advisory results may be incomplete and cannot prove the software is safe. Continue?";
        if(MessageBox.Show(notice,"Optional NuGet vulnerability intelligence",MessageBoxButton.YesNo,MessageBoxImage.Information)!=MessageBoxResult.Yes)
            return;
        if(sender is Button action)action.IsEnabled=false;
        try
        {
            NuGetAdvisoryResult.Text="Checking exact NuGet package versions against published OSV advisories…";
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(25));
            nugetAuditResult=await PackageVulnerabilityAudit.QueryAsync(http,select.FileName,timeout.Token);
            NuGetAdvisoryResult.Text=nugetAuditResult.Evidence+" "+nugetAuditResult.Limitation;
            await Refresh();
        }
        catch(Exception ex)
        {
            nugetAuditResult=null;
            NuGetAdvisoryResult.Text="NuGet advisory lookup failed: "+ex.GetType().Name+
                ". Software vulnerability status remains unknown; no scan has been certified.";
        }
        finally{if(sender is Button restoreAction)restoreAction.IsEnabled=true;}
    }
    private async void SecretsClick(object sender,RoutedEventArgs e)
    {
        var dialog=new OpenFolderDialog{Title="Select the folder you authorize OTS to scan",Multiselect=false};if(dialog.ShowDialog()!=true)return;
        try
        {
            StatusLine.Text="Scanning selected folder within file and size limits…";
            var report=await Task.Run(()=>ScanSecrets(dialog.FolderName));var save=new SaveFileDialog{Filter="Text report|*.txt",FileName="OTS-Secrets-Hygiene.txt"};if(save.ShowDialog()==true)File.WriteAllText(save.FileName,report);StatusLine.Text="Secrets scan finished. Results contain locations and indicator types, never secret values.";
        }
        catch(Exception ex){MessageBox.Show(ex.Message);}
    }
    private static string ScanSecrets(string root)
    {
        // Explicitly selected root only. No follow of NTFS junctions, symbolic links,
        // or other reparse points; no secret values are emitted or persisted.
        var full=Path.GetFullPath(root);
        if(!Directory.Exists(full))throw new DirectoryNotFoundException(full);
        var exclusions=new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {".git",".svn","node_modules","bin","obj",".venv","vendor","dist","build"};
        List<string> result=["OTS Firewall79X — local heuristic secrets scan",
            "Results contain possible indicator types and local paths only, never matched values.",
            "Excluded tree names: "+string.Join(", ",exclusions.Order())];
        var dirs=new Stack<string>();dirs.Push(full);
        int files=0,skipped=0,findings=0,excluded=0,errors=0;long bytes=0;
        var watch=Stopwatch.StartNew();
        while(dirs.Count>0&&files<5000&&bytes<64L*1024*1024&&watch.Elapsed<TimeSpan.FromMinutes(2))
        {
            var dir=dirs.Pop();
            try
            {
                if(File.GetAttributes(dir).HasFlag(FileAttributes.ReparsePoint)){skipped++;continue;}
                foreach(var child in Directory.EnumerateDirectories(dir).Take(5000))
                {
                    if(exclusions.Contains(Path.GetFileName(child))){excluded++;continue;}
                    if(dirs.Count<5000)dirs.Push(child);else skipped++;
                }
                foreach(var path in Directory.EnumerateFiles(dir))
                {
                    if(files>=5000||bytes>=64L*1024*1024||watch.Elapsed>=TimeSpan.FromMinutes(2))break;
                    files++;
                    try
                    {
                        var f=new FileInfo(path);
                        if(!f.Exists||f.Length>256*1024||f.Attributes.HasFlag(FileAttributes.ReparsePoint)){skipped++;continue;}
                        // Avoid following a changed file through a symlink after enumeration.
                        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,8192,FileOptions.SequentialScan);
                        if(stream.Length>256*1024){skipped++;continue;}
                        using var reader=new StreamReader(stream,System.Text.Encoding.UTF8,true);
                        var text=reader.ReadToEnd();
                        bytes+=stream.Length;
                        foreach(var kind in Detections.SecretKinds(text))
                        {
                            findings++;
                            result.Add($"{kind}: {path}");
                            if(findings>=2500)break;
                        }
                        if(findings>=2500)break;
                    }
                    catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException){errors++;}
                }
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){errors++;}
            if(findings>=2500)break;
        }
        result.Add($"Examined entries: {files}; bytes read: {bytes}; possible indicators: {findings}; skipped: {skipped}; excluded directories: {excluded}; inaccessible/errors: {errors}; queued directories: {dirs.Count}.");
        result.Add("Caps: 5,000 files, 256 KiB/file, 64 MiB total, 2 minutes, 2,500 indicators. Exclusions, changing files, binary and oversize content can cause misses. No external uploads or automatic remediation. Review privately before sharing report.");
        return string.Join(Environment.NewLine,result);
    }
    private async void BreachClick(object sender,RoutedEventArgs e)
    {
        var password=BreachPassword.Password;BreachPassword.Clear();
        if(password.Length==0)return;
        byte[]? secret=null;
        string prefix,suffix;
        try
        {
            secret=Encoding.UTF8.GetBytes(password);
            password=string.Empty;
            (prefix,suffix)=PasswordBreachRange.ComputeRange(secret);
        }
        catch(ArgumentOutOfRangeException)
        {
            BreachResult.Text="Password input must be between 1 and 4,096 UTF-8 bytes.";return;
        }
        finally
        {
            if(secret!=null)CryptographicOperations.ZeroMemory(secret);
            password=string.Empty;
        }
        try
        {
            BreachResult.Text="Checking the password prefix against the breach service…";
            using var req=new HttpRequestMessage(HttpMethod.Get,
                "https://api.pwnedpasswords.com/range/"+prefix);
            req.Headers.Add("Add-Padding","true");
            req.Headers.CacheControl=new System.Net.Http.Headers.CacheControlHeaderValue{NoStore=true,NoCache=true};
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var response=await http.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            response.EnsureSuccessStatusCode();
            if(response.Content.Headers.ContentLength>1024*1024)
                throw new InvalidDataException("Breach API response exceeds maximum length");
            await response.Content.LoadIntoBufferAsync(1024*1024,timeout.Token);
            var body=await response.Content.ReadAsStringAsync(timeout.Token);
            var count=PasswordBreachRange.ParseCount(suffix,body);
            BreachResult.Text=count>0
                ?$"This password appears {count:N0} times in the breach corpus. Change it wherever used."
                :"No match returned by this service. This does not prove the password is strong or has never been exposed.";
        }
        catch(Exception ex)when(ex is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
        {
            BreachResult.Text="Breach check could not be verified. No risk conclusion is available; try again when the service is reachable.";
        }
    }
    private void ArchiveClick(object sender,RoutedEventArgs e)
    {
        var report=Report();if(report==null)return;var save=new SaveFileDialog{Filter="Encrypted OTS archive|*.otsbackup",FileName=$"OTS-Report-{DateTime.Now:yyyyMMdd-HHmmss}.otsbackup"};if(save.ShowDialog()!=true)return;
        try{SecureArchive.Encrypt(save.FileName,Encoding.UTF8.GetBytes(report),ArchivePassword.Password);var verified=SecureArchive.Decrypt(save.FileName,ArchivePassword.Password);if(!verified.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(report)))throw new CryptographicException("Archive verification failed");StatusLine.Text="Encrypted archive written and restore verification passed.";}catch(Exception ex){MessageBox.Show(ex.Message);}finally{ArchivePassword.Clear();}
    }
    private void RestoreArchiveClick(object sender,RoutedEventArgs e)
    {
        var open=new OpenFileDialog{Filter="Encrypted OTS archive|*.otsbackup"};if(open.ShowDialog()!=true)return;
        byte[]? plain=null;
        try{plain=SecureArchive.Decrypt(open.FileName,ArchivePassword.Password);var save=new SaveFileDialog{Filter="Restored report|*.md",FileName="OTS-Restored-Report.md"};if(save.ShowDialog()==true){File.WriteAllBytes(save.FileName,plain);StatusLine.Text="Archive authenticated and restored to your chosen file.";}}catch(Exception ex){MessageBox.Show("Archive restore failed: "+ex.Message);}finally{if(plain!=null)CryptographicOperations.ZeroMemory(plain);ArchivePassword.Clear();}
    }
    private async void FolderBackupClick(object sender,RoutedEventArgs e)
    {
        var folder=new OpenFolderDialog{Title="Select the folder to encrypt (60 MiB maximum)"};if(folder.ShowDialog()!=true)return;
        var save=new SaveFileDialog{Filter="Encrypted folder backup|*.otsfolder",FileName=$"OTS-Folder-{DateTime.Now:yyyyMMdd-HHmmss}.otsfolder",OverwritePrompt=true};if(save.ShowDialog()!=true)return;
        var password=ArchivePassword.Password;ArchivePassword.Clear();
        try{StatusLine.Text="Encrypting selected files and verifying every file hash…";var summary=await Task.Run(()=>FolderBackup.Create(folder.FolderName,save.FileName,password));StatusLine.Text=$"Verified backup saved: {summary.Files} files, {summary.Bytes:N0} bytes. Keep the passphrase safe.";}
        catch(Exception ex){MessageBox.Show(ex.Message,"Backup failed",MessageBoxButton.OK,MessageBoxImage.Warning);}
    }
    private async void FolderRestoreClick(object sender,RoutedEventArgs e)
    {
        var open=new OpenFileDialog{Filter="Encrypted folder backup|*.otsfolder"};if(open.ShowDialog()!=true)return;
        var folder=new OpenFolderDialog{Title="Choose a parent folder; restored files go into a new subfolder"};if(folder.ShowDialog()!=true)return;
        var target=Path.Combine(folder.FolderName,$"OTS-Restored-{DateTime.Now:yyyyMMdd-HHmmss}");var password=ArchivePassword.Password;ArchivePassword.Clear();
        try{var summary=await Task.Run(()=>FolderBackup.Restore(open.FileName,target,password));StatusLine.Text=$"Restored and verified {summary.Files} files in {target}";}
        catch(Exception ex){MessageBox.Show(ex.Message,"Restore failed",MessageBoxButton.OK,MessageBoxImage.Warning);}
    }

}
