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
    private Dashboard? dashboard;private List<Row> rows=[];private bool refreshing;private UserMonitor? userMonitor;private readonly DispatcherTimer timer;private bool ready;
    private static readonly HttpClient http=new(){Timeout=TimeSpan.FromSeconds(20),MaxResponseContentBufferSize=5*1024*1024};
    public MainWindow()
    {
        InitializeComponent();SourceInitialized+=(_,_)=>NativeChrome.Apply(this);ready=true;timer=new(){Interval=TimeSpan.FromSeconds(5)};timer.Tick+=async(_,_)=>await Refresh();timer.Start();Loaded+=async(_,_)=>{notifications=new(this);await Refresh();};Closed+=(_,_)=>{timer.Stop();userMonitor?.Dispose();notifications?.Dispose();};
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
                var overlay=userMonitor.Results().ToDictionary(l=>l.Id);var layers=dashboard.Layers.Select(l=>overlay.GetValueOrDefault(l.Id,l)).ToList();var score=Posture.Calculate(layers,dashboard.Enabled);
                dashboard=dashboard with{Layers=layers,Score=score.Score,Confidence=score.Confidence,Events=dashboard.Events.Concat(userMonitor.Events()).OrderByDescending(e=>e.Time).Take(300).ToList()};
            }
            ProtectionText.Text=stale?"Protection status stale — service health requires attention":dashboard.Protection;
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
        List<string> result=["OTS Firewall79X — heuristic secrets scan. No secret values retained."];var dirs=new Stack<string>();dirs.Push(root);int files=0,skipped=0;long bytes=0;var watch=Stopwatch.StartNew();
        while(dirs.Count>0&&files<5000&&bytes<64*1024*1024&&watch.Elapsed<TimeSpan.FromMinutes(2))
        {
            var dir=dirs.Pop();try
            {
                if(File.GetAttributes(dir).HasFlag(FileAttributes.ReparsePoint)){skipped++;continue;}
                foreach(var child in Directory.EnumerateDirectories(dir).Take(5000))if(dirs.Count<5000)dirs.Push(child);
                foreach(var path in Directory.EnumerateFiles(dir))
                {
                    if(files>=5000||bytes>=64*1024*1024)break;files++;
                    try{var f=new FileInfo(path);if(f.Length>256*1024||f.Attributes.HasFlag(FileAttributes.ReparsePoint)){skipped++;continue;}bytes+=f.Length;var text=File.ReadAllText(path);var kind=Detections.SecretKind(text);if(kind!=null)result.Add($"{kind}: {path}");}
                    catch(IOException){skipped++;}catch(UnauthorizedAccessException){skipped++;}
                }
            }
            catch(IOException){skipped++;}catch(UnauthorizedAccessException){skipped++;}
        }
        result.Add($"Examined entries: {files}; bytes read: {bytes}; skipped/errors: {skipped}; remaining queued directories: {dirs.Count}. Budget: 5,000 files, 256 KiB/file, 64 MiB total, two minutes. Large directories may be truncated.");return string.Join(Environment.NewLine,result);
    }
    private async void BreachClick(object sender,RoutedEventArgs e)
    {
        var password=BreachPassword.Password;BreachPassword.Clear();if(password.Length==0)return;
        try
        {
            string hash=Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));password="";
            using var req=new HttpRequestMessage(HttpMethod.Get,"https://api.pwnedpasswords.com/range/"+hash[..5]);req.Headers.Add("Add-Padding","true");
            using var response=await http.SendAsync(req);response.EnsureSuccessStatusCode();var body=await response.Content.ReadAsStringAsync();long count=0;
            foreach(var line in body.Split('\n')){var pair=line.Trim().Split(':');if(pair.Length==2&&pair[0].Equals(hash[5..],StringComparison.OrdinalIgnoreCase))long.TryParse(pair[1],out count);}
            BreachResult.Text=count>0?$"This password appears {count:N0} times in the breach corpus. Change it wherever used.":"No match returned. This does not prove the password is strong or has never been exposed.";
        }
        catch(Exception ex){BreachResult.Text="Check failed: "+ex.Message;}
    }
    private void ArchiveClick(object sender,RoutedEventArgs e)
    {
        var report=Report();if(report==null)return;var save=new SaveFileDialog{Filter="Encrypted OTS archive|*.otsbackup",FileName=$"OTS-Report-{DateTime.Now:yyyyMMdd-HHmmss}.otsbackup"};if(save.ShowDialog()!=true)return;
        try{SecureArchive.Encrypt(save.FileName,Encoding.UTF8.GetBytes(report),ArchivePassword.Password);var verified=SecureArchive.Decrypt(save.FileName,ArchivePassword.Password);if(!verified.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(report)))throw new CryptographicException("Archive verification failed");StatusLine.Text="Encrypted archive written and restore verification passed.";}catch(Exception ex){MessageBox.Show(ex.Message);}finally{ArchivePassword.Clear();}
    }
    private void RestoreArchiveClick(object sender,RoutedEventArgs e)
    {
        var open=new OpenFileDialog{Filter="Encrypted OTS archive|*.otsbackup"};if(open.ShowDialog()!=true)return;
        try{var plain=SecureArchive.Decrypt(open.FileName,ArchivePassword.Password);var save=new SaveFileDialog{Filter="Restored report|*.md",FileName="OTS-Restored-Report.md"};if(save.ShowDialog()==true)File.WriteAllBytes(save.FileName,plain);CryptographicOperations.ZeroMemory(plain);StatusLine.Text="Archive authenticated and restored to your chosen file.";}catch(Exception ex){MessageBox.Show("Archive restore failed: "+ex.Message);}finally{ArchivePassword.Clear();}
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
