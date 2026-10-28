using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

/// <summary>Read-only bounded Windows host inventory. User hives are never mounted.</summary>
public static class EndpointInventory
{
    private static IEnumerable<string> Profiles() =>
        Registry.Users.GetSubKeyNames().Take(256).Where(s=>s.StartsWith("S-1-5-21-",StringComparison.OrdinalIgnoreCase)&&
            !s.EndsWith("_Classes",StringComparison.OrdinalIgnoreCase));
    public static List<string> UserStartup()
    {
        List<string> values=[];
        foreach(var sid in Profiles())
        foreach(var path in new[]{@"Software\Microsoft\Windows\CurrentVersion\Run",
                                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"})
        {
            try
            {
                using var k=Registry.Users.OpenSubKey(sid+@"\"+path);
                if(k==null)continue;
                foreach(var name in k.GetValueNames().Take(512))
                    values.Add(sid+":"+path+":"+name+":"+Convert.ToString(k.GetValue(name),CultureInfo.InvariantCulture));
            }
            catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
        }
        return values.Order(StringComparer.OrdinalIgnoreCase).Take(4096).ToList();
    }
    public static List<string> UserProxy()
    {
        List<string> values=[];
        foreach(var sid in Profiles())
        {
            try
            {
                using var k=Registry.Users.OpenSubKey(sid+@"\Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if(k==null)continue;
                foreach(var name in new[]{"ProxyEnable","ProxyServer","AutoConfigURL","ProxyOverride"})
                    values.Add(sid+":"+name+":"+Convert.ToString(k.GetValue(name),CultureInfo.InvariantCulture));
            }
            catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
        }
        return values.Order(StringComparer.OrdinalIgnoreCase).ToList();
    }
    public static List<string> ScheduledTasks()
    {
        var folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","Tasks");
        if(!Directory.Exists(folder))throw new DirectoryNotFoundException("Task definitions inaccessible");
        List<string> result=[];
        foreach(var file in Directory.EnumerateFiles(folder,"*",SearchOption.AllDirectories).Take(5001))
        {
            if(result.Count>=5000)throw new InvalidDataException("Task inventory over budget");
            try
            {
                var f=new FileInfo(file);if(f.Attributes.HasFlag(FileAttributes.ReparsePoint))continue;
                result.Add(Path.GetRelativePath(folder,file)+":"+f.Length+":"+f.LastWriteTimeUtc.Ticks);
            }
            catch(IOException){}catch(UnauthorizedAccessException){}
        }
        return result.Order(StringComparer.OrdinalIgnoreCase).ToList();
    }
    public static List<string> BrowserExtensions()
    {
        List<string> result=[];
        foreach(var sid in Profiles())
        {
            try
            {
                using var profile=Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\"+sid);
                string? folder=profile?.GetValue("ProfileImagePath") as string;
                if(string.IsNullOrWhiteSpace(folder))continue;
                folder=Environment.ExpandEnvironmentVariables(folder);
                foreach(var name in new[]{@"Google\Chrome",@"Microsoft\Edge",
                    @"BraveSoftware\Brave-Browser",@"Vivaldi"})
                {
                    var userData=Path.Combine(folder,"AppData","Local",name,"User Data");
                    if(!Directory.Exists(userData))continue;
                    foreach(var browserProfile in Directory.EnumerateDirectories(userData).Take(64))
                    {
                        var profileName=Path.GetFileName(browserProfile);
                        if(profileName!="Default"&&!profileName.StartsWith("Profile ",StringComparison.OrdinalIgnoreCase))continue;
                        var extensions=Path.Combine(browserProfile,"Extensions");
                        if(!Directory.Exists(extensions))continue;
                        foreach(var ext in Directory.EnumerateDirectories(extensions).Take(512))
                        {
                            var versions=Directory.EnumerateDirectories(ext).Select(Path.GetFileName).Order().Take(20);
                            result.Add(sid+":"+name+":"+profileName+":"+Path.GetFileName(ext)+":"+
                                string.Join(",",versions));
                        }
                    }
                }
                var firefox=Path.Combine(folder,"AppData","Roaming","Mozilla","Firefox","Profiles");
                if(Directory.Exists(firefox))
                    foreach(var fp in Directory.EnumerateDirectories(firefox).Take(64))
                    {
                        var addons=Path.Combine(fp,"extensions");if(!Directory.Exists(addons))continue;
                        foreach(var file in Directory.EnumerateFileSystemEntries(addons).Take(512))
                            result.Add(sid+":firefox:"+Path.GetFileName(fp)+":"+Path.GetFileName(file));
                    }
            }
            catch(IOException){}catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
        }
        return result.Order(StringComparer.OrdinalIgnoreCase).Take(4096).ToList();
    }
    public static List<string> SoftwareSources()
    {
        List<string> values=[];
        foreach(var path in new[]{@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                                  @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                                  @"SOFTWARE\Policies\Microsoft\Windows\AppInstaller"})
        {
            using var key=Registry.LocalMachine.OpenSubKey(path);if(key==null)continue;
            foreach(var name in key.GetValueNames().Take(128))
            {
                var v=key.GetValue(name);
                var text=v is byte[] data?"binary:"+data.Length:Convert.ToString(v,CultureInfo.InvariantCulture)??"";
                values.Add(path+":"+name+":"+text[..Math.Min(text.Length,256)]);
            }
        }
        return values.Order(StringComparer.OrdinalIgnoreCase).ToList();
    }
    public static (int Distros,DockerDaemonAudit.Result Daemon) Container()
    {
        int count=0;
        foreach(var sid in Profiles())
        {
            try
            {
                using var k=Registry.Users.OpenSubKey(sid+@"\Software\Microsoft\Windows\CurrentVersion\Lxss");
                count+=k?.GetSubKeyNames().Length??0;
            }
            catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
        }
        var file=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "docker","config","daemon.json");
        if(!File.Exists(file)||new FileInfo(file).Length>65536)
            return (count,DockerDaemonAudit.Parse(null));
        return (count,DockerDaemonAudit.Parse(File.ReadAllText(file)));
    }
    public static (int Keys,List<string> Values) UserMediaConsent()
    {
        int roots=0;List<string> values=[];
        foreach(var sid in Profiles())
        foreach(var capability in new[]{"webcam","microphone"})
        {
            try
            {
                var path=sid+@"\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\"+capability;
                using var root=Registry.Users.OpenSubKey(path);
                if(root==null)continue;
                roots++;
                foreach(var name in root.GetSubKeyNames().Take(256))
                {
                    using var app=root.OpenSubKey(name);
                    if(app==null)continue;
                    values.Add(sid+":"+capability+":"+name+":start="+app.GetValue("LastUsedTimeStart")+
                        ":stop="+app.GetValue("LastUsedTimeStop"));
                    if(name.Equals("NonPackaged",StringComparison.OrdinalIgnoreCase))
                        foreach(var child in app.GetSubKeyNames().Take(256))
                        {
                            using var sub=app.OpenSubKey(child);
                            if(sub!=null)values.Add(sid+":"+capability+":"+child+":start="+sub.GetValue("LastUsedTimeStart")+
                                ":stop="+sub.GetValue("LastUsedTimeStop"));
                        }
                }
            }
            catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
        }
        return (roots,values.Take(4096).Order(StringComparer.OrdinalIgnoreCase).ToList());
    }
    public static BootPolicyAudit.Result BootOptions()
    {
        var exe=Path.Combine(Environment.SystemDirectory,"bcdedit.exe");
        if(!File.Exists(exe))return BootPolicyAudit.Parse(null);
        using var p=new Process();
        p.StartInfo=new ProcessStartInfo(exe){UseShellExecute=false,CreateNoWindow=true,
            RedirectStandardOutput=true,RedirectStandardError=true};
        p.StartInfo.ArgumentList.Add("/enum");
        p.StartInfo.ArgumentList.Add("{current}");
        if(!p.Start())return BootPolicyAudit.Parse(null);
        var output=p.StandardOutput.ReadToEndAsync();
        if(!p.WaitForExit(5000))
        {
            try{p.Kill(true);}catch(InvalidOperationException){}
            return BootPolicyAudit.Parse(null);
        }
        return p.ExitCode==0?BootPolicyAudit.Parse(output.GetAwaiter().GetResult()):BootPolicyAudit.Parse(null);
    }
}
