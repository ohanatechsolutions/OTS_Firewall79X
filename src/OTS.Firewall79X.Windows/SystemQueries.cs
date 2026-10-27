using System.Management;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
namespace OTS.Firewall79X.Windows;

public static class SystemQueries
{
    public static List<Dictionary<string,string>> Wmi(string scope,string query,params string[] fields)
    {
        using var search=new ManagementObjectSearcher(new ManagementScope(scope),new ObjectQuery(query),new System.Management.EnumerationOptions{Timeout=TimeSpan.FromSeconds(8),ReturnImmediately=false});
        using var rows=search.Get();List<Dictionary<string,string>> result=[];
        foreach(ManagementObject row in rows)
        {
            using(row){var item=new Dictionary<string,string>();foreach(var field in fields){var v=row[field];item[field]=v is Array a?string.Join(",",a.Cast<object>()):v?.ToString()??"";}result.Add(item);}
            if(result.Count>10000)throw new InvalidDataException("WMI row budget exceeded");
        }
        return result;
    }
    public static object? Reg(string path,string value)
    { using var key=Registry.LocalMachine.OpenSubKey(path);return key?.GetValue(value); }
    public static string Fingerprint(object data)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(data)));
    public static string FileHash(string path)
    {
        var f=new FileInfo(path);if(f.Length>64*1024*1024)throw new IOException("Integrity file exceeds budget");
        using var s=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);return Convert.ToHexString(SHA256.HashData(s));
    }
    public static List<string> RootCertificates()
    {using var store=new X509Store(StoreName.Root,StoreLocation.LocalMachine);store.Open(OpenFlags.ReadOnly);return store.Certificates.Select(c=>c.Thumbprint).Order().ToList();}
    public static List<string> Startup()
    {
        List<string> result=[];
        foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"})
        {using var key=Registry.LocalMachine.OpenSubKey(path);if(key!=null)result.AddRange(key.GetValueNames().Select(n=>$"{path}:{n}:{key.GetValue(n)}"));}
        return result.Order().ToList();
    }
    public static List<string> InstalledSoftware()
    {
        List<string> result=[];
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {using var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);using var root=hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");if(root==null)continue;foreach(var name in root.GetSubKeyNames()){using var app=root.OpenSubKey(name);if(app?.GetValue("DisplayName") is string display)result.Add($"{display} {app.GetValue("DisplayVersion")}");}}
        return result.Order().ToList();
    }
}
