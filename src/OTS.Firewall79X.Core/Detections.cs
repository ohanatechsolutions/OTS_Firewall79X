using System.Net;
namespace OTS.Firewall79X.Core;

public static class Detections
{
    public static bool IsPublicAddress(string text)
    {
        if(!IPAddress.TryParse(text,out var ip) || IPAddress.IsLoopback(ip))return false;
        if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
        var b=ip.GetAddressBytes();
        if(b.Length==16)return !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast && !ip.IsIPv6SiteLocal && !ip.Equals(IPAddress.IPv6Any) && (b[0]&0xfe)!=0xfc;
        return !(b[0] is 0 or 10 or 127 || b[0]>=224 || b[0]==169&&b[1]==254 || b[0]==172&&b[1]>=16&&b[1]<=31 || b[0]==192&&(b[1]==168 || b[1]==0) || b[0]==100&&b[1]>=64&&b[1]<=127 || b[0]==198&&b[1] is 18 or 19);
    }
    public static bool IsBeacon(IReadOnlyList<DateTimeOffset> times)
    {
        if(times.Count<8)return false;
        var gaps=times.Zip(times.Skip(1),(a,b)=>(b-a).TotalSeconds).ToArray();
        var mean=gaps.Average();
        return mean>=10 && mean<=3600 && Math.Sqrt(gaps.Average(g=>Math.Pow(g-mean,2)))/mean<0.08;
    }
    public static bool Scan(IEnumerable<int> ports)=>ports.Distinct().Count()>=12;
    public static bool FileBurst(IEnumerable<DateTimeOffset> times,DateTimeOffset now)=>times.Count(t=>t<=now && t>=now.AddSeconds(-10))>=40;
    public static string? ExecutionIndicator(string? process,string? command)
    {
        var name=Path.GetFileName(process??"").ToLowerInvariant(); var c=(command??"").ToLowerInvariant();
        if(name is "powershell.exe" or "pwsh.exe" && (c.Contains("-encodedcommand")||c.Contains("downloadstring(")||c.Contains("frombase64string(")))return "Encoded or download-capable PowerShell execution; review context";
        if(name is "mshta.exe" or "regsvr32.exe" && (c.Contains("http://")||c.Contains("https://")))return "Script-capable Windows binary referencing a remote URL";
        if(name.EndsWith(".pdf.exe")||name.EndsWith(".jpg.exe"))return "Executable with misleading double extension";
        return null;
    }
    public static string? SecretKind(string text)
    {
        if(text.Contains("-----BEGIN PRIVATE KEY-----")||text.Contains("-----BEGIN RSA PRIVATE KEY-----"))return "Private key";
        if(System.Text.RegularExpressions.Regex.IsMatch(text,@"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b",System.Text.RegularExpressions.RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100)))return "Possible access token";
        return null;
    }
}
