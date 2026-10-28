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
        if(name is "wscript.exe" or "cscript.exe" && (c.Contains("https://")||c.Contains("http://")))return "Script host referencing a remote URL";
        if(name=="rundll32.exe"&&c.Contains("javascript:"))return "Script handler invoked via rundll32";
        if(name.EndsWith(".pdf.exe")||name.EndsWith(".jpg.exe"))return "Executable with misleading double extension";
        return null;
    }
    public static string? ExecutionIndicator(string? process,string? command,string? parent)
    {
        var direct=ExecutionIndicator(process,command);
        if(direct!=null)return direct;
        var child=Path.GetFileName(process??"").ToLowerInvariant();
        var source=Path.GetFileName(parent??"").ToLowerInvariant();
        if(source is "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" &&
           child is "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe")
            return "Office application spawned script-capable child; verify authorization";
        return null;
    }
    /// <summary>Detects manifest capabilities requiring human review. Does not
    /// classify an extension as malware or attest its publisher signature.</summary>
    public static bool BrowserManifestHasHighImpactPermissions(System.Text.Json.JsonElement manifest)
    {
        if(manifest.ValueKind!=System.Text.Json.JsonValueKind.Object)return false;
        foreach(var property in new[]{"permissions","host_permissions","optional_permissions","optional_host_permissions"})
        {
            if(!manifest.TryGetProperty(property,out var entries)||
               entries.ValueKind!=System.Text.Json.JsonValueKind.Array)continue;
            foreach(var entry in entries.EnumerateArray())
            {
                if(entry.ValueKind!=System.Text.Json.JsonValueKind.String)continue;
                var value=entry.GetString()??"";
                if(value is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" ||
                   new[]{"debugger","management","nativeMessaging","proxy","webRequestBlocking"}
                       .Contains(value,StringComparer.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }
    /// <summary>Strict, bounded indicators only. Returns categories, never source tokens.
    /// A match is not proof of an active or exploitable credential.</summary>
    public static IReadOnlyList<string> SecretKinds(string text)
    {
        if(text.Length>1024*1024)throw new ArgumentOutOfRangeException(nameof(text),"File exceeds scanner budget");
        if(text.IndexOf('\0')>=0)return [];
        var types=new List<string>();
        if(text.Contains("-----BEGIN PRIVATE KEY-----",StringComparison.Ordinal)||
           text.Contains("-----BEGIN RSA PRIVATE KEY-----",StringComparison.Ordinal)||
           text.Contains("-----BEGIN EC PRIVATE KEY-----",StringComparison.Ordinal)||
           text.Contains("-----BEGIN OPENSSH PRIVATE KEY-----",StringComparison.Ordinal)||
           text.Contains("-----BEGIN PGP PRIVATE KEY BLOCK-----",StringComparison.Ordinal))
            types.Add("Private key");
        static bool Has(string source,string pattern)
        {
            try{return System.Text.RegularExpressions.Regex.IsMatch(source,pattern,
                System.Text.RegularExpressions.RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(150));}
            catch(System.Text.RegularExpressions.RegexMatchTimeoutException){return false;}
        }
        if(Has(text,@"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b"))
            types.Add("Possible GitHub access token");
        if(Has(text,@"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"))
            types.Add("Possible AWS access key identifier (not a secret by itself)");
        if(Has(text,@"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"))
            types.Add("Possible Slack token");
        if(Has(text,@"\bAIza[0-9A-Za-z_-]{35}\b"))
            types.Add("Possible Google API key");
        if(Has(text,@"\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}\b"))
            types.Add("Possible API key");
        if(Has(text,@"(?i)\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|password)\b\s*[:=]\s*[""']?(?!(?:redacted|example|changeme|placeholder|none|null|undefined|your[_-]?)\b)[A-Za-z0-9_+=/-]{24,}"))
            types.Add("Possible hard-coded credential assignment");
        return types;
    }
    public static string? SecretKind(string text)
    {
        // Compatibility for callers expecting one indicator.
        var categories=SecretKinds(text);
        return categories.FirstOrDefault(x=>x=="Private key")??categories.FirstOrDefault();
    }
}
