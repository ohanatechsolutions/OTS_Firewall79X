using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace OTS.Firewall79X.Core;

/// <summary>Correlates real Windows Security 4663 file-read audit events. Access-mask
/// semantics are taken from the OS; no read events are synthesized from file watches.
/// Path names are used only transiently and kept as hashes for at most one minute.</summary>
public sealed class AuditedFileAccess
{
    public sealed record Finding(bool AuditedRead, bool BrowserCredentialRead, bool UnexpectedCredentialReader, bool BulkRead, int DistinctFiles);
    private readonly Dictionary<string, Dictionary<string,DateTimeOffset>> reads=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,DateTimeOffset> credentialAlerts=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,DateTimeOffset> bulkAlerts=new(StringComparer.OrdinalIgnoreCase);

    public static bool IsReadAccess(string? accessMask)
    {
        if(string.IsNullOrWhiteSpace(accessMask))return false;
        var mask=accessMask.Trim();
        bool hex=mask.StartsWith("0x",StringComparison.OrdinalIgnoreCase);
        if(hex)mask=mask[2..];
        if(!uint.TryParse(mask,hex?NumberStyles.HexNumber:NumberStyles.Integer,CultureInfo.InvariantCulture,out var value))return false;
        return (value & 1u)!=0;
    }
    public static bool IsBrowserCredentialPath(string path)
    {
        if(string.IsNullOrWhiteSpace(path)||path.Length>4096)return false;
        var p=path.Replace('/','\\');
        bool chromium=p.Contains(@"\User Data\",StringComparison.OrdinalIgnoreCase) &&
            (p.Contains(@"\Google\Chrome\",StringComparison.OrdinalIgnoreCase) ||
             p.Contains(@"\Microsoft\Edge\",StringComparison.OrdinalIgnoreCase) ||
             p.Contains(@"\BraveSoftware\Brave-Browser\",StringComparison.OrdinalIgnoreCase) ||
             p.Contains(@"\Vivaldi\",StringComparison.OrdinalIgnoreCase));
        if(chromium && (p.EndsWith(@"\Login Data",StringComparison.OrdinalIgnoreCase) ||
                         p.EndsWith(@"\Network\Cookies",StringComparison.OrdinalIgnoreCase) ||
                         p.EndsWith(@"\Cookies",StringComparison.OrdinalIgnoreCase) ||
                         p.EndsWith(@"\Local State",StringComparison.OrdinalIgnoreCase)))return true;
        return p.Contains(@"\Mozilla\Firefox\Profiles\",StringComparison.OrdinalIgnoreCase) &&
               (p.EndsWith(@"\logins.json",StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith(@"\key4.db",StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith(@"\cookies.sqlite",StringComparison.OrdinalIgnoreCase));
    }
    private static string FileName(string path)
    {
        var i=path.LastIndexOfAny(['\\','/']);
        return path[(i+1)..].ToLowerInvariant();
    }
    private static bool ExpectedReader(string process,string path)
    {
        var p=FileName(process);var s=path.Replace('/','\\');
        if(p is "msmpeng.exe" or "searchindexer.exe")return true;
        if(s.Contains(@"\Microsoft\Edge\",StringComparison.OrdinalIgnoreCase))return p=="msedge.exe";
        if(s.Contains(@"\BraveSoftware\Brave-Browser\",StringComparison.OrdinalIgnoreCase))return p=="brave.exe";
        if(s.Contains(@"\Vivaldi\",StringComparison.OrdinalIgnoreCase))return p=="vivaldi.exe";
        if(s.Contains(@"\Mozilla\Firefox\",StringComparison.OrdinalIgnoreCase))return p=="firefox.exe";
        return p=="chrome.exe";
    }
    public Finding Observe(string? objectType,string? objectName,string? processName,string? accessMask,DateTimeOffset now)
    {
        if(!string.Equals(objectType,"File",StringComparison.OrdinalIgnoreCase) ||
           !IsReadAccess(accessMask) || string.IsNullOrWhiteSpace(objectName) ||
           string.IsNullOrWhiteSpace(processName) || objectName.Length>4096 || processName.Length>2048)
            return new(false,false,false,false,0);

        var process=FileName(processName);
        var sensitive=IsBrowserCredentialPath(objectName);
        var unexpected=sensitive&&!ExpectedReader(processName,objectName)&&
            (!credentialAlerts.TryGetValue(process,out var last)||now-last>TimeSpan.FromMinutes(5));
        if(unexpected)credentialAlerts[process]=now;

        if(reads.Count>256){reads.Clear();bulkAlerts.Clear();credentialAlerts.Clear();}
        if(!reads.TryGetValue(process,out var paths))reads[process]=paths=new(StringComparer.Ordinal);
        foreach(var entry in paths.Where(p=>now-p.Value>TimeSpan.FromMinutes(1)).Select(p=>p.Key).ToArray())
            paths.Remove(entry);
        var hash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(objectName.ToUpperInvariant())));
        paths[hash]=now;
        if(paths.Count>512)paths.Clear(); // Bounded state; drop evidence instead of pretending continuity
        var bulk=paths.Count>=64&&(!bulkAlerts.TryGetValue(process,out var earlier) || now-earlier>TimeSpan.FromMinutes(5));
        if(bulk)bulkAlerts[process]=now;
        return new(true,sensitive,unexpected,bulk,paths.Count);
    }
}
