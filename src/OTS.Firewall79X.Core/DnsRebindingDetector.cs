using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace OTS.Firewall79X.Core;

/// <summary>Privacy-bounded, observation-only check for a public DNS answer followed
/// by a private/local answer for the same external name. Never rewrites DNS or hosts.</summary>
public sealed class DnsRebindingDetector
{
    public sealed record Finding(bool ParsedAddressAnswer, bool SuspiciousTransition, int AddressCount);
    private readonly Dictionary<string,DateTimeOffset> recentlyPublic=new(StringComparer.Ordinal);
    private readonly Dictionary<string,DateTimeOffset> recentAlerts=new(StringComparer.Ordinal);

    public static bool IsLocal(IPAddress ip)
    {
        if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
        // Treat special-use / non-globally-routable results (CGNAT, IPv6
        // documentation ranges and unspecified addresses included) as internal
        // targets for *observation*, never as automatic firewall deny targets.
        return !NetworkAbuseWindow.EligiblePublicSource(ip.ToString());
    }
    private static bool IsExternalName(string name)
    {
        if(name.Length<4||name.Length>253||!name.Contains('.')||name.Any(char.IsWhiteSpace))return false;
        if(name.StartsWith('.')||name.Contains(".."))return false;
        var labels=name.Split('.');
        if(labels.Length<2 || labels.Any(label=>label.Length is <1 or >63 ||
            !char.IsAsciiLetterOrDigit(label[0]) || !char.IsAsciiLetterOrDigit(label[^1]) ||
            label.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-')))return false;
        return !new[]{".local",".lan",".internal",".home.arpa",".localhost",".test",".invalid",".onion"}.Any(s=>name.EndsWith(s,StringComparison.OrdinalIgnoreCase));
    }
    public Finding Observe(string? rawName,string? rawAnswers,string? status,DateTimeOffset now)
    {
        if(string.IsNullOrWhiteSpace(rawName)||string.IsNullOrWhiteSpace(rawAnswers)||
           rawAnswers.Length>4096 || status is not ("0" or "0x0"))
            return new(false,false,0);
        var name=rawName.Trim().TrimEnd('.').ToLowerInvariant();
        if(!IsExternalName(name))return new(false,false,0);
        var tokens=rawAnswers.Split(';',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries);
        if(tokens.Length>64)return new(false,false,0); // Never silently ignore excess answer records.
        var addresses=new List<IPAddress>();
        foreach(var token in tokens)
        {
            if(!IPAddress.TryParse(token,out var ip))continue; // DNS CNAME targets are not IPs.
            if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
            if(ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                addresses.Add(ip);
        }
        if(addresses.Count==0)return new(false,false,0);
        bool local=addresses.Any(IsLocal);
        bool external=addresses.Any(ip=>NetworkAbuseWindow.EligiblePublicSource(ip.ToString()));
        var key=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name)));
        if(recentlyPublic.Count>2048){recentlyPublic.Clear();recentAlerts.Clear();}
        // An answer combining a public IP with a private IP can itself be a
        // rebinding vector; do not suppress it just because a public IP remains.
        bool transition=local&&recentlyPublic.TryGetValue(key,out var last) &&
            now>=last && now-last<TimeSpan.FromMinutes(10) &&
            (!recentAlerts.TryGetValue(key,out var alert)||now-alert>TimeSpan.FromMinutes(5));
        if(transition)recentAlerts[key]=now;
        if(external&&!local)recentlyPublic[key]=now;
        return new(true,transition,addresses.Count);
    }
}
