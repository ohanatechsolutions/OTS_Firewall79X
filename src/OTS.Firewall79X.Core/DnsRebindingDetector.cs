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
        if(IPAddress.IsLoopback(ip))return true;
        var bytes=ip.GetAddressBytes();
        if(ip.AddressFamily==AddressFamily.InterNetwork)
            return bytes[0]==10||bytes[0]==127||
                bytes[0]==172&&bytes[1]>=16&&bytes[1]<=31||
                bytes[0]==192&&bytes[1]==168||
                bytes[0]==169&&bytes[1]==254;
        return ip.IsIPv6LinkLocal||ip.IsIPv6SiteLocal||(bytes[0]&0xfe)==0xfc;
    }
    private static bool IsExternalName(string name)
    {
        if(name.Length<4||name.Length>253||!name.Contains('.')||name.Any(char.IsWhiteSpace))return false;
        if(name.StartsWith('.')||name.Contains(".."))return false;
        return !new[]{".local",".lan",".internal",".home.arpa",".localhost",".test",".invalid",".onion"}.Any(s=>name.EndsWith(s,StringComparison.OrdinalIgnoreCase));
    }
    public Finding Observe(string? rawName,string? rawAnswers,string? status,DateTimeOffset now)
    {
        if(string.IsNullOrWhiteSpace(rawName)||string.IsNullOrWhiteSpace(rawAnswers)||
           rawAnswers.Length>4096 || status is not ("0" or "0x0"))
            return new(false,false,0);
        var name=rawName.Trim().TrimEnd('.').ToLowerInvariant();
        if(!IsExternalName(name))return new(false,false,0);
        var addresses=new List<IPAddress>();
        foreach(var token in rawAnswers.Split(';',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries).Take(64))
        {
            if(!IPAddress.TryParse(token,out var ip))continue; // DNS CNAME targets are not IPs.
            if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
            if(ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                addresses.Add(ip);
        }
        if(addresses.Count==0)return new(false,false,0);
        bool local=addresses.Any(IsLocal);
        bool external=addresses.Any(ip=>Detections.IsPublicAddress(ip.ToString()));
        var key=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name)));
        if(recentlyPublic.Count>2048){recentlyPublic.Clear();recentAlerts.Clear();}
        bool transition=local&&!external&&recentlyPublic.TryGetValue(key,out var last) &&
            now>=last && now-last<TimeSpan.FromMinutes(10) &&
            (!recentAlerts.TryGetValue(key,out var alert)||now-alert>TimeSpan.FromMinutes(5));
        if(transition)recentAlerts[key]=now;
        if(external&&!local)recentlyPublic[key]=now;
        return new(true,transition,addresses.Count);
    }
}
