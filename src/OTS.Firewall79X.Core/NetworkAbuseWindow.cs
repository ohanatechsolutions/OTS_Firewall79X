using System.Net;
using System.Net.Sockets;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Conservative detector for *inbound* Windows Security 5157 events. These events mean
/// Windows has ALREADY blocked the connection; they do not provide raw packet inspection.
/// Decisions only authorize a bounded additional source restriction, never a ban on a
/// private, local, special-purpose, mapped, or configured trusted address.
/// </summary>
public sealed class NetworkAbuseWindow
{
    public sealed record Finding(bool Eligible, bool Scan, bool Flood, bool Restrict, string Address);
    private readonly object gate = new();
    private readonly Dictionary<string,Queue<(DateTimeOffset At,int Port)>> history = new(StringComparer.Ordinal);
    private readonly Dictionary<string,DateTimeOffset> cooldown = new(StringComparer.Ordinal);

    // Called under gate. Retire stale source histories before rejecting a new
    // source at capacity; otherwise a flood of unique old senders could keep
    // the fixed-size monitor permanently blind to future public sources.
    private void PruneStale(DateTimeOffset now, int limit)
    {
        foreach (var stale in history.Where(x => x.Value.Count == 0 ||
                     x.Value.Last().At < now.AddMinutes(-2))
                 .Select(x => x.Key).Take(limit).ToArray())
        {
            history.Remove(stale);
            cooldown.Remove(stale);
        }
    }

    public static bool EligiblePublicSource(string? value, IEnumerable<string>? trusted = null)
    {
        if(string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value,out var ip) ||
           ip.IsIPv4MappedToIPv6 || !Detections.IsPublicAddress(value))return false;
        var b=ip.GetAddressBytes();
        if(ip.AddressFamily==AddressFamily.InterNetwork)
        {
            // Documentation, special-purpose and benchmarking networks are not Internet attackers.
            if(b[0]==192&&b[1]==0&&b[2]==2 ||
               b[0]==198&&b[1]==51&&b[2]==100 ||
               b[0]==203&&b[1]==0&&b[2]==113 ||
               b[0]==192&&b[1]==88&&b[2]==99 ||
               b[0]==192&&b[1]==0&&b[2]==0 ||
               b[0]==198&&b[1] is 18 or 19 ||
               b[0]==255)return false;
        }
        else if(b.Length==16)
        {
            // Documentation IPv6 block 2001:db8::/32 and IPv6 unspecified/reserved.
            if(b[0]==0x20&&b[1]==0x01&&b[2]==0x0d&&b[3]==0xb8 ||
               b[0]==0 || ip.IsIPv6Multicast)return false;
        }
        if(trusted!=null)
        {
            foreach(var name in trusted)
                if(IPAddress.TryParse(name,out var allowed) && allowed.Equals(ip))return false;
        }
        return true;
    }

    public Finding Observe(string? source,string? direction,int destinationPort,DateTimeOffset now,IEnumerable<string>? trusted=null)
    {
        if(direction!="%%14592" || destinationPort is <1 or >65535 ||
           !EligiblePublicSource(source,trusted))
            return new(false,false,false,false,"");
        var address=IPAddress.Parse(source!).ToString();
        lock(gate)
        {
            if(history.Count>=1024 && !history.ContainsKey(address))
            {
                PruneStale(now, 1024);
                // Still full of active sources: bounded refusal, never a ban.
                if(history.Count>=1024)return new(false,false,false,false,"");
            }
            if(!history.TryGetValue(address,out var window))history[address]=window=new();
            while(window.Count>0 && (window.Peek().At<now.AddSeconds(-60)||window.Count>=256))
                window.Dequeue();
            window.Enqueue((now,destinationPort));
            int different=window.Select(x=>x.Port).Distinct().Count();
            bool scan=different>=12;
            bool flood=window.Count>=100 && different>=4;
            // Escalation intentionally requires more than an ordinary scan warning.
            bool candidate=different>=20 && window.Count>=20 || window.Count>=150 && different>=4;
            bool restricted=candidate && (!cooldown.TryGetValue(address,out var until)||now>=until);
            if(restricted)cooldown[address]=now.AddMinutes(20);
            if(history.Count>900)PruneStale(now,100);
            return new(true,scan,flood,restricted,address);
        }
    }
}
