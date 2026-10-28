using System.Net;

namespace OTS.Firewall79X.Core;

/// <summary>Pure, bounded classification helpers. A signal is an investigative lead, never a malware verdict.</summary>
public static class TrafficRules
{
    public sealed record Endpoint(IPAddress Address, int Port);
    public static Endpoint? ParseEndpoint(string? value)
    {
        if(string.IsNullOrEmpty(value) || value.Length>100 || !value.StartsWith('['))return null;
        int end=value.LastIndexOf("]:",StringComparison.Ordinal);
        if(end<2 || !IPAddress.TryParse(value[1..end],out var ip) ||
            !int.TryParse(value[(end+2)..],out int port) || port is <0 or >65535)return null;
        return new(ip,port);
    }
    public static bool SmtpPort(int port)=>port is 25 or 465 or 587 or 2525;
    public static bool SuspiciousMailClient(string? process,int port)
    {
        if(!SmtpPort(port))return false;
        var p=Path.GetFileNameWithoutExtension(process??"").ToLowerInvariant();
        return p is not ("outlook" or "thunderbird" or "mailbird" or "emclient" or "thebat");
    }
    public static bool NonLoopbackBind(string? endpoint)
    {
        var parsed=ParseEndpoint(endpoint);
        return parsed!=null && !IPAddress.IsLoopback(parsed.Address);
    }
    public static bool IsMac(string? value)
    {
        if(string.IsNullOrWhiteSpace(value))return false;
        string canonical=new(value.Where(Uri.IsHexDigit).ToArray());
        return canonical.Length is 12 or 16 && canonical.Any(c=>c!='0');
    }
    public static bool ClockStep(DateTimeOffset earlierUtc,long earlierTick,
        DateTimeOffset laterUtc,long laterTick,TimeSpan threshold)
    {
        if(laterTick<earlierTick || threshold<TimeSpan.Zero)return false;
        var monotonic=TimeSpan.FromMilliseconds(laterTick-earlierTick);
        return (laterUtc-earlierUtc-monotonic).Duration()>threshold;
    }
    public static bool RemoteClockDrift(DateTimeOffset localUtc, DateTimeOffset remoteUtc,
        TimeSpan roundTrip,TimeSpan threshold)
    {
        if(roundTrip<TimeSpan.Zero||roundTrip>TimeSpan.FromSeconds(10))return false;
        return (localUtc-remoteUtc).Duration()>threshold+roundTrip;
    }
    public static string? MitreTechnique(string signal)=>signal switch
    {
        "repeated-logon-failures"=>"T1110 (possible Brute Force; authentication failures are not proof)",
        "script-powershell"=>"T1059.001 (possible PowerShell execution)",
        "remote-rdp-logon"=>"T1021.001 (Remote Desktop Protocol session observed)",
        _=>null
    };
}

/// <summary>Require repeated observations before warning on normal ARP/NDP cache churn.</summary>
public sealed class NeighborChangeTracker
{
    public sealed record Change(string Key,string OldMac,string NewMac,bool Gateway);
    private Dictionary<string,string> baseline=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,(string Mac,int Samples)> pending=new(StringComparer.OrdinalIgnoreCase);
    public bool HasBaseline {get;private set;}
    public IReadOnlyList<Change> Update(IReadOnlyDictionary<string,string> current,
        IReadOnlySet<string> gatewayAddresses)
    {
        List<Change> changes=[];
        if(!HasBaseline){baseline=current.ToDictionary(x=>x.Key,x=>x.Value,StringComparer.OrdinalIgnoreCase);HasBaseline=true;return changes;}
        foreach(var (key,mac) in current)
        {
            if(!baseline.TryGetValue(key,out var previous)){baseline[key]=mac;continue;}
            if(string.Equals(previous,mac,StringComparison.OrdinalIgnoreCase)){pending.Remove(key);continue;}
            var p=pending.GetValueOrDefault(key);
            int seen=string.Equals(p.Mac,mac,StringComparison.OrdinalIgnoreCase)?p.Samples+1:1;
            if(seen<2){pending[key]=(mac,seen);continue;}
            string ip=key.Contains(':')?key[(key.IndexOf(':')+1)..]:key;
            changes.Add(new(key,previous,mac,gatewayAddresses.Contains(ip)));
            baseline[key]=mac;pending.Remove(key);
        }
        foreach(var key in baseline.Keys.Where(k=>!current.ContainsKey(k)).ToArray())
        {baseline.Remove(key);pending.Remove(key);}
        if(baseline.Count>4096) {baseline=new(current.Take(4096).ToDictionary(x=>x.Key,x=>x.Value,StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase);pending.Clear();}
        return changes;
    }
}
