using System.Globalization;
using System.Net;
using System.Text.Json;
namespace OTS.Firewall79X.Core;

/// <summary>Read-only, conservative endpoint indicators. No result authorizes blocking.</summary>
public static class EndpointSignals
{
    public static int? AuditProcessId(string? raw)
    {
        if(string.IsNullOrWhiteSpace(raw))return null;
        var s=raw.Trim();bool hex=s.StartsWith("0x",StringComparison.OrdinalIgnoreCase);if(hex)s=s[2..];
        return uint.TryParse(s,hex?NumberStyles.HexNumber:NumberStyles.Integer,CultureInfo.InvariantCulture,out var id)
            && id>0 && id<=int.MaxValue?(int)id:null;
    }
    public static bool PublicTcpForProcess(int pid,IEnumerable<Connection> connections)
    {
        foreach(var c in connections)
        {
            if(c.Pid!=pid||c.State!="Established"||c.Remote.Length>160)continue;
            int end=c.Remote.LastIndexOf("]:",StringComparison.Ordinal);
            if(end<2||!c.Remote.StartsWith('['))continue;
            if(IPAddress.TryParse(c.Remote[1..end],out var ip)&&Detections.IsPublicAddress(ip.ToString()))return true;
        }
        return false;
    }
    public static bool MiningIndicator(string? process,int highCpuStreak,bool poolPortSeen)
    {
        if(highCpuStreak<3)return false;
        string name=Path.GetFileName(process??"").ToLowerInvariant();
        return name is "xmrig.exe" or "xmrig" or "minerd.exe" or "minerd" or
            "cpuminer.exe" or "cpuminer" or "ethminer.exe" or "ethminer" ||
            (poolPortSeen && highCpuStreak>=4);
    }
    public static bool PoolPortSeen(int pid,IEnumerable<Connection> conns)=>
        conns.Any(c=>c.Pid==pid&&c.State=="Established"&&new[]{3333,4444,5555,7777,14444}
            .Any(port=>c.Remote.EndsWith("]:"+port,StringComparison.Ordinal)));
    public static bool DefenderKeyloggerIndicator(string? name)
    {
        var n=(name??"").Trim();return n.Length<=256 &&
            (n.Contains("keylogger",StringComparison.OrdinalIgnoreCase) ||
             n.Contains("keystroke",StringComparison.OrdinalIgnoreCase) ||
             n.Contains("keylog.",StringComparison.OrdinalIgnoreCase));
    }
}
public static class BootPolicyAudit
{
    public sealed record Result(bool Parsed,bool WeakeningDetected,string Evidence);
    public static Result Parse(string? output)
    {
        if(string.IsNullOrWhiteSpace(output)||output.Length>65536)
            return new(false,false,"BCD configuration unavailable or over budget");
        string[] options=["testsigning","nointegritychecks","debug","bootdebug","hypervisordebug"];
        var weak=new List<string>();bool seen=false;
        foreach(var line in output.Split('\n'))
        {
            var parts=line.Trim().Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length!=2||!options.Contains(parts[0],StringComparer.OrdinalIgnoreCase))continue;
            seen=true;
            if(parts[1].Equals("yes",StringComparison.OrdinalIgnoreCase)||
               parts[1].Equals("on",StringComparison.OrdinalIgnoreCase)||parts[1]=="1")weak.Add(parts[0]);
        }
        return new(seen,weak.Count>0,weak.Count>0
            ?"BCD weakening settings: "+string.Join(", ",weak)
            :seen?"Observed BCD security option values; no known weakening setting explicitly enabled":
                  "No recognized optional BCD settings observed; integrity is not established");
    }
}
public static class DockerDaemonAudit
{
    public sealed record Result(bool Parsed,bool UnverifiedTcpHost,int HostCount,string Evidence);
    public static Result Parse(string? json)
    {
        if(string.IsNullOrWhiteSpace(json)||json.Length>65536)
            return new(false,false,0,"Docker daemon config missing or over budget");
        try
        {
            using var d=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=16});
            if(d.RootElement.ValueKind!=JsonValueKind.Object)return new(false,false,0,"Docker config is not a JSON object");
            bool verified=d.RootElement.TryGetProperty("tlsverify",out var tls)&&tls.ValueKind==JsonValueKind.True;
            int count=0;bool exposed=false;
            if(d.RootElement.TryGetProperty("hosts",out var hosts))
            {
                if(hosts.ValueKind!=JsonValueKind.Array||hosts.GetArrayLength()>128)
                    return new(false,false,0,"Docker hosts list invalid or too large");
                foreach(var host in hosts.EnumerateArray())
                {
                    if(host.ValueKind!=JsonValueKind.String)continue;
                    count++;
                    if(!verified&&(host.GetString()??"").StartsWith("tcp://",StringComparison.OrdinalIgnoreCase))exposed=true;
                }
            }
            return new(true,exposed,count,exposed
                ?"Docker TCP host without explicit TLS verification in config; effective runtime not verified"
                :"No unverified Docker TCP host in inspected config; effective runtime not verified");
        }
        catch(JsonException){return new(false,false,0,"Malformed Docker daemon configuration");}
    }
}
