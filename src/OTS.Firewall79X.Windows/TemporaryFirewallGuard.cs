using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>
/// Owns ONLY temporary, exact-IP inbound deny rules. Windows Firewall is never disabled,
/// profile defaults are not modified, and existing third-party exceptions are untouched.
/// Startup/off restores rules bearing our exclusive prefix. Persistent Windows Firewall
/// rules are not crash-atomic: a hard service termination may leave one until restart.
/// </summary>
public sealed class TemporaryFirewallGuard : IDisposable
{
    private const string Prefix="OTS Firewall79X temporary inbound source ";
    private readonly object gate=new();
    private readonly Dictionary<string,DateTimeOffset> active=new(StringComparer.Ordinal);
    private readonly NetworkAbuseWindow detector=new();
    private readonly EventStore events;
    private bool started;
    public bool Operational {get;private set;}
    public string Health {get;private set;}="Not initialized";
    public int ActiveRules {get { lock(gate)return active.Count; } }
    public TemporaryFirewallGuard(EventStore events) => this.events=events;

    private static dynamic Policy()
    {
        var type=Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ??
            throw new PlatformNotSupportedException("Windows Firewall COM API unavailable");
        return Activator.CreateInstance(type)!;
    }
    private static string RuleName(string ip)=>Prefix+ip;
    private static HashSet<string> TrustedAddresses()
    {
        var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            var properties=network.GetIPProperties();
            foreach(var address in properties.UnicastAddresses)result.Add(address.Address.ToString());
            foreach(var address in properties.GatewayAddresses)result.Add(address.Address.ToString());
            foreach(var address in properties.DnsAddresses)result.Add(address.ToString());
            foreach(var address in properties.DhcpServerAddresses)result.Add(address.ToString());
        }
        return result;
    }
    private static void RemoveOwned(dynamic policy)
    {
        var names=new List<string>();
        foreach(dynamic rule in policy.Rules)
        {
            try
            {
                string name=(string)rule.Name;
                if(name.StartsWith(Prefix,StringComparison.Ordinal))names.Add(name);
            }
            finally { Marshal.ReleaseComObject(rule); }
            if(names.Count>128)throw new InvalidDataException("Unexpected number of owned rules; refusing bulk deletion");
        }
        foreach(var name in names)policy.Rules.Remove(name);
    }
    public void Start()
    {
        lock(gate)
        {
            if(started)return;
            started=true;
            if(!OperatingSystem.IsWindows()){Health="Windows Firewall API unavailable on this host";return;}
            dynamic? policy=null;
            try
            {
                policy=Policy();RemoveOwned(policy);
                Operational=true;Health="Rule ownership and startup cleanup verified";
            }
            catch(Exception ex)
            {
                Operational=false;Health=Wire.Clean(ex.Message,200);
                events.Add(3,"Warning","Temporary rule protection unavailable",Health);
            }
            finally { if(policy!=null)Marshal.ReleaseComObject(policy); }
        }
    }
    public void ObserveBlocked(string? source,string? direction,int port,DateTimeOffset at)
    {
        if(!Operational)return;
        // Fast refusal: only public inbound events can ever trigger a restriction.
        var finding=detector.Observe(source,direction,port,at);
        if(!finding.Restrict)return;
        lock(gate)
        {
            if(!Operational || active.Count>=32 || active.ContainsKey(finding.Address))return;
            if(!NetworkAbuseWindow.EligiblePublicSource(finding.Address,TrustedAddresses()))return;
            dynamic? policy=null;dynamic? rule=null;
            try
            {
                policy=Policy();
                var type=Type.GetTypeFromProgID("HNetCfg.FWRule") ??
                    throw new PlatformNotSupportedException("Windows Firewall rule API unavailable");
                rule=Activator.CreateInstance(type)!;
                rule.Name=RuleName(finding.Address);
                rule.Description="OTS-owned temporary inbound restriction for repeated already-blocked attempts; reclaimed when disabled or expired";
                rule.Direction=1; // NET_FW_RULE_DIR_IN
                rule.Action=0; // NET_FW_ACTION_BLOCK
                rule.Protocol=256; // NET_FW_IP_PROTOCOL_ANY (IPv4 or IPv6)
                rule.RemoteAddresses=finding.Address;
                rule.Profiles=int.MaxValue; // NET_FW_PROFILE2_ALL
                rule.Enabled=true;
                policy.Rules.Add(rule);
                active[finding.Address]=at.AddMinutes(5);
                events.Add(3,"Warning","Temporary inbound source restriction installed",
                    $"{finding.Address}; expires in five minutes; {active.Count} owned rules. Windows is the enforcing firewall; no dropped-packet count is claimed.");
            }
            catch(Exception ex)
            {
                Health="Restriction installation failed: "+Wire.Clean(ex.Message,160);
                events.Add(3,"Warning","Temporary restriction not installed",Health);
            }
            finally
            {
                if(rule!=null)Marshal.ReleaseComObject(rule);
                if(policy!=null)Marshal.ReleaseComObject(policy);
            }
        }
    }
    public void Sweep(DateTimeOffset now)
    {
        lock(gate)
        {
            if(!Operational || !active.Values.Any(t=>t<=now))return;
            dynamic? policy=null;
            try
            {
                policy=Policy();
                foreach(var pair in active.Where(p=>p.Value<=now).ToArray())
                {
                    policy.Rules.Remove(RuleName(pair.Key));
                    active.Remove(pair.Key);
                }
            }
            catch(Exception ex)
            {
                Health="Expired rule cleanup failed: "+Wire.Clean(ex.Message,160);
                events.Add(3,"Warning","Temporary firewall rollback needs attention",Health);
            }
            finally { if(policy!=null)Marshal.ReleaseComObject(policy); }
        }
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(!started)return;
            dynamic? policy=null;
            try
            {
                policy=Policy();RemoveOwned(policy);
                active.Clear();Health="All OTS temporary source restrictions restored";
            }
            catch(Exception ex)
            {
                Health="Shutdown rule rollback failed: "+Wire.Clean(ex.Message,160);
                events.Add(3,"High","Temporary firewall rules require recovery",Health);
            }
            finally
            {
                Operational=false;started=false;
                if(policy!=null)Marshal.ReleaseComObject(policy);
            }
        }
    }
}
