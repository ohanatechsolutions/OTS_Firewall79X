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
    private const string IntelPrefix="OTS Firewall79X temporary outbound intelligence ";
    private const string AuthenticationPrefix="OTS Firewall79X temporary RDP authentication source ";
    private readonly object gate=new();
    private readonly Dictionary<string,DateTimeOffset> active=new(StringComparer.Ordinal);
    private readonly Dictionary<string,DateTimeOffset> intelligence=new(StringComparer.Ordinal);
    private readonly Dictionary<string,DateTimeOffset> authentication=new(StringComparer.Ordinal);
    private bool authenticationEnabled;
    public bool AuthenticationProtectionEnabled {get { lock(gate)return Operational&&authenticationEnabled; }}
    public int AuthenticationRules {get { lock(gate)return authentication.Count; } }
    private readonly NetworkAbuseWindow detector=new();
    private readonly EventStore events;
    private bool started;
    public bool Operational {get;private set;}
    public string Health {get;private set;}="Not initialized";
    public int ActiveRules {get { lock(gate)return active.Count; } }
    public int IntelligenceRules {get { lock(gate)return intelligence.Count; } }
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
                if(name.StartsWith(Prefix,StringComparison.Ordinal)||name.StartsWith(IntelPrefix,StringComparison.Ordinal)||
                   name.StartsWith(AuthenticationPrefix,StringComparison.Ordinal))names.Add(name);
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

    /// <summary>
    /// Optional RDP-only source protection. A separate administrator command is required
    /// each time the OTS service is activated. No account lockout settings or existing
    /// administrator firewall rules are changed. Network telemetry is untrusted:
    /// public-source and host-allowlist checks are repeated at enforcement time.
    /// </summary>
    public bool SetAuthenticationProtection(bool enable)
    {
        lock(gate)
        {
            if(!Operational)return false;
            if(!enable)
            {
                authenticationEnabled=false;
                dynamic? policy=null;
                try
                {
                    policy=Policy();
                    foreach(var address in authentication.Keys.ToArray())
                    {
                        policy.Rules.Remove(AuthenticationPrefix+address);
                        authentication.Remove(address);
                    }
                    Health="RDP temporary authentication restrictions disabled and removed";
                }
                catch(Exception ex)
                {
                    Health="Authentication rule rollback failed: "+Wire.Clean(ex.Message,160);
                    events.Add(41,"High","Authentication rule rollback requires attention",Health);
                    return false;
                }
                finally {if(policy!=null)Marshal.ReleaseComObject(policy);}
            }
            else
            {
                authenticationEnabled=true;
                Health="Optional short-lived RDP source restrictions armed; strong invalid-account evidence required";
            }
            return true;
        }
    }
    /// <summary>Only called after 32 RDP logon failures against >=5 distinct
    /// nonexistent usernames within 2 minutes. No restriction without explicit opt-in.</summary>
    public bool ObserveAuthenticationAttack(string source,DateTimeOffset now)
    {
        lock(gate)
        {
            if(!Operational||!authenticationEnabled||authentication.Count>=8||authentication.ContainsKey(source)||
               !NetworkAbuseWindow.EligiblePublicSource(source))return false;
            HashSet<string> trusted;
            try{trusted=TrustedAddresses();}
            catch(Exception ex)
            {
                Health="Trusted network address verification unavailable: "+Wire.Clean(ex.Message,140);
                return false;
            }
            if(!NetworkAbuseWindow.EligiblePublicSource(source,trusted))return false;
            dynamic? policy=null;dynamic? rule=null;
            try
            {
                policy=Policy();
                var type=Type.GetTypeFromProgID("HNetCfg.FWRule")??
                    throw new PlatformNotSupportedException("Windows Firewall rule API unavailable");
                rule=Activator.CreateInstance(type)!;
                rule.Name=AuthenticationPrefix+source;
                rule.Description="OTS opt-in temporary RDP-only inbound restriction for repeated nonexistent-user attempts; 2-minute TTL; removed at OFF/startup";
                rule.Direction=1;rule.Action=0;rule.Protocol=6;rule.LocalPorts="3389";
                rule.RemoteAddresses=source;rule.Profiles=int.MaxValue;rule.Enabled=true;
                policy.Rules.Add(rule);
                authentication[source]=now.AddMinutes(2);
                events.Add(41,"Warning","Optional temporary RDP source restriction installed",
                    $"Source {source}; TCP 3389 only; expires in two minutes. Windows Firewall enforces the rule; actual packet drops are not measured.");
                return true;
            }
            catch(Exception ex)
            {
                Health="RDP restriction installation failed: "+Wire.Clean(ex.Message,160);
                events.Add(41,"Warning","RDP source restriction not installed",Health);
                // If rule installation partially succeeded, reclaim our exact owned name.
                try{if(policy!=null)policy.Rules.Remove(AuthenticationPrefix+source);}catch(Exception){}
                return false;
            }
            finally
            {
                if(rule!=null)Marshal.ReleaseComObject(rule);
                if(policy!=null)Marshal.ReleaseComObject(policy);
            }
        }
    }
    /// <summary>Reactive exact-destination rule for an observed, freshly listed Feodo IPv4 C2 endpoint.
    /// Current HTTPS source material is not independently signed; does not imply a malware verdict.</summary>
    public bool BlockObservedIntelligence(string address,DateTimeOffset now)
    {
        if(!Operational || !NetworkAbuseWindow.EligiblePublicSource(address))return false;
        lock(gate)
        {
            if(!Operational || intelligence.Count>=16 || intelligence.ContainsKey(address))return false;
            if(!NetworkAbuseWindow.EligiblePublicSource(address,TrustedAddresses()))return false;
            dynamic? policy=null;dynamic? rule=null;
            try
            {
                policy=Policy();
                var type=Type.GetTypeFromProgID("HNetCfg.FWRule")??
                    throw new PlatformNotSupportedException("Windows Firewall rule API unavailable");
                rule=Activator.CreateInstance(type)!;
                rule.Name=IntelPrefix+address;
                rule.Description="OTS temporary rule for observed, fresh Feodo intelligence; removed at expiry/feed failure/OFF";
                rule.Direction=2;  // NET_FW_RULE_DIR_OUT
                rule.Action=0;     // NET_FW_ACTION_BLOCK
                rule.Protocol=256; // Any protocol
                rule.RemoteAddresses=address;
                rule.Profiles=int.MaxValue;
                rule.Enabled=true;
                policy.Rules.Add(rule);
                intelligence[address]=now.AddMinutes(5);
                events.Add(5,"High","Temporary intelligence restriction installed",
                    $"Exact outbound destination {address}; five-minute rule installed. Actual packet drops are not measured.");
                return true;
            }
            catch(Exception ex)
            {
                Health="Intelligence restriction failed: "+Wire.Clean(ex.Message,160);
                events.Add(5,"Warning","Intelligence rule failed",Health);
                return false;
            }
            finally
            {
                if(rule!=null)Marshal.ReleaseComObject(rule);
                if(policy!=null)Marshal.ReleaseComObject(policy);
            }
        }
    }
    public void Sweep(DateTimeOffset now,bool intelligenceFresh=true)
    {
        lock(gate)
        {
            if(!Operational || (!active.Values.Any(t=>t<=now)&&!intelligence.Any(p=>p.Value<=now||!intelligenceFresh)&&
                !authentication.Any(p=>p.Value<=now||!authenticationEnabled)))return;
            dynamic? policy=null;
            try
            {
                policy=Policy();
                foreach(var pair in active.Where(p=>p.Value<=now).ToArray())
                {
                    policy.Rules.Remove(RuleName(pair.Key));
                    active.Remove(pair.Key);
                }
                foreach(var pair in authentication.Where(p=>p.Value<=now||!authenticationEnabled).ToArray())
                {
                    policy.Rules.Remove(AuthenticationPrefix+pair.Key);
                    authentication.Remove(pair.Key);
                }
                foreach(var pair in intelligence.Where(p=>p.Value<=now||!intelligenceFresh).ToArray())
                {
                    policy.Rules.Remove(IntelPrefix+pair.Key);
                    intelligence.Remove(pair.Key);
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
                active.Clear();intelligence.Clear();authentication.Clear();authenticationEnabled=false;
                Health="All OTS temporary restrictions restored";
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
