using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class LayerChecks : IDisposable
{
    private readonly EventStore events;private readonly Dictionary<string,string> baselines=[];
    private IntegrityBaselineStore? durableBinaryBaselines;
    private readonly NeighborChangeTracker neighborChanges=new();
    private NeighborInventory.Snapshot? neighborSnapshot;
    private Dictionary<string,string> neighbors=[];
    private HashSet<string> previousConnections=[];
    private HashSet<string>? previousListeners;
    private Dictionary<string,WirelessAudit.Network> previousWifi=new(StringComparer.OrdinalIgnoreCase);
    private bool? previousRdpEnabled;
    private readonly ClockDriftProbe clock=new();
    private DateTimeOffset lastClockAlert=DateTimeOffset.MinValue;
    private DefenderNetworkIds.Status? defenderNetwork;

    private readonly Dictionary<string,List<DateTimeOffset>> connectionsHistory=[];
    private readonly Dictionary<int,(TimeSpan Cpu,DateTimeOffset Time,DateTime Start,int Streak)> processSamples=[];
    public EventSensors? Sensors {get;set;}
    public TemporaryFirewallGuard? NetworkGuard {get;set;}
    private HashSet<string>? bluetoothPrevious;
    public FeodoThreatFeed? ThreatFeed {get;set;}
    public MaliciousDomainFeed? DomainFeed {get;set;}
    public DomainHostsProtection? DomainBlocks {get;set;}
    public AdditionalHostMonitor? HostMonitor {get;set;}
    private readonly HashSet<string> intelAlerts=[];
    private SecurityDeviceAudit.Result? deviceSnapshot;
    private SecurityDeviceAudit.Result DeviceStatus()=>deviceSnapshot??=SecurityDeviceAudit.Read();
    public List<Connection> Connections {get;private set;}=[];
    public string? NetworkError {get;private set;}
    public string? UdpError {get;private set;}
    private bool? bluetoothDiscoverable;
    private Dictionary<string,(bool Authenticated,bool Connected)>? lastBluetoothDevices;
    public FirewallAudit? Firewall {get;}=new();
    private (bool Safe,string Description,List<FirewallAudit.Rule> Rules)? firewall;
    public LayerChecks(EventStore events){this.events=events;}
    public void Prepare()
    {
        firewall=null;NetworkError=null;UdpError=null;deviceSnapshot=null;neighborSnapshot=null;defenderNetwork=null;
        try{Connections=NetworkTables.Connections();TrackNetwork();TrackIntel();}catch(Exception ex){Connections=[];NetworkError=ex.Message;}
        try{Connections.AddRange(NetworkTables.UdpSockets());}catch(Exception ex){UdpError=ex.Message;}
        try{firewall=Firewall!.Read();}catch(Exception ex){events.Add(1,"Warning","Firewall query failed",ex.Message);}
    }
    private void TrackNetwork()
    {
        var now=DateTimeOffset.UtcNow;var current=Connections.Where(c=>c.State=="Established").Select(c=>$"{c.Pid}:{c.Remote}").ToHashSet();
        foreach(var c in Connections.Where(c=>c.State=="Established"&&!previousConnections.Contains($"{c.Pid}:{c.Remote}")))
        {
            string key=$"{c.Pid}:{c.Process}:{c.Remote}";events.Add(16,"Info","New observed connection",key);
            if(BeaconAnalysis.HasAttribution(c.Pid,c.Process))
            {
                if(connectionsHistory.Count>=4096&&!connectionsHistory.ContainsKey(key))
                {
                    foreach(var stale in connectionsHistory.Where(x=>x.Value.Count==0 ||
                        x.Value[^1]<now.AddHours(-12)).Select(x=>x.Key).ToArray())
                        connectionsHistory.Remove(stale);
                    if(connectionsHistory.Count>=4096)
                    {
                        var oldest=connectionsHistory.MinBy(x=>x.Value.Count==0
                            ?DateTimeOffset.MinValue:x.Value[^1]).Key;
                        connectionsHistory.Remove(oldest);
                    }
                }
                if(!connectionsHistory.TryGetValue(key,out var history))connectionsHistory[key]=history=[];
                history.Add(now);history.RemoveAll(t=>t<now.AddHours(-12));if(history.Count>32)history.RemoveAt(0);
                if(BeaconAnalysis.Suspicious(c.Process,history))
                    events.Add(79,"Warning","Possible regular outbound beacon",
                        $"{key}; {history.Count} observed reconnections; timing is suggestive, not a malicious verdict");
            }
            var remote=TrafficRules.ParseEndpoint(c.Remote);
            if(remote!=null&&TrafficRules.SuspiciousMailClient(c.Process,remote.Port))
                events.Add(22,"Warning","Unusual outbound SMTP connection",
                    $"{Wire.Clean(c.Process,80)} (PID {c.Pid}) connected to TCP {remote.Port}; SMTP payload and intent were not inspected.");
        }
        previousConnections=current;
    }
    private void TrackIntel()
    {
        var intel=ThreatFeed?.Active;
        if(intel==null)return;
        foreach(var c in Connections.Where(c=>c.State=="Established"))
        {
            var endpoint=c.Remote;
            int close=endpoint.LastIndexOf("]:",StringComparison.Ordinal);
            if(close<2 || endpoint[0]!='[')continue;
            var host=endpoint[1..close];
            if(!intel.Addresses.Contains(host))continue;
            var fingerprint=$"{c.Pid}:{host}";
            if(intelAlerts.Count>2000)intelAlerts.Clear();
            if(intelAlerts.Add(fingerprint))
            {
                bool blocked=NetworkGuard?.BlockObservedIntelligence(host,DateTimeOffset.UtcNow)==true;
                events.Add(5,"High","Possible botnet C2 connection",
                    $"Windows observed {Wire.Clean(c.Process,80)} (PID {c.Pid}) connected to a Feodo-listed IPv4 address. "+
                    (blocked?"A temporary outbound rule was installed; any subsequent drops are not verified.":"No additional OTS restriction was installed."));
            }
        }
    }
    private LayerResult Good(int id,string evidence,LayerMode mode=LayerMode.Auditing,string limitation="")=>new(id,mode,true,evidence,limitation);
    private LayerResult Bad(int id,string evidence,string limitation="")=>new(id,LayerMode.Auditing,false,evidence,limitation);
    private LayerResult Missing(int id,string evidence)=>new(id,LayerMode.Unavailable,false,evidence);
    private LayerResult Na(int id,string evidence)=>new(id,LayerMode.NotApplicable,false,evidence);
    private void Changed(int layer,string name,object value)
    {
        string hash=SystemQueries.Fingerprint(value);
        if(baselines.TryGetValue(name,out var old)&&old!=hash)events.Add(layer,"Warning","Configuration changed",name);
        baselines[name]=hash;
    }
    private LayerResult Channel(int id,string channel,string detail)
    {
        if(Sensors?.Has(channel)!=true)return Missing(id,Sensors?.Health.GetValueOrDefault(channel)??"Event collector is not running");
        if(channel=="Security")
        {
            var policy=AuditPolicy.Coverage(id);
            if(!policy.Enabled)return new(id,LayerMode.Unavailable,false,policy.Evidence,"Collector remains subscribed, but cannot claim functional coverage without the required audit policy. No system audit policy is modified.");
        }
        return Good(id,detail,LayerMode.Monitoring,"Existing system audit requirements are checked for Security-log detectors. Per-user exclusions and provider-specific settings can further limit events; no policy is changed.");
    }
    public LayerResult Check(int id)
    {
        switch(id)
        {
            case 1:
                if(firewall==null)return Missing(id,"Windows Firewall state could not be read");
                return firewall.Value.Safe?Good(id,firewall.Value.Description,LayerMode.Enforcing,"Windows Firewall is enforcing inbound default deny on all three profiles. Rule precedence, policy conflicts, exceptions and statefulness are not independently certified."):Bad(id,firewall.Value.Description,"One or more profiles allow inbound or have firewall disabled. No automatic blanket policy overwrite.");
            case 6:
                if(firewall==null)return Missing(id,"Windows Firewall state unavailable for IPv6 policy audit");
                if(NetworkError!=null||UdpError!=null)return Missing(id,"TCP/UDP IPv4/IPv6 endpoint enumeration incomplete: "+(NetworkError??UdpError));
                return firewall.Value.Safe
                    ?Good(id,$"All firewall profiles have inbound default deny; {Connections.Count(c=>c.State=="UDP Bound")} IPv4/IPv6 UDP bindings observed",LayerMode.Monitoring,"Firewall profile policies apply to both families; raw ICMPv6, fragmentation, all WFP policies and recovery parity have not been independently verified.")
                    :Bad(id,firewall.Value.Description,"A disabled/permissive profile undermines both address families.");
            case 9:
                if(firewall==null)return Missing(id,"Windows Firewall policy unavailable");
                bool publicSmb=firewall.Value.Rules.Any(r=>r.Enabled&&r.Direction=="1"&&r.Action=="1"&&r.Protocol=="6"&&
                    int.TryParse(r.Profiles,out int profiles)&&(profiles&4)!=0&&
                    r.RemoteAddresses is "*" or "" && r.LocalPorts.Split(',').Any(p=>p.Trim() is "139" or "445"));
                if(!firewall.Value.Safe)return Bad(id,firewall.Value.Description,"Inbound firewall defaults do not enforce a safe baseline on every profile.");
                return publicSmb
                    ?Bad(id,"Broad SMB inbound allow rule is configured for the Public profile","An overlapping block can change effective behavior; review exposed sharing and remote access.")
                    :Good(id,"All Windows Firewall profiles enabled/default-deny; no broad TCP 139/445 Public-profile allow observed",LayerMode.Auditing,"Read-only rule review; not proof of effective GPO, network category, broader sharing protocols or automatic untrusted Wi-Fi hardening.");
            case 2:case 3:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security event subscription is unavailable");
                if(!AuditPolicy.Coverage(id).Enabled)return Missing(id,"Filtering Platform Connection failure auditing is disabled; source restrictions are not reliably triggered.");
                if(NetworkGuard?.Operational!=true)return Missing(id,"Temporary Windows Firewall source restriction API unavailable: "+(NetworkGuard?.Health??"not started"));
                return id==2
                    ?Good(id,$"Event-correlated source restrictions active; {NetworkGuard.ActiveRules} temporary inbound rules",LayerMode.Monitoring,"Not SYN, UDP, ICMP, connection-rate or link-saturation mitigation; only Windows 5157 already-blocked connections are observed.")
                    :Good(id,$"Validated inbound scan alerting and exact-source five-minute blocks; {NetworkGuard.ActiveRules} temporary rules",LayerMode.Enforcing,"Uses already-blocked Windows 5157 events; 20-port/150-event thresholds and cooldown reduce but do not eliminate false positives; a hard crash can leave rules until service recovery.");
            case 4:return Missing(id,"No supported WFP callout/packet parser for ingress spoofing, malformed IPv4/IPv6 headers, extension chains or fragments; Windows TCP/IP validation is not claimed as an OTS packet-inspection engine.");
            case 5:
                return ThreatFeed?.Active is { } intel
                    ?Good(id,$"{intel.Addresses.Count} fresh Feodo C2 IPv4 indicators; {NetworkGuard?.IntelligenceRules??0} short-lived exact-destination outbound rules; observed TCP connections monitored",LayerMode.Monitoring,"Rules are reactive and may not interrupt existing connections; not signed intelligence, full-feed blocking, IPv6 indicators, UDP flow inspection or a malware verdict.")
                    :Missing(id,ThreatFeed?.Summary??"Threat intelligence unavailable");
            case 7:
                var model=SystemQueries.Wmi("root\\cimv2","SELECT Manufacturer,Model FROM Win32_ComputerSystem","Manufacturer","Model").FirstOrDefault();
                var vm=string.Join(" ",model?.Values??Enumerable.Empty<string>());
                return vm.Contains("Amazon",StringComparison.OrdinalIgnoreCase)||vm.Contains("Google",StringComparison.OrdinalIgnoreCase)||vm.Contains("Virtual",StringComparison.OrdinalIgnoreCase)?Bad(id,"Virtual/cloud-capable host detected; metadata access policy requires workload knowledge","No metadata endpoint requests or firewall changes are made."):Na(id,"No recognized cloud VM model; metadata enforcement is not enabled");
            case 8:
                if(Sensors?.Has("Microsoft-Windows-DNS-Client/Operational")!=true)
                    return Missing(id,"DNS Client operational event channel unavailable or disabled; no resolver inspection is possible");
                return Sensors.ObservedDnsResponses>0
                    ?Good(id,$"{Sensors.ObservedDnsResponses} actual DNS Client 3008 response events correlated for public-to-private address transitions",LayerMode.Monitoring,"Heuristic warning only: may miss DoH, alternate resolvers and queries without Event 3008; split-horizon networks can trigger legitimate changes. No DNS interception or rebinding block is applied.")
                    :Missing(id,"DNS Client subscription exists, but no valid address-bearing Event 3008 responses have been observed; rebinding telemetry is unverified.");
            case 10:
                var bt=SystemQueries.Wmi("root\\cimv2","SELECT Name,Status,PNPDeviceID FROM Win32_PnPEntity WHERE PNPClass='Bluetooth'","Name","Status","PNPDeviceID");
                var currentBt=bt.Select(x=>x.GetValueOrDefault("PNPDeviceID","")).Where(x=>x.Length>0).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if(bluetoothPrevious!=null)
                    foreach(var device in currentBt.Except(bluetoothPrevious).Take(32))
                        events.Add(10,"Warning","New Bluetooth PnP device observed","Device inventory changed; pairing/discoverability and connection authorization are not attested. ID fingerprint "+SystemQueries.Fingerprint(device)[..16]);
                bluetoothPrevious=currentBt;Changed(id,"Bluetooth device inventory",bt);
                var radio=BluetoothRadioAudit.Read();
                if(bt.Count==0&&radio.Available&&radio.Radios==0)return Na(id,"No active native Bluetooth radio or Bluetooth PnP inventory");
                if(!radio.Available)return Missing(id,radio.Evidence);
                bool visible=radio.Discoverable>0;
                if(visible&&bluetoothDiscoverable!=true)
                    events.Add(10,"Warning","Bluetooth radio discoverable","Windows native API reports a discoverable local Bluetooth radio; verify whether discovery is intentional.");
                bluetoothDiscoverable=visible;
                var paired=BluetoothDeviceAudit.Read();
                if(!paired.Available)return Good(id,$"{bt.Count} Bluetooth PnP entries; "+radio.Evidence,LayerMode.Monitoring,
                    "Bluetooth Classic device state unavailable: "+paired.Evidence+"; Bluetooth LE is not independently monitored.");
                var currentDevices=paired.Devices.ToDictionary(x=>x.Id,x=>(x.Authenticated,x.Connected),StringComparer.OrdinalIgnoreCase);
                if(lastBluetoothDevices!=null)
                    foreach(var device in currentDevices.Take(256))
                    {
                        var previous=lastBluetoothDevices.GetValueOrDefault(device.Key);
                        if(!lastBluetoothDevices.ContainsKey(device.Key)&&device.Value.Authenticated)
                            events.Add(10,"Warning","New paired Bluetooth Classic device",
                                "Paired device fingerprint "+SystemQueries.Fingerprint(device.Key)[..16]+"; Windows cache change does not establish authorization.");
                        if(device.Value.Connected&&(!lastBluetoothDevices.ContainsKey(device.Key)||!previous.Connected))
                            events.Add(10,"Warning","Bluetooth Classic device became connected",
                                "Connection fingerprint "+SystemQueries.Fingerprint(device.Key)[..16]+"; verify this is expected.");
                    }
                lastBluetoothDevices=currentDevices;
                return Good(id,$"{bt.Count} Bluetooth PnP entries; "+radio.Evidence+"; "+paired.Evidence,LayerMode.Monitoring,
                    "Paired/connected flags are Windows cached Classic device reports, not active BLE monitoring or proof of authorization.");
            case 11:case 12:case 13:return Missing(id,"Deception monitor has not reported health");
            case 14:
                defenderNetwork??=DefenderNetworkIds.Read();
                if(Sensors?.Has("Microsoft-Windows-Windows Defender/Operational")!=true)
                    return Missing(id,"Defender Operational subscription unavailable; native network threats cannot be verified.");
                if(!defenderNetwork.Available||!defenderNetwork.ProtectionEnabled&&!defenderNetwork.AuditOnly)
                    return Missing(id,defenderNetwork.Evidence+"; no independently integrated packet IDS.");
                return Good(id,defenderNetwork.Evidence+
                    $"; {Sensors.NetworkProtectionDetections} actual native network threat/audit events processed",
                    LayerMode.Monitoring,defenderNetwork.Limitation+
                    " Detection event counts may remain zero on quiet systems; controlled attack-signature testing and dedicated IDS rule updates remain outstanding.");
            case 15:
                return Channel(id,"Security","Windows blocked connections and login events are correlated; specific supported signals carry cautious MITRE ATT&CK technique hypotheses (T1110, T1021.001, T1059.001). Unverified network events are not assigned techniques.");
            case 16:
                if(NetworkError!=null&&UdpError!=null)return Missing(id,"TCP and UDP table collection unavailable: "+NetworkError+"; "+UdpError);
                return Good(id,$"{Connections.Count(c=>c.State!="UDP Bound")} TCP endpoints and {Connections.Count(c=>c.State=="UDP Bound")} UDP bindings with owning process IDs; DNS Client responses observed={Sensors?.ObservedDnsResponses??0}",
                    LayerMode.Monitoring,"TCP/UDP snapshots are not packet capture; UDP remote peer and query-to-process association are unavailable in native socket tables. Short-lived traffic, DoH and alternate resolvers may not be observed."+
                    (UdpError==null?"":" UDP collector unavailable: "+UdpError));
            case 17:case 20:
                neighborSnapshot??=NeighborInventory.Read();
                var current=neighborSnapshot.Entries;
                if(id==17)
                {
                    foreach(var change in neighborChanges.Update(current,NeighborInventory.Gateways()))
                        events.Add(17,change.Gateway?"High":"Warning",
                            change.Gateway?"Possible gateway neighbor impersonation":"Neighbor link-layer address changed",
                            $"{Wire.Clean(change.Key,100)}: {Wire.Clean(change.OldMac,24)} -> {Wire.Clean(change.NewMac,24)} confirmed twice; network roaming, DHCP renewal, proxy ARP/NDP and infrastructure failover are legitimate alternatives.");
                }
                else
                {
                    if(neighbors.Count>0)
                        foreach(var pair in current.Where(p=>!neighbors.ContainsKey(p.Key)).Take(40))
                            events.Add(20,"Info","New passive LAN neighbor observed",
                                $"{Wire.Clean(pair.Key,100)} {Wire.Clean(pair.Value,24)}; not proof that a new physical device joined.");
                    neighbors=current.ToDictionary(x=>x.Key,x=>x.Value,StringComparer.OrdinalIgnoreCase);
                }
                return Good(id,$"{current.Count} observed IP neighbors ({neighborSnapshot.IPv6Count} IPv6) via {neighborSnapshot.Source}",
                    LayerMode.Monitoring,"Passive neighbor cache only; cannot distinguish every spoof from legitimate changes or discover silent hosts. MAC changes require two consecutive confirmations; IPv6 visibility depends on provider availability.");
            case 18:
                var dhcp=SystemQueries.Wmi("root\\cimv2",
                    "SELECT DHCPServer,DefaultIPGateway,Description FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True",
                    "DHCPServer","DefaultIPGateway","Description");
                Changed(id,"DHCP and gateway configuration",dhcp);
                return Good(id,$"Baseline of DHCP server and gateway assignment on {dhcp.Count} Windows adapters",
                    LayerMode.Monitoring,"Configuration changes are observable, but rogue DHCP offers not accepted by this host cannot be observed without packet capture; DHCP changes can be legitimate.");
            case 19:
                if(NetworkError!=null)return Missing(id,NetworkError);
                var listeners=Connections.Where(c=>c.State=="Listening")
                    .Select(c=>$"TCP {c.Process} {c.Local}")
                    .Concat(Connections.Where(c=>c.State=="UDP Bound").Select(c=>$"UDP {c.Process} {c.Local}"))
                    .Order(StringComparer.OrdinalIgnoreCase).Take(12000).ToArray();
                if(id==19)
                {
                    var currentListeners=listeners.ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if(previousListeners!=null)
                        foreach(var newlyOpen in currentListeners.Except(previousListeners).Take(32))
                        {
                            int pos=newlyOpen.LastIndexOf('[');
                            var parsed=pos>=0?TrafficRules.ParseEndpoint(newlyOpen[pos..]):null;
                            if(parsed!=null&&TrafficRules.NonLoopbackBind(newlyOpen[pos..])&&parsed.Port is >0 and <49152)
                                events.Add(19,"Warning","New network-facing local socket",
                                    Wire.Clean(newlyOpen,180)+"; binding does not prove router/public reachability.");
                        }
                    previousListeners=currentListeners;
                    Changed(19,"Listening TCP and bound UDP services",listeners);
                }
                return Good(id,$"{Connections.Count(c=>c.State=="Listening")} listening TCP sockets; {Connections.Count(c=>c.State=="UDP Bound")} bound UDP sockets (including ephemeral)",
                    LayerMode.Monitoring,"Read-only local socket inventory; wildcard bindings may still be firewalled and UDP bindings are not established connections. Router, NAT, upstream policy and external reachability are not checked."+
                    (UdpError==null?"":" UDP inventory unavailable: "+UdpError));
            case 21:
                var wifi=WirelessAudit.Read();
                if(wifi.Count==0)return Na(id,"No connected WLAN interface reported by native Windows WLAN APIs");
                foreach(var w in wifi)
                {
                    Changed(18,"Connected Wi-Fi BSSID/authentication: "+w.Ssid,new{w.Bssid,w.Authentication,w.Cipher});
                    if(previousWifi.TryGetValue(w.Interface,out var old)&&old.Ssid==w.Ssid)
                    {
                        if(old.Bssid!=w.Bssid)
                            events.Add(18,"Info","Wi-Fi access point changed",
                                $"{Wire.Clean(w.Ssid,70)} BSSID changed; normal roaming is possible. BSSID change alone is not an evil-twin verdict.");
                        if(!old.Weak&&w.Weak)
                            events.Add(18,"High","Wi-Fi authentication/cipher downgrade",
                                $"{Wire.Clean(w.Ssid,70)} transitioned to weak network security; verify access point identity.");
                    }
                    if(w.Weak)events.Add(21,"High","Weak Wi-Fi security",
                        $"{Wire.Clean(w.Ssid,70)}: auth={w.Authentication}, cipher={w.Cipher}");
                    previousWifi[w.Interface]=w;
                }
                foreach(var key in previousWifi.Keys.Except(wifi.Select(w=>w.Interface)).ToArray())previousWifi.Remove(key);
                var evidence=string.Join("; ",wifi.Select(w=>$"{w.Ssid}: security={w.SecurityEnabled}, auth={w.Authentication}, cipher={w.Cipher}, signal={w.Signal}%"));
                return wifi.Any(w=>w.Weak)?Bad(id,evidence,
                    "Only native connected WLAN settings are assessed; WPA3 transition/enterprise policy details and evil-twin impersonation are not cryptographically verified.")
                    :Good(id,evidence,LayerMode.Auditing,
                    "Native WLAN connection attributes only. SSID/BSSID changes and security downgrades are monitored; encrypted Wi-Fi is not proof that the access point is trustworthy.");
            case 22:
                return NetworkError==null?Good(id,
                    "Monitors observed new TCP SMTP connections on ports 25, 465, 587 and 2525 with PID/process attribution",
                    LayerMode.Monitoring,"Allowlisted mail clients can be abused and nonstandard mail ports/short connections can be missed. No email content inspection or malware verdict.")
                    :Missing(id,NetworkError);
            case 23:
                var remote=SystemQueries.Wmi("root\\cimv2",
                    "SELECT Name,State,StartMode,PathName FROM Win32_Service WHERE Name='TermService' OR Name='sshd' OR Name='WinRM' OR Name='RemoteRegistry' OR Name LIKE '%VNC%' OR Name LIKE '%AnyDesk%' OR Name LIKE '%TeamViewer%' OR Name LIKE '%ScreenConnect%' OR Name LIKE '%RustDesk%'",
                    "Name","State","StartMode","PathName");
                Changed(id,"Remote-management service state/startup/path",remote);
                bool rdpEnabled=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections") is int rdpPolicyValue&&rdpPolicyValue==0;
                if(previousRdpEnabled==false&&rdpEnabled)
                    events.Add(23,"High","Remote Desktop newly enabled","RDP policy now permits incoming connections. Firewall and external accessibility remain separate.");
                previousRdpEnabled=rdpEnabled;
                Changed(id,"RDP authorization policy",rdpEnabled);
                var management=Connections.Where(c=>c.State=="Listening")
                    .Where(c=>TrafficRules.ParseEndpoint(c.Local)?.Port is 3389 or 5985 or 5986 or 5900).ToArray();
                return Good(id,$"{remote.Count} recognized management services; RDP enabled={rdpEnabled}; {management.Length} common remote-management TCP listeners",
                    LayerMode.Monitoring,"Service names/ports are heuristics; portable tools, custom ports, management tunnels and remote support in other user sessions may be missed.");
            case 24:
                var time=clock.Sample();
                if((time.ClockStep||time.RemoteDrift)&&DateTimeOffset.UtcNow-lastClockAlert>TimeSpan.FromMinutes(5))
                {
                    lastClockAlert=DateTimeOffset.UtcNow;
                    events.Add(24,"High","Suspicious system clock change",
                        (time.ClockStep?"Monotonic time comparison detected an abrupt clock step. ":"")+
                        (time.RemoteDrift?"Clock differs by over 120 seconds from an HTTPS server. ":"")+
                        Wire.Clean(time.Evidence,200));
                }
                return Good(id,time.Evidence+(time.ClockStep?"; local clock step detected":""),
                    LayerMode.Monitoring,
                    "Monotonic step detection plus periodic read-only HTTPS Date check. The server Date header is not signed secure time or NTP; outbound access, proxies, jitter and clock-dependent TLS validation can limit confidence."+
                    (time.HasRemoteSample?"":" No independent remote time sample available."));
            case 25:
                var services=SystemQueries.Wmi("root\\cimv2","SELECT Name,PathName,StartMode FROM Win32_Service","Name","PathName","StartMode");
                var tasks=EndpointInventory.ScheduledTasks();var startup=EndpointInventory.UserStartup();
                var extensions=EndpointInventory.BrowserExtensions();
                Changed(id,"Service persistence",services);Changed(id,"Machine startup entries",SystemQueries.Startup());
                Changed(id,"Loaded user startup",startup);Changed(id,"Scheduled task files",tasks);
                Changed(id,"Browser extension directories",extensions);
                Changed(id,"Installed software",SystemQueries.InstalledSoftware());
                return Good(id,$"{services.Count} services; {tasks.Count} task definitions; {startup.Count} loaded-user startup entries; {extensions.Count} browser extensions inventoried",LayerMode.Monitoring,
                    "Snapshot-only; unloaded user hives, managed browser policies, transient tasks and some browsers remain out of scope. Extension directory presence is not evidence of maliciousness.");
            case 26:
                var drivers=SystemQueries.Wmi("root\\cimv2","SELECT Name,PathName,State FROM Win32_SystemDriver","Name","PathName","State");
                Changed(id,"Kernel driver inventory",drivers);
                var signed=SystemQueries.Wmi("root\\cimv2","SELECT DeviceName,IsSigned,DriverProviderName FROM Win32_PnPSignedDriver","DeviceName","IsSigned","DriverProviderName");
                Changed(id,"PnP driver signature reports",signed);
                int unsigned=signed.Count(d=>d.GetValueOrDefault("IsSigned")=="False");
                return Good(id,$"{drivers.Count} system drivers; {signed.Count} PnP signature records; {unsigned} report IsSigned=False",LayerMode.Monitoring,
                    "PnP signature flags are not a trust or revocation verdict. Existing CodeIntegrity event channel is conditional; no kernel-memory scanning, rootkit attestation or complete driver-signature verification.");
            case 27:return Channel(id,"Security","Monitors account creation, administrator-group membership, privilege-use, and audit-policy events.");
            case 28:
                var media=EndpointInventory.UserMediaConsent();
                if(media.Keys==0)return Missing(id,"No readable loaded-user camera/microphone ConsentStore registry keys; background privacy telemetry is unavailable.");
                Changed(id,"Camera/microphone consent activity",media.Values);
                return Good(id,$"Observed {media.Keys} loaded-user camera/microphone ConsentStore keys and {media.Values.Count} activity entries",LayerMode.Monitoring,
                    "Read-only per-user registry timestamps can be delayed or absent; does not capture every active application, device stream or blocked request. UI need not be open, but unmounted user profiles are unavailable.");
            case 29:
                int high=0;var now=DateTimeOffset.UtcNow;var live=new HashSet<int>();
                foreach(var p in Process.GetProcesses())using(p)
                {
                    try
                    {
                        live.Add(p.Id);var cpu=p.TotalProcessorTime;var start=p.StartTime.ToUniversalTime();int streak=0;
                        if(processSamples.TryGetValue(p.Id,out var old)&&old.Start==start&&(now-old.Time).TotalSeconds>=1)
                        {
                            double pct=(cpu-old.Cpu).TotalSeconds/(now-old.Time).TotalSeconds/Environment.ProcessorCount*100;
                            if(pct>40){high++;streak=old.Streak+1;}
                            if((streak==3||streak==4)&&EndpointSignals.MiningIndicator(p.ProcessName,streak,EndpointSignals.PoolPortSeen(p.Id,Connections)))
                                events.Add(id,"Warning","Possible mining/resource-abuse indicator",
                                    $"{Wire.Clean(p.ProcessName,64)} PID {p.Id}: sustained CPU and mining-associated process/port evidence; not a confirmed malware verdict.");
                        }
                        processSamples[p.Id]=(cpu,now,start,streak);
                    }
                    catch(System.ComponentModel.Win32Exception){}catch(InvalidOperationException){}
                }
                foreach(var pid in processSamples.Keys.Where(pid=>!live.Contains(pid)).ToArray())processSamples.Remove(pid);
                return Good(id,$"{processSamples.Count} accessible processes sampled; {high} current high-CPU observations",LayerMode.Monitoring,
                    "Multiple high-CPU samples plus corroborating process/port metadata required. Common port values can be benign; restricted and short-lived miners are not covered.");
            case 30:
                var systemChannel=Channel(id,"System","Native Windows System event collector");
                if(systemChannel.Mode==LayerMode.Unavailable)return systemChannel;
                return Good(id,"System collector live; TaskScheduler/WMI="+
                    (Sensors?.Has("Microsoft-Windows-TaskScheduler/Operational")==true?"TaskScheduler ":"")+
                    (Sensors?.Has("Microsoft-Windows-WMI-Activity/Operational")==true?"WMI Activity":"not fully subscribed"),
                    LayerMode.Monitoring,"Event channels and their audit policy can be disabled. No kernel ETW trace, complete process lifetime capture or event-loss attestation.");
            case 31:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security Event Log collector unavailable");
                var coverage31=AuditPolicy.Coverage(31);
                if(!coverage31.Enabled)return Missing(id,coverage31.Evidence+"; file-read SACLs are also required");
                return Sensors.ObservedAuditedBrowserFileReads>0
                    ?Good(id,$"{Sensors.ObservedAuditedBrowserFileReads} real Windows 4663 browser credential/session file-read audits observed",LayerMode.Monitoring,"Audit File System success and matching file SACLs are required. Alerts unexpected readers; Windows auditing does not guarantee every access, and no secrets are read by OTS.")
                    :Missing(id,"Windows File System auditing is enabled, but no browser credential read events have been observed. Matching file SACLs may be absent; no audit policy or SACL is silently changed.");
            case 32:return Missing(id,"Clipboard monitoring requires the interactive-user collector");
            case 33:
                var proxy=EndpointInventory.UserProxy();Changed(id,"Loaded-user proxy values",proxy);
                Changed(id,"Machine root trust store",SystemQueries.RootCertificates());
                var hosts=Path.Combine(Environment.SystemDirectory,"drivers","etc","hosts");if(File.Exists(hosts))Changed(id,"Hosts file",SystemQueries.FileHash(hosts));
                Changed(id,"Network DNS configuration",NetworkInterface.GetAllNetworkInterfaces().Select(n=>new{n.Id,Dns=n.GetIPProperties().DnsAddresses.Select(x=>x.ToString()).ToArray()}).ToArray());
                return Good(id,$"Trust/hosts/DNS baselines and {proxy.Count} loaded-user proxy values monitored",LayerMode.Monitoring,
                    "Loaded-user profile scope; read-only polling can miss short-lived tampering. Captured values are fingerprinted, not logged.");
            case 34:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security Event Log collector unavailable");
                var coverage34=AuditPolicy.Coverage(34);
                if(!coverage34.Enabled)return Missing(id,coverage34.Evidence+"; per-file SACLs are also required");
                var correlated=Sensors.RecentBulkReadPids.Where(pid=>EndpointSignals.PublicTcpForProcess(pid,Connections)).ToArray();
                foreach(var pid in correlated)
                    events.Add(34,"Warning","Audited bulk reads with outbound TCP",
                        $"PID {pid} recently read 64+ SACL-audited files and has an established public TCP connection. This does NOT prove an upload or exfiltration.");
                return Sensors.ObservedAuditedFileReads>0
                    ?Good(id,$"{Sensors.ObservedAuditedFileReads} genuine Windows 4663 reads; {correlated.Length} current bulk-read/outbound-TCP correlations",LayerMode.Monitoring,
                        "Requires successful object-access audit and matching file SACLs. Real transfer, uploaded bytes, cloud encryption, causality and short-lived TCP are NOT established.")
                    :Missing(id,"Object-access policy exists but there are no audited file reads. A suitable file SACL is necessary; no automatic SACL or audit policy changes are applied.");
            case 35:
                var binaries=Directory.GetFiles(AppContext.BaseDirectory,"OTS*.dll");
                var systemBinaries=new[]{"winlogon.exe","lsass.exe","services.exe"}
                    .Select(name=>Path.Combine(Environment.SystemDirectory,name)).Where(File.Exists).ToArray();
                int first=0,modified=0;
                try
                {
                    durableBinaryBaselines??=new IntegrityBaselineStore(Paths.At("binary-integrity-baselines.json"));
                    foreach(var file in binaries.Concat(systemBinaries))
                    {
                        var result=durableBinaryBaselines.Observe(file,SystemQueries.FileHash(file));
                        if(result==IntegrityBaselineStore.ChangeKind.FirstObservation)first++;
                        if(result==IntegrityBaselineStore.ChangeKind.Changed)
                        {
                            modified++;
                            events.Add(id,"Warning","Persistent binary integrity observation changed",
                                $"{Path.GetFileName(file)} differed from the previously stored local SHA-256 baseline. An authorized Windows or application upgrade can cause this.");
                        }
                    }
                }
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or InvalidDataException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException)
                {
                    return Missing(id,"Persistent binary integrity inventory unavailable or unsafe: "+Wire.Clean(ex.Message,120));
                }
                return new(id,LayerMode.Monitoring,modified==0,
                    $"{binaries.Length} OTS assemblies, {systemBinaries.Length} core system binaries; "+
                    $"persistent protected observations={durableBinaryBaselines.Count}; "+
                    $"new baselines={first}; changed since previous reading={modified}",
                    "Persistent first-observation SHA-256 baselines are not cryptographically attested vendor signatures or boot-time integrity. "+
                    "An authorized update can change a binary; large files, transient mutations and unlisted paths are outside this sampled scope.");
            case 36:return Channel(id,"Security","Analyzes real 4688 process creation: script-capable binaries, suspicious command lines, and Office-to-script parent/child chains where native audit supplies the parent.");
            case 37:
                var secure=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled");
                var deviceState=DeviceStatus();
                BootPolicyAudit.Result boot;
                try{boot=EndpointInventory.BootOptions();}catch(Exception ex){boot=new(false,false,"BCD read unavailable: "+Wire.Clean(ex.Message,120));}
                if(boot.WeakeningDetected)return Bad(id,boot.Evidence+"; "+deviceState.Evidence,"Read-only BCD risk finding; OS configuration not modified.");
                if(secure is not int v)return Missing(id,"Secure Boot state unavailable; "+boot.Evidence+"; "+deviceState.Evidence);
                if(v!=1)return Bad(id,"Secure Boot disabled; "+deviceState.Evidence,"TPM and OS encryption are read-only observations, not boot-chain attestation.");
                if(deviceState.TpmEnabled==false)return Bad(id,"Secure Boot enabled, TPM disabled/inactive; "+deviceState.Evidence,"Read-only WMI and registry evidence; firmware and boot attestations still needed.");
                return Good(id,"Secure Boot enabled; "+boot.Evidence+"; "+deviceState.Evidence,LayerMode.Auditing,
                    "BCD parsing is not boot attestation and localizable output may be unsupported. No firmware integrity or measured-boot attestation.");
            case 38:
                if(Sensors?.Has("Microsoft-Windows-Windows Defender/Operational")!=true)
                    return Missing(id,"Defender detection event channel unavailable; keylogger/input-hook visibility unverified.");
                if(Sensors.ObservedKeyloggerAlerts==0)
                    return Missing(id,"Defender channel subscribed but no keylogger-labelled malware detection observed; cross-process input-hook inspection unavailable. Subscription alone is not detection evidence.");
                return Good(id,$"Observed {Sensors.ObservedKeyloggerAlerts} authentic Defender keylogging-related threat detections",
                    LayerMode.Monitoring,"Only previously identified malware events are monitored; no hooks are enumerated and unknown keyloggers are not detectable. Major capability remains incomplete.");
            case 39:
                var sources=EndpointInventory.SoftwareSources();
                Changed(id,"Trusted publisher roots",SystemQueries.RootCertificates());
                Changed(id,"Windows Update/AppInstaller policy sources",sources);
                Changed(id,"Software source inventory",SystemQueries.InstalledSoftware());
                return Good(id,$"Root store, installed software, and {sources.Count} update-source policy values fingerprinted",LayerMode.Auditing,
                    "Policy inventory is not actual publisher-signature verification or comprehensive user package-source validation.");
            case 40:
                var container=SystemQueries.Wmi("root\\cimv2","SELECT Name,State FROM Win32_Service WHERE Name='docker' OR Name='com.docker.service' OR Name='containerd'","Name","State");
                if(NetworkError!=null)return Missing(id,"Container management listener inspection unavailable: "+NetworkError);
                var endpoints=ContainerManagementAudit.Analyze(Connections.Where(c=>c.State=="Listening").Select(c=>c.Local),container.Count>0);
                var containerConfig=EndpointInventory.Container();
                Changed(id,"Docker daemon config",containerConfig.Daemon);
                if(containerConfig.Daemon.UnverifiedTcpHost)
                    return Bad(id,containerConfig.Daemon.Evidence,"Configuration is not proof of an active listener; validate effective Docker flags and TLS settings.");
                if(endpoints.PlaintextCandidates>0)
                {
                    events.Add(id,"High","Potential unauthenticated container-management endpoint",
                        $"TCP 2375 listening on {endpoints.PlaintextCandidates} addresses; {endpoints.RemotePlaintextCandidates} non-loopback. Confirm listener process, TLS and firewall accessibility.");
                    return Bad(id,$"Possible plaintext container API: {endpoints.PlaintextCandidates} TCP 2375 listeners; {endpoints.RemotePlaintextCandidates} non-loopback addresses",
                        "Port-based observation, not definitive Docker identification. Even loopback APIs can be unsafe. No socket probe, policy change or block performed.");
                }
                if(!endpoints.ObservedAnyDockerService&&endpoints.TlsCandidates==0&&containerConfig.Distros==0&&!containerConfig.Daemon.Parsed)
                    return Na(id,"No recognized container service, management listener, loaded-user WSL installation or Docker daemon configuration observed; this is not a complete remote engine search.");
                return Good(id,$"{container.Count} services; {containerConfig.Distros} loaded-user WSL distributions; {endpoints.TlsCandidates} possible TLS listeners; "+containerConfig.Daemon.Evidence,
                    LayerMode.Auditing,"No effective daemon query, published-container-port audit, named-pipe ACL or WSL2 port-forwarding proof. TCP 2376 does not prove TLS.");
            case 41:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Security event subscription unavailable: no verified remote login protection");
                var audit41=AuditPolicy.Coverage(41);
                if(!audit41.Enabled)return Missing(id,audit41.Evidence);
                return Good(id,$"Observed {Sensors.ObservedRemoteLogonFailures} verified public-source remote failed logins; threshold=8/2min; opt-in RDP restrictions={(NetworkGuard?.AuthenticationProtectionEnabled==true?"armed":"off")}; active RDP rules={NetworkGuard?.AuthenticationRules??0}",
                    NetworkGuard?.AuthenticationProtectionEnabled==true?LayerMode.Enforcing:LayerMode.Monitoring,
                     "Windows Security 4625 types 3/10 only. Optional administrator-enabled restrictions apply only to TCP 3389 after 32 invalid-account RDP failures targeting five distinct nonexistent users, for two minutes. A false positive can interrupt remote management; default is alerts only.");
            case 42:
                var sshAudit=SshEffectiveAudit.Read(Connections);
                return new(id,sshAudit.Mode,sshAudit.Healthy,sshAudit.Evidence,sshAudit.Limitations);
            case 43:
                return new(id,LayerMode.Idle,false,"Optional password range lookup is idle; the user must explicitly request a check",
                    "Only five SHA-1 hex prefix characters are submitted to the range endpoint with padding; responses are size- and format-validated. No password is stored or sent. Requires internet access.");
            case 44:
                var accountAudit=LocalAccountSecurityAudit.Read();
                Changed(id,"Local account, administrator and password policy baseline",accountAudit.Baseline);
                return new(id,LayerMode.Auditing,accountAudit.Healthy,accountAudit.Evidence,accountAudit.Limitations);
            case 45:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security log collector unavailable");
                var audit45=AuditPolicy.Coverage(45);
                if(!audit45.Enabled)return Missing(id,audit45.Evidence);
                return Good(id,$"Verified logon/failed-logon audit policy and Security event subscription; {Sensors.ObservedLoginSecurityEvents} account/session events and {Sensors.ObservedPrivilegeSecurityEvents} privilege events observed",
                    LayerMode.Monitoring,"Classifies interactive, network, unlock, remote interactive and cached logons; watches explicit credentials, privileged logons, account changes, and token elevation when process creation is audited. Security event logging and provider configuration determine coverage.");
            case 46:
                var defender=SystemQueries.Wmi("root\\Microsoft\\Windows\\Defender",
                    "SELECT AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus",
                    "AntivirusEnabled","RealTimeProtectionEnabled","AntivirusSignatureLastUpdated").FirstOrDefault();
                var hardening=HostHardeningAudit.Read();var hardware=DeviceStatus();
                var additional=SectionFAudits.HostEvidence();
                var defenderStatus=defender==null?"Defender provider unavailable (other AV may be in use)":
                    $"Defender real-time={defender["RealTimeProtectionEnabled"]}, enabled={defender["AntivirusEnabled"]}";
                var hostSummary=defenderStatus+"; "+hardening.Summary+"; "+additional+"; "+hardware.Evidence;
                if(defender==null)return Missing(id,hostSummary+"; endpoint antivirus state unknown");
                var weak=defender["AntivirusEnabled"]!="True"||defender["RealTimeProtectionEnabled"]!="True"||
                    !hardening.UacEnabled||!hardening.DepEnabled||hardening.LsaProtected==false||
                    hardening.Smb1Disabled==false||hardware.TpmEnabled==false||hardware.OsVolumeProtected==false;
                return new(id,LayerMode.Auditing,false,hostSummary,
                    (weak?"One or more checks are weak/unknown; also: ":"Observed controls do not complete the full specification; ")+
                    "Machine-wide ASLR, effective account/domain policy, real current-user lock screen, insecure ACLs, encryption recovery and TPM/firmware attestation are not validated. A separate AV product may replace Defender.");
            case 47:
                var policyPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
                var autoRun=SystemQueries.Reg(policyPath,"NoDriveTypeAutoRun") is int a&&a==255;
                var autoCommand=SystemQueries.Reg(policyPath,"NoAutorun") is int b&&b==1;
                var nonVolume=SystemQueries.Reg(policyPath,"NoAutoplayfornonVolume") is int c&&c==1;
                var smartScreenPolicy=SystemQueries.Reg(@"SOFTWARE\Policies\Microsoft\Windows\System","EnableSmartScreen") is int ss&&ss==1;
                var state=$"NoDriveTypeAutoRun={autoRun}; NoAutorun={autoCommand}; NoAutoplayfornonVolume={nonVolume}; Shell SmartScreen policy={smartScreenPolicy}";
                return autoRun&&autoCommand&&nonVolume&&smartScreenPolicy
                    ?Good(id,state+"; four allowable DWORD policies configured; only actual OTS changes were journaled for rollback",LayerMode.Enforcing,
                        "Values may be enforced by Group Policy; scope is limited to AutoRun/AutoPlay and SmartScreen policy; actual SmartScreen reputation provider operation is not independently attested. No legacy protocol is automatically disabled without a dedicated compatibility/rollback design.")
                    :Bad(id,state+"; one or more journaled hardening settings missing or externally changed",
                        "Every OTS-owned mutation uses durable prepare/apply/compare-before-restore. Other security policies remain untouched.");
            case 48:return Missing(id,"Browser audit requires the interactive-user collector");
            case 50:return new(id,LayerMode.Idle,false,"Select a folder in the desktop interface to scan for likely secrets","Reads only the selected tree within budgets; reports secret type and file location, never matched plaintext.");
            case 51:
                var rdp=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections");var assist=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\Remote Assistance","fAllowToGetHelp");
                var remoteSummary=$"RDP deny-connections={rdp??"unknown"}; Remote Assistance={assist??"unknown"}; "+
                    SectionFAudits.RemoteHardware(Connections.Where(c=>c.State=="Listening").Select(c=>c.Local));
                if(rdp is int rdpValue && rdpValue==0 || assist is int assistValue && assistValue==1)
                    return Bad(id,remoteSummary+"; a remote access capability is permitted","Firewall and router reachability, firmware Intel AMT provisioning, device wake, and hardware DMA status require validation; no policy is changed.");
                return new(id,LayerMode.Auditing,false,remoteSummary,
                    "Partial read-only audit. Unknown RDP/Remote Assistance, firmware Intel AMT and DMA indicators prevent certification.");
            case 52:
                var fixes=SystemQueries.Wmi("root\\cimv2","SELECT HotFixID,InstalledOn FROM Win32_QuickFixEngineering","HotFixID","InstalledOn");Changed(id,"Installed Windows hotfixes",fixes);
                var pending=WindowsMissingUpdateAudit.Latest(out var updateState);
                if(pending==null)return Missing(id,$"{fixes.Count} historical installed hotfix records; "+updateState);
                if(!pending.Verified)return Missing(id,$"{fixes.Count} historical hotfix records; "+updateState);
                return new(id,LayerMode.Auditing,false,$"{fixes.Count} historical installed hotfixes; "+updateState,
                    "Pending count is a completed native Windows Update Agent search, not proof the system is secure. Missing updates may include non-security items. Third-party package CVE matching has no verified vendor/version-to-advisory correlation configured.");
            case 73:return firewall!=null?Good(id,FirewallAudit.Analyze(firewall.Value.Rules),LayerMode.Auditing,"Bounded potential CIDR/port overlap audit; not effective-rule or WFP/GPO/IPsec precedence verification."):Missing(id,"Firewall rule enumeration unavailable");
            case 75:
                if(DomainFeed?.Active is not { } domains)return Missing(id,DomainFeed?.Status??"No validated domain intelligence available");
                return DomainBlocks?.Applied==true
                    ?Good(id,$"Administrator opt-in managed hosts filtering active; {domains.Domains.Count} fresh feed indicators. {DomainBlocks.Status}",LayerMode.Enforcing,"Exact hostname mapping only, 1,000-entry cap; DNS-over-HTTPS may bypass. Public mirror not cryptographically signed; offline/hardware proof outstanding.")
                    :Good(id,$"Observation mode: {domains.Domains.Count} URLhaus-format indicators. {DomainFeed.Status}",LayerMode.Monitoring,"Enforcement is OFF until the administrator explicitly opts in. Public mirror is not signed. DNS client events may be disabled.");
            case 76:return HostMonitor?.Check(76)??Missing(id,"Background Defender file monitor is not started");
            case 77:return HostMonitor?.Check(77)??Missing(id,"USB device notifications are not started");
            case 78:return HostMonitor?.Check(78)??Missing(id,"Background file-change monitor is not started");
            case 79:return NetworkError==null?Good(id,$"{connectionsHistory.Count} attributable process/destination reconnection histories; 4,096-key bounded selective eviction and benign-process suppression",LayerMode.Monitoring,"Bounded 30/90-second TCP sampling misses many short connections and UDP; public and private destinations may still produce false positives. A regular interval is not proof of compromise."):Missing(id,NetworkError);
            default:return Missing(id,"Runtime component has not supplied health evidence");
        }
    }
    public void Dispose()=>clock.Dispose();
}
