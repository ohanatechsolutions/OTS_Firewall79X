using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class LayerChecks : IDisposable
{
    private readonly EventStore events;private readonly Dictionary<string,string> baselines=[];
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
    public List<Connection> UdpSockets {get;private set;}=[];
    public string? UdpError {get;private set;}

    private readonly Dictionary<string,List<DateTimeOffset>> connectionsHistory=[];
    private readonly Dictionary<int,(TimeSpan Cpu,DateTimeOffset Time,DateTime Start)> processSamples=[];
    public EventSensors? Sensors {get;set;}
    public FeodoThreatFeed? ThreatFeed {get;set;}
    private readonly HashSet<string> intelAlerts=[];
    private SecurityDeviceAudit.Result? deviceSnapshot;
    private SecurityDeviceAudit.Result DeviceStatus()=>deviceSnapshot??=SecurityDeviceAudit.Read();
    public List<Connection> Connections {get;private set;}=[];
    public string? NetworkError {get;private set;}
    public FirewallAudit? Firewall {get;}=new();
    private (bool Safe,string Description,List<FirewallAudit.Rule> Rules)? firewall;
    public LayerChecks(EventStore events){this.events=events;}
    public void Prepare()
    {
        firewall=null;NetworkError=null;UdpError=null;deviceSnapshot=null;neighborSnapshot=null;defenderNetwork=null;
        try{Connections=NetworkTables.Connections();TrackNetwork();TrackIntel();}catch(Exception ex){Connections=[];NetworkError=ex.Message;}
        try{UdpSockets=UdpTable.Read();}catch(Exception ex){UdpSockets=[];UdpError=Wire.Clean(ex.Message,180);}

        try{firewall=Firewall!.Read();}catch(Exception ex){events.Add(1,"Warning","Firewall query failed",ex.Message);}
    }
    private void TrackNetwork()
    {
        var now=DateTimeOffset.UtcNow;var current=Connections.Where(c=>c.State=="Established").Select(c=>$"{c.Pid}:{c.Remote}").ToHashSet();
        foreach(var c in Connections.Where(c=>c.State=="Established"&&!previousConnections.Contains($"{c.Pid}:{c.Remote}")))
        {
            string key=$"{c.Process}:{c.Remote}";events.Add(16,"Info","New observed connection",key);
            if(connectionsHistory.Count>4096)connectionsHistory.Clear();
            if(!connectionsHistory.TryGetValue(key,out var history))connectionsHistory[key]=history=[];
            history.Add(now);history.RemoveAll(t=>t<now.AddHours(-12));if(history.Count>32)history.RemoveAt(0);
            if(Detections.IsBeacon(history))events.Add(79,"Warning","Periodic connection indicator",$"{key}; periodicity alone is not proof of malware");
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
                events.Add(5,"High","Possible botnet C2 connection",
                    $"Windows observed {Wire.Clean(c.Process,80)} (PID {c.Pid}) connected to a Feodo-listed IPv4 address; review network activity. No OTS block was applied.");
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
            case 1:case 6:case 9:
                if(firewall==null)return Missing(id,"Windows Firewall state could not be read");
                return firewall.Value.Safe?Good(id,firewall.Value.Description,LayerMode.Enforcing,"Enforcement is provided by existing Windows Firewall policy. Existing exceptions are preserved. OTS does not automatically overwrite profile settings."):Bad(id,firewall.Value.Description,"Some profiles are disabled or allow inbound by default; automatic policy replacement is withheld to preserve management access.");
            case 2:return Channel(id,"Security","Detects high rates of logged blocked connections; does not rate-limit SYN/ICMP/UDP floods or prevent link saturation.");
            case 3:return Channel(id,"Security","Detects 12 distinct blocked destination ports per source within 60 seconds; alerts without automatic bans.");
            case 4:return Missing(id,"Packet-level anti-spoofing and malformed-packet inspection are not implemented. Windows TCP/IP validation is not claimed as an OTS layer.");
            case 5:
                return ThreatFeed?.Active is { } intel
                    ?Good(id,$"Observation-only: {intel.Addresses.Count} recent Feodo Tracker C2 IPv4 indicators; established outbound TCP connections compared each scan",LayerMode.Monitoring,"No source-blocking rules, domain intelligence, full UDP visibility or signed-feed proof. Only currently fresh source timestamps are accepted.")
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
                var bt=SystemQueries.Wmi("root\\cimv2","SELECT Name,Status FROM Win32_PnPEntity WHERE PNPClass='Bluetooth'","Name","Status");Changed(id,"Bluetooth device inventory",bt);
                return bt.Count==0?Na(id,"No Bluetooth device reported by Windows"):Good(id,$"{bt.Count} Bluetooth devices observed",LayerMode.Monitoring,"Inventory changes only; pairing authorization and discoverability hardening are not implemented.");
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
                return Good(id,$"{Connections.Count} TCP endpoints and {UdpSockets.Count} UDP bindings with owning process IDs; DNS Client responses observed={Sensors?.ObservedDnsResponses??0}",
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
            case 19:case 49:
                if(NetworkError!=null)return Missing(id,NetworkError);
                var listeners=Connections.Where(c=>c.State=="Listening")
                    .Select(c=>$"TCP {c.Process} {c.Local}")
                    .Concat(UdpSockets.Select(c=>$"UDP {c.Process} {c.Local}"))
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
                return Good(id,$"{Connections.Count(c=>c.State=="Listening")} listening TCP sockets; {UdpSockets.Count} bound UDP sockets (including ephemeral)",
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
                var services=SystemQueries.Wmi("root\\cimv2","SELECT Name,PathName,StartMode FROM Win32_Service","Name","PathName","StartMode");Changed(id,"Service persistence",services);Changed(id,"Machine startup entries",SystemQueries.Startup());Changed(id,"Installed software",SystemQueries.InstalledSoftware());
                return Good(id,$"{services.Count} services, machine Run keys, and installed software monitored",LayerMode.Monitoring,"Scheduled tasks and per-user browser extensions require additional coverage.");
            case 26:
                var drivers=SystemQueries.Wmi("root\\cimv2","SELECT Name,PathName,State FROM Win32_SystemDriver","Name","PathName","State");Changed(id,"Kernel driver inventory",drivers);
                return Good(id,$"{drivers.Count} system drivers inventoried",LayerMode.Monitoring,"Driver changes and enabled CodeIntegrity events; no memory rootkit scanner or kernel attestation.");
            case 27:return Channel(id,"Security","Monitors account creation, administrator-group membership, privilege-use, and audit-policy events.");
            case 28:return Missing(id,"Camera/microphone privacy observation requires the interactive-user collector");
            case 29:
                int high=0;var now=DateTimeOffset.UtcNow;var live=new HashSet<int>();
                foreach(var p in Process.GetProcesses())using(p){try{live.Add(p.Id);var cpu=p.TotalProcessorTime;var start=p.StartTime.ToUniversalTime();if(processSamples.TryGetValue(p.Id,out var old)&&old.Start==start&&(now-old.Time).TotalSeconds>=1){double pct=(cpu-old.Cpu).TotalSeconds/(now-old.Time).TotalSeconds/Environment.ProcessorCount*100;if(pct>40){high++;events.Add(id,"Warning","High CPU utilization",$"{p.ProcessName}: {pct:F1}% across all logical processors; resource use alone does not identify a miner");}}processSamples[p.Id]=(cpu,now,start);}catch(System.ComponentModel.Win32Exception){}catch(InvalidOperationException){}}
                foreach(var pid in processSamples.Keys.Where(pid=>!live.Contains(pid)).ToArray())processSamples.Remove(pid);
                return Good(id,$"{processSamples.Count} accessible processes sampled; {high} high-CPU observations",LayerMode.Monitoring,"Restricted/exited processes are skipped; no mining verdict from resource use alone.");
            case 30:return Channel(id,"System","Monitors service changes and available security, Defender, CodeIntegrity, and PowerShell event channels.");
            case 31:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security Event Log collector unavailable");
                var coverage31=AuditPolicy.Coverage(31);
                if(!coverage31.Enabled)return Missing(id,coverage31.Evidence+"; file-read SACLs are also required");
                return Sensors.ObservedAuditedBrowserFileReads>0
                    ?Good(id,$"{Sensors.ObservedAuditedBrowserFileReads} real Windows 4663 browser credential/session file-read audits observed",LayerMode.Monitoring,"Audit File System success and matching file SACLs are required. Alerts unexpected readers; Windows auditing does not guarantee every access, and no secrets are read by OTS.")
                    :Missing(id,"Windows File System auditing is enabled, but no browser credential read events have been observed. Matching file SACLs may be absent; no audit policy or SACL is silently changed.");
            case 32:return Missing(id,"Clipboard monitoring requires the interactive-user collector");
            case 33:
                Changed(id,"Machine root trust store",SystemQueries.RootCertificates());var hosts=Path.Combine(Environment.SystemDirectory,"drivers","etc","hosts");if(File.Exists(hosts))Changed(id,"Hosts file",SystemQueries.FileHash(hosts));Changed(id,"Network DNS configuration",NetworkInterface.GetAllNetworkInterfaces().Select(n=>new{n.Id,Dns=n.GetIPProperties().DnsAddresses.Select(x=>x.ToString()).ToArray()}).ToArray());
                return Good(id,"Root trust, hosts-file integrity, and interface DNS baselines monitored",LayerMode.Monitoring,"Changes are alerts, not automatically malicious. User proxy configuration requires user collector.");
            case 34:
                if(Sensors?.Has("Security")!=true)return Missing(id,"Windows Security Event Log collector unavailable");
                var coverage34=AuditPolicy.Coverage(34);
                if(!coverage34.Enabled)return Missing(id,coverage34.Evidence+"; per-file SACLs are also required");
                return Sensors.ObservedAuditedFileReads>0
                    ?Good(id,$"{Sensors.ObservedAuditedFileReads} authenticated Windows 4663 file-read audit events observed; per-process, distinct-file bursts correlated",LayerMode.Monitoring,"Alerts unusual read bursts only, with false-positive suppression. Actual copying, file sizes, encrypted upload, and exfiltration are not proven; only SACL-audited objects are visible.")
                    :Missing(id,"Object-access policy exists but there are no audited file reads. A suitable file SACL is necessary; no automatic SACL or audit policy changes are applied.");
            case 35:
                var binaries=Directory.GetFiles(AppContext.BaseDirectory,"OTS*.dll");foreach(var file in binaries)Changed(id,Path.GetFileName(file),SystemQueries.FileHash(file));
                return Good(id,$"Integrity baselines for {binaries.Length} OTS assemblies",LayerMode.Monitoring,"Baseline detects changes after first observation; authenticity and broad system-file coverage are separate requirements.");
            case 36:return Channel(id,"Security","Examines process-creation command lines where already audited; detects a narrow set of encoded PowerShell and remote script execution indicators.");
            case 37:
                var secure=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled");
                var deviceState=DeviceStatus();
                if(secure is not int v)return Missing(id,"Secure Boot state unavailable; "+deviceState.Evidence);
                if(v!=1)return Bad(id,"Secure Boot disabled; "+deviceState.Evidence,"TPM and OS encryption are read-only observations, not boot-chain attestation.");
                if(deviceState.TpmEnabled==false)return Bad(id,"Secure Boot enabled, TPM disabled/inactive; "+deviceState.Evidence,"Read-only WMI and registry evidence; firmware and boot attestations still needed.");
                return Good(id,"Secure Boot enabled; "+deviceState.Evidence,LayerMode.Auditing,"Unknown TPM/encryption does not establish protection. No measured-boot attestation or firmware integrity verification.");
            case 38:return Missing(id,"Reliable cross-process keylogger/input-hook inspection is not implemented; no claim of keylogger protection.");
            case 39:
                Changed(id,"Trusted publisher roots",SystemQueries.RootCertificates());Changed(id,"Software source inventory",SystemQueries.InstalledSoftware());
                return Good(id,"Trust-store and installed-software changes observed",LayerMode.Auditing,"Does not validate package repository metadata or every software update source.");
            case 40:
                var container=SystemQueries.Wmi("root\\cimv2","SELECT Name,State FROM Win32_Service WHERE Name='docker' OR Name='com.docker.service' OR Name='containerd'","Name","State");
                if(NetworkError!=null)return Missing(id,"Container management listener inspection unavailable: "+NetworkError);
                var endpoints=ContainerManagementAudit.Analyze(Connections.Where(c=>c.State=="Listening").Select(c=>c.Local),container.Count>0);
                if(endpoints.PlaintextCandidates>0)
                {
                    events.Add(id,"High","Potential unauthenticated container-management endpoint",
                        $"TCP 2375 listening on {endpoints.PlaintextCandidates} addresses; {endpoints.RemotePlaintextCandidates} non-loopback. Confirm listener process, TLS and firewall accessibility.");
                    return Bad(id,$"Possible plaintext container API: {endpoints.PlaintextCandidates} TCP 2375 listeners; {endpoints.RemotePlaintextCandidates} non-loopback addresses",
                        "Port-based observation, not definitive Docker identification. Even loopback APIs can be unsafe. No socket probe, policy change or block performed.");
                }
                if(!endpoints.ObservedAnyDockerService&&endpoints.TlsCandidates==0)return Na(id,"No recognized Docker/containerd service or common 2375/2376 management listener detected; WSL/remote engines not assessed");
                return Good(id,$"{container.Count} container service records; {endpoints.TlsCandidates} possible TLS management listeners (TCP 2376); no TCP 2375 detected",
                    LayerMode.Auditing,"TCP 2376 does not prove TLS or certificate verification. Container privilege, bind mounts, WSL2 port forwarding and service pipe ACLs require additional checks.");
            case 41:return Channel(id,"Security","Alerts on eight failed logins per source in two minutes; automatic source bans withheld to avoid lockout.");
            case 42:
                var config=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ssh","sshd_config");
                if(!File.Exists(config))return Na(id,"Default Windows sshd_config not found; custom -f configuration, OpenSSH service state and listening endpoints require separate verification");
                if(new FileInfo(config).Length>256*1024)return Missing(id,"OpenSSH configuration exceeds bounded review size");
                var ssh=OpenSshPolicyAudit.Parse(File.ReadAllText(config));
                var info=$"Global sshd directives: password authentication={ssh.PasswordAuthentication?.ToString()??"unspecified"}, public-key authentication={ssh.PublicKeyAuthentication?.ToString()??"unspecified"}, empty passwords={ssh.PermitEmptyPasswords?.ToString()??"unspecified"}, Include/Match={ssh.RequiresEffectiveVerification}";
                if(ssh.ExplicitWeakness)return Bad(id,info+"; explicitly permissive global authentication directive detected",
                    "OpenSSH's effective -T output, includes, Match contexts, startup -f settings and key-file ACLs have not been verified.");
                return ssh.ExplicitlyHardened
                    ?Good(id,info,LayerMode.Auditing,"Global configuration is explicitly restrictive, but effective -T settings, service arguments, key ACLs and port exposure still need independent verification.")
                    :Missing(id,info+"; insufficient evidence to claim SSH is hardened. Conditional Include/Match settings and defaults require an effective sshd -T audit.");
            case 43:return new(id,LayerMode.Idle,false,"Optional password check is available in the desktop interface; no password provided","Uses SHA-1 range queries only when requested; plaintext is never uploaded.");
            case 44:
                var accounts=SystemQueries.Wmi("root\\cimv2","SELECT Name,Disabled,PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True","Name","Disabled","PasswordRequired");int weak=accounts.Count(a=>a["Disabled"]=="False"&&a["PasswordRequired"]=="False");Changed(id,"Local account state",accounts);return weak>0?Bad(id,$"{weak} enabled accounts do not require passwords", "Account policy flags do not establish actual password strength or staleness."):Good(id,$"{accounts.Count} local accounts audited",LayerMode.Auditing,"Does not inspect password contents, domain policies, or account staleness.");
            case 45:return Channel(id,"Security","Monitors login, failed login, and special-privilege assignment events.");
            case 46:
                var defender=SystemQueries.Wmi("root\\Microsoft\\Windows\\Defender","SELECT AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus","AntivirusEnabled","RealTimeProtectionEnabled","AntivirusSignatureLastUpdated").FirstOrDefault();
                var hardening=HostHardeningAudit.Read();var hardware=DeviceStatus();
                if(defender==null)return Missing(id,"Microsoft Defender status is unavailable; "+hardening.Summary+"; "+hardware.Evidence);
                bool active=defender["AntivirusEnabled"]=="True"&&defender["RealTimeProtectionEnabled"]=="True";
                return active?Good(id,"Defender real-time protection enabled; "+hardening.Summary+"; "+hardware.Evidence,LayerMode.Auditing,"OS encryption and TPM observations are provider-dependent. Full ASLR, key recovery policy, security patching and boot attestation remain unverified."):Bad(id,"Defender real-time protection is not confirmed; "+hardening.Summary+"; "+hardware.Evidence,"May reflect a different antivirus product. No Windows security settings are changed.");
            case 47:return SystemQueries.Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoDriveTypeAutoRun") is int autorun&&autorun==255?Good(id,"AutoRun disabled for drive types; journaled restoration available",LayerMode.Enforcing,"Narrow hardening scope; legacy protocols and other policies are not automatically changed."):Bad(id,"AutoRun hardening is not applied or was changed externally");
            case 48:return Missing(id,"Browser audit requires the interactive-user collector");
            case 50:return new(id,LayerMode.Idle,false,"Select a folder in the desktop interface to scan for likely secrets","Reads only the selected tree within budgets; reports secret type and file location, never matched plaintext.");
            case 51:
                var rdp=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections");var assist=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\Remote Assistance","fAllowToGetHelp");
                var remoteSummary=$"RDP deny-connections={rdp??"unknown"}; Remote Assistance={assist??"unknown"}";
                if(rdp is int rdpValue && rdpValue==0 || assist is int assistValue && assistValue==1)
                    return Bad(id,remoteSummary+"; remote access is permitted by at least one policy","A permitted remote feature is not proof the host is externally reachable. No policy is changed.");
                return Good(id,remoteSummary,LayerMode.Auditing,"Unspecified policies are not proof of protection. Intel AMT, DMA protections, Wake-on-LAN and firmware policy are not fully assessed.");
            case 52:
                var fixes=SystemQueries.Wmi("root\\cimv2","SELECT HotFixID,InstalledOn FROM Win32_QuickFixEngineering","HotFixID","InstalledOn");Changed(id,"Installed Windows hotfixes",fixes);
                return Good(id,$"{fixes.Count} installed Windows hotfix records",LayerMode.Auditing,"Inventory only. Missing-update search and software CVE matching are incomplete; this does not prove the host is patched.");
            case 73:return firewall!=null?Good(id,FirewallAudit.Analyze(firewall.Value.Rules),LayerMode.Auditing,"Exact-match analysis only; full WFP/IPsec/GPO precedence and range shadowing are not modeled."):Missing(id,"Firewall rule enumeration unavailable");
            case 75:return Missing(id,"No verified malicious-domain feed or DNS enforcement engine is configured. Legitimate resolution remains unchanged.");
            case 76:return Channel(id,"Microsoft-Windows-Windows Defender/Operational","Observes Defender detection/remediation events; desktop Downloads scanner requests native Defender scans.");
            case 77:
                var devices=SystemQueries.Wmi("root\\cimv2","SELECT Name,PNPDeviceID FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'","Name","PNPDeviceID");Changed(id,"USB devices",devices);return Good(id,$"{devices.Count} USB devices observed",LayerMode.Monitoring,"Polling can miss brief connections; no automatic device blocking.");
            case 78:return Missing(id,"Ransomware canary and file-burst monitoring requires interactive-user collector");
            case 79:return NetworkError==null?Good(id,$"{connectionsHistory.Count} process/destination histories",LayerMode.Monitoring,"Polling and regularity heuristic only; short connections may be missed and benign polling can appear periodic."):Missing(id,NetworkError);
            default:return Missing(id,"Runtime component has not supplied health evidence");
        }
    }
    public void Dispose()=>clock.Dispose();
}
