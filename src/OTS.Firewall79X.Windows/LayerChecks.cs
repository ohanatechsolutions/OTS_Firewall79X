using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class LayerChecks
{
    private readonly EventStore events;private readonly Dictionary<string,string> baselines=[];
    private Dictionary<string,string> neighbors=[];private HashSet<string> previousConnections=[];
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
        firewall=null;NetworkError=null;deviceSnapshot=null;
        try{Connections=NetworkTables.Connections();TrackNetwork();TrackIntel();}catch(Exception ex){Connections=[];NetworkError=ex.Message;}
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
            if(c.Remote.EndsWith(":25")&&!new[]{"outlook","thunderbird"}.Contains(c.Process.ToLowerInvariant()))events.Add(22,"Warning","Unusual SMTP connection",$"{c.Process} connected to TCP 25");
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
            case 14:return Missing(id,"An established packet intrusion-detection engine and validated network signature set are not yet integrated.");
            case 15:return Channel(id,"Security","Classifies supported Windows authentication, privilege, and blocked-connection events; broad ATT&CK correlation is incomplete.");
            case 16:return NetworkError==null?Good(id,$"{Connections.Count} TCP endpoints with owning process IDs",LayerMode.Monitoring,"IPv4/IPv6 polling can miss short-lived connections; UDP attribution is absent. DNS observations require the DNS Client Operational channel."):Missing(id,NetworkError);
            case 17:case 20:
                var current=NetworkTables.Neighbors();
                if(id==17){foreach(var pair in current)if(neighbors.TryGetValue(pair.Key,out var old)&&old!=pair.Value)events.Add(17,"Warning","Neighbor MAC changed",$"{pair.Key}: {old} -> {pair.Value}; roaming and gateway replacement can be legitimate");}
                else{if(neighbors.Count>0)foreach(var pair in current.Where(p=>!neighbors.ContainsKey(p.Key)))events.Add(20,"Info","New neighbor observed",$"{pair.Key} {pair.Value}");neighbors=current;}
                return Good(id,$"{current.Count} IPv4 ARP neighbors observed",LayerMode.Monitoring,"Passive ARP cache only; no complete LAN inventory, IPv6 NDP monitoring, or proof of spoofing.");
            case 18:
                var dhcp=SystemQueries.Wmi("root\\cimv2","SELECT DHCPServer,DefaultIPGateway,Description FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True","DHCPServer","DefaultIPGateway","Description");Changed(id,"DHCP and gateway configuration",dhcp);
                return Good(id,$"Monitoring DHCP/gateway configuration for {dhcp.Count} adapters",LayerMode.Monitoring,"Detects configuration changes, not unaccepted rogue DHCP offers or Wi-Fi evil twins.");
            case 19:
                if(NetworkError!=null)return Missing(id,NetworkError);var listeners=Connections.Where(c=>c.State=="Listening").Select(c=>$"{c.Process}:{c.Local}").Order().ToArray();Changed(19,"Listening TCP services",listeners);
                return Good(id,$"{listeners.Length} local TCP listeners",LayerMode.Monitoring,"Local observation only; public reachability, NAT, router policy, and UDP exposure are not externally verified.");
            case 49:
                if(NetworkError!=null)return Missing(id,"Local listener inventory unavailable; external verification has not been performed: "+NetworkError);
                var bound=Connections.Where(c=>c.State=="Listening").Select(c=>c.Local).ToArray();
                return new(id,LayerMode.Auditing,false,SectionFAudits.Exposure(bound),
                    "OPTIONAL EXTERNAL VERIFICATION UNAVAILABLE: no user-authorized remote probe or authenticated third-party exposure assessment is configured. Local binding is not Internet reachability.");
            case 21:
                var wifi=WirelessAudit.Read();if(wifi.Count==0)return Na(id,"No connected WLAN interface reported");
                foreach(var w in wifi){Changed(18,"Connected Wi-Fi BSSID/authentication: "+w.Ssid,new{w.Bssid,w.Authentication,w.Cipher});if(w.Weak)events.Add(21,"High","Weak Wi-Fi security",$"{w.Ssid}: authentication {w.Authentication}, cipher {w.Cipher}");}
                var evidence=string.Join("; ",wifi.Select(w=>$"{w.Ssid}: security={w.SecurityEnabled}, auth={w.Authentication}, cipher={w.Cipher}, signal={w.Signal}%"));
                return wifi.Any(w=>w.Weak)?Bad(id,evidence,"Cipher/authentication state is not proof that a network is trustworthy; no evil-twin attestation."):Good(id,evidence,LayerMode.Auditing,"Native WLAN connection attributes only; hardware/privacy-policy dependent. A secured SSID can still be hostile.");
            case 22:return NetworkError==null?Good(id,"Observes new TCP port 25 connections",LayerMode.Monitoring,"Heuristic application-name exceptions; no SMTP content inspection; short-lived connections can be missed."):Missing(id,NetworkError);
            case 23:
                var remote=SystemQueries.Wmi("root\\cimv2","SELECT Name,State FROM Win32_Service WHERE Name='TermService' OR Name='sshd' OR Name LIKE '%VNC%' OR Name LIKE '%AnyDesk%' OR Name LIKE '%TeamViewer%'","Name","State");Changed(id,"Remote-management services",remote);
                return Good(id,$"{remote.Count} recognized remote-management services",LayerMode.Monitoring,"Recognition list is not exhaustive.");
            case 24:return Channel(id,"Security","Monitors Windows time-change security events; independent network clock-drift measurement is not implemented.");
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
                var state=$"NoDriveTypeAutoRun={autoRun}; NoAutorun={autoCommand}; NoAutoplayfornonVolume={nonVolume}";
                return autoRun&&autoCommand&&nonVolume
                    ?Good(id,state+"; reversible OTS-owned DWORD changes",LayerMode.Enforcing,
                        "Values may be enforced by Group Policy; scope is limited to AutoRun/AutoPlay. No legacy protocol is automatically disabled without a dedicated compatibility/rollback design.")
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
}
