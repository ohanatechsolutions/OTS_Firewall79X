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
    private readonly Dictionary<int,(TimeSpan Cpu,DateTimeOffset Time,DateTime Start,int Streak)> processSamples=[];
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
            case 19:case 49:
                if(NetworkError!=null)return Missing(id,NetworkError);var listeners=Connections.Where(c=>c.State=="Listening").Select(c=>$"{c.Process}:{c.Local}").Order().ToArray();Changed(19,"Listening TCP services",listeners);
                return Good(id,$"{listeners.Length} local TCP listeners",LayerMode.Monitoring,"Local observation only; public reachability, NAT, router policy, and UDP exposure are not externally verified.");
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
                var drivers=SystemQueries.Wmi("root\\cimv2","SELECT Name,PathName,State FROM Win32_SystemDriver","Name","PathName","State");Changed(id,"Kernel driver inventory",drivers);
                return Good(id,$"{drivers.Count} system drivers inventoried",LayerMode.Monitoring,"Driver changes and enabled CodeIntegrity events; no memory rootkit scanner or kernel attestation.");
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
                foreach(var file in binaries.Concat(systemBinaries))Changed(id,"File integrity: "+file,SystemQueries.FileHash(file));
                return Good(id,$"{binaries.Length} OTS assemblies and {systemBinaries.Length} core Windows binaries have sampled SHA-256 baselines",LayerMode.Monitoring,
                    "Baselines start on first observation, are not cryptographically attested and are not persisted across service restarts. Other files and fast changes can be missed.");
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
                return Good(id,$"Microsoft Defender malware channel subscribed; keylogging-labelled detections: {Sensors.ObservedKeyloggerAlerts}",
                    LayerMode.Monitoring,"Recognized Defender detections only. Does not enumerate input hooks, record keystrokes, or detect arbitrary keyloggers; major capability remains unimplemented.");
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
}
