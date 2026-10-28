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
    public List<Connection> Connections {get;private set;}=[];
    public string? NetworkError {get;private set;}
    public FirewallAudit? Firewall {get;}=new();
    private (bool Safe,string Description,List<FirewallAudit.Rule> Rules)? firewall;
    public LayerChecks(EventStore events){this.events=events;}
    public void Prepare()
    {
        firewall=null;NetworkError=null;
        try{Connections=NetworkTables.Connections();TrackNetwork();}catch(Exception ex){Connections=[];NetworkError=ex.Message;}
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
            case 5:return Missing(id,"No validated redistributable IP intelligence feed is bundled. No IP blocks are applied.");
            case 7:
                var model=SystemQueries.Wmi("root\\cimv2","SELECT Manufacturer,Model FROM Win32_ComputerSystem","Manufacturer","Model").FirstOrDefault();
                var vm=string.Join(" ",model?.Values??Enumerable.Empty<string>());
                return vm.Contains("Amazon",StringComparison.OrdinalIgnoreCase)||vm.Contains("Google",StringComparison.OrdinalIgnoreCase)||vm.Contains("Virtual",StringComparison.OrdinalIgnoreCase)?Bad(id,"Virtual/cloud-capable host detected; metadata access policy requires workload knowledge","No metadata endpoint requests or firewall changes are made."):Na(id,"No recognized cloud VM model; metadata enforcement is not enabled");
            case 8:return Missing(id,"DNS response interception and safe rebinding exceptions are not implemented. DNS event journaling does not provide rebinding protection.");
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
            case 31:return Missing(id,"Read-access telemetry for browser credential/session files is unavailable without additional auditing or a supported sensor. File-write watching would not satisfy this requirement.");
            case 32:return Missing(id,"Clipboard monitoring requires the interactive-user collector");
            case 33:
                Changed(id,"Machine root trust store",SystemQueries.RootCertificates());var hosts=Path.Combine(Environment.SystemDirectory,"drivers","etc","hosts");if(File.Exists(hosts))Changed(id,"Hosts file",SystemQueries.FileHash(hosts));Changed(id,"Network DNS configuration",NetworkInterface.GetAllNetworkInterfaces().Select(n=>new{n.Id,Dns=n.GetIPProperties().DnsAddresses.Select(x=>x.ToString()).ToArray()}).ToArray());
                return Good(id,"Root trust, hosts-file integrity, and interface DNS baselines monitored",LayerMode.Monitoring,"Changes are alerts, not automatically malicious. User proxy configuration requires user collector.");
            case 34:return Missing(id,"Read/copy attribution and encrypted-transfer correlation are not implemented. File-change bursts are handled separately by layer 78.");
            case 35:
                var binaries=Directory.GetFiles(AppContext.BaseDirectory,"OTS*.dll");foreach(var file in binaries)Changed(id,Path.GetFileName(file),SystemQueries.FileHash(file));
                return Good(id,$"Integrity baselines for {binaries.Length} OTS assemblies",LayerMode.Monitoring,"Baseline detects changes after first observation; authenticity and broad system-file coverage are separate requirements.");
            case 36:return Channel(id,"Security","Examines process-creation command lines where already audited; detects a narrow set of encoded PowerShell and remote script execution indicators.");
            case 37:
                var secure=SystemQueries.Reg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled");
                return secure is int v? (v==1?Good(id,"Secure Boot registry indicator is enabled",LayerMode.Auditing,"This is configuration evidence, not measured boot attestation."):Bad(id,"Secure Boot is disabled")):Missing(id,"Secure Boot state not reported by this host");
            case 38:return Missing(id,"Reliable cross-process keylogger/input-hook inspection is not implemented; no claim of keylogger protection.");
            case 39:
                Changed(id,"Trusted publisher roots",SystemQueries.RootCertificates());Changed(id,"Software source inventory",SystemQueries.InstalledSoftware());
                return Good(id,"Trust-store and installed-software changes observed",LayerMode.Auditing,"Does not validate package repository metadata or every software update source.");
            case 40:
                var container=SystemQueries.Wmi("root\\cimv2","SELECT Name,State FROM Win32_Service WHERE Name='docker' OR Name='com.docker.service' OR Name='containerd'","Name","State");
                if(container.Count==0)return Na(id,"No recognized local container service installed");
                bool exposed=Connections.Any(c=>c.State=="Listening"&&c.Local.EndsWith(":2375"));return exposed?Bad(id,"Unencrypted Docker management port 2375 is listening","Local socket observation; container filesystem permissions and publish rules are not inspected."):Good(id,"No TCP 2375 listener observed",LayerMode.Auditing,"Container inventory, Unix sockets, and per-container permissions are not inspected.");
            case 41:return Channel(id,"Security","Alerts on eight failed logins per source in two minutes; automatic source bans withheld to avoid lockout.");
            case 42:
                var config=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ssh","sshd_config");if(!File.Exists(config))return Na(id,"No OpenSSH server configuration found");
                var lines=File.ReadAllLines(config).Select(s=>s.Trim()).Where(s=>s.Length>0&&!s.StartsWith('#')).ToArray();
                bool pass=lines.Any(s=>s.Equals("PasswordAuthentication no",StringComparison.OrdinalIgnoreCase));return pass?Good(id,"Explicit PasswordAuthentication no found",LayerMode.Auditing,"Report-only; Include and Match blocks require effective-configuration review; key ACL audit incomplete."):Bad(id,"PasswordAuthentication no is not explicit","OpenSSH defaults, Include and Match can affect actual behavior; no configuration changed.");
            case 43:return new(id,LayerMode.Idle,false,"Optional password check is available in the desktop interface; no password provided","Uses SHA-1 range queries only when requested; plaintext is never uploaded.");
            case 44:
                var accounts=SystemQueries.Wmi("root\\cimv2","SELECT Name,Disabled,PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True","Name","Disabled","PasswordRequired");int weak=accounts.Count(a=>a["Disabled"]=="False"&&a["PasswordRequired"]=="False");Changed(id,"Local account state",accounts);return weak>0?Bad(id,$"{weak} enabled accounts do not require passwords", "Account policy flags do not establish actual password strength or staleness."):Good(id,$"{accounts.Count} local accounts audited",LayerMode.Auditing,"Does not inspect password contents, domain policies, or account staleness.");
            case 45:return Channel(id,"Security","Monitors login, failed login, and special-privilege assignment events.");
            case 46:
                var defender=SystemQueries.Wmi("root\\Microsoft\\Windows\\Defender","SELECT AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus","AntivirusEnabled","RealTimeProtectionEnabled","AntivirusSignatureLastUpdated").FirstOrDefault();
                var hardening=HostHardeningAudit.Read();
                if(defender==null)return Missing(id,"Microsoft Defender status is unavailable; "+hardening.Summary);
                bool active=defender["AntivirusEnabled"]=="True"&&defender["RealTimeProtectionEnabled"]=="True";
                return active?Good(id,"Defender real-time protection enabled; "+hardening.Summary,LayerMode.Auditing,"UAC, DEP, and LSA indicators are read-only partial checks; an absent/unsupported value is not reported as protected. No broad ASLR, BitLocker or patch verification."):Bad(id,"Defender real-time protection is not confirmed; "+hardening.Summary,"May reflect a different antivirus product. Existing security settings are never automatically changed.");
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
