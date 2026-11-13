using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Xml.Linq;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class EventSensors : IDisposable
{
    private readonly List<EventLogWatcher> watchers=[];private readonly EventStore events;
    private readonly object sync=new();private readonly Dictionary<string,Queue<(DateTimeOffset Time,int Port)>> attempts=[];
    private readonly AuthenticationFailureMonitor authenticationFailures=new();
    private readonly AuditedFileAccess access=new();
    private readonly DnsRebindingDetector dnsRebinding=new();
    public MaliciousDomainFeed? Domains {get;set;}
    public DeceptionMonitor? Deception { get; set; }
    private readonly TemporaryFirewallGuard? networkGuard;
    private int remoteFailedLoginEvents,loginSecurityEvents,privilegeSecurityEvents;
    public int ObservedPrivilegeSecurityEvents=>Volatile.Read(ref privilegeSecurityEvents);
    public int ObservedRemoteLogonFailures=>Volatile.Read(ref remoteFailedLoginEvents);
    public int ObservedLoginSecurityEvents=>Volatile.Read(ref loginSecurityEvents);
    private int parsedDnsResponses;
    private int networkProtectionDetections;
    public int NetworkProtectionDetections=>Volatile.Read(ref networkProtectionDetections);
    public int ObservedDnsResponses=>Volatile.Read(ref parsedDnsResponses);
    private int fileReadEvents, browserFileEvents, keyloggerAlerts;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int,DateTimeOffset> recentBulk=new();
    public int ObservedKeyloggerAlerts=>Volatile.Read(ref keyloggerAlerts);
    public IReadOnlyList<int> RecentBulkReadPids
    {
        get
        {
            var cutoff=DateTimeOffset.UtcNow.AddMinutes(-2);
            foreach(var entry in recentBulk)
                if(entry.Value<cutoff)recentBulk.TryRemove(entry.Key,out _);
            return recentBulk.Keys.Take(256).ToArray();
        }
    }
    public int ObservedAuditedFileReads=>Volatile.Read(ref fileReadEvents);
    public int ObservedAuditedBrowserFileReads=>Volatile.Read(ref browserFileEvents);
    public System.Collections.Concurrent.ConcurrentDictionary<string,string> Health {get;}=new();
    public EventSensors(EventStore events,TemporaryFirewallGuard? networkGuard=null){this.events=events;this.networkGuard=networkGuard;}
    public const string SecurityEventQuery="*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4740 or EventID=4778 or EventID=4779 or EventID=4800 or EventID=4801 or EventID=4672 or EventID=4673 or EventID=4674 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 or EventID=4728 or EventID=4732 or EventID=4735 or EventID=4737 or EventID=4738 or EventID=4756 or EventID=4719 or EventID=1102 or EventID=5157 or EventID=4688 or EventID=4616 or EventID=4663)]]";
    public void Start()
    {
        Watch("Security",SecurityEventQuery);
        Watch("System","*[System[(EventID=7045 or EventID=7040 or EventID=7036 or EventID=219)]]");
        Watch("Microsoft-Windows-TaskScheduler/Operational","*[System[(EventID=106 or EventID=140 or EventID=141)]]");
        Watch("Microsoft-Windows-WMI-Activity/Operational","*[System[(EventID=5857 or EventID=5858 or EventID=5860 or EventID=5861)]]");
        Watch("Microsoft-Windows-Windows Defender/Operational","*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=1125 or EventID=1126)]]");
        Watch("Microsoft-Windows-CodeIntegrity/Operational","*[System[(Level=2 or Level=3)]]");
        Watch("Microsoft-Windows-PowerShell/Operational","*[System[(EventID=4104)]]");
        Watch("Microsoft-Windows-DNS-Client/Operational","*[System[(EventID=3006 or EventID=3008)]]");
    }
    private void Watch(string channel,string query)
    {
        try
        {
            using var config=new EventLogConfiguration(channel);
            if(!config.IsEnabled){Health[channel]="Channel disabled; no auditing policy changed";return;}
            var watcher=new EventLogWatcher(new EventLogQuery(channel,PathType.LogName,query));
            watcher.EventRecordWritten+=(_,args)=>
            {
                if(args.EventException!=null){lock(sync)Health[channel]=args.EventException.Message;events.Add(30,"Warning","Event channel failure",$"{channel}: {args.EventException.Message}");return;}
                if(args.EventRecord==null)return;
                using var record=args.EventRecord;
                try{Process(channel,record);}catch(Exception ex){events.Add(56,"Warning","Event rejected",ex.Message);}
            };
            watcher.Enabled=true;watchers.Add(watcher);Health[channel]="Subscribed; source policy and event availability determine coverage";
        }
        catch(Exception ex){Health[channel]=ex.Message;}
    }
    private void Process(string channel,EventRecord record)
    {
        var xml=record.ToXml();if(xml.Length>256*1024)throw new InvalidDataException("Event too large");
        using var reader=XmlReader.Create(new StringReader(xml),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=256*1024});
        var doc=XDocument.Load(reader);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        var fields=doc.Descendants(ns+"Data").GroupBy(x=>(string?)x.Attribute("Name")??"").ToDictionary(g=>g.Key,g=>g.First().Value);
        string Get(string key)=>fields.GetValueOrDefault(key,"");var now=DateTimeOffset.UtcNow;
        if(channel=="Security")
        {
            switch(record.Id)
            {
                case 4624:
                {
                    var type=Get("LogonType");
                    if(type is "2" or "3" or "7" or "9" or "10" or "11")
                    {
                        var kind=type switch {"2"=>"Interactive","3"=>"Network","7"=>"Unlock","9"=>"New credentials","10"=>"Remote interactive (RDP)","11"=>"Cached interactive",_=>"Unknown"};
                        var account=Wire.Clean(Get("TargetUserName"),64);
                        events.Add(45,type=="10"?"Warning":"Info",kind+" logon",
                            $"Account={account}; remote={Wire.Clean(Get("IpAddress"),64)}; Windows Security event 4624.");
                        Interlocked.Increment(ref loginSecurityEvents);
                        if(type=="10")events.Add(15,"Info","Remote-interactive access technique hypothesis",
                            TrafficRules.MitreTechnique("remote-rdp-logon")!+"; classify only a verified Windows 4624 logon type 10.");
                    }
                    break;
                }
                case 4625:
                {
                    var type=Get("LogonType");
                    events.Add(45,"Warning","Failed authentication",
                        $"Type={Wire.Clean(type,8)}; source={Wire.Clean(Get("IpAddress"),64)}; status={Wire.Clean(Get("Status"),20)}; Windows event 4625.");
                    Interlocked.Increment(ref loginSecurityEvents);
                    lock(sync)
                    {
                        var failure=authenticationFailures.Observe(Get("IpAddress"),type,now,Get("SubStatus"),Get("TargetUserName"));
                        if(failure.ValidRemoteSource)
                        {
                            Interlocked.Increment(ref remoteFailedLoginEvents);
                            if(failure.Alert)
                            {
                                events.Add(41,"High","Repeated remote authentication failures",
                                    $"{failure.Count} observed network/remote-interactive failures from {failure.Source} within two minutes; an alert is not proof of an attack.");
                                events.Add(15,"Warning","Authentication attack-pattern hypothesis",
                                    $"{failure.Count} verified remote failures; {TrafficRules.MitreTechnique("repeated-logon-failures")}. Authentication attempts are not proof of compromise.");
                            }
                            // A distinct 32-failure restriction threshold can be reached
                            // during the separate five-minute 8-failure alert cooldown.
                            // Never gate opt-in RDP protection on alert notification timing.
                            if(failure.RestrictionCandidate)
                                networkGuard?.ObserveAuthenticationAttack(failure.Source,now);
                        }
                    }
                    break;
                }
                case 4634:case 4647:case 4778:case 4779:case 4800:case 4801:
                    events.Add(45,"Info","Session state changed",
                        $"Windows Security event {record.Id}; session transitions are not new authentication.");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4740:
                    events.Add(45,"Warning","Account lockout recorded",
                        "Windows Security event 4740; review native Windows logs for the affected account and cause.");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4648:
                    events.Add(45,"Warning","Explicit credentials used",
                        $"Windows event 4648; calling account {Wire.Clean(Get("SubjectUserName"),64)}. No credentials collected.");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4672:case 4673:case 4674:case 4720:case 4722:case 4724:case 4726:
                case 4728:case 4732:case 4735:case 4737:case 4738:case 4756:case 4719:case 1102:
                {
                    var privileged=record.Id is 4672 or 4673 or 4674;
                    var description=record.Id==4672?"Special privileges assigned at logon":
                        privileged?"Sensitive privilege operation audited":"Account, group or security policy changed";
                    var detail=$"Security event {record.Id}; target {Wire.Clean(Get("TargetUserName"),80)}; verify authorization in native Windows logs.";
                    events.Add(27,privileged?"Info":"Warning",description,detail);
                    events.Add(45,privileged?"Info":"Warning",description,detail);
                    Interlocked.Increment(ref privilegeSecurityEvents);
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                }
                case 4616:events.Add(24,"Warning","System time changed",$"Previous {Get("PreviousTime")}; new {Get("NewTime")}");break;
                case 4663:
                    Deception?.ObserveFileAudit(Get("ObjectType"), Get("ObjectName"), Get("AccessMask"), Get("ProcessName"), Get("ProcessId"), Get("SubjectUserName"));
                    AuditedFileAccess.Finding found;
                    lock(sync)found=access.Observe(Get("ObjectType"),Get("ObjectName"),Get("ProcessName"),Get("AccessMask"),now);
                    if(found.AuditedRead)Interlocked.Increment(ref fileReadEvents);
                    if(found.BrowserCredentialRead)Interlocked.Increment(ref browserFileEvents);
                    if(found.UnexpectedCredentialReader)
                        events.Add(31,"Warning","Audited browser credential file access",
                            $"An unexpected process ({Wire.Clean(Path.GetFileName(Get("ProcessName")),64)}) read a browser credential/session file; check the Windows Security log. No secrets were collected.");
                    if(found.BulkRead)
                    {
                        var pid=EndpointSignals.AuditProcessId(Get("ProcessId"));
                        if(pid is int valid)
                        {
                            if(recentBulk.Count>256)recentBulk.Clear();
                            recentBulk[valid]=now;
                        }
                        events.Add(34,"Warning","Bulk audited file-read indicator",
                            $"{found.DistinctFiles} distinct files accessed by one process within one minute; backups and indexing can be legitimate. Copy/exfiltration has not been proven.");
                    }
                    break;
                case 4688:
                {
                    var indicator=Detections.ExecutionIndicator(Get("NewProcessName"),Get("CommandLine"),Get("ParentProcessName"));
                    if(indicator!=null)
                    {
                        events.Add(36,"Warning","Suspicious execution indicator",indicator);
                        var commandProcess=Path.GetFileName(Get("NewProcessName"));
                        if(string.Equals(commandProcess,"powershell.exe",StringComparison.OrdinalIgnoreCase)||
                           string.Equals(commandProcess,"pwsh.exe",StringComparison.OrdinalIgnoreCase))
                            events.Add(15,"Warning","Script-execution technique hypothesis",
                                TrafficRules.MitreTechnique("script-powershell")!+"; evidence is a Windows process-creation audit.");
                    }
                    if(Get("TokenElevationType")=="%%1937")
                    {
                        events.Add(45,"Info","Elevated process token observed",
                            $"Windows Security event 4688; executable {Wire.Clean(Path.GetFileName(Get("NewProcessName")),80)}; process elevation is not necessarily malicious.");
                        Interlocked.Increment(ref privilegeSecurityEvents);
                    }
                    break;
                }
                case 5157:
                {
                    // WFP 5157 SourceAddress/SourcePort are LOCAL; DestAddress/DestPort are REMOTE.
                    // Apply restrictions only on validated inbound TCP metadata.
                    if(!BlockedConnectionEvent.TryParseInboundTcp(
                        Get("Direction"),Get("SourceAddress"),Get("SourcePort"),
                        Get("DestAddress"),Get("DestPort"),Get("Protocol"),out var blocked) || blocked==null)
                        break;
                    var address=blocked.RemoteAddress;
                    var port=blocked.LocalPort;
                    networkGuard?.ObserveBlocked(address,Get("Direction"),port,now);
                    lock(sync)
                    {
                        if(attempts.Count>4096)attempts.Clear();
                        if(!attempts.TryGetValue(address,out var q))attempts[address]=q=new();
                        q.Enqueue((now,port));
                        while(q.Count>0&&(q.Peek().Time<now.AddMinutes(-1)||q.Count>1000))q.Dequeue();
                        if(Detections.Scan(q.Select(x=>x.Port)))
                            events.Add(3,"High","Possible inbound TCP port scan",
                                $"Remote {address} reached {q.Select(x=>x.Port).Distinct().Count()} distinct local ports in 60 seconds; Windows had already blocked each attempt.");
                        if(q.Count>=100)events.Add(2,"Warning","High already-blocked inbound TCP rate",
                            $"Remote {address}: {q.Count} blocked attempts in 60 seconds; no volumetric flood mitigation is claimed.");
                    }
                    break;
                }
            }
        }
        else if(channel.Contains("Windows Defender"))
        {
            if(record.Id is 1125 or 1126)
            {
                Interlocked.Increment(ref networkProtectionDetections);
                events.Add(14,record.Id==1126?"High":"Warning",
                    record.Id==1126?"Defender Network Protection blocked a connection":"Defender Network Protection audit detection",
                    $"Windows Defender Operational event {record.Id}; Windows-owned threat detection (not OTS IDS enforcement). Consult the original event for target and rule details.");
            }
            events.Add(76,record.Id==1116?"High":"Info","Microsoft Defender event",
                $"Event {record.Id}; consult Windows Security Protection History for detection and remediation details");
            if(record.Id==1116&&EndpointSignals.DefenderKeyloggerIndicator(Get("Threat Name")+" "+Get("ThreatName")))
            {
                Interlocked.Increment(ref keyloggerAlerts);
                events.Add(38,"High","Defender keylogging-related detection",
                    "A genuine Defender malware event included a keylogging indicator; review Windows Security. OTS did not inspect hooks or keystrokes.");
            }
        }
        else if(channel.Contains("CodeIntegrity"))events.Add(26,"High","Code-integrity warning",$"Windows code-integrity event {record.Id}");
        else if(channel.Contains("PowerShell")){var text=Get("ScriptBlockText");var indicator=Detections.ExecutionIndicator("powershell.exe",text);if(indicator!=null)events.Add(36,"Warning","PowerShell indicator",indicator);}
        else if(channel.Contains("TaskScheduler"))
            events.Add(25,"Warning","Native Task Scheduler event",
                $"Windows event {record.Id}; task {Wire.Clean(Get("TaskName"),128)}. Execution alone does not establish persistence.");
        else if(channel.Contains("WMI-Activity"))
            events.Add(36,"Info","Native WMI activity",
                $"Windows event {record.Id}; inspect the original WMI Activity event for client process and operation.");
        else if(channel.Contains("DNS-Client"))
        {
            Deception?.ObserveDnsQuery(Get("QueryName"));
            if(record.Id != 3008) return;
            DnsRebindingDetector.Finding finding;
            lock(sync)finding=dnsRebinding.Observe(Get("QueryName"),Get("QueryResults"),Get("QueryStatus"),now);
            if(finding.ParsedAddressAnswer)Interlocked.Increment(ref parsedDnsResponses);
            if(finding.SuspiciousTransition)
                events.Add(8,"Warning","Possible DNS rebinding pattern",
                    $"A publicly resolved DNS name subsequently returned a non-public/special-use address: {Wire.Clean(Get("QueryName"),128)}. Split-horizon DNS and VPN changes may be legitimate. No DNS block applied.");
            if(finding.ParsedAddressAnswer && Get("QueryStatus")=="0" && Domains?.IsListed(Get("QueryName"))==true)
                events.Add(75,"High","Listed malicious-domain DNS lookup",$"Windows DNS event observed an exact current feed hostname: {Wire.Clean(Get("QueryName"),128)}. Source is a public unsigned mirror; verify context.");
            var attributedPid=Get("ClientPID");
            if(string.IsNullOrEmpty(attributedPid))attributedPid=Get("ClientProcessId");
            string attribution=int.TryParse(attributedPid,out int clientPid)&&clientPid>0
                ?$"provider-reported client PID {clientPid} (unverified)"
                :"no trustworthy initiating-process attribution";
            events.Add(16,"Info","DNS observation",
                $"{Wire.Clean(Get("QueryName"),160)} status={Wire.Clean(Get("QueryStatus"),16)}; {attribution}");
        }
        else if(channel=="System")
        {
            if(record.Id is 7045 or 7040)
                events.Add(25,"Warning","Service installation or configuration changed",
                    $"Windows System event {record.Id}; service {Wire.Clean(Get("ServiceName"),100)}");
            else if(record.Id==219)
                events.Add(26,"Warning","Windows driver loading warning",
                    "System event 219: review the native Kernel-PnP driver event for details.");
            // Event 7036 is routine service start/stop, not a configuration change.
        }
    }
    public bool Has(string channel){lock(sync)return Health.GetValueOrDefault(channel,"").StartsWith("Subscribed");}
    public void Dispose(){foreach(var watcher in watchers)watcher.Dispose();watchers.Clear();}
}
