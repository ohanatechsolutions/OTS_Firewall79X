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
    private readonly TemporaryFirewallGuard? networkGuard;
    private int remoteFailedLoginEvents,loginSecurityEvents;
    public int ObservedRemoteLogonFailures=>Volatile.Read(ref remoteFailedLoginEvents);
    public int ObservedLoginSecurityEvents=>Volatile.Read(ref loginSecurityEvents);
    private int parsedDnsResponses;
    public int ObservedDnsResponses=>Volatile.Read(ref parsedDnsResponses);
    private int fileReadEvents, browserFileEvents;
    public int ObservedAuditedFileReads=>Volatile.Read(ref fileReadEvents);
    public int ObservedAuditedBrowserFileReads=>Volatile.Read(ref browserFileEvents);
    public System.Collections.Concurrent.ConcurrentDictionary<string,string> Health {get;}=new();
    public EventSensors(EventStore events,TemporaryFirewallGuard? networkGuard=null){this.events=events;this.networkGuard=networkGuard;}
    public void Start()
    {
        Watch("Security","*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or (EventID>=4720 and EventID<=4767) or EventID=4719 or EventID=5157 or EventID=4688 or EventID=4616 or EventID=4663)]]");
        Watch("System","*[System[(EventID=7045 or EventID=7040)]]");
        Watch("Microsoft-Windows-Windows Defender/Operational","*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007)]]");
        Watch("Microsoft-Windows-CodeIntegrity/Operational","*[System[(Level=2 or Level=3)]]");
        Watch("Microsoft-Windows-PowerShell/Operational","*[System[(EventID=4104)]]");
        Watch("Microsoft-Windows-DNS-Client/Operational","*[System[(EventID=3008)]]");
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
                    if(type is "2" or "3" or "7" or "10" or "11")
                    {
                        var kind=type switch {"2"=>"Interactive","3"=>"Network","7"=>"Unlock","10"=>"Remote interactive (RDP)","11"=>"Cached interactive",_=>"Unknown"};
                        var account=Wire.Clean(Get("TargetUserName"),64);
                        events.Add(45,type=="10"?"Warning":"Info",kind+" logon",
                            $"Account={account}; remote={Wire.Clean(Get("IpAddress"),64)}; Windows Security event 4624.");
                        Interlocked.Increment(ref loginSecurityEvents);
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
                        var failure=authenticationFailures.Observe(Get("IpAddress"),type,now);
                        if(failure.ValidRemoteSource)
                        {
                            Interlocked.Increment(ref remoteFailedLoginEvents);
                            if(failure.Alert)
                                events.Add(41,"High","Repeated remote authentication failures",
                                    $"{failure.Count} observed network/remote-interactive failures from {failure.Source} within two minutes; suspicious but no IP ban or account lockout was applied.");
                        }
                    }
                    break;
                }
                case 4648:
                    events.Add(45,"Warning","Explicit credentials used",
                        $"Windows event 4648; calling account {Wire.Clean(Get("SubjectUserName"),64)}. No credentials collected.");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4672:
                    events.Add(45,"Warning","Special privileges assigned to logon",
                        $"Windows event 4672; account {Wire.Clean(Get("SubjectUserName"),64)}. Assignment does not necessarily mean an administrator elevated an app.");
                    events.Add(27,"Warning","Special privilege logon","Windows event 4672");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4720:case 4722:case 4723:case 4724:case 4725:case 4726:
                case 4728:case 4729:case 4732:case 4733:case 4738:case 4740:
                case 4756:case 4767:
                    events.Add(44,"Warning","Account or privileged group changed",
                        $"Windows event {record.Id}; target {Wire.Clean(Get("TargetUserName"),64)}. Review the Security event for the actor and effective permissions.");
                    events.Add(27,"Warning","Account security event",$"Windows event {record.Id}");
                    Interlocked.Increment(ref loginSecurityEvents);
                    break;
                case 4719:
                    events.Add(27,"High","Security audit policy modified","Windows event 4719; audit reliability may have changed");
                    events.Add(45,"Warning","Authentication audit policy modified","Recheck logon and account change event coverage");
                    break;
                case 4616:events.Add(24,"Warning","System time changed",$"Previous {Get("PreviousTime")}; new {Get("NewTime")}");break;
                case 4663:
                    AuditedFileAccess.Finding found;
                    lock(sync)found=access.Observe(Get("ObjectType"),Get("ObjectName"),Get("ProcessName"),Get("AccessMask"),now);
                    if(found.AuditedRead)Interlocked.Increment(ref fileReadEvents);
                    if(found.BrowserCredentialRead)Interlocked.Increment(ref browserFileEvents);
                    if(found.UnexpectedCredentialReader)
                        events.Add(31,"Warning","Audited browser credential file access",
                            $"An unexpected process ({Wire.Clean(Path.GetFileName(Get("ProcessName")),64)}) read a browser credential/session file; check the Windows Security log. No secrets were collected.");
                    if(found.BulkRead)
                        events.Add(34,"Warning","Bulk audited file-read indicator",
                            $"{found.DistinctFiles} distinct files accessed by one process within one minute; backups and indexing can be legitimate. Copy/exfiltration has not been proven.");
                    break;
                case 4688:
                {
                    var indicator=Detections.ExecutionIndicator(Get("NewProcessName"),Get("CommandLine"));
                    if(indicator!=null)events.Add(36,"Warning","Suspicious execution indicator",indicator);
                    if(Get("TokenElevationType")=="%%1937")
                    {
                        events.Add(45,"Info","Elevated process token observed",
                            $"Windows event 4688; executable {Wire.Clean(Path.GetFileName(Get("NewProcessName")),80)}; full token reported. This alone is not proof of abuse.");
                        Interlocked.Increment(ref loginSecurityEvents);
                    }
                    break;
                }
                case 5157:
                    var address=Get("SourceAddress");int.TryParse(Get("DestPort"),out var port);
                    networkGuard?.ObserveBlocked(address,Get("Direction"),port,now);
                    events.Add(15,"Info","Windows blocked connection",$"Source {address}; destination port {port}. OS block observed; not attributed to OTS enforcement.");
                    lock(sync){if(attempts.Count>4096)attempts.Clear();if(!attempts.TryGetValue(address,out var q))attempts[address]=q=new();q.Enqueue((now,port));while(q.Count>0&&(q.Peek().Time<now.AddMinutes(-1)||q.Count>1000))q.Dequeue();if(Detections.Scan(q.Select(x=>x.Port)))events.Add(3,"High","Possible port scan",$"Source {address}; distinct blocked destination ports within 60 seconds");if(q.Count>=100)events.Add(2,"High","High blocked-connection rate",$"Source {address}; {q.Count} blocked connection events in 60 seconds");}break;
            }
        }
        else if(channel.Contains("Windows Defender"))events.Add(76,record.Id==1116?"High":"Info","Microsoft Defender event",$"Event {record.Id}; consult Windows Security Protection History for detection and remediation details");
        else if(channel.Contains("CodeIntegrity"))events.Add(26,"High","Code-integrity warning",$"Windows code-integrity event {record.Id}");
        else if(channel.Contains("PowerShell")){var text=Get("ScriptBlockText");var indicator=Detections.ExecutionIndicator("powershell.exe",text);if(indicator!=null)events.Add(36,"Warning","PowerShell indicator",indicator);}
        else if(channel.Contains("DNS-Client"))
        {
            DnsRebindingDetector.Finding finding;
            lock(sync)finding=dnsRebinding.Observe(Get("QueryName"),Get("QueryResults"),Get("QueryStatus"),now);
            if(finding.ParsedAddressAnswer)Interlocked.Increment(ref parsedDnsResponses);
            if(finding.SuspiciousTransition)
                events.Add(8,"Warning","Possible DNS rebinding pattern",
                    $"A publicly resolved DNS name subsequently returned a local/private address: {Wire.Clean(Get("QueryName"),128)}. Split-horizon DNS and VPN changes may be legitimate. No DNS block applied.");
            events.Add(16,"Info","DNS observation",$"{Get("QueryName")} {Get("QueryStatus")}");
        }
        else events.Add(25,"Warning","Service configuration changed",$"Windows event {record.Id}; service {Get("ServiceName")}");
    }
    public bool Has(string channel){lock(sync)return Health.GetValueOrDefault(channel,"").StartsWith("Subscribed");}
    public void Dispose(){foreach(var watcher in watchers)watcher.Dispose();watchers.Clear();}
}
