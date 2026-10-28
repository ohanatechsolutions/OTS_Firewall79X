using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Xml.Linq;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class EventSensors : IDisposable
{
    private readonly List<EventLogWatcher> watchers=[];private readonly EventStore events;
    private readonly object sync=new();private readonly Dictionary<string,Queue<(DateTimeOffset Time,int Port)>> attempts=[];
    private readonly Dictionary<string,Queue<DateTimeOffset>> failures=[];
    private readonly AuditedFileAccess access=new();
    private int fileReadEvents, browserFileEvents;
    public int ObservedAuditedFileReads=>Volatile.Read(ref fileReadEvents);
    public int ObservedAuditedBrowserFileReads=>Volatile.Read(ref browserFileEvents);
    public System.Collections.Concurrent.ConcurrentDictionary<string,string> Health {get;}=new();
    public EventSensors(EventStore events){this.events=events;}
    public void Start()
    {
        Watch("Security","*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4719 or EventID=5157 or EventID=4688 or EventID=4616 or EventID=4663)]]");
        Watch("System","*[System[(EventID=7045 or EventID=7040)]]");
        Watch("Microsoft-Windows-Windows Defender/Operational","*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007)]]");
        Watch("Microsoft-Windows-CodeIntegrity/Operational","*[System[(Level=2 or Level=3)]]");
        Watch("Microsoft-Windows-PowerShell/Operational","*[System[(EventID=4104)]]");
        Watch("Microsoft-Windows-DNS-Client/Operational","*");
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
                case 4624:events.Add(45,"Info","Login",$"Type {Get("LogonType")}; source {Get("IpAddress")}");break;
                case 4625:
                    events.Add(45,"Warning","Failed login",$"Source {Get("IpAddress")}; status {Get("Status")}");
                    lock(sync){var ip=Get("IpAddress");if(failures.Count>4096)failures.Clear();if(!failures.TryGetValue(ip,out var q))failures[ip]=q=new();q.Enqueue(now);while(q.Count>0&&q.Peek()<now.AddMinutes(-2))q.Dequeue();if(q.Count>=8)events.Add(41,"High","Repeated failed authentication",$"{q.Count} failures from {ip} within 2 minutes; no automatic ban");}break;
                case 4672:case 4720:case 4728:case 4732:case 4719:events.Add(27,"Warning","Account or privilege event",$"Security event {record.Id}; review Windows Security log for account details");break;
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
                case 4688:var indicator=Detections.ExecutionIndicator(Get("NewProcessName"),Get("CommandLine"));if(indicator!=null)events.Add(36,"Warning","Suspicious execution indicator",indicator);break;
                case 5157:
                    var address=Get("SourceAddress");int.TryParse(Get("DestPort"),out var port);
                    events.Add(15,"Info","Windows blocked connection",$"Source {address}; destination port {port}. OS block observed; not attributed to OTS enforcement.");
                    lock(sync){if(attempts.Count>4096)attempts.Clear();if(!attempts.TryGetValue(address,out var q))attempts[address]=q=new();q.Enqueue((now,port));while(q.Count>0&&(q.Peek().Time<now.AddMinutes(-1)||q.Count>1000))q.Dequeue();if(Detections.Scan(q.Select(x=>x.Port)))events.Add(3,"High","Possible port scan",$"Source {address}; distinct blocked destination ports within 60 seconds");if(q.Count>=100)events.Add(2,"High","High blocked-connection rate",$"Source {address}; {q.Count} blocked connection events in 60 seconds");}break;
            }
        }
        else if(channel.Contains("Windows Defender"))events.Add(76,record.Id==1116?"High":"Info","Microsoft Defender event",$"Event {record.Id}; consult Windows Security Protection History for detection and remediation details");
        else if(channel.Contains("CodeIntegrity"))events.Add(26,"High","Code-integrity warning",$"Windows code-integrity event {record.Id}");
        else if(channel.Contains("PowerShell")){var text=Get("ScriptBlockText");var indicator=Detections.ExecutionIndicator("powershell.exe",text);if(indicator!=null)events.Add(36,"Warning","PowerShell indicator",indicator);}
        else if(channel.Contains("DNS-Client"))events.Add(16,"Info","DNS observation",$"{Get("QueryName")} {Get("QueryStatus")}");
        else events.Add(25,"Warning","Service configuration changed",$"Windows event {record.Id}; service {Get("ServiceName")}");
    }
    public bool Has(string channel){lock(sync)return Health.GetValueOrDefault(channel,"").StartsWith("Subscribed");}
    public void Dispose(){foreach(var watcher in watchers)watcher.Dispose();watchers.Clear();}
}
