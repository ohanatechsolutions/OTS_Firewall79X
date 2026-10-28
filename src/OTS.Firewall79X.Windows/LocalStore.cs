using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public static class Paths
{
    public static readonly string Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Ohana Tech Solutions","Firewall79X");
    public static string At(string name)=>Path.Combine(Root,name);
    public static void SecureDirectory(string path)
    {
        var full=Path.GetFullPath(path);
        var current=new DirectoryInfo(full);
        while(current!=null){if(current.Exists&&(current.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse-point ancestor rejected for protected storage");current=current.Parent;}
        var existed=Directory.Exists(full);var dir=Directory.CreateDirectory(full);
        if((dir.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse points are not allowed for protected storage");
        if(existed)
        {
            var owner=dir.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if(owner==null||!(owner.IsWellKnown(WellKnownSidType.LocalSystemSid)||owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))throw new UnauthorizedAccessException("Protected storage has an unexpected owner; refusing to trust existing state");
            foreach(var item in dir.EnumerateFileSystemInfos())if((item.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked item rejected in protected storage");
        }
        var acl=new DirectorySecurity(); acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        dir.SetAccessControl(acl);
    }
}
public sealed class EventStore
{
    private readonly object sync=new(); private readonly Queue<SecurityEvent> recent=[];
    private readonly Dictionary<string,DateTimeOffset> last=[];
    private readonly string directory; private readonly byte[] key; private string chain="";
    public long Total {get;private set;} public long Blocked {get;private set;}
    public string? LastError {get;private set;}
    public int VerifiedRetainedEvents {get;private set;}
    public int LegacyChainGaps {get;private set;}
    private int snapshotRequested;
    public bool ConsumeSnapshotRequest()=>Interlocked.Exchange(ref snapshotRequested,0)==1;
    public EventStore(string directory)
    {
        this.directory=directory; Paths.SecureDirectory(directory);
        var keyPath=Path.Combine(directory,"integrity.dpapi");
        if(File.Exists(keyPath))key=ProtectedData.Unprotect(File.ReadAllBytes(keyPath),null,DataProtectionScope.LocalMachine);
        else { key=RandomNumberGenerator.GetBytes(32); File.WriteAllBytes(keyPath,ProtectedData.Protect(key,null,DataProtectionScope.LocalMachine)); }
        // Validate the retained on-disk history before accepting it. Older builds reset the
        // chain on each service start; those legacy gaps are disclosed, not silently trusted.
        chain=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        try
        {
            var files=Directory.GetFiles(directory,"events-*.jsonl.gz").Order(StringComparer.Ordinal).ToList();
            files.Add(Path.Combine(directory,"events.jsonl"));
            var lines=new List<string>();
            foreach(var file in files.Where(File.Exists))
            {
                if(new FileInfo(file).Length>8*1024*1024)throw new InvalidDataException("Stored log segment exceeds verification limit");
                using var raw=File.OpenRead(file);
                using Stream body=file.EndsWith(".gz",StringComparison.OrdinalIgnoreCase)?new GZipStream(raw,CompressionMode.Decompress):raw;
                using var reader=new StreamReader(body,Encoding.UTF8);
                int expanded=0;string? line;
                while((line=reader.ReadLine())!=null)
                {
                    expanded+=line.Length;
                    if(expanded>4*1024*1024)throw new InvalidDataException("Expanded log segment exceeds verification limit");
                    lines.Add(line);
                }
            }
            var verification=EventIntegrity.Verify(lines,key);
            VerifiedRetainedEvents=verification.Verified;LegacyChainGaps=verification.ChainGaps;
            if(verification.LastHmac!=null)chain=verification.LastHmac;
            // Rebuild durable counters from individually authenticated records; the dashboard
            // must not reset its historical totals every time the Windows service restarts.
            foreach(var line in lines.Where(x=>!string.IsNullOrWhiteSpace(x)))
            {
                var record=JsonSerializer.Deserialize<EventIntegrity.Record>(line,Wire.Json)
                    ?? throw new InvalidDataException("Missing verified event record");
                var evt=JsonSerializer.Deserialize<SecurityEvent>(record.Data,Wire.Json)
                    ?? throw new InvalidDataException("Missing verified security event");
                if(evt.Layer is < 0 or > 79 || evt.Time==default ||
                    evt.Severity is not ("Info" or "Warning" or "High") ||
                    evt.Kind is null || evt.Detail is null)
                    throw new InvalidDataException("Invalid retained security event schema");
                Total++;if(evt.Blocked)Blocked++;
                recent.Enqueue(evt);while(recent.Count>300)recent.Dequeue();
            }
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            LastError="Existing security log history failed integrity verification: "+Wire.Clean(ex.Message,256);
        }
    }
    public List<SecurityEvent> Recent() { lock(sync)return recent.Reverse().ToList(); }
    public void Add(int layer,string severity,string kind,string detail,bool blocked=false)
    {
        lock(sync)
        {
            var now=DateTimeOffset.UtcNow; detail=Wire.Clean(detail); string id=$"{layer}:{kind}:{detail}";
            if(last.TryGetValue(id,out var time)&&now-time<TimeSpan.FromMinutes(2))return;
            if(last.Count>4000)last.Clear(); last[id]=now;
            var e=new SecurityEvent(now,layer,severity,kind,detail,blocked);
            if(severity=="High")Interlocked.Exchange(ref snapshotRequested,1);
            Total++;if(blocked)Blocked++;recent.Enqueue(e);while(recent.Count>300)recent.Dequeue();
            // Never append to a history whose authentication or schema verification failed.
            // Preserve tampered evidence on disk for investigation; new events remain in RAM.
            if(LastError!=null)return;
            try
            {
            var data=JsonSerializer.Serialize(e,Wire.Json);
            var previous=chain;var next=Convert.ToHexString(HMACSHA256.HashData(key,Encoding.UTF8.GetBytes(previous+data)));
            var path=Path.Combine(directory,"events.jsonl");
            if(File.Exists(path)&&new FileInfo(path).Length>2*1024*1024)
            {
                var archive=Path.Combine(directory,$"events-{now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.jsonl.gz");
                using(var input=File.OpenRead(path))using(var output=File.Create(archive))using(var gz=new GZipStream(output,CompressionLevel.Fastest))input.CopyTo(gz);
                File.Delete(path);
                foreach(var old in Directory.GetFiles(directory,"*.gz").OrderByDescending(File.GetLastWriteTimeUtc).Skip(20))File.Delete(old);
            }
            File.AppendAllText(path,JsonSerializer.Serialize(new {Previous=previous,Data=data,Hmac=next},Wire.Json)+"\n");
            chain=next;VerifiedRetainedEvents++;
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){LastError=Wire.Clean(ex.Message);}
        }
    }
}
