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
    public EventStore(string directory)
    {
        this.directory=directory; Paths.SecureDirectory(directory);
        var keyPath=Path.Combine(directory,"integrity.dpapi");
        if(File.Exists(keyPath))key=ProtectedData.Unprotect(File.ReadAllBytes(keyPath),null,DataProtectionScope.LocalMachine);
        else { key=RandomNumberGenerator.GetBytes(32); File.WriteAllBytes(keyPath,ProtectedData.Protect(key,null,DataProtectionScope.LocalMachine)); }
        // Each startup creates a fresh bounded segment; prior segments remain available to administrators.
        chain=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
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
            var data=JsonSerializer.Serialize(e,Wire.Json);
            var previous=chain;chain=Convert.ToHexString(HMACSHA256.HashData(key,Encoding.UTF8.GetBytes(previous+data)));
            var path=Path.Combine(directory,"events.jsonl");
            if(File.Exists(path)&&new FileInfo(path).Length>2*1024*1024)
            {
                var archive=Path.Combine(directory,$"events-{now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.jsonl.gz");
                using(var input=File.OpenRead(path))using(var output=File.Create(archive))using(var gz=new GZipStream(output,CompressionLevel.Fastest))input.CopyTo(gz);
                File.Delete(path);
                foreach(var old in Directory.GetFiles(directory,"*.gz").OrderByDescending(File.GetLastWriteTimeUtc).Skip(20))File.Delete(old);
            }
            File.AppendAllText(path,JsonSerializer.Serialize(new {Previous=previous,Data=data,Hmac=chain},Wire.Json)+"\n");
            Total++;if(blocked)Blocked++;recent.Enqueue(e);while(recent.Count>300)recent.Dequeue();
        }
    }
}
