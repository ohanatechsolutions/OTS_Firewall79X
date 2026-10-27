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
        var dir=Directory.CreateDirectory(path);
        if((dir.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse points are not allowed for protected storage");
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
public static class SecureArchive
{
    // File format: OTS1 | salt(16) | nonce(12) | tag(16) | ciphertext. AES-GCM with PBKDF2-SHA256.
    public static void Encrypt(string destination,byte[] payload,string password)
    {
        if(password.Length<12)throw new ArgumentException("Use at least 12 characters");
        if(payload.Length>64*1024*1024)throw new ArgumentException("Archive too large");
        byte[] salt=RandomNumberGenerator.GetBytes(16),nonce=RandomNumberGenerator.GetBytes(12),tag=new byte[16],cipher=new byte[payload.Length];
        var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,payload,cipher,tag,"OTS1"u8);using var f=File.Create(destination);f.Write("OTS1"u8);f.Write(salt);f.Write(nonce);f.Write(tag);f.Write(cipher);f.Flush(true);}finally{CryptographicOperations.ZeroMemory(key);}
    }
    public static byte[] Decrypt(string path,string password)
    {
        var info=new FileInfo(path);if(info.Length<48||info.Length>64*1024*1024+48)throw new InvalidDataException("Invalid archive size");
        var b=File.ReadAllBytes(path);if(!b.AsSpan(0,4).SequenceEqual("OTS1"u8))throw new InvalidDataException("Invalid archive header");
        var key=Rfc2898DeriveBytes.Pbkdf2(password,b.AsSpan(4,16),600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);var plain=new byte[b.Length-48];aes.Decrypt(b.AsSpan(20,12),b.AsSpan(48),b.AsSpan(32,16),plain,"OTS1"u8);return plain;}finally{CryptographicOperations.ZeroMemory(key);}
    }
}
