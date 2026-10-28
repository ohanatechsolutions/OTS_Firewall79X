using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Machine DPAPI-protected, versioned 256-bit HMAC key ring.
/// A local administrator remains a trusted principal; this is at-rest protection
/// and controlled key lifecycle, not remote/off-device key escrow.</summary>
public sealed class MachineLogKeyRing
{
    private sealed record Document(int CurrentId,DateTimeOffset RotatedUtc,Dictionary<int,string> Keys);
    private static readonly byte[] Purpose=Encoding.UTF8.GetBytes("OTS.Firewall79X.LogKeyRing.v1");
    private readonly string ringPath;
    private readonly Dictionary<int,byte[]> keys=new();
    public IReadOnlyDictionary<int,byte[]> Keys=>keys;
    public int CurrentId{get;private set;}
    public byte[] CurrentKey=>keys[CurrentId];
    public DateTimeOffset RotatedUtc{get;private set;}

    private static void WriteBinaryAtomic(string path,byte[] bytes)
    {
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try
        {
            using(var stream=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough))
            { stream.Write(bytes);stream.Flush(true); }
            File.Move(temp,path,true);
        }
        finally { if(File.Exists(temp))File.Delete(temp); }
    }

    public MachineLogKeyRing(string directory)
    {
        // Caller must first establish an administrator/SYSTEM-owned ACL-controlled directory.
        ringPath=Path.Combine(directory,"keyring.dpapi");
        var legacyPath=Path.Combine(directory,"integrity.dpapi");
        byte[] original;
        if(File.Exists(legacyPath))
            original=ProtectedData.Unprotect(File.ReadAllBytes(legacyPath),null,DataProtectionScope.LocalMachine);
        else
        {
            // Missing historical key with retained logs is an integrity incident.
            // Never silently mint a replacement that cannot authenticate evidence.
            if(Directory.EnumerateFiles(directory,"events*.jsonl*").Any())
                throw new InvalidDataException("Historical integrity key missing; retained security logs preserved");
            original=RandomNumberGenerator.GetBytes(32);
            WriteBinaryAtomic(legacyPath,ProtectedData.Protect(original,null,DataProtectionScope.LocalMachine));
        }
        if(original.Length!=32)throw new InvalidDataException("Invalid legacy log key length");
        if(File.Exists(ringPath))
        {
            var bytes=ProtectedData.Unprotect(File.ReadAllBytes(ringPath),Purpose,DataProtectionScope.LocalMachine);
            Document doc;
            try {doc=JsonSerializer.Deserialize<Document>(bytes,Wire.Json)??throw new InvalidDataException("Missing keyring metadata");}
            catch(JsonException ex){throw new InvalidDataException("Malformed keyring metadata",ex);}
            if(doc.Keys is null || doc.Keys.Count is < 1 or > 64 ||
                doc.CurrentId is < 0 or > 1_000_000 || !doc.Keys.ContainsKey(doc.CurrentId) ||
                doc.RotatedUtc==default || doc.RotatedUtc>DateTimeOffset.UtcNow.AddMinutes(5))
                throw new InvalidDataException("Invalid keyring metadata");
            foreach(var item in doc.Keys)
            {
                if(item.Key is < 0 or > 1_000_000 || item.Value is null || item.Value.Length>256)
                    throw new InvalidDataException("Invalid key version");
                byte[] material;
                try {material=Convert.FromBase64String(item.Value);}
                catch(FormatException ex){throw new InvalidDataException("Malformed key material",ex);}
                if(material.Length!=32)throw new InvalidDataException("Invalid key length");
                keys.Add(item.Key,material);
            }
            if(keys.TryGetValue(0,out var initial) &&
                !CryptographicOperations.FixedTimeEquals(initial,original))
                throw new CryptographicException("Historical key material does not match legacy protected key");
            CurrentId=doc.CurrentId;RotatedUtc=doc.RotatedUtc;
        }
        else
        {
            keys.Add(0,original);CurrentId=0;RotatedUtc=DateTimeOffset.UtcNow;
            Persist(CurrentId,RotatedUtc,keys);
        }
    }

    private void Persist(int id,DateTimeOffset rotated,IReadOnlyDictionary<int,byte[]> material)
    {
        var json=JsonSerializer.SerializeToUtf8Bytes(
            new Document(id,rotated,material.ToDictionary(x=>x.Key,x=>Convert.ToBase64String(x.Value))),Wire.Json);
        try { WriteBinaryAtomic(ringPath,ProtectedData.Protect(json,Purpose,DataProtectionScope.LocalMachine)); }
        finally { CryptographicOperations.ZeroMemory(json); }
    }

    public void Rotate(DateTimeOffset now)
    {
        if(now<RotatedUtc || CurrentId>=1_000_000 || keys.Count>=64)
            throw new InvalidOperationException("Log key rotation requires operator review");
        var newId=CurrentId+1;
        var fresh=RandomNumberGenerator.GetBytes(32);
        var candidate=new Dictionary<int,byte[]>(keys){{newId,fresh}};
        try {Persist(newId,now,candidate);}
        catch {CryptographicOperations.ZeroMemory(fresh);throw;}
        keys.Add(newId,fresh);
        CurrentId=newId;RotatedUtc=now;
    }
    public bool RotateIfDue(DateTimeOffset now)
    {
        if(now-RotatedUtc<TimeSpan.FromDays(90))return false;
        Rotate(now);
        return true;
    }
}
