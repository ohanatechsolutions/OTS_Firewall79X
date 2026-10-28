using System.Text.Json;
namespace OTS.Firewall79X.Core;

public interface ISettingStore { string? Read(string key); void Write(string key, string? value); }
public sealed record Change(string Key, string? Before, string? Applied, string State);
public sealed class ChangeJournal
{
    private readonly string path; private readonly ISettingStore store;
    private List<Change> entries;
    public ChangeJournal(string path, ISettingStore store)
    {
        this.path=path; this.store=store;
        if(File.Exists(path)&&new FileInfo(path).Length>1024*1024)throw new InvalidDataException("Journal file exceeds size budget");
        entries = File.Exists(path) ? JsonSerializer.Deserialize<List<Change>>(File.ReadAllText(path), Wire.Json) ?? throw new InvalidDataException("Invalid journal") : [];
        if(entries.Count>1024||entries.Any(e=>string.IsNullOrEmpty(e.Key)||e.Key.Length>256||e.State is not ("prepared" or "applied" or "restored" or "conflict-preserved")))throw new InvalidDataException("Journal exceeds limits or contains invalid states");
    }
    public IReadOnlyList<Change> Entries => entries;
    public void Apply(string key, string? value)
    {
        if(string.IsNullOrEmpty(key)||key.Length>256||value?.Length>4096)throw new ArgumentException("Setting exceeds limits");
        if(entries.Count(e=>e.State is "prepared" or "applied")>=768)throw new InvalidOperationException("Active transaction budget exceeded");
        if(entries.Any(e=>e.Key==key && e.State is "prepared" or "applied")) throw new InvalidOperationException("Setting already owned");
        var before=store.Read(key); if(before==value)return;
        entries.Add(new(key,before,value,"prepared")); Save(); // durable intent before system mutation
        store.Write(key,value);
        if(store.Read(key)!=value) throw new IOException("Setting did not persist");
        entries[^1]=entries[^1] with { State="applied" }; Save();
    }
    public List<string> Restore()
    {
        List<string> conflicts=[];
        for(int i=entries.Count-1;i>=0;i--)
        {
            var e=entries[i]; if(e.State is not ("prepared" or "applied"))continue;
            var current=store.Read(e.Key);
            if(current==e.Applied) { store.Write(e.Key,e.Before); if(store.Read(e.Key)!=e.Before)throw new IOException("Restore verification failed"); entries[i]=e with { State="restored" }; }
            else if(current==e.Before) entries[i]=e with { State="restored" };
            else { conflicts.Add(e.Key); entries[i]=e with { State="conflict-preserved" }; }
            Save();
        }
        return conflicts;
    }
    private void Save()
    {
        int cutoff=entries.Count-256;
        entries=entries.Where((e,index)=>index>=cutoff||e.State is "prepared" or "applied").ToList();
        AtomicFile.Write(path,JsonSerializer.Serialize(entries,Wire.Json));
    }
}
public static class AtomicFile
{
    public static void Write(string path,string contents)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try { using(var fs=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)) { var data=System.Text.Encoding.UTF8.GetBytes(contents);fs.Write(data);fs.Flush(true); } File.Move(temp,path,true); }
        finally { if(File.Exists(temp))File.Delete(temp); }
    }
}
