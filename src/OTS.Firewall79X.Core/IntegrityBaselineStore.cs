using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Bounded, local, restart-persistent observations of selected binary hashes.
/// Stored under the service's protected ProgramData directory. An observed baseline
/// is not a trusted vendor signature or an immutable remote attestation.
/// </summary>
public sealed class IntegrityBaselineStore
{
    private sealed record State(int Schema, Dictionary<string,string> Checks);
    public enum ChangeKind { FirstObservation, Unchanged, Changed }
    private readonly string path;
    private readonly Dictionary<string,string> observations=new(StringComparer.OrdinalIgnoreCase);
    public int Count=>observations.Count;

    public IntegrityBaselineStore(string file)
    {
        path=Path.GetFullPath(file);
        var parent=Path.GetDirectoryName(path)??throw new InvalidDataException("Invalid baseline path");
        if(!Directory.Exists(parent))throw new DirectoryNotFoundException(parent);
        for(var dir=new DirectoryInfo(parent);dir!=null;dir=dir.Parent)
            if(dir.Exists&&(dir.Attributes&FileAttributes.ReparsePoint)!=0)
                throw new InvalidDataException("Linked baseline parent directory");
        if(Directory.Exists(path))throw new InvalidDataException("Baseline state path is a directory");
        if(!File.Exists(path))return;
        var info=new FileInfo(path);
        if(info.Length is < 10 or > 256*1024 || (info.Attributes&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Integrity baseline state malformed or linked");
        var state=JsonSerializer.Deserialize<State>(File.ReadAllText(path),Wire.Json)
            ??throw new InvalidDataException("Missing integrity baseline state");
        if(state.Schema!=1 || state.Checks is null || state.Checks.Count>128)
            throw new InvalidDataException("Unsupported or excessive integrity baseline state");
        foreach(var pair in state.Checks)
        {
            Validate(pair.Key,pair.Value);
            if(!observations.TryAdd(pair.Key,pair.Value))
                throw new InvalidDataException("Duplicate baseline path");
        }
    }

    private static void Validate(string path,string digest)
    {
        if(string.IsNullOrWhiteSpace(path)||path.Length>1024||
            !Path.IsPathFullyQualified(path)||path!=Path.GetFullPath(path)||
            digest is null || digest.Length!=64 || !digest.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("Invalid binary baseline path/hash");
    }

    public ChangeKind Observe(string file,string sha256)
    {
        var full=Path.GetFullPath(file);
        Validate(full,sha256);
        var hash=sha256.ToUpperInvariant();
        if(observations.TryGetValue(full,out var previous)&&previous==hash)
            return ChangeKind.Unchanged;
        var result=previous==null?ChangeKind.FirstObservation:ChangeKind.Changed;
        if(previous==null && observations.Count>=128)
            throw new InvalidDataException("Maximum 128 persistent binary baselines");
        observations[full]=hash;
        try{Save();}
        catch
        {
            if(previous==null)observations.Remove(full);
            else observations[full]=previous;
            throw;
        }
        return result;
    }

    private void Save()
    {
        if(File.Exists(path) && (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Linked binary baseline state rejected");
        var body=JsonSerializer.Serialize(new State(1,new Dictionary<string,string>(observations,StringComparer.OrdinalIgnoreCase)),Wire.Json);
        if(body.Length>256*1024)throw new InvalidDataException("Serialized binary baseline too large");
        AtomicFile.Write(path,body);
    }
}
