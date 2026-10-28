using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
namespace OTS.Firewall79X.Core;

public static class FolderBackup
{
    public const long MaxBytes=60L*1024*1024;
    private sealed record Entry(string Path,long Length,string Sha256,long? LastWriteUtcTicks=null);
    public sealed record Summary(int Files,long Bytes);
    private static void NoLink(string path)
    {
        for(var d=new DirectoryInfo(path);d!=null;d=d.Parent)if(d.Exists&&d.Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("Linked directories are not accepted for backups/restores");
    }
    private static string ValidatePath(string name)
    {
        if(string.IsNullOrEmpty(name)||name.Length>1024||name.Contains('\\')||name.StartsWith('/')||Path.IsPathRooted(name))throw new InvalidDataException("Invalid backup entry path");
        foreach(var part in name.Split('/'))
        {
            if(part is "" or "." or ".."||part.Any(c=>c<32||"<>:\"|?*".Contains(c))||part.EndsWith(' ')||part.EndsWith('.'))throw new InvalidDataException("Unsafe backup entry name");
            var stem=part.Split('.')[0].ToUpperInvariant();if(stem is "CON" or "PRN" or "AUX" or "NUL"||stem.Length==4&&(stem.StartsWith("COM")||stem.StartsWith("LPT"))&&stem[3] is >= '1' and <= '9')throw new InvalidDataException("Reserved device filename");
        }
        return name;
    }
    public static Summary Create(string source,string destination,string password)
    {
        source=Path.GetFullPath(source);destination=Path.GetFullPath(destination);NoLink(source);NoLink(Path.GetDirectoryName(destination)!);
        if(!Directory.Exists(source))throw new DirectoryNotFoundException(source);
        if(File.Exists(destination)||Directory.Exists(destination))throw new IOException("Choose a new version filename; backups never replace an existing archive");
        if(destination.StartsWith(source.TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Backup destination must be outside the source folder");
        var entries=new List<Entry>();long total=0;using var payload=new MemoryStream();
        using(var zip=new ZipArchive(payload,ZipArchiveMode.Create,true))
        {
            var directories=new Stack<string>();directories.Push(source);int visited=0;
            while(directories.Count>0)
            {
                var dir=directories.Pop();if(++visited>5000)throw new IOException("Directory budget exceeded");NoLink(dir);
                foreach(var child in Directory.EnumerateDirectories(dir)){if(directories.Count>=5000)throw new IOException("Directory budget exceeded");NoLink(child);directories.Push(child);}
                foreach(var file in Directory.EnumerateFiles(dir))
                {
                    var info=new FileInfo(file);if(info.Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("Linked files are not accepted");
                    if(entries.Count>=5000||info.Length>MaxBytes-total)throw new IOException("Backup exceeds 5,000 files or 60 MiB; choose a smaller folder");
                    var relative=ValidatePath(Path.GetRelativePath(source,file).Replace(Path.DirectorySeparatorChar,'/'));
                    using var input=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var entry=zip.CreateEntry("files/"+relative,CompressionLevel.Fastest);long length=0;var buffer=new byte[65536];
                    using(var output=entry.Open()){int n;while((n=input.Read(buffer))>0){if(total+n>MaxBytes)throw new IOException("Backup grew beyond budget");output.Write(buffer,0,n);hash.AppendData(buffer,0,n);length+=n;total+=n;}}
                    entries.Add(new(relative,length,Convert.ToHexString(hash.GetHashAndReset()),info.LastWriteTimeUtc.Ticks));
                }
            }
            using var manifest=zip.CreateEntry("manifest.json").Open();JsonSerializer.Serialize(manifest,entries,Wire.Json);
        }
        var temp=destination+"."+Guid.NewGuid().ToString("N")+".partial";
        try{SecureArchive.Encrypt(temp,payload.ToArray(),password);var summary=Verify(temp,password);File.Move(temp,destination,false);return summary;}
        finally{if(File.Exists(temp))File.Delete(temp);}
    }
    public static Summary Verify(string archive,string password)=>Read(archive,password,null);
    public static Summary Restore(string archive,string newFolder,string password)
    {
        newFolder=Path.GetFullPath(newFolder);var parent=Path.GetDirectoryName(newFolder)??throw new IOException("Invalid destination");NoLink(parent);
        if(!Directory.Exists(parent))throw new DirectoryNotFoundException(parent);
        if(Directory.Exists(newFolder)||File.Exists(newFolder))throw new IOException("Restore requires a new folder and never overwrites existing files");
        var staging=Path.Combine(parent,"OTS-Restore-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(staging);
        try{var summary=Read(archive,password,staging);Directory.Move(staging,newFolder);return summary;}
        finally{if(Directory.Exists(staging))Directory.Delete(staging,true);}
    }
    private static Summary Read(string archive,string password,string? destination)
    {
        var bytes=SecureArchive.Decrypt(archive,password);
        try
        {
            using var payload=new MemoryStream(bytes,false);using var zip=new ZipArchive(payload,ZipArchiveMode.Read);
            if(zip.Entries.Count>5001)throw new InvalidDataException("Entry budget exceeded");
            var manifest=zip.GetEntry("manifest.json")??throw new InvalidDataException("Backup manifest missing");if(manifest.Length>2*1024*1024)throw new InvalidDataException("Manifest too large");
            List<Entry> entries;
            using(var input=manifest.Open())using(var limited=new MemoryStream())
            {
                var buffer=new byte[65536];int n;while((n=input.Read(buffer))>0){if(limited.Length+n>2*1024*1024)throw new InvalidDataException("Expanded manifest exceeds limit");limited.Write(buffer,0,n);}
                entries=JsonSerializer.Deserialize<List<Entry>>(limited.ToArray(),Wire.Json)??throw new InvalidDataException("Invalid manifest");
            }
            if(zip.Entries.Select(e=>e.FullName).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=zip.Entries.Count)throw new InvalidDataException("Duplicate archive entry names");
            if(entries.Count>5000||zip.Entries.Count!=entries.Count+1)throw new InvalidDataException("Entry count mismatch");
            var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long total=0;
            foreach(var item in entries)
            {
                string name=ValidatePath(item.Path);if(!names.Add(name)||item.Length<0||item.Length>MaxBytes-total)throw new InvalidDataException("Invalid or duplicate entry");
                var entry=zip.GetEntry("files/"+name)??throw new InvalidDataException("Missing file");if(entry.Length!=item.Length)throw new InvalidDataException("Length mismatch");
                FileStream? output=null;string? outputPath=null;
                try
                {
                    if(destination!=null){var target=Path.GetFullPath(Path.Combine(destination,name.Replace('/',Path.DirectorySeparatorChar)));if(!target.StartsWith(destination+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Archive path escapes destination");Directory.CreateDirectory(Path.GetDirectoryName(target)!);NoLink(Path.GetDirectoryName(target)!);output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None);outputPath=target;}
                    using var input=entry.Open();using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[65536];long length=0;int n;
                    while((n=input.Read(buffer))>0){length+=n;if(length>item.Length)throw new InvalidDataException("Expanded size exceeded");hash.AppendData(buffer,0,n);output?.Write(buffer,0,n);}
                    if(length!=item.Length||Convert.ToHexString(hash.GetHashAndReset())!=item.Sha256)throw new InvalidDataException("Backup file integrity mismatch");total+=length;
                }
                finally{output?.Dispose();}
                // Restore metadata only after authenticated content has passed its digest check.
                if(outputPath!=null && item.LastWriteUtcTicks is long ticks)
                {
                    if(ticks<DateTime.UnixEpoch.Ticks||ticks>DateTime.MaxValue.Ticks)throw new InvalidDataException("Invalid saved file timestamp");
                    File.SetLastWriteTimeUtc(outputPath,new DateTime(ticks,DateTimeKind.Utc));
                }
            }
            return new(entries.Count,total);
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
}
