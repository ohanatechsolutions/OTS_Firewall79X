using System.IO.Compression;
using System.Security.Cryptography;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Crash-recoverable rotation of service JSONL event records. The uncompressed
/// *.pending file is authoritative until a verified gzip is atomically committed.
/// On startup a matching gzip+pending pair is read only once; mismatches fail
/// closed rather than concealing evidence damage.
/// </summary>
public static class EventLogRotation
{
    private const long MaxSegmentBytes=4L*1024*1024;
    private static string ArchiveFor(string pending) =>
        pending.EndsWith(".jsonl.pending",StringComparison.Ordinal)
            ? pending[..^".pending".Length]+".gz"
            : throw new InvalidDataException("Invalid pending log name");

    private static void CheckFile(string path)
    {
        var info=new FileInfo(path);
        if(!info.Exists || (info.Attributes&FileAttributes.ReparsePoint)!=0 ||
           info.Length>8L*1024*1024)
            throw new InvalidDataException("Linked, missing or oversized log rotation segment");
    }

    private static void VerifyTwin(string pending,string gzip)
    {
        CheckFile(pending);CheckFile(gzip);
        using var raw=File.OpenRead(gzip);
        using var zipped=new GZipStream(raw,CompressionMode.Decompress);
        using var decompressed=new MemoryStream();
        byte[] buffer=new byte[65536];int read;
        while((read=zipped.Read(buffer))>0)
        {
            if(decompressed.Length+read>MaxSegmentBytes)
                throw new InvalidDataException("Expanded rotated log exceeds size budget");
            decompressed.Write(buffer,0,read);
        }
        using var original=File.OpenRead(pending);
        if(original.Length!=decompressed.Length)
            throw new InvalidDataException("Rotated log source and archive lengths differ");
        var a=SHA256.HashData(original);
        var b=SHA256.HashData(decompressed.ToArray());
        if(!CryptographicOperations.FixedTimeEquals(a,b))
            throw new InvalidDataException("Rotated log source and archive digest mismatch");
    }

    private static void CommitCompressed(string pending,string archive)
    {
        CheckFile(pending);
        var temporary=archive+"."+Guid.NewGuid().ToString("N")+".partial";
        try
        {
            using(var source=File.OpenRead(pending))
            using(var destination=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,
                FileShare.None,65536,FileOptions.WriteThrough))
            {
                using(var gzip=new GZipStream(destination,CompressionLevel.Fastest,true))
                    source.CopyTo(gzip);
                destination.Flush(true);
            }
            VerifyTwin(pending,temporary);
            File.Move(temporary,archive,false);
        }
        finally{if(File.Exists(temporary))File.Delete(temporary);}
    }

    public static void Rotate(string active,DateTimeOffset now)
    {
        if(!File.Exists(active))return;
        CheckFile(active);
        var parent=Path.GetDirectoryName(Path.GetFullPath(active))!;
        var stem=Path.Combine(parent,$"events-{now:yyyyMMdd-HHmmss-fffffff}-{Guid.NewGuid():N}.jsonl");
        var pending=stem+".pending";
        var gzip=stem+".gz";
        File.Move(active,pending,false);
        CommitCompressed(pending,gzip);
        File.Delete(pending);
    }

    public static IReadOnlyList<string> SelectVerifiedSegments(string directory)
    {
        var gzips=Directory.GetFiles(directory,"events-*.jsonl.gz").ToList();
        var pending=Directory.GetFiles(directory,"events-*.jsonl.pending");
        if(gzips.Count>128||pending.Length>128)
            throw new InvalidDataException("Log segment recovery budget exceeded");
        foreach(var path in gzips)CheckFile(path);
        foreach(var path in pending)
        {
            CheckFile(path);
            var archive=ArchiveFor(path);
            if(File.Exists(archive))VerifyTwin(path,archive);
            else gzips.Add(path);
        }
        return gzips.OrderBy(Path.GetFileName,StringComparer.Ordinal).ToArray();
    }

    // Call only after the selected segments have passed HMAC-chain and schema
    // verification. An interruption during recovery leaves *.pending for retry.
    public static void FinalizePending(string directory)
    {
        var pending=Directory.GetFiles(directory,"events-*.jsonl.pending");
        if(pending.Length>128)throw new InvalidDataException("Excessive pending log segments");
        foreach(var source in pending.Order(StringComparer.Ordinal))
        {
            var archive=ArchiveFor(source);
            if(File.Exists(archive))VerifyTwin(source,archive);
            else CommitCompressed(source,archive);
            File.Delete(source);
        }
    }
}
