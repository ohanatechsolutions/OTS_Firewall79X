using System.Globalization;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Protected on-disk high-water mark for unsigned HTTPS threat-feed publication
/// timestamps. Prevents an older but still "fresh" download from replacing a newer
/// accepted observation, including after a service restart. NOT a feed signature,
/// trusted timestamp authority, or independent protection from local administrators.
/// </summary>
public static class ThreatFeedPublicationFloor
{
    public static void Accept(string path, DateTimeOffset publicationUtc, DateTimeOffset nowUtc,
        TimeSpan maximumAge, TimeSpan futureSkew)
    {
        if (maximumAge <= TimeSpan.Zero || futureSkew < TimeSpan.Zero ||
            publicationUtc > nowUtc + futureSkew || publicationUtc < nowUtc - maximumAge)
            throw new InvalidDataException("Threat-feed publication is stale or in the future");
        var full=Path.GetFullPath(path);
        var parent=Path.GetDirectoryName(full)??throw new InvalidDataException("Invalid publication-state path");
        if (!Directory.Exists(parent))throw new DirectoryNotFoundException(parent);
        for(var dir=new DirectoryInfo(parent);dir!=null;dir=dir.Parent)
            if(dir.Exists && (dir.Attributes&FileAttributes.ReparsePoint)!=0)
                throw new InvalidDataException("Linked publication-state directory rejected");
        if(File.Exists(full))
        {
            var file=new FileInfo(full);
            if(file.Length is < 15 or > 100 || (file.Attributes&FileAttributes.ReparsePoint)!=0)
                throw new InvalidDataException("Publication-state file size/link invalid");
            var previousText=File.ReadAllText(full).TrimEnd('\r','\n');
            if (!DateTimeOffset.TryParseExact(previousText,"O",CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind,out var previous) ||
                previous.Offset!=TimeSpan.Zero)
                throw new InvalidDataException("Stored publication-state timestamp is malformed");
            if (publicationUtc < previous)
                throw new InvalidDataException("Threat-feed publication timestamp rolled backward");
            if(publicationUtc==previous)return;
        }
        else if(Directory.Exists(full))
            throw new InvalidDataException("Publication-state path is a directory");
        AtomicFile.Write(full,publicationUtc.ToUniversalTime().ToString("O",CultureInfo.InvariantCulture)+"\n");
    }
}
