using System.Text.Json;
using System.Text.RegularExpressions;

namespace OTS.Firewall79X.Core;

/// <summary>Exact NuGet name and resolved-version pairs from an authorized lockfile.
/// User paths, package content, credentials and build environment are never required.</summary>
public static class NuGetLockParser
{
    public sealed record Package(string Name,string Version);
    private static readonly Regex NamePattern=new(
        @"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$",
        RegexOptions.CultureInvariant|RegexOptions.Compiled,TimeSpan.FromMilliseconds(100));
    private static readonly Regex VersionPattern=new(
        @"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$",
        RegexOptions.CultureInvariant|RegexOptions.Compiled,TimeSpan.FromMilliseconds(100));
    public static IReadOnlyList<Package> Parse(string source)
    {
        if(source.Length>1024*1024)throw new InvalidDataException("NuGet lockfile exceeds 1 MiB");
        using var doc=JsonDocument.Parse(source,new JsonDocumentOptions{MaxDepth=20});
        if(doc.RootElement.ValueKind!=JsonValueKind.Object||
           !doc.RootElement.TryGetProperty("dependencies",out var frameworks)||
           frameworks.ValueKind!=JsonValueKind.Object)
            throw new InvalidDataException("Not a supported packages.lock.json file");
        var packages=new Dictionary<string,Package>(StringComparer.OrdinalIgnoreCase);
        foreach(var framework in frameworks.EnumerateObject())
        {
            if(framework.Value.ValueKind!=JsonValueKind.Object)continue;
            foreach(var entry in framework.Value.EnumerateObject())
            {
                if(entry.Value.ValueKind!=JsonValueKind.Object||!entry.Value.TryGetProperty("resolved",out var ver)||
                   ver.ValueKind!=JsonValueKind.String)continue;
                var name=entry.Name;var version=ver.GetString()??"";
                if(!NamePattern.IsMatch(name)||!VersionPattern.IsMatch(version))
                    throw new InvalidDataException("Lockfile contains invalid package identifier or version");
                packages[name+"@"+version]=new(name,version);
                if(packages.Count>100)
                    throw new InvalidDataException("Maximum 100 distinct NuGet package versions per audit");
            }
        }
        if(packages.Count==0)throw new InvalidDataException("No resolved NuGet package versions in lockfile");
        return packages.Values.OrderBy(x=>x.Name,StringComparer.OrdinalIgnoreCase)
            .ThenBy(x=>x.Version,StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
