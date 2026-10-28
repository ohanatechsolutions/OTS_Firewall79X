using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>Pure fail-closed parser for OSV v1/querybatch response. Does not
/// perform network calls and does not interpret absence of advisories as safety.</summary>
public static class OsvBatchValidator
{
    public sealed record Finding(string Name,string Version,IReadOnlyList<string> AdvisoryIds,bool NeedsAnotherPage);
    public sealed record Summary(int Queried,int PackagesAffected,int AdvisoryCount,bool Complete,IReadOnlyList<Finding> Findings);
    public static Summary Parse(string body,IReadOnlyList<NuGetLockParser.Package> packages)
    {
        if(packages.Count is <1 or >100||body.Length>1024*1024)
            throw new InvalidDataException("OSV query or response exceeds budget");
        using var data=JsonDocument.Parse(body,new JsonDocumentOptions{MaxDepth=20});
        if(data.RootElement.ValueKind!=JsonValueKind.Object||
           !data.RootElement.TryGetProperty("results",out var results)||
           results.ValueKind!=JsonValueKind.Array||results.GetArrayLength()!=packages.Count)
            throw new InvalidDataException("OSV response does not match submitted package count");
        List<Finding> findings=[];int affected=0,count=0;bool complete=true;
        int index=0;
        foreach(var result in results.EnumerateArray())
        {
            if(result.ValueKind!=JsonValueKind.Object)
                throw new InvalidDataException("OSV result must be an object");
            var pkg=packages[index++];
            bool paginated=result.TryGetProperty("next_page_token",out var token)&&
                token.ValueKind==JsonValueKind.String&&!string.IsNullOrEmpty(token.GetString());
            if(paginated)complete=false;
            var ids=new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            if(result.TryGetProperty("vulns",out var vulns))
            {
                if(vulns.ValueKind!=JsonValueKind.Array)
                    throw new InvalidDataException("OSV advisory list must be an array");
                foreach(var entry in vulns.EnumerateArray())
                {
                    if(entry.ValueKind!=JsonValueKind.Object||!entry.TryGetProperty("id",out var id)||
                       id.ValueKind!=JsonValueKind.String)
                        throw new InvalidDataException("OSV advisory is missing an ID");
                    var value=id.GetString()??"";
                    if(value.Length is <1 or >100||
                       !value.All(c=>char.IsAsciiLetterOrDigit(c)||c is '-' or '_' or '.'))
                        throw new InvalidDataException("Invalid advisory identifier returned");
                    ids.Add(value);
                    if(ids.Count>256)throw new InvalidDataException("OSV advisory cap exceeded");
                }
            }
            if(ids.Count>0)affected++;
            count+=ids.Count;
            if(ids.Count>0||paginated)
                findings.Add(new(pkg.Name,pkg.Version,ids.ToArray(),paginated));
        }
        return new(packages.Count,affected,count,complete,findings);
    }
}
