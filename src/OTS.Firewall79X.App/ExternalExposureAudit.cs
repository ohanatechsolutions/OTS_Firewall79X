using System.Net.Http;
using System.Net;
using System.Text.Json;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.App;

/// <summary>An explicitly opted-in lookup of a third party's historical, outside-in
/// Internet port observations. NOT a direct probe or current reachability test.
/// Public IPv4 is disclosed only after the confirmation in the desktop UI.</summary>
internal static class ExternalExposureAudit
{
    internal sealed record Result(DateTimeOffset ObservedAt,string Evidence,string Limitation);
    internal static async Task<Result> LookupAsync(HttpClient client,CancellationToken ct)
    {
        using var ipResponse=await client.GetAsync("https://api4.ipify.org?format=json",HttpCompletionOption.ResponseHeadersRead,ct);
        ipResponse.EnsureSuccessStatusCode();
        if(ipResponse.Content.Headers.ContentLength is > 8192)throw new InvalidDataException("IP lookup response exceeds limit");
        var ipBody=await ipResponse.Content.ReadAsStringAsync(ct);
        if(ipBody.Length>8192)throw new InvalidDataException("IP lookup response exceeds limit");
        using var json=JsonDocument.Parse(ipBody,new JsonDocumentOptions{MaxDepth=8});
        if(!json.RootElement.TryGetProperty("ip",out var address)||address.ValueKind!=JsonValueKind.String)
            throw new InvalidDataException("IP response missing address");
        var raw=address.GetString()??"";
        if(!IPAddress.TryParse(raw,out var ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||
           !Detections.IsPublicAddress(raw))
            throw new InvalidDataException("Public IPv4 could not be confirmed; no third-party port lookup sent");
        var endpoint="https://internetdb.shodan.io/"+ip;
        using var response=await client.GetAsync(endpoint,HttpCompletionOption.ResponseHeadersRead,ct);
        if(response.StatusCode==HttpStatusCode.NotFound)
            return new(DateTimeOffset.UtcNow,"Shodan InternetDB has no historical record for the current public IPv4 address.",
                "NO PUBLIC SAFETY CONCLUSION: absence of a historical database record does not prove ports are closed or unreachable. NAT, IPv6, timestamps and current router state remain unverified.");
        response.EnsureSuccessStatusCode();
        if(response.Content.Headers.ContentLength is > 128*1024)
            throw new InvalidDataException("Exposure intelligence response exceeds limit");
        var body=await response.Content.ReadAsStringAsync(ct);
        if(body.Length>128*1024)throw new InvalidDataException("Exposure intelligence response exceeds limit");
        using var data=JsonDocument.Parse(body,new JsonDocumentOptions{MaxDepth=12});
        if(!data.RootElement.TryGetProperty("ip",out var resultAddress)||
           resultAddress.GetString()!=raw)
            throw new InvalidDataException("External observation does not match requested public IPv4");
        if(!data.RootElement.TryGetProperty("ports",out var portsElement)||
           portsElement.ValueKind!=JsonValueKind.Array)
            throw new InvalidDataException("External observation contains no valid port inventory");
        var ports=new SortedSet<int>();
        foreach(var p in portsElement.EnumerateArray().Take(4096))
            if(p.ValueKind==JsonValueKind.Number&&p.TryGetInt32(out var number)&&number is >=1 and <=65535)
                ports.Add(number);
        var display=ports.Count==0?"no ports recorded":string.Join(", ",ports.Take(30))+
            (ports.Count>30?$" (+{ports.Count-30} more)":"");
        // Never output or persist the user's public IP. The UI already explicitly
        // obtained consent for the disclosure to ipify and Shodan InternetDB.
        return new(DateTimeOffset.UtcNow,$"External database historical observation: {ports.Count} port(s), {display}.",
            "Historical Shodan observations are not a live authorized outside-in probe. No service was contacted on the user's computer. Data may be old or refer to a shared carrier-grade NAT IP. IPv6, UDP, dynamic public IP, actual host access and firewall/routing state are not verified.");
    }
}
