using System.Net;
using System.Security.Cryptography;
using System.Text;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Optional network intelligence observation. Does not install firewall rules,
/// disable system DNS, or treat HTTPS transport as feed code signing.</summary>
public sealed class FeodoThreatFeed : IDisposable
{
    private const string Source = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
    private readonly HttpClient http = new(new HttpClientHandler {AllowAutoRedirect=false, AutomaticDecompression=DecompressionMethods.None})
    {Timeout=TimeSpan.FromSeconds(12)};
    private FeodoFeedParser.Feed? active;
    private DateTimeOffset nextAttempt = DateTimeOffset.MinValue;
    private string health="Not downloaded";
    public FeodoFeedParser.Feed? Active
    {
        get
        {
            var snapshot=Volatile.Read(ref active);
            return snapshot != null && FeodoFeedParser.IsFresh(snapshot, DateTimeOffset.UtcNow) ? snapshot : null;
        }
    }
    public string Summary
    {
        get
        {
            var snapshot=Active;
            return snapshot!=null
                ? $"Feodo Tracker HTTPS observation feed: {snapshot.Addresses.Count} IPv4 C2 indicators; source updated {snapshot.UpdatedUtc:O}. No OTS firewall blocks installed."
                : "Feodo Tracker feed unavailable or stale: " + health + ". No OTS firewall blocks installed.";
        }
    }
    public async Task RefreshIfDueAsync(CancellationToken ct)
    {
        var now=DateTimeOffset.UtcNow;
        if(now<nextAttempt)return;
        nextAttempt=now.AddMinutes(15);
        try
        {
            using var response=await http.GetAsync(Source,HttpCompletionOption.ResponseHeadersRead,ct);
            if(response.StatusCode!=HttpStatusCode.OK)throw new InvalidDataException($"Threat source HTTP status {(int)response.StatusCode}");
            if(response.Content.Headers.ContentLength is long length && length>512_000)throw new InvalidDataException("Threat source too large");
            await using var stream=await response.Content.ReadAsStreamAsync(ct);
            using var output=new MemoryStream();
            var buffer=new byte[8192];
            int bytes;
            while((bytes=await stream.ReadAsync(buffer,ct))>0)
            {
                if(output.Length+bytes>512_000)throw new InvalidDataException("Threat source exceeded body budget");
                output.Write(buffer,0,bytes);
            }
            var payload=output.ToArray();
            var body=new UTF8Encoding(false,true).GetString(payload);
            var parsed=FeodoFeedParser.Parse(body);
            if(!FeodoFeedParser.IsFresh(parsed,DateTimeOffset.UtcNow))
                throw new InvalidDataException("Source publication timestamp is stale or in the future");
            Volatile.Write(ref active,parsed);
            health=$"Last HTTPS fetch {DateTimeOffset.UtcNow:O}; SHA-256 {Convert.ToHexString(SHA256.HashData(payload))}; no feed signing proof";
        }
        catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch(Exception ex)when(ex is IOException or HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.DecoderFallbackException)
        {
            health=Wire.Clean(ex.Message,256);
            Volatile.Write(ref active,null);
        }
    }
    public void Dispose()=>http.Dispose();
}
