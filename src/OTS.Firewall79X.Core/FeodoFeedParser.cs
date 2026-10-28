using System.Globalization;
using System.Net;
using System.Net.Sockets;
namespace OTS.Firewall79X.Core;

/// <summary>Strict parser for the official, plain-text abuse.ch Feodo recommended C2 IP feed.
/// This is observation-only evidence; HTTP content is not a signed executable or policy.</summary>
public static class FeodoFeedParser
{
    public sealed record Feed(DateTimeOffset UpdatedUtc, IReadOnlySet<string> Addresses);
    public static Feed Parse(string body)
    {
        if (body.Length > 512_000) throw new InvalidDataException("Threat feed size budget exceeded");
        var addresses = new HashSet<string>(StringComparer.Ordinal);
        DateTimeOffset? updated = null;
        int count = 0;
        foreach (var raw in body.Split('\n'))
        {
            if (++count > 12_000) throw new InvalidDataException("Threat feed line budget exceeded");
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('#'))
            {
                const string prefix = "# Last updated:";
                if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (updated != null) throw new InvalidDataException("Duplicated feed update timestamp");
                    var value = line[prefix.Length..].Trim();
                    if (!DateTime.TryParseExact(value, "yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal, out var stamp))
                        throw new InvalidDataException("Invalid feed update timestamp");
                    updated = new DateTimeOffset(stamp, TimeSpan.Zero);
                }
                continue;
            }
            if (line.Length > 64 || !IPAddress.TryParse(line, out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork || !Detections.IsPublicAddress(line) ||
                !line.Equals(ip.ToString(), StringComparison.Ordinal))
                throw new InvalidDataException("Threat feed contained an invalid/nonpublic/noncanonical IPv4 address");
            addresses.Add(line);
            if (addresses.Count > 10_000) throw new InvalidDataException("Threat feed IP count budget exceeded");
        }
        if (updated is null || addresses.Count == 0) throw new InvalidDataException("Threat feed has no dated, valid IP indicators");
        return new(updated.Value, addresses);
    }
    public static bool IsFresh(Feed feed, DateTimeOffset now) =>
        feed.UpdatedUtc <= now.AddMinutes(5) && feed.UpdatedUtc >= now.AddHours(-24);
}
