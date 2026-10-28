using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>Authenticates individual retained log entries and detects broken links.
/// Legacy service instances restarted their chain at every process start, so continuity
/// gaps are explicitly reported rather than incorrectly called tampering.</summary>
public static class EventIntegrity
{
    public sealed record Record(string Previous, string Data, string Hmac);
    public sealed record Verification(int Verified, string? LastHmac, int ChainGaps);
    private static byte[] DecodeDigest(string hex)
    {
        if (hex.Length != 64) throw new InvalidDataException("Invalid integrity digest length");
        try { return Convert.FromHexString(hex); }
        catch (FormatException ex) { throw new InvalidDataException("Invalid integrity digest", ex); }
    }

    public static Verification Verify(IEnumerable<string> lines, byte[] key)
    {
        if (key.Length != 32) throw new ArgumentException("Log integrity key must be 256 bits", nameof(key));
        int count = 0, gaps = 0;
        string? previous = null;
        foreach (string line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (line.Length > 32768) throw new InvalidDataException("Log record size limit exceeded");
            Record item;
            try { item = JsonSerializer.Deserialize<Record>(line, Wire.Json) ?? throw new InvalidDataException("Empty log record"); }
            catch (JsonException ex) { throw new InvalidDataException("Malformed log record", ex); }
            if (item.Previous is null || item.Hmac is null || item.Data is null)
                throw new InvalidDataException("Missing integrity fields");
            var previousDigest = DecodeDigest(item.Previous);
            var actualDigest = DecodeDigest(item.Hmac);
            var computed = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(item.Previous + item.Data));
            if (!CryptographicOperations.FixedTimeEquals(actualDigest, computed))
                throw new InvalidDataException("Log record integrity authentication failed");
            if (previous != null && !CryptographicOperations.FixedTimeEquals(previousDigest, DecodeDigest(previous))) gaps++;
            previous = item.Hmac;
            count++;
        }
        return new Verification(count, previous, gaps);
    }
}
