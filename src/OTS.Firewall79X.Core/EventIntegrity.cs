using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>HMAC-authenticated, linked retained segments. KeyId=0 is compatible with
/// legacy records; positive key IDs are bound into new HMACs to support protected
/// key rotation without invalidating previously authenticated history.</summary>
public static class EventIntegrity
{
    public sealed record Record(string Previous, string Data, string Hmac, int KeyId = 0);
    public sealed record Verification(int Verified, string? LastHmac, int ChainGaps);

    private static byte[] DecodeDigest(string? hex)
    {
        if (hex is null || hex.Length != 64)
            throw new InvalidDataException("Invalid integrity digest length");
        try { return Convert.FromHexString(hex); }
        catch (FormatException ex) { throw new InvalidDataException("Invalid integrity digest", ex); }
    }
    public static string Compute(int id, byte[] key, string previous, string data)
    {
        if (key is null || key.Length != 32 || id is < 0 or > 1_000_000)
            throw new ArgumentException("Invalid integrity key identifier/material");
        _ = DecodeDigest(previous);
        var payload=id==0?previous+data:$"OTS79X-v2:{id}:{previous}:{data}";
        return Convert.ToHexString(HMACSHA256.HashData(key,Encoding.UTF8.GetBytes(payload)));
    }
    public static Verification Verify(IEnumerable<string> lines, byte[] legacyKey) =>
        Verify(lines,new Dictionary<int,byte[]> {{0,legacyKey}});

    public static Verification Verify(IEnumerable<string> lines, IReadOnlyDictionary<int,byte[]> keys)
    {
        if(keys is null || keys.Count is < 1 or > 64 || keys.Any(p=>p.Key is < 0 or > 1_000_000 || p.Value is null || p.Value.Length!=32))
            throw new ArgumentException("Invalid log-integrity key ring",nameof(keys));
        int count=0,gaps=0;
        string? previous=null;
        foreach(var line in lines)
        {
            if(string.IsNullOrWhiteSpace(line))continue;
            if(line.Length>32768)throw new InvalidDataException("Log record size limit exceeded");
            Record record;
            try {record=JsonSerializer.Deserialize<Record>(line,Wire.Json)
                ?? throw new InvalidDataException("Empty log record");}
            catch(JsonException ex){throw new InvalidDataException("Malformed log record",ex);}
            if(record.Previous is null || record.Hmac is null || record.Data is null ||
                record.KeyId is < 0 or > 1_000_000 || !keys.TryGetValue(record.KeyId,out var key))
                throw new InvalidDataException("Missing integrity fields or unknown key version");
            var previousDigest=DecodeDigest(record.Previous);
            var actual=DecodeDigest(record.Hmac);
            var expected=DecodeDigest(Compute(record.KeyId,key,record.Previous,record.Data));
            if(!CryptographicOperations.FixedTimeEquals(actual,expected))
                throw new InvalidDataException("Log record integrity authentication failed");
            if(previous!=null && !CryptographicOperations.FixedTimeEquals(previousDigest,DecodeDigest(previous)))gaps++;
            previous=record.Hmac;
            count++;
        }
        return new(count,previous,gaps);
    }
}
