using System.Globalization;

namespace OTS.Firewall79X.Core;

/// <summary>Pure, deterministic classification for the three deception layers.
/// Never performs network I/O or interprets an untrusted URL as a destination.</summary>
public static class DeceptionRules
{
    public static bool IsCanaryDnsQuery(string? observedName, string expectedName) =>
        observedName is not null
        && observedName.Trim().TrimEnd('.').Equals(expectedName, StringComparison.OrdinalIgnoreCase);

    public static bool IsCanaryHttpRequest(string? firstLine, string exactPath)
    {
        if (firstLine is null || firstLine.Length > 512 || exactPath.Length is < 8 or > 160
            || !exactPath.StartsWith("/canary/", StringComparison.Ordinal)) return false;
        var fields = firstLine.Split(' ', StringSplitOptions.None);
        return fields.Length == 3 && fields[0] is "GET" or "HEAD"
            && fields[1].Equals(exactPath, StringComparison.Ordinal)
            && fields[2] is "HTTP/1.0" or "HTTP/1.1";
    }

    // The Windows Security 4663 AccessMask is hexadecimal. ReadData is 0x1,
    // WriteData/AppendData are 0x2/0x4, and DELETE is 0x10000.
    public static (bool Read, bool Changed) ClassifyFileAudit(
        string? objectType, string? objectName, string? expectedPath, string? accessMask)
    {
        if (!string.Equals(objectType, "File", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(objectName) || string.IsNullOrWhiteSpace(expectedPath)
            || !string.Equals(objectName, expectedPath, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(accessMask)) return (false, false);
        if (!accessMask.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            || accessMask.Length < 3 || accessMask.Length > 10) return (false, false);
        var text = accessMask[2..];
        if (!uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var flags))
            return (false, false);
        return ((flags & 0x1u) != 0, (flags & 0x10006u) != 0);
    }

    public static bool IsGeneratedCanaryDnsName(string? host) =>
        host is { Length: 44 }
        && host.StartsWith("ots-", StringComparison.Ordinal)
        && host.EndsWith(".invalid", StringComparison.Ordinal)
        && host.AsSpan(4, 32).ToString().All(Uri.IsHexDigit);
}
