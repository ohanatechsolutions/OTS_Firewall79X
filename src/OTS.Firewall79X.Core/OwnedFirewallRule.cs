using System.Net;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Fail-safe identity checks for firewall rules managed by OTS. A matching name
/// alone is never proof of ownership: externally altered rules must be preserved.
/// This does not make local administrators an untrusted security boundary.
/// </summary>
public static class OwnedFirewallRule
{
    public const string InboundPrefix = "OTS Firewall79X temporary inbound source ";
    public const string IntelligencePrefix = "OTS Firewall79X temporary outbound intelligence ";
    public const string InboundDescription =
        "OTS-owned temporary inbound restriction for repeated already-blocked attempts; reclaimed when disabled or expired";
    public const string IntelligenceDescription =
        "OTS temporary rule for observed, fresh Feodo intelligence; removed at expiry/feed failure/OFF";

    public static bool HasReservedName(string? name) =>
        name != null && (name.StartsWith(InboundPrefix, StringComparison.Ordinal) ||
                          name.StartsWith(IntelligencePrefix, StringComparison.Ordinal));

    /// <summary>Recognize a single exact host; Windows Firewall COM can return
    /// IPv4 address/255.255.255.255 or address/32 instead of the input literal.
    /// Never accept subnets, ranges, lists, whitespace or a different address.</summary>
    public static bool ExactHostAddress(string? observed,string? expected)
    {
        if (observed is null || expected is null || !IPAddress.TryParse(expected,out var ip) ||
            !string.Equals(expected,ip.ToString(),StringComparison.OrdinalIgnoreCase))return false;
        if (string.Equals(observed,expected,StringComparison.OrdinalIgnoreCase))return true;
        var suffix=ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork
            ? new[]{"/32","/255.255.255.255"} : new[]{"/128"};
        return suffix.Any(mask=>string.Equals(observed,expected+mask,StringComparison.OrdinalIgnoreCase));
    }

    public static bool Matches(
        string? name, string? description, string? remoteAddresses,
        int direction, int action, int protocol, int profiles, bool enabled)
    {
        if (name is null || !HasReservedName(name) || !enabled || action != 0 ||
            protocol != 256 || profiles != int.MaxValue)
            return false;

        bool outbound = name.StartsWith(IntelligencePrefix, StringComparison.Ordinal);
        string address = name[(outbound ? IntelligencePrefix.Length : InboundPrefix.Length)..];
        if (address.Length is < 3 or > 64 || !IPAddress.TryParse(address, out var ip) ||
            !NetworkAbuseWindow.EligiblePublicSource(address) ||
            (outbound && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork))
            return false;
        // Match EXACT canonical address, never a broad CIDR, range or address list.
        if (!string.Equals(address, ip.ToString(), StringComparison.OrdinalIgnoreCase) ||
            !ExactHostAddress(remoteAddresses,address))
            return false;
        return outbound
            ? direction == 2 && description == IntelligenceDescription
            : direction == 1 && description == InboundDescription;
    }
}
