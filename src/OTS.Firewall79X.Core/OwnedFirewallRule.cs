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
            !string.Equals(remoteAddresses, address, StringComparison.OrdinalIgnoreCase))
            return false;
        return outbound
            ? direction == 2 && description == IntelligenceDescription
            : direction == 1 && description == InboundDescription;
    }
}
