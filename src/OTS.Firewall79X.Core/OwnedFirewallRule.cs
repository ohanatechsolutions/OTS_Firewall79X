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
    public const string AuthenticationPrefix = "OTS Firewall79X temporary RDP authentication source ";
    public const string AuthenticationDescription =
        "OTS opt-in temporary RDP-only inbound restriction for repeated nonexistent-user attempts; 2-minute TTL; removed at OFF/startup";
    public const string InboundDescription =
        "OTS-owned temporary inbound restriction for repeated already-blocked attempts; reclaimed when disabled or expired";
    public const string IntelligenceDescription =
        "OTS temporary rule for observed, fresh Feodo intelligence; removed at expiry/feed failure/OFF";

    public static bool HasReservedName(string? name) =>
        name != null && (name.StartsWith(InboundPrefix, StringComparison.Ordinal) ||
                          name.StartsWith(IntelligencePrefix, StringComparison.Ordinal) ||
                          name.StartsWith(AuthenticationPrefix, StringComparison.Ordinal));

    /// <summary>Only exact hosts: Windows Firewall COM serializes a single IPv4
    /// address as address/255.255.255.255 (or address/32), and IPv6 as /128.
    /// A network, address list, wildcard, or different host is not ours.</summary>
    public static bool ExactHostAddress(string? observed,string? expected)
    {
        if(observed is null||expected is null||!IPAddress.TryParse(expected,out var ip)||
           !string.Equals(expected,ip.ToString(),StringComparison.OrdinalIgnoreCase))return false;
        if(string.Equals(observed,expected,StringComparison.OrdinalIgnoreCase))return true;
        var masks=ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork
            ? new[]{"/32","/255.255.255.255"} : new[]{"/128"};
        return masks.Any(mask=>string.Equals(observed,expected+mask,StringComparison.OrdinalIgnoreCase));
    }

    public static bool Matches(
        string? name, string? description, string? remoteAddresses,
        int direction, int action, int protocol, int profiles, bool enabled,
        string? localPorts = null)
    {
        if (name is null || !HasReservedName(name) || !enabled || action != 0 ||
            profiles != int.MaxValue)
            return false;

        bool outbound = name.StartsWith(IntelligencePrefix, StringComparison.Ordinal);
        bool authentication = name.StartsWith(AuthenticationPrefix, StringComparison.Ordinal);
        if (authentication ? protocol != 6 || localPorts != "3389" : protocol != 256)
            return false;
        string address = name[(outbound ? IntelligencePrefix.Length :
            authentication ? AuthenticationPrefix.Length : InboundPrefix.Length)..];
        if (address.Length is < 3 or > 64 || !IPAddress.TryParse(address, out var ip) ||
            !NetworkAbuseWindow.EligiblePublicSource(address) ||
            (outbound && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork))
            return false;
        // Match EXACT canonical address, never a broad CIDR, range or address list.
        if (!string.Equals(address, ip.ToString(), StringComparison.OrdinalIgnoreCase) ||
            !ExactHostAddress(remoteAddresses,address))
            return false;
        return authentication
            ? direction == 1 && description == AuthenticationDescription
            : outbound
                ? direction == 2 && description == IntelligenceDescription
                : direction == 1 && description == InboundDescription;
    }
}
