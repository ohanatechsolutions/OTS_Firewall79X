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

    public static bool IsExactHostSelector(string? selector, IPAddress expected)
    {
        if(string.IsNullOrWhiteSpace(selector) || selector.Length>100 ||
           selector.Contains(',') || selector.Contains(';') || selector.Contains('-') ||
           selector.Contains('*'))return false;
        var host=selector;
        int slash=selector.IndexOf('/');
        if(slash>=0)
        {
            if(selector.IndexOf('/',slash+1)>=0)return false;
            var mask=selector[(slash+1)..];
            bool correct=expected.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork
                ? mask is "32" or "255.255.255.255" : mask=="128";
            if(!correct)return false;
            host=selector[..slash];
        }
        return IPAddress.TryParse(host,out var parsed) &&
            !parsed.IsIPv4MappedToIPv6 && parsed.Equals(expected);
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
        // Windows Firewall may normalize an exact host into a /32, all-ones mask or /128.
        // Never accept a subnet/range/wildcard or multiple hosts as OTS-owned.
        if (!string.Equals(address, ip.ToString(), StringComparison.OrdinalIgnoreCase) ||
            !IsExactHostSelector(remoteAddresses, ip))
            return false;
        return authentication
            ? direction == 1 && description == AuthenticationDescription
            : outbound
                ? direction == 2 && description == IntelligenceDescription
                : direction == 1 && description == InboundDescription;
    }
}
