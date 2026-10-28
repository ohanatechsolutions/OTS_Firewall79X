using System.Net;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Minimum identity required to remove a local firewall rule. Names alone are
/// never trusted as evidence of rule ownership. Local administrators can modify
/// rules, so this is an accidental-conflict safeguard, NOT an adversarial ACL.
/// </summary>
public static class TemporaryRuleIdentity
{
    public const string InboundPrefix="OTS Firewall79X temporary inbound source ";
    public const string OutboundPrefix="OTS Firewall79X temporary outbound intelligence ";
    public const string Group="OTS Firewall79X / Temporary Security Rules";
    public const string Marker="OTS79X::owned::v2::";
    private const string LegacyInbound="OTS-owned temporary inbound restriction for repeated already-blocked attempts; reclaimed when disabled or expired";
    private const string LegacyOutbound="OTS temporary rule for observed, fresh Feodo intelligence; removed at expiry/feed failure/OFF";

    public static bool UsesReservedName(string? name) =>
        name?.StartsWith(InboundPrefix,StringComparison.Ordinal)==true ||
        name?.StartsWith(OutboundPrefix,StringComparison.Ordinal)==true;

    public static bool IsOwned(string? name,string? description,string? group,
        string? remoteAddresses,int direction,int action,int protocol)
    {
        if(!UsesReservedName(name))return false;
        bool inbound=name!.StartsWith(InboundPrefix,StringComparison.Ordinal);
        string suffix=name[(inbound?InboundPrefix:OutboundPrefix).Length..];
        if(!NetworkAbuseWindow.EligiblePublicSource(suffix) ||
           !OwnedFirewallRule.ExactHostAddress(remoteAddresses,suffix) ||
           direction!=(inbound?1:2) || action!=0 || protocol!=256)return false;
        // Allow narrowly specified legacy rules from earlier preview builds to
        // be reclaimed without deleting arbitrary similarly named user rules.
        if(string.Equals(group,Group,StringComparison.Ordinal) &&
           string.Equals(description,Marker+(inbound?"inbound":"intelligence"),StringComparison.Ordinal))
            return true;
        return string.IsNullOrWhiteSpace(group) &&
            string.Equals(description,inbound?LegacyInbound:LegacyOutbound,StringComparison.Ordinal);
    }
}
