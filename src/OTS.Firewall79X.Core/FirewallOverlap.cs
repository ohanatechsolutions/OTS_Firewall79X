using System.Net;

namespace OTS.Firewall79X.Core;

public sealed record FirewallRuleView(string Name, string Direction, string Action, string Protocol,
    string LocalPorts, string RemoteAddresses, string Profiles, string Application, bool Enabled);
public sealed record FirewallOverlapResult(int Examined, int DuplicateRules, int OpposingExactMatches,
    int PotentialOverlaps, int BroadInboundAllows, bool Truncated, string Limitations)
{
    public override string ToString() =>
        $"{Examined} enabled rules examined; {DuplicateRules} exact duplicates; {OpposingExactMatches} opposing exact matches; " +
        $"{PotentialOverlaps} additional potential partial overlaps; {BroadInboundAllows} broad inbound allows. " +
        (Truncated ? "Comparison budget reached. " : "") + Limitations;
}

public static class FirewallOverlap
{
    // Conservative, bounded potential-overlap detection. It NEVER claims to compute Windows Firewall precedence.
    public static FirewallOverlapResult Analyze(IEnumerable<FirewallRuleView> all)
    {
        var selected = all.Where(r => r.Enabled).Take(801).ToArray();
        bool truncated = selected.Length > 800;
        var rules = selected.Take(800).ToArray();
        int duplicates = rules.GroupBy(Key).Sum(g => Math.Max(0, g.Count() - 1));
        int exact = rules.GroupBy(r => string.Join("\u001f", r.Direction, r.Protocol,
             r.LocalPorts, r.RemoteAddresses, r.Profiles, r.Application))
             .Count(g => g.Select(x => x.Action).Distinct().Count() > 1);
        int broad = rules.Count(r => r.Direction == "1" && r.Action == "1" &&
            Any(r.RemoteAddresses) && Any(r.LocalPorts) && string.IsNullOrWhiteSpace(r.Application));
        int potential = 0;
        for (int i = 0; i < rules.Length && potential < 1000; i++)
            for (int j = i + 1; j < rules.Length && potential < 1000; j++)
            {
                var a = rules[i]; var b = rules[j];
                if (Key(a) == Key(b)) continue; // reported as exact duplicate
                if (a.Direction == b.Direction && a.Protocol == b.Protocol &&
                    a.LocalPorts == b.LocalPorts && a.RemoteAddresses == b.RemoteAddresses &&
                    a.Profiles == b.Profiles && a.Application == b.Application) continue; // exact opposing match
                if (a.Direction != b.Direction || !ProtocolOverlaps(a.Protocol, b.Protocol)
                    || !ProfilesOverlap(a.Profiles, b.Profiles)
                    || !ApplicationOverlaps(a.Application, b.Application)) continue;
                if (!PortsOverlap(a.LocalPorts, b.LocalPorts) || !AddressesOverlap(a.RemoteAddresses, b.RemoteAddresses)) continue;
                potential++;
                if (potential >= 1000) truncated = true;
            }
        return new(rules.Length, duplicates, exact, potential, broad, truncated,
            "Potential overlap is not proven shadowing: WFP, GPO precedence, rule interfaces/services, " +
            "local addresses, dynamic address keywords, edge traversal and IPsec are NOT modeled. " +
            "Unrecognized ranges are excluded rather than assumed to match.");
    }

    private static string Key(FirewallRuleView r) =>
        string.Join("\u001f", r.Direction, r.Action, r.Protocol, r.LocalPorts,
            r.RemoteAddresses, r.Profiles, r.Application);
    private static bool Any(string? s) =>
        string.IsNullOrWhiteSpace(s) || s.Trim() is "*" or "Any";
    private static bool ProtocolOverlaps(string x, string y) =>
        x == y || x == "256" || y == "256";
    private static bool ApplicationOverlaps(string x, string y) =>
        string.IsNullOrWhiteSpace(x) || string.IsNullOrWhiteSpace(y) ||
        string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
    private static bool ProfilesOverlap(string x, string y)
    {
        if (!int.TryParse(x, out int a) || !int.TryParse(y, out int b)) return false;
        return a != 0 && b != 0 && (a & b) != 0;
    }

    public static bool PortsOverlap(string a, string b)
    {
        if (Any(a)) return ValidPortSet(b);
        if (Any(b)) return ValidPortSet(a);
        if (!TryPorts(a, out var left) || !TryPorts(b, out var right)) return false;
        return left.Any(x => right.Any(y => x.Min <= y.Max && y.Min <= x.Max));
    }
    private static bool ValidPortSet(string s) => Any(s) || TryPorts(s, out _);
    private static bool TryPorts(string text, out List<(int Min, int Max)> ranges)
    {
        ranges = [];
        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length is 0 or > 64) return false;
        foreach (var part in parts)
        {
            var a = part.Split('-', StringSplitOptions.TrimEntries);
            if (a.Length is < 1 or > 2 || !ushort.TryParse(a[0], out var first) ||
                first == 0 || (a.Length == 2 && (!ushort.TryParse(a[1], out var last) || last < first)))
                return false;
            int end = a.Length == 1 ? first : ushort.Parse(a[1]);
            ranges.Add((first, end));
        }
        return true;
    }

    public static bool AddressesOverlap(string a, string b)
    {
        if (Any(a)) return ValidAddressSet(b);
        if (Any(b)) return ValidAddressSet(a);
        if (!TryAddresses(a, out var left) || !TryAddresses(b, out var right)) return false;
        return left.Any(x => right.Any(y => PrefixOverlap(x, y)));
    }

    private sealed record Prefix(IPAddress Address, int Bits);
    private static bool ValidAddressSet(string s) => Any(s) || TryAddresses(s, out _);
    private static bool TryAddresses(string text, out List<Prefix> prefixes)
    {
        prefixes = [];
        var tokens = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length is 0 or > 64) return false;
        foreach (var token in tokens)
        {
            var pair = token.Split('/');
            if (pair.Length is < 1 or > 2 || !IPAddress.TryParse(pair[0], out var ip)) return false;
            int bits = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            if (pair.Length == 2)
            {
                int maximum = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                if (int.TryParse(pair[1], out var numeric))
                {
                    if (numeric < 0 || numeric > maximum) return false;
                    bits = numeric;
                }
                else if (maximum == 32 && IPAddress.TryParse(pair[1], out var mask) &&
                         mask.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                         TryContiguousIpv4Mask(mask, out var prefix))
                    bits = prefix;
                else return false;
            }
            prefixes.Add(new(ip, bits));
        }
        return true;
    }
    // Windows Firewall COM can serialize IPv4 CIDRs using dotted subnet masks
    // rather than numeric prefix lengths. Reject non-contiguous masks; these
    // are evidence hints only, never effective firewall-policy decisions.
    private static bool TryContiguousIpv4Mask(IPAddress mask, out int prefix)
    {
        prefix=0;
        bool sawZero=false;
        foreach(var octet in mask.GetAddressBytes())
            for(int shift=7;shift>=0;shift--)
            {
                bool set=(octet&(1<<shift))!=0;
                if(set)
                {
                    if(sawZero)return false;
                    prefix++;
                }
                else sawZero=true;
            }
        return true;
    }

    private static bool PrefixOverlap(Prefix a, Prefix b)
    {
        var x = a.Address.GetAddressBytes(); var y = b.Address.GetAddressBytes();
        if (x.Length != y.Length) return false;
        int bits = Math.Min(a.Bits, b.Bits);
        for (int i = 0; i < bits / 8; i++) if (x[i] != y[i]) return false;
        int remaining = bits % 8;
        return remaining == 0 || (x[bits / 8] & (0xff << (8 - remaining))) ==
                                (y[bits / 8] & (0xff << (8 - remaining)));
    }
}
