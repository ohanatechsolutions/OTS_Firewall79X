using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OTS.Firewall79X.Core;

/// <summary>Validated, bounded remote-login failure aggregation. This component does not
/// change firewall policy or lock out accounts: security-event IP fields alone cannot
/// establish whether blocking an address is safe on every host.</summary>
public sealed class AuthenticationFailureMonitor
{
    public sealed record Finding(bool ValidRemoteSource, bool Alert, int Count, string Source, string Reason)
    {
        // A candidate is not a block: an administrator must separately enable the guard,
        // and the Windows rule manager must independently re-verify local trusted addresses.
        public bool RestrictionCandidate { get; init; }
    }
    private sealed class Window
    {
        public Queue<(DateTimeOffset At,string? InvalidAccountTag)> Attempts { get; } = new();
        public DateTimeOffset LastAlert { get; set; } = DateTimeOffset.MinValue;
        public DateTimeOffset LastRestrictionCandidate { get; set; } = DateTimeOffset.MinValue;
        public DateTimeOffset LastObserved { get; set; } = DateTimeOffset.MinValue;
    }
    private readonly Dictionary<string,Window> sources = new(StringComparer.Ordinal);
    private readonly TimeSpan period = TimeSpan.FromMinutes(2);
    private readonly TimeSpan cooldown = TimeSpan.FromMinutes(5);
    private readonly byte[] accountTagKey = RandomNumberGenerator.GetBytes(32);

    public Finding Observe(string? rawSource, string? rawLogonType, DateTimeOffset now,
        string? rawSubStatus = null, string? rawUserName = null)
    {
        if (!int.TryParse(rawLogonType,NumberStyles.None,CultureInfo.InvariantCulture,out var logonType)
            || logonType is not (3 or 10))
            return new(false,false,0,"","Local, unknown, or unsupported logon type");
        if (!IPAddress.TryParse(rawSource,out var address) || address.ToString().Contains('%')
            || !NetworkAbuseWindow.EligiblePublicSource(address.ToString()))
            return new(false,false,0,"","Not a verified public remote source");
        var source=address.ToString();
        if (sources.Count>=2048 && !sources.ContainsKey(source))
        {
            foreach (var stale in sources.Where(x=>x.Value.Attempts.Count==0
                || x.Value.Attempts.Last().At<now-period).Select(x=>x.Key).ToArray())sources.Remove(stale);
            if (sources.Count>=2048)sources.Remove(sources.Keys.First()); // bounded memory, never claim coverage for evicted sources
        }
        if (!sources.TryGetValue(source,out var window))sources[source]=window=new Window();
        if (now<window.LastObserved)
        {
            // A host clock rollback or out-of-order event must never turn old
            // attempts into a fresh burst or bypass restriction cooldown.
            window.Attempts.Clear();
            window.LastAlert=now;
            window.LastRestrictionCandidate=now;
        }
        window.LastObserved=now;
        while (window.Attempts.Count>0&&window.Attempts.Peek().At<=now-period)window.Attempts.Dequeue();
        // Only Windows STATUS_NO_SUCH_USER (not a mistyped password for a valid account)
        // can contribute toward the optional RDP-only restriction threshold.
        string? tag=null;
        if (logonType==10 && string.Equals(rawSubStatus,"0xC0000064",StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(rawUserName) && rawUserName.Length<=128)
        {
            var raw=Encoding.UTF8.GetBytes(rawUserName.Trim().ToUpperInvariant());
            try{tag=Convert.ToHexString(HMACSHA256.HashData(accountTagKey,raw).AsSpan(0,8));}
            finally{CryptographicOperations.ZeroMemory(raw);}
        }
        window.Attempts.Enqueue((now,tag));
        while (window.Attempts.Count>128)window.Attempts.Dequeue();
        bool alert=window.Attempts.Count>=8 && now-window.LastAlert>=cooldown;
        if(alert)window.LastAlert=now;
        bool candidate=logonType==10 && window.Attempts.Count>=32
            && window.Attempts.Count(x=>x.InvalidAccountTag!=null)>=32
            && window.Attempts.Where(x=>x.InvalidAccountTag!=null).Select(x=>x.InvalidAccountTag).Distinct().Count()>=5
            && now-window.LastRestrictionCandidate>=TimeSpan.FromMinutes(10);
        if(candidate)window.LastRestrictionCandidate=now;
        return new(true,alert,window.Attempts.Count,source,
            alert?"Repeated remote authentication failures":"Monitoring remote failures; no automatic access restriction")
            { RestrictionCandidate=candidate };
    }
}

/// <summary>HIBP SHA-1 range API parsing. No password or full digest belongs on the wire.
/// SHA-1 is used here strictly as the API's lookup identifier, not for password storage.</summary>
public static class PasswordBreachRange
{
    public static (string Prefix,string Suffix) ComputeRange(ReadOnlySpan<byte> utf8Password)
    {
        if(utf8Password.Length==0 || utf8Password.Length>4096)throw new ArgumentOutOfRangeException(nameof(utf8Password));
        Span<byte> digest=stackalloc byte[20];
        SHA1.HashData(utf8Password,digest);
        try
        {
            var hash=Convert.ToHexString(digest);
            return(hash[..5],hash[5..]);
        }
        finally{CryptographicOperations.ZeroMemory(digest);}
    }

    public static long ParseCount(string suffix,string response)
    {
        if(suffix.Length!=35||!suffix.All(IsHex))throw new ArgumentException("Invalid SHA-1 suffix",nameof(suffix));
        if(response.Length>1024*1024)throw new InvalidDataException("Breach response exceeds limit");
        long? matched=null;int lines=0;
        foreach(var raw in response.Split('\n'))
        {
            var line=raw.TrimEnd('\r');
            if(line.Length==0)continue;
            if(++lines>20000)throw new InvalidDataException("Breach response has too many lines");
            int pos=line.IndexOf(':');
            if(pos!=35 || line.Length>60 || !line[..35].All(IsHex) ||
               !long.TryParse(line[(pos+1)..],NumberStyles.None,CultureInfo.InvariantCulture,out var count))
                throw new InvalidDataException("Invalid breach response record");
            if(line[..35].Equals(suffix,StringComparison.OrdinalIgnoreCase))
            {
                if(matched.HasValue)throw new InvalidDataException("Duplicate breach response record");
                matched=count;
            }
        }
        if(lines==0)throw new InvalidDataException("Empty breach response");
        return matched??0;
    }
    private static bool IsHex(char c)=>(c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');
}

/// <summary>Parse sshd -T effective values, never a guess from commented defaults.</summary>
public static class EffectiveSshPolicy
{
    public sealed record Result(bool? PasswordAuthentication,bool? PubkeyAuthentication,
        bool? PermitEmptyPasswords,bool? PermitRootLogin,bool? StrictModes,
        bool? AllowTcpForwarding,bool? X11Forwarding,bool Complete)
    {
        public bool Weak => PasswordAuthentication==true || PermitEmptyPasswords==true
            || PubkeyAuthentication==false || StrictModes==false || PermitRootLogin==true;
        public bool Hardened => Complete && PasswordAuthentication==false
            && PubkeyAuthentication==true && PermitEmptyPasswords==false
            && StrictModes==true && PermitRootLogin==false;
    }
    public static Result Parse(string text)
    {
        if(text.Length>256*1024)throw new InvalidDataException("Effective SSH output exceeds limit");
        Dictionary<string,string> settings=new(StringComparer.OrdinalIgnoreCase);
        foreach(var line in text.Split('\n'))
        {
            var parts=line.Trim().Split((char[]?)null,2,StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length!=2)continue;
            settings.TryAdd(parts[0],parts[1].Trim());
        }
        bool? Flag(string key)=>settings.GetValueOrDefault(key)?.ToLowerInvariant() switch
        {
            "yes"=>true,"no"=>false,_=>null
        };
        bool? root=settings.GetValueOrDefault("permitrootlogin")?.ToLowerInvariant() switch
        {
            "yes"=>true,"no" or "prohibit-password" or "without-password" or "forced-commands-only"=>false,_=>null
        };
        var password=Flag("passwordauthentication");var pubkey=Flag("pubkeyauthentication");
        var empty=Flag("permitemptypasswords");var strict=Flag("strictmodes");
        return new(password,pubkey,empty,root,strict,Flag("allowtcpforwarding"),Flag("x11forwarding"),
            password.HasValue&&pubkey.HasValue&&empty.HasValue&&root.HasValue&&strict.HasValue);
    }
}
