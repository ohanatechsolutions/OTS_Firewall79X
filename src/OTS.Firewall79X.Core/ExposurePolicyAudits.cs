using System.Net;
using System.Net.Sockets;

namespace OTS.Firewall79X.Core;

/// <summary>Conservative parser for *global* sshd configuration only.
/// Include, Match, custom startup paths and command-line overrides require effective
/// configuration verification. A partial parse never asserts hardened access.</summary>
public static class OpenSshPolicyAudit
{
    public sealed record Result(bool? PasswordAuthentication, bool? PublicKeyAuthentication,
        bool? PermitEmptyPasswords, bool RequiresEffectiveVerification, int InspectedLines)
    {
        public bool ExplicitlyHardened => PasswordAuthentication == false &&
            PublicKeyAuthentication == true && PermitEmptyPasswords == false &&
            !RequiresEffectiveVerification;
        public bool ExplicitWeakness => PasswordAuthentication == true || PermitEmptyPasswords == true ||
            PublicKeyAuthentication == false;
    }

    public static Result Parse(string config)
    {
        if (config.Length>256*1024)throw new InvalidDataException("OpenSSH configuration exceeds audit budget");
        bool? password=null, publicKey=null, empty=null;
        bool conditional=false, global=true;int count=0;
        foreach (var raw in config.Split('\n'))
        {
            if(++count>10000)throw new InvalidDataException("OpenSSH configuration line budget exceeded");
            var line=raw.Trim();var comment=line.IndexOf('#');
            if(comment>=0)line=line[..comment].Trim();
            if(line.Length==0)continue;
            var parts=line.Split((char[]?)null,2,StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length<2)continue;
            var key=parts[0].ToLowerInvariant();var value=parts[1].Trim();
            if(key=="include"){conditional=true;continue;}
            if(key=="match"){conditional=true;global=false;continue;}
            if(!global)continue; // user-specific Match settings are never assumed global
            var v=value.Split((char[]?)null,2,StringSplitOptions.RemoveEmptyEntries)[0].ToLowerInvariant();
            bool? parsed=v switch {"yes"=>true,"no"=>false,_=>null};
            switch(key)
            {
                // OpenSSH sshd_config uses first obtained value for each global keyword.
                case "passwordauthentication": if(password is null)password=parsed;break;
                case "pubkeyauthentication": if(publicKey is null)publicKey=parsed;break;
                case "permitemptypasswords": if(empty is null)empty=parsed;break;
            }
        }
        return new(password,publicKey,empty,conditional,count);
    }
}

/// <summary>Read-only local TCP listening-port classification for common Docker
/// management API endpoints. A port is evidence of possible exposure, not proof of
/// which protocol or service owns it.</summary>
public static class ContainerManagementAudit
{
    public sealed record Endpoint(string Address,int Port,bool AnyAddress,bool Loopback);
    public sealed record Result(int PlaintextCandidates,int RemotePlaintextCandidates,int TlsCandidates,
        bool ObservedAnyDockerService, IReadOnlyList<Endpoint> Observed)
    {
        public bool RequiresAttention => RemotePlaintextCandidates>0 || PlaintextCandidates>0;
    }
    public static Endpoint? ParseListeningAddress(string? local)
    {
        if(string.IsNullOrWhiteSpace(local)||local.Length>128||!local.StartsWith('['))return null;
        int delimiter=local.LastIndexOf("]:",StringComparison.Ordinal);
        if(delimiter<=1||!int.TryParse(local[(delimiter+2)..],out var port)||port is not (2375 or 2376))return null;
        var address=local[1..delimiter];
        if(!IPAddress.TryParse(address,out var ip))return null;
        bool any=IPAddress.Any.Equals(ip)||IPAddress.IPv6Any.Equals(ip);
        return new(ip.ToString(),port,any,IPAddress.IsLoopback(ip));
    }
    public static Result Analyze(IEnumerable<string> listeners,bool dockerServicePresent)
    {
        var endpoints=listeners.Select(ParseListeningAddress).Where(x=>x!=null).Cast<Endpoint>().Take(100).ToArray();
        return new(endpoints.Count(x=>x.Port==2375),
            endpoints.Count(x=>x.Port==2375&&!x.Loopback),
            endpoints.Count(x=>x.Port==2376),dockerServicePresent,endpoints);
    }
}
