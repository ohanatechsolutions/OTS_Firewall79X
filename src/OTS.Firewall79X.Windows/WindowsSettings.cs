using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class WindowsSettings : ISettingStore
{
    // Explicit allowlist. Journal keys must never become arbitrary registry writes.
    public const string AutoRun="machine.autorun.disabled";
    public const string NoAutorun="machine.autorun.command.disabled";
    public const string NoAutoplayNonVolume="machine.autoplay.nonvolume.disabled";
    public const string SmartScreen="machine.smartscreen.shell.enabled";
    public static readonly IReadOnlySet<string> SafeHardeningKeys =
        new HashSet<string>(StringComparer.Ordinal){AutoRun,NoAutorun,NoAutoplayNonVolume,SmartScreen};
    private const string Explorer=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string Shell=@"SOFTWARE\Policies\Microsoft\Windows\System";
    private static (string Path,string Name) Location(string key)=>key switch
    {
        AutoRun=>(Explorer,"NoDriveTypeAutoRun"),
        NoAutorun=>(Explorer,"NoAutorun"),
        NoAutoplayNonVolume=>(Explorer,"NoAutoplayfornonVolume"),
        SmartScreen=>(Shell,"EnableSmartScreen"),
        _=>throw new ArgumentException("Setting is not in the allowlist",nameof(key))
    };
    public string? Read(string key)
    {
        var (path,name)=Location(key);
        using var registry=Registry.LocalMachine.OpenSubKey(path);
        if(registry?.GetValue(name)==null)return null;
        if(registry.GetValueKind(name)!=RegistryValueKind.DWord)
            return "non-DWORD:"+registry.GetValueKind(name); // observed external type: preserve on OFF
        return ((int)registry.GetValue(name)!).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
    public void Write(string key,string? value)
    {
        var (path,name)=Location(key);
        int? number=value==null?null:int.TryParse(value,System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,out var n)?n:null;
        // Restore must accept the exact DWORD that existed before OTS changed it.
        // Enforcement values are constrained at the only journal.Apply call sites.
        if(value!=null&&number==null)
            throw new ArgumentException("Invalid DWORD journal value",nameof(value));
        using var registry=Registry.LocalMachine.CreateSubKey(path,true)
            ??throw new UnauthorizedAccessException("Hardening registry location unavailable");
        if(registry.GetValue(name)!=null&&registry.GetValueKind(name)!=RegistryValueKind.DWord)
            throw new InvalidDataException("Refusing to overwrite a non-DWORD policy");
        if(number==null)registry.DeleteValue(name,false);
        else registry.SetValue(name,number.Value,RegistryValueKind.DWord);
    }
}
public sealed class FirewallAudit
{
    public record Rule(string Name,string Direction,string Action,string Protocol,string LocalPorts,string RemoteAddresses,string Profiles,string Application,bool Enabled);
    public (bool Safe,string Description,List<Rule> Rules) Read()
    {
        var type=Type.GetTypeFromProgID("HNetCfg.FwPolicy2")??throw new NotSupportedException("Windows Firewall COM unavailable");
        dynamic policy=Activator.CreateInstance(type)!;
        try
        {
            bool safe=true;List<string> profiles=[];
            foreach(int id in new[]{1,2,4})
            {
                bool enabled=policy.FirewallEnabled[id];int inbound=(int)policy.DefaultInboundAction[id];
                safe&=enabled&&inbound==0;profiles.Add($"{id}: enabled={enabled}, inbound={(inbound==0?"block":"allow")}");
            }
            List<Rule> rules=[];
            foreach(dynamic rule in policy.Rules)
            {
                try{rules.Add(new((string)rule.Name,((int)rule.Direction).ToString(),((int)rule.Action).ToString(),((int)rule.Protocol).ToString(),(string?)rule.LocalPorts??"",(string?)rule.RemoteAddresses??"",((int)rule.Profiles).ToString(),(string?)rule.ApplicationName??"",(bool)rule.Enabled));}
                finally{System.Runtime.InteropServices.Marshal.ReleaseComObject(rule);}
                if(rules.Count>=20000)throw new InvalidDataException("Firewall rule budget exceeded");
            }
            return (safe,string.Join("; ",profiles),rules);
        }
        finally{System.Runtime.InteropServices.Marshal.ReleaseComObject(policy);}
    }
    public static string Analyze(IEnumerable<Rule> rules)
    {
        return FirewallOverlap.Analyze(rules.Select(r => new FirewallRuleView(r.Name, r.Direction, r.Action,
            r.Protocol, r.LocalPorts, r.RemoteAddresses, r.Profiles, r.Application, r.Enabled))).ToString();
    }
}
