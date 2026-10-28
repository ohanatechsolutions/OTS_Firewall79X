using Microsoft.Win32;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public sealed class WindowsSettings : ISettingStore
{
    public const string AutoRun="machine.autorun.disabled";
    public string? Read(string key)
    {
        if(key==AutoRun){using var r=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");return r?.GetValue("NoDriveTypeAutoRun")?.ToString();}
        throw new ArgumentException("Setting is not in the allowlist");
    }
    public void Write(string key,string? value)
    {
        if(key!=AutoRun)throw new ArgumentException("Setting is not in the allowlist");
        using var r=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
        if(value==null)r.DeleteValue("NoDriveTypeAutoRun",false);else r.SetValue("NoDriveTypeAutoRun",int.Parse(value),RegistryValueKind.DWord);
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
        var enabled=rules.Where(r=>r.Enabled).ToArray();
        int duplicate=enabled.GroupBy(r=>new{r.Direction,r.Action,r.Protocol,r.LocalPorts,r.RemoteAddresses,r.Profiles,r.Application}).Sum(g=>Math.Max(0,g.Count()-1));
        int conflict=enabled.GroupBy(r=>new{r.Direction,r.Protocol,r.LocalPorts,r.RemoteAddresses,r.Profiles,r.Application}).Count(g=>g.Select(r=>r.Action).Distinct().Count()>1);
        int broad=enabled.Count(r=>r.Direction=="1"&&r.Action=="1"&&r.RemoteAddresses=="*"&&string.IsNullOrEmpty(r.Application)&&r.LocalPorts is "*" or "");
        return $"{enabled.Length} enabled rules; {duplicate} exact duplicate matches; {conflict} opposing-action matches; {broad} broad inbound allows. Partial overlaps and policy precedence require manual review.";
    }
}
