using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OTS.Firewall79X.Windows;

/// <summary>Read-only host defense configuration indicators; never modifies policy.
/// UNKNOWN values are not counted as success.</summary>
public static class HostHardeningAudit
{
    [DllImport("kernel32.dll", EntryPoint="GetSystemDEPPolicy")]
    private static extern uint GetSystemDepPolicy();

    public sealed record Result(string Summary, bool UacEnabled, bool DepEnabled, bool? LsaProtected, bool? Smb1Disabled);
    private static int? Dword(string subkey, string value)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subkey);
            return key?.GetValue(value) is int v ? v : null;
        }
        catch(System.Security.SecurityException) { return null; }
        catch(UnauthorizedAccessException) { return null; }
    }
    public static Result Read()
    {
        var uac = Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","EnableLUA");
        var lsa = Dword(@"SYSTEM\CurrentControlSet\Control\Lsa","RunAsPPL");
        var smb = Dword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters","SMB1");
        uint? dep=null;
        try { dep=GetSystemDepPolicy(); }
        catch(EntryPointNotFoundException) { }
        var details = new[]
        {
            $"UAC={(uac is null?"unknown":uac==1?"enabled":"disabled")}",
            $"DEP={(dep is null?"unknown":dep is 0?"off":dep is >=1 and <=3?"configured":"unknown")}",
            $"LSA protection={(lsa is null?"unknown":lsa is 1 or 2?"configured":"disabled")}",
            $"SMBv1 server={(smb is null?"unknown":smb==0?"explicitly disabled":"potentially enabled")}"
        };
        return new(string.Join("; ",details),uac==1,dep is >=1 and <=3,lsa is null?null:lsa is 1 or 2,smb is null?null:smb==0);
    }
}
