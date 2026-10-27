using System.ComponentModel;
using System.Runtime.InteropServices;
namespace OTS.Firewall79X.Windows;

public static class AuditPolicy
{
    [StructLayout(LayoutKind.Sequential)]private struct Policy {public Guid Subcategory;public uint Flags;public Guid Category;}
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.U1)]private static extern bool AuditQuerySystemPolicy([In] Guid[] categories,uint count,out IntPtr policy);
    [DllImport("advapi32.dll")]private static extern void AuditFree(IntPtr buffer);
    private static uint Read(string suffix)
    {
        var guid=new Guid($"0CCE{suffix}-69AE-11D9-BED3-505054503030");
        if(!AuditQuerySystemPolicy([guid],1,out var buffer))throw new Win32Exception(Marshal.GetLastWin32Error(),"Windows audit policy could not be verified");
        try{var p=Marshal.PtrToStructure<Policy>(buffer);if(p.Subcategory!=guid)throw new InvalidDataException("Unexpected audit-policy response");return p.Flags;}
        finally{AuditFree(buffer);}
    }
    public static (bool Enabled,string Evidence) Coverage(int layer)
    {
        (string Id,uint Required,string Name)[] required=layer switch
        {
            2 or 3 => [("9226",2,"Filtering Platform Connection failures")],
            15 => [("9226",2,"Filtering Platform Connection failures"),("9215",3,"Logon success/failure")],
            24 => [("9210",1,"Security State Change")],
            27 => [("9235",1,"User Account Management"),("9237",1,"Security Group Management"),("921B",1,"Special Logon"),("922F",1,"Audit Policy Change")],
            36 => [("922B",1,"Process Creation")],
            41 => [("9215",2,"Logon failures")],
            45 => [("9215",3,"Logon success/failure"),("921B",1,"Special Logon")],
            _ => []
        };
        List<string> missing=[];
        foreach(var rule in required)if((Read(rule.Id)&rule.Required)!=rule.Required)missing.Add(rule.Name);
        if(layer==36&&!(SystemQueries.Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled") is int enabled&&enabled==1))missing.Add("Process-creation command-line inclusion");
        return missing.Count==0?(true,"Required system audit subcategories verified"):(false,"Required Windows audit settings are disabled: "+string.Join(", ",missing));
    }
}
