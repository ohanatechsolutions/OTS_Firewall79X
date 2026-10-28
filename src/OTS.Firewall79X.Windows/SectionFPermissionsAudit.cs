using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace OTS.Firewall79X.Windows;

/// <summary>Bounded, read-only DACL inspection for selected OTS and Windows paths.
/// Any broad write ACE is a review indicator, NOT a computed effective access check:
/// deny precedence, object inheritance, owner privilege, and device filesystem
/// semantics can change actual rights. Never modifies an ACL.</summary>
public static class SectionFPermissionsAudit
{
    private const uint DaclSecurityInformation=4;
    private const int WriteData=0x0002, AppendData=0x0004, WriteEa=0x0010,
        WriteAttributes=0x0100, Delete=0x00010000, WriteDac=0x00040000, WriteOwner=0x00080000,
        GenericWrite=unchecked((int)0x40000000), GenericAll=0x10000000;

    [DllImport("advapi32.dll",EntryPoint="GetFileSecurityW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSecurity(string path,uint securityInfo,
        [Out] byte[]? descriptor,uint length,out uint required);

    public sealed record Result(string Label,bool? BroadWriteIndicator,string Evidence);
    private static bool BroadSid(string? sid)=>sid is
        "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545" or "S-1-5-7";
    private static bool WriteMask(int mask)=>
        (mask&(WriteData|AppendData|WriteEa|WriteAttributes|Delete|WriteDac|WriteOwner|GenericWrite|GenericAll))!=0;
    public static bool HasPotentialBroadWriteAce(RawSecurityDescriptor descriptor)
    {
        if(descriptor.DiscretionaryAcl==null)return true; // null DACL grants full access
        foreach(GenericAce entry in descriptor.DiscretionaryAcl)
            if(entry is QualifiedAce allow&&allow.AceQualifier==AceQualifier.AccessAllowed&&
               BroadSid(allow.SecurityIdentifier?.Value)&&WriteMask(allow.AccessMask))
                return true;
        return false;
    }
    public static Result Read(string label,string path)
    {
        if(string.IsNullOrWhiteSpace(path)||path.Length>1024)
            return new(label,null,"ACL path invalid or above limit");
        if(!File.Exists(path)&&!Directory.Exists(path))
            return new(label,null,"Path not present; DACL not assessed");
        try
        {
            _=GetFileSecurity(path,DaclSecurityInformation,null,0,out uint needed);
            if(needed is <20 or >128*1024)
                return new(label,null,"DACL unreadable or exceeds 128 KiB limit");
            var buffer=new byte[checked((int)needed)];
            if(!GetFileSecurity(path,DaclSecurityInformation,buffer,(uint)buffer.Length,out uint read)||
               read>buffer.Length)
                return new(label,null,"DACL API returned an error; status unknown ("+Marshal.GetLastWin32Error()+")");
            var descriptor=new RawSecurityDescriptor(buffer,0);
            var potentiallyBroad=HasPotentialBroadWriteAce(descriptor);
            return new(label,potentiallyBroad,potentiallyBroad
                ?"Possible broad WRITE allow ACE or null DACL; human effective-access review required"
                :"No obvious broad WRITE allow ACE among Everyone/Authenticated Users/Users/Anonymous; effective access is NOT established");
        }
        catch(Exception ex)when(ex is ArgumentException or System.Security.SecurityException or UnauthorizedAccessException or InvalidOperationException)
        {return new(label,null,"DACL decoding/access unavailable: "+ex.GetType().Name);}
    }
}
