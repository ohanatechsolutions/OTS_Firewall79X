using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace OTS.Firewall79X.Windows;

public static class PipeServerIdentity
{
    [StructLayout(LayoutKind.Sequential)]private struct ServiceStatusProcess {public uint ServiceType,State,Controls,Win32Exit,SpecificExit,Checkpoint,WaitHint,ProcessId,Flags;}
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint processId);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatusProcess status,int size,out int needed);
    [DllImport("advapi32.dll")]private static extern bool CloseServiceHandle(IntPtr handle);
    public static void Verify(SafePipeHandle pipe)
    {
        if(!GetNamedPipeServerProcessId(pipe,out var actual))throw new Win32Exception(Marshal.GetLastWin32Error());
        var manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service=OpenService(manager,"OTSFirewall79X",4);if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            try{if(!QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<ServiceStatusProcess>(),out _))throw new Win32Exception(Marshal.GetLastWin32Error());if(status.ProcessId==0||status.ProcessId!=actual||status.State is not (2 or 4))throw new UnauthorizedAccessException("Named-pipe endpoint is not the registered OTS security service");}
            finally{CloseServiceHandle(service);}
        }
        finally{CloseServiceHandle(manager);}
    }
}
