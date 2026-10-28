using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OTS.Firewall79X.Windows;

/// <summary>Read-only native Windows Bluetooth radio inspection. No pairing,
/// discovery, or connectable settings are modified by OTS.</summary>
public static class BluetoothRadioAudit
{
    public sealed record Result(bool Available,int Radios,int Discoverable,int Connectable,string Evidence);
    [StructLayout(LayoutKind.Sequential)] private struct Search { public uint Size; }
    [DllImport("bthprops.cpl",SetLastError=true)]
    private static extern IntPtr BluetoothFindFirstRadio(ref Search search,out IntPtr radio);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindNextRadio(IntPtr search,out IntPtr radio);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindRadioClose(IntPtr search);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothIsDiscoverable(IntPtr radio);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothIsConnectable(IntPtr radio);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public static Result Read()
    {
        if(!OperatingSystem.IsWindows())return new(false,0,0,0,"Windows Bluetooth API unavailable on this OS");
        IntPtr searchHandle=IntPtr.Zero,radio=IntPtr.Zero;
        int count=0,discoverable=0,connectable=0;
        try
        {
            var parameters=new Search{Size=(uint)Marshal.SizeOf<Search>()};
            searchHandle=BluetoothFindFirstRadio(ref parameters,out radio);
            if(searchHandle==IntPtr.Zero)
            {
                int error=Marshal.GetLastWin32Error();
                if(error is 259 or 1168)return new(true,0,0,0,"Native Bluetooth radio enumeration found no active local radio");
                return new(false,0,0,0,"Bluetooth radio enumeration failed: Win32 "+error);
            }
            while(radio!=IntPtr.Zero)
            {
                try
                {
                    if(++count>16)throw new InvalidDataException("Bluetooth radio limit exceeded");
                    if(BluetoothIsDiscoverable(radio))discoverable++;
                    if(BluetoothIsConnectable(radio))connectable++;
                }
                finally{CloseHandle(radio);radio=IntPtr.Zero;}
                if(!BluetoothFindNextRadio(searchHandle,out radio))break;
            }
            return new(true,count,discoverable,connectable,
                $"{count} radios; {discoverable} discoverable; {connectable} connectable; native radio report only");
        }
        catch(Exception e)when(e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or Win32Exception or InvalidDataException)
        {
            return new(false,count,discoverable,connectable,"Bluetooth native inspection failed: "+e.GetType().Name);
        }
        finally
        {
            if(radio!=IntPtr.Zero)CloseHandle(radio);
            if(searchHandle!=IntPtr.Zero)BluetoothFindRadioClose(searchHandle);
        }
    }
}
