using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public static class WirelessAudit
{
    public sealed record Network(string Interface,string Ssid,string Bssid,bool SecurityEnabled,uint Authentication,uint Cipher,uint Signal)
    {public bool Weak=>!SecurityEnabled||Cipher is 0 or 1 or 2 or 5 or 257;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct InterfaceInfo {public Guid Id;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Description;public uint State;}
    [StructLayout(LayoutKind.Sequential)] private struct Ssid {public uint Length;[MarshalAs(UnmanagedType.ByValArray,SizeConst=32)]public byte[] Bytes;}
    [StructLayout(LayoutKind.Sequential)] private struct Association {public Ssid Ssid;public uint BssType;[MarshalAs(UnmanagedType.ByValArray,SizeConst=6)]public byte[] Bssid;public uint PhyType,PhyIndex,Signal,RxRate,TxRate;}
    [StructLayout(LayoutKind.Sequential)] private struct Security {public int Enabled,OneX;public uint Authentication,Cipher;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Attributes {public uint State,Mode;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Profile;public Association Association;public Security Security;}
    [DllImport("wlanapi.dll")]private static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
    [DllImport("wlanapi.dll")]private static extern uint WlanEnumInterfaces(IntPtr handle,IntPtr reserved,out IntPtr list);
    [DllImport("wlanapi.dll")]private static extern uint WlanQueryInterface(IntPtr handle,ref Guid id,uint opcode,IntPtr reserved,out uint size,out IntPtr data,out uint opcodeType);
    [DllImport("wlanapi.dll")]private static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
    [DllImport("wlanapi.dll")]private static extern void WlanFreeMemory(IntPtr memory);
    public static List<Network> Read()
    {
        uint rc=WlanOpenHandle(2,IntPtr.Zero,out _,out var handle);if(rc!=0)throw new Win32Exception((int)rc,"WLAN service/API unavailable");
        try
        {
            rc=WlanEnumInterfaces(handle,IntPtr.Zero,out var list);if(rc!=0)throw new Win32Exception((int)rc);
            try
            {
                int count=Marshal.ReadInt32(list);if(count<0||count>256)throw new InvalidDataException("Invalid WLAN interface count");List<Network> networks=[];
                for(int i=0;i<count;i++)
                {
                    var info=Marshal.PtrToStructure<InterfaceInfo>(list+8+i*Marshal.SizeOf<InterfaceInfo>());if(info.State!=1)continue;
                    rc=WlanQueryInterface(handle,ref info.Id,7,IntPtr.Zero,out uint size,out var data,out _);if(rc!=0)throw new Win32Exception((int)rc,"WLAN connection attributes unavailable; privacy policy may restrict access");
                    try{if(size<Marshal.SizeOf<Attributes>())throw new InvalidDataException("Truncated WLAN attributes");var a=Marshal.PtrToStructure<Attributes>(data);if(a.Association.Ssid.Length>32)throw new InvalidDataException("Invalid SSID size");networks.Add(new(info.Id.ToString(),Wire.Clean(Encoding.UTF8.GetString(a.Association.Ssid.Bytes,0,(int)a.Association.Ssid.Length)),Convert.ToHexString(a.Association.Bssid),a.Security.Enabled!=0,a.Security.Authentication,a.Security.Cipher,a.Association.Signal));}
                    finally{WlanFreeMemory(data);}
                }
                return networks;
            }
            finally{WlanFreeMemory(list);}
        }
        finally{WlanCloseHandle(handle,IntPtr.Zero);}
    }
}
