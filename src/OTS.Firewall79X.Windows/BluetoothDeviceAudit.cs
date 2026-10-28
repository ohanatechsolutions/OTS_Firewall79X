using System.Runtime.InteropServices;

namespace OTS.Firewall79X.Windows;

/// <summary>Passive, bounded Bluetooth Classic remembered/paired/connected state.
/// Never issues inquiry, pairing prompts, or Bluetooth radio configuration changes.
/// BLE and some device connection states may not be represented by this legacy API.
/// </summary>
public static class BluetoothDeviceAudit
{
    public sealed record Device(string Id,bool Connected,bool Remembered,bool Authenticated);
    public sealed record Result(bool Available,IReadOnlyList<Device> Devices,string Evidence);
    [StructLayout(LayoutKind.Sequential)]
    private struct Search
    {
        public uint Size;
        public int ReturnAuthenticated,ReturnRemembered,ReturnUnknown,ReturnConnected,IssueInquiry;
        public byte TimeoutMultiplier;
        public IntPtr Radio;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime
    {
        public ushort Year,Month,DayOfWeek,Day,Hour,Minute,Second,Milliseconds;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct Info
    {
        public uint Size;
        public ulong Address;
        public uint ClassOfDevice;
        public int Connected,Remembered,Authenticated;
        public SystemTime LastSeen,LastUsed;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=248)]
        public string Name;
    }
    [DllImport("bthprops.cpl",SetLastError=true)]
    private static extern IntPtr BluetoothFindFirstDevice(ref Search search,ref Info info);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindNextDevice(IntPtr search,ref Info info);
    [DllImport("bthprops.cpl",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindDeviceClose(IntPtr search);

    public static Result Read()
    {
        if(!OperatingSystem.IsWindows())return new(false,[],"Bluetooth Windows API unavailable on this OS");
        IntPtr handle=IntPtr.Zero;
        try
        {
            var search=new Search
            {
                Size=(uint)Marshal.SizeOf<Search>(),ReturnAuthenticated=1,
                ReturnRemembered=1,ReturnConnected=1,ReturnUnknown=0,
                IssueInquiry=0,TimeoutMultiplier=0,Radio=IntPtr.Zero
            };
            var info=new Info{Size=(uint)Marshal.SizeOf<Info>(),Name=string.Empty};
            handle=BluetoothFindFirstDevice(ref search,ref info);
            if(handle==IntPtr.Zero)
            {
                int error=Marshal.GetLastWin32Error();
                return error is 259 or 1168 or 0
                    ?new(true,[],"No cached Bluetooth Classic device entries; BLE devices not assessed")
                    :new(false,[],"Bluetooth device inventory unavailable: Win32 "+error);
            }
            var found=new Dictionary<string,Device>(StringComparer.OrdinalIgnoreCase);
            do
            {
                string key=info.Address.ToString("X12");
                if(info.Address!=0)
                    found[key]=new(key,info.Connected!=0,info.Remembered!=0,info.Authenticated!=0);
                if(found.Count>=256)break;
                info=new Info{Size=(uint)Marshal.SizeOf<Info>(),Name=string.Empty};
            }while(BluetoothFindNextDevice(handle,ref info));
            return new(true,found.Values.ToArray(),
                $"{found.Count} cached Bluetooth Classic device records (no active inquiry)");
        }
        catch(Exception ex)when(ex is DllNotFoundException or EntryPointNotFoundException or
            BadImageFormatException or ArgumentException or InvalidDataException)
        {
            return new(false,[],"Bluetooth cached-device inspection unavailable: "+ex.GetType().Name);
        }
        finally {if(handle!=IntPtr.Zero)BluetoothFindDeviceClose(handle);}
    }
}
