using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
namespace OTS.Firewall79X.App;

internal sealed class DesktopNotifications : IDisposable
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct IconData
    {
        public uint Size;public IntPtr Window;public uint Id,Flags,Callback;public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)]public string Tip;
        public uint State,StateMask;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Info;
        public uint Timeout;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)]public string Title;
        public uint InfoFlags;public Guid Guid;public IntPtr BalloonIcon;
    }
    [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool Shell_NotifyIcon(uint message,ref IconData data);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]private static extern IntPtr LoadIcon(IntPtr instance,IntPtr name);
    private IconData data;public bool Ready {get;private set;}
    public DesktopNotifications(Window window)
    {
        data=new(){Size=(uint)Marshal.SizeOf<IconData>(),Window=new WindowInteropHelper(window).EnsureHandle(),Id=79,Flags=2|4,Icon=LoadIcon(IntPtr.Zero,(IntPtr)32518),Tip="OTS Firewall79X",Info="",Title=""};
        Ready=Shell_NotifyIcon(0,ref data);
    }
    public bool Show(string title,string detail)
    {
        data.Flags=0x10;data.Title=title[..Math.Min(63,title.Length)];data.Info=detail[..Math.Min(255,detail.Length)];data.InfoFlags=2;data.Timeout=10000;
        Ready=Shell_NotifyIcon(1,ref data);
        if(!Ready){data.Flags=2|4|0x10;Ready=Shell_NotifyIcon(0,ref data);}
        return Ready;
    }
    public void Dispose(){Shell_NotifyIcon(2,ref data);Ready=false;}
}
