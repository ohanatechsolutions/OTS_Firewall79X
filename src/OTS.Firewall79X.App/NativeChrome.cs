using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
namespace OTS.Firewall79X.App;
internal static class NativeChrome
{
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr window,int attribute,ref int value,int size);
    public static void Apply(Window window)
    {
        int enabled=1;var handle=new WindowInteropHelper(window).Handle;
        if(DwmSetWindowAttribute(handle,20,ref enabled,sizeof(int))<0)
            DwmSetWindowAttribute(handle,19,ref enabled,sizeof(int));
    }
}
