using System.Runtime.InteropServices;
namespace OTS.Firewall79X.App;

internal static class BoundedClipboard
{
    [DllImport("user32.dll")]private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll")]private static extern bool CloseClipboard();
    [DllImport("user32.dll")]private static extern IntPtr GetClipboardData(uint format);
    [DllImport("kernel32.dll")]private static extern UIntPtr GlobalSize(IntPtr memory);
    [DllImport("kernel32.dll")]private static extern IntPtr GlobalLock(IntPtr memory);
    [DllImport("kernel32.dll")]private static extern bool GlobalUnlock(IntPtr memory);
    public static string? ReadAddressCandidate()
    {
        if(!OpenClipboard(IntPtr.Zero))return null;
        try
        {
            var memory=GetClipboardData(13);if(memory==IntPtr.Zero)return null;
            ulong bytes=GlobalSize(memory).ToUInt64();if(bytes<2||bytes>512||bytes%2!=0)return null;
            var pointer=GlobalLock(memory);if(pointer==IntPtr.Zero)return null;
            try{var text=Marshal.PtrToStringUni(pointer,(int)(bytes/2));return text?.Split('\0',2)[0];}
            finally{GlobalUnlock(memory);}
        }
        finally{CloseClipboard();}
    }
}
