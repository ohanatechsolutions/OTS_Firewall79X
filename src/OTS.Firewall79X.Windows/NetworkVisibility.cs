using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Read-only OS socket tables. UDP has no remote peer in the Windows owner-PID table.</summary>
public static class UdpTable
{
    [DllImport("iphlpapi.dll", SetLastError=true)]
    private static extern uint GetExtendedUdpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
    public static List<Connection> Read()
    {
        List<Connection> sockets=[];
        foreach(int family in new[]{2,23})
        {
            int size=0;uint result=GetExtendedUdpTable(IntPtr.Zero,ref size,false,family,1,0);
            if(result is not (0 or 122))throw new Win32Exception((int)result);
            if(size<4||size>16*1024*1024)throw new InvalidDataException("Invalid UDP table size");
            var memory=Marshal.AllocHGlobal(size);
            try
            {
                result=GetExtendedUdpTable(memory,ref size,false,family,1,0);
                if(result!=0)throw new Win32Exception((int)result);
                var bytes=new byte[size];Marshal.Copy(memory,bytes,0,size);
                int rows=BitConverter.ToInt32(bytes,0),stride=family==2?12:28;
                if(rows<0||4L+(long)rows*stride>size)throw new InvalidDataException("Invalid UDP row count");
                for(int i=0;i<rows&&sockets.Count<8000;i++)
                {
                    int p=4+i*stride, pid=BitConverter.ToInt32(bytes,p+(family==2?8:24));
                    int port=(bytes[p+(family==2?4:20)]<<8)|bytes[p+(family==2?5:21)];
                    IPAddress local=family==2
                        ?new IPAddress(bytes.AsSpan(p,4))
                        :new IPAddress(bytes.AsSpan(p,16),BitConverter.ToUInt32(bytes,p+16));
                    string name="Unavailable";
                    try{using var process=Process.GetProcessById(pid);name=process.ProcessName;}
                    catch(ArgumentException){name="Exited";}
                    catch(Win32Exception){name="Access restricted";}
                    sockets.Add(new(pid,name,$"[{local}]:{port}","", "UDPBound"));
                }
            }
            finally{Marshal.FreeHGlobal(memory);}
        }
        return sockets;
    }
}

/// <summary>Native Windows neighbor provider with IPv4 ARP fallback.
/// Polling cannot establish that all LAN hosts were discovered.</summary>
public static class NeighborInventory
{
    public sealed record Snapshot(Dictionary<string,string> Entries,int IPv6Count,string Source);
    public static Snapshot Read()
    {
        try
        {
            var rows=SystemQueries.Wmi(@"root\StandardCimv2",
                "SELECT InterfaceIndex,IPAddress,LinkLayerAddress,State FROM MSFT_NetNeighbor",
                "InterfaceIndex","IPAddress","LinkLayerAddress","State");
            Dictionary<string,string> found=new(StringComparer.OrdinalIgnoreCase);
            int ipv6=0;
            foreach(var row in rows)
            {
                string address=row["IPAddress"], mac=row["LinkLayerAddress"];
                if(!IPAddress.TryParse(address,out var ip)||!TrafficRules.IsMac(mac)||IPAddress.IsLoopback(ip)||
                    ip.IsIPv6Multicast||ip.AddressFamily==AddressFamily.InterNetwork&&ip.GetAddressBytes()[0]>=224)continue;
                string normalized=new(mac.Where(Uri.IsHexDigit).ToArray());
                string key=row["InterfaceIndex"]+":"+ip;
                if(ip.AddressFamily==AddressFamily.InterNetworkV6)ipv6++;
                if(found.Count<4096)found[key]=normalized.ToUpperInvariant();
            }
            return new(found,ipv6,"Windows MSFT_NetNeighbor (IPv4/IPv6)");
        }
        catch(Exception ex)when(ex is ManagementException or COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new(NetworkTables.Neighbors(),0,"IPv4 ARP fallback; IPv6 neighbor provider unavailable");
        }
    }
    public static HashSet<string> Gateways()
    {
        HashSet<string> ips=new(StringComparer.OrdinalIgnoreCase);
        foreach(var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            try{foreach(var g in nic.GetIPProperties().GatewayAddresses)ips.Add(g.Address.ToString());}
            catch(System.Net.NetworkInformation.NetworkInformationException){}
        }
        return ips;
    }
}

/// <summary>Microsoft Defender Network Protection is an established Windows detection
/// provider; it does not constitute a full packet IDS or third-party signature engine.</summary>
public static class DefenderNetworkIds
{
    public sealed record Status(bool Available,bool ProtectionEnabled,bool AuditOnly,
        string Evidence,string Limitation);
    public static Status Read()
    {
        try
        {
            var preferences=SystemQueries.Wmi(@"root\Microsoft\Windows\Defender",
                "SELECT EnableNetworkProtection FROM MSFT_MpPreference","EnableNetworkProtection").FirstOrDefault();
            var state=SystemQueries.Wmi(@"root\Microsoft\Windows\Defender",
                "SELECT NISEnabled,NISSignatureLastUpdated FROM MSFT_MpComputerStatus",
                "NISEnabled","NISSignatureLastUpdated").FirstOrDefault();
            if(preferences==null||state==null)
                return new(false,false,false,"Defender Network Protection provider did not return preference/status","Unavailable on this Windows edition or another antivirus provider is active.");
            string level=preferences.GetValueOrDefault("EnableNetworkProtection","");
            bool nis=bool.TryParse(state["NISEnabled"],out var active)&&active;
            bool enforcing=level=="1",auditing=level=="2";
            var evidence=$"Windows Defender Network Protection={(enforcing?"Block":auditing?"Audit":"Off/unspecified")}; NIS enabled={nis}; NIS signature timestamp={Wire.Clean(state["NISSignatureLastUpdated"],80)}";
            return new(true,nis&&enforcing,nis&&auditing,evidence,
                "Defender supplies its own detection intelligence and updates. This is only a native Defender network threat event source; it is not an independent packet IDS, rule editor, or proof of all traffic coverage.");
        }
        catch(Exception ex)when(ex is ManagementException or COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new(false,false,false,"Defender Network Protection status unavailable: "+Wire.Clean(ex.Message,180),
                "Cannot infer IDS coverage from a subscribed event channel alone.");
        }
    }
}

/// <summary>Bounded read-only HTTPS Date check and monotonic clock step detection.
/// HTTPS Date is not authenticated NTP or a secure time attestation.</summary>
public sealed class ClockDriftProbe : IDisposable
{
    private readonly HttpClient client=new(new HttpClientHandler {AllowAutoRedirect=false})
        {Timeout=TimeSpan.FromSeconds(3)};
    private long lastTick=-1;
    private DateTimeOffset lastUtc;
    private DateTimeOffset lastProbe=DateTimeOffset.MinValue;
    public sealed record Result(bool ClockStep,bool HasRemoteSample,bool RemoteDrift,
        TimeSpan? Delta,string Evidence);
    private Result? cached;
    public Result Sample()
    {
        var now=DateTimeOffset.UtcNow;long tick=Environment.TickCount64;
        bool step=lastTick>=0&&TrafficRules.ClockStep(lastUtc,lastTick,now,tick,TimeSpan.FromSeconds(90));
        lastTick=tick;lastUtc=now;
        if(cached!=null&&now-lastProbe<TimeSpan.FromMinutes(15)&&!step)
            return cached with{ClockStep=false};
        lastProbe=now;
        try
        {
            using var request=new HttpRequestMessage(HttpMethod.Head,"https://www.cloudflare.com/");
            var watch=Stopwatch.StartNew();
            using var response=client.Send(request,HttpCompletionOption.ResponseHeadersRead,CancellationToken.None);
            watch.Stop();
            if(!response.IsSuccessStatusCode||response.Headers.Date is not DateTimeOffset server)
                throw new InvalidDataException("HTTPS response missing a valid Date header");
            var local=DateTimeOffset.UtcNow;
            var delta=local-server;
            bool drift=TrafficRules.RemoteClockDrift(local,server,watch.Elapsed,TimeSpan.FromSeconds(120));
            cached=new(step,true,drift,delta,
                $"Authenticated HTTPS Date comparison (cloudflare.com), local minus server {delta.TotalSeconds:F0}s; round trip {watch.Elapsed.TotalMilliseconds:F0}ms");
        }
        catch(Exception ex)when(ex is HttpRequestException or TaskCanceledException or InvalidOperationException or InvalidDataException)
        {
            cached=new(step,false,false,null,"Independent HTTPS clock comparison unavailable: "+Wire.Clean(ex.Message,180));
        }
        return cached;
    }
    public void Dispose()=>client.Dispose();
}
