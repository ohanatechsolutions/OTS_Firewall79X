using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OTS.Firewall79X.Windows;

/// <summary>Additional, read-only Section F evidence. Unknown and inaccessible providers
/// are explicitly recorded rather than silently interpreted as secure.</summary>
public static class SectionFAudits
{
    private static int? Dword(string path,string key)
    {
        try
        {
            using var r=Registry.LocalMachine.OpenSubKey(path);
            if(r?.GetValue(key)==null||r.GetValueKind(key)!=RegistryValueKind.DWord)return null;
            return (int)r.GetValue(key)!;
        }
        catch(System.Security.SecurityException){return null;}
        catch(UnauthorizedAccessException){return null;}
        catch(IOException){return null;}
    }

    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process,int policy,out uint flags,int length);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("netapi32.dll",CharSet=CharSet.Unicode)]
    private static extern uint NetUserModalsGet(string? server,uint level,out IntPtr data);
    [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);
    [StructLayout(LayoutKind.Sequential)]
    private struct UserModals0 { public uint MinPasswordLength,MaxPasswordAge,MinPasswordAge,ForceLogoff,PasswordHistoryLength; }
    [StructLayout(LayoutKind.Sequential)]
    private struct UserModals3 { public uint LockoutDuration,LockoutObservationWindow,LockoutThreshold; }

    public static string HostEvidence()
    {
        var findings=new List<string>();
        try
        {
            if(GetProcessMitigationPolicy(GetCurrentProcess(),1,out var flags,sizeof(uint)))
                findings.Add("ASLR (OTS service process only): bottom-up="+((flags&1)!=0)+", mandatory relocations="+((flags&2)!=0)+", high entropy="+((flags&4)!=0));
            else findings.Add("ASLR: process mitigation provider unavailable; machine-wide ASLR unverified");
        }
        catch(Exception ex)when(ex is EntryPointNotFoundException or DllNotFoundException)
        {findings.Add("ASLR: unsupported API; machine-wide ASLR unverified");}
        var idle=Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","InactivityTimeoutSecs");
        findings.Add(idle is null?"Machine inactivity-lock policy: unknown (user screensaver policies not audited)"
            :idle==0?"Machine inactivity-lock policy: disabled (0 seconds)":"Machine inactivity-lock policy: "+idle+" seconds; interactive session policy may differ");
        var uacAdmin=Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","ConsentPromptBehaviorAdmin");
        findings.Add("Admin elevation consent policy: "+(uacAdmin?.ToString()??"unknown"));
        try
        {
            IntPtr p=IntPtr.Zero;
            try
            {
                var status=NetUserModalsGet(null,0,out p);
                if(status==0&&p!=IntPtr.Zero)
                {
                    var v=Marshal.PtrToStructure<UserModals0>(p);
                    findings.Add("Local password policy: minimum length="+v.MinPasswordLength+
                        "; history="+v.PasswordHistoryLength+"; maximum age days="+(v.MaxPasswordAge==uint.MaxValue?"unlimited":(v.MaxPasswordAge/86400).ToString()));
                }
                else findings.Add("Local password policy: NetUserModalsGet unavailable ("+status+")");
            }
            finally{if(p!=IntPtr.Zero)NetApiBufferFree(p);}
            p=IntPtr.Zero;
            try
            {
                var status=NetUserModalsGet(null,3,out p);
                if(status==0&&p!=IntPtr.Zero)
                {
                    var v=Marshal.PtrToStructure<UserModals3>(p);
                    findings.Add("Local lockout threshold: "+v.LockoutThreshold+" (0=disabled)");
                }
                else findings.Add("Local lockout policy: unavailable ("+status+")");
            }
            finally{if(p!=IntPtr.Zero)NetApiBufferFree(p);}
        }
        catch(Exception ex)when(ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
        {findings.Add("Account policy provider unavailable");}
        try
        {
            var vbs=SystemQueries.Wmi(@"root\Microsoft\Windows\DeviceGuard",
                "SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard","VirtualizationBasedSecurityStatus");
            findings.Add(vbs.Count>0?"VBS status code: "+vbs[0]["VirtualizationBasedSecurityStatus"]+" (0=off, 1=enabled, 2=running)"
                :"VBS/Device Guard state unavailable");
        }
        catch(Exception ex)when(ex is System.Management.ManagementException or UnauthorizedAccessException or COMException or System.Security.SecurityException)
        {findings.Add("VBS/Device Guard provider unavailable: "+ex.GetType().Name);}
        // Windows service is not the interactive user: do not claim a user screen lock is verified.
        return string.Join("; ",findings);
    }

    private static int? Port(string endpoint)
    {
        int i=endpoint.LastIndexOf(':');
        return i>=0&&int.TryParse(endpoint.AsSpan(i+1),out var port)&&port is >=1 and <=65535?port:null;
    }
    public static bool IsManagementPort(string endpoint)=>Port(endpoint) is 3389 or 5985 or 5986 or 16992 or 16993 or 16994 or 16995;
    public static bool NonLoopbackListener(string endpoint)
    {
        int i=endpoint.LastIndexOf(':');if(i<=0)return false;
        var addr=endpoint[..i].Trim('[',']');
        return IPAddress.TryParse(addr,out var ip)&&!IPAddress.IsLoopback(ip);
    }
    public static string Exposure(IEnumerable<string> localListeningEndpoints)
    {
        var endpoints=localListeningEndpoints.Take(20000).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var nonloop=endpoints.Count(NonLoopbackListener);
        var mgmt=endpoints.Count(x=>NonLoopbackListener(x)&&IsManagementPort(x));
        return $"{endpoints.Length} local TCP listeners, {nonloop} bound beyond loopback, {mgmt} on common management ports. "+
            "Binding to a wildcard/non-loopback address does NOT prove access from the Internet. No remote probe has been authorized or performed.";
    }
    public static string RemoteHardware(IEnumerable<string> listeners)
    {
        var report=new List<string>();
        var adapters=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.NetworkInterfaceType!=NetworkInterfaceType.Loopback).ToArray();
        report.Add("Network adapters="+adapters.Length);
        try
        {
            var wake=SystemQueries.Wmi(@"root\wmi",
                "SELECT InstanceName,Enable FROM MSPower_DeviceWakeEnable","InstanceName","Enable");
            report.Add(wake.Count==0?"Device wake settings unavailable (Wake-on-LAN unknown)"
                :$"Device wake capabilities: {wake.Count} provider records, {wake.Count(x=>x.GetValueOrDefault("Enable")=="True")} enabled; does not prove magic-packet wake");
        }
        catch(Exception ex)when(ex is System.Management.ManagementException or UnauthorizedAccessException)
        {report.Add("Wake provider unavailable: "+ex.GetType().Name);}
        var lms=SystemQueries.Wmi(@"root\cimv2",
            "SELECT Name,State FROM Win32_Service WHERE Name='LMS' OR Name='jhi_service'","Name","State");
        report.Add("Intel local management service records="+lms.Count+" (absence does not rule out firmware AMT)");
        var management=listeners.Where(x=>NonLoopbackListener(x)&&IsManagementPort(x)).Take(20).ToArray();
        report.Add("Non-loopback potential management listeners="+management.Length+
            (management.Length==0?"":": "+string.Join(", ",management)));
        var dma=Dword(@"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection","DeviceEnumerationPolicy");
        report.Add("Kernel DMA external-device enumeration policy="+(dma?.ToString()??"unknown; hardware support not verified"));
        report.Add("Intel AMT firmware provisioning, BIOS controls, and externally reachable firmware ports cannot be proven from Windows services alone");
        return string.Join("; ",report);
    }
}

/// <summary>Non-destructive Windows Update Agent scan. The synchronous COM search runs
/// outside the security cycle; a single in-flight task is bounded by concurrency, and
/// the application never claims a clean patch state without a completed scan.</summary>
public static class WindowsMissingUpdateAudit
{
    public sealed record Snapshot(DateTimeOffset Time,int Missing,int SecurityCandidates,string Evidence,bool Verified);
    private static readonly object Gate=new();
    private static Task<Snapshot>? pending;
    private static Snapshot? last;
    private static DateTimeOffset started;
    private static Snapshot Search()
    {
        object? session=null,searcher=null,found=null,updates=null;
        try
        {
            var type=Type.GetTypeFromProgID("Microsoft.Update.Session")??throw new NotSupportedException("Windows Update Agent COM unavailable");
            session=Activator.CreateInstance(type)??throw new IOException("Cannot create Windows Update Agent session");
            dynamic ses=session;ses.ClientApplicationID="OTS Firewall79X read-only audit";
            searcher=ses.CreateUpdateSearcher();dynamic worker=searcher;
            found=worker.Search("IsInstalled=0 and IsHidden=0 and Type='Software'");
            dynamic result=found;updates=result.Updates;dynamic list=updates;
            int count=Math.Min((int)list.Count,4096),security=0;
            for(var i=0;i<count;i++)
            {
                object item=list.Item(i);
                try
                {
                    dynamic u=item;string severity=(string?)u.MsrcSeverity??"";
                    if(severity.Equals("Critical",StringComparison.OrdinalIgnoreCase)||
                       severity.Equals("Important",StringComparison.OrdinalIgnoreCase))security++;
                }
                catch(COMException) { /* severity may be absent */ }
                finally{if(Marshal.IsComObject(item))Marshal.FinalReleaseComObject(item);}
            }
            return new(DateTimeOffset.UtcNow,count,security,
                $"Windows Update Agent completed read-only search: {count} pending software updates, "+
                $"{security} with Critical/Important MSRC severity where published. The severity field is optional; absence is not a clean bill of health. Driver/firmware and third-party CVEs are not covered.",true);
        }
        catch(Exception ex)
        {
            return new(DateTimeOffset.UtcNow,0,0,"Windows Update Agent search unavailable: "+ex.GetType().Name+
                ". Missing-update status is unknown, not zero.",false);
        }
        finally
        {
            foreach(var x in new[]{updates,found,searcher,session})
                if(x!=null&&Marshal.IsComObject(x))Marshal.FinalReleaseComObject(x);
        }
    }
    public static Snapshot? Latest(out string state)
    {
        lock(Gate)
        {
            if(pending?.IsCompleted==true)
            {
                try{last=pending.GetAwaiter().GetResult();}
                catch(Exception ex){last=new(DateTimeOffset.UtcNow,0,0,"Audit failed: "+ex.GetType().Name,false);}
                pending=null;
            }
            if(last!=null&&DateTimeOffset.UtcNow-last.Time<TimeSpan.FromHours(6))
            {state=last.Evidence;return last;}
            if(pending==null)
            {
                started=DateTimeOffset.UtcNow;
                pending=Task.Run(Search);
            }
            state="Read-only Windows Update Agent scan in progress since "+started.ToString("u")+
                "; no result yet (COM search can take several minutes). No third-party CVE match data is configured.";
            return null;
        }
    }
}
