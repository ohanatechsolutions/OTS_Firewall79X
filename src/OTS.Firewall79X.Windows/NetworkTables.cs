using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public static class NetworkTables
{
    [DllImport("iphlpapi.dll",SetLastError=true)] private static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetIpNetTable(IntPtr table,ref int size,bool order);
    public static List<Connection> Connections()
    {
        List<Connection> result=[];
        foreach(var family in new[]{2,23})
        {
            int size=0;uint code=GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,5,0);
            if(code is not (0 or 122))throw new Win32Exception((int)code);
            if(size<4||size>16*1024*1024)throw new InvalidDataException("Invalid TCP table size");
            var memory=Marshal.AllocHGlobal(size);
            try
            {
                code=GetExtendedTcpTable(memory,ref size,false,family,5,0);if(code!=0)throw new Win32Exception((int)code);
                var b=new byte[size];Marshal.Copy(memory,b,0,size);int count=BitConverter.ToInt32(b,0),stride=family==2?24:56;
                if(count<0||4L+(long)count*stride>size)throw new InvalidDataException("Invalid TCP count");
                for(int i=0;i<count&&result.Count<8000;i++)
                {
                    int p=4+i*stride,state,pid;IPAddress local,remote;int lp,rp;
                    if(family==2){state=BitConverter.ToInt32(b,p);local=new IPAddress(b.AsSpan(p+4,4));lp=Port(b,p+8);remote=new IPAddress(b.AsSpan(p+12,4));rp=Port(b,p+16);pid=BitConverter.ToInt32(b,p+20);}
                    else{local=new IPAddress(b.AsSpan(p,16),BitConverter.ToUInt32(b,p+16));lp=Port(b,p+20);remote=new IPAddress(b.AsSpan(p+24,16),BitConverter.ToUInt32(b,p+40));rp=Port(b,p+44);state=BitConverter.ToInt32(b,p+48);pid=BitConverter.ToInt32(b,p+52);}
                    string process="Unavailable";try{using var proc=Process.GetProcessById(pid);process=proc.ProcessName;}catch(ArgumentException){process="Exited";}catch(Win32Exception){process="Access restricted";}
                    result.Add(new(pid,process,$"[{local}]:{lp}",$"[{remote}]:{rp}",state==2?"Listening":state==5?"Established":state.ToString()));
                }
            }
            finally{Marshal.FreeHGlobal(memory);}
        }
        return result;
    }
    private static int Port(byte[] b,int p)=>(b[p]<<8)|b[p+1];
    public static Dictionary<string,string> Neighbors()
    {
        int size=0;uint rc=GetIpNetTable(IntPtr.Zero,ref size,false);if(rc==232)return [];
        if(rc is not (0 or 122))throw new Win32Exception((int)rc);
        if(size<4||size>1024*1024)throw new InvalidDataException("Invalid ARP table size");
        var memory=Marshal.AllocHGlobal(size);
        try
        {
            rc=GetIpNetTable(memory,ref size,false);if(rc!=0)throw new Win32Exception((int)rc);
            var b=new byte[size];Marshal.Copy(memory,b,0,size);int count=BitConverter.ToInt32(b,0);
            if(count<0||4L+count*24L>size)throw new InvalidDataException("Invalid ARP count");
            Dictionary<string,string> results=[];
            for(int i=0;i<count;i++){int p=4+i*24,len=BitConverter.ToInt32(b,p+4),type=BitConverter.ToInt32(b,p+20);if(len<1||len>8||type is 1 or 2)continue;var ip=new IPAddress(b.AsSpan(p+16,4)).ToString();results[$"{BitConverter.ToInt32(b,p)}:{ip}"]=Convert.ToHexString(b.AsSpan(p+8,len));}
            return results;
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
}
