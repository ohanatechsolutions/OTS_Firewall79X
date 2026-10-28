using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using OTS.Firewall79X.Core;

namespace OTS.Firewall79X.Windows;

/// <summary>Read-only SSH verification. Unknown effective contexts are not marked secure.</summary>
public static class SshEffectiveAudit
{
    public sealed record Result(LayerMode Mode,bool Healthy,string Evidence,string Limitations);
    public static Result Read(IReadOnlyCollection<Connection> connections)
    {
        var services=SystemQueries.Wmi("root\\cimv2",
            "SELECT Name,State,PathName FROM Win32_Service WHERE Name='sshd'","Name","State","PathName");
        var listeners=connections.Where(c=>c.State=="Listening" &&
            (c.Process.Equals("sshd",StringComparison.OrdinalIgnoreCase) ||
             c.Local.EndsWith("]:22",StringComparison.Ordinal))).ToArray();
        if(services.Count==0&&listeners.Length==0)
            return new(LayerMode.NotApplicable,false,"OpenSSH server service and common SSH listeners are absent",
                "Unknown alternate SSH servers or hidden listeners are not ruled out.");
        if(services.Count==0)
            return new(LayerMode.Unavailable,false,"SSH-like listener detected but Windows OpenSSH service not registered",
                "No Microsoft OpenSSH configuration can be safely attributed to this service.");
        var service=services[0];
        var path=service.GetValueOrDefault("PathName","");var state=service.GetValueOrDefault("State","unknown");
        var executable=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","OpenSSH","sshd.exe");
        if(!File.Exists(executable))
            return new(LayerMode.Unavailable,false,"OpenSSH service found; system sshd.exe unavailable",
                "Custom binary or service executable cannot be attested; no file was executed.");
        var serviceCommand=Environment.ExpandEnvironmentVariables(path).Trim();
        // Default -T is not authoritative when SCM supplies *any* additional
        // runtime options (including -f, -o and -p), not just an obvious -f.
        if(!serviceCommand.Equals("\""+executable+"\"",StringComparison.OrdinalIgnoreCase) &&
           !serviceCommand.Equals(executable,StringComparison.OrdinalIgnoreCase))
            return new(LayerMode.Unavailable,false,"OpenSSH service command differs from the built-in sshd.exe default invocation",
                "Custom binary or startup options may change the effective policy; no untrusted executable was launched.");
        string output;
        try
        {
            using var p=new Process();
            p.StartInfo=new ProcessStartInfo(executable)
            {
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,
                RedirectStandardError=true
            };
            p.StartInfo.ArgumentList.Add("-T");
            if(!p.Start())throw new IOException("Unable to launch Windows OpenSSH policy auditor");
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(6));
            var stdout=p.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr=p.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                Task.WhenAll(stdout,stderr,p.WaitForExitAsync(timeout.Token)).GetAwaiter().GetResult();
            }
            catch(OperationCanceledException)
            {
                try{p.Kill(true);}catch(InvalidOperationException){}
                return new(LayerMode.Unavailable,false,"sshd -T effective-policy check timed out","No configuration was altered.");
            }
            if(p.ExitCode!=0)return new(LayerMode.Unavailable,false,
                "sshd -T could not validate effective configuration (exit "+p.ExitCode+")",
                "Check host keys, permissions, Include and Match contexts; error text was not persisted.");
            output=stdout.Result;
        }
        catch(Exception ex)when(ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return new(LayerMode.Unavailable,false,"Unable to verify effective OpenSSH configuration: "+Wire.Clean(ex.Message,128),
                "The service configuration remains untouched.");
        }
        var policy=EffectiveSshPolicy.Parse(output);
        var config=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ssh","sshd_config");
        bool hasConditionals=false;
        try
        {
            if(File.Exists(config))
            {
                var file=new FileInfo(config);
                if(file.Length>256*1024)return new(LayerMode.Unavailable,false,"OpenSSH config exceeds review budget","");
                hasConditionals=OpenSshPolicyAudit.Parse(File.ReadAllText(config)).RequiresEffectiveVerification;
            }
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException)
        {
            return new(LayerMode.Unavailable,false,"OpenSSH file review failed: "+Wire.Clean(ex.Message,120),"");
        }
        var keyPaths=new List<string>();
        var adminKeys=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ssh","administrators_authorized_keys");
        if(File.Exists(adminKeys))keyPaths.Add(adminKeys);
        var profiles=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var usersRoot=Directory.GetParent(profiles)?.FullName;
        if(usersRoot!=null&&Directory.Exists(usersRoot))
        {
            try
            {
                foreach(var dir in Directory.EnumerateDirectories(usersRoot).Take(100))
                {
                    var info=new DirectoryInfo(dir);
                    if((info.Attributes&FileAttributes.ReparsePoint)!=0)continue;
                    var key=Path.Combine(dir,".ssh","authorized_keys");
                    if(File.Exists(key))keyPaths.Add(key);
                }
            }
            catch(UnauthorizedAccessException){return new(LayerMode.Unavailable,false,"User SSH key ACL inventory access denied","No key contents were read.");}
        }
        int weak=0;int unknown=0;
        foreach(var file in keyPaths)
        {
            try
            {
                if((File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0){unknown++;continue;}
                var acl=FileSystemAclExtensions.GetAccessControl(new FileInfo(file));
                foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                {
                    if(rule.AccessControlType!=AccessControlType.Allow)continue;
                    var sid=((SecurityIdentifier)rule.IdentityReference).Value;
                    if(sid is "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545")
                    {
                        const FileSystemRights writable=FileSystemRights.Write|FileSystemRights.Modify|FileSystemRights.FullControl|
                            FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
                        if((rule.FileSystemRights&writable)!=0){weak++;break;}
                    }
                }
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {unknown++;}
        }
        string summary=$"Service={state}; sshd -T verified; password={policy.PasswordAuthentication?.ToString()??"unknown"}; " +
            $"pubkey={policy.PubkeyAuthentication?.ToString()??"unknown"}; empty-passwords={policy.PermitEmptyPasswords?.ToString()??"unknown"}; "+
            $"strict-modes={policy.StrictModes?.ToString()??"unknown"}; root-login={policy.PermitRootLogin?.ToString()??"unknown"}; "+
            $"SSH-like listeners={listeners.Length}; authorized-key files checked={keyPaths.Count}; weak key ACLs={weak}; ACL unknown={unknown}.";
        const string limits="Read-only Windows OpenSSH audit. sshd -T verifies its default connection context only; Match/Include, custom listen ports, per-account authorizations and external firewall reachability are not exhaustively attested.";
        if(weak>0||policy.Weak)return new(LayerMode.Auditing,false,summary+" Explicitly unsafe policy or writable authorized keys.",limits);
        if(!policy.Hardened||unknown>0||hasConditionals)
            return new(LayerMode.Unavailable,false,summary+" Conditional contexts or missing policy/ACL evidence require review.",limits);
        return new(LayerMode.Auditing,true,summary,limits);
    }
}

public static class LocalAccountSecurityAudit
{
    [StructLayout(LayoutKind.Sequential)]
    private struct UserModalsInfo0
    {
        public uint MinPasswordLength,MaxPasswordAge,MinPasswordAge,ForceLogoff,PasswordHistoryLength;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UserModalsInfo3
    {
        public uint LockoutDuration,LockoutObservationWindow,LockoutThreshold;
    }
    [DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    private static extern uint NetUserModalsGet(string? server,uint level,out IntPtr buffer);
    [DllImport("Netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);
    public sealed record Result(bool Healthy,string Evidence,string Limitations,object Baseline);
    public static Result Read()
    {
        var accounts=SystemQueries.Wmi("root\\cimv2",
            "SELECT Name,SID,Disabled,PasswordRequired,Lockout FROM Win32_UserAccount WHERE LocalAccount=True",
            "Name","SID","Disabled","PasswordRequired","Lockout");
        int noPassword=accounts.Count(a=>a["Disabled"].Equals("False",StringComparison.OrdinalIgnoreCase)&&
            a["PasswordRequired"].Equals("False",StringComparison.OrdinalIgnoreCase));
        var builtinAdmins=accounts.Where(a=>a["SID"].EndsWith("-500",StringComparison.Ordinal)&&
            a["Disabled"].Equals("False",StringComparison.OrdinalIgnoreCase)).Select(a=>a["Name"]).ToArray();
        var guest=accounts.Where(a=>a["SID"].EndsWith("-501",StringComparison.Ordinal)&&
            a["Disabled"].Equals("False",StringComparison.OrdinalIgnoreCase)).Select(a=>a["Name"]).ToArray();
        var localGroups=SystemQueries.Wmi("root\\cimv2",
            "SELECT Name,SID FROM Win32_Group WHERE LocalAccount=True","Name","SID");
        var administrators=localGroups.FirstOrDefault(g=>g["SID"]=="S-1-5-32-544");
        var adminMembers=new List<string>();
        if(administrators!=null)
        {
            var membership=SystemQueries.Wmi("root\\cimv2",
                "SELECT GroupComponent,PartComponent FROM Win32_GroupUser","GroupComponent","PartComponent");
            var nameToken="Name=\""+administrators["Name"]+"\"";
            adminMembers=membership.Where(m=>m["GroupComponent"].Contains(nameToken,StringComparison.OrdinalIgnoreCase))
                .Select(m=>Wire.Clean(m["PartComponent"],180)).Distinct().Order().ToList();
        }
        uint minimum=0,history=0,maxAge=0,lockoutThreshold=0;bool policyKnown=false,lockoutKnown=false;
        IntPtr buffer=IntPtr.Zero;
        try
        {
            if(NetUserModalsGet(null,0,out buffer)==0&&buffer!=IntPtr.Zero)
            {
                var policy=Marshal.PtrToStructure<UserModalsInfo0>(buffer);
                minimum=policy.MinPasswordLength;history=policy.PasswordHistoryLength;
                maxAge=policy.MaxPasswordAge;policyKnown=true;
            }
        }
        finally{if(buffer!=IntPtr.Zero)NetApiBufferFree(buffer);}
        buffer=IntPtr.Zero;
        try
        {
            if(NetUserModalsGet(null,3,out buffer)==0&&buffer!=IntPtr.Zero)
            {
                lockoutThreshold=Marshal.PtrToStructure<UserModalsInfo3>(buffer).LockoutThreshold;
                lockoutKnown=true;
            }
        }
        finally{if(buffer!=IntPtr.Zero)NetApiBufferFree(buffer);}
        List<string> stale=[];
        try
        {
            var profiles=SystemQueries.Wmi("root\\cimv2",
                "SELECT Name,LastLogon FROM Win32_NetworkLoginProfile","Name","LastLogon");
            var active=accounts.Where(a=>a["Disabled"].Equals("False",StringComparison.OrdinalIgnoreCase)).ToList();
            foreach(var entry in profiles)
            {
                var name=entry["Name"].Split('\\').Last();
                if(!active.Any(a=>a["Name"].Equals(name,StringComparison.OrdinalIgnoreCase)))continue;
                var timestamp=entry["LastLogon"];
                if(timestamp.Length>=14 &&
                   DateTime.TryParseExact(timestamp[..14],"yyyyMMddHHmmss",CultureInfo.InvariantCulture,
                       DateTimeStyles.AssumeLocal,out var last) &&
                   last<DateTime.Now.AddDays(-180))stale.Add(name);
            }
        }
        catch(Exception ex)when(ex is System.Management.ManagementException or UnauthorizedAccessException)
        {
            // LastLogon is an opportunistic WMI observation, never proof that accounts are active.
        }
        var policyAssessment=policyKnown&&lockoutKnown
            ?IdentityPasswordPolicy.Assess(minimum,history,maxAge,lockoutThreshold)
            :null;
        bool risky=noPassword>0||builtinAdmins.Length>0||guest.Length>0||
            (policyAssessment?.Risks.Count>0);
        var summary=$"Local accounts={accounts.Count}; enabled without password requirement={noPassword}; "+
            $"built-in Administrator enabled={builtinAdmins.Length}; Guest enabled={guest.Length}; "+
            $"Administrators members={adminMembers.Count}; minimum password length={(policyKnown?minimum.ToString():"unavailable")}; "+
            $"password history={(policyKnown?history.ToString():"unavailable")}; "+
            $"max password age={(policyKnown?(maxAge==uint.MaxValue?"unlimited":TimeSpan.FromSeconds(maxAge).TotalDays.ToString("F0",CultureInfo.InvariantCulture)+" days"):"unavailable")}; "+
            $"account lockout threshold={(lockoutKnown?lockoutThreshold.ToString():"unavailable")}; "+
            $"policy review flags={(policyAssessment==null?"unknown":string.Join(", ",policyAssessment.Risks))}; "+
            $"last-logon over 180 days (where available)={stale.Count}.";
        const string limits="Account/password flags and WMI last-logon are incomplete signals; nonlocal identities, domain/Entra policy, password contents, and full effective group privileges are not established. Review administrator memberships for unexpected access.";
        return new(!risky&&policyKnown&&lockoutKnown&&administrators!=null,summary+(stale.Count>0? " Potentially stale: "+string.Join(", ",stale.Select(x=>Wire.Clean(x,64)))+".":""),limits,
            new{Accounts=accounts,Administrators=adminMembers,PasswordPolicy=new{Known=policyKnown,Minimum=minimum,History=history,MaxAge=maxAge,LockoutKnown=lockoutKnown,LockoutThreshold=lockoutThreshold},Stale=stale});
    }
}
