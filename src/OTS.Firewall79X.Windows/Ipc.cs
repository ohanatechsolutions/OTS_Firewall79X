using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

public static class Ipc
{
    public const string PipeName="OTS.Firewall79X.v1";
    public static async Task<Response> SendAsync(string command,CancellationToken ct=default)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var pipe=new NamedPipeClientStream(".",PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(timeout.Token);await Wire.WriteAsync(pipe,new Request(command),timeout.Token);
        return await Wire.ReadAsync<Response>(pipe,4*1024*1024,timeout.Token);
    }
    public static async Task ServeAsync(Func<Request,Response> handle,Action<Exception> error,CancellationToken ct)
    {
        // One bounded request per connection. Multiple listeners prevent a stalled client blocking all access.
        await Task.WhenAll(Enumerable.Range(0,4).Select(_=>Listener(handle,error,ct)));
    }
    private static async Task Listener(Func<Request,Response> handle,Action<Exception> error,CancellationToken ct)
    {
        var acl=new PipeSecurity();acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        while(!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe=NamedPipeServerStreamAcl.Create(PipeName,PipeDirection.InOut,4,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,8192,8192,acl);
                await pipe.WaitForConnectionAsync(ct);
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var request=await Wire.ReadAsync<Request>(pipe,1024,timeout.Token);
                bool admin=false;pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent(true);if(identity!=null)admin=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);});
                Response result;
                if(!Wire.Commands.Contains(request.Command)) result=new(false,"Unknown command");
                else if(Wire.RequiresAdmin(request.Command)&&!admin)result=new(false,"Administrator authorization is required");
                else result=handle(request);
                await Wire.WriteAsync(pipe,result,timeout.Token);
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){break;}
            catch(Exception ex){error(ex);await Task.Delay(100,ct).ConfigureAwait(false);}
        }
    }
}
