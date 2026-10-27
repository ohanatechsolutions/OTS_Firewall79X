using System.ServiceProcess;
using System.Windows;
using OTS.Firewall79X.Core;
using OTS.Firewall79X.Windows;
namespace OTS.Firewall79X.Recovery;
public static class Program
{
    [STAThread]public static int Main(string[] args)
    {
        string command=args.FirstOrDefault()?.TrimStart('-')??"restore";
        bool quiet=args.Contains("--quiet");
        if(!Wire.Commands.Contains(command)&&command!="uninstall")return 2;
        try
        {
            Response response;
            if(command is "restore" or "uninstall")
            {
                try{response=Ipc.SendAsync("restore").GetAwaiter().GetResult();if(!response.Ok)throw new InvalidOperationException(response.Message);}
                catch(Exception)
                {
                    // Offline recovery is only allowed after the service is verified stopped.
                    using(var service=new ServiceController("OTSFirewall79X"))
                    {try{if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}}catch(InvalidOperationException ex)when(ex.InnerException is System.ComponentModel.Win32Exception w&&w.NativeErrorCode==1060){}}
                    Paths.SecureDirectory(Paths.Root);var journal=new ChangeJournal(Paths.At("changes.json"),new WindowsSettings());var conflicts=journal.Restore();
                    AtomicFile.Write(Paths.At("state.json"),"{\"Enabled\":false,\"ResumeAt\":null}");response=new(true,$"Offline restore completed; {conflicts.Count} external changes preserved");
                }
                if(command=="uninstall"){using var service=new ServiceController("OTSFirewall79X");if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}}
            }
            else response=Ipc.SendAsync(command).GetAwaiter().GetResult();
            if(!quiet)MessageBox.Show(response.Message,"OTS Firewall79X",MessageBoxButton.OK,response.Ok?MessageBoxImage.Information:MessageBoxImage.Error);
            return response.Ok?0:1;
        }
        catch(Exception ex){if(!quiet)MessageBox.Show(ex.Message,"OTS Firewall79X recovery failed",MessageBoxButton.OK,MessageBoxImage.Error);return 1;}
    }
}
