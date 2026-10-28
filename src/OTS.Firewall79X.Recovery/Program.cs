using System.ServiceProcess;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
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
                    // Offline recovery must also remove OTS-owned domain entries after a crash.
                    new DomainHostsProtection(null).Restore();
                    AtomicFile.Write(Paths.At("state.json"),"{\"Enabled\":false,\"ResumeAt\":null}");response=new(true,$"Offline restore completed; {conflicts.Count} external changes preserved");
                }
                if(command=="uninstall"){using var service=new ServiceController("OTSFirewall79X");if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}}
            }
            else if(command is "configure-backup" or "configure-export")
            {
                var requested=ShowResilienceSetup(command);
                if(requested==null)return 0; // cancelled: do not alter any previous configuration
                response=Ipc.SendAsync(requested).GetAwaiter().GetResult();
            }
            else response=Ipc.SendAsync(command).GetAwaiter().GetResult();
            if(!quiet)MessageBox.Show(response.Message,"OTS Firewall79X",MessageBoxButton.OK,response.Ok?MessageBoxImage.Information:MessageBoxImage.Error);
            return response.Ok?0:1;
        }
        catch(Exception ex){if(!quiet)MessageBox.Show(ex.Message,"OTS Firewall79X recovery failed",MessageBoxButton.OK,MessageBoxImage.Error);return 1;}
    }
    // Admin-owned dialog deliberately collects the optional recovery passphrase after UAC elevation.
    // It is NEVER sent through command line arguments, process environment or the event log.
    private static Request? ShowResilienceSetup(string command)
    {
        bool backup=command=="configure-backup";
        var window=new Window
        {
            Title=backup?"OTS Firewall79X — Schedule encrypted backup":"OTS Firewall79X — Configure encrypted log export",
            Width=590,Height=470,MinWidth=540,MinHeight=390,
            WindowStartupLocation=WindowStartupLocation.CenterScreen,
            Background=System.Windows.Media.Brushes.White
        };
        var content=new StackPanel{Margin=new Thickness(22)};
        var intro=new TextBlock{
            Text=backup
                ?"Schedule one encrypted version about every 24 hours while OTS is ON. Choose a small source folder (up to 60 MiB) and a separate mounted removable/network destination."
                :"Export encrypted rotated security logs to a removable/network folder. Only finalized log segments are copied; normal monitoring is unchanged.",
            TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,12)};
        content.Children.Add(intro);
        var source=new TextBox{Margin=new Thickness(0,3,0,10),MinHeight=27};
        var dest=new TextBox{Margin=new Thickness(0,3,0,10),MinHeight=27};
        if(backup)
        {
            content.Children.Add(new TextBlock{Text="Source folder to back up:"});
            var chooseSource=new Button{Content="Choose backup source folder",HorizontalAlignment=HorizontalAlignment.Left};
            chooseSource.Click+=(_,_)=>{var picker=new OpenFolderDialog{Title="Select source folder for encrypted backup"};if(picker.ShowDialog()==true)source.Text=picker.FolderName;};
            content.Children.Add(chooseSource);content.Children.Add(source);
        }
        content.Children.Add(new TextBlock{Text="Off-device destination folder (removable volume or network share):"});
        var chooseDest=new Button{Content="Choose external destination folder",HorizontalAlignment=HorizontalAlignment.Left};
        chooseDest.Click+=(_,_)=>{var picker=new OpenFolderDialog{Title="Select destination on removable or network storage"};if(picker.ShowDialog()==true)dest.Text=picker.FolderName;};
        content.Children.Add(chooseDest);content.Children.Add(dest);
        content.Children.Add(new TextBlock{Text="Recovery passphrase (at least 12 characters):"});
        var password=new PasswordBox{MaxLength=512,Margin=new Thickness(0,3,0,12),MinHeight=29};
        content.Children.Add(password);
        content.Children.Add(new TextBlock{
            Text="Keep this passphrase separately: machine DPAPI protects the configured local copy, but encrypted archives cannot be recovered elsewhere without your passphrase. Nothing is uploaded unless you opt in.",
            TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,15)});
        var buttons=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Right};
        var cancel=new Button{Content="Cancel",MinWidth=80,Margin=new Thickness(0,0,10,0)};
        cancel.Click+=(_,_)=>window.DialogResult=false;
        var save=new Button{Content=backup?"Enable scheduled backup":"Enable encrypted log export",MinWidth=180};
        save.Click+=(_,_)=>{
            if((backup&&string.IsNullOrWhiteSpace(source.Text))||string.IsNullOrWhiteSpace(dest.Text)||password.Password.Length<12)
            {MessageBox.Show("Select folders and enter a recovery passphrase of at least 12 characters.","Incomplete setup",MessageBoxButton.OK,MessageBoxImage.Warning);return;}
            window.DialogResult=true;
        };
        buttons.Children.Add(cancel);buttons.Children.Add(save);content.Children.Add(buttons);
        window.Content=new ScrollViewer{Content=content,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        if(window.ShowDialog()!=true){password.Clear();return null;}
        var request=new Request(command,Source:backup?source.Text:null,Destination:dest.Text,Secret:password.Password);
        password.Clear();
        return request;
    }
}
