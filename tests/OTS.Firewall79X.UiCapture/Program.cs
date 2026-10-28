using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using OTS.Firewall79X.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")return 2;
        var output=Path.GetFullPath(args.Length>0?args[0]:"artifacts/ui");Directory.CreateDirectory(output);
        Application.ResourceAssembly=typeof(App).Assembly;
        var app=new App();app.InitializeComponent();
        var exit=0;
        app.Startup+=async (_,_)=>
        {
            await Task.Delay(500);
            if(app.MainWindow is not MainWindow window){Console.Error.WriteLine("Main window did not start");exit=1;app.Shutdown();return;}
            window.Width=1380;window.Height=980;window.Left=0;window.Top=0;
            try
            {
                await Task.Delay(2500);
                var tabs=(TabControl)window.FindName("MainTabs");
                for(int i=0;i<tabs.Items.Count;i++)
                {
                    tabs.SelectedIndex=i;await Task.Delay(350);window.UpdateLayout();
                    Capture(window,Path.Combine(output,$"{i:00}-desktop.png"));
                    if(i==0)Capture(window,Path.Combine(output,"08-dashboard-8k.png"),7680/((FrameworkElement)window.Content).ActualWidth);
                }
                tabs.SelectedIndex=0;window.Width=1000;window.Height=700;await Task.Delay(350);window.UpdateLayout();Capture(window,Path.Combine(output,"07-compact.png"));
                // Search must still route to the real filtered layer list.
                var search=(TextBox)window.FindName("LayerSearch");search.Text="79";
                if(tabs.SelectedIndex!=1)throw new InvalidOperationException("Search did not open security layers");
                if(((DataGrid)window.FindName("LayerGrid")).Items.Count==0)throw new InvalidOperationException("Search returned no layer 79");
                Console.WriteLine("PASS All seven screens rendered; compact layout and layer search exercised");
            }
            catch(Exception ex){Console.Error.WriteLine(ex);exit=1;}
            finally{window.Close();app.Shutdown();}
        };
        app.Run();return exit;
    }
    private static void Capture(Window window,string path,double scale=1)
    {
        var root=(FrameworkElement)window.Content;
        var bitmap=new RenderTargetBitmap((int)Math.Ceiling(root.ActualWidth*scale),(int)Math.Ceiling(root.ActualHeight*scale),96*scale,96*scale,PixelFormats.Pbgra32);
        bitmap.Render(root);var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bitmap));using var file=File.Create(path);png.Save(file);
    }
}
