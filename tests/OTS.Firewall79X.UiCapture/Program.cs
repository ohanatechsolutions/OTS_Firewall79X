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
        var app=new App();app.InitializeComponent();
        app.StartupUri=new Uri("/OTS Firewall79X;component/MainWindow.xaml",UriKind.Relative);
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
                    if(i==0)Capture(window,Path.Combine(output,"08-dashboard-8k.png"),1600,900,4.8);
                }
                tabs.SelectedIndex=0;window.Width=1000;window.Height=700;await Task.Delay(350);window.UpdateLayout();Capture(window,Path.Combine(output,"07-compact.png"),1000,700);
                // Search must still route to the real filtered layer list.
                var search=(TextBox)window.FindName("LayerSearch");search.Text="79";
                if(tabs.SelectedIndex!=1)throw new InvalidOperationException("Search did not open security layers");
                if(!args.Contains("--render-only")&&((DataGrid)window.FindName("LayerGrid")).Items.Count==0)throw new InvalidOperationException("Search returned no layer 79");
                Console.WriteLine("PASS All seven screens rendered; compact layout and layer search exercised");
            }
            catch(Exception ex){Console.Error.WriteLine(ex);exit=1;}
            finally{window.Close();app.Shutdown();}
        };
        app.Run();return exit;
    }
    private static void Capture(Window window,string path,double width=1380,double height=900,double scale=1)
    {
        var root=(FrameworkElement)window.Content;
        root.SetValue(System.Windows.Documents.TextElement.FontFamilyProperty,window.FontFamily);
        root.SetValue(System.Windows.Documents.TextElement.FontSizeProperty,window.FontSize);
        // Detach only during synchronous rendering so the runner's native window cannot clip the preview.
        window.Content=null;
        try
        {
            root.Width=width;root.Height=height;root.Measure(new Size(width,height));root.Arrange(new Rect(0,0,width,height));root.UpdateLayout();
            var bitmap=new RenderTargetBitmap((int)Math.Ceiling(width*scale),(int)Math.Ceiling(height*scale),96*scale,96*scale,PixelFormats.Pbgra32);
            bitmap.Render(root);
            // Rounded edges can be antialiased and translucent by design.
            // Check well inside the frame and verify that the rendered UI is not blank.
            var inset=Math.Max(3,(int)Math.Ceiling(12*scale));
            var sample=new byte[4];
            bitmap.CopyPixels(new Int32Rect(bitmap.PixelWidth-inset,bitmap.PixelHeight-inset,1,1),sample,4,0);
            if(sample[3]<220)throw new InvalidOperationException("UI background was not rendered near the lower-right interior");
            var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bitmap));using var file=File.Create(path);png.Save(file);
        }
        finally { root.Width=double.NaN;root.Height=double.NaN;window.Content=root;window.UpdateLayout(); }
    }
}
