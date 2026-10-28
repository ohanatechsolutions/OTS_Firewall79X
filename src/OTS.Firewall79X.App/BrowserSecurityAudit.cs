using OTS.Firewall79X.Core;
using System.Text.Json;
using Microsoft.Win32;

namespace OTS.Firewall79X.App;

/// <summary>Read-only inventory of browser policy and user-selected profiles. Never reads
/// browser history, cookies, passwords, session databases, or page content.</summary>
internal static class BrowserSecurityAudit
{
    internal sealed record Result(int Profiles,int Extensions,int RiskyExtensions,int SafeBrowsingDisabled,
        int Unreadable,int UnknownPolicies,string Evidence);
    private sealed record Browser(string Name,string Root,string PolicyPath,bool Firefox=false);
    private static string? Policy(string path,string name)
    {
        try
        {
            // Machine policy takes precedence over current-user policy.
            using var machine=Registry.LocalMachine.OpenSubKey(path);
            if(machine?.GetValue(name) is { } m)return m.ToString();
            using var user=Registry.CurrentUser.OpenSubKey(path);
            return user?.GetValue(name)?.ToString();
        }
        catch(System.Security.SecurityException){return null;}
        catch(UnauthorizedAccessException){return null;}
    }
    private static bool TryJson(string path,int maxBytes,out JsonDocument? result)
    {
        result=null;
        try
        {
            var file=new FileInfo(path);
            if(!file.Exists||file.Length>maxBytes||file.Length==0||
               file.Attributes.HasFlag(FileAttributes.ReparsePoint))return false;
            using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,4096,FileOptions.SequentialScan);
            result=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=24,AllowTrailingCommas=true});
            return true;
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or JsonException)
        {result?.Dispose();result=null;return false;}
    }
    private static bool? SafeBrowsing(string profilePrefs,string policyPath)
    {
        var level=Policy(policyPath,"SafeBrowsingProtectionLevel");
        if(level is "0")return false;
        if(level is "1" or "2")return true;
        var enabled=Policy(policyPath,"SafeBrowsingEnabled");
        if(enabled is "0")return false;
        if(enabled is "1")return true;
        if(!TryJson(profilePrefs,4*1024*1024,out var doc))return null;
        using(doc)
        {
            if(doc!.RootElement.TryGetProperty("safebrowsing",out var sb)&&
               sb.ValueKind==JsonValueKind.Object&&sb.TryGetProperty("enabled",out var value))
                return value.ValueKind switch{JsonValueKind.True=>true,JsonValueKind.False=>false,_=>null};
            return null;
        }
    }
    public static Result Read()
    {
        var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming=Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        Browser[] browsers=[
            new("Chrome",Path.Combine(local,"Google","Chrome","User Data"),@"SOFTWARE\Policies\Google\Chrome"),
            new("Edge",Path.Combine(local,"Microsoft","Edge","User Data"),@"SOFTWARE\Policies\Microsoft\Edge"),
            new("Brave",Path.Combine(local,"BraveSoftware","Brave-Browser","User Data"),@"SOFTWARE\Policies\BraveSoftware\Brave"),
            new("Firefox",Path.Combine(roaming,"Mozilla","Firefox","Profiles"),@"SOFTWARE\Policies\Mozilla\Firefox",true)
        ];
        int profiles=0,extensions=0,risky=0,disabled=0,errors=0,unknownPolicies=0;
        var visited=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var browser in browsers)
        {
            if(!Directory.Exists(browser.Root))continue;
            string[] candidates;
            try
            {
                candidates=Directory.EnumerateDirectories(browser.Root).Take(128).ToArray();
                if(!browser.Firefox)candidates=candidates
                    .Where(p=>Path.GetFileName(p).Equals("Default",StringComparison.OrdinalIgnoreCase)||
                        Path.GetFileName(p).StartsWith("Profile ",StringComparison.OrdinalIgnoreCase)).ToArray();
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException)
            {errors++;continue;}
            foreach(var profile in candidates)
            {
                if(profiles>=128)break;
                try
                {
                    if(File.GetAttributes(profile).HasFlag(FileAttributes.ReparsePoint))continue;
                    if(!visited.Add(profile))continue;
                    profiles++;
                    if(browser.Firefox)
                    {
                        // Firefox extension metadata is observed only as a bounded inventory;
                        // signed-state and effective user policy are not independently verified.
                        if(TryJson(Path.Combine(profile,"extensions.json"),2*1024*1024,out var firefoxJson))
                            using(firefoxJson)
                            {
                                if(firefoxJson!.RootElement.TryGetProperty("addons",out var addons)&&
                                    addons.ValueKind==JsonValueKind.Array)
                                    extensions+=Math.Min(addons.GetArrayLength(),500);
                            }
                        unknownPolicies++;continue;
                    }
                    var security=SafeBrowsing(Path.Combine(profile,"Preferences"),browser.PolicyPath);
                    if(security==false)disabled++;
                    if(security==null)unknownPolicies++;
                    var extRoot=Path.Combine(profile,"Extensions");
                    if(!Directory.Exists(extRoot))continue;
                    foreach(var ext in Directory.EnumerateDirectories(extRoot).Take(500))
                    {
                        if(File.GetAttributes(ext).HasFlag(FileAttributes.ReparsePoint))continue;
                        extensions++;
                        foreach(var version in Directory.EnumerateDirectories(ext).Take(5))
                        {
                            if(File.GetAttributes(version).HasFlag(FileAttributes.ReparsePoint))continue;
                            if(!TryJson(Path.Combine(version,"manifest.json"),128*1024,out var manifest))
                            {errors++;continue;}
                            using(manifest){if(Detections.BrowserManifestHasHighImpactPermissions(manifest!.RootElement))risky++;}
                            break; // newest manifest should be checked by version ordering in future
                        }
                        if(extensions>=1500)break;
                    }
                }
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException)
                {errors++;}
            }
        }
        return new(profiles,extensions,risky,disabled,errors,unknownPolicies,
            $"{profiles} supported profiles (Chrome/Edge/Brave/Firefox); {extensions} extensions inventoried; "+
            $"{risky} manifest(s) request high-impact permissions; {disabled} profile(s) explicitly disable Safe Browsing; "+
            $"{unknownPolicies} profile(s) have unknown/effective security policy; {errors} inaccessible/invalid entries. "+
            "Manifest permissions indicate capability, not maliciousness. Firefox signing, Chrome store trust, browser version patching, extensions outside user profiles and all centrally enforced policies are not fully attested.");
    }
}
