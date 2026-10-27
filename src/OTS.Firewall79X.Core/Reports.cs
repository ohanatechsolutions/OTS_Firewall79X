using System.Text;
namespace OTS.Firewall79X.Core;
public static class Reports
{
    private static string Escape(string text)=>Wire.Clean(text).Replace("|","\\|");
    public static string Generate(Dashboard d)
    {
        var b=new StringBuilder($"# OTS Firewall79X security report\n\nGenerated: {d.Time:O}\n\nProtection: {d.Protection}\n\nCapability health score: {d.Score}/100; observed data confidence: {d.Confidence}%. This is not a probability of avoiding compromise.\n\nEvents since service start: {d.TotalEvents}; confirmed OTS blocks: {d.BlockedEvents}.\n\n| ID | Layer | Mode | Health | Evidence | Limitations |\n|---|---|---|---|---|---|\n");
        foreach(var l in d.Layers.OrderBy(l=>l.Id)){var name=Catalog.All.Single(c=>c.Id==l.Id).Name;b.AppendLine($"| {l.Id} | {Escape(name)} | {l.Mode} | {(l.Healthy?"Operational within stated limits":"Needs attention / inactive")} | {Escape(l.Evidence)} | {Escape(l.Limitation)} |");}
        b.AppendLine("\n## Recent events\n");foreach(var e in d.Events.Take(100))b.AppendLine($"- {e.Time:O} [{e.Severity}] Layer {e.Layer}: {Escape(e.Kind)} — {Escape(e.Detail)}");
        return b.ToString();
    }
}
