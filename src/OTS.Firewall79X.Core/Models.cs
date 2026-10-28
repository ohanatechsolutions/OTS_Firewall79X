using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OTS.Firewall79X.Core;

public enum LayerMode { Idle, Enforcing, Monitoring, Auditing, Unavailable, NotApplicable }
public sealed record LayerDefinition(int Id, string Name, string Category, string Description);
public sealed record LayerResult(int Id, LayerMode Mode, bool Healthy, string Evidence, string Limitation = "", DateTimeOffset? CheckedAt = null, double? DurationMs = null);
public sealed record SecurityEvent(DateTimeOffset Time, int Layer, string Severity, string Kind, string Detail, bool Blocked = false);
public sealed record Connection(int Pid, string Process, string Local, string Remote, string State);
public sealed record Dashboard(bool Enabled, string Protection, int Score, double Confidence, DateTimeOffset Time, DateTimeOffset? ResumeAt, List<LayerResult> Layers, List<SecurityEvent> Events, List<Connection> Connections, long TotalEvents, long BlockedEvents, double ServiceMemoryMb, double? CpuPercent, string FeedStatus);
public sealed record Request(string Command, int? Layer = null, bool? Enabled = null, string? Source = null, string? Destination = null, string? Secret = null);
public sealed record Response(bool Ok, string Message, Dashboard? Dashboard = null);
public static class Wire
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, Converters = { new JsonStringEnumConverter() }, MaxDepth = 32 };
    public static readonly HashSet<string> Commands = ["status", "on", "off", "pause", "restore", "report", "selftest", "configure-backup", "configure-export", "disable-backup", "disable-export"];
    public static bool RequiresAdmin(string command) => command != "status";
    public static string Clean(string? text, int max = 2048) => new((text ?? "").Where(c => !char.IsControl(c) || c is '\t').Take(max).ToArray());
    public static async Task WriteAsync<T>(Stream stream, T data, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(data, Json);
        if (bytes.Length > 4 * 1024 * 1024) throw new InvalidDataException("Response too large");
        await stream.WriteAsync(BitConverter.GetBytes(bytes.Length), ct);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }
    public static async Task<T> ReadAsync<T>(Stream stream, int max, CancellationToken ct)
    {
        var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, ct);
        int length = BitConverter.ToInt32(prefix);
        if (length < 2 || length > max) throw new InvalidDataException("Invalid message length");
        var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, ct);
        return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new InvalidDataException("Empty message");
    }
}
public static class Catalog
{
    public static readonly IReadOnlyList<LayerDefinition> All = Load();
    private static IReadOnlyList<LayerDefinition> Load()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("OTS.Firewall79X.Core.catalog.json")!;
        var result = JsonSerializer.Deserialize<List<LayerDefinition>>(s, Wire.Json)!;
        if (!result.Select(x => x.Id).SequenceEqual(Enumerable.Range(1,79))) throw new InvalidDataException("Catalog must contain IDs 1–79");
        return result;
    }
}
public static class Posture
{
    // A weighted capability-health score, not a probability of avoiding compromise.
    public static int Weight(int id) => id is 1 or 6 or 46 or 53 or 55 or 57 or 59 or 65 or 76 ? 3 : 1;
    public static (int Score, double Confidence) Calculate(IEnumerable<LayerResult> layers, bool enabled)
    {
        if (!enabled) return (0, 0);
        var all = layers.Where(l => l.Mode != LayerMode.NotApplicable).ToArray();
        int total = all.Sum(l => Weight(l.Id));
        if (total == 0) return (0, 0);
        int healthy = all.Where(l=>l.Healthy && l.Mode is LayerMode.Enforcing or LayerMode.Monitoring or LayerMode.Auditing).Sum(l=>Weight(l.Id));
        int observed = all.Where(l=>l.CheckedAt != null && l.Mode is not (LayerMode.Unavailable or LayerMode.Idle)).Sum(l=>Weight(l.Id));
        return ((int)Math.Round(100.0*healthy/total), Math.Round(100.0*observed/total,1));
    }
}
