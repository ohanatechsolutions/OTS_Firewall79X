namespace OTS.Firewall79X.Core;

/// <summary>Pure, deterministic safety policies for restart throttling and resource backoff.</summary>
public sealed class RestartBudget
{
    private readonly Queue<DateTimeOffset> attempts = new();
    private DateTimeOffset lastAttempt = DateTimeOffset.MinValue;
    public bool TryAcquire(DateTimeOffset now, int maxPerHour = 3, int minimumSeconds = 60)
    {
        if (maxPerHour is < 1 or > 12 || minimumSeconds is < 5 or > 3600)
            throw new ArgumentOutOfRangeException(nameof(maxPerHour));
        while (attempts.Count > 0 && now - attempts.Peek() >= TimeSpan.FromHours(1))
            attempts.Dequeue();
        if (now < lastAttempt || now - lastAttempt < TimeSpan.FromSeconds(minimumSeconds) ||
            attempts.Count >= maxPerHour) return false;
        lastAttempt = now;
        attempts.Enqueue(now);
        return true;
    }
}
public static class ResourceBudget
{
    public sealed record Decision(TimeSpan CycleInterval, TimeSpan InventoryInterval,
        bool DeferNonessentialDiskWork, string Reason);
    public static Decision Evaluate(bool battery, double serviceCpuPercent,
        double serviceMemoryMb, long availableDiskBytes, long diskCapacityBytes)
    {
        if (double.IsNaN(serviceCpuPercent) || double.IsNaN(serviceMemoryMb) ||
            availableDiskBytes < 0 || diskCapacityBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(serviceCpuPercent));
        bool pressure = serviceCpuPercent > 10 || serviceMemoryMb > 256;
        bool diskLow = diskCapacityBytes > 0 && (availableDiskBytes < 512L * 1024 * 1024 ||
            availableDiskBytes * 1.0 / diskCapacityBytes < 0.05);
        var interval = battery ? (pressure ? 180 : 90) : (pressure ? 60 : 30);
        if (diskLow) interval = Math.Max(interval, 180);
        return new(TimeSpan.FromSeconds(interval),
            TimeSpan.FromMinutes(battery || diskLow ? 15 : 5),
            diskLow, diskLow ? "Low disk capacity: defer nonessential disk writes" :
            pressure ? "Service CPU/memory pressure" : battery ? "Battery-saving schedule" : "Normal AC schedule");
    }
}
public static class HeartbeatPolicy
{
    public static bool IsStale(DateTimeOffset lastSuccess, DateTimeOffset now, TimeSpan limit) =>
        limit > TimeSpan.Zero && (lastSuccess > now.AddMinutes(5) ||
        now - lastSuccess > limit);
}
