using System.Globalization;

namespace LDW.OperationsBridge.Core;

public sealed record DragonflyRunnerStatusSnapshot(
    string State,
    string? Reason,
    int VisibleCpus,
    long MemAvailableMib,
    long FreeDiskGib,
    double LoadFraction,
    int ResidueCount,
    bool BasePresent);

public sealed record DragonflyRunnerLifecycleResult(
    string State,
    string? Reason);

public interface IDragonflyRunnerAdapter
{
    Task<DragonflyRunnerStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken);
    Task<DragonflyRunnerLifecycleResult> StartAsync(CancellationToken cancellationToken);
    Task<DragonflyRunnerLifecycleResult> DrainAsync(CancellationToken cancellationToken);
}

public sealed class DragonflyRunnerAdapterUnavailableException : Exception
{
    public DragonflyRunnerAdapterUnavailableException()
        : base("Dragonfly runner adapter is not configured.")
    {
    }
}

public sealed class UnavailableDragonflyRunnerAdapter : IDragonflyRunnerAdapter
{
    public Task<DragonflyRunnerStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<DragonflyRunnerStatusSnapshot>(new DragonflyRunnerAdapterUnavailableException());
    }

    public Task<DragonflyRunnerLifecycleResult> StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<DragonflyRunnerLifecycleResult>(new DragonflyRunnerAdapterUnavailableException());
    }

    public Task<DragonflyRunnerLifecycleResult> DrainAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<DragonflyRunnerLifecycleResult>(new DragonflyRunnerAdapterUnavailableException());
    }
}

public static class DragonflyRunnerContract
{
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
    {
        "STOPPED", "AVAILABLE", "RUNNING", "DRAINING", "HOLD", "FAILED"
    };

    public static bool IsSafeStatus(DragonflyRunnerStatusSnapshot? status)
    {
        if (status is null || !IsSafeState(status.State) || !IsSafeReason(status.Reason))
            return false;
        return status.VisibleCpus is > 0 and <= 1024
            && status.MemAvailableMib is >= 0 and <= 1_000_000_000
            && status.FreeDiskGib is >= 0 and <= 1_000_000_000
            && status.LoadFraction is >= 0 and <= 1_000_000
            && status.ResidueCount is >= 0 and <= 1_000_000;
    }

    public static bool IsSafeStartResult(DragonflyRunnerLifecycleResult? result)
        => result is not null
           && result.State == "AVAILABLE"
           && IsSafeReason(result.Reason);

    public static bool IsSafeDrainResult(DragonflyRunnerLifecycleResult? result)
        => result is not null
           && result.State is "STOPPED" or "DRAINING"
           && IsSafeReason(result.Reason);

    public static IReadOnlyDictionary<string, string> StatusPayload(DragonflyRunnerStatusSnapshot status)
    {
        if (!IsSafeStatus(status))
            throw new InvalidOperationException("Unsafe Dragonfly status result.");

        var payload = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["state"] = status.State,
            ["visible_cpus"] = status.VisibleCpus.ToString(CultureInfo.InvariantCulture),
            ["mem_available_mib"] = status.MemAvailableMib.ToString(CultureInfo.InvariantCulture),
            ["free_disk_gib"] = status.FreeDiskGib.ToString(CultureInfo.InvariantCulture),
            ["load_fraction"] = status.LoadFraction.ToString("0.###", CultureInfo.InvariantCulture),
            ["residue_count"] = status.ResidueCount.ToString(CultureInfo.InvariantCulture),
            ["base_present"] = status.BasePresent ? "true" : "false"
        };
        if (status.Reason is not null)
            payload["reason"] = status.Reason;
        return payload;
    }

    public static IReadOnlyDictionary<string, string> LifecyclePayload(DragonflyRunnerLifecycleResult result)
    {
        var payload = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["state"] = result.State
        };
        if (result.Reason is not null)
            payload["reason"] = result.Reason;
        return payload;
    }

    private static bool IsSafeState(string? state)
        => state is not null && States.Contains(state);

    private static bool IsSafeReason(string? reason)
    {
        if (reason is null)
            return true;
        if (reason.Length is < 1 or > 64)
            return false;
        foreach (var c in reason)
        {
            if (char.IsUpper(c) || char.IsDigit(c) || c == '_')
                continue;
            return false;
        }
        return true;
    }
}
