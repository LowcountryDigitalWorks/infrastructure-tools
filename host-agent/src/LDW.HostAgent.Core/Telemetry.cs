namespace LDW.HostAgent.Core;

public sealed record SystemTelemetry(
    DateTimeOffset ObservedAt,
    ulong TotalPhysicalBytes,
    ulong AvailablePhysicalBytes,
    double? CpuBusyPercent,
    IReadOnlyList<DiskTelemetry> Disks,
    MemoryPressureTelemetry MemoryPressure)
{
    public double AvailablePercent => TotalPhysicalBytes == 0 ? 0 : AvailablePhysicalBytes * 100d / TotalPhysicalBytes;
}

public sealed record DiskTelemetry(string Mount, ulong TotalBytes, ulong AvailableBytes);

public sealed record MemoryPressureTelemetry(
    double? CommitHeadroomPercent,
    double? SwapInBytesPerSecond,
    double? SwapOutBytesPerSecond,
    double? PsiSomeAverage10,
    double? PsiFullAverage10,
    TimeSpan SustainedFor,
    string Summary);

public enum MemoryPressureLevel { Normal, Elevated, Severe, Unknown }

public static class MemoryPressureEvaluator
{
    public static MemoryPressureLevel Evaluate(SystemTelemetry sample)
    {
        if (sample.TotalPhysicalBytes == 0)
            return MemoryPressureLevel.Unknown;

        var lowAvailable = sample.AvailablePercent < 10;
        var veryLowAvailable = sample.AvailablePercent < 5;
        var paging = (sample.MemoryPressure.SwapInBytesPerSecond ?? 0) > 0
            || (sample.MemoryPressure.SwapOutBytesPerSecond ?? 0) > 0;
        var psiSome = sample.MemoryPressure.PsiSomeAverage10 ?? 0;
        var psiFull = sample.MemoryPressure.PsiFullAverage10 ?? 0;
        var commitHigh = sample.MemoryPressure.CommitHeadroomPercent is < 10;
        var sustained = sample.MemoryPressure.SustainedFor >= TimeSpan.FromSeconds(30);

        if (sustained && ((veryLowAvailable && (paging || psiSome > 0 || commitHigh)) || psiFull >= 1 || (commitHigh && paging)))
            return MemoryPressureLevel.Severe;
        if (lowAvailable || paging || psiSome >= 1 || commitHigh)
            return MemoryPressureLevel.Elevated;
        return MemoryPressureLevel.Normal;
    }
}

public interface IComponentProbe
{
    ComponentKind Kind { get; }
    ValueTask<ComponentObservation> ObserveAsync(ComponentDefinition component, CancellationToken cancellationToken);
}

public interface ISystemProbe
{
    ValueTask<SystemTelemetry> ObserveAsync(CancellationToken cancellationToken);
}

public sealed record LinuxNodeTelemetry(
    string NodeId,
    DateTimeOffset ObservedAt,
    string Kernel,
    TimeSpan Uptime,
    double Load1,
    ulong MemoryAvailableBytes,
    ulong SwapUsedBytes,
    IReadOnlyList<DiskTelemetry> Disks,
    double? CpuPsiSomeAverage10,
    double? MemoryPsiSomeAverage10,
    double? MemoryPsiFullAverage10,
    IReadOnlyDictionary<string, ObservedState> SystemdUnits,
    bool RebootRequired,
    bool Reachable);

public interface IStrictSshTransport
{
    ValueTask<string> ExecuteReadOnlyAsync(
        string nodeId,
        string allowlistedProbeId,
        CancellationToken cancellationToken);
}

public sealed record StrictSshConnectionPolicy(
    string KnownHostsFile,
    string IdentityFile,
    bool StrictHostKeyChecking,
    bool IdentitiesOnly,
    bool BatchMode)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(KnownHostsFile) || string.IsNullOrWhiteSpace(IdentityFile)
            || !StrictHostKeyChecking || !IdentitiesOnly || !BatchMode)
            throw new InvalidOperationException("Linux-node SSH requires an explicit identity, known-hosts file, strict host-key checking, IdentitiesOnly, and BatchMode.");
    }
}

public interface ILinuxNodeProbe
{
    ValueTask<LinuxNodeTelemetry> ObserveAsync(string nodeId, CancellationToken cancellationToken);
}

public sealed record GitHubRunnerTelemetry(long Id, string Name, bool Online, bool Busy, IReadOnlyList<string> Labels);

public interface IGitHubRunnerStatusSource
{
    ValueTask<GitHubRunnerTelemetry?> GetRunnerAsync(string repository, long runnerId, CancellationToken cancellationToken);
}

public interface IComponentControl
{
    ValueTask<ComponentObservation> RequestAsync(string componentId, string allowlistedAction, CancellationToken cancellationToken);
}
