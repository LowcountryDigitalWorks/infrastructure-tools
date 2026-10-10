using LDW.HostAgent.Core;
using LDW.HostAgent.Windows;

if (WindowsPrivilege.IsElevated())
{
    Console.Error.WriteLine("live-probe=refused-elevated");
    return 2;
}

var configuration = HostAgentSettingsLoader.Load();
var provider = new HostAgentLiveSnapshotProvider(configuration);
var live = await provider.ObserveAsync(CancellationToken.None);
Console.WriteLine($"live-probe=pass; elevated=false; configFound={configuration.Found}; configValid={configuration.Valid}");
Console.WriteLine($"overall={live.Snapshot.Color}/{live.Snapshot.Health}; ownerSession={live.RuntimeContext.OwnerSession}");
foreach (var observation in live.Snapshot.Components)
    Console.WriteLine($"component={observation.ComponentId}; color={observation.Color}; state={observation.State}; health={observation.Health}; summary={observation.Summary}");
Console.WriteLine($"system=availableMemoryPercent:{live.SystemTelemetry.AvailablePercent:F1}; cpuSampleKnown:{live.SystemTelemetry.CpuBusyPercent.HasValue}; fixedDiskCount:{live.SystemTelemetry.Disks.Count}; pressure:{MemoryPressureEvaluator.Evaluate(live.SystemTelemetry)}");
if (live.LinuxTelemetry is { } linux)
{
    Console.WriteLine($"linuxTelemetry=available; kernel={linux.Kernel}; uptimeSeconds={(long)linux.Uptime.TotalSeconds}; load1={linux.Load1:F2}; memoryAvailableBytes={linux.MemoryAvailableBytes}; swapUsedBytes={linux.SwapUsedBytes}; diskCount={linux.Disks.Count}; cpuPsiKnown={linux.CpuPsiSomeAverage10.HasValue}; memoryPsiKnown={linux.MemoryPsiSomeAverage10.HasValue}; rebootRequired={linux.RebootRequired}; updatesKnown={linux.UpdatesAvailable.HasValue}");
}
else
{
    Console.WriteLine("linuxTelemetry=unavailable");
}
if (live.GitHubRunnerTelemetry is { } runner)
{
    Console.WriteLine($"githubRunner=available; online={runner.Online}; busy={runner.Busy}; labelCount={runner.Labels.Count}; idPresent={runner.Id > 0}");
}
else
{
    Console.WriteLine("githubRunner=unavailable");
}
return 0;
