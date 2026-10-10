using System.Globalization;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed record HostAgentLiveSnapshot(
    DeviceDefinition Definition,
    DeviceSnapshot Snapshot,
    SystemTelemetry SystemTelemetry,
    RuntimeContext RuntimeContext,
    HostAgentSettingsLoadResult Configuration,
    LinuxNodeTelemetry? LinuxTelemetry,
    GitHubRunnerTelemetry? GitHubRunnerTelemetry);

internal sealed class HostAgentLiveSnapshotProvider
{
    private readonly WindowsSystemProbe _systemProbe = new();
    private readonly WindowsRuntimeContextProbe _runtimeProbe = new();
    private readonly ReadOnlyCommandRunner _commands = new();
    private readonly HostAgentSettingsLoadResult _configuration;
    private readonly WindowsLiveAdapters _adapters;
    private readonly DeviceDefinition _definition;

    public HostAgentLiveSnapshotProvider(HostAgentSettingsLoadResult configuration)
    {
        _configuration = configuration;
        _adapters = new WindowsLiveAdapters(_commands, configuration.Settings);
        _definition = CreateDefinition(configuration.Settings);
    }

    public async ValueTask<HostAgentLiveSnapshot> ObserveAsync(CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var runtime = _runtimeProbe.Observe();
        var system = await _systemProbe.ObserveAsync(cancellationToken);
        var definitions = _definition.Environments.SelectMany(e => e.Components)
            .ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var observations = new List<ComponentObservation>();

        observations.Add(await _adapters.ObserveTailscaleAsync(definitions[Ids.Tailscale], runtime, cancellationToken));
        observations.Add(await _adapters.ObserveRustDeskAsync(definitions[Ids.RustDesk], runtime, cancellationToken));
        observations.Add(await _adapters.ObserveDesktopCommanderAsync(definitions[Ids.DesktopCommander], runtime, cancellationToken));

        var wsl = await _adapters.ObserveWslAsync(definitions[Ids.Wsl], runtime, cancellationToken);
        observations.Add(wsl.Observation);
        observations.Add(await _adapters.ObserveCursorWorkerAsync(definitions[Ids.CursorWorker], runtime, wsl.Distro, cancellationToken));

        var linux = await _adapters.ObserveLinuxNodeAsync(definitions[Ids.LinuxNode], runtime, cancellationToken);
        observations.Add(linux.Observation);
        var runner = await _adapters.ObserveGitHubRunnerAsync(definitions[Ids.GitHubRunner], runtime, cancellationToken);
        observations.Add(runner.Observation);

        observations.Add(CreateMemoryObservation(definitions[Ids.Memory], system));
        observations.Add(CreateDiskObservation(definitions[Ids.Disk], system));
        observations.Add(CreateCpuObservation(definitions[Ids.Cpu], system));

        var aggregate = DeviceHealthAggregator.Aggregate(_definition, observations);
        var snapshot = new DeviceSnapshot(
            "local-windows-host",
            observedAt,
            observations,
            aggregate.Health,
            aggregate.Color,
            aggregate.Summary);
        return new HostAgentLiveSnapshot(_definition, snapshot, system, runtime, _configuration, linux.Telemetry, runner.Telemetry);
    }

    private static DeviceDefinition CreateDefinition(HostAgentSettings settings)
    {
        var remote = new EnvironmentDefinition("remote-access", "Remote Access",
        [
            new ComponentDefinition(Ids.Tailscale, "Tailscale", ComponentKind.Tailscale, DesiredState.Running),
            new ComponentDefinition(Ids.RustDesk, "RustDesk", ComponentKind.RustDesk, DesiredState.Running),
            new ComponentDefinition(Ids.DesktopCommander, "Desktop Commander", ComponentKind.DesktopCommander, DesiredState.RunningAfterLogin)
        ]);
        var development = new EnvironmentDefinition("development-automation", "Development / Automation",
        [
            new ComponentDefinition(Ids.Wsl, "Ubuntu (Cursor)", ComponentKind.WslUbuntu, DesiredState.OnDemand, Required: false),
            new ComponentDefinition(Ids.CursorWorker, "Cursor Worker", ComponentKind.CursorWorker, DesiredState.RunningAfterLogin, DependsOn: [Ids.Wsl]),
            new ComponentDefinition(Ids.LinuxNode, settings.LinuxNode?.DisplayName ?? "Linux CI node", ComponentKind.LinuxNode, DesiredState.Reachable),
            new ComponentDefinition(Ids.GitHubRunner, settings.GitHubRunner?.DisplayName ?? "GitHub Runner", ComponentKind.GithubRunner, DesiredState.Running, DependsOn: [Ids.LinuxNode])
        ]);
        var system = new EnvironmentDefinition("system", "System",
        [
            new ComponentDefinition(Ids.Memory, "Memory / commit pressure", ComponentKind.Memory, DesiredState.Running),
            new ComponentDefinition(Ids.Disk, "Disk", ComponentKind.Disk, DesiredState.Running),
            new ComponentDefinition(Ids.Cpu, "CPU / pressure state", ComponentKind.Cpu, DesiredState.Running)
        ]);
        return new DeviceDefinition("local-windows-host",
            string.IsNullOrWhiteSpace(settings.DeviceDisplayName) ? Environment.MachineName : settings.DeviceDisplayName,
            DevicePlatform.Windows,
            [remote, development, system]);
    }

    private static ComponentObservation CreateMemoryObservation(ComponentDefinition component, SystemTelemetry system)
    {
        var level = MemoryPressureEvaluator.Evaluate(system);
        var health = level switch
        {
            MemoryPressureLevel.Normal => HealthState.Healthy,
            MemoryPressureLevel.Elevated or MemoryPressureLevel.Severe => HealthState.Degraded,
            _ => HealthState.Unknown
        };
        var commit = system.MemoryPressure.CommitHeadroomPercent.HasValue
            ? $"{system.MemoryPressure.CommitHeadroomPercent.Value:F1}% commit headroom"
            : "commit headroom unavailable";
        return new ComponentObservation(component.Id, ObservedState.Running, health, system.ObservedAt,
            $"{system.AvailablePercent:F1}% physical memory available; {commit}; pressure assessment is {level}.");
    }

    private static ComponentObservation CreateDiskObservation(ComponentDefinition component, SystemTelemetry system)
    {
        if (system.Disks.Count == 0)
            return new ComponentObservation(component.Id, ObservedState.Unknown, HealthState.Unknown, system.ObservedAt,
                "No fixed-disk telemetry is available.");
        var freePercents = system.Disks.Where(d => d.TotalBytes > 0)
            .Select(d => d.AvailableBytes * 100d / d.TotalBytes)
            .ToArray();
        if (freePercents.Length == 0)
            return new ComponentObservation(component.Id, ObservedState.Unknown, HealthState.Unknown, system.ObservedAt,
                "Fixed disks were observed but capacity could not be evaluated.");
        var lowest = freePercents.Min();
        return new ComponentObservation(component.Id, ObservedState.Running,
            lowest < 10 ? HealthState.Degraded : HealthState.Healthy,
            system.ObservedAt,
            $"{system.Disks.Count} fixed disk(s) observed; lowest free capacity is {lowest:F1}%.");
    }

    private static ComponentObservation CreateCpuObservation(ComponentDefinition component, SystemTelemetry system)
    {
        if (!system.CpuBusyPercent.HasValue)
            return new ComponentObservation(component.Id, ObservedState.Unknown, HealthState.Unknown, system.ObservedAt,
                "Short CPU sample is unavailable.");
        return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Healthy, system.ObservedAt,
            $"Short CPU sample is {system.CpuBusyPercent.Value.ToString("F1", CultureInfo.InvariantCulture)}%; no alarm is derived from a single short sample.");
    }

    internal static class Ids
    {
        public const string Tailscale = "remote.tailscale";
        public const string RustDesk = "remote.rustdesk";
        public const string DesktopCommander = "remote.desktop-commander";
        public const string Wsl = "dev.wsl-ubuntu";
        public const string CursorWorker = "dev.cursor-worker";
        public const string LinuxNode = "dev.linux-ci-node";
        public const string GitHubRunner = "dev.github-runner";
        public const string Memory = "system.memory";
        public const string Disk = "system.disk";
        public const string Cpu = "system.cpu";
    }
}
