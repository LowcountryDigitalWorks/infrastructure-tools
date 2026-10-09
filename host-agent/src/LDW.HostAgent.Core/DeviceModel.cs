namespace LDW.HostAgent.Core;

public enum DevicePlatform { Windows, Linux, Unknown }
public enum DesiredState { Running, Stopped, Disabled, OnDemand, RunningAfterLogin, Reachable }
public enum ObservedState { Running, Stopped, Disabled, Unavailable, Unknown }
public enum HealthState { Healthy, ExpectedInactive, ResourceWorkload, Degraded, Failed, Initializing, Unknown }
public enum StatusColor { Green, Blue, Purple, Yellow, Red, Gray }
public enum ComponentKind
{
    OperatingSystem, Memory, Disk, Cpu, Tailscale, RustDesk, DesktopCommander,
    WslUbuntu, CursorWorker, LinuxNode, HyperV, GithubRunner, Custom
}

public sealed record DeviceDefinition(
    string Id,
    string Name,
    DevicePlatform Platform,
    IReadOnlyList<EnvironmentDefinition> Environments);

public sealed record EnvironmentDefinition(string Id, string Name, IReadOnlyList<ComponentDefinition> Components);

public sealed record ComponentDefinition(
    string Id,
    string Name,
    ComponentKind Kind,
    DesiredState DesiredState,
    bool Required = true,
    IReadOnlyList<string>? DependsOn = null);

public sealed record ComponentObservation(
    string ComponentId,
    ObservedState State,
    HealthState Health,
    DateTimeOffset ObservedAt,
    string Summary,
    string? Evidence = null)
{
    public StatusColor Color => Health switch
    {
        HealthState.Healthy => StatusColor.Green,
        HealthState.ExpectedInactive => StatusColor.Blue,
        HealthState.ResourceWorkload => StatusColor.Purple,
        HealthState.Degraded => StatusColor.Yellow,
        HealthState.Failed => StatusColor.Red,
        _ => StatusColor.Gray
    };
}

public sealed record DeviceSnapshot(
    string DeviceId,
    DateTimeOffset ObservedAt,
    IReadOnlyList<ComponentObservation> Components,
    HealthState Health,
    StatusColor Color,
    string Summary);

public static class DesiredStateEvaluator
{
    public static HealthState Evaluate(ComponentDefinition component, ObservedState observed)
    {
        if (observed == ObservedState.Unknown)
            return HealthState.Unknown;

        return component.DesiredState switch
        {
            DesiredState.Running or DesiredState.Reachable when observed == ObservedState.Running => HealthState.Healthy,
            DesiredState.Stopped or DesiredState.Disabled when observed is ObservedState.Stopped or ObservedState.Disabled => HealthState.ExpectedInactive,
            DesiredState.OnDemand when observed is ObservedState.Stopped or ObservedState.Disabled => HealthState.ExpectedInactive,
            DesiredState.RunningAfterLogin when observed is ObservedState.Stopped or ObservedState.Disabled => HealthState.ExpectedInactive,
            _ => component.Required ? HealthState.Failed : HealthState.Degraded
        };
    }
}

public static class DeviceHealthAggregator
{
    public static (HealthState Health, StatusColor Color, string Summary) Aggregate(
        DeviceDefinition device,
        IReadOnlyCollection<ComponentObservation> observations)
    {
        var required = device.Environments.SelectMany(e => e.Components).Where(c => c.Required).ToArray();
        if (required.Length == 0)
            return (HealthState.Healthy, StatusColor.Green, "No required components are configured.");

        var byId = observations.ToDictionary(o => o.ComponentId, StringComparer.OrdinalIgnoreCase);
        var health = required.Select(c =>
        {
            var own = byId.TryGetValue(c.Id, out var observation) ? observation.Health : HealthState.Initializing;
            if (own is HealthState.Failed or HealthState.Degraded or HealthState.Initializing or HealthState.Unknown)
                return own;
            foreach (var dependencyId in c.DependsOn ?? [])
            {
                if (!byId.TryGetValue(dependencyId, out var dependency))
                    return HealthState.Initializing;
                if (dependency.Health is HealthState.Failed or HealthState.ExpectedInactive)
                    return HealthState.Failed;
                if (dependency.Health is HealthState.Degraded or HealthState.Initializing or HealthState.Unknown)
                    return dependency.Health;
            }
            return own;
        }).ToArray();
        var aggregate = health.Contains(HealthState.Failed) ? HealthState.Failed
            : health.Contains(HealthState.Degraded) ? HealthState.Degraded
            : health.Contains(HealthState.Initializing) ? HealthState.Initializing
            : health.Contains(HealthState.Unknown) ? HealthState.Unknown
            : health.Contains(HealthState.ResourceWorkload) ? HealthState.ResourceWorkload
            : health.Contains(HealthState.ExpectedInactive) ? HealthState.ExpectedInactive
            : HealthState.Healthy;
        var color = aggregate switch
        {
            HealthState.Healthy => StatusColor.Green,
            HealthState.ExpectedInactive => StatusColor.Blue,
            HealthState.ResourceWorkload => StatusColor.Purple,
            HealthState.Degraded => StatusColor.Yellow,
            HealthState.Failed => StatusColor.Red,
            _ => StatusColor.Gray
        };
        var summary = aggregate switch
        {
            HealthState.Healthy => "All required components match their desired state.",
            HealthState.ExpectedInactive => "A required component is intentionally inactive.",
            HealthState.ResourceWorkload => "A known resource workload is active.",
            HealthState.Degraded => "A required component needs attention.",
            HealthState.Failed => "A required component is unavailable or failed.",
            HealthState.Unknown => "Required component status is not yet known.",
            _ => "Host Agent is collecting its first observations."
        };
        return (aggregate, color, summary);
    }
}
