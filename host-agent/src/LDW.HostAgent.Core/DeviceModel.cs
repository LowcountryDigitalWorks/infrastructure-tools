namespace LDW.HostAgent.Core;

public enum DevicePlatform { Windows, Linux, Unknown }
public enum DesiredState { Running, Stopped, Disabled, OnDemand, RunningAfterLogin, Reachable }
public enum ObservedState { Running, Stopped, Disabled, Unavailable, Unknown }
public enum HealthState { Healthy, Degraded, Failed, Initializing, Unknown }
public enum ActivityState { None, ActiveCiJob, CiBoostEnabled }
public enum OwnerSessionState { Unknown, Inactive, Active }
public enum StatusColor { Green, Blue, Purple, Yellow, Red, Gray }
public enum ComponentKind
{
    OperatingSystem, Memory, Disk, Cpu, Tailscale, RustDesk, DesktopCommander,
    WslUbuntu, CursorWorker, LinuxNode, HyperV, GithubRunner, Custom
}

public sealed record RuntimeContext(OwnerSessionState OwnerSession);

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
    string? Evidence = null,
    ActivityState Activity = ActivityState.None)
{
    public StatusColor Color => Health switch
    {
        HealthState.Failed => StatusColor.Red,
        HealthState.Degraded => StatusColor.Yellow,
        HealthState.Initializing or HealthState.Unknown => StatusColor.Gray,
        _ => Activity switch
        {
            ActivityState.CiBoostEnabled => StatusColor.Purple,
            ActivityState.ActiveCiJob => StatusColor.Blue,
            _ => StatusColor.Green
        }
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
    public static HealthState Evaluate(ComponentDefinition component, ObservedState observed, RuntimeContext runtime)
    {
        if (observed == ObservedState.Unknown)
            return HealthState.Unknown;

        if (component.DesiredState == DesiredState.RunningAfterLogin)
        {
            if (observed == ObservedState.Running)
                return HealthState.Healthy;

            if (observed is ObservedState.Stopped or ObservedState.Disabled)
            {
                return runtime.OwnerSession switch
                {
                    OwnerSessionState.Inactive => HealthState.Healthy,
                    OwnerSessionState.Unknown => HealthState.Unknown,
                    _ => component.Required ? HealthState.Failed : HealthState.Degraded
                };
            }

            return component.Required ? HealthState.Failed : HealthState.Degraded;
        }

        return component.DesiredState switch
        {
            DesiredState.Running or DesiredState.Reachable when observed == ObservedState.Running => HealthState.Healthy,
            DesiredState.Stopped or DesiredState.Disabled when observed is ObservedState.Stopped or ObservedState.Disabled => HealthState.Healthy,
            DesiredState.OnDemand when observed is ObservedState.Running or ObservedState.Stopped or ObservedState.Disabled => HealthState.Healthy,
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
            return (HealthState.Healthy, ResolveHealthyColor(observations), ResolveHealthySummary(observations, "No required components are configured."));

        var byId = observations.ToDictionary(o => o.ComponentId, StringComparer.OrdinalIgnoreCase);
        var health = required.Select(c =>
        {
            var own = byId.TryGetValue(c.Id, out var observation) ? observation.Health : HealthState.Initializing;
            if (own is HealthState.Failed or HealthState.Degraded or HealthState.Initializing or HealthState.Unknown)
                return own;

            // Dependencies only need to be available while this component is itself expected to be active.
            // This prevents an intentionally inactive pre-login/on-demand component from failing solely because
            // its dependency is also intentionally inactive, while preserving dependency checks for active work.
            if (observation is not null
                && observation.State is ObservedState.Stopped or ObservedState.Disabled
                && c.DesiredState is DesiredState.Stopped or DesiredState.Disabled or DesiredState.OnDemand or DesiredState.RunningAfterLogin)
                return own;

            foreach (var dependencyId in c.DependsOn ?? [])
            {
                if (!byId.TryGetValue(dependencyId, out var dependency))
                    return HealthState.Initializing;
                if (dependency.Health == HealthState.Failed)
                    return HealthState.Failed;
                if (dependency.Health is HealthState.Degraded or HealthState.Initializing or HealthState.Unknown)
                    return dependency.Health;
                if (dependency.State != ObservedState.Running)
                    return HealthState.Failed;
            }

            return own;
        }).ToArray();

        var aggregate = health.Contains(HealthState.Failed) ? HealthState.Failed
            : health.Contains(HealthState.Degraded) ? HealthState.Degraded
            : health.Contains(HealthState.Initializing) ? HealthState.Initializing
            : health.Contains(HealthState.Unknown) ? HealthState.Unknown
            : HealthState.Healthy;

        var color = aggregate switch
        {
            HealthState.Failed => StatusColor.Red,
            HealthState.Degraded => StatusColor.Yellow,
            HealthState.Initializing or HealthState.Unknown => StatusColor.Gray,
            _ => ResolveHealthyColor(observations)
        };

        var summary = aggregate switch
        {
            HealthState.Healthy => ResolveHealthySummary(observations, "All required components match their desired state."),
            HealthState.Degraded => "A required component needs attention.",
            HealthState.Failed => "A required component is unavailable or failed.",
            HealthState.Unknown => "Required component status is not yet known.",
            _ => "Host Agent is collecting its first observations."
        };

        return (aggregate, color, summary);
    }

    private static StatusColor ResolveHealthyColor(IReadOnlyCollection<ComponentObservation> observations)
    {
        if (observations.Any(o => o.Activity == ActivityState.CiBoostEnabled))
            return StatusColor.Purple;
        if (observations.Any(o => o.Activity == ActivityState.ActiveCiJob))
            return StatusColor.Blue;
        return StatusColor.Green;
    }

    private static string ResolveHealthySummary(IReadOnlyCollection<ComponentObservation> observations, string fallback)
    {
        if (observations.Any(o => o.Activity == ActivityState.CiBoostEnabled))
            return "CI Boost is enabled; required components remain healthy for their desired state.";
        if (observations.Any(o => o.Activity == ActivityState.ActiveCiJob))
            return "A CI job is active; required components remain healthy for their desired state.";
        return fallback;
    }
}
