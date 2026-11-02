namespace LDW.HostAgent.Core;

public static class CodyncHealthContract
{
    public const string FixedLoopbackEndpoint = "http://127.0.0.1:19222/health";
    public const string LoopbackHost = "127.0.0.1";
    public const int LoopbackPort = 19222;
    public const string HealthPath = "/health";

    public static readonly Uri EndpointUri = new("http://127.0.0.1:19222/health", UriKind.Absolute);

    public static ComponentObservation Evaluate(
        ComponentDefinition component,
        RuntimeContext runtime,
        CodyncProbeResult probeResult,
        DateTimeOffset observedAt)
    {
        if (probeResult.TimedOut)
        {
            const ObservedState state = ObservedState.Unknown;
            const HealthState health = HealthState.Degraded;

            return new ComponentObservation(
                component.Id,
                state,
                health,
                observedAt,
                "Codync background host health probe timed out on loopback.");
        }

        if (probeResult.ConnectionRefused)
        {
            const ObservedState state = ObservedState.Stopped;
            var health = DesiredStateEvaluator.Evaluate(component, state, runtime);
            var summary = health == HealthState.Initializing && component.DesiredState == DesiredState.RunningAfterLogin
                ? $"{component.Name} is initializing after sign-in; waiting for its post-login startup window."
                : runtime.OwnerSession == OwnerSessionState.Inactive && component.DesiredState == DesiredState.RunningAfterLogin
                    ? "Codync background host is intentionally inactive before owner login."
                    : "Codync background host is not responding on loopback (connection refused).";

            return new ComponentObservation(
                component.Id,
                state,
                health,
                observedAt,
                summary);
        }

        if (probeResult.Unavailable || !probeResult.HttpStatusCode.HasValue)
        {
            const ObservedState state = ObservedState.Unavailable;
            var health = DesiredStateEvaluator.Evaluate(component, state, runtime);
            return new ComponentObservation(
                component.Id,
                state,
                health,
                observedAt,
                "Codync background host health endpoint is unavailable on loopback.");
        }

        var statusCode = probeResult.HttpStatusCode.Value;
        if (statusCode == 200)
        {
            const ObservedState state = ObservedState.Running;
            var health = DesiredStateEvaluator.Evaluate(component, state, runtime);
            return new ComponentObservation(
                component.Id,
                state,
                health,
                observedAt,
                "Codync background host is running and healthy on loopback.");
        }

        {
            const ObservedState state = ObservedState.Running;
            const HealthState health = HealthState.Degraded;
            return new ComponentObservation(
                component.Id,
                state,
                health,
                observedAt,
                $"Codync background host returned HTTP {statusCode} on loopback.");
        }
    }
}

public sealed record CodyncProbeResult(
    int? HttpStatusCode,
    bool ConnectionRefused = false,
    bool TimedOut = false,
    bool Unavailable = false);

public interface ICodyncHealthClient
{
    ValueTask<CodyncProbeResult> ProbeHealthAsync(CancellationToken cancellationToken);
}
