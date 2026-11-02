using System.Runtime.CompilerServices;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Core.Tests;

internal static class CodyncHealthContractTests
{
    [ModuleInitializer]
    internal static void Run()
    {
        var now = DateTimeOffset.UtcNow;
        var activeSession = new RuntimeContext(OwnerSessionState.Active);
        var inactiveSession = new RuntimeContext(OwnerSessionState.Inactive);
        var unknownSession = new RuntimeContext(OwnerSessionState.Unknown);
        var settlingSession = new RuntimeContext(OwnerSessionState.Active, OwnerSessionSettling: true);

        var component = new ComponentDefinition(
            "dev.codync-host",
            "Codync background host",
            ComponentKind.CodyncHost,
            DesiredState.RunningAfterLogin,
            Required: true);

        // 1. Fixed loopback-only contract verification
        Assert(CodyncHealthContract.FixedLoopbackEndpoint == "http://127.0.0.1:19222/health", "fixed loopback endpoint must match exactly");
        Assert(CodyncHealthContract.LoopbackHost == "127.0.0.1", "host must be loopback 127.0.0.1");
        Assert(CodyncHealthContract.LoopbackPort == 19222, "port must be 19222");
        Assert(CodyncHealthContract.HealthPath == "/health", "path must be /health");
        Assert(CodyncHealthContract.EndpointUri.IsLoopback, "URI must be loopback");
        Assert(CodyncHealthContract.EndpointUri.Port == 19222, "URI port must be 19222");
        Assert(CodyncHealthContract.EndpointUri.AbsolutePath == "/health", "URI path must be /health");

        // 2. Valid health => healthy / running
        var healthyProbe = new CodyncProbeResult(200);
        var healthyObs = CodyncHealthContract.Evaluate(component, activeSession, healthyProbe, now);
        Assert(healthyObs.State == ObservedState.Running, "HTTP 200 must observe Running state");
        Assert(healthyObs.Health == HealthState.Healthy, "HTTP 200 must evaluate to Healthy");
        Assert(healthyObs.Color == StatusColor.Green, "Healthy must yield Green status color");
        Assert(healthyObs.Summary.Contains("running and healthy", StringComparison.Ordinal), "summary must state running and healthy");
        Assert(healthyObs.ObservedAt == now, "freshness timestamp must be preserved");

        // 3. Connection refused => Stopped; fail-closed according to session context
        var refusedProbe = new CodyncProbeResult(null, ConnectionRefused: true);

        // Active session with expired settle window => Failed (Required = true)
        var failedRefusedObs = CodyncHealthContract.Evaluate(component, activeSession, refusedProbe, now);
        Assert(failedRefusedObs.State == ObservedState.Stopped, "connection refused must observe Stopped");
        Assert(failedRefusedObs.Health == HealthState.Failed, "post-login active connection refused must evaluate to Failed");
        Assert(failedRefusedObs.Color == StatusColor.Red, "Failed must yield Red status color");
        Assert(failedRefusedObs.Summary.Contains("connection refused", StringComparison.Ordinal), "summary must mention connection refused");

        // Active session during settle window => Initializing
        var settlingRefusedObs = CodyncHealthContract.Evaluate(component, settlingSession, refusedProbe, now);
        Assert(settlingRefusedObs.State == ObservedState.Stopped, "settling connection refused must observe Stopped");
        Assert(settlingRefusedObs.Health == HealthState.Initializing, "settling session must evaluate to Initializing");
        Assert(settlingRefusedObs.Color == StatusColor.Gray, "Initializing must yield Gray status color");
        Assert(settlingRefusedObs.Summary.Contains("initializing after sign-in", StringComparison.Ordinal), "summary must mention post-login settle window");

        // Inactive session pre-login => Healthy (intentionally inactive before login)
        var preLoginRefusedObs = CodyncHealthContract.Evaluate(component, inactiveSession, refusedProbe, now);
        Assert(preLoginRefusedObs.State == ObservedState.Stopped, "pre-login connection refused must observe Stopped");
        Assert(preLoginRefusedObs.Health == HealthState.Healthy, "pre-login stopped component must evaluate to Healthy");
        Assert(preLoginRefusedObs.Color == StatusColor.Green, "pre-login healthy stopped component must yield Green status color");
        Assert(preLoginRefusedObs.Summary.Contains("intentionally inactive", StringComparison.Ordinal), "summary must state intentionally inactive before login");

        // Unknown session => Unknown
        var unknownSessionObs = CodyncHealthContract.Evaluate(component, unknownSession, refusedProbe, now);
        Assert(unknownSessionObs.Health == HealthState.Unknown, "unknown session must evaluate to Unknown");
        Assert(unknownSessionObs.Color == StatusColor.Gray, "Unknown must yield Gray status color");

        // 4. Timeout fail closed
        var timedOutProbe = new CodyncProbeResult(null, TimedOut: true);
        var timeoutObs = CodyncHealthContract.Evaluate(component, activeSession, timedOutProbe, now);
        Assert(timeoutObs.State == ObservedState.Unknown, "timeout must observe Unknown state");
        Assert(timeoutObs.Health == HealthState.Degraded, "timeout must fail closed to Degraded, never Healthy");
        Assert(timeoutObs.Color == StatusColor.Yellow, "Degraded timeout must yield Yellow status color");
        Assert(timeoutObs.Summary.Contains("timed out", StringComparison.Ordinal), "summary must mention timeout");

        // Timeout even pre-login must not fabricate Healthy
        var preLoginTimeoutObs = CodyncHealthContract.Evaluate(component, inactiveSession, timedOutProbe, now);
        Assert(preLoginTimeoutObs.Health != HealthState.Healthy, "timeout must never fabricate Healthy even pre-login");

        // 5. Non-200 HTTP response fail closed (e.g. 500, 503, 404)
        var serverErrorProbe = new CodyncProbeResult(500);
        var serverErrorObs = CodyncHealthContract.Evaluate(component, activeSession, serverErrorProbe, now);
        Assert(serverErrorObs.State == ObservedState.Running, "non-200 must observe Running host");
        Assert(serverErrorObs.Health == HealthState.Degraded, "HTTP 500 must fail closed to Degraded, never Healthy");
        Assert(serverErrorObs.Color == StatusColor.Yellow, "HTTP 500 must yield Yellow status color");
        Assert(serverErrorObs.Summary.Contains("HTTP 500", StringComparison.Ordinal), "summary must mention HTTP status code");

        var notFoundProbe = new CodyncProbeResult(404);
        var notFoundObs = CodyncHealthContract.Evaluate(component, activeSession, notFoundProbe, now);
        Assert(notFoundObs.Health == HealthState.Degraded, "HTTP 404 must fail closed to Degraded");
        Assert(notFoundObs.Summary.Contains("HTTP 404", StringComparison.Ordinal), "summary must mention HTTP 404");

        // 6. Endpoint unavailable / null status code
        var unavailableProbe = new CodyncProbeResult(null, Unavailable: true);
        var unavailableObs = CodyncHealthContract.Evaluate(component, activeSession, unavailableProbe, now);
        Assert(unavailableObs.State == ObservedState.Unavailable, "unavailable probe must observe Unavailable");
        Assert(unavailableObs.Health == HealthState.Failed, "required component unavailable must evaluate to Failed");
        Assert(unavailableObs.Color == StatusColor.Red, "Failed must yield Red status color");

        // 7. No response body leakage
        const string syntheticSecretBody = "{\"secret\":\"top-secret-token\",\"binaryPath\":\"C:\\\\private\\\\path\\\\codync-host.exe\"}";
        // The evaluation method does not even accept a response body parameter:
        Assert(!typeof(CodyncHealthContract).GetMethod("Evaluate")!.GetParameters().Any(p => p.Name!.Contains("body", StringComparison.OrdinalIgnoreCase)),
            "Evaluate method must not take response body parameters");
        Assert(!serverErrorObs.Summary.Contains(syntheticSecretBody, StringComparison.Ordinal), "summary must not leak body");
        Assert(serverErrorObs.Evidence is null, "evidence must remain null without body leaks");

        // 8. Aggregate health and attention participation
        var testDevice = new DeviceDefinition(
            "test-device",
            "Test Device",
            DevicePlatform.Windows,
            [
                new EnvironmentDefinition("development-automation", "Development / Automation", [component])
            ]);

        // When Codync is Healthy => Device is Healthy / Green
        var aggregateHealthy = DeviceHealthAggregator.Aggregate(testDevice, [healthyObs]);
        Assert(aggregateHealthy.Health == HealthState.Healthy, "aggregate must be Healthy when Codync is healthy");
        Assert(aggregateHealthy.Color == StatusColor.Green, "aggregate must be Green when Codync is healthy");

        // When Codync is Failed => Device is Failed / Red / attention
        var aggregateFailed = DeviceHealthAggregator.Aggregate(testDevice, [failedRefusedObs]);
        Assert(aggregateFailed.Health == HealthState.Failed, "aggregate must be Failed when Codync is failed");
        Assert(aggregateFailed.Color == StatusColor.Red, "aggregate must be Red when Codync is failed");
        Assert(aggregateFailed.Summary.Contains("unavailable or failed", StringComparison.Ordinal), "summary must reflect failed component");

        // When Codync is Degraded (e.g. timeout or HTTP 500) => Device is Degraded / Yellow / attention
        var aggregateDegraded = DeviceHealthAggregator.Aggregate(testDevice, [timeoutObs]);
        Assert(aggregateDegraded.Health == HealthState.Degraded, "aggregate must be Degraded when Codync is degraded");
        Assert(aggregateDegraded.Color == StatusColor.Yellow, "aggregate must be Yellow when Codync is degraded");
        Assert(aggregateDegraded.Summary.Contains("needs attention", StringComparison.Ordinal), "summary must reflect attention required");

        // 9. No mutation or restart logic contract
        var contractMethods = typeof(CodyncHealthContract).GetMethods();
        Assert(!contractMethods.Any(m => m.Name.Contains("Restart", StringComparison.OrdinalIgnoreCase) ||
                                         m.Name.Contains("Start", StringComparison.OrdinalIgnoreCase) ||
                                         m.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                                         m.Name.Contains("Write", StringComparison.OrdinalIgnoreCase)),
            "CodyncHealthContract must not declare mutation/restart/control methods");
    }

    private static void Assert(bool condition, string description)
    {
        if (!condition)
            throw new InvalidOperationException($"FAILED Codync health contract: {description}");
    }
}
