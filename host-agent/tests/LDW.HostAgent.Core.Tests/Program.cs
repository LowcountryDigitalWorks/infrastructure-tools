using LDW.HostAgent.Core;

var assertionCount = 0;
var now = DateTimeOffset.UtcNow;
var activeSession = new RuntimeContext(OwnerSessionState.Active);
var inactiveSession = new RuntimeContext(OwnerSessionState.Inactive);
var unknownSession = new RuntimeContext(OwnerSessionState.Unknown);
var required = new ComponentDefinition("runner", "Runner", ComponentKind.GithubRunner, DesiredState.Running);
var onDemand = new ComponentDefinition("wsl", "Ubuntu", ComponentKind.WslUbuntu, DesiredState.OnDemand, Required: false);
var afterLogin = new ComponentDefinition("cursor-worker", "Cursor Worker", ComponentKind.CursorWorker, DesiredState.RunningAfterLogin);

Assert(DesiredStateEvaluator.Evaluate(required, ObservedState.Running, activeSession) == HealthState.Healthy, "required running component is healthy");
Assert(DesiredStateEvaluator.Evaluate(required, ObservedState.Stopped, activeSession) == HealthState.Failed, "required stopped component fails");
Assert(DesiredStateEvaluator.Evaluate(onDemand, ObservedState.Stopped, activeSession) == HealthState.Healthy, "on-demand stopped component is healthy for desired state");
Assert(DesiredStateEvaluator.Evaluate(onDemand, ObservedState.Running, activeSession) == HealthState.Healthy, "on-demand running component is healthy while active");
Assert(DesiredStateEvaluator.Evaluate(onDemand, ObservedState.Unknown, activeSession) == HealthState.Unknown, "unknown state remains unknown");
Assert(DesiredStateEvaluator.Evaluate(afterLogin, ObservedState.Stopped, inactiveSession) == HealthState.Healthy, "pre-login stopped RunningAfterLogin component is intentionally inactive");
Assert(DesiredStateEvaluator.Evaluate(afterLogin, ObservedState.Running, activeSession) == HealthState.Healthy, "post-login running RunningAfterLogin component is healthy");
Assert(DesiredStateEvaluator.Evaluate(afterLogin, ObservedState.Stopped, activeSession) == HealthState.Failed, "post-login stopped RunningAfterLogin component fails");
Assert(DesiredStateEvaluator.Evaluate(afterLogin, ObservedState.Stopped, unknownSession) == HealthState.Unknown, "unknown owner-session context does not hide RunningAfterLogin state");

var inactiveObservation = new ComponentObservation("wsl", ObservedState.Stopped, HealthState.Healthy, now, "On demand and intentionally inactive");
var healthyObservation = new ComponentObservation("runner", ObservedState.Running, HealthState.Healthy, now, "Online");
Assert(inactiveObservation.Color == StatusColor.Green, "intentional inactivity remains green healthy-for-desired-state");
Assert((healthyObservation with { Activity = ActivityState.ActiveCiJob }).Color == StatusColor.Blue, "active CI job is blue");
Assert((healthyObservation with { Activity = ActivityState.CiBoostEnabled }).Color == StatusColor.Purple, "CI Boost enabled is purple");
Assert((healthyObservation with { Health = HealthState.Degraded, Activity = ActivityState.CiBoostEnabled }).Color == StatusColor.Yellow, "degraded health is yellow even when CI Boost is enabled");
Assert((healthyObservation with { Health = HealthState.Unknown }).Color == StatusColor.Gray, "unknown health is gray");
Assert((healthyObservation with { Health = HealthState.Initializing }).Color == StatusColor.Gray, "initializing health is gray");

var device = new DeviceDefinition("test-device", "Test device", DevicePlatform.Linux,
    [new EnvironmentDefinition("automation", "Automation", [required, onDemand])]);
var aggregate = DeviceHealthAggregator.Aggregate(device, [inactiveObservation, healthyObservation]);
Assert(aggregate.Health == HealthState.Healthy && aggregate.Color == StatusColor.Green, "optional idle workload does not degrade healthy device");
var activeCi = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Activity = ActivityState.ActiveCiJob }]);
Assert(activeCi.Health == HealthState.Healthy && activeCi.Color == StatusColor.Blue, "healthy device with active CI job is blue");
var boost = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Activity = ActivityState.CiBoostEnabled }]);
Assert(boost.Health == HealthState.Healthy && boost.Color == StatusColor.Purple, "healthy device with CI Boost enabled is purple");
var failed = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Health = HealthState.Failed, Activity = ActivityState.ActiveCiJob }]);
Assert(failed.Health == HealthState.Failed && failed.Color == StatusColor.Red, "failure remains red even when CI activity exists");
var degraded = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Health = HealthState.Degraded, Activity = ActivityState.CiBoostEnabled }]);
Assert(degraded.Health == HealthState.Degraded && degraded.Color == StatusColor.Yellow, "aggregate degraded health is yellow");
var unknown = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Health = HealthState.Unknown }]);
Assert(unknown.Health == HealthState.Unknown && unknown.Color == StatusColor.Gray, "aggregate unknown health is gray");

var dependentDevice = device with
{
    Environments = [new EnvironmentDefinition("automation", "Automation", [required with { DependsOn = ["wsl"] }, onDemand])]
};
var dependencyFailure = DeviceHealthAggregator.Aggregate(dependentDevice, [inactiveObservation, healthyObservation]);
Assert(dependencyFailure.Health == HealthState.Failed, "healthy-for-desired-state inactive dependency still fails an active required dependent");

var normal = new SystemTelemetry(now, 16_000, 8_000, null, [], new MemoryPressureTelemetry(null, 0, 0, 0, 0, TimeSpan.Zero, "normal"));
Assert(MemoryPressureEvaluator.Evaluate(normal) == MemoryPressureLevel.Normal, "healthy headroom is normal");
var temporaryLow = normal with { AvailablePhysicalBytes = 500 };
Assert(MemoryPressureEvaluator.Evaluate(temporaryLow) == MemoryPressureLevel.Elevated, "low available memory is attention, not severe by itself");
var sustainedPressure = temporaryLow with { MemoryPressure = new MemoryPressureTelemetry(5, 100, 100, 2, 1, TimeSpan.FromSeconds(45), "sustained paging") };
Assert(MemoryPressureEvaluator.Evaluate(sustainedPressure) == MemoryPressureLevel.Severe, "severe status requires sustained multiple pressure signals");
var invalidSsh = new StrictSshConnectionPolicy("known_hosts", "identity", false, true, true);
try
{
    invalidSsh.Validate();
    throw new InvalidOperationException("FAILED: SSH policy accepted disabled host-key checking");
}
catch (InvalidOperationException ex) when (ex.Message.Contains("requires an explicit identity", StringComparison.Ordinal)) { }
new StrictSshConnectionPolicy("known_hosts", "identity", true, true, true).Validate();
Assert(true, "strict SSH policy accepts explicit fail-closed settings");
Console.WriteLine($"Host Agent core contract tests passed ({assertionCount} assertions).");

void Assert(bool condition, string description)
{
    assertionCount++;
    if (!condition) throw new InvalidOperationException($"FAILED: {description}");
}
