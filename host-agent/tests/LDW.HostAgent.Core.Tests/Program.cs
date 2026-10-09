using LDW.HostAgent.Core;

var now = DateTimeOffset.UtcNow;
var required = new ComponentDefinition("runner", "Runner", ComponentKind.GithubRunner, DesiredState.Running);
var onDemand = new ComponentDefinition("wsl", "Ubuntu", ComponentKind.WslUbuntu, DesiredState.OnDemand, Required: false);
Assert(DesiredStateEvaluator.Evaluate(required, ObservedState.Running) == HealthState.Healthy, "required running component is healthy");
Assert(DesiredStateEvaluator.Evaluate(required, ObservedState.Stopped) == HealthState.Failed, "required stopped component fails");
Assert(DesiredStateEvaluator.Evaluate(onDemand, ObservedState.Stopped) == HealthState.ExpectedInactive, "on-demand stopped component is expected");
Assert(DesiredStateEvaluator.Evaluate(onDemand, ObservedState.Unknown) == HealthState.Unknown, "unknown state remains unknown");

var device = new DeviceDefinition("test-device", "Test device", DevicePlatform.Linux,
    [new EnvironmentDefinition("automation", "Automation", [required, onDemand])]);
var inactiveObservation = new ComponentObservation("wsl", ObservedState.Stopped, HealthState.ExpectedInactive, now, "On demand");
var healthyObservation = new ComponentObservation("runner", ObservedState.Running, HealthState.Healthy, now, "Online");
var aggregate = DeviceHealthAggregator.Aggregate(device, [inactiveObservation, healthyObservation]);
Assert(aggregate.Health == HealthState.Healthy && aggregate.Color == StatusColor.Green, "optional idle workload does not degrade healthy device");
var failed = DeviceHealthAggregator.Aggregate(device,
    [inactiveObservation, healthyObservation with { Health = HealthState.Failed }]);
Assert(failed.Health == HealthState.Failed && failed.Color == StatusColor.Red, "required failure is red");
var dependentDevice = device with
{
    Environments = [new EnvironmentDefinition("automation", "Automation", [required with { DependsOn = ["wsl"] }, onDemand])]
};
var dependencyFailure = DeviceHealthAggregator.Aggregate(dependentDevice, [inactiveObservation, healthyObservation]);
Assert(dependencyFailure.Health == HealthState.Failed, "unavailable dependency fails its required dependent");

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
Console.WriteLine("Host Agent core contract tests passed (12 assertions).");

static void Assert(bool condition, string description)
{
    if (!condition) throw new InvalidOperationException($"FAILED: {description}");
}
