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
Assert(OwnerSessionStateMapper.FromWtsConnectState(0) == OwnerSessionState.Active, "WTS active maps to active owner session");
Assert(OwnerSessionStateMapper.FromWtsConnectState(4) == OwnerSessionState.Inactive, "WTS disconnected maps to inactive owner session");
Assert(OwnerSessionStateMapper.FromWtsConnectState(null) == OwnerSessionState.Unknown, "missing WTS state maps to unknown owner session");

var tailscaleStatus = TailscaleStatusParser.Parse("{\"BackendState\":\"Running\",\"Self\":{\"Online\":true},\"Health\":[]}");
Assert(tailscaleStatus.Ready && tailscaleStatus.HealthIssueCount == 0, "Tailscale parser derives readiness without exposing address fields");
var tailscaleAttention = TailscaleStatusParser.Parse("{\"BackendState\":\"Running\",\"Self\":{\"Online\":true},\"Health\":[\"attention\"]}");
Assert(!tailscaleAttention.Ready && tailscaleAttention.HealthIssueCount == 1, "Tailscale health attention prevents ready state");
Assert(TailscalePrefsParser.ParseForceDaemon("{\"ForceDaemon\":true}") == true, "Tailscale prefs parser recognizes unattended/server mode");
Assert(TailscalePrefsParser.ParseForceDaemon("{\"ForceDaemon\":false}") == false, "Tailscale prefs parser recognizes disabled unattended/server mode");
Assert(ReadOnlyStatusParsers.IsWindowsServiceAutomatic("START_TYPE         : 2   AUTO_START") == true, "service config parser recognizes automatic start");
Assert(ReadOnlyStatusParsers.IsWindowsServiceAutomatic("START_TYPE         : 3   DEMAND_START") == false, "service config parser recognizes demand start");

var wslText = "  NAME      STATE           VERSION\r\n* Ubuntu    Running         2\r\n  Test Distro  Stopped      2\r\n";
var wslDistros = WslListParser.Parse(wslText);
Assert(wslDistros.Count == 2 && wslDistros[0].Name == "Ubuntu" && wslDistros[0].State == ObservedState.Running, "WSL parser maps running distro");
Assert(wslDistros[1].Name == "Test Distro" && wslDistros[1].State == ObservedState.Stopped, "WSL parser preserves spaced distro name and stopped state");
Assert(ReadOnlyStatusParsers.IsWindowsServiceRunning("STATE              : 4  RUNNING"), "SC service parser recognizes running service");
Assert(ReadOnlyStatusParsers.ParseScheduledTaskRunning("\"\\Task\",\"N/A\",\"Running\"") == true, "scheduled task parser recognizes running state");
Assert(ReadOnlyStatusParsers.ParseSystemctlIsActive("failed\n") == ObservedState.Stopped, "systemctl failed maps to stopped");

var runnerTelemetry = GitHubRunnerStatusParser.Parse("{\"id\":12345,\"name\":\"test-runner\",\"status\":\"online\",\"busy\":true,\"labels\":[{\"name\":\"self-hosted\"},{\"name\":\"test-label\"}]}");
Assert(runnerTelemetry.Id == 12345 && runnerTelemetry.Online && runnerTelemetry.Busy && runnerTelemetry.Labels.Count == 2, "GitHub Runner parser maps online/busy/id/labels");

var linuxText = string.Join("\n", new[]
{
    "KERNEL=7.0.0-test",
    "UPTIME_SECONDS=123.5",
    "LOAD1=0.42",
    "MEM_AVAILABLE_KB=2048",
    "SWAP_TOTAL_KB=1024",
    "SWAP_FREE_KB=768",
    "ROOT_TOTAL_BYTES=1000000",
    "ROOT_AVAILABLE_BYTES=500000",
    "CPU_PSI_SOME_AVG10=0.10",
    "MEM_PSI_SOME_AVG10=0.20",
    "MEM_PSI_FULL_AVG10=0.00",
    "UPDATES_AVAILABLE=3",
    "REBOOT_REQUIRED=1",
    "RUNNER_SERVICE=active"
});
var linuxTelemetry = LinuxProbeParser.Parse("node", linuxText, now);
Assert(linuxTelemetry.Kernel == "7.0.0-test" && linuxTelemetry.MemoryAvailableBytes == 2048UL * 1024, "Linux parser maps kernel and available memory");
Assert(linuxTelemetry.SwapUsedBytes == 256UL * 1024 && linuxTelemetry.UpdatesAvailable == 3 && linuxTelemetry.RebootRequired, "Linux parser maps swap/update/reboot attention");
Assert(linuxTelemetry.SystemdUnits["github-runner"] == ObservedState.Running && linuxTelemetry.Disks[0].AvailableBytes == 500000, "Linux parser maps runner service and root disk telemetry");
AssertThrows<FormatException>(() => LinuxProbeParser.Parse("node", linuxText.Replace("KERNEL=7.0.0-test\n", string.Empty, StringComparison.Ordinal), now), "Linux parser rejects missing required core telemetry");
AssertThrows<FormatException>(() => LinuxProbeParser.Parse("node", linuxText.Replace("SWAP_FREE_KB=768", "SWAP_FREE_KB=2048", StringComparison.Ordinal), now), "Linux parser rejects impossible swap telemetry");
AssertThrows<FormatException>(() => LinuxProbeParser.Parse("node", linuxText.Replace("ROOT_AVAILABLE_BYTES=500000", "ROOT_AVAILABLE_BYTES=2000000", StringComparison.Ordinal), now), "Linux parser rejects impossible disk telemetry");
var linuxWithoutPsi = LinuxProbeParser.Parse("node", string.Join("\n", linuxText.Split('\n').Where(line => !line.Contains("PSI_", StringComparison.Ordinal))), now);
Assert(linuxWithoutPsi.CpuPsiSomeAverage10 is null && linuxWithoutPsi.MemoryPsiSomeAverage10 is null && linuxWithoutPsi.MemoryPsiFullAverage10 is null, "Linux parser permits unsupported PSI as unavailable rather than fabricating values");

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
var preLoginDevice = new DeviceDefinition("prelogin-device", "Prelogin device", DevicePlatform.Windows,
    [new EnvironmentDefinition("automation", "Automation", [onDemand, afterLogin with { DependsOn = ["wsl"] }])]);
var preLoginCursor = new ComponentObservation("cursor-worker", ObservedState.Stopped, HealthState.Healthy, now, "Owner session inactive");
var preLoginAggregate = DeviceHealthAggregator.Aggregate(preLoginDevice, [inactiveObservation, preLoginCursor]);
Assert(preLoginAggregate.Health == HealthState.Healthy, "pre-login intentionally inactive RunningAfterLogin component does not require inactive dependency availability");

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
void AssertThrows<TException>(Action action, string description) where TException : Exception
{
    assertionCount++;
    try
    {
        action();
        throw new InvalidOperationException($"FAILED: {description}");
    }
    catch (TException) { }
}
