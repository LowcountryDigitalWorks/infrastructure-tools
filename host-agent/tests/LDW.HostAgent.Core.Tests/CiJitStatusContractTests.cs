using System.Runtime.CompilerServices;
using LDW.HostAgent.Core;

internal static class CiJitStatusContractTests
{
    [ModuleInitializer]
    internal static void Run()
    {
        var now = DateTimeOffset.UtcNow;
        var clean = new CiJitStatusInput(
            now, "ci10-test", true, true, true, false,
            CiJitQueueState.Fresh, 0, 0, CiJitCapacityState.Ready);

        Assert(CiJitStatusResolver.Resolve(clean).State == CiJitOwnerState.Idle, "fresh clean zero queue maps to IDLE");
        Assert(CiJitStatusResolver.Resolve(clean).Color == StatusColor.Green, "IDLE is green");

        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Planned }, CiJitOwnerState.Dispatching, "Planned");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Registered }, CiJitOwnerState.Dispatching, "Registered");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Provisioned }, CiJitOwnerState.Dispatching, "Provisioned");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Running }, CiJitOwnerState.Running, "Running");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.JobCompleted }, CiJitOwnerState.Cleaning, "JobCompleted");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.RunnerAbsent }, CiJitOwnerState.Cleaning, "RunnerAbsent");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.GuestRemoved }, CiJitOwnerState.Cleaning, "GuestRemoved");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.ArtifactsRemoved }, CiJitOwnerState.Cleaning, "ArtifactsRemoved");

        var runningWithBacklog = CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            EligibleQueuedCount = 2
        });
        Assert(runningWithBacklog.State == CiJitOwnerState.Running, "active local RUNNING wins over queue backlog");
        Assert(runningWithBacklog.EligibleQueuedCount == 2 && runningWithBacklog.QueueSummary == "2 waiting", "queue backlog remains visible during RUNNING");

        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Ready }, CiJitOwnerState.Queued, "ready queue");
        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Capacity, ReasonCode = "CAPACITY" }, CiJitOwnerState.Hold, "capacity hold");
        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Busy, ReasonCode = "BUSY" }, CiJitOwnerState.Hold, "busy hold");
        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Ready, ReasonCode = "POLICY_HOLD" }, CiJitOwnerState.Hold, "policy hold overrides otherwise-ready local capacity");

        AssertState(clean with { QueueState = CiJitQueueState.Unavailable, EligibleQueuedCount = null, HeldQueuedCount = null }, CiJitOwnerState.Unknown, "unavailable queue never fabricates idle");
        AssertState(clean with { LocalStateFresh = false }, CiJitOwnerState.Unknown, "pre-boot/stale local state fails closed");
        AssertState(clean with { ProvenanceValid = false }, CiJitOwnerState.Unknown, "provenance mismatch fails closed");
        AssertState(clean with { ProvenFailure = true }, CiJitOwnerState.Failed, "positive owned-resource contradiction is FAILED");

        var runningQueueUnavailable = CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            QueueState = CiJitQueueState.Unavailable,
            EligibleQueuedCount = null,
            HeldQueuedCount = null
        });
        Assert(runningQueueUnavailable.State == CiJitOwnerState.Running, "valid local RUNNING survives queue API unavailability");
        Assert(runningQueueUnavailable.QueueSummary == "Queue unavailable", "queue unavailability remains visible during RUNNING");

        AssertThrows<ArgumentOutOfRangeException>(() => CiJitStatusResolver.Resolve(clean with { EligibleQueuedCount = -1 }), "negative eligible count rejected");
        AssertThrows<ArgumentOutOfRangeException>(() => CiJitStatusResolver.Resolve(clean with { SelectedRunId = 0 }), "nonpositive run id rejected");
        AssertThrows<ArgumentOutOfRangeException>(() => CiJitStatusResolver.Resolve(clean with { SelectedJobId = -1 }), "nonpositive job id rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Fresh, EligibleQueuedCount = null }), "fresh queue without eligible count rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Stale, EligibleQueuedCount = 0, HeldQueuedCount = null }), "stale queue cannot retain zero eligible count");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Unavailable, EligibleQueuedCount = null, HeldQueuedCount = 1 }), "unavailable queue cannot retain held count");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { Capacity = CiJitCapacityState.Ready, ReasonCode = "CAPACITY" }), "capacity reason must match capacity state");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { Capacity = CiJitCapacityState.Ready, ReasonCode = "BUSY" }), "busy reason must match capacity state");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = "" }), "missing source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = new string('a', 40) }), "raw SHA-like source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = "ci10/raw/provider" }), "raw path-like source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "CAPACITY\nraw" }), "raw multiline reason rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "TOKEN_VALUE" }), "unrecognized reason code rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = "https://api.github.com/raw" }), "raw provider reference rejected as profile");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = new string('b', 40) }), "SHA-like profile value rejected");

        var details = CiJitStatusResolver.Resolve(clean with
        {
            EligibleQueuedCount = 1,
            ReasonCode = "POLICY_HOLD",
            SelectedProfile = "ci10-bo-secret-scan",
            SelectedRunId = 123,
            SelectedJobId = 456
        });
        Assert(details.State == CiJitOwnerState.Hold, "policy hold is reflected in owner state");
        Assert(details.ReasonCode == "POLICY_HOLD", "only allowlisted reason codes survive projection");
        Assert(details.SelectedProfile == "ci10-bo-secret-scan" && details.SelectedRunId == 123 && details.SelectedJobId == 456,
            "bounded profile/run/job details survive without raw provider payload");
    }

    private static void AssertState(CiJitStatusInput input, CiJitOwnerState expected, string name) =>
        Assert(CiJitStatusResolver.Resolve(input).State == expected, $"{name} state mapping");

    private static void Assert(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"FAILED CI/JIT status contract: {description}");
    }

    private static void AssertThrows<TException>(Action action, string description) where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException($"FAILED CI/JIT status contract: {description}");
        }
        catch (TException) { }
    }
}
