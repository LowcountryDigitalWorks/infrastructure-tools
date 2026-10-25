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

        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Planned, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Dispatching, "Planned");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Registered, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Dispatching, "Registered");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Provisioned, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Dispatching, "Provisioned");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.Running, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Running, "Running");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.JobCompleted, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Cleaning, "JobCompleted");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.RunnerAbsent, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Cleaning, "RunnerAbsent");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.GuestRemoved, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Cleaning, "GuestRemoved");
        AssertState(clean with { ControllerPhase = CiJitControllerPhase.ArtifactsRemoved, Capacity = CiJitCapacityState.Busy }, CiJitOwnerState.Cleaning, "ArtifactsRemoved");

        var runningWithBacklog = CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            Capacity = CiJitCapacityState.Busy,
            EligibleQueuedCount = 2
        });
        Assert(runningWithBacklog.State == CiJitOwnerState.Running, "active local RUNNING wins over queue backlog");
        Assert(runningWithBacklog.EligibleQueuedCount == 2 && runningWithBacklog.QueueSummary == "2 waiting", "queue backlog remains visible during RUNNING");

        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Ready }, CiJitOwnerState.Queued, "ready queue");
        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Capacity, ReasonCode = "CAPACITY" }, CiJitOwnerState.Hold, "capacity hold");
        var busyWithBacklog = CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            Capacity = CiJitCapacityState.Busy,
            EligibleQueuedCount = 1,
            ReasonCode = "BUSY"
        });
        Assert(busyWithBacklog.State == CiJitOwnerState.Running, "active owned work remains primary while BUSY and queued backlog are visible");
        AssertState(clean with { EligibleQueuedCount = 1, Capacity = CiJitCapacityState.Ready, ReasonCode = "POLICY_HOLD" }, CiJitOwnerState.Hold, "policy hold overrides otherwise-ready local capacity");

        var heldOnly = CiJitStatusResolver.Resolve(clean with
        {
            EligibleQueuedCount = 0,
            HeldQueuedCount = 1
        });
        Assert(heldOnly.State == CiJitOwnerState.Hold, "held-only fresh queue cannot render IDLE");
        Assert(heldOnly.QueueSummary == "1 held", "held-only queue remains visible in summary");

        var mixedQueue = CiJitStatusResolver.Resolve(clean with
        {
            EligibleQueuedCount = 2,
            HeldQueuedCount = 1
        });
        Assert(mixedQueue.State == CiJitOwnerState.Queued, "eligible work remains primary when eligible and held candidates coexist");
        Assert(mixedQueue.QueueSummary == "2 waiting · 1 held", "mixed queue summary preserves eligible and held counts separately");

        AssertState(clean with { QueueState = CiJitQueueState.Unavailable, EligibleQueuedCount = null, HeldQueuedCount = null }, CiJitOwnerState.Unknown, "unavailable queue never fabricates idle");
        AssertState(clean with { LocalStateFresh = false }, CiJitOwnerState.Unknown, "pre-boot/stale local state fails closed");
        AssertState(clean with { ProvenanceValid = false }, CiJitOwnerState.Unknown, "provenance mismatch fails closed");
        AssertState(clean with { ProvenFailure = true }, CiJitOwnerState.Failed, "positive owned-resource contradiction is FAILED");

        var runningQueueUnavailable = CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            Capacity = CiJitCapacityState.Busy,
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
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Fresh, HeldQueuedCount = null }), "fresh queue without held count rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Stale, EligibleQueuedCount = 0, HeldQueuedCount = null }), "stale queue cannot retain zero eligible count");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Unavailable, EligibleQueuedCount = null, HeldQueuedCount = 1 }), "unavailable queue cannot retain held count");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { Capacity = CiJitCapacityState.Ready, ReasonCode = "CAPACITY" }), "capacity reason must match capacity state");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { Capacity = CiJitCapacityState.Ready, ReasonCode = "BUSY" }), "busy reason must match capacity state");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = "" }), "missing source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = new string('a', 40) }), "raw SHA-like source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SourceVersion = "ci10/raw/provider" }), "raw path-like source provenance rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "CAPACITY\nraw" }), "raw multiline reason rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "TOKEN_VALUE" }), "unrecognized reason code rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = "https://api.github.com/raw", SelectedRunId = 123, SelectedJobId = 456 }), "raw provider reference rejected as profile");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = new string('b', 40), SelectedRunId = 123, SelectedJobId = 456 }), "SHA-like profile value rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = "ci10-bo-secret-scan" }), "profile-only selected identity rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedRunId = 123, SelectedJobId = 456 }), "run/job selected identity without profile rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = "ci10-bo-secret-scan", SelectedRunId = 123 }), "selected identity missing job rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { SelectedProfile = "ci10-bo-secret-scan", SelectedJobId = 456 }), "selected identity missing run rejected");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            SelectedProfile = "ci10-bo-secret-scan",
            SelectedRunId = 123,
            SelectedJobId = 456
        }), "selected identity rejected when fresh eligible queue is empty");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            QueueState = CiJitQueueState.Unavailable,
            EligibleQueuedCount = null,
            HeldQueuedCount = null,
            SelectedProfile = "ci10-bo-secret-scan",
            SelectedRunId = 123,
            SelectedJobId = 456
        }), "selected identity rejected when queue is unavailable");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            QueueState = CiJitQueueState.Stale,
            EligibleQueuedCount = null,
            HeldQueuedCount = null,
            SelectedProfile = "ci10-bo-secret-scan",
            SelectedRunId = 123,
            SelectedJobId = 456
        }), "selected identity rejected when queue is stale");

        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "QUEUE_UNAVAILABLE" }), "unavailable queue reason rejected for fresh evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { QueueState = CiJitQueueState.Stale, EligibleQueuedCount = null, HeldQueuedCount = null, ReasonCode = "QUEUE_UNAVAILABLE" }), "unavailable queue reason rejected for stale evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "QUEUE_STALE" }), "stale queue reason rejected for fresh evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "LOCAL_STATE_STALE" }), "stale local reason rejected for fresh local evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "LOCAL_STATE_UNAVAILABLE" }), "unavailable local reason rejected for available local evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            LocalStateAvailable = false,
            LocalStateFresh = true
        }), "unavailable local state cannot be marked fresh");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "PROVENANCE_MISMATCH" }), "provenance reason rejected for valid provenance");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "POLICY_HOLD" }), "policy hold reason rejected without queued work");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { Capacity = CiJitCapacityState.Capacity, ReasonCode = "CAPACITY" }), "capacity reason rejected without queued work");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ReasonCode = "STALE_RESIDUE" }), "residue reason requires confirmed failure evidence");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with { ProvenFailure = true, ReasonCode = "POLICY_HOLD" }), "confirmed failure cannot be paired with a hold reason");
        AssertState(clean with { ReasonCode = "UNKNOWN" }, CiJitOwnerState.Unknown, "UNKNOWN reason cannot project clean IDLE");
        AssertState(clean with { ReasonCode = "MALFORMED_STATE" }, CiJitOwnerState.Unknown, "malformed-state reason cannot project clean IDLE");
        AssertState(clean with
        {
            QueueState = CiJitQueueState.Stale,
            EligibleQueuedCount = null,
            HeldQueuedCount = null,
            ReasonCode = "QUEUE_STALE"
        }, CiJitOwnerState.Unknown, "matching stale queue reason remains UNKNOWN");
        AssertState(clean with
        {
            QueueState = CiJitQueueState.Unavailable,
            EligibleQueuedCount = null,
            HeldQueuedCount = null,
            ReasonCode = "QUEUE_UNAVAILABLE"
        }, CiJitOwnerState.Unknown, "matching unavailable queue reason remains UNKNOWN");
        AssertState(clean with
        {
            QueueState = CiJitQueueState.Unavailable,
            EligibleQueuedCount = null,
            HeldQueuedCount = null,
            ReasonCode = "SOURCE_UNAVAILABLE"
        }, CiJitOwnerState.Unknown, "matching unavailable-source reason remains UNKNOWN");
        AssertState(clean with
        {
            LocalStateAvailable = false,
            LocalStateFresh = false,
            ReasonCode = "LOCAL_STATE_UNAVAILABLE"
        }, CiJitOwnerState.Unknown, "matching unavailable local-state reason remains UNKNOWN");
        AssertState(clean with
        {
            LocalStateFresh = false,
            ReasonCode = "LOCAL_STATE_STALE"
        }, CiJitOwnerState.Unknown, "matching stale local-state reason remains UNKNOWN");
        AssertState(clean with
        {
            ProvenanceValid = false,
            ReasonCode = "PROVENANCE_MISMATCH"
        }, CiJitOwnerState.Unknown, "matching provenance reason remains UNKNOWN");
        AssertState(clean with
        {
            ProvenFailure = true,
            ReasonCode = "STALE_RESIDUE"
        }, CiJitOwnerState.Failed, "matching residue reason remains FAILED");

        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            Capacity = CiJitCapacityState.Ready
        }), "active RUNNING phase cannot coexist with READY capacity");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Running,
            Capacity = CiJitCapacityState.Capacity
        }), "active RUNNING phase requires BUSY capacity");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            ControllerPhase = CiJitControllerPhase.Complete,
            Capacity = CiJitCapacityState.Busy
        }), "completed phase cannot retain BUSY capacity");
        AssertThrows<ArgumentException>(() => CiJitStatusResolver.Resolve(clean with
        {
            Capacity = CiJitCapacityState.Busy
        }), "BUSY capacity requires an active controller phase");

        var details = CiJitStatusResolver.Resolve(clean with
        {
            EligibleQueuedCount = 1,
            ReasonCode = "POLICY_HOLD",
            Capacity = CiJitCapacityState.Ready,
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
