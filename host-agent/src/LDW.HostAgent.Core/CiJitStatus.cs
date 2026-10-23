namespace LDW.HostAgent.Core;

public enum CiJitOwnerState
{
    Idle,
    Queued,
    Dispatching,
    Running,
    Cleaning,
    Hold,
    Failed,
    Unknown
}

public enum CiJitQueueState
{
    Fresh,
    Stale,
    Unavailable
}

public enum CiJitCapacityState
{
    Ready,
    Busy,
    Capacity,
    Unknown
}

public enum CiJitControllerPhase
{
    Planned,
    Registered,
    Provisioned,
    Running,
    JobCompleted,
    RunnerAbsent,
    GuestRemoved,
    ArtifactsRemoved,
    Complete
}

public sealed record CiJitStatusInput(
    DateTimeOffset ObservedAtUtc,
    string SourceVersion,
    bool LocalStateAvailable,
    bool LocalStateFresh,
    bool ProvenanceValid,
    bool ProvenFailure,
    CiJitQueueState QueueState,
    int? EligibleQueuedCount,
    int? HeldQueuedCount,
    CiJitCapacityState Capacity,
    CiJitControllerPhase? ControllerPhase = null,
    string? ReasonCode = null,
    string? SelectedProfile = null,
    long? SelectedRunId = null,
    long? SelectedJobId = null);

public sealed record CiJitStatusSnapshot(
    DateTimeOffset ObservedAtUtc,
    string SourceVersion,
    CiJitOwnerState State,
    StatusColor Color,
    string? ReasonCode,
    bool LocalStateFresh,
    CiJitQueueState QueueState,
    int? EligibleQueuedCount,
    int? HeldQueuedCount,
    string? SelectedProfile,
    long? SelectedRunId,
    long? SelectedJobId,
    CiJitControllerPhase? ControllerPhase,
    CiJitCapacityState Capacity)
{
    public string QueueSummary => QueueState switch
    {
        CiJitQueueState.Fresh when EligibleQueuedCount is 0 => "No eligible jobs",
        CiJitQueueState.Fresh when EligibleQueuedCount is 1 => "1 waiting",
        CiJitQueueState.Fresh when EligibleQueuedCount is > 1 => $"{EligibleQueuedCount} waiting",
        CiJitQueueState.Stale => "Queue stale",
        _ => "Queue unavailable"
    };
}

public static class CiJitStatusResolver
{
    public static CiJitStatusSnapshot Resolve(CiJitStatusInput input)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(input.SourceVersion);
        if (input.EligibleQueuedCount is < 0) throw new ArgumentOutOfRangeException(nameof(input.EligibleQueuedCount));
        if (input.HeldQueuedCount is < 0) throw new ArgumentOutOfRangeException(nameof(input.HeldQueuedCount));

        var state = ResolveState(input);
        return new CiJitStatusSnapshot(
            input.ObservedAtUtc,
            input.SourceVersion,
            state,
            ColorFor(state),
            input.ReasonCode,
            input.LocalStateFresh,
            input.QueueState,
            input.EligibleQueuedCount,
            input.HeldQueuedCount,
            input.SelectedProfile,
            input.SelectedRunId,
            input.SelectedJobId,
            input.ControllerPhase,
            input.Capacity);
    }

    private static CiJitOwnerState ResolveState(CiJitStatusInput input)
    {
        if (input.ProvenFailure) return CiJitOwnerState.Failed;
        if (!input.LocalStateAvailable || !input.LocalStateFresh || !input.ProvenanceValid)
            return CiJitOwnerState.Unknown;

        switch (input.ControllerPhase)
        {
            case CiJitControllerPhase.JobCompleted:
            case CiJitControllerPhase.RunnerAbsent:
            case CiJitControllerPhase.GuestRemoved:
            case CiJitControllerPhase.ArtifactsRemoved:
                return CiJitOwnerState.Cleaning;
            case CiJitControllerPhase.Running:
                return CiJitOwnerState.Running;
            case CiJitControllerPhase.Planned:
            case CiJitControllerPhase.Registered:
            case CiJitControllerPhase.Provisioned:
                return CiJitOwnerState.Dispatching;
        }

        if (input.QueueState != CiJitQueueState.Fresh || input.EligibleQueuedCount is null)
            return CiJitOwnerState.Unknown;

        if (input.EligibleQueuedCount > 0)
        {
            return input.Capacity switch
            {
                CiJitCapacityState.Ready => CiJitOwnerState.Queued,
                CiJitCapacityState.Busy or CiJitCapacityState.Capacity => CiJitOwnerState.Hold,
                _ => CiJitOwnerState.Unknown
            };
        }

        return CiJitOwnerState.Idle;
    }

    private static StatusColor ColorFor(CiJitOwnerState state) => state switch
    {
        CiJitOwnerState.Idle => StatusColor.Green,
        CiJitOwnerState.Queued or CiJitOwnerState.Hold => StatusColor.Yellow,
        CiJitOwnerState.Dispatching or CiJitOwnerState.Running or CiJitOwnerState.Cleaning => StatusColor.Blue,
        CiJitOwnerState.Failed => StatusColor.Red,
        _ => StatusColor.Gray
    };
}
