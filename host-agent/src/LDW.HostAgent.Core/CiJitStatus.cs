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
        CiJitQueueState.Fresh when EligibleQueuedCount is 0 && HeldQueuedCount is 0 => "No eligible jobs",
        CiJitQueueState.Fresh when EligibleQueuedCount is 0 && HeldQueuedCount is 1 => "1 held",
        CiJitQueueState.Fresh when EligibleQueuedCount is 0 && HeldQueuedCount is > 1 => $"{HeldQueuedCount} held",
        CiJitQueueState.Fresh when EligibleQueuedCount is 1 && HeldQueuedCount is 0 => "1 waiting",
        CiJitQueueState.Fresh when EligibleQueuedCount is > 1 && HeldQueuedCount is 0 => $"{EligibleQueuedCount} waiting",
        CiJitQueueState.Fresh when EligibleQueuedCount is 1 && HeldQueuedCount is 1 => "1 waiting · 1 held",
        CiJitQueueState.Fresh when EligibleQueuedCount is 1 && HeldQueuedCount is > 1 => $"1 waiting · {HeldQueuedCount} held",
        CiJitQueueState.Fresh when EligibleQueuedCount is > 1 && HeldQueuedCount is 1 => $"{EligibleQueuedCount} waiting · 1 held",
        CiJitQueueState.Fresh when EligibleQueuedCount is > 1 && HeldQueuedCount is > 1 => $"{EligibleQueuedCount} waiting · {HeldQueuedCount} held",
        CiJitQueueState.Stale => "Queue stale",
        _ => "Queue unavailable"
    };
}

public static class CiJitStatusResolver
{
    private static readonly HashSet<string> AllowedReasonCodes = new(StringComparer.Ordinal)
    {
        "BUSY",
        "CAPACITY",
        "LOCAL_STATE_STALE",
        "LOCAL_STATE_UNAVAILABLE",
        "MALFORMED_STATE",
        "MULTIPLE_ACTIVE_RUNS",
        "OWNED_RESOURCE_CONTRADICTION",
        "POLICY_HOLD",
        "PROVENANCE_MISMATCH",
        "QUEUE_STALE",
        "QUEUE_UNAVAILABLE",
        "SOURCE_UNAVAILABLE",
        "STALE_RESIDUE",
        "UNKNOWN"
    };

    public static CiJitStatusSnapshot Resolve(CiJitStatusInput input)
    {
        ValidateSafeIdentifier(input.SourceVersion, nameof(input.SourceVersion), 64, allowUppercase: true, allowColon: true);
        if (LooksLikeSha(input.SourceVersion))
            throw new ArgumentException("SourceVersion must be a sanitized release/provenance identifier, not a raw SHA.", nameof(input.SourceVersion));
        if (input.ReasonCode is not null && !AllowedReasonCodes.Contains(input.ReasonCode))
            throw new ArgumentException("ReasonCode is not in the sanitized allowlist.", nameof(input.ReasonCode));

        if (input.SelectedProfile is not null)
        {
            ValidateSafeIdentifier(input.SelectedProfile, nameof(input.SelectedProfile), 64, allowUppercase: false, allowColon: false);
            if (LooksLikeSha(input.SelectedProfile))
                throw new ArgumentException("SelectedProfile must be a bounded profile identifier, not a raw SHA.", nameof(input.SelectedProfile));
        }
        if (input.EligibleQueuedCount is < 0) throw new ArgumentOutOfRangeException(nameof(input.EligibleQueuedCount));
        if (input.HeldQueuedCount is < 0) throw new ArgumentOutOfRangeException(nameof(input.HeldQueuedCount));
        if (input.SelectedRunId is <= 0) throw new ArgumentOutOfRangeException(nameof(input.SelectedRunId));
        if (input.SelectedJobId is <= 0) throw new ArgumentOutOfRangeException(nameof(input.SelectedJobId));

        var selectedIdentityParts =
            (input.SelectedProfile is not null ? 1 : 0)
            + (input.SelectedRunId is not null ? 1 : 0)
            + (input.SelectedJobId is not null ? 1 : 0);
        if (selectedIdentityParts is not 0 and not 3)
            throw new ArgumentException("Selected queue identity must be either absent or include profile, run ID, and job ID.", nameof(input.SelectedProfile));

        ValidateQueueSnapshot(input);
        ValidateReasonCode(input);
        ValidateControllerCapacity(input);

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

    private static void ValidateQueueSnapshot(CiJitStatusInput input)
    {
        if (!input.LocalStateAvailable && input.LocalStateFresh)
            throw new ArgumentException("Unavailable local state cannot be marked fresh.", nameof(input.LocalStateFresh));

        if (input.QueueState == CiJitQueueState.Fresh
            && (input.EligibleQueuedCount is null || input.HeldQueuedCount is null))
            throw new ArgumentException("Fresh queue evidence requires explicit eligible and held queue counts.", nameof(input.QueueState));

        if (input.QueueState != CiJitQueueState.Fresh && (input.EligibleQueuedCount is not null || input.HeldQueuedCount is not null))
            throw new ArgumentException("Stale or unavailable queue evidence cannot retain queue counts.", nameof(input.QueueState));

        if (input.SelectedProfile is not null
            && (input.QueueState != CiJitQueueState.Fresh || input.EligibleQueuedCount is not > 0))
            throw new ArgumentException("Selected queue identity requires fresh evidence with eligible work.", nameof(input.SelectedProfile));
    }

    private static void ValidateReasonCode(CiJitStatusInput input)
    {
        var hasQueuedWork = input.QueueState == CiJitQueueState.Fresh
            && (input.EligibleQueuedCount > 0 || input.HeldQueuedCount > 0);

        switch (input.ReasonCode)
        {
            case null:
                break;
            case "BUSY" when input.Capacity != CiJitCapacityState.Busy:
            case "CAPACITY" when input.Capacity != CiJitCapacityState.Capacity:
                throw new ArgumentException("ReasonCode must match its capacity state.", nameof(input.ReasonCode));
            case "CAPACITY" when !hasQueuedWork
                || !input.LocalStateAvailable
                || !input.LocalStateFresh
                || !input.ProvenanceValid:
            case "POLICY_HOLD" when !hasQueuedWork
                || !input.LocalStateAvailable
                || !input.LocalStateFresh
                || !input.ProvenanceValid:
                throw new ArgumentException("Hold reasons require trusted local state and current queued work.", nameof(input.ReasonCode));
            case "QUEUE_STALE" when input.QueueState != CiJitQueueState.Stale:
                throw new ArgumentException("QUEUE_STALE reason requires stale queue evidence.", nameof(input.ReasonCode));
            case "QUEUE_UNAVAILABLE" when input.QueueState != CiJitQueueState.Unavailable:
                throw new ArgumentException("QUEUE_UNAVAILABLE reason requires unavailable queue evidence.", nameof(input.ReasonCode));
            case "LOCAL_STATE_STALE" when !input.LocalStateAvailable || input.LocalStateFresh:
                throw new ArgumentException("LOCAL_STATE_STALE reason requires available stale local state.", nameof(input.ReasonCode));
            case "LOCAL_STATE_UNAVAILABLE" when input.LocalStateAvailable:
                throw new ArgumentException("LOCAL_STATE_UNAVAILABLE reason requires unavailable local state.", nameof(input.ReasonCode));
            case "PROVENANCE_MISMATCH" when input.ProvenanceValid:
                throw new ArgumentException("PROVENANCE_MISMATCH reason requires invalid provenance.", nameof(input.ReasonCode));
            case "SOURCE_UNAVAILABLE" when input.LocalStateAvailable && input.QueueState != CiJitQueueState.Unavailable:
                throw new ArgumentException("SOURCE_UNAVAILABLE reason requires an unavailable source.", nameof(input.ReasonCode));
            case "MULTIPLE_ACTIVE_RUNS":
            case "OWNED_RESOURCE_CONTRADICTION":
            case "STALE_RESIDUE":
                if (!input.ProvenFailure)
                    throw new ArgumentException("Failure reasons require confirmed failure evidence.", nameof(input.ReasonCode));
                break;
        }

        if (input.ProvenFailure
            && input.ReasonCode is not null
            and not "MULTIPLE_ACTIVE_RUNS"
            and not "OWNED_RESOURCE_CONTRADICTION"
            and not "STALE_RESIDUE")
            throw new ArgumentException("Confirmed failure evidence cannot use a non-failure reason.", nameof(input.ReasonCode));
    }

    private static void ValidateControllerCapacity(CiJitStatusInput input)
    {
        var activePhase = input.ControllerPhase is
            CiJitControllerPhase.Planned
            or CiJitControllerPhase.Registered
            or CiJitControllerPhase.Provisioned
            or CiJitControllerPhase.Running
            or CiJitControllerPhase.JobCompleted
            or CiJitControllerPhase.RunnerAbsent
            or CiJitControllerPhase.GuestRemoved
            or CiJitControllerPhase.ArtifactsRemoved;

        if ((input.Capacity == CiJitCapacityState.Busy) != activePhase)
            throw new ArgumentException("BUSY capacity must match an active controller phase.", nameof(input.Capacity));
    }

    private static CiJitOwnerState ResolveState(CiJitStatusInput input)
    {
        if (input.ProvenFailure) return CiJitOwnerState.Failed;
        if (input.ReasonCode is "UNKNOWN" or "MALFORMED_STATE" or "SOURCE_UNAVAILABLE")
            return CiJitOwnerState.Unknown;
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

        if (input.QueueState != CiJitQueueState.Fresh || input.EligibleQueuedCount is null || input.HeldQueuedCount is null)
            return CiJitOwnerState.Unknown;

        if (input.EligibleQueuedCount > 0)
        {
            if (input.ReasonCode == "POLICY_HOLD") return CiJitOwnerState.Hold;

            return input.Capacity switch
            {
                CiJitCapacityState.Ready => CiJitOwnerState.Queued,
                CiJitCapacityState.Busy or CiJitCapacityState.Capacity => CiJitOwnerState.Hold,
                _ => CiJitOwnerState.Unknown
            };
        }

        if (input.HeldQueuedCount > 0)
            return CiJitOwnerState.Hold;

        return CiJitOwnerState.Idle;
    }

    private static void ValidateSafeIdentifier(string value, string parameterName, int maxLength, bool allowUppercase, bool allowColon)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maxLength)
            throw new ArgumentException("Sanitized identifier exceeds its maximum length.", parameterName);

        foreach (var character in value)
        {
            var allowed = char.IsAsciiDigit(character)
                || (character is >= 'a' and <= 'z')
                || (allowUppercase && character is >= 'A' and <= 'Z')
                || character is '.' or '_' or '-'
                || (allowColon && character == ':');
            if (!allowed)
                throw new ArgumentException("Sanitized identifier contains a disallowed character.", parameterName);
        }
    }

    private static bool LooksLikeSha(string value) =>
        (value.Length is 40 or 64) && value.All(Uri.IsHexDigit);

    private static StatusColor ColorFor(CiJitOwnerState state) => state switch
    {
        CiJitOwnerState.Idle => StatusColor.Green,
        CiJitOwnerState.Queued or CiJitOwnerState.Hold => StatusColor.Yellow,
        CiJitOwnerState.Dispatching or CiJitOwnerState.Running or CiJitOwnerState.Cleaning => StatusColor.Blue,
        CiJitOwnerState.Failed => StatusColor.Red,
        _ => StatusColor.Gray
    };
}
