using System.Text.Json;

namespace LDW.HostAgent.Core;

/// <summary>
/// Strict reader for the sanitized machine-local CI/JIT projection produced by the
/// accepted dispatcher/controller path. This parser never reads GitHub or raw controller state.
/// </summary>
public static class CiJitLocalProjection
{
    public const int Schema = 1;
    public const string SourceVersion = "ci-jit-v1";
    public static readonly TimeSpan QueueFreshnessWindow = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan ActiveLocalFreshnessWindow = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan BootComparisonTolerance = TimeSpan.FromMinutes(2);

    private static readonly HashSet<string> Fields = new(StringComparer.Ordinal)
    {
        "schema",
        "source_version",
        "boot_started_utc",
        "local_observed_at_utc",
        "provenance_valid",
        "proven_failure",
        "controller_phase",
        "capacity",
        "reason_code",
        "queue_observed_at_utc",
        "queue_state",
        "eligible_queued_count",
        "held_queued_count",
        "selected_profile",
        "selected_run_id",
        "selected_job_id"
    };

    public static CiJitStatusSnapshot Parse(
        string json,
        DateTimeOffset nowUtc,
        DateTimeOffset estimatedBootStartedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8
        });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("CI/JIT projection root must be an object.");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!Fields.Contains(property.Name) || !seen.Add(property.Name))
                throw new InvalidDataException("CI/JIT projection contains an unsupported or duplicate field.");
        }
        if (!seen.SetEquals(Fields))
            throw new InvalidDataException("CI/JIT projection field set is incomplete.");

        if (ReadInt32(root, "schema") != Schema)
            throw new InvalidDataException("CI/JIT projection schema is unsupported.");
        if (!string.Equals(ReadString(root, "source_version"), SourceVersion, StringComparison.Ordinal))
            throw new InvalidDataException("CI/JIT projection source version is unsupported.");

        var bootStartedUtc = ReadTimestamp(root, "boot_started_utc");
        var localObservedAtUtc = ReadTimestamp(root, "local_observed_at_utc");
        if (localObservedAtUtc > nowUtc.AddMinutes(1))
            throw new InvalidDataException("CI/JIT local observation is in the future.");

        var provenanceValid = ReadBoolean(root, "provenance_valid");
        var provenFailure = ReadBoolean(root, "proven_failure");
        var controllerPhase = ReadNullableEnum<CiJitControllerPhase>(root, "controller_phase");
        var capacity = ReadEnum<CiJitCapacityState>(root, "capacity");
        var rawReason = ReadNullableString(root, "reason_code");

        var queueState = ReadEnum<CiJitQueueState>(root, "queue_state");
        if (queueState == CiJitQueueState.Stale)
            throw new InvalidDataException("Producer must emit FRESH or UNAVAILABLE; staleness is reader-derived.");

        var queueObservedAtUtc = ReadNullableTimestamp(root, "queue_observed_at_utc");
        var eligible = ReadNullableNonNegativeInt(root, "eligible_queued_count");
        var held = ReadNullableNonNegativeInt(root, "held_queued_count");
        var selectedProfile = ReadNullableString(root, "selected_profile");
        var selectedRunId = ReadNullablePositiveLong(root, "selected_run_id");
        var selectedJobId = ReadNullablePositiveLong(root, "selected_job_id");

        if (queueState == CiJitQueueState.Fresh)
        {
            if (queueObservedAtUtc is null || eligible is null || held is null)
                throw new InvalidDataException("Fresh CI/JIT queue evidence requires timestamp and counts.");
            if (queueObservedAtUtc > nowUtc.AddMinutes(1))
                throw new InvalidDataException("CI/JIT queue observation is in the future.");
        }
        else if (queueObservedAtUtc is not null || eligible is not null || held is not null
            || selectedProfile is not null || selectedRunId is not null || selectedJobId is not null)
        {
            throw new InvalidDataException("Unavailable CI/JIT queue evidence cannot retain queue detail.");
        }

        var selectedParts = (selectedProfile is not null ? 1 : 0)
            + (selectedRunId is not null ? 1 : 0)
            + (selectedJobId is not null ? 1 : 0);
        if (selectedParts is not 0 and not 3)
            throw new InvalidDataException("Selected CI/JIT queue identity must be complete or absent.");

        var sameBoot = (bootStartedUtc - estimatedBootStartedUtc).Duration() <= BootComparisonTolerance;
        var activePhase = controllerPhase is
            CiJitControllerPhase.Planned
            or CiJitControllerPhase.Registered
            or CiJitControllerPhase.Provisioned
            or CiJitControllerPhase.Running
            or CiJitControllerPhase.JobCompleted
            or CiJitControllerPhase.RunnerAbsent
            or CiJitControllerPhase.GuestRemoved
            or CiJitControllerPhase.ArtifactsRemoved;
        var localStateFresh = sameBoot
            && (!activePhase || nowUtc - localObservedAtUtc <= ActiveLocalFreshnessWindow);
        var effectiveQueueState = queueState;
        if (queueState == CiJitQueueState.Fresh
            && nowUtc - queueObservedAtUtc!.Value > QueueFreshnessWindow)
        {
            effectiveQueueState = CiJitQueueState.Stale;
            eligible = null;
            held = null;
            selectedProfile = null;
            selectedRunId = null;
            selectedJobId = null;
        }

        var reason = rawReason;
        if (provenFailure)
        {
            // The resolver validates that a proven failure uses only a failure-class reason.
        }
        else if (!localStateFresh)
        {
            reason = "LOCAL_STATE_STALE";
        }
        else if (!provenanceValid)
        {
            reason = "PROVENANCE_MISMATCH";
        }
        else if (effectiveQueueState == CiJitQueueState.Stale)
        {
            reason = "QUEUE_STALE";
        }
        else if (effectiveQueueState == CiJitQueueState.Unavailable && reason is null)
        {
            reason = "QUEUE_UNAVAILABLE";
        }

        var observedAt = queueObservedAtUtc is { } q && q > localObservedAtUtc ? q : localObservedAtUtc;
        return CiJitStatusResolver.Resolve(new CiJitStatusInput(
            observedAt,
            SourceVersion,
            LocalStateAvailable: true,
            LocalStateFresh: localStateFresh,
            ProvenanceValid: provenanceValid,
            ProvenFailure: provenFailure,
            QueueState: effectiveQueueState,
            EligibleQueuedCount: eligible,
            HeldQueuedCount: held,
            Capacity: capacity,
            ControllerPhase: controllerPhase,
            ReasonCode: reason,
            SelectedProfile: selectedProfile,
            SelectedRunId: selectedRunId,
            SelectedJobId: selectedJobId));
    }

    public static CiJitStatusSnapshot Unavailable(DateTimeOffset nowUtc, string reasonCode = "LOCAL_STATE_UNAVAILABLE") =>
        CiJitStatusResolver.Resolve(new CiJitStatusInput(
            nowUtc,
            SourceVersion,
            LocalStateAvailable: false,
            LocalStateFresh: false,
            ProvenanceValid: true,
            ProvenFailure: false,
            QueueState: CiJitQueueState.Unavailable,
            EligibleQueuedCount: null,
            HeldQueuedCount: null,
            Capacity: CiJitCapacityState.Unknown,
            ControllerPhase: null,
            ReasonCode: reasonCode));

    private static JsonElement Required(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
            throw new InvalidDataException("CI/JIT projection field is missing.");
        return value;
    }

    private static string ReadString(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException("CI/JIT projection string field is invalid.");
        return value.GetString()!;
    }

    private static string? ReadNullableString(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException("CI/JIT projection nullable string field is invalid.");
        return value.GetString();
    }

    private static bool ReadBoolean(JsonElement root, string name)
    {
        var value = Required(root, name);
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new InvalidDataException("CI/JIT projection boolean field is invalid.")
        };
    }

    private static int ReadInt32(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result))
            throw new InvalidDataException("CI/JIT projection integer field is invalid.");
        return result;
    }

    private static int? ReadNullableNonNegativeInt(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result) || result < 0)
            throw new InvalidDataException("CI/JIT projection queue count is invalid.");
        return result;
    }

    private static long? ReadNullablePositiveLong(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var result) || result <= 0)
            throw new InvalidDataException("CI/JIT projection identifier is invalid.");
        return result;
    }

    private static DateTimeOffset ReadTimestamp(JsonElement root, string name)
    {
        var text = ReadString(root, name);
        if (!DateTimeOffset.TryParse(text, null, System.Globalization.DateTimeStyles.RoundtripKind, out var value))
            throw new InvalidDataException("CI/JIT projection timestamp is invalid.");
        return value.ToUniversalTime();
    }

    private static DateTimeOffset? ReadNullableTimestamp(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String
            || !DateTimeOffset.TryParse(value.GetString(), null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed))
            throw new InvalidDataException("CI/JIT projection nullable timestamp is invalid.");
        return parsed.ToUniversalTime();
    }

    private static T ReadEnum<T>(JsonElement root, string name) where T : struct, Enum
    {
        var text = ReadString(root, name);
        if (!Enum.TryParse<T>(text, ignoreCase: true, out var value)
            || !string.Equals(value.ToString(), text, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("CI/JIT projection enum field is invalid.");
        return value;
    }

    private static T? ReadNullableEnum<T>(JsonElement root, string name) where T : struct, Enum
    {
        var value = Required(root, name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String
            || !Enum.TryParse<T>(value.GetString(), ignoreCase: true, out var parsed)
            || !string.Equals(parsed.ToString(), value.GetString(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("CI/JIT projection nullable enum field is invalid.");
        return parsed;
    }
}
