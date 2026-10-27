using System.Globalization;
using LDW.HostAgent.Core;

namespace LDW.AdminBroker;

public sealed record CiJitControlResult(
    bool Success,
    string ResultState,
    string ReasonCode,
    string? OperationId = null,
    string? ProfileId = null,
    long? RunId = null,
    long? JobId = null,
    CiJitStatusSnapshot? Status = null,
    string? StaleItems = null);

public interface ICiJitControlAdapter
{
    CiJitControlResult GetStatus(CancellationToken cancellationToken);
    CiJitControlResult Discover(CancellationToken cancellationToken);
    CiJitControlResult RunOnce(CancellationToken cancellationToken);
    CiJitControlResult Recover(CancellationToken cancellationToken);
    CiJitControlResult AbortActive(CancellationToken cancellationToken);
    CiJitControlResult ListStale(CancellationToken cancellationToken);
    CiJitControlResult RetireStale(long runId, CancellationToken cancellationToken);
    CiJitControlResult GetOperationResult(Guid operationId, CancellationToken cancellationToken);
}

public static class CiJitControlContract
{
    public const string TargetIdentity = "local-ci-jit";

    private static readonly HashSet<string> ResultStates = new(StringComparer.Ordinal)
    {
        "QUEUED", "STARTED", "PASS", "BLOCKED", "FAILED", "STALE", "AMBIGUOUS"
    };

    private static readonly HashSet<string> ReasonCodes = new(StringComparer.Ordinal)
    {
        "NONE",
        "ADAPTER_UNAVAILABLE",
        "INVALID_ADAPTER_RESULT",
        "TARGET_REFUSED",
        "QUEUE_UNAVAILABLE",
        "QUEUE_STALE",
        "BUSY",
        "CAPACITY",
        "POLICY_HOLD",
        "PROVENANCE_MISMATCH",
        "LOCK_OR_RESIDUE_UNCERTAIN",
        "IDENTITY_MISMATCH",
        "NO_ACTIVE_JOB",
        "CURRENT_CANDIDATE",
        "NOT_STALE",
        "PR_CLOSED",
        "PR_MERGED",
        "PR_HEAD_MOVED",
        "SUPERSEDED",
        "PROFILE_MISMATCH",
        "OPERATION_NOT_FOUND",
        "FAILED"
    };

    private static readonly HashSet<string> StaleReasonCodes = new(StringComparer.Ordinal)
    {
        "PR_CLOSED",
        "PR_MERGED",
        "PR_HEAD_MOVED",
        "SUPERSEDED",
        "PROFILE_MISMATCH"
    };

    private static readonly HashSet<string> StatusReasonCodes = new(StringComparer.Ordinal)
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

    public static bool IsOperation(string? operation) => operation is
        AdminBrokerContract.Operations.CiJitStatus
        or AdminBrokerContract.Operations.CiJitDiscover
        or AdminBrokerContract.Operations.CiJitRunOnce
        or AdminBrokerContract.Operations.CiJitRecover
        or AdminBrokerContract.Operations.CiJitAbortActive
        or AdminBrokerContract.Operations.CiJitListStale
        or AdminBrokerContract.Operations.CiJitRetireStale
        or AdminBrokerContract.Operations.CiJitGetOperationResult;

    public static bool IsResultState(string? value) =>
        value is not null && ResultStates.Contains(value);

    public static bool IsReasonCode(string? value) =>
        value is not null && ReasonCodes.Contains(value);

    internal static bool IsSafeResult(CiJitControlResult? result)
    {
        if (result is null || !IsResultState(result.ResultState) || !IsReasonCode(result.ReasonCode))
            return false;
        if (result.Success && result.ResultState is "BLOCKED" or "FAILED" or "AMBIGUOUS")
            return false;
        if (!result.Success && result.ResultState is "PASS" or "STARTED" or "QUEUED")
            return false;
        if (result.OperationId is not null && !Guid.TryParseExact(result.OperationId, "D", out _))
            return false;
        if (result.ProfileId is not null && !IsSafeIdentifier(result.ProfileId, 64, allowUppercase: false, allowColon: false))
            return false;
        if (result.RunId is <= 0 || result.JobId is <= 0)
            return false;
        if (result.StaleItems is not null && !IsSafeStaleItems(result.StaleItems))
            return false;
        return result.Status is null || IsSafeStatus(result.Status);
    }

    internal static IReadOnlyDictionary<string, string>? CreateDetails(CiJitControlResult result)
    {
        if (!IsSafeResult(result))
            return null;

        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        Add(details, "reasonCode", result.ReasonCode);
        Add(details, "operationId", result.OperationId);
        Add(details, "profileId", result.ProfileId);
        Add(details, "runId", result.RunId?.ToString(CultureInfo.InvariantCulture));
        Add(details, "jobId", result.JobId?.ToString(CultureInfo.InvariantCulture));
        Add(details, "staleItems", result.StaleItems);

        if (result.Status is { } status)
        {
            Add(details, "observedAtUtc", status.ObservedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            Add(details, "sourceVersion", status.SourceVersion);
            Add(details, "ownerState", status.State.ToString().ToUpperInvariant());
            Add(details, "statusReasonCode", status.ReasonCode);
            Add(details, "localStateFresh", status.LocalStateFresh ? "true" : "false");
            Add(details, "queueState", status.QueueState.ToString().ToUpperInvariant());
            Add(details, "eligibleQueuedCount", status.EligibleQueuedCount?.ToString(CultureInfo.InvariantCulture));
            Add(details, "heldQueuedCount", status.HeldQueuedCount?.ToString(CultureInfo.InvariantCulture));
            Add(details, "selectedProfile", status.SelectedProfile);
            Add(details, "selectedRunId", status.SelectedRunId?.ToString(CultureInfo.InvariantCulture));
            Add(details, "selectedJobId", status.SelectedJobId?.ToString(CultureInfo.InvariantCulture));
            Add(details, "controllerPhase", status.ControllerPhase?.ToString().ToUpperInvariant());
            Add(details, "capacity", status.Capacity.ToString().ToUpperInvariant());
        }

        return details.Count == 0 ? null : details;
    }

    private static bool IsSafeStaleItems(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 1024)
            return false;
        var entries = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (entries.Length is < 1 or > 16)
            return false;
        var seen = new HashSet<long>();
        foreach (var entry in entries)
        {
            var pair = entry.Split(':', 2, StringSplitOptions.None);
            if (pair.Length != 2
                || !long.TryParse(pair[0], NumberStyles.None, CultureInfo.InvariantCulture, out var runId)
                || runId <= 0
                || !seen.Add(runId)
                || !StaleReasonCodes.Contains(pair[1]))
                return false;
        }
        return true;
    }

    private static bool IsSafeStatus(CiJitStatusSnapshot status)
    {
        if (!IsSafeIdentifier(status.SourceVersion, 64, allowUppercase: true, allowColon: true)
            || LooksLikeSha(status.SourceVersion)
            || (status.ReasonCode is not null && !StatusReasonCodes.Contains(status.ReasonCode))
            || status.EligibleQueuedCount is < 0
            || status.HeldQueuedCount is < 0
            || status.SelectedRunId is <= 0
            || status.SelectedJobId is <= 0)
            return false;

        var selectedParts = (status.SelectedProfile is not null ? 1 : 0)
            + (status.SelectedRunId is not null ? 1 : 0)
            + (status.SelectedJobId is not null ? 1 : 0);
        if (selectedParts is not 0 and not 3)
            return false;
        if (status.SelectedProfile is not null
            && (!IsSafeIdentifier(status.SelectedProfile, 64, allowUppercase: false, allowColon: false)
                || LooksLikeSha(status.SelectedProfile)
                || status.QueueState != CiJitQueueState.Fresh
                || status.EligibleQueuedCount is not > 0))
            return false;
        if (status.QueueState == CiJitQueueState.Fresh
            && (status.EligibleQueuedCount is null || status.HeldQueuedCount is null))
            return false;
        if (status.QueueState != CiJitQueueState.Fresh
            && (status.EligibleQueuedCount is not null || status.HeldQueuedCount is not null))
            return false;

        return true;
    }

    private static bool IsSafeIdentifier(string value, int maximumLength, bool allowUppercase, bool allowColon)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
            return false;
        foreach (var c in value)
        {
            if (char.IsLower(c) || char.IsDigit(c) || c is '-' or '_' or '.')
                continue;
            if (allowUppercase && char.IsUpper(c))
                continue;
            if (allowColon && c == ':')
                continue;
            return false;
        }
        return true;
    }

    private static bool LooksLikeSha(string value) =>
        value.Length is 40 or 64 && value.All(Uri.IsHexDigit);

    private static void Add(IDictionary<string, string> details, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            details[key] = value;
    }
}

internal sealed class UnavailableCiJitControlAdapter : ICiJitControlAdapter
{
    private static CiJitControlResult Unavailable() =>
        new(false, "BLOCKED", "ADAPTER_UNAVAILABLE");

    public CiJitControlResult GetStatus(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult Discover(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult RunOnce(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult Recover(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult AbortActive(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult ListStale(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult RetireStale(long runId, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
    public CiJitControlResult GetOperationResult(Guid operationId, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable(); }
}