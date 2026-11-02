using System.Text.RegularExpressions;

namespace LDW.AdminBroker;

public sealed record AdminPrivilegedControlResult(
    bool Success,
    string ResultState,
    string ReasonCode,
    string? CorrelationId = null,
    string? OperationId = null,
    IReadOnlyDictionary<string, string>? Details = null);

public interface IAdminPrivilegedControlAdapter
{
    AdminPrivilegedControlResult RunReviewedOperation(string operationId, Guid correlationId, CancellationToken cancellationToken);
    AdminPrivilegedControlResult GetOperationResult(Guid correlationId, CancellationToken cancellationToken);
}

public static class AdminReviewedOperationRegistry
{
    public const string ElevatedIdentityProof = "ELEVATED_IDENTITY_PROOF";

    public static readonly HashSet<string> All = new(StringComparer.Ordinal)
    {
        ElevatedIdentityProof
    };

    public static bool IsValidOperation(string? operationId) =>
        !string.IsNullOrWhiteSpace(operationId) && All.Contains(operationId);
}

public static class AdminPrivilegedControlContract
{
    public const string TargetIdentity = "local-privileged-control";

    private static readonly HashSet<string> ResultStates = new(StringComparer.Ordinal)
    {
        "QUEUED", "STARTED", "PASS", "BLOCKED", "FAILED", "AMBIGUOUS"
    };

    private static readonly HashSet<string> ReasonCodes = new(StringComparer.Ordinal)
    {
        "NONE",
        "ADAPTER_UNAVAILABLE",
        "INVALID_ADAPTER_RESULT",
        "TARGET_REFUSED",
        "UNKNOWN_OPERATION",
        "INVALID_REQUEST",
        "BUSY",
        "TIMEOUT",
        "PROVENANCE_MISMATCH",
        "ELEVATION_REQUIRED",
        "EXECUTION_FAILED",
        "OPERATION_NOT_FOUND",
        "POLICY_REJECTED",
        "DUPLICATE_REQUEST",
        "FAILED"
    };

    private static readonly Regex SafeIdentifierRegex = new(@"^[A-Z0-9_]{1,64}$", RegexOptions.Compiled);
    private static readonly Regex SafeDetailKeyRegex = new(@"^[a-zA-Z0-9_]{1,64}$", RegexOptions.Compiled);
    private static readonly Regex SafeDetailValueRegex = new(@"^[a-zA-Z0-9_\-\.:]{1,256}$", RegexOptions.Compiled);

    public static bool IsOperation(string? operation) => operation is
        AdminBrokerContract.Operations.AdminReviewedOperationRun
        or AdminBrokerContract.Operations.AdminReviewedOperationGetResult;

    public static bool IsResultState(string? value) =>
        value is not null && ResultStates.Contains(value);

    public static bool IsReasonCode(string? value) =>
        value is not null && ReasonCodes.Contains(value);

    public static bool IsSafeResult(AdminPrivilegedControlResult? result)
    {
        if (result is null || !IsResultState(result.ResultState) || !IsReasonCode(result.ReasonCode))
            return false;
        if (result.Success && result.ResultState is "BLOCKED" or "FAILED" or "AMBIGUOUS")
            return false;
        if (!result.Success && result.ResultState is "PASS" or "STARTED" or "QUEUED")
            return false;
        if (result.CorrelationId is not null && !Guid.TryParseExact(result.CorrelationId, "D", out _))
            return false;
        if (result.OperationId is not null && !SafeIdentifierRegex.IsMatch(result.OperationId))
            return false;
        if (result.Details is not null)
        {
            if (result.Details.Count > 16) return false;
            foreach (var (k, v) in result.Details)
            {
                if (!SafeDetailKeyRegex.IsMatch(k) || !SafeDetailValueRegex.IsMatch(v))
                    return false;
            }
        }
        return true;
    }

    public static IReadOnlyDictionary<string, string>? CreateDetails(AdminPrivilegedControlResult result)
    {
        if (!IsSafeResult(result))
            return null;

        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        details["reasonCode"] = result.ReasonCode;
        if (result.CorrelationId is not null) details["correlationId"] = result.CorrelationId;
        if (result.OperationId is not null) details["operationId"] = result.OperationId;

        if (result.Details is not null)
        {
            foreach (var (k, v) in result.Details)
            {
                details[k] = v;
            }
        }

        return details;
    }
}

public sealed class UnavailableAdminPrivilegedControlAdapter : IAdminPrivilegedControlAdapter
{
    public AdminPrivilegedControlResult RunReviewedOperation(string operationId, Guid correlationId, CancellationToken cancellationToken) =>
        new(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);

    public AdminPrivilegedControlResult GetOperationResult(Guid correlationId, CancellationToken cancellationToken) =>
        new(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"));
}
