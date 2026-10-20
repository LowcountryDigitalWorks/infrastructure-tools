namespace LDW.OperationsBridge.Core;

public static class BridgeProtocol
{
    public const string Version = "1.0";
    public const string BridgeRuntime = "ldw-operations-bridge";
    public const string BridgeRuntimeVersion = "1.0.0";
    public const int MaxEvidenceLength = 512;
    public const int MaxPayloadEntries = 32;
    public const int MaxPayloadValueLength = 256;
    public const int MaxArgEntries = 16;
    public const int MaxArgValueLength = 256;
    public const int MaxBridgeRuntimeLength = 64;
    public const int MaxBridgeVersionLength = 32;

    public static readonly IReadOnlySet<BridgeOperation> AllowedReadOnlyOperations =
        new HashSet<BridgeOperation>
        {
            BridgeOperation.BrowserHealth,
            BridgeOperation.ListTabs,
            BridgeOperation.ReadTabMetadata
        };

    public static readonly IReadOnlySet<DispatchTerminalStatus> AllowedTerminalStatuses =
        new HashSet<DispatchTerminalStatus>
        {
            DispatchTerminalStatus.Pass,
            DispatchTerminalStatus.Blocked,
            DispatchTerminalStatus.Failed,
            DispatchTerminalStatus.Stale,
            DispatchTerminalStatus.Ambiguous
        };

    public static string ToWireOperation(BridgeOperation operation)
        => operation switch
        {
            BridgeOperation.BrowserHealth => "browser.health",
            BridgeOperation.ListTabs => "browser.list_tabs",
            BridgeOperation.ReadTabMetadata => "browser.read_tab",
            _ => "unknown"
        };

    public static bool TryParseWireOperation(string? value, out BridgeOperation operation)
    {
        switch (value)
        {
            case "browser.health":
                operation = BridgeOperation.BrowserHealth;
                return true;
            case "browser.list_tabs":
                operation = BridgeOperation.ListTabs;
                return true;
            case "browser.read_tab":
                operation = BridgeOperation.ReadTabMetadata;
                return true;
            default:
                operation = BridgeOperation.Unknown;
                return false;
        }
    }

    public static string ToWireTerminalStatus(DispatchTerminalStatus status)
        => status switch
        {
            DispatchTerminalStatus.Pass => "PASS",
            DispatchTerminalStatus.Blocked => "BLOCKED",
            DispatchTerminalStatus.Failed => "FAILED",
            DispatchTerminalStatus.Stale => "STALE",
            DispatchTerminalStatus.Ambiguous => "AMBIGUOUS",
            _ => "FAILED"
        };

    public static bool TryParseWireTerminalStatus(string? value, out DispatchTerminalStatus status)
    {
        switch (value)
        {
            case "PASS":
                status = DispatchTerminalStatus.Pass;
                return true;
            case "BLOCKED":
                status = DispatchTerminalStatus.Blocked;
                return true;
            case "FAILED":
                status = DispatchTerminalStatus.Failed;
                return true;
            case "STALE":
                status = DispatchTerminalStatus.Stale;
                return true;
            case "AMBIGUOUS":
                status = DispatchTerminalStatus.Ambiguous;
                return true;
            default:
                status = DispatchTerminalStatus.Failed;
                return false;
        }
    }

    public static IReadOnlyDictionary<string, string> BoundPayload(IReadOnlyDictionary<string, string>? payload)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (payload is null)
        {
            return result;
        }

        foreach (var pair in payload)
        {
            if (result.Count >= MaxPayloadEntries)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(pair.Key))
            {
                continue;
            }

            var value = pair.Value ?? string.Empty;
            if (value.Length > MaxPayloadValueLength)
            {
                value = value[..MaxPayloadValueLength];
            }

            result[pair.Key] = value;
        }

        return result;
    }

    public static string BoundEvidence(string? evidence)
    {
        var value = string.IsNullOrWhiteSpace(evidence) ? "No evidence provided." : evidence.Trim();
        return value.Length > MaxEvidenceLength ? value[..MaxEvidenceLength] : value;
    }

    public static string BoundBridgeRuntime(string? runtime)
    {
        var value = string.IsNullOrWhiteSpace(runtime) ? BridgeRuntime : runtime.Trim();
        return value.Length > MaxBridgeRuntimeLength ? value[..MaxBridgeRuntimeLength] : value;
    }

    public static string BoundBridgeVersion(string? version)
    {
        var value = string.IsNullOrWhiteSpace(version) ? BridgeRuntimeVersion : version.Trim();
        return value.Length > MaxBridgeVersionLength ? value[..MaxBridgeVersionLength] : value;
    }
}

public enum BridgeOperation
{
    Unknown = 0,
    BrowserHealth = 1,
    ListTabs = 2,
    ReadTabMetadata = 3
}

public enum DispatchLifecycle
{
    Queued = 0,
    Delivered = 1,
    Started = 2,
    Terminal = 3
}

public enum DispatchTerminalStatus
{
    Pass = 0,
    Blocked = 1,
    Failed = 2,
    Stale = 3,
    Ambiguous = 4
}

public sealed record BridgeDispatchRequest(
    string ProtocolVersion,
    Guid DispatchId,
    string BridgeId,
    BridgeOperation Operation,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string IdempotencyKey,
    string CorrelationId,
    IReadOnlyDictionary<string, string> Args);

public sealed record BridgeDispatchResult(
    Guid DispatchId,
    string IdempotencyKey,
    string CorrelationId,
    string BridgeRuntime,
    string BridgeVersion,
    BridgeOperation Operation,
    DispatchTerminalStatus TerminalStatus,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    string Evidence,
    IReadOnlyDictionary<string, string> Payload)
{
    public string ResultClass => BridgeProtocol.ToWireTerminalStatus(TerminalStatus);
    public string OperationClass => BridgeProtocol.ToWireOperation(Operation);
}

public sealed record BrowserTabMetadata(
    string TabId,
    string Identity,
    string Title,
    string Url);

public sealed record BrowserHealth(
    bool Ready,
    string RuntimeVersion,
    string Notes);
