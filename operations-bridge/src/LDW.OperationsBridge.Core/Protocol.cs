namespace LDW.OperationsBridge.Core;

public static class BridgeProtocol
{
    public const string Version = "1.0";

    public static readonly IReadOnlySet<BridgeOperation> AllowedReadOnlyOperations =
        new HashSet<BridgeOperation>
        {
            BridgeOperation.BrowserHealth,
            BridgeOperation.ListTabs,
            BridgeOperation.ReadTabMetadata
        };
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
    DispatchTerminalStatus TerminalStatus,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    string Evidence,
    IReadOnlyDictionary<string, string> Payload);

public sealed record BrowserTabMetadata(
    string TabId,
    string Identity,
    string Title,
    string Url);

public sealed record BrowserHealth(
    bool Ready,
    string RuntimeVersion,
    string Notes);
