namespace LDW.OperationsBridge.Core;

public enum DispatchValidationError
{
    None = 0,
    UnknownProtocol,
    UnknownBridge,
    UnknownOperation,
    InvalidEnvelope,
    InvalidOperationArgs,
    StaleOrExpired
}

public sealed class DispatchValidator
{
    private static readonly TimeSpan MaxRequestTtl = TimeSpan.FromMinutes(5);
    private readonly ISet<string> _allowedBridgeIds;
    private readonly ISet<BridgeOperation> _allowedOperations;

    public DispatchValidator(IEnumerable<string> allowedBridgeIds, IEnumerable<BridgeOperation> allowedOperations)
    {
        _allowedBridgeIds = new HashSet<string>(allowedBridgeIds, StringComparer.Ordinal);
        _allowedOperations = new HashSet<BridgeOperation>(allowedOperations);
    }

    public DispatchValidationError Validate(BridgeDispatchRequest request, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(request.ProtocolVersion) ||
            request.DispatchId == Guid.Empty ||
            string.IsNullOrWhiteSpace(request.BridgeId) ||
            string.IsNullOrWhiteSpace(request.IdempotencyKey) ||
            string.IsNullOrWhiteSpace(request.CorrelationId) ||
            request.Args is null ||
            request.Args.Count > BridgeProtocol.MaxArgEntries ||
            request.Args.Any(pair =>
                string.IsNullOrWhiteSpace(pair.Key) ||
                pair.Value is null ||
                pair.Value.Length > BridgeProtocol.MaxArgValueLength))
        {
            return DispatchValidationError.InvalidEnvelope;
        }

        if (!string.Equals(request.ProtocolVersion, BridgeProtocol.Version, StringComparison.Ordinal))
        {
            return DispatchValidationError.UnknownProtocol;
        }

        if (!_allowedBridgeIds.Contains(request.BridgeId))
        {
            return DispatchValidationError.UnknownBridge;
        }

        if (!_allowedOperations.Contains(request.Operation) || request.Operation == BridgeOperation.Unknown)
        {
            return DispatchValidationError.UnknownOperation;
        }

        if (!CodyncOperationSchema.IsValid(request.Operation, request.Args))
        {
            return DispatchValidationError.InvalidOperationArgs;
        }

        if (request.ExpiresAt <= request.IssuedAt ||
            request.ExpiresAt - request.IssuedAt > MaxRequestTtl ||
            now > request.ExpiresAt ||
            now < request.IssuedAt.AddMinutes(-5))
        {
            return DispatchValidationError.StaleOrExpired;
        }

        return DispatchValidationError.None;
    }
}
