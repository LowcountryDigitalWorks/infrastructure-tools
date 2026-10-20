namespace LDW.OperationsBridge.Core;

public enum DispatchAcceptState
{
    Accepted = 0,
    Duplicate = 1,
    Blocked = 2
}

public sealed record DispatchAcceptResult(
    DispatchAcceptState State,
    DispatchEnvelope Envelope,
    DispatchValidationError ValidationError);

public sealed record DispatchEnvelope(
    BridgeDispatchRequest Request,
    DateTimeOffset AcceptedAt,
    DispatchLifecycle Lifecycle,
    string? DeliveryConnectionId,
    DateTimeOffset? DeliveredAt,
    DateTimeOffset? StartedAt,
    BridgeDispatchResult? TerminalResult);

public sealed class RelayDispatchStore
{
    private readonly DispatchValidator _validator;
    private readonly Dictionary<Guid, DispatchEnvelope> _dispatches = [];
    private readonly Dictionary<string, Guid> _idempotencyIndex = new(StringComparer.Ordinal);

    public RelayDispatchStore(DispatchValidator validator)
    {
        _validator = validator;
    }

    public DispatchAcceptResult Accept(BridgeDispatchRequest request, DateTimeOffset now)
    {
        var validationError = _validator.Validate(request, now);
        if (validationError != DispatchValidationError.None)
        {
            return new DispatchAcceptResult(
                DispatchAcceptState.Blocked,
                BuildBlockedEnvelope(request, now, validationError),
                validationError);
        }

        if (_idempotencyIndex.TryGetValue(request.IdempotencyKey, out var existingDispatchId)
            && _dispatches.TryGetValue(existingDispatchId, out var existing))
        {
            return new DispatchAcceptResult(DispatchAcceptState.Duplicate, existing, DispatchValidationError.None);
        }

        var envelope = new DispatchEnvelope(
            request,
            now,
            DispatchLifecycle.Queued,
            DeliveryConnectionId: null,
            DeliveredAt: null,
            StartedAt: null,
            TerminalResult: null);
        _dispatches[request.DispatchId] = envelope;
        _idempotencyIndex[request.IdempotencyKey] = request.DispatchId;
        return new DispatchAcceptResult(DispatchAcceptState.Accepted, envelope, DispatchValidationError.None);
    }

    public bool TryMarkDelivered(Guid dispatchId, string connectionId, DateTimeOffset now)
    {
        if (!_dispatches.TryGetValue(dispatchId, out var envelope))
        {
            return false;
        }

        if (envelope.Lifecycle != DispatchLifecycle.Queued || envelope.TerminalResult is not null)
        {
            return false;
        }

        _dispatches[dispatchId] = envelope with
        {
            Lifecycle = DispatchLifecycle.Delivered,
            DeliveredAt = now,
            DeliveryConnectionId = connectionId
        };
        return true;
    }

    public bool TryMarkStarted(Guid dispatchId, string connectionId, DateTimeOffset now)
    {
        if (!_dispatches.TryGetValue(dispatchId, out var envelope))
        {
            return false;
        }

        if (envelope.Lifecycle != DispatchLifecycle.Delivered ||
            envelope.TerminalResult is not null ||
            !string.Equals(envelope.DeliveryConnectionId, connectionId, StringComparison.Ordinal))
        {
            return false;
        }

        _dispatches[dispatchId] = envelope with
        {
            Lifecycle = DispatchLifecycle.Started,
            StartedAt = now
        };
        return true;
    }

    public bool TryComplete(
        Guid dispatchId,
        string connectionId,
        string correlationId,
        DispatchTerminalStatus status,
        DateTimeOffset now,
        string evidence,
        IReadOnlyDictionary<string, string> payload)
    {
        if (!_dispatches.TryGetValue(dispatchId, out var envelope))
        {
            return false;
        }

        if (envelope.TerminalResult is not null || envelope.StartedAt is null)
        {
            return false;
        }

        // Lost correlation or connection mismatch fails closed to AMBIGUOUS, never PASS.
        if (!string.Equals(envelope.DeliveryConnectionId, connectionId, StringComparison.Ordinal) ||
            !string.Equals(envelope.Request.CorrelationId, correlationId, StringComparison.Ordinal))
        {
            status = DispatchTerminalStatus.Ambiguous;
            evidence = "Lost correlation or connection identity mismatch.";
            payload = new Dictionary<string, string>();
        }

        if (status == DispatchTerminalStatus.Pass &&
            now > envelope.Request.ExpiresAt)
        {
            status = DispatchTerminalStatus.Stale;
            evidence = "Result arrived after expiry.";
            payload = new Dictionary<string, string>();
        }

        var result = new BridgeDispatchResult(
            dispatchId,
            envelope.Request.IdempotencyKey,
            envelope.Request.CorrelationId,
            status,
            envelope.StartedAt.Value,
            now,
            evidence,
            payload);

        _dispatches[dispatchId] = envelope with
        {
            Lifecycle = DispatchLifecycle.Terminal,
            TerminalResult = result
        };
        return true;
    }

    public int ResolveExpired(DateTimeOffset now)
    {
        var updated = 0;
        foreach (var entry in _dispatches.ToArray())
        {
            var envelope = entry.Value;
            if (envelope.TerminalResult is not null)
            {
                continue;
            }

            if (now <= envelope.Request.ExpiresAt)
            {
                continue;
            }

            var startedAt = envelope.StartedAt ?? envelope.DeliveredAt ?? envelope.AcceptedAt;
            var terminal = new BridgeDispatchResult(
                envelope.Request.DispatchId,
                envelope.Request.IdempotencyKey,
                envelope.Request.CorrelationId,
                envelope.StartedAt is null ? DispatchTerminalStatus.Stale : DispatchTerminalStatus.Ambiguous,
                startedAt,
                now,
                envelope.StartedAt is null
                    ? "Dispatch expired before execution start."
                    : "Connection dropped before correlated terminal result.",
                new Dictionary<string, string>());

            _dispatches[entry.Key] = envelope with
            {
                Lifecycle = DispatchLifecycle.Terminal,
                TerminalResult = terminal
            };
            updated++;
        }

        return updated;
    }

    public DispatchEnvelope? Get(Guid dispatchId)
        => _dispatches.TryGetValue(dispatchId, out var envelope) ? envelope : null;

    private static DispatchEnvelope BuildBlockedEnvelope(
        BridgeDispatchRequest request,
        DateTimeOffset now,
        DispatchValidationError validationError)
    {
        var terminal = new BridgeDispatchResult(
            request.DispatchId,
            request.IdempotencyKey,
            request.CorrelationId,
            validationError == DispatchValidationError.StaleOrExpired
                ? DispatchTerminalStatus.Stale
                : DispatchTerminalStatus.Blocked,
            now,
            now,
            $"Rejected: {validationError}",
            new Dictionary<string, string>());

        return new DispatchEnvelope(
            request,
            now,
            DispatchLifecycle.Terminal,
            DeliveryConnectionId: null,
            DeliveredAt: null,
            StartedAt: now,
            TerminalResult: terminal);
    }
}
