using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

public sealed class DragonflyOutboundBridgeClient
{
    private readonly string _bridgeId;
    private readonly IDragonflyRunnerAdapter _adapter;
    private readonly DispatchValidator _validator;

    public DragonflyOutboundBridgeClient(
        string bridgeId,
        IDragonflyRunnerAdapter adapter,
        DispatchValidator validator)
    {
        _bridgeId = bridgeId;
        _adapter = adapter;
        _validator = validator;
    }

    public void Attach(IBridgeTransport transport)
    {
        transport.DispatchReceived += async (request, _, cancellationToken) =>
        {
            var receivedAt = DateTimeOffset.UtcNow;
            var validationError = _validator.Validate(request, receivedAt);
            if (validationError != DispatchValidationError.None)
            {
                await transport.SendResultAsync(
                    BuildRejectedResult(request, receivedAt, validationError),
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!string.Equals(request.BridgeId, _bridgeId, StringComparison.Ordinal))
            {
                await transport.SendResultAsync(
                    BuildRejectedResult(request, receivedAt, DispatchValidationError.UnknownBridge),
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            BridgeDispatchResult result;
            try
            {
                result = await ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (DragonflyRunnerAdapterUnavailableException)
            {
                result = BuildTerminal(
                    request,
                    DispatchTerminalStatus.Blocked,
                    startedAt: null,
                    "Dragonfly runner adapter is not configured.",
                    null);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                var mutation = request.Operation is BridgeOperation.DragonflyRunnerStart
                    or BridgeOperation.DragonflyRunnerDrain;
                result = BuildTerminal(
                    request,
                    mutation ? DispatchTerminalStatus.Ambiguous : DispatchTerminalStatus.Failed,
                    receivedAt,
                    mutation
                        ? "Dragonfly lifecycle adapter outcome is ambiguous."
                        : "Dragonfly status adapter failed.",
                    null);
            }

            await transport.SendResultAsync(result, cancellationToken).ConfigureAwait(false);
        };
    }

    private async Task<BridgeDispatchResult> ExecuteAsync(
        BridgeDispatchRequest request,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        switch (request.Operation)
        {
            case BridgeOperation.DragonflyRunnerStatus:
            {
                var status = await _adapter.GetStatusAsync(cancellationToken).ConfigureAwait(false);
                if (!DragonflyRunnerContract.IsSafeStatus(status))
                {
                    return BuildTerminal(
                        request,
                        DispatchTerminalStatus.Failed,
                        startedAt,
                        "Dragonfly status adapter returned an invalid result.",
                        null);
                }
                return BuildTerminal(
                    request,
                    DispatchTerminalStatus.Pass,
                    startedAt,
                    "Dragonfly runner status read completed.",
                    DragonflyRunnerContract.StatusPayload(status));
            }
            case BridgeOperation.DragonflyRunnerStart:
            {
                var lifecycle = await _adapter.StartAsync(cancellationToken).ConfigureAwait(false);
                if (!DragonflyRunnerContract.IsSafeStartResult(lifecycle))
                {
                    return BuildTerminal(
                        request,
                        DispatchTerminalStatus.Ambiguous,
                        startedAt,
                        "Dragonfly Start returned an invalid or uncertain lifecycle result.",
                        null);
                }
                return BuildTerminal(
                    request,
                    DispatchTerminalStatus.Pass,
                    startedAt,
                    "Dragonfly runner Start completed.",
                    DragonflyRunnerContract.LifecyclePayload(lifecycle));
            }
            case BridgeOperation.DragonflyRunnerDrain:
            {
                var lifecycle = await _adapter.DrainAsync(cancellationToken).ConfigureAwait(false);
                if (!DragonflyRunnerContract.IsSafeDrainResult(lifecycle))
                {
                    return BuildTerminal(
                        request,
                        DispatchTerminalStatus.Ambiguous,
                        startedAt,
                        "Dragonfly Drain returned an invalid or uncertain lifecycle result.",
                        null);
                }
                return BuildTerminal(
                    request,
                    DispatchTerminalStatus.Pass,
                    startedAt,
                    "Dragonfly runner Drain completed.",
                    DragonflyRunnerContract.LifecyclePayload(lifecycle));
            }
            default:
                return BuildTerminal(
                    request,
                    DispatchTerminalStatus.Blocked,
                    startedAt: null,
                    "Operation is not in the Dragonfly owner-control allowlist.",
                    null);
        }
    }

    private static BridgeDispatchResult BuildRejectedResult(
        BridgeDispatchRequest request,
        DateTimeOffset now,
        DispatchValidationError validationError)
    {
        var status = validationError == DispatchValidationError.StaleOrExpired
            ? DispatchTerminalStatus.Stale
            : DispatchTerminalStatus.Blocked;
        return new BridgeDispatchResult(
            request.DispatchId,
            request.IdempotencyKey,
            request.CorrelationId,
            BridgeProtocol.BridgeRuntime,
            BridgeProtocol.BridgeRuntimeVersion,
            request.Operation,
            status,
            null,
            now,
            BridgeProtocol.BoundEvidence($"Rejected before Dragonfly execution: {validationError}"),
            BridgeProtocol.BoundPayload(null, request.Operation));
    }

    private static BridgeDispatchResult BuildTerminal(
        BridgeDispatchRequest request,
        DispatchTerminalStatus terminalStatus,
        DateTimeOffset? startedAt,
        string evidence,
        IReadOnlyDictionary<string, string>? payload)
        => new(
            request.DispatchId,
            request.IdempotencyKey,
            request.CorrelationId,
            BridgeProtocol.BridgeRuntime,
            BridgeProtocol.BridgeRuntimeVersion,
            request.Operation,
            terminalStatus,
            startedAt,
            DateTimeOffset.UtcNow,
            BridgeProtocol.BoundEvidence(evidence),
            BridgeProtocol.BoundPayload(payload, request.Operation));
}
