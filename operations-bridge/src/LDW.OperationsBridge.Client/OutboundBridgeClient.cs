using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

public interface IBridgeTransport
{
    event Func<BridgeDispatchRequest, string, CancellationToken, Task>? DispatchReceived;
    Task SendResultAsync(BridgeDispatchResult result, CancellationToken cancellationToken);
}

public sealed class OutboundBridgeClient
{
    private readonly string _bridgeId;
    private readonly IBridgeBrowserAdapter _browserAdapter;
    private readonly DispatchValidator _validator;

    public OutboundBridgeClient(
        string bridgeId,
        IBridgeBrowserAdapter browserAdapter,
        DispatchValidator validator)
    {
        _bridgeId = bridgeId;
        _browserAdapter = browserAdapter;
        _validator = validator;
    }

    public void Attach(IBridgeTransport transport)
    {
        transport.DispatchReceived += async (request, _, cancellationToken) =>
        {
            var now = DateTimeOffset.UtcNow;
            var validationError = _validator.Validate(request, now);
            if (validationError != DispatchValidationError.None)
            {
                var rejected = BuildRejectedResult(request, now, validationError);
                await transport.SendResultAsync(rejected, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!string.Equals(request.BridgeId, _bridgeId, StringComparison.Ordinal))
            {
                var mismatched = BuildRejectedResult(request, now, DispatchValidationError.UnknownBridge);
                await transport.SendResultAsync(mismatched, cancellationToken).ConfigureAwait(false);
                return;
            }

            var result = await ExecuteReadOnlyOperationAsync(request, cancellationToken).ConfigureAwait(false);
            await transport.SendResultAsync(result, cancellationToken).ConfigureAwait(false);
        };
    }

    private async Task<BridgeDispatchResult> ExecuteReadOnlyOperationAsync(
        BridgeDispatchRequest request,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var payload = new Dictionary<string, string>(StringComparer.Ordinal);
        var status = DispatchTerminalStatus.Pass;
        var evidence = "Operation completed.";

        switch (request.Operation)
        {
            case BridgeOperation.BrowserHealth:
            {
                var health = await _browserAdapter.GetHealthAsync(cancellationToken).ConfigureAwait(false);
                payload["ready"] = health.Ready ? "true" : "false";
                payload["runtime_version"] = health.RuntimeVersion;
                payload["notes"] = health.Notes;
                break;
            }
            case BridgeOperation.ListTabs:
            {
                var tabs = await _browserAdapter.ListTabsAsync(cancellationToken).ConfigureAwait(false);
                payload["tab_count"] = tabs.Count.ToString();
                for (var i = 0; i < tabs.Count; i++)
                {
                    payload[$"tab_{i}_id"] = tabs[i].TabId;
                    payload[$"tab_{i}_identity"] = tabs[i].Identity;
                    payload[$"tab_{i}_title"] = tabs[i].Title;
                    payload[$"tab_{i}_url"] = tabs[i].Url;
                }
                break;
            }
            case BridgeOperation.ReadTabMetadata:
            {
                request.Args.TryGetValue("tab_id", out var tabId);
                if (string.IsNullOrWhiteSpace(tabId))
                {
                    status = DispatchTerminalStatus.Blocked;
                    evidence = "Missing required argument: tab_id.";
                    break;
                }

                var tab = await _browserAdapter.ReadTabMetadataAsync(tabId, cancellationToken).ConfigureAwait(false);
                if (tab is null)
                {
                    status = DispatchTerminalStatus.Blocked;
                    evidence = "Tab is missing or not allowlisted.";
                    break;
                }

                payload["tab_id"] = tab.TabId;
                payload["identity"] = tab.Identity;
                payload["title"] = tab.Title;
                payload["url"] = tab.Url;
                break;
            }
            default:
                status = DispatchTerminalStatus.Blocked;
                evidence = "Unknown operation.";
                break;
        }

        var completedAt = DateTimeOffset.UtcNow;
        return new BridgeDispatchResult(
            request.DispatchId,
            request.IdempotencyKey,
            request.CorrelationId,
            status,
            startedAt,
            completedAt,
            BridgeProtocol.BoundEvidence(evidence),
            BridgeProtocol.BoundPayload(payload));
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
            status,
            now,
            now,
            BridgeProtocol.BoundEvidence($"Rejected before local execution: {validationError}"),
            BridgeProtocol.BoundPayload(null));
    }
}
