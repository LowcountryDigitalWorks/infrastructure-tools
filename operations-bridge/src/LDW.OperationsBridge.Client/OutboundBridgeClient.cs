using LDW.OperationsBridge.Core;
using System.Text.Json;

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
    private readonly ICodyncBridgeAdapter? _codyncAdapter;
    private readonly DispatchValidator _validator;

    public OutboundBridgeClient(
        string bridgeId,
        IBridgeBrowserAdapter browserAdapter,
        DispatchValidator validator,
        ICodyncBridgeAdapter? codyncAdapter = null)
    {
        _bridgeId = bridgeId;
        _browserAdapter = browserAdapter;
        _validator = validator;
        _codyncAdapter = codyncAdapter;
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

            BridgeDispatchResult result;
            try
            {
                result = await ExecuteReadOnlyOperationAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                var failedAt = DateTimeOffset.UtcNow;
                result = new BridgeDispatchResult(
                    request.DispatchId,
                    request.IdempotencyKey,
                    request.CorrelationId,
                    BridgeProtocol.BridgeRuntime,
                    BridgeProtocol.BridgeRuntimeVersion,
                    request.Operation,
                    DispatchTerminalStatus.Failed,
                    now,
                    failedAt,
                    BridgeProtocol.BoundEvidence($"Adapter exception: {ex.GetType().Name}"),
                    BridgeProtocol.BoundPayload(null));
            }

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
                if (tabs.Count > 6)
                    throw new InvalidOperationException("Browser metadata exceeds the bounded bridge result size.");
                payload["tab_count"] = tabs.Count.ToString();
                for (var i = 0; i < tabs.Count; i++)
                {
                    payload[$"tab_{i}_id"] = tabs[i].TabId;
                    payload[$"tab_{i}_identity"] = tabs[i].Identity;
                    payload[$"tab_{i}_title"] = tabs[i].Title;
                    payload[$"tab_{i}_url"] = tabs[i].Url;
                    payload[$"tab_{i}_selected"] = tabs[i].Selected ? "true" : "false";
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
                payload["selected"] = tab.Selected ? "true" : "false";
                break;
            }
            case BridgeOperation.CodyncHealth:
            {
                if (_codyncAdapter is null) return CodyncUnavailable(request, startedAt);
                var health = await _codyncAdapter.GetHealthAsync(cancellationToken).ConfigureAwait(false);
                payload["ready"] = health.Ready ? "true" : "false";
                payload["version"] = health.Version;
                payload["busy"] = health.Busy ? "true" : "false";
                break;
            }
            case BridgeOperation.CodyncListApprovedBotsGroups:
            {
                if (_codyncAdapter is null) return CodyncUnavailable(request, startedAt);
                var destinations = await _codyncAdapter.ListApprovedBotsGroupsAsync(cancellationToken).ConfigureAwait(false);
                payload["destination_count"] = destinations.Count.ToString();
                payload["approved_destinations_json"] = JsonSerializer.Serialize(destinations, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                break;
            }
            case BridgeOperation.CodyncSendExact:
            {
                if (_codyncAdapter is null) return CodyncUnavailable(request, startedAt);
                var destinationId = Arg(request, "destination_id");
                var destinationName = Arg(request, "destination_name");
                var text = Arg(request, "text");
                var mentionIds = Arg(request, "mentioned_member_ids").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var nonce = $"ldw-operations-{request.DispatchId:D}";
                var receipt = await _codyncAdapter.SendExactAsync(destinationId, destinationName, text, nonce, mentionIds, cancellationToken).ConfigureAwait(false);
                status = DispatchTerminalStatus.Blocked;
                payload["stage"] = "accepted_send";
                payload["destination_id"] = receipt.DestinationId;
                payload["destination_name"] = receipt.DestinationName;
                payload["client_nonce"] = receipt.ClientNonce;
                payload["root_entry_id"] = receipt.RootEntryId;
                payload["root_sequence"] = receipt.RootSequence.ToString();
                payload["root_turn"] = receipt.RootTurn.ToString();
                payload["root_revision"] = receipt.RootRevision.ToString();
                payload["submitted_at"] = receipt.SubmittedAt.ToString("O");
                evidence = "Codync accepted the exact nonce-correlated message; this is not provider-start or reply evidence.";
                break;
            }
            case BridgeOperation.CodyncWaitReadExact:
            {
                if (_codyncAdapter is null) return CodyncUnavailable(request, startedAt);
                var destinationId = Arg(request, "destination_id");
                var destination = CodyncApprovedDestinations.All.SingleOrDefault(item => item.Id == destinationId && item.Name == Arg(request, "destination_name"));
                if (destination is null) return CodyncBlocked(request, startedAt, "Destination identity is not in the approved allowlist.");
                if (!Guid.TryParseExact(Arg(request, "send_dispatch_id"), "D", out var sendDispatchId) ||
                    !long.TryParse(Arg(request, "root_sequence"), out var rootSequence) ||
                    !long.TryParse(Arg(request, "root_revision"), out var rootRevision) ||
                    !int.TryParse(Arg(request, "timeout_seconds"), out var timeoutSeconds) || timeoutSeconds is < 1 or > 240)
                {
                    return CodyncBlocked(request, startedAt, "Wait correlation arguments are invalid or outside the allowed bound.");
                }
                var rootTurnText = Arg(request, "root_turn");
                if (!long.TryParse(rootTurnText, out var rootTurn) || string.IsNullOrWhiteSpace(Arg(request, "root_entry_id")) ||
                    !DateTimeOffset.TryParse(Arg(request, "submitted_at"), out var submittedAt))
                    return CodyncBlocked(request, startedAt, "Root entry/turn correlation is invalid.");
                var expectedNonce = $"ldw-operations-{sendDispatchId:D}";
                if (!string.Equals(Arg(request, "client_nonce"), expectedNonce, StringComparison.Ordinal))
                    return CodyncBlocked(request, startedAt, "Client nonce does not match the original dispatch ID.");
                var expectedAuthorId = Arg(request, "expected_author_id");
                if (destination.Kind == "group" ? !destination.Members.Contains(expectedAuthorId, StringComparer.Ordinal) : destination.Id != expectedAuthorId)
                    return CodyncBlocked(request, startedAt, "Expected reply author is outside the exact destination identity.");
                var receipt = new CodyncSendReceipt(destination.Id, destination.Name, expectedNonce, Arg(request, "root_entry_id"), rootSequence, rootTurn, rootRevision, submittedAt);
                var result = await _codyncAdapter.WaitReadExactAsync(receipt, expectedAuthorId, TimeSpan.FromSeconds(timeoutSeconds), cancellationToken).ConfigureAwait(false);
                payload["provider_start_observed"] = result.ProviderStartObserved ? "true" : "false";
                payload["needs_input"] = result.NeedsInput ? "true" : "false";
                payload["state"] = result.State;
                if (result.Reply is { } reply)
                {
                    payload["reply_author_id"] = reply.AuthorId;
                    payload["reply_sequence"] = reply.Sequence.ToString();
                    payload["reply_text"] = reply.Text;
                }
                if (result.NeedsInput || result.State == "needs_input") status = DispatchTerminalStatus.Blocked;
                else if (result.State == "stale_identity") status = DispatchTerminalStatus.Stale;
                else if (result.State is "timeout" or "connection_lost" or "subscription_missing") status = DispatchTerminalStatus.Failed;
                else if (!result.ProviderStartObserved || result.Reply is null) status = DispatchTerminalStatus.Ambiguous;
                evidence = BridgeProtocol.BoundEvidence(result.Evidence);
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
            BridgeProtocol.BridgeRuntime,
            BridgeProtocol.BridgeRuntimeVersion,
            request.Operation,
            status,
            startedAt,
            completedAt,
            BridgeProtocol.BoundEvidence(evidence),
            BridgeProtocol.BoundPayload(payload, request.Operation));
    }

    private static BridgeDispatchResult CodyncUnavailable(BridgeDispatchRequest request, DateTimeOffset startedAt)
        => CodyncBlocked(request, startedAt, "Codync adapter is not configured in this bridge runtime.");

    private static BridgeDispatchResult CodyncBlocked(BridgeDispatchRequest request, DateTimeOffset startedAt, string evidence)
        => new(request.DispatchId, request.IdempotencyKey, request.CorrelationId,
            BridgeProtocol.BridgeRuntime, BridgeProtocol.BridgeRuntimeVersion, request.Operation,
            DispatchTerminalStatus.Blocked, startedAt, DateTimeOffset.UtcNow, BridgeProtocol.BoundEvidence(evidence),
            BridgeProtocol.BoundPayload(null));

    private static string Arg(BridgeDispatchRequest request, string name)
        => request.Args.TryGetValue(name, out var value) ? value : string.Empty;

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
            now,
            now,
            BridgeProtocol.BoundEvidence($"Rejected before local execution: {validationError}"),
            BridgeProtocol.BoundPayload(null));
    }
}
