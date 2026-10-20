using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

var assertionCount = 0;
var bridgeId = "ldw01-bridge";
var now = DateTimeOffset.UtcNow;
var validator = new DispatchValidator([bridgeId], BridgeProtocol.AllowedReadOnlyOperations);
var store = new RelayDispatchStore(validator);

var validRequest = BuildRequest(
    bridgeId,
    BridgeOperation.ListTabs,
    now.AddSeconds(-5),
    now.AddMinutes(2),
    "idem-1",
    "corr-1");

var accept = store.Accept(validRequest, now);
Assert(accept.State == DispatchAcceptState.Accepted, "accepts valid read-only dispatch");
Assert(store.TryMarkDelivered(validRequest.DispatchId, "conn-a", now.AddSeconds(1)), "marks delivered with connection identity");
Assert(store.TryMarkStarted(validRequest.DispatchId, "conn-a", now.AddSeconds(2)), "marks started with matching connection identity");
Assert(
    store.TryComplete(
        validRequest.DispatchId,
        "conn-a",
        "corr-1",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(3),
        "ok",
        new Dictionary<string, string> { ["tab_count"] = "1" }),
    "accepts correlated pass result");
Assert(store.Get(validRequest.DispatchId)?.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Pass, "stores PASS terminal result exactly once");

Assert(
    !store.TryComplete(
        validRequest.DispatchId,
        "conn-a",
        "corr-1",
        DispatchTerminalStatus.Failed,
        now.AddSeconds(4),
        "late duplicate",
        new Dictionary<string, string>()),
    "rejects second terminal completion for same dispatch");

var duplicate = store.Accept(
    BuildRequest(
        bridgeId,
        BridgeOperation.ListTabs,
        now.AddSeconds(-2),
        now.AddMinutes(3),
        "idem-1",
        "corr-2"),
    now);
Assert(duplicate.State == DispatchAcceptState.Duplicate, "duplicate idempotency key does not re-execute");
Assert(duplicate.Envelope.Request.DispatchId == validRequest.DispatchId, "duplicate idempotency returns original dispatch");

var unknownOp = store.Accept(
    BuildRequest(bridgeId, BridgeOperation.Unknown, now, now.AddMinutes(1), "idem-2", "corr-3"),
    now);
Assert(unknownOp.State == DispatchAcceptState.Blocked, "unknown operation fails closed");
Assert(unknownOp.Envelope.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Blocked, "unknown operation becomes BLOCKED terminal");

var unknownBridge = store.Accept(
    BuildRequest("unknown", BridgeOperation.ListTabs, now, now.AddMinutes(1), "idem-3", "corr-4"),
    now);
Assert(unknownBridge.State == DispatchAcceptState.Blocked, "unknown bridge fails closed");

var badSchema = store.Accept(
    BuildRequest(bridgeId, BridgeOperation.ListTabs, now, now.AddMinutes(1), "idem-4", "corr-5") with { ProtocolVersion = "9.9" },
    now);
Assert(badSchema.State == DispatchAcceptState.Blocked, "unknown protocol fails closed");

var stale = store.Accept(
    BuildRequest(bridgeId, BridgeOperation.ListTabs, now.AddMinutes(-10), now.AddSeconds(-1), "idem-5", "corr-6"),
    now);
Assert(stale.State == DispatchAcceptState.Blocked, "stale TTL fails closed");
Assert(stale.Envelope.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Stale, "stale request terminal is STALE");

var oversizedTtl = store.Accept(
    BuildRequest(bridgeId, BridgeOperation.ListTabs, now, now.AddMinutes(20), "idem-ttl", "corr-ttl"),
    now);
Assert(oversizedTtl.State == DispatchAcceptState.Blocked, "issued->expires window above maximum TTL fails closed");
Assert(oversizedTtl.Envelope.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Stale, "oversized TTL maps to STALE terminal");

var lostCorrelation = BuildRequest(
    bridgeId,
    BridgeOperation.BrowserHealth,
    now,
    now.AddMinutes(1),
    "idem-6",
    "corr-7");
Assert(store.Accept(lostCorrelation, now).State == DispatchAcceptState.Accepted, "accepts request for correlation test");
Assert(store.TryMarkDelivered(lostCorrelation.DispatchId, "conn-corr", now), "delivered before correlation test");
Assert(store.TryMarkStarted(lostCorrelation.DispatchId, "conn-corr", now), "started before correlation test");
Assert(
    store.TryComplete(
        lostCorrelation.DispatchId,
        "other-connection",
        "wrong-correlation",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(10),
        "should not pass",
        new Dictionary<string, string> { ["ready"] = "true" }),
    "completion still records terminal under fail-closed conversion");
Assert(store.Get(lostCorrelation.DispatchId)?.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Ambiguous, "lost correlation becomes AMBIGUOUS, never PASS");
Assert(store.Get(lostCorrelation.DispatchId)?.TerminalResult?.CorrelationId == "corr-7", "lost correlation preserves original correlation identity");

var disconnectBeforeTerminal = BuildRequest(
    bridgeId,
    BridgeOperation.ListTabs,
    now,
    now.AddSeconds(1),
    "idem-7",
    "corr-8");
Assert(store.Accept(disconnectBeforeTerminal, now).State == DispatchAcceptState.Accepted, "accepts request for disconnect test");
Assert(store.TryMarkDelivered(disconnectBeforeTerminal.DispatchId, "conn-drop", now), "delivers request before disconnect");
Assert(store.TryMarkStarted(disconnectBeforeTerminal.DispatchId, "conn-drop", now), "starts request before disconnect");
Assert(store.ResolveExpired(now.AddSeconds(3)) > 0, "expiry resolver marks timed-out dispatches terminal");
Assert(store.Get(disconnectBeforeTerminal.DispatchId)?.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Ambiguous, "connection loss does not manufacture PASS");

var adapter = new SyntheticBrowserAdapter(
[
    new BrowserTabMetadata("1", "CHATGPT_MAIN", "ChatGPT | Operations", "https://chatgpt.com/c/123"),
    new BrowserTabMetadata("2", "NOT_ALLOWLISTED", "Bank", "https://bank.example.com/private"),
    new BrowserTabMetadata("3", "LOOKALIKE", "Fake GPT", "https://evilchatgpt.com/prompt"),
    new BrowserTabMetadata("4", "SUBDOMAIN_OK", "OpenAI", "https://status.openai.com/")
]);

var client = new OutboundBridgeClient(bridgeId, adapter);
var transport = new FakeBridgeTransport();
client.Attach(transport);

var readOnlyDispatch = BuildRequest(
    bridgeId,
    BridgeOperation.ListTabs,
    now,
    now.AddMinutes(2),
    "idem-8",
    "corr-9");
await transport.DeliverAsync(readOnlyDispatch, "conn-client");

Assert(transport.Results.Count == 1, "outbound client emits exactly one result");
Assert(transport.Results[0].TerminalStatus == DispatchTerminalStatus.Pass, "read-only operation passes");
Assert(transport.Results[0].Payload.ContainsKey("tab_0_url"), "result includes sanitized metadata");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("bank.example.com", StringComparison.OrdinalIgnoreCase)), "non-allowlisted tab metadata is filtered");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("evilchatgpt.com", StringComparison.OrdinalIgnoreCase)), "lookalike host is filtered from allowlist");
Assert(transport.Results[0].Payload.Values.Any(value => value.Contains("status.openai.com", StringComparison.OrdinalIgnoreCase)), "allowlisted subdomain remains visible");

Console.WriteLine($"Operations bridge deterministic tests passed ({assertionCount} assertions).");

static BridgeDispatchRequest BuildRequest(
    string bridgeId,
    BridgeOperation operation,
    DateTimeOffset issuedAt,
    DateTimeOffset expiresAt,
    string idempotencyKey,
    string correlationId)
{
    return new BridgeDispatchRequest(
        BridgeProtocol.Version,
        Guid.NewGuid(),
        bridgeId,
        operation,
        issuedAt,
        expiresAt,
        idempotencyKey,
        correlationId,
        new Dictionary<string, string>());
}

void Assert(bool condition, string description)
{
    assertionCount++;
    if (!condition)
    {
        throw new InvalidOperationException($"FAILED: {description}");
    }
}

sealed class FakeBridgeTransport : IBridgeTransport
{
    public event Func<BridgeDispatchRequest, string, CancellationToken, Task>? DispatchReceived;
    public List<BridgeDispatchResult> Results { get; } = [];

    public async Task DeliverAsync(BridgeDispatchRequest request, string connectionId)
    {
        var handler = DispatchReceived;
        if (handler is null)
        {
            throw new InvalidOperationException("No dispatch handler attached.");
        }

        await handler(request, connectionId, CancellationToken.None).ConfigureAwait(false);
    }

    public Task SendResultAsync(BridgeDispatchResult result, CancellationToken cancellationToken)
    {
        Results.Add(result);
        return Task.CompletedTask;
    }
}
