using System.Text.Json;
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

var adapter = new CountingBrowserAdapter(
[
    new BrowserTabMetadata("1", "CHATGPT_MAIN", "ChatGPT | Operations", "https://chatgpt.com/c/123"),
    new BrowserTabMetadata("2", "NOT_ALLOWLISTED", "Bank", "https://bank.example.com/private"),
    new BrowserTabMetadata("3", "LOOKALIKE", "Fake GPT", "https://evilchatgpt.com/prompt"),
    new BrowserTabMetadata("4", "SUBDOMAIN_OK", "OpenAI", "https://status.openai.com/")
]);

var client = new OutboundBridgeClient(bridgeId, adapter, validator);
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
Assert(adapter.ListTabsCalls == 1, "allowlisted happy-path invoked adapter once");

var staleClientRequest = BuildRequest(
    bridgeId,
    BridgeOperation.ListTabs,
    now.AddMinutes(-10),
    now.AddMinutes(-1),
    "idem-stale-client",
    "corr-stale-client");
var adapterCallsBeforeStale = adapter.TotalCalls;
await transport.DeliverAsync(staleClientRequest, "conn-stale");
Assert(adapter.TotalCalls == adapterCallsBeforeStale, "stale request blocked before adapter execution");
Assert(transport.Results[^1].TerminalStatus == DispatchTerminalStatus.Stale, "stale client request returns STALE");

var unknownClientRequest = BuildRequest(
    bridgeId,
    BridgeOperation.Unknown,
    now,
    now.AddMinutes(1),
    "idem-unknown-client",
    "corr-unknown-client");
var adapterCallsBeforeUnknown = adapter.TotalCalls;
await transport.DeliverAsync(unknownClientRequest, "conn-unknown");
Assert(adapter.TotalCalls == adapterCallsBeforeUnknown, "unknown operation blocked before adapter execution");
Assert(transport.Results[^1].TerminalStatus == DispatchTerminalStatus.Blocked, "unknown client operation returns BLOCKED");

var wireJson = JsonSerializer.Serialize(new
{
    type = "dispatch",
    protocolVersion = BridgeProtocol.Version,
    dispatchId = Guid.NewGuid().ToString("D"),
    bridgeId,
    operation = "browser.health",
    issuedAt = now.ToString("O"),
    expiresAt = now.AddMinutes(2).ToString("O"),
    idempotencyKey = "idem-wire",
    correlationId = "corr-wire",
    args = new Dictionary<string, string>()
});
Assert(ClientWebSocketBridgeTransport.TryParseDispatchMessage(wireJson, out var parsed, out var parseError), $"parses concrete WS dispatch envelope ({parseError})");
Assert(parsed is not null && parsed.Operation == BridgeOperation.BrowserHealth, "wire operation maps to BrowserHealth");

var terminalWire = ClientWebSocketBridgeTransport.ToTerminalWireMessage(
    new BridgeDispatchResult(
        parsed!.DispatchId,
        parsed.IdempotencyKey,
        parsed.CorrelationId,
        DispatchTerminalStatus.Pass,
        now,
        now.AddSeconds(1),
        new string('e', BridgeProtocol.MaxEvidenceLength + 40),
        new Dictionary<string, string>
        {
            ["ok"] = "true",
            ["overflow"] = new string('p', BridgeProtocol.MaxPayloadValueLength + 40)
        }));
var terminalJson = JsonSerializer.Serialize(terminalWire);
using (var terminalDoc = JsonDocument.Parse(terminalJson))
{
    var root = terminalDoc.RootElement;
    Assert(root.GetProperty("type").GetString() == "terminal", "terminal wire type is terminal");
    Assert(root.GetProperty("status").GetString() == "PASS", "terminal wire status is closed PASS");
    Assert(root.GetProperty("evidence").GetString()!.Length == BridgeProtocol.MaxEvidenceLength, "terminal evidence is bounded");
    Assert(root.GetProperty("payload").GetProperty("overflow").GetString()!.Length == BridgeProtocol.MaxPayloadValueLength, "terminal payload values are bounded");
}

Assert(BridgeProtocol.AllowedTerminalStatuses.SetEquals(
[
    DispatchTerminalStatus.Pass,
    DispatchTerminalStatus.Blocked,
    DispatchTerminalStatus.Failed,
    DispatchTerminalStatus.Stale,
    DispatchTerminalStatus.Ambiguous
]), "terminal enum is closed to PASS/BLOCKED/FAILED/STALE/AMBIGUOUS");

Assert(!ClientWebSocketBridgeTransport.TryParseDispatchMessage(
    """{"type":"dispatch","protocolVersion":"1.0","dispatchId":"bad","bridgeId":"ldw01-bridge","operation":"browser.eval","issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:01:00Z","idempotencyKey":"x","correlationId":"y","args":{}}""",
    out _,
    out _), "unknown/invalid wire dispatch fails parse before execution");

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

sealed class CountingBrowserAdapter : IBridgeBrowserAdapter
{
    private readonly SyntheticBrowserAdapter _inner;

    public CountingBrowserAdapter(IEnumerable<BrowserTabMetadata> tabs)
    {
        _inner = new SyntheticBrowserAdapter(tabs);
    }

    public int ListTabsCalls { get; private set; }
    public int TotalCalls { get; private set; }

    public Task<BrowserHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        TotalCalls++;
        return _inner.GetHealthAsync(cancellationToken);
    }

    public Task<IReadOnlyList<BrowserTabMetadata>> ListTabsAsync(CancellationToken cancellationToken)
    {
        TotalCalls++;
        ListTabsCalls++;
        return _inner.ListTabsAsync(cancellationToken);
    }

    public Task<BrowserTabMetadata?> ReadTabMetadataAsync(string tabId, CancellationToken cancellationToken)
    {
        TotalCalls++;
        return _inner.ReadTabMetadataAsync(tabId, cancellationToken);
    }
}
