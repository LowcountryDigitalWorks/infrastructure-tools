using System.Text.Json;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
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
        "idem-1",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(3),
        "ok",
        new Dictionary<string, string> { ["tab_count"] = "1" },
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now.AddSeconds(2)),
    "accepts correlated pass result");
Assert(store.Get(validRequest.DispatchId)?.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Pass, "stores PASS terminal result exactly once");
Assert(store.Get(validRequest.DispatchId)?.TerminalResult?.BridgeRuntime == BridgeProtocol.BridgeRuntime, "PASS terminal preserves bridge runtime");
Assert(store.Get(validRequest.DispatchId)?.TerminalResult?.Operation == BridgeOperation.ListTabs, "PASS terminal preserves exact operation");

Assert(
    !store.TryComplete(
        validRequest.DispatchId,
        "conn-a",
        "corr-1",
        "idem-1",
        DispatchTerminalStatus.Failed,
        now.AddSeconds(4),
        "late duplicate",
        new Dictionary<string, string>(),
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now.AddSeconds(2)),
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

var codyncBot = CodyncApprovedDestinations.All.Single(item => item.Name == "LDW IR - Cursor");
var codyncGroup = CodyncApprovedDestinations.All.Single(item => item.Name == "LDW Review Board — Cursor");
var validCodyncSend = BuildRequest(bridgeId, BridgeOperation.CodyncSendExact, now, now.AddMinutes(1), "idem-codync-send", "corr-codync-send") with
{
    Args = new Dictionary<string, string> { ["destination_id"] = codyncBot.Id, ["destination_name"] = codyncBot.Name, ["text"] = "Return the harmless sentinel." }
};
Assert(store.Accept(validCodyncSend, now).State == DispatchAcceptState.Accepted, "accepts an exact approved Codync bot send schema");
var unsafeCodyncSend = validCodyncSend with { DispatchId = Guid.NewGuid(), IdempotencyKey = "idem-codync-all", Args = new Dictionary<string, string> { ["destination_id"] = codyncGroup.Id, ["destination_name"] = codyncGroup.Name, ["text"] = "@all answer" } };
Assert(store.Accept(unsafeCodyncSend, now).State == DispatchAcceptState.Blocked, "unmentioned all-member group send fails closed");
var unknownCodyncArg = validCodyncSend with { DispatchId = Guid.NewGuid(), IdempotencyKey = "idem-codync-rpc", Args = new Dictionary<string, string>(validCodyncSend.Args) { ["method"] = "createBot" } };
Assert(store.Accept(unknownCodyncArg, now).State == DispatchAcceptState.Blocked, "Codync operation rejects generic method arguments");

var codyncAdapter = new FakeCodyncAdapter();
var codyncClient = new OutboundBridgeClient(bridgeId, new SyntheticBrowserAdapter([]), validator, codyncAdapter);
var codyncTransport = new FakeBridgeTransport();
codyncClient.Attach(codyncTransport);
var groupSendId = Guid.NewGuid();
var groupSend = BuildRequest(bridgeId, BridgeOperation.CodyncSendExact, now, now.AddMinutes(2), "idem-group-send", "corr-group-send") with
{
    DispatchId = groupSendId,
    Args = new Dictionary<string, string>
    {
        ["destination_id"] = codyncGroup.Id,
        ["destination_name"] = codyncGroup.Name,
        ["text"] = "@LDW IR - Cursor reply PASS LDW644-SMOKE",
        ["mentioned_member_ids"] = codyncBot.Id
    }
};
await codyncTransport.DeliverAsync(groupSend, "conn-codync");
Assert(codyncTransport.Results[^1].TerminalStatus == DispatchTerminalStatus.Blocked, "exact Codync send cannot manufacture provider PASS");
Assert(codyncTransport.Results[^1].Payload["stage"] == "accepted_send", "Codync send clearly labels accepted-send stage");
Assert(codyncTransport.Results[^1].Payload["client_nonce"] == $"ldw-operations-{groupSendId:D}", "Codync client nonce is derived deterministically from dispatch ID");

var waitArgs = new Dictionary<string, string>
{
    ["destination_id"] = codyncGroup.Id,
    ["destination_name"] = codyncGroup.Name,
    ["send_dispatch_id"] = groupSendId.ToString("D"),
    ["client_nonce"] = $"ldw-operations-{groupSendId:D}",
    ["root_entry_id"] = "d54b9631-2aa7-41e9-94af-0a15039abd43",
    ["root_sequence"] = "10",
    ["root_turn"] = "3",
    ["root_revision"] = "42",
    ["submitted_at"] = now.ToString("O"),
    ["expected_author_id"] = codyncBot.Id,
    ["timeout_seconds"] = "120"
};
var waitRequest = BuildRequest(bridgeId, BridgeOperation.CodyncWaitReadExact, now, now.AddMinutes(3), "idem-codync-wait", "corr-codync-wait") with { Args = waitArgs };
await codyncTransport.DeliverAsync(waitRequest, "conn-codync");
Assert(codyncTransport.Results[^1].TerminalStatus == DispatchTerminalStatus.Pass, "Codync wait passes only with provider start plus exact final reply");
Assert(codyncTransport.Results[^1].Payload["provider_start_observed"] == "true", "Codync wait exposes provider-positive start evidence");
Assert(codyncTransport.Results[^1].Payload["reply_author_id"] == codyncBot.Id, "Codync wait correlates the exact member author");

foreach (var (state, expectedStatus) in new[]
{
    ("stale_identity", DispatchTerminalStatus.Stale),
    ("timeout", DispatchTerminalStatus.Failed),
    ("connection_lost", DispatchTerminalStatus.Failed),
    ("needs_input", DispatchTerminalStatus.Blocked)
})
{
    var stateClient = new OutboundBridgeClient(bridgeId, new SyntheticBrowserAdapter([]), validator,
        new FakeCodyncAdapter(new CodyncWaitResult(false, state == "needs_input", null, state, "synthetic state")));
    var stateTransport = new FakeBridgeTransport();
    stateClient.Attach(stateTransport);
    var stateRequest = waitRequest with
    {
        DispatchId = Guid.NewGuid(),
        IdempotencyKey = "idem-codync-" + state,
        CorrelationId = "corr-codync-" + state,
        Args = new Dictionary<string, string>(waitArgs) { ["send_dispatch_id"] = Guid.NewGuid().ToString("D") }
    };
    var nonceDispatchId = Guid.Parse(stateRequest.Args["send_dispatch_id"]);
    stateRequest = stateRequest with { Args = new Dictionary<string, string>(stateRequest.Args) { ["client_nonce"] = $"ldw-operations-{nonceDispatchId:D}" } };
    await stateTransport.DeliverAsync(stateRequest, "conn-codync-state");
    Assert(stateTransport.Results[^1].TerminalStatus == expectedStatus, $"Codync wait state {state} maps to {expectedStatus}");
}

var localHost = new FakeCodyncHttpHandler();
using (var liveAdapter = new CodyncLoopbackAdapter(_ => ValueTask.FromResult("unit-test-bearer-never-return"), localHost))
{
    var health = await liveAdapter.GetHealthAsync(CancellationToken.None);
    Assert(health.Ready && health.Version == "2.20.4", "Codync adapter parses host health through its fixed loopback API");
    var sentAt = DateTimeOffset.UtcNow;
    var liveReceipt = await liveAdapter.SendExactAsync(codyncBot.Id, codyncBot.Name, "Read-only deterministic fixture.", "ldw-test-nonce", [], CancellationToken.None);
    Assert(liveReceipt.SubmittedAt >= sentAt && liveReceipt.RootEntryId == FakeCodyncHttpHandler.RootEntryId, "Codync adapter returns exact root receipt and original send time");
    var liveWait = await liveAdapter.WaitReadExactAsync(liveReceipt, codyncBot.Id, TimeSpan.FromSeconds(5), CancellationToken.None);
    Assert(liveWait.ProviderStartObserved && liveWait.Reply?.AuthorId == codyncBot.Id && liveWait.Reply.Sequence == 11, "Codync adapter correlates provider start and exact final author/root turn");
    var safeResult = JsonSerializer.Serialize(liveWait);
    Assert(!safeResult.Contains("unit-test-bearer-never-return", StringComparison.Ordinal), "Codync bearer never appears in adapter result");
}

using (var rosterAdapter = new CodyncLoopbackAdapter(_ => ValueTask.FromResult("unit-test-bearer-never-return"), new FakeCodyncHttpHandler(rosterOnly: true)))
{
    var approved = await rosterAdapter.ListApprovedBotsGroupsAsync(CancellationToken.None);
    Assert(approved.Count == CodyncApprovedDestinations.All.Count, "Codync adapter resolves the full exact approved roster from SSE");
    var serialized = JsonSerializer.Serialize(approved, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    var boundedRoster = BridgeProtocol.BoundPayload(new Dictionary<string, string> { ["approved_destinations_json"] = serialized }, BridgeOperation.CodyncListApprovedBotsGroups);
    Assert(boundedRoster["approved_destinations_json"].Length == serialized.Length, "approved Codync roster is not truncated in terminal payload");
}

using (var malformedAdapter = new CodyncLoopbackAdapter(_ => ValueTask.FromResult("unit-test-bearer-never-return"), new FakeCodyncHttpHandler(malformedRoster: true)))
{
    await AssertThrowsAsync<JsonException>(() => malformedAdapter.ListApprovedBotsGroupsAsync(CancellationToken.None), "malformed Codync SSE JSON fails closed");
}

foreach (var failureMode in new[] { "wrong_author", "wrong_sequence", "wrong_turn", "stream_loss" })
{
    using var failureAdapter = new CodyncLoopbackAdapter(_ => ValueTask.FromResult("unit-test-bearer-never-return"), new FakeCodyncHttpHandler(failureMode: failureMode));
    var receipt = await failureAdapter.SendExactAsync(codyncBot.Id, codyncBot.Name, "Fixture only.", "ldw-test-" + failureMode, [], CancellationToken.None);
    var wait = await failureAdapter.WaitReadExactAsync(receipt, codyncBot.Id, TimeSpan.FromSeconds(5), CancellationToken.None);
    Assert(wait.Reply is null && wait.State == "connection_lost", $"Codync rejects {failureMode} final evidence");
}

using (var wrongRootAdapter = new CodyncLoopbackAdapter(_ => ValueTask.FromResult("unit-test-bearer-never-return"), new FakeCodyncHttpHandler(failureMode: "wrong_root")))
{
    var receipt = await wrongRootAdapter.SendExactAsync(codyncBot.Id, codyncBot.Name, "Fixture only.", "ldw-test-wrong-root", [], CancellationToken.None);
    await AssertThrowsAsync<InvalidOperationException>(
        () => wrongRootAdapter.WaitReadExactAsync(receipt, codyncBot.Id, TimeSpan.FromSeconds(5), CancellationToken.None),
        "Codync rejects stale or mismatched history root correlation");
}

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
        "idem-6",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(10),
        "should not pass",
        new Dictionary<string, string> { ["ready"] = "true" },
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now),
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
Assert(store.Get(disconnectBeforeTerminal.DispatchId)?.TerminalResult?.ExecutionStartObserved == true, "started dispatch preserves observed start on relay resolution");
Assert(store.Get(disconnectBeforeTerminal.DispatchId)?.TerminalResult?.BridgeRuntime is null, "relay resolution does not invent bridge runtime");

var adapter = new CountingBrowserAdapter(
[
    new BrowserTabMetadata("1", "CHATGPT_MAIN", "ChatGPT | Operations", "https://chatgpt.com/c/123?access_token=secret#frag"),
    new BrowserTabMetadata("2", "NOT_ALLOWLISTED", "Bank", "https://bank.example.com/private"),
    new BrowserTabMetadata("3", "LOOKALIKE", "Fake GPT", "https://evilchatgpt.com/prompt"),
    new BrowserTabMetadata("4", "SUBDOMAIN_OK", "OpenAI", "https://status.openai.com/"),
    new BrowserTabMetadata("5", "USERINFO", "Creds", "https://user:pass@chatgpt.com/c/safe"),
    new BrowserTabMetadata("6", "RESET_PATH", "Reset", "https://chatgpt.com/reset/Sup3rSecretResetTokenValue1234567890"),
    new BrowserTabMetadata("7", "LOGIN_TOKEN_PATH", "Login", "https://chatgpt.com/login/token/one-time-login-secret-abcDEF999"),
    new BrowserTabMetadata("8", "SHORT_TOKEN_ROOT", "Short token", "https://chatgpt.com/abc123"),
    new BrowserTabMetadata("9", "SHORT_TOKEN_SEGMENT", "Short token segment", "https://chatgpt.com/r/aBc123")
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
Assert(transport.Results[0].Payload.Values.Any(value => value.Equals("https://chatgpt.com/c/*", StringComparison.Ordinal)), "allowlisted URL keeps short structural path identity with deeper segments redacted");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("access_token", StringComparison.OrdinalIgnoreCase)), "secret-bearing query values never leave LDW01");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("user:pass@", StringComparison.OrdinalIgnoreCase)), "URL userinfo never leaves LDW01");
Assert(transport.Results[0].Payload.Values.Count(value => value.Equals("https://chatgpt.com/c/*", StringComparison.Ordinal)) >= 2, "userinfo-bearing allowlisted URL uses the same structural path representation");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("Sup3rSecretResetTokenValue1234567890", StringComparison.Ordinal)), "reset-path token material never leaves LDW01");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("one-time-login-secret-abcDEF999", StringComparison.Ordinal)), "login/token path secret material never leaves LDW01");
Assert(transport.Results[0].Payload.Values.Any(value => value.Equals("https://chatgpt.com/reset/*", StringComparison.Ordinal)), "reset-style path redacts to structural label plus placeholder");
Assert(transport.Results[0].Payload.Values.Any(value => value.Equals("https://chatgpt.com/login/*", StringComparison.Ordinal)), "login/token-style path redacts to structural label plus placeholder");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("abc123", StringComparison.OrdinalIgnoreCase)), "short token-like path material never leaves LDW01");
Assert(!transport.Results[0].Payload.Values.Any(value => value.Contains("aBc123", StringComparison.OrdinalIgnoreCase)), "short token-like later path material never leaves LDW01");
Assert(transport.Results[0].Payload.Values.Any(value => value.Equals("https://chatgpt.com/*", StringComparison.Ordinal)), "unrecognized first path segment is fully redacted");
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
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        parsed.Operation,
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
    Assert(root.GetProperty("bridgeRuntime").GetString() == BridgeProtocol.BridgeRuntime, "terminal wire includes bridge runtime");
    Assert(root.GetProperty("bridgeVersion").GetString() == BridgeProtocol.BridgeRuntimeVersion, "terminal wire includes bridge version");
    Assert(root.GetProperty("operation").GetString() == "browser.health", "terminal wire includes exact operation class");
    Assert(root.GetProperty("resultClass").GetString() == "PASS", "terminal wire includes result class");
    Assert(root.GetProperty("startedAt").GetString() is not null, "terminal wire includes startedAt");
    Assert(root.GetProperty("completedAt").GetString() is not null, "terminal wire includes completedAt");
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

// HIGH: bearer must not attach unless wss + explicitly trusted Worker endpoint.
var trusted = new TrustedRelayEndpoint(new Uri("wss://relay.example/relay/connect?bridgeId=ldw01-bridge"));
AssertThrows(
    () => BridgeConnectGuard.EnsureTrustedSecureEndpoint(new Uri("ws://relay.example/relay/connect"), [trusted]),
    "plaintext ws endpoint is rejected before credential attach");
AssertThrows(
    () => BridgeConnectGuard.EnsureTrustedSecureEndpoint(new Uri("wss://attacker.example/relay/connect"), [trusted]),
    "arbitrary wss endpoint is rejected before credential attach");
AssertThrows(
    () => BridgeConnectGuard.EnsureTrustedSecureEndpoint(trusted.ConnectUri, Array.Empty<TrustedRelayEndpoint>()),
    "empty trusted endpoint configuration fails closed");
BridgeConnectGuard.EnsureTrustedSecureEndpoint(trusted.ConnectUri, [trusted]);
assertionCount++;

// MEDIUM: missing/mismatched idempotency key never records PASS.
var idemGuard = BuildRequest(bridgeId, BridgeOperation.BrowserHealth, now, now.AddMinutes(2), "idem-key-guard", "corr-key-guard");
Assert(store.Accept(idemGuard, now).State == DispatchAcceptState.Accepted, "accepts idempotency guard dispatch");
Assert(store.TryMarkDelivered(idemGuard.DispatchId, "conn-idem", now), "delivers idempotency guard dispatch");
Assert(store.TryMarkStarted(idemGuard.DispatchId, "conn-idem", now), "starts idempotency guard dispatch");
Assert(
    !store.TryComplete(
        idemGuard.DispatchId,
        "conn-idem",
        "corr-key-guard",
        "",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(1),
        "missing key",
        new Dictionary<string, string>(),
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now),
    "missing idempotency key rejects terminal completion");
Assert(
    !store.TryComplete(
        idemGuard.DispatchId,
        "conn-idem",
        "corr-key-guard",
        "wrong-idem",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(1),
        "mismatched key",
        new Dictionary<string, string>(),
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now),
    "mismatched idempotency key rejects terminal completion");
Assert(store.Get(idemGuard.DispatchId)?.TerminalResult is null, "idempotency mismatch never records terminal PASS");
Assert(
    store.TryComplete(
        idemGuard.DispatchId,
        "conn-idem",
        "corr-key-guard",
        "idem-key-guard",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(2),
        "matched",
        new Dictionary<string, string> { ["ready"] = "true" },
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now.AddSeconds(1)),
    "exact idempotency match accepts terminal");

// MEDIUM: adapter exceptions resolve FAILED without manufacturing PASS.
var throwingAdapter = new ThrowingBrowserAdapter();
var throwingClient = new OutboundBridgeClient(bridgeId, throwingAdapter, validator);
var throwingTransport = new FakeBridgeTransport();
throwingClient.Attach(throwingTransport);
var throwingDispatch = BuildRequest(bridgeId, BridgeOperation.ListTabs, now, now.AddMinutes(2), "idem-throw", "corr-throw");
await throwingTransport.DeliverAsync(throwingDispatch, "conn-throw");
Assert(throwingTransport.Results.Count == 1, "adapter exception still emits one terminal");
Assert(throwingTransport.Results[0].TerminalStatus == DispatchTerminalStatus.Failed, "adapter exception resolves FAILED");
Assert(throwingTransport.Results[0].ResultClass == "FAILED", "adapter exception result class is FAILED");

// MEDIUM: connection-loss resolver marks delivered/started nonterminal as AMBIGUOUS.
var lostConn = BuildRequest(bridgeId, BridgeOperation.ListTabs, now, now.AddMinutes(5), "idem-lost-conn", "corr-lost-conn");
Assert(store.Accept(lostConn, now).State == DispatchAcceptState.Accepted, "accepts connection-loss dispatch");
Assert(store.TryMarkDelivered(lostConn.DispatchId, "conn-lost", now), "delivers before connection loss");
Assert(store.ResolveConnectionLoss("conn-lost", now.AddSeconds(1)) == 1, "connection-loss resolver updates one dispatch");
Assert(store.Get(lostConn.DispatchId)?.TerminalResult?.TerminalStatus == DispatchTerminalStatus.Ambiguous, "connection loss resolves AMBIGUOUS not PASS");
Assert(store.Get(lostConn.DispatchId)?.TerminalResult?.ExecutionStartObserved == false, "delivered-only loss keeps execution start unobserved");
Assert(store.Get(lostConn.DispatchId)?.TerminalResult?.StartedAt is null, "delivered-only loss does not invent startedAt");
Assert(store.Get(lostConn.DispatchId)?.TerminalResult?.BridgeRuntime is null, "delivered-only loss does not invent bridge runtime");

// MEDIUM: client terminal without observed provenance is rejected.
var provenanceGuard = BuildRequest(bridgeId, BridgeOperation.BrowserHealth, now, now.AddMinutes(2), "idem-prov", "corr-prov");
Assert(store.Accept(provenanceGuard, now).State == DispatchAcceptState.Accepted, "accepts provenance guard dispatch");
Assert(store.TryMarkDelivered(provenanceGuard.DispatchId, "conn-prov", now), "delivers provenance guard");
Assert(store.TryMarkStarted(provenanceGuard.DispatchId, "conn-prov", now), "starts provenance guard");
Assert(
    !store.TryComplete(
        provenanceGuard.DispatchId,
        "conn-prov",
        "corr-prov",
        "idem-prov",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(1),
        "missing runtime",
        new Dictionary<string, string>(),
        bridgeRuntime: null,
        bridgeVersion: BridgeProtocol.BridgeRuntimeVersion,
        startedAt: now),
    "missing bridgeRuntime rejects client terminal");
Assert(
    !store.TryComplete(
        provenanceGuard.DispatchId,
        "conn-prov",
        "corr-prov",
        "idem-prov",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(1),
        "future start",
        new Dictionary<string, string>(),
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now.AddMinutes(5)),
    "startedAt after completedAt rejects client terminal");
Assert(store.Get(provenanceGuard.DispatchId)?.TerminalResult is null, "unobserved provenance never records PASS");
Assert(
    store.TryComplete(
        provenanceGuard.DispatchId,
        "conn-prov",
        "corr-prov",
        "idem-prov",
        DispatchTerminalStatus.Pass,
        now.AddSeconds(2),
        "observed",
        new Dictionary<string, string> { ["ready"] = "true" },
        BridgeProtocol.BridgeRuntime,
        BridgeProtocol.BridgeRuntimeVersion,
        now.AddSeconds(1)),
    "observed provenance accepts client terminal");

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

void AssertThrows(Action action, string description)
{
    assertionCount++;
    try
    {
        action();
        throw new InvalidOperationException($"FAILED: {description} (expected exception)");
    }
    catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal))
    {
        throw;
    }
    catch (Exception)
    {
        // expected fail-closed rejection
    }
}

async Task AssertThrowsAsync<TException>(Func<Task> action, string description) where TException : Exception
{
    assertionCount++;
    try
    {
        await action().ConfigureAwait(false);
        throw new InvalidOperationException($"FAILED: {description} (expected {typeof(TException).Name})");
    }
    catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal))
    {
        throw;
    }
    catch (TException)
    {
        // expected fail-closed rejection
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

sealed class ThrowingBrowserAdapter : IBridgeBrowserAdapter
{
    public Task<BrowserHealth> GetHealthAsync(CancellationToken cancellationToken)
        => throw new InvalidOperationException("synthetic adapter fault");

    public Task<IReadOnlyList<BrowserTabMetadata>> ListTabsAsync(CancellationToken cancellationToken)
        => throw new InvalidOperationException("synthetic adapter fault");

    public Task<BrowserTabMetadata?> ReadTabMetadataAsync(string tabId, CancellationToken cancellationToken)
        => throw new InvalidOperationException("synthetic adapter fault");
}

sealed class FakeCodyncAdapter(CodyncWaitResult? configuredWait = null) : ICodyncBridgeAdapter
{
    public Task<CodyncHostHealth> GetHealthAsync(CancellationToken cancellationToken)
        => Task.FromResult(new CodyncHostHealth(true, "2.20.4", false));

    public Task<IReadOnlyList<CodyncDestination>> ListApprovedBotsGroupsAsync(CancellationToken cancellationToken)
        => Task.FromResult(CodyncApprovedDestinations.All);

    public Task<CodyncSendReceipt> SendExactAsync(string destinationId, string destinationName, string text, string clientNonce, IReadOnlyList<string> mentionedMemberIds, CancellationToken cancellationToken)
        => Task.FromResult(new CodyncSendReceipt(destinationId, destinationName, clientNonce, "d54b9631-2aa7-41e9-94af-0a15039abd43", 10, 3, 42, DateTimeOffset.UtcNow));

    public Task<CodyncWaitResult> WaitReadExactAsync(CodyncSendReceipt receipt, string expectedAuthorId, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult(configuredWait ?? new CodyncWaitResult(true, false,
            new CodyncCorrelatedReply(receipt.DestinationId, receipt.DestinationName, receipt.RootEntryId, expectedAuthorId,
                "PASS LDW644-SMOKE", 11, DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow, false),
            "reply", "Provider start and exact correlated final reply observed."));
}

sealed class FakeCodyncHttpHandler(bool malformedRoster = false, bool rosterOnly = false, string? failureMode = null) : HttpMessageHandler
{
    public const string RootEntryId = "d54b9631-2aa7-41e9-94af-0a15039abd43";
    private int _eventRequestCount;
    private string _nonce = string.Empty;
    private readonly string _botId = CodyncApprovedDestinations.All[0].Id;
    private bool _sendSeen;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Headers.Authorization?.Scheme != "Bearer" || request.Headers.Authorization.Parameter != "unit-test-bearer-never-return")
            return Json(HttpStatusCode.Unauthorized, "{}");
        if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath == "/health")
            return Json(HttpStatusCode.OK, "{\"ok\":true,\"version\":\"2.20.4\",\"busy\":false}");
        if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath == "/events")
        {
            _eventRequestCount++;
            if (malformedRoster && _eventRequestCount == 1)
                return Events("data: {not-json}\n\n");
            if (rosterOnly || _sendSeen || _eventRequestCount == 1)
            {
                var roster = CodyncApprovedDestinations.All.Select(item => new
                {
                    type = "bot",
                    bot = new
                    {
                        id = item.Id,
                        name = item.Name,
                        kind = item.Kind == "group" ? "group" : "agent",
                        members = item.Members
                    }
                });
                return Events(string.Join("\n", roster.Select(item => "data: " + JsonSerializer.Serialize(item))) + "\n\n");
            }
            if (_eventRequestCount == 2)
                return Events("data: {\"type\":\"hello\",\"rev\":42}\n\n");
            if (request.RequestUri.Query.Contains("since=42", StringComparison.Ordinal))
            {
                var startedAt = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds();
                var start = new { type = "bot", bot = new { id = _botId, workingChat = _botId, workingTurn = 3, startedAt, status = "working" } };
                if (failureMode == "stream_loss") return Events("data: " + JsonSerializer.Serialize(start) + "\n\n");
                var author = failureMode == "wrong_author" ? CodyncApprovedDestinations.All[1].Id : _botId;
                var sequence = failureMode == "wrong_sequence" ? 10 : 11;
                var turn = failureMode == "wrong_turn" ? 4 : 3;
                var final = new { type = "entry", entry = new { botId = _botId, id = Guid.NewGuid().ToString("D"), seq = sequence, turn, kind = "agent", data = new { final = true, author, text = "PASS LDW-CODYNC-FAKE" } } };
                return Events("data: " + JsonSerializer.Serialize(start) + "\n\ndata: " + JsonSerializer.Serialize(final) + "\n\n");
            }
        }
        if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath == "/api/send")
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            _nonce = document.RootElement.GetProperty("clientNonce").GetString()!;
            _sendSeen = true;
            var entry = new { entry = new { id = RootEntryId, botId = _botId, seq = 10, turn = 3, rev = 43, kind = "user", data = new { clientNonce = _nonce } } };
            return Json(HttpStatusCode.OK, JsonSerializer.Serialize(entry));
        }
        if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath == "/api/history")
        {
            var rootId = failureMode == "wrong_root" ? "00000000-0000-4000-8000-000000000001" : RootEntryId;
            var history = new { entries = new[] { new { id = rootId, botId = _botId, seq = 10, turn = 3, kind = "user", data = new { clientNonce = _nonce } } } };
            return Json(HttpStatusCode.OK, JsonSerializer.Serialize(history));
        }
        return Json(HttpStatusCode.NotFound, "{}");
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Events(string body)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/event-stream")
        };
}
