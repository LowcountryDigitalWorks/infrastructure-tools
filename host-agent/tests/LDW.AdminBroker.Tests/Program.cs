using System.Text.Json;
using LDW.AdminBroker;
using LDW.LocalSecretStore;

var assertions = 0;
var root = Path.Combine(Path.GetTempPath(), "LDW_AdminBroker_Tests_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var secretPath = Path.Combine(root, "secret.dat");
    var store = new LocalSecretStore(secretPath, new TestProtector());
    const string secret = "synthetic-value-only";
    Assert(store.SetSecret(LocalSecretStore.FixedSecretIdCorsairNeon, secret), "test protector stores synthetic value");
    var status = store.GetStatus(LocalSecretStore.FixedSecretIdCorsairNeon);
    Assert(status.Exists && status.LastUpdatedUtc.HasValue, "status exposes existence and update time");
    Assert(!status.ToString()!.Contains(secret), "status contains no plaintext");
    Assert(store.GetSecretValueInMemory(LocalSecretStore.FixedSecretIdCorsairNeon) == secret, "test protector round-trips value");
    try { store.GetStatus("other-secret"); throw new Exception("Expected fixed identity rejection"); }
    catch (ArgumentException) { Assert(true, "only fixed secret identity accepted"); }

    if (!OperatingSystem.IsWindows())
    {
        try { new SecretProtector().Protect([1]); throw new Exception("Expected platform rejection"); }
        catch (PlatformNotSupportedException) { Assert(true, "DPAPI protector fails closed off Windows"); }
    }

    var noParams = """{"version":1,"requestId":"11111111-1111-1111-1111-111111111111","operation":"CODYNC_BOT_CREATE","targetIdentity":"bot","parameters":{"name":"synthetic","description":"test","endpointUrl":"http://127.0.0.1/","capabilities":[]}}""";
    Assert(AdminBrokerContract.TryParseRequest(noParams, out var parsed) && parsed is not null, "UUID request parses");
    Assert(!AdminBrokerContract.TryParseRequest(noParams.Replace("11111111-1111-1111-1111-111111111111", "req-1"), out _), "non-UUID request id rejected");
    Assert(!AdminBrokerContract.TryParseRequest(noParams.Replace("\"capabilities\":[]", "\"capabilities\":[],\"unexpected\":1"), out _), "unknown operation parameter rejected");
    Assert(!AdminBrokerContract.TryParseRequest(noParams.Replace(",\"capabilities\":[]", string.Empty), out _), "missing operation parameter rejected");
    Assert(!AdminBrokerContract.TryParseRequest(new string('x', AdminBrokerContract.MaximumRequestCharacters + 1), out _), "oversize request rejected");
    var permitted = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    Assert(AdminBrokerAuthorizationPolicy.IsPermittedCaller(permitted, [permitted]), "explicit configured SID policy accepts caller");
    Assert(!AdminBrokerAuthorizationPolicy.IsPermittedCaller("S-1-5-21-1234567890-1234567890-1234567890-1002", [permitted]), "unconfigured caller rejected");

    var engine = new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler());
    var request = parsed!;
    var first = await engine.ProcessRequestAsync(request, "S-1-5-21-100", CancellationToken.None);
    var duplicate = await engine.ProcessRequestAsync(request, "S-1-5-21-100", CancellationToken.None);
    Assert(!first.Success && first.ErrorCode == "NOT_IMPLEMENTED", "Codync operation explicitly unavailable");
    Assert(duplicate.ErrorCode == "DUPLICATE_REQUEST", "duplicate UUID deterministic within replay TTL");
    Assert(AdminBrokerContract.CreateResponseJson(first).Length <= AdminBrokerContract.MaximumResponseCharacters, "response stays within contract bound");
    try { await engine.ProcessRequestAsync(request with { RequestId = "33333333-3333-3333-3333-333333333333" }, permitted, new CancellationToken(true)); throw new Exception("Expected cancellation"); }
    catch (OperationCanceledException) { Assert(true, "cancelled engine request stops before response"); }
    var host = request with { RequestId = "22222222-2222-2222-2222-222222222222", Operation = AdminBrokerContract.Operations.HostAgentRestartReviewedComponent };
    Assert((await engine.ProcessRequestAsync(host, "S-1-5-21-100", CancellationToken.None)).ErrorCode == "NOT_IMPLEMENTED", "Host Agent operation explicitly unavailable");

    var launcher = new CorsairNeonLauncher(store);
    Assert((await launcher.LaunchProofProcessAsync()).ErrorCode == "NOT_IMPLEMENTED", "launcher has no caller-controlled executable interface");
    var log = new AdminBrokerAuditLogger(Path.Combine(root, "audit.jsonl"));
    log.Log(new AuditRecord(DateTime.UtcNow, request.RequestId, request.Operation, request.TargetIdentity, "synthetic", false, "Unavailable", "NOT_IMPLEMENTED", "unavailable"));
    Assert(log.ReadRecords().Count == 1, "bounded synthetic audit record persists");
    Assert(log.ReadRecords()[0].TargetIdentity == "redacted" && log.ReadRecords()[0].Summary == "Operation audit record.", "audit omits free-form target and summary");
    var directoryPath = Path.Combine(root, "audit-is-directory"); Directory.CreateDirectory(directoryPath);
    try { new AdminBrokerAuditLogger(directoryPath).Log(new AuditRecord(DateTime.UtcNow, request.RequestId, request.Operation, request.TargetIdentity, null, false, "Unavailable", null, "x")); throw new Exception("Expected audit persistence error"); }
    catch (UnauthorizedAccessException) { Assert(true, "audit persistence failure propagates"); }
    var fakePipeServer = new AdminBrokerPipeServer(["S-1-5-21-100"], engine, log);
    try { await fakePipeServer.ServeOneAsync(new System.IO.Pipes.NamedPipeServerStream("synthetic"), CancellationToken.None); throw new Exception("Expected unavailable transport"); }
    catch (NotSupportedException) { Assert(true, "named-pipe transport is unavailable"); }
    Console.WriteLine($"Admin Broker tests passed ({assertions} assertions).");
}
finally { Directory.Delete(root, true); }

void Assert(bool condition, string message) { assertions++; if (!condition) throw new InvalidOperationException(message); }

sealed class TestProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null) => plaintext.ToArray();
    public byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null) => encryptedData.ToArray();
}
