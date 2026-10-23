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
    foreach (var invalidStoreJson in new[] { "{invalid", "{\"Version\":99,\"Secrets\":{}}" })
    {
        var invalidPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".dat");
        File.WriteAllText(invalidPath, invalidStoreJson);
        var invalidStore = new LocalSecretStore(invalidPath, new TestProtector());
        foreach (var mutate in new Action[]
        {
            () => invalidStore.SetSecret(LocalSecretStore.FixedSecretIdCorsairNeon, "replacement"),
            () => invalidStore.RotateSecret(LocalSecretStore.FixedSecretIdCorsairNeon, "replacement"),
            () => invalidStore.RemoveSecret(LocalSecretStore.FixedSecretIdCorsairNeon)
        })
        {
            try { mutate(); throw new Exception("Expected invalid store failure"); }
            catch (SecretStoreFileException ex)
            {
                Assert(ex.Message == "The existing secret store file is unreadable or invalid.", "invalid store errors are deterministic and redacted");
                Assert(File.ReadAllText(invalidPath) == invalidStoreJson, "invalid store is not overwritten");
            }
        }
    }
    var validTimestamp = new DateTime(2026, 10, 22, 12, 0, 0, DateTimeKind.Utc);
    var validPayloadJson = JsonSerializer.Serialize(new SecretEntryPayload(
        LocalSecretStore.FixedSecretIdCorsairNeon,
        validTimestamp,
        "AQ=="));
    var validStoreJson = JsonSerializer.Serialize(new SecretStoreFileContent(
        LocalSecretStore.Version,
        new Dictionary<string, SecretEntryPayload>
        {
            [LocalSecretStore.FixedSecretIdCorsairNeon] = new(
                LocalSecretStore.FixedSecretIdCorsairNeon,
                validTimestamp,
                "AQ==")
        }));
    var corruptStoreFixtures = new Dictionary<string, string>
    {
        ["duplicate Version property"] = "{\"Version\":1,\"Version\":1,\"Secrets\":{}}",
        ["duplicate fixed secret dictionary key"] = "{\"Version\":1,\"Secrets\":{" +
            JsonSerializer.Serialize(LocalSecretStore.FixedSecretIdCorsairNeon) + ":" + validPayloadJson + "," +
            JsonSerializer.Serialize(LocalSecretStore.FixedSecretIdCorsairNeon) + ":" + validPayloadJson + "}}",
        ["unknown top-level property"] = validStoreJson[..^1] + ",\"Unexpected\":true}",
        ["unknown SecretEntryPayload property"] = "{\"Version\":1,\"Secrets\":{" +
            JsonSerializer.Serialize(LocalSecretStore.FixedSecretIdCorsairNeon) + ":" +
            validPayloadJson[..^1] + ",\"Unexpected\":true}}",
        ["dictionary key differs from payload ID"] = CreateStoreJson("OTHER_SECRET_ID", new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, validTimestamp, "AQ==")),
        ["unsupported payload ID"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload("OTHER_SECRET_ID", validTimestamp, "AQ==")),
        ["empty ciphertext"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, validTimestamp, string.Empty)),
        ["invalid Base64"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, validTimestamp, "not-base64!")),
        ["empty decoded ciphertext"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, validTimestamp, " \r\n ")),
        ["default timestamp"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, default, "AQ==")),
        ["unspecified timestamp"] = CreateStoreJson(LocalSecretStore.FixedSecretIdCorsairNeon, new SecretEntryPayload(LocalSecretStore.FixedSecretIdCorsairNeon, DateTime.SpecifyKind(validTimestamp, DateTimeKind.Unspecified), "AQ=="))
    };
    foreach (var (caseName, corruptStoreJson) in corruptStoreFixtures)
    {
        var corruptPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".dat");
        var originalBytes = System.Text.Encoding.UTF8.GetBytes(corruptStoreJson);
        File.WriteAllBytes(corruptPath, originalBytes);
        var corruptStore = new LocalSecretStore(corruptPath, new TestProtector());
        foreach (var (operation, mutate) in new (string Name, Action Run)[]
        {
            ("SetSecret", () => corruptStore.SetSecret(LocalSecretStore.FixedSecretIdCorsairNeon, "replacement")),
            ("RotateSecret", () => corruptStore.RotateSecret(LocalSecretStore.FixedSecretIdCorsairNeon, "replacement")),
            ("RemoveSecret", () => corruptStore.RemoveSecret(LocalSecretStore.FixedSecretIdCorsairNeon))
        })
        {
            try { mutate(); throw new Exception("Expected corrupt store failure: " + caseName + " / " + operation); }
            catch (SecretStoreFileException ex)
            {
                Assert(ex.Message == "The existing secret store file is unreadable or invalid.", caseName + " / " + operation + " error is redacted");
                Assert(File.ReadAllBytes(corruptPath).SequenceEqual(originalBytes), caseName + " / " + operation + " preserves exact file bytes");
            }
        }
        foreach (var read in new Action[]
        {
            () => corruptStore.GetStatus(LocalSecretStore.FixedSecretIdCorsairNeon),
            () => corruptStore.GetSecretValueInMemory(LocalSecretStore.FixedSecretIdCorsairNeon)
        })
        {
            try { read(); throw new Exception("Expected corrupt store read failure: " + caseName); }
            catch (SecretStoreFileException ex)
            {
                Assert(ex.Message == "The existing secret store file is unreadable or invalid.", caseName + " read error is redacted");
                Assert(File.ReadAllBytes(corruptPath).SequenceEqual(originalBytes), caseName + " read preserves exact file bytes");
            }
        }
    }
    var readFailurePath = Path.Combine(root, "read-failure");
    Directory.CreateDirectory(readFailurePath);
    var readFailureStore = new LocalSecretStore(readFailurePath, new TestProtector());
    try { readFailureStore.SetSecret(LocalSecretStore.FixedSecretIdCorsairNeon, "replacement"); throw new Exception("Expected read failure"); }
    catch (SecretStoreFileException ex) { Assert(ex.Message == "The existing secret store file is unreadable or invalid.", "read failure does not expose path or content"); }
    try { store.GetStatus("other-secret"); throw new Exception("Expected fixed identity rejection"); }
    catch (ArgumentException) { Assert(true, "only fixed secret identity accepted"); }

    if (!OperatingSystem.IsWindows())
    {
        try { new SecretProtector().Protect([1]); throw new Exception("Expected platform rejection"); }
        catch (PlatformNotSupportedException) { Assert(true, "DPAPI protector fails closed off Windows"); }
    }

    var noParams = """{"version":1,"requestId":"11111111-1111-1111-1111-111111111111","operation":"CODYNC_BOT_CREATE","targetIdentity":"bot","parameters":{"name":"synthetic","description":"test","endpointUrl":"http://127.0.0.1/","capabilities":[]}}""";
    Assert(AdminBrokerContract.TryParseRequest(noParams, out var parsed) && parsed is not null, "UUID request parses");
    foreach (var property in new[] { "requestId", "operation", "targetIdentity", "parameters" })
    {
        var duplicateRequest = noParams.Insert(1, "\"" + property + "\":null,");
        Assert(!AdminBrokerContract.TryParseRequest(duplicateRequest, out _), "duplicate top-level " + property + " rejected");
    }
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
    Assert(log.ReadRecords()[0].ResultState == "Unavailable" && log.ReadRecords()[0].ErrorCode == "NOT_IMPLEMENTED", "audit preserves fixed result metadata");
    const string auditCanary = "AUDIT-CANARY-secret-token-connection-string";
    foreach (var unsafeRecord in new[]
    {
        new AuditRecord(DateTime.UtcNow, request.RequestId, request.Operation, request.TargetIdentity, "synthetic", false, auditCanary, "NOT_IMPLEMENTED", "unavailable"),
        new AuditRecord(DateTime.UtcNow, request.RequestId, request.Operation, request.TargetIdentity, "synthetic", false, "Unavailable", auditCanary, "unavailable")
    })
    {
        try { log.Log(unsafeRecord); throw new Exception("Expected unsafe audit metadata rejection"); }
        catch (InvalidOperationException ex) { Assert(ex.Message == "Audit record contains unsupported fields.", "unsafe audit metadata rejection is fixed and redacted"); }
    }
    var auditText = File.ReadAllText(Path.Combine(root, "audit.jsonl"));
    Assert(!auditText.Contains(auditCanary, StringComparison.Ordinal), "canary supplied through ResultState or ErrorCode is never persisted");
    Assert(log.ReadRecords().Count == 1, "rejected audit metadata leaves existing records unchanged");
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

string CreateStoreJson(string key, SecretEntryPayload payload) =>
    JsonSerializer.Serialize(new SecretStoreFileContent(LocalSecretStore.Version, new Dictionary<string, SecretEntryPayload> { [key] = payload }));

sealed class TestProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null) => plaintext.ToArray();
    public byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null) => encryptedData.ToArray();
}
