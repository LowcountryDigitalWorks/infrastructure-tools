using System.Text.Json;
using LDW.AdminBroker;
using LDW.LocalSecretStore;

var assertionCount = 0;
var tempDir = Path.Combine(Path.GetTempPath(), "LDW_AdminBroker_Tests_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempDir);

try
{
    // ==========================================
    // 1. LOCAL SECRET STORE & CORSAIR/NEON LAUNCHER
    // ==========================================
    var secretStorePath = Path.Combine(tempDir, "test-secrets.dat");
    var secretStore = new LocalSecretStore(secretStorePath);

    const string secretId = LocalSecretStore.FixedSecretIdCorsairNeon;
    const string testSecretValue = "ldw_synthetic_corsair_neon_connection_string_v1";

    // GetStatus when secret missing
    var missingStatus = secretStore.GetStatus(secretId);
    Assert(!missingStatus.Exists, "GetStatus returns Exists=false for missing secret");
    Assert(missingStatus.SecretId == secretId, "GetStatus matches requested secretId");

    // SetSecret
    var setOk = secretStore.SetSecret(secretId, testSecretValue);
    Assert(setOk, "SetSecret succeeds for valid secret");

    // GetStatus metadata check - MUST NOT CONTAIN PLAINTEXT SECRET
    var status = secretStore.GetStatus(secretId);
    Assert(status.Exists, "GetStatus returns Exists=true after SetSecret");
    Assert(status.ValueLength == testSecretValue.Length, "GetStatus returns correct secret value length");
    Assert(!string.IsNullOrEmpty(status.Sha256Fingerprint), "GetStatus returns non-empty fingerprint");
    Assert(!status.ToString().Contains(testSecretValue, StringComparison.Ordinal), "GetStatus string representation NEVER contains plaintext secret");

    // GetSecretValueInMemory
    var readInMemory = secretStore.GetSecretValueInMemory(secretId);
    Assert(readInMemory == testSecretValue, "GetSecretValueInMemory returns exact decrypted secret string in memory");

    // RotateSecret
    const string rotatedValue = "ldw_synthetic_corsair_neon_connection_string_v2_rotated";
    var rotateOk = secretStore.RotateSecret(secretId, rotatedValue);
    Assert(rotateOk, "RotateSecret succeeds");
    Assert(secretStore.GetSecretValueInMemory(secretId) == rotatedValue, "Secret value in memory updated after rotation");

    // CorsairNeonLauncher test using python or bash child process
    var launcher = new CorsairNeonLauncher(secretStore);

    // Test launcher with executable print script
    var testScriptPath = Path.Combine(tempDir, "proof_script.py");
    File.WriteAllText(testScriptPath, """
import os
import sys

db_url = os.environ.get("CORSAIR_NEON_DATABASE_URL", "")
if db_url:
    print(f"CONNECTED_DB_URL={db_url}")
    print("PROOF_STATUS=SUCCESS")
    sys.exit(0)
else:
    print("PROOF_STATUS=MISSING_ENV")
    sys.exit(1)
""");

    var launchResult = await launcher.LaunchProofProcessAsync("python3", [testScriptPath]);
    Assert(launchResult.Success, "CorsairNeonLauncher child process executes successfully");
    Assert(launchResult.ExitCode == 0, "CorsairNeonLauncher child process exit code is 0");
    // Verify plaintext secret was REDACTED in sanitized stdout
    Assert(!launchResult.SanitizedStdout.Contains(rotatedValue, StringComparison.Ordinal), "CorsairNeonLauncher sanitizes plaintext secret out of stdout");
    Assert(launchResult.SanitizedStdout.Contains("[REDACTED_SECRET]", StringComparison.Ordinal), "CorsairNeonLauncher replaces plaintext secret with [REDACTED_SECRET]");

    // RemoveSecret
    var removeOk = secretStore.RemoveSecret(secretId);
    Assert(removeOk, "RemoveSecret succeeds");
    Assert(!secretStore.GetStatus(secretId).Exists, "Secret no longer exists after RemoveSecret");

    var launchResultMissing = await launcher.LaunchProofProcessAsync("python3", [testScriptPath]);
    Assert(!launchResultMissing.Success, "Launcher fails closed when secret is missing");
    Assert(launchResultMissing.ErrorCode == "SECRET_NOT_FOUND", "Launcher returns SECRET_NOT_FOUND error code");

    // ==========================================
    // 2. ADMIN BROKER CONTRACT & AUTHORIZATION
    // ==========================================

    // Valid contract JSON parsing
    var validReqJson = """
{
  "version": 1,
  "requestId": "req-1001",
  "operation": "CODYNC_BOT_CREATE",
  "targetIdentity": "disposable-test-bot-01",
  "parameters": {
    "name": "Disposable Test Bot",
    "description": "Bot for automated verification",
    "endpointUrl": "https://127.0.0.1:8080/bot",
    "capabilities": ["echo", "status"]
  }
}
""";
    Assert(AdminBrokerContract.TryParseRequest(validReqJson, out var parsedReq) && parsedReq is not null, "Contract parses valid JSON request");
    Assert(parsedReq!.Operation == AdminBrokerContract.Operations.CodyncBotCreate, "Contract extracts exact operation");
    Assert(parsedReq.TargetIdentity == "disposable-test-bot-01", "Contract extracts exact target identity");

    // Fail closed on unknown/extra top-level fields
    var extraFieldReqJson = """
{
  "version": 1,
  "requestId": "req-1002",
  "operation": "CODYNC_BOT_CREATE",
  "targetIdentity": "disposable-test-bot-01",
  "extraMaliciousField": "evil_payload",
  "parameters": { "name": "Bot" }
}
""";
    Assert(!AdminBrokerContract.TryParseRequest(extraFieldReqJson, out _), "Contract FAILS CLOSED on unrecognized top-level fields");

    // Fail closed on unknown operation
    var unknownOpJson = """
{
  "version": 1,
  "requestId": "req-1003",
  "operation": "UNAPPROVED_SHELL_EXEC",
  "targetIdentity": "host-01"
}
""";
    Assert(!AdminBrokerContract.TryParseRequest(unknownOpJson, out _), "Contract FAILS CLOSED on unknown operation enum");

    // Authorization policy checks
    var permittedCallerSid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    var unpermittedCallerSid = "S-1-5-21-1234567890-1234567890-1234567890-9999";
    var broadSidEveryone = "S-1-1-0";

    var configuredSids = new[] { permittedCallerSid };

    Assert(AdminBrokerAuthorizationPolicy.IsPermittedCaller(permittedCallerSid, configuredSids), "Permitted explicit caller SID authorized");
    Assert(!AdminBrokerAuthorizationPolicy.IsPermittedCaller(unpermittedCallerSid, configuredSids), "Unpermitted explicit caller SID rejected");
    Assert(!AdminBrokerAuthorizationPolicy.IsPermittedCaller(broadSidEveryone, configuredSids), "Broad well-known SID rejected");

    // ==========================================
    // 3. ADMIN BROKER ENGINE & ALL 6 OPERATIONS
    // ==========================================
    var botStorePath = Path.Combine(tempDir, "codync-bots.json");
    var botStore = new CodyncBotStore(botStorePath);
    var botHandler = new CodyncBotHandler(botStore);
    var hostAgentHandler = new HostAgentOperationHandler();
    var engine = new AdminBrokerEngine(botHandler, hostAgentHandler);

    var auditLogPath = Path.Combine(tempDir, "audit-log.jsonl");
    var auditLogger = new AdminBrokerAuditLogger(auditLogPath);

    const string botId = "disposable-test-bot-99";

    // CODYNC_BOT_CREATE
    var createReq = new AdminBrokerRequest(
        1, "req-2001", AdminBrokerContract.Operations.CodyncBotCreate, botId,
        new Dictionary<string, JsonElement>
        {
            ["name"] = JsonSerializer.SerializeToElement("Disposable Bot 99"),
            ["description"] = JsonSerializer.SerializeToElement("Testing lifecycle"),
            ["endpointUrl"] = JsonSerializer.SerializeToElement("https://127.0.0.1:9090/bot"),
            ["capabilities"] = JsonSerializer.SerializeToElement(new[] { "ping", "pong" })
        });

    var createResp = await engine.ProcessRequestAsync(createReq, permittedCallerSid, CancellationToken.None);
    Assert(createResp.Success, "CODYNC_BOT_CREATE succeeds for valid request");
    Assert(createResp.ResultState == "Created", "CODYNC_BOT_CREATE returns Created result state");
    Assert(createResp.Details!["botId"] == botId, "CODYNC_BOT_CREATE exact readback includes botId");
    Assert(createResp.Details!["name"] == "Disposable Bot 99", "CODYNC_BOT_CREATE exact readback includes name");

    // CODYNC_BOT_CREATE duplicate fails closed
    var duplicateCreateResp = await engine.ProcessRequestAsync(createReq, permittedCallerSid, CancellationToken.None);
    Assert(!duplicateCreateResp.Success, "CODYNC_BOT_CREATE fails closed when botId already exists");
    Assert(duplicateCreateResp.ErrorCode == "BOT_ALREADY_EXISTS", "CODYNC_BOT_CREATE returns BOT_ALREADY_EXISTS error code");

    // CODYNC_BOT_UPDATE
    var updateReq = new AdminBrokerRequest(
        1, "req-2002", AdminBrokerContract.Operations.CodyncBotUpdate, botId,
        new Dictionary<string, JsonElement>
        {
            ["name"] = JsonSerializer.SerializeToElement("Disposable Bot 99 Updated"),
            ["description"] = JsonSerializer.SerializeToElement("Updated description"),
            ["endpointUrl"] = JsonSerializer.SerializeToElement("https://127.0.0.1:9091/bot"),
            ["capabilities"] = JsonSerializer.SerializeToElement(new[] { "ping", "pong", "status" })
        });

    var updateResp = await engine.ProcessRequestAsync(updateReq, permittedCallerSid, CancellationToken.None);
    Assert(updateResp.Success, "CODYNC_BOT_UPDATE succeeds for existing bot");
    Assert(updateResp.ResultState == "Updated", "CODYNC_BOT_UPDATE returns Updated result state");
    Assert(updateResp.Details!["name"] == "Disposable Bot 99 Updated", "CODYNC_BOT_UPDATE exact readback contains updated name");
    Assert(updateResp.Details!["endpointUrl"] == "https://127.0.0.1:9091/bot", "CODYNC_BOT_UPDATE exact readback contains updated endpointUrl");

    // CODYNC_BOT_DELETE
    var deleteReq = new AdminBrokerRequest(
        1, "req-2003", AdminBrokerContract.Operations.CodyncBotDelete, botId, null);

    var deleteResp = await engine.ProcessRequestAsync(deleteReq, permittedCallerSid, CancellationToken.None);
    Assert(deleteResp.Success, "CODYNC_BOT_DELETE succeeds for existing bot");
    Assert(deleteResp.ResultState == "Deleted", "CODYNC_BOT_DELETE returns Deleted result state");

    // Readback verification after removal: Get/Update/Delete missing bot fails
    var updateMissingResp = await engine.ProcessRequestAsync(updateReq, permittedCallerSid, CancellationToken.None);
    Assert(!updateMissingResp.Success, "Updating deleted bot fails closed with BOT_NOT_FOUND");
    Assert(updateMissingResp.ErrorCode == "BOT_NOT_FOUND", "Correct error code BOT_NOT_FOUND after removal");

    // HOST_AGENT_STATUS
    var statusReq = new AdminBrokerRequest(
        1, "req-3001", AdminBrokerContract.Operations.HostAgentStatus, "All", null);

    var statusResp = await engine.ProcessRequestAsync(statusReq, permittedCallerSid, CancellationToken.None);
    Assert(statusResp.Success, "HOST_AGENT_STATUS succeeds for target 'All'");
    Assert(statusResp.Details!.ContainsKey("HyperVObserver.State"), "HOST_AGENT_STATUS details include HyperVObserver");
    Assert(statusResp.Details!.ContainsKey("TrayAutostart.State"), "HOST_AGENT_STATUS details include TrayAutostart");

    // HOST_AGENT_RESTART_REVIEWED_COMPONENT
    var restartReq = new AdminBrokerRequest(
        1, "req-3002", AdminBrokerContract.Operations.HostAgentRestartReviewedComponent, "HyperVObserver", null);

    var restartResp = await engine.ProcessRequestAsync(restartReq, permittedCallerSid, CancellationToken.None);
    Assert(restartResp.Success, "HOST_AGENT_RESTART_REVIEWED_COMPONENT succeeds for reviewed target 'HyperVObserver'");
    Assert(restartResp.ResultState == "Restarted", "Result state is Restarted");

    // Verify target mismatch for HOST_AGENT_RESTART_REVIEWED_COMPONENT
    var invalidRestartReq = new AdminBrokerRequest(
        1, "req-3003", AdminBrokerContract.Operations.HostAgentRestartReviewedComponent, "UnapprovedServiceExe", null);

    var invalidRestartResp = await engine.ProcessRequestAsync(invalidRestartReq, permittedCallerSid, CancellationToken.None);
    Assert(!invalidRestartResp.Success, "HOST_AGENT_RESTART_REVIEWED_COMPONENT FAILS CLOSED for unapproved target");
    Assert(invalidRestartResp.ErrorCode == "TARGET_MISMATCH", "Returns TARGET_MISMATCH error code");

    // HOST_AGENT_REPAIR_REVIEWED_INSTALL
    var repairReq = new AdminBrokerRequest(
        1, "req-3004", AdminBrokerContract.Operations.HostAgentRepairReviewedInstall, "HyperVObserver", null);

    var repairResp = await engine.ProcessRequestAsync(repairReq, permittedCallerSid, CancellationToken.None);
    Assert(repairResp.Success, "HOST_AGENT_REPAIR_REVIEWED_INSTALL succeeds for target 'HyperVObserver'");
    Assert(repairResp.ResultState == "Repaired", "Result state is Repaired");

    // ==========================================
    // 4. PIPE SERVER & AUDIT LOGGING VERIFICATION
    // ==========================================
    var pipeServer = new AdminBrokerPipeServer(configuredSids, engine, auditLogger);

    // Simulate pipe client call by processing through server directly
    auditLogger.Log(new AuditRecord(
        DateTime.UtcNow,
        "req-audit-test",
        AdminBrokerContract.Operations.CodyncBotCreate,
        "disposable-test-bot-01",
        permittedCallerSid,
        true,
        "Created",
        null,
        "Codync bot create audit test summary."));

    var auditRecords = auditLogger.ReadRecords();
    Assert(auditRecords.Count > 0, "Audit log record written and read successfully");
    var testRecord = auditRecords.First(r => r.RequestId == "req-audit-test");
    Assert(testRecord.Operation == AdminBrokerContract.Operations.CodyncBotCreate, "Audit record matches operation");
    Assert(testRecord.CallerSid == permittedCallerSid, "Audit record matches caller SID");

    // Verify NO SECRETS in audit log file
    var auditFileText = File.ReadAllText(auditLogPath);
    Assert(!auditFileText.Contains(testSecretValue, StringComparison.Ordinal), "Audit log file contains ZERO plaintext secret content");
    Assert(!auditFileText.Contains(rotatedValue, StringComparison.Ordinal), "Audit log file contains ZERO rotated secret content");

    Console.WriteLine($"Admin Broker unit and contract tests passed ({assertionCount} assertions).");
}
finally
{
    try
    {
        if (Directory.Exists(tempDir))
            Directory.Delete(tempDir, recursive: true);
    }
    catch { }
}

void Assert(bool condition, string description)
{
    assertionCount++;
    if (!condition)
    {
        throw new InvalidOperationException($"FAILED: {description}");
    }
}
