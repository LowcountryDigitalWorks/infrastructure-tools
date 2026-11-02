using System.Runtime.CompilerServices;
using System.Text.Json;
using LDW.AdminBroker;

internal static class LocalAdminPrivilegedControlAdapterRegressionTests
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        Run();
    }

    private static void Run()
    {
        var assertions = 0;
        void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("Privileged adapter regression assertion failed: " + message);
            assertions++;
        }

        var boundary = new RecordingBoundary();
        var adapter = new LocalAdminPrivilegedControlAdapter(boundary);

        // 1. Unknown operation fails closed before boundary invocation
        var correlationId = Guid.NewGuid();
        var unknownResult = adapter.RunReviewedOperation("UNKNOWN_OP", correlationId, CancellationToken.None);
        Assert(!unknownResult.Success && unknownResult.ReasonCode == "UNKNOWN_OPERATION", "unknown operation returns UNKNOWN_OPERATION");
        Assert(boundary.QueueCalls.Count == 0, "unknown operation never reaches boundary");

        // 2. Allowlisted proof operation reaches boundary
        var proofResult = adapter.RunReviewedOperation(AdminReviewedOperationRegistry.ElevatedIdentityProof, correlationId, CancellationToken.None);
        Assert(proofResult.Success && proofResult.ResultState == "QUEUED", "proof operation queues at boundary");
        Assert(boundary.QueueCalls.Count == 1, "proof operation reaches boundary once");
        Assert(boundary.QueueCalls[0].OperationId == AdminReviewedOperationRegistry.ElevatedIdentityProof, "operationId preserved");
        Assert(boundary.QueueCalls[0].CorrelationId == correlationId, "correlationId preserved");

        // 3. GetResult passes correlationId to boundary
        var queryCorrelationId = Guid.NewGuid();
        var getResult = adapter.GetOperationResult(queryCorrelationId, CancellationToken.None);
        Assert(getResult.Success && getResult.ResultState == "PASS", "GetOperationResult delegates to boundary");
        Assert(boundary.GetResultCalls.Count == 1 && boundary.GetResultCalls[0] == queryCorrelationId, "correlationId forwarded");

        // 4. Handler integration
        var handler = new AdminPrivilegedOperationHandler(adapter);

        // 4a. Run request via handler
        var runReq = new AdminBrokerRequest(
            AdminBrokerContract.Version,
            correlationId.ToString("D"),
            AdminBrokerContract.Operations.AdminReviewedOperationRun,
            AdminPrivilegedControlContract.TargetIdentity,
            new Dictionary<string, JsonElement>
            {
                ["operationId"] = JsonElement("ELEVATED_IDENTITY_PROOF")
            });
        var runResponse = handler.Process(runReq, CancellationToken.None);
        Assert(runResponse.Success && runResponse.ResultState == "QUEUED", "handler dispatches RUN");
        Assert(runResponse.RequestId == correlationId.ToString("D"), "response requestId correlates");

        // 4b. GetResult request via handler
        var getReq = new AdminBrokerRequest(
            AdminBrokerContract.Version,
            Guid.NewGuid().ToString("D"),
            AdminBrokerContract.Operations.AdminReviewedOperationGetResult,
            AdminPrivilegedControlContract.TargetIdentity,
            new Dictionary<string, JsonElement>
            {
                ["correlationId"] = JsonElement(correlationId.ToString("D"))
            });
        var getResponse = handler.Process(getReq, CancellationToken.None);
        Assert(getResponse.Success && getResponse.ResultState == "PASS", "handler dispatches GET_RESULT");

        // 4c. Policy rejection via handler (e.g. unreviewed operation)
        var invalidReq = runReq with
        {
            Parameters = new Dictionary<string, JsonElement>
            {
                ["operationId"] = JsonElement("UNREVIEWED_OP")
            }
        };
        var invalidResponse = handler.Process(invalidReq, CancellationToken.None);
        Assert(!invalidResponse.Success && invalidResponse.ErrorCode == "POLICY_REJECTED", "handler rejects policy violation");

        // 4d. Target mismatch via handler
        var targetMismatchReq = runReq with { TargetIdentity = "wrong-target" };
        var targetMismatchResponse = handler.Process(targetMismatchReq, CancellationToken.None);
        Assert(!targetMismatchResponse.Success && targetMismatchResponse.ErrorCode == "TARGET_REFUSED", "handler rejects target mismatch");

        // 5. Engine integration: duplicate request rejection
        var botHandler = new CodyncBotHandler();
        var hostAgentHandler = new HostAgentOperationHandler();
        var engine = new AdminBrokerEngine(botHandler, hostAgentHandler, handler);

        var firstEngineResult = engine.ProcessRequestAsync(runReq, "S-1-5-21-1", CancellationToken.None).GetAwaiter().GetResult();
        Assert(firstEngineResult.Success, "engine accepts initial request");

        var duplicateEngineResult = engine.ProcessRequestAsync(runReq, "S-1-5-21-1", CancellationToken.None).GetAwaiter().GetResult();
        Assert(!duplicateEngineResult.Success && duplicateEngineResult.ErrorCode == "DUPLICATE_REQUEST", "engine rejects duplicate request ID");

        // 6. Real adapter durable replay rejection on duplicate correlationId
        var tempRoot = Path.Combine(Path.GetTempPath(), "LDW_AdapterTest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var reqDir = Path.Combine(tempRoot, "requests");
            var resDir = Path.Combine(tempRoot, "results");
            Directory.CreateDirectory(reqDir);
            Directory.CreateDirectory(resDir);

            var existingCorrId = Guid.NewGuid();
            var existingResultFile = Path.Combine(resDir, existingCorrId.ToString("D") + ".json");
            File.WriteAllText(existingResultFile, "{\"schema\":1,\"correlationId\":\"" + existingCorrId.ToString("D") + "\",\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"success\":true,\"resultState\":\"PASS\",\"reasonCode\":\"NONE\"}");

            var realAdapter = new LocalAdminPrivilegedControlAdapter(
                new ScheduledTaskAdminPrivilegedOperationBoundary(
                    rootOverride: tempRoot,
                    startTaskOverride: (_, _) => true,
                    skipAclCheckForTesting: true));

            var duplicateRunResult = realAdapter.RunReviewedOperation("ELEVATED_IDENTITY_PROOF", existingCorrId, CancellationToken.None);
            Assert(!duplicateRunResult.Success && duplicateRunResult.ReasonCode == "DUPLICATE_REQUEST",
                "durable replay: duplicate correlationId rejected with DUPLICATE_REQUEST");

            // 7. In-flight STARTED state handling and timeout reconciliation
            var inFlightCorrId = Guid.NewGuid();
            var inFlightResultFile = Path.Combine(resDir, inFlightCorrId.ToString("D") + ".json");
            File.WriteAllText(inFlightResultFile, "{\"schema\":1,\"correlationId\":\"" + inFlightCorrId.ToString("D") + "\",\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"success\":true,\"resultState\":\"STARTED\",\"reasonCode\":\"NONE\"}");

            // Recent in-flight result returns STARTED
            var inFlightCheck = realAdapter.GetOperationResult(inFlightCorrId, CancellationToken.None);
            Assert(inFlightCheck.Success && inFlightCheck.ResultState == "STARTED",
                "active in-flight result returns STARTED");

            // Timed-out in-flight result returns FAILED/TIMEOUT
            File.SetLastWriteTimeUtc(inFlightResultFile, DateTime.UtcNow.AddMinutes(-20));
            var timedOutCheck = realAdapter.GetOperationResult(inFlightCorrId, CancellationToken.None);
            Assert(!timedOutCheck.Success && timedOutCheck.ResultState == "FAILED" && timedOutCheck.ReasonCode == "TIMEOUT",
                "expired in-flight result returns FAILED / TIMEOUT");

            // 8. Stale request in request.json without result triggers reconciliation and returns TIMEOUT
            var staleCorrId = Guid.NewGuid();
            var staleReqFile = Path.Combine(reqDir, "request.json");
            File.WriteAllText(staleReqFile, "{\"schema\":1,\"correlationId\":\"" + staleCorrId.ToString("D") + "\",\"operationId\":\"ELEVATED_IDENTITY_PROOF\"}");
            File.SetLastWriteTimeUtc(staleReqFile, DateTime.UtcNow.AddMinutes(-20));

            var staleGetResult = realAdapter.GetOperationResult(staleCorrId, CancellationToken.None);
            Assert(!staleGetResult.Success && staleGetResult.ResultState == "FAILED" && staleGetResult.ReasonCode == "TIMEOUT",
                "expired request in slot returns FAILED / TIMEOUT on query");

            // Queueing when slot occupied returns BUSY and demand-starts task for reconciliation
            var freshCorrId = Guid.NewGuid();
            var busyRunResult = realAdapter.RunReviewedOperation("ELEVATED_IDENTITY_PROOF", freshCorrId, CancellationToken.None);
            Assert(!busyRunResult.Success && busyRunResult.ReasonCode == "BUSY",
                "queueing while slot occupied returns BUSY");

            // 9. Operational ACL drift rejection (tempRoot is non-admin/SYSTEM owned in user profile, so skipAclCheck=false fails closed)
            var failingAclAdapter = new LocalAdminPrivilegedControlAdapter(
                new ScheduledTaskAdminPrivilegedOperationBoundary(
                    rootOverride: tempRoot,
                    startTaskOverride: (_, _) => true,
                    skipAclCheckForTesting: false));

            var aclFailedResult = failingAclAdapter.RunReviewedOperation("ELEVATED_IDENTITY_PROOF", Guid.NewGuid(), CancellationToken.None);
            Assert(!aclFailedResult.Success && aclFailedResult.ReasonCode == "PROVENANCE_MISMATCH",
                "ACL drift rejected with PROVENANCE_MISMATCH");
        }
        finally
        {
            if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, true);
        }

        // 10. Production Host composition regression:
        // Proves AdminBrokerEngine configured as in Program.cs routes reviewed-admin operations
        // to LocalAdminPrivilegedControlAdapter rather than defaulting to ADAPTER_UNAVAILABLE.
        var hostEngine = new AdminBrokerEngine(
            new CodyncBotHandler(),
            new HostAgentOperationHandler(new LocalCiJitControlAdapter()),
            new AdminPrivilegedOperationHandler(new LocalAdminPrivilegedControlAdapter(boundary)));

        var hostRunReq = new AdminBrokerRequest(
            AdminBrokerContract.Version,
            Guid.NewGuid().ToString("D"),
            AdminBrokerContract.Operations.AdminReviewedOperationRun,
            AdminPrivilegedControlContract.TargetIdentity,
            new Dictionary<string, JsonElement>
            {
                ["operationId"] = JsonElement("ELEVATED_IDENTITY_PROOF")
            });
        var hostRunResult = hostEngine.ProcessRequestAsync(hostRunReq, "S-1-5-21-1", CancellationToken.None).GetAwaiter().GetResult();
        Assert(hostRunResult.Success && hostRunResult.ResultState == "QUEUED",
            "production Host composition routes ADMIN_REVIEWED_OPERATION_RUN to QUEUED");
        Assert(hostRunResult.ErrorCode != "ADAPTER_UNAVAILABLE",
            "production Host composition does not fall back to ADAPTER_UNAVAILABLE");

        Console.WriteLine($"Privileged adapter regression tests: {assertions} assertions passed.");
    }

    private static JsonElement JsonElement(string value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value)).RootElement.Clone();

    private sealed class RecordingBoundary : IAdminPrivilegedOperationBoundary
    {
        public List<(string OperationId, Guid CorrelationId)> QueueCalls { get; } = new();
        public List<Guid> GetResultCalls { get; } = new();

        public AdminPrivilegedControlResult Queue(string operationId, Guid correlationId, CancellationToken cancellationToken)
        {
            QueueCalls.Add((operationId, correlationId));
            return new AdminPrivilegedControlResult(true, "QUEUED", "NONE", correlationId.ToString("D"), operationId);
        }

        public AdminPrivilegedControlResult GetResult(Guid correlationId, CancellationToken cancellationToken)
        {
            GetResultCalls.Add(correlationId);
            return new AdminPrivilegedControlResult(
                true, "PASS", "NONE", correlationId.ToString("D"), AdminReviewedOperationRegistry.ElevatedIdentityProof,
                new Dictionary<string, string> { ["identityState"] = "ELEVATED_ADMINISTRATOR" });
        }
    }
}
