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

            // 7. Stale request crash/timeout reconciliation
            var staleCorrId = Guid.NewGuid();
            var staleReqFile = Path.Combine(reqDir, "request.json");
            File.WriteAllText(staleReqFile, "{\"schema\":1,\"correlationId\":\"" + staleCorrId.ToString("D") + "\",\"operationId\":\"ELEVATED_IDENTITY_PROOF\"}");
            File.SetLastWriteTimeUtc(staleReqFile, DateTime.UtcNow.AddMinutes(-20));

            var freshCorrId = Guid.NewGuid();
            var freshRunResult = realAdapter.RunReviewedOperation("ELEVATED_IDENTITY_PROOF", freshCorrId, CancellationToken.None);
            Assert(freshRunResult.Success && freshRunResult.ResultState == "QUEUED",
                "stale request unblocked: fresh request successfully queued");

            var staleResultFile = Path.Combine(resDir, staleCorrId.ToString("D") + ".json");
            Assert(File.Exists(staleResultFile), "stale request reconciled to result file");
            var staleResultContent = File.ReadAllText(staleResultFile);
            Assert(staleResultContent.Contains("\"TIMEOUT\""), "stale request marked as TIMEOUT");

            // 8. Demand-driven result lifecycle pruning (>24h deleted, <24h preserved)
            var oldGuid = Guid.NewGuid();
            var oldFile = Path.Combine(resDir, oldGuid.ToString("D") + ".json");
            File.WriteAllText(oldFile, "{\"schema\":1}");
            File.SetLastWriteTimeUtc(oldFile, DateTime.UtcNow.AddHours(-25));

            var newGuid = Guid.NewGuid();
            var newFile = Path.Combine(resDir, newGuid.ToString("D") + ".json");
            File.WriteAllText(newFile, "{\"schema\":1}");
            File.SetLastWriteTimeUtc(newFile, DateTime.UtcNow.AddHours(-1));

            _ = realAdapter.GetOperationResult(freshCorrId, CancellationToken.None);
            Assert(!File.Exists(oldFile), "old result (>24h) pruned demand-driven");
            Assert(File.Exists(newFile), "recent result preserved");

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
