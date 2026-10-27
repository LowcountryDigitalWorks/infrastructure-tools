using System.Runtime.CompilerServices;
using System.Text.Json;
using LDW.AdminBroker;
using LDW.HostAgent.Core;

internal static class CiJitControlContractTests
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
            if (!condition) throw new Exception("CI/JIT contract assertion failed: " + message);
            assertions++;
        }

        var fixedTarget = CiJitControlContract.TargetIdentity;
        var noParameterOperations = new[]
        {
            AdminBrokerContract.Operations.CiJitStatus,
            AdminBrokerContract.Operations.CiJitDiscover,
            AdminBrokerContract.Operations.CiJitRunOnce,
            AdminBrokerContract.Operations.CiJitRecover,
            AdminBrokerContract.Operations.CiJitAbortActive,
            AdminBrokerContract.Operations.CiJitListStale
        };

        foreach (var operation in noParameterOperations)
        {
            var json = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"" + operation
                + "\",\"targetIdentity\":\"" + fixedTarget + "\",\"parameters\":{}}";
            Assert(AdminBrokerContract.TryParseRequest(json, out var request) && request is not null,
                operation + " parses with no parameters");
            Assert(AdminBrokerRequestPolicy.IsAllowed(request!), operation + " passes fixed-target policy");
            Assert(!AdminBrokerRequestPolicy.IsAllowed(request! with { TargetIdentity = "another-host" }),
                operation + " refuses caller-selected target");

            var arbitrary = request! with
            {
                Parameters = new Dictionary<string, JsonElement>
                {
                    ["runId"] = Json("123")
                }
            };
            Assert(!AdminBrokerRequestPolicy.IsAllowed(arbitrary), operation + " rejects arbitrary candidate parameter");
        }

        const string retireJson = "{\"version\":1,\"requestId\":\"22222222-2222-2222-2222-222222222222\",\"operation\":\"CI_JIT_RETIRE_STALE\",\"targetIdentity\":\"local-ci-jit\",\"parameters\":{\"runId\":123}}";
        Assert(AdminBrokerContract.TryParseRequest(retireJson, out var retire) && retire is not null,
            "stale retirement parses exact runId only");
        Assert(AdminBrokerRequestPolicy.IsAllowed(retire!), "positive stale runId accepted");
        var zeroRetire = retire! with { Parameters = new Dictionary<string, JsonElement> { ["runId"] = Json("0") } };
        Assert(!AdminBrokerRequestPolicy.IsAllowed(zeroRetire), "zero stale runId rejected");
        Assert(!AdminBrokerContract.TryParseRequest(retireJson.Replace("123", "\"123\""), out _),
            "string stale runId rejected at schema boundary");

        const string resultJson = "{\"version\":1,\"requestId\":\"33333333-3333-3333-3333-333333333333\",\"operation\":\"CI_JIT_GET_OPERATION_RESULT\",\"targetIdentity\":\"local-ci-jit\",\"parameters\":{\"operationId\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"}}";
        Assert(AdminBrokerContract.TryParseRequest(resultJson, out var resultRequest) && resultRequest is not null,
            "operation result requires bounded UUID");
        Assert(AdminBrokerRequestPolicy.IsAllowed(resultRequest!), "operation result UUID accepted");
        Assert(!AdminBrokerContract.TryParseRequest(resultJson.Replace("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "not-an-id"), out _),
            "invalid operation result ID rejected");

        var defaultEngine = new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler());
        var discoverRequest = new AdminBrokerRequest(
            AdminBrokerContract.Version,
            "44444444-4444-4444-4444-444444444444",
            AdminBrokerContract.Operations.CiJitDiscover,
            fixedTarget,
            new Dictionary<string, JsonElement>());
        var defaultResponse = defaultEngine.ProcessRequestAsync(discoverRequest, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(!defaultResponse.Success && defaultResponse.ResultState == "BLOCKED" && defaultResponse.ErrorCode == "ADAPTER_UNAVAILABLE",
            "default broker remains incapable of CI/JIT execution");

        var adapter = new RecordingAdapter();
        var engine = new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler(adapter));
        var runRequest = discoverRequest with
        {
            RequestId = "55555555-5555-5555-5555-555555555555",
            Operation = AdminBrokerContract.Operations.CiJitRunOnce
        };
        var first = engine.ProcessRequestAsync(runRequest, null, CancellationToken.None).GetAwaiter().GetResult();
        var duplicate = engine.ProcessRequestAsync(runRequest, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(first.Success && first.ResultState == "STARTED" && first.ErrorCode is null,
            "typed adapter may return a bounded started result");
        Assert(adapter.RunOnceCalls == 1, "duplicate request ID never invokes run-once twice");
        Assert(duplicate.ErrorCode == "DUPLICATE_REQUEST", "duplicate request returns deterministic replay response");

        var retireResponse = engine.ProcessRequestAsync(retire! with { RequestId = "66666666-6666-6666-6666-666666666666" }, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(retireResponse.Success && adapter.LastRetireRunId == 123, "only validated stale runId reaches adapter");

        var statusRequest = discoverRequest with
        {
            RequestId = "77777777-7777-7777-7777-777777777777",
            Operation = AdminBrokerContract.Operations.CiJitStatus
        };
        var statusResponse = engine.ProcessRequestAsync(statusRequest, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(statusResponse.Success && statusResponse.Details is not null, "status returns bounded details");
        Assert(statusResponse.Details!.Keys.All(k => new[]
        {
            "operationId", "profileId", "runId", "jobId", "observedAtUtc", "sourceVersion", "ownerState",
            "statusReasonCode", "localStateFresh", "queueState", "eligibleQueuedCount", "heldQueuedCount",
            "selectedProfile", "selectedRunId", "selectedJobId", "controllerPhase", "capacity"
        }.Contains(k, StringComparer.Ordinal)), "status detail keys stay on fixed allowlist");
        var serializedStatus = AdminBrokerContract.CreateResponseJson(statusResponse);
        Assert(!serializedStatus.Contains("token", StringComparison.OrdinalIgnoreCase)
            && !serializedStatus.Contains("C:\\", StringComparison.OrdinalIgnoreCase),
            "status response contains no token or private path material");

        var unsafeAdapter = new UnsafeAdapter();
        var unsafeEngine = new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler(unsafeAdapter));
        var unsafeResponse = unsafeEngine.ProcessRequestAsync(statusRequest with { RequestId = "88888888-8888-8888-8888-888888888888" }, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(!unsafeResponse.Success && unsafeResponse.ErrorCode == "INVALID_ADAPTER_RESULT",
            "unsafe adapter output fails closed before serialization");

        var auditRoot = Path.Combine(Path.GetTempPath(), "LDW_CiJit_Audit_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(auditRoot);
        try
        {
            var audit = new AdminBrokerAuditLogger(Path.Combine(auditRoot, "audit.jsonl"));
            audit.Log(new AuditRecord(DateTime.UtcNow, first.RequestId, first.Operation, fixedTarget, null,
                first.Success, first.ResultState, first.ErrorCode, first.Summary));
            Assert(audit.ReadRecords().Count == 1, "bounded CI/JIT audit state is accepted");
            try
            {
                audit.Log(new AuditRecord(DateTime.UtcNow, Guid.NewGuid().ToString("D"), first.Operation, fixedTarget, null,
                    false, "BLOCKED", "ARBITRARY_ERROR", "unsafe"));
                throw new Exception("Expected arbitrary audit error rejection");
            }
            catch (InvalidOperationException)
            {
                Assert(true, "arbitrary CI/JIT audit reason is rejected");
            }
        }
        finally
        {
            try { Directory.Delete(auditRoot, true); } catch { }
        }

        Console.WriteLine($"CI/JIT broker contract tests: {assertions} assertions passed.");
    }

    private static JsonElement Json(string value) => JsonDocument.Parse(value).RootElement.Clone();

    private sealed class RecordingAdapter : ICiJitControlAdapter
    {
        public int RunOnceCalls { get; private set; }
        public long? LastRetireRunId { get; private set; }

        public CiJitControlResult GetStatus(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = CiJitStatusResolver.Resolve(new CiJitStatusInput(
                DateTimeOffset.UtcNow,
                "ci-jit-v1",
                true,
                true,
                true,
                false,
                CiJitQueueState.Fresh,
                1,
                0,
                CiJitCapacityState.Ready,
                null,
                null,
                "bizops-secret-scan",
                1001,
                2001));
            return new CiJitControlResult(true, "PASS", "NONE", Status: status);
        }

        public CiJitControlResult Discover(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new CiJitControlResult(true, "PASS", "NONE", ProfileId: "bizops-secret-scan", RunId: 1001, JobId: 2001);
        }

        public CiJitControlResult RunOnce(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RunOnceCalls++;
            return new CiJitControlResult(true, "STARTED", "NONE", Guid.NewGuid().ToString("D"), "bizops-secret-scan", 1001, 2001);
        }

        public CiJitControlResult Recover(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return new(true, "PASS", "NONE"); }
        public CiJitControlResult AbortActive(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return new(false, "BLOCKED", "NO_ACTIVE_JOB"); }
        public CiJitControlResult ListStale(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return new(true, "PASS", "NONE"); }
        public CiJitControlResult RetireStale(long runId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRetireRunId = runId;
            return new(true, "PASS", "PR_HEAD_MOVED", RunId: runId);
        }
        public CiJitControlResult GetOperationResult(Guid operationId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(true, "PASS", "NONE", operationId.ToString("D"));
        }
    }

    private sealed class UnsafeAdapter : ICiJitControlAdapter
    {
        private static CiJitControlResult Unsafe() => new(true, "PASS", "NONE", ProfileId: "../../secret-path");
        public CiJitControlResult GetStatus(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult Discover(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult RunOnce(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult Recover(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult AbortActive(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult ListStale(CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult RetireStale(long runId, CancellationToken cancellationToken) => Unsafe();
        public CiJitControlResult GetOperationResult(Guid operationId, CancellationToken cancellationToken) => Unsafe();
    }
}
