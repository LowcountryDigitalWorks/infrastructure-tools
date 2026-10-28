using System.Runtime.CompilerServices;
using LDW.AdminBroker;
using LDW.HostAgent.Core;

internal static class LocalCiJitControlAdapterRegressionTests
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
            if (!condition) throw new Exception("Local CI/JIT adapter regression assertion failed: " + message);
            assertions++;
        }

        var snapshot = CiJitLocalProjection.Unavailable(DateTimeOffset.UtcNow);
        var statusSource = new RecordingStatusSource(snapshot);
        var boundary = new RecordingBoundary();
        var adapter = new LocalCiJitControlAdapter(statusSource, boundary);

        var status = adapter.GetStatus(CancellationToken.None);
        Assert(status.Success && status.Status is not null, "status returns the injected sanitized projection");
        Assert(statusSource.ReadCalls == 1, "status reads the projection exactly once");
        Assert(boundary.QueueCalls.Count == 0, "status never reaches the privileged operation boundary");

        var fixedOperations = new[]
        {
            CiJitFixedOperation.Discover,
            CiJitFixedOperation.RunOnce,
            CiJitFixedOperation.Recover,
            CiJitFixedOperation.AbortActive,
            CiJitFixedOperation.ListStale
        };
        foreach (var operation in fixedOperations)
        {
            var result = operation switch
            {
                CiJitFixedOperation.Discover => adapter.Discover(CancellationToken.None),
                CiJitFixedOperation.RunOnce => adapter.RunOnce(CancellationToken.None),
                CiJitFixedOperation.Recover => adapter.Recover(CancellationToken.None),
                CiJitFixedOperation.AbortActive => adapter.AbortActive(CancellationToken.None),
                CiJitFixedOperation.ListStale => adapter.ListStale(CancellationToken.None),
                _ => throw new InvalidOperationException()
            };
            Assert(result.Success && result.ResultState == "QUEUED", operation + " reaches the fixed boundary");
            var call = boundary.QueueCalls[^1];
            Assert(call.Operation == operation, operation + " maps to the exact fixed operation");
            Assert(call.RunId is null, operation + " cannot carry caller-selected run/candidate identity");
        }

        var queueCallsBeforeInvalidRetire = boundary.QueueCalls.Count;
        var invalidRetire = adapter.RetireStale(0, CancellationToken.None);
        Assert(!invalidRetire.Success && invalidRetire.ReasonCode == "NOT_STALE", "non-positive stale run id fails closed");
        Assert(boundary.QueueCalls.Count == queueCallsBeforeInvalidRetire, "invalid stale run id never reaches the privileged boundary");

        var retire = adapter.RetireStale(4242, CancellationToken.None);
        Assert(retire.Success, "positive stale run id reaches the fixed boundary");
        Assert(boundary.QueueCalls[^1] == (CiJitFixedOperation.RetireStale, 4242L), "stale retirement forwards only the exact authorized run id");

        var operationId = Guid.NewGuid();
        var operationResult = adapter.GetOperationResult(operationId, CancellationToken.None);
        Assert(operationResult.Success && boundary.LastResultId == operationId, "operation-result lookup forwards only the opaque operation id");

        var replayBoundary = new RecordingBoundary();
        var replayAdapter = new LocalCiJitControlAdapter(new RecordingStatusSource(snapshot), replayBoundary);
        var engine = new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler(replayAdapter));
        var request = new AdminBrokerRequest(
            AdminBrokerContract.Version,
            "91919191-9191-9191-9191-919191919191",
            AdminBrokerContract.Operations.CiJitRunOnce,
            CiJitControlContract.TargetIdentity,
            new Dictionary<string, System.Text.Json.JsonElement>());
        var first = engine.ProcessRequestAsync(request, null, CancellationToken.None).GetAwaiter().GetResult();
        var duplicate = engine.ProcessRequestAsync(request, null, CancellationToken.None).GetAwaiter().GetResult();
        Assert(first.Success && first.ResultState == "QUEUED", "real local adapter can return bounded queued state");
        Assert(replayBoundary.QueueCalls.Count == 1, "duplicate broker request id cannot duplicate launch-boundary invocation");
        Assert(!duplicate.Success && duplicate.ErrorCode == "DUPLICATE_REQUEST", "duplicate launch request fails deterministically");

        var repoRoot = FindRepositoryRoot();
        var managePath = Path.Combine(repoRoot, "host-agent", "deploy", "Manage-CiJitControlTasks.ps1");
        var workerPath = Path.Combine(repoRoot, "host-agent", "deploy", "Invoke-CiJitControlTask.ps1");
        var adapterPath = Path.Combine(repoRoot, "host-agent", "src", "LDW.AdminBroker", "LocalCiJitControlAdapter.cs");
        var hostProgramPath = Path.Combine(repoRoot, "host-agent", "src", "LDW.AdminBroker.Host", "Program.cs");
        var manage = File.ReadAllText(managePath);
        var worker = File.ReadAllText(workerPath);
        var adapterSource = File.ReadAllText(adapterPath);
        var hostProgram = File.ReadAllText(hostProgramPath);

        foreach (var task in new[]
        {
            @"\LDW-CI-JIT-DISCOVER", @"\LDW-CI-JIT-RUN-ONCE", @"\LDW-CI-JIT-RECOVER",
            @"\LDW-CI-JIT-ABORT-ACTIVE", @"\LDW-CI-JIT-LIST-STALE", @"\LDW-CI-JIT-RETIRE-STALE"
        })
        {
            Assert(manage.Contains(task, StringComparison.Ordinal), "task plan contains fixed identity " + task);
        }
        Assert(manage.Contains("$definition.Triggers.Count -ne 0", StringComparison.Ordinal), "task readback rejects any trigger");
        Assert(manage.Contains("'TRIGGER_COUNT=0'", StringComparison.Ordinal), "plan/status reports zero triggers");
        Assert(!manage.Contains("Triggers.Create", StringComparison.OrdinalIgnoreCase)
            && !manage.Contains("New-ScheduledTaskTrigger", StringComparison.OrdinalIgnoreCase)
            && !manage.Contains("Repetition", StringComparison.OrdinalIgnoreCase),
            "task installation source contains no trigger or recurrence constructor");

        var taskSddlLine = manage.Split('\n').Single(line => line.TrimStart().StartsWith("$taskSddl=", StringComparison.Ordinal));
        Assert(taskSddlLine.Contains("(A;;FA;;;SY)", StringComparison.Ordinal)
            && taskSddlLine.Contains("(A;;FA;;;BA)", StringComparison.Ordinal)
            && taskSddlLine.Contains("(A;;GRGX;;;", StringComparison.Ordinal),
            "task ACL grants SYSTEM/Admin control and owner read/execute");
        Assert(!taskSddlLine.Contains("(A;;FA;;;'+$OwnerSid", StringComparison.Ordinal)
            && !taskSddlLine.Contains("(A;;GW;;;'+$OwnerSid", StringComparison.Ordinal),
            "owner task invocation rights do not grant definition replacement rights");

        var workerParamBlock = Slice(worker, "[CmdletBinding()]", "$ErrorActionPreference");
        Assert(workerParamBlock.Contains("ValidateSet('DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE')", StringComparison.Ordinal),
            "worker operation input is a closed six-verb enum");
        foreach (var forbiddenParameter in new[] { "$Repository", "$Workflow", "$JobId", "$ProfileId", "$Candidate", "$Executable", "$Path", "$Arguments", "$Environment" })
        {
            Assert(!workerParamBlock.Contains(forbiddenParameter, StringComparison.Ordinal), "worker exposes no caller-selected " + forbiddenParameter + " parameter");
        }
        Assert(!worker.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase)
            && !worker.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)
            && !worker.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase),
            "worker contains no generic shell execution primitive");
        Assert(worker.Contains("ProcessStartInfo", StringComparison.Ordinal)
            && worker.Contains("ArgumentList.Add", StringComparison.Ordinal),
            "fixed child invocation uses structured argument-list construction");

        var staleBody = Slice(worker, "function Get-ProvenStaleEntries", "function Retire-ProvenStale");
        foreach (var evidence in new[] { "PR_MERGED", "PR_CLOSED", "PR_HEAD_MOVED", "PROFILE_MISMATCH", "Test-UnassignedQueued" })
        {
            Assert(worker.Contains(evidence, StringComparison.Ordinal), "stale proof preserves live evidence class " + evidence);
        }
        foreach (var ageToken in new[] { "created_at", "updated_at", "run_started_at", "AddMinutes", "TotalMinutes", "TotalHours" })
        {
            Assert(!staleBody.Contains(ageToken, StringComparison.OrdinalIgnoreCase), "age alone is not stale proof: " + ageToken);
        }

        var retireBody = Slice(worker, "function Retire-ProvenStale", "try {");
        Assert(CountOccurrences(retireBody, "Get-ProvenStaleEntries -TargetRunId $RunId") == 2,
            "stale retirement re-reads live evidence immediately before cancellation");
        var secondRead = retireBody.LastIndexOf("Get-ProvenStaleEntries -TargetRunId $RunId", StringComparison.Ordinal);
        var cancel = retireBody.IndexOf("/cancel", StringComparison.Ordinal);
        Assert(secondRead >= 0 && cancel > secondRead, "cancel occurs only after the second exact stale-evidence read");

        var abortBody = Slice(worker, "'ABORT_ACTIVE' {", "'LIST_STALE' {");
        Assert(abortBody.Contains("$runs.Count -ne 1", StringComparison.Ordinal)
            && abortBody.Contains("'-Mode','Cleanup','-LocalRunId'", StringComparison.Ordinal),
            "abort refuses ambiguous ownership and reaches only exact local cleanup");

        var resultBody = Slice(worker, "function Write-Result", "function Invoke-Child");
        foreach (var forbiddenResult in new[] { "stdout", "stderr", "commandLine", "accessToken", "bearer", "secret" })
        {
            Assert(!resultBody.Contains(forbiddenResult, StringComparison.OrdinalIgnoreCase), "result envelope excludes raw/private field " + forbiddenResult);
        }
        Assert(resultBody.Contains("schema=1", StringComparison.Ordinal)
            && resultBody.Contains("resultState=$State", StringComparison.Ordinal)
            && resultBody.Contains("reasonCode=$Reason", StringComparison.Ordinal),
            "result envelope is the bounded correlation/status contract");

        Assert(adapterSource.Contains("MaximumEnvelopeBytes = 16 * 1024", StringComparison.Ordinal)
            && adapterSource.Contains("UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow", StringComparison.Ordinal)
            && adapterSource.Contains("CiJitControlContract.IsSafeResult(projected)", StringComparison.Ordinal),
            "adapter rejects oversized, extra-field, and unsafe result envelopes");
        Assert(adapterSource.Contains("\"LDW\", \"CiJitStatus\", \"status.json\"", StringComparison.Ordinal)
            && adapterSource.Contains("CiJitLocalProjection.Parse", StringComparison.Ordinal),
            "status source is pinned to the accepted sanitized #71 projection");
        Assert(hostProgram.Contains("new HostAgentOperationHandler(new LocalCiJitControlAdapter())", StringComparison.Ordinal),
            "concrete local adapter is composed explicitly at the normal-user host boundary");
        Assert(adapterSource.Contains("UnavailableCiJitControlAdapter", StringComparison.Ordinal) == false,
            "local adapter does not weaken or replace the separate fail-closed unavailable fallback type");

        Console.WriteLine($"Local CI/JIT adapter regression tests: {assertions} assertions passed.");
    }

    private static string FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var current = new DirectoryInfo(start);
            while (current is not null)
            {
                if (File.Exists(Path.Combine(current.FullName, "host-agent", "deploy", "Manage-CiJitControlTasks.ps1")))
                    return current.FullName;
                current = current.Parent;
            }
        }
        throw new DirectoryNotFoundException("Could not locate infrastructure-tools repository root for source-contract tests.");
    }

    private static string Slice(string source, string startToken, string endToken)
    {
        var start = source.IndexOf(startToken, StringComparison.Ordinal);
        if (start < 0) throw new InvalidOperationException("Missing source token: " + startToken);
        var end = source.IndexOf(endToken, start + startToken.Length, StringComparison.Ordinal);
        if (end < 0) throw new InvalidOperationException("Missing source token: " + endToken);
        return source[start..end];
    }

    private static int CountOccurrences(string source, string token)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(token, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += token.Length;
        }
        return count;
    }

    private sealed class RecordingStatusSource(CiJitStatusSnapshot snapshot) : ICiJitStatusSource
    {
        public int ReadCalls { get; private set; }
        public CiJitStatusSnapshot Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCalls++;
            return snapshot;
        }
    }

    private sealed class RecordingBoundary : ICiJitOperationBoundary
    {
        public List<(CiJitFixedOperation Operation, long? RunId)> QueueCalls { get; } = new();
        public Guid? LastResultId { get; private set; }

        public CiJitControlResult Queue(CiJitFixedOperation operation, long? runId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            QueueCalls.Add((operation, runId));
            return new CiJitControlResult(true, "QUEUED", "NONE", Guid.NewGuid().ToString("D"), RunId: runId);
        }

        public CiJitControlResult GetResult(Guid operationId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastResultId = operationId;
            return new CiJitControlResult(true, "PASS", "NONE", operationId.ToString("D"));
        }
    }
}
