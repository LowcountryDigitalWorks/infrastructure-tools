using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

internal static class DragonflyBridgeContractTests
{
    public static async Task RunAsync()
    {
        var expected = new HashSet<BridgeOperation>
        {
            BridgeOperation.DragonflyRunnerStatus,
            BridgeOperation.DragonflyRunnerStart,
            BridgeOperation.DragonflyRunnerDrain
        };
        Assert(BridgeProtocol.AllowedDragonflyOwnerControlOperations.SetEquals(expected), "Dragonfly allowlist contains exactly status/start/drain");
        Assert(!BridgeProtocol.AllowedReadOnlyOperations.Overlaps(expected), "existing LDW01 read-only allowlist is not widened");

        foreach (var pair in new[]
        {
            (BridgeOperation.DragonflyRunnerStatus, "dragonfly.runner.status"),
            (BridgeOperation.DragonflyRunnerStart, "dragonfly.runner.start"),
            (BridgeOperation.DragonflyRunnerDrain, "dragonfly.runner.drain")
        })
        {
            Assert(BridgeProtocol.ToWireOperation(pair.Item1) == pair.Item2, "Dragonfly wire operation is exact");
            Assert(BridgeProtocol.TryParseWireOperation(pair.Item2, out var parsed) && parsed == pair.Item1, "Dragonfly wire operation round-trips");
        }

        var bridgeId = "dragonfly-redrix-01";
        var now = DateTimeOffset.UtcNow;
        var validator = new DispatchValidator([bridgeId], BridgeProtocol.AllowedDragonflyOwnerControlOperations);
        var valid = Request(bridgeId, BridgeOperation.DragonflyRunnerStatus, now, new Dictionary<string, string>());
        Assert(validator.Validate(valid, now) == DispatchValidationError.None, "empty Dragonfly args are valid");
        var withArgs = Request(
            bridgeId,
            BridgeOperation.DragonflyRunnerStatus,
            now,
            new Dictionary<string, string> { ["path"] = "/tmp/no" });
        Assert(validator.Validate(withArgs, now) == DispatchValidationError.InvalidOperationArgs, "Dragonfly args fail closed");
        var browserRequest = Request(bridgeId, BridgeOperation.ListTabs, now, new Dictionary<string, string>());
        Assert(validator.Validate(browserRequest, now) == DispatchValidationError.UnknownOperation, "Dragonfly validator refuses browser operations");

        var unavailableTransport = new CaptureTransport();
        var unavailableClient = new DragonflyOutboundBridgeClient(
            bridgeId,
            new UnavailableDragonflyRunnerAdapter(),
            validator);
        unavailableClient.Attach(unavailableTransport);
        await unavailableTransport.DeliverAsync(valid);
        var unavailable = Single(unavailableTransport);
        Assert(unavailable.TerminalStatus == DispatchTerminalStatus.Blocked, "default unavailable adapter is BLOCKED");
        Assert(!unavailable.ExecutionStartObserved, "default unavailable adapter does not claim execution start");
        Assert(unavailable.Payload.Count == 0, "unavailable adapter returns no payload");

        var adapter = new SyntheticAdapter();
        var transport = new CaptureTransport();
        new DragonflyOutboundBridgeClient(bridgeId, adapter, validator).Attach(transport);

        await transport.DeliverAsync(valid);
        var status = transport.Results[^1];
        Assert(status.TerminalStatus == DispatchTerminalStatus.Pass, "safe Dragonfly status returns PASS");
        Assert(status.ExecutionStartObserved, "safe status records local adapter start");
        Assert(status.Payload.Count == 7, "status payload has only bounded fields when reason is null");
        Assert(status.Payload["state"] == "STOPPED", "status state is preserved");
        Assert(status.Payload["visible_cpus"] == "12", "status CPU count is bounded");
        Assert(!status.Payload.ContainsKey("qemu_pid") && !status.Payload.ContainsKey("run_id"), "status payload cannot contain private runtime identity");

        await transport.DeliverAsync(Request(bridgeId, BridgeOperation.DragonflyRunnerStart, now, new Dictionary<string, string>()));
        var start = transport.Results[^1];
        Assert(start.TerminalStatus == DispatchTerminalStatus.Pass, "safe Start returns PASS");
        Assert(start.Payload["state"] == "AVAILABLE", "Start only accepts AVAILABLE success state");
        Assert(adapter.StartCalls == 1, "Start invokes typed adapter exactly once");

        await transport.DeliverAsync(Request(bridgeId, BridgeOperation.DragonflyRunnerDrain, now, new Dictionary<string, string>()));
        var drain = transport.Results[^1];
        Assert(drain.TerminalStatus == DispatchTerminalStatus.Pass, "safe Drain returns PASS");
        Assert(drain.Payload["state"] == "DRAINING", "Drain accepts bounded DRAINING state");
        Assert(adapter.DrainCalls == 1, "Drain invokes typed adapter exactly once");

        var invalidMutationAdapter = new SyntheticAdapter
        {
            StartResult = new DragonflyRunnerLifecycleResult("STOPPED", null)
        };
        var invalidMutationTransport = new CaptureTransport();
        new DragonflyOutboundBridgeClient(bridgeId, invalidMutationAdapter, validator).Attach(invalidMutationTransport);
        await invalidMutationTransport.DeliverAsync(Request(bridgeId, BridgeOperation.DragonflyRunnerStart, now, new Dictionary<string, string>()));
        var invalidStart = Single(invalidMutationTransport);
        Assert(invalidStart.TerminalStatus == DispatchTerminalStatus.Ambiguous, "invalid Start result is AMBIGUOUS, not PASS/FAILED");
        Assert(invalidStart.Payload.Count == 0, "ambiguous mutation result exposes no adapter payload");

        var invalidStatusAdapter = new SyntheticAdapter
        {
            StatusResult = new DragonflyRunnerStatusSnapshot("STOPPED", "/home/eddie/private", 12, 12000, 81, 0.01, 0, true)
        };
        var invalidStatusTransport = new CaptureTransport();
        new DragonflyOutboundBridgeClient(bridgeId, invalidStatusAdapter, validator).Attach(invalidStatusTransport);
        await invalidStatusTransport.DeliverAsync(valid);
        var invalidStatus = Single(invalidStatusTransport);
        Assert(invalidStatus.TerminalStatus == DispatchTerminalStatus.Failed, "unsafe status output fails closed");
        Assert(!invalidStatus.Evidence.Contains("/home/", StringComparison.Ordinal), "unsafe status reason is not echoed");
        Assert(invalidStatus.Payload.Count == 0, "unsafe status payload is discarded");

        var wrongBridgeTransport = new CaptureTransport();
        var wrongBridgeAdapter = new SyntheticAdapter();
        new DragonflyOutboundBridgeClient(bridgeId, wrongBridgeAdapter, validator).Attach(wrongBridgeTransport);
        await wrongBridgeTransport.DeliverAsync(Request("other", BridgeOperation.DragonflyRunnerStart, now, new Dictionary<string, string>()));
        var wrongBridge = Single(wrongBridgeTransport);
        Assert(wrongBridge.TerminalStatus == DispatchTerminalStatus.Blocked, "wrong bridge identity is blocked before adapter execution");
        Assert(wrongBridgeAdapter.StartCalls == 0, "wrong bridge identity does not invoke Start adapter");
    }

    private static BridgeDispatchRequest Request(
        string bridgeId,
        BridgeOperation operation,
        DateTimeOffset now,
        IReadOnlyDictionary<string, string> args)
        => new(
            BridgeProtocol.Version,
            Guid.NewGuid(),
            bridgeId,
            operation,
            now.AddSeconds(-1),
            now.AddMinutes(1),
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            args);

    private static BridgeDispatchResult Single(CaptureTransport transport)
    {
        Assert(transport.Results.Count == 1, "exactly one terminal result is emitted");
        return transport.Results[0];
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAILED: " + message);
    }

    private sealed class CaptureTransport : IBridgeTransport
    {
        public event Func<BridgeDispatchRequest, string, CancellationToken, Task>? DispatchReceived;
        public List<BridgeDispatchResult> Results { get; } = [];

        public async Task DeliverAsync(BridgeDispatchRequest request)
        {
            var handler = DispatchReceived ?? throw new InvalidOperationException("FAILED: no dispatch handler attached");
            await handler(request, "synthetic-connection", CancellationToken.None).ConfigureAwait(false);
        }

        public Task SendResultAsync(BridgeDispatchResult result, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Results.Add(result);
            return Task.CompletedTask;
        }
    }

    private sealed class SyntheticAdapter : IDragonflyRunnerAdapter
    {
        public DragonflyRunnerStatusSnapshot StatusResult { get; init; } =
            new("STOPPED", null, 12, 12000, 81, 0.01, 0, true);
        public DragonflyRunnerLifecycleResult StartResult { get; init; } =
            new("AVAILABLE", null);
        public DragonflyRunnerLifecycleResult DrainResult { get; init; } =
            new("DRAINING", null);
        public int StatusCalls { get; private set; }
        public int StartCalls { get; private set; }
        public int DrainCalls { get; private set; }

        public Task<DragonflyRunnerStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StatusCalls++;
            return Task.FromResult(StatusResult);
        }

        public Task<DragonflyRunnerLifecycleResult> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCalls++;
            return Task.FromResult(StartResult);
        }

        public Task<DragonflyRunnerLifecycleResult> DrainAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DrainCalls++;
            return Task.FromResult(DrainResult);
        }
    }
}
