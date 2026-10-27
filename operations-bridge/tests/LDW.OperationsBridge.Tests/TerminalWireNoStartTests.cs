using System.Text.Json;
using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

internal static class TerminalWireNoStartTests
{
    public static void Run()
    {
        var now = DateTimeOffset.Parse("2026-10-27T20:00:00Z");

        foreach (var status in new[] { DispatchTerminalStatus.Blocked, DispatchTerminalStatus.Stale })
        {
            var wire = ClientWebSocketBridgeTransport.ToTerminalWireMessage(Result(status, startedAt: null, now));
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(wire));
            var root = document.RootElement;
            Assert(root.GetProperty("startedAt").ValueKind == JsonValueKind.Null, $"no-start {status} preserves null startedAt on wire");
            Assert(root.GetProperty("status").GetString() == BridgeProtocol.ToWireTerminalStatus(status), $"no-start {status} preserves terminal class");
            Assert(root.GetProperty("bridgeRuntime").GetString() == BridgeProtocol.BridgeRuntime, $"no-start {status} preserves observed runtime");
            Assert(root.GetProperty("bridgeVersion").GetString() == BridgeProtocol.BridgeRuntimeVersion, $"no-start {status} preserves observed version");
        }

        foreach (var status in new[] { DispatchTerminalStatus.Pass, DispatchTerminalStatus.Failed, DispatchTerminalStatus.Ambiguous })
        {
            AssertThrows<InvalidOperationException>(
                () => ClientWebSocketBridgeTransport.ToTerminalWireMessage(Result(status, startedAt: null, now)),
                $"no-start {status} is refused because execution start is required");
        }

        var startedPass = ClientWebSocketBridgeTransport.ToTerminalWireMessage(Result(DispatchTerminalStatus.Pass, now, now));
        using (var document = JsonDocument.Parse(JsonSerializer.Serialize(startedPass)))
        {
            Assert(document.RootElement.GetProperty("startedAt").GetString() == now.ToString("O"), "started PASS keeps exact start timestamp");
        }

        AssertThrows<InvalidOperationException>(
            () => ClientWebSocketBridgeTransport.ToTerminalWireMessage(Result(DispatchTerminalStatus.Blocked, null, now) with { BridgeRuntime = null }),
            "no-start BLOCKED still requires observed runtime");
        AssertThrows<InvalidOperationException>(
            () => ClientWebSocketBridgeTransport.ToTerminalWireMessage(Result(DispatchTerminalStatus.Stale, null, now) with { BridgeVersion = null }),
            "no-start STALE still requires observed version");
    }

    private static BridgeDispatchResult Result(DispatchTerminalStatus status, DateTimeOffset? startedAt, DateTimeOffset now)
        => new(
            Guid.Parse("12345678-1234-4234-9234-123456789abc"),
            "idem-terminal-wire",
            "corr-terminal-wire",
            BridgeProtocol.BridgeRuntime,
            BridgeProtocol.BridgeRuntimeVersion,
            BridgeOperation.DragonflyRunnerStatus,
            status,
            startedAt,
            now.AddSeconds(1),
            "synthetic terminal",
            new Dictionary<string, string>());

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAILED: " + message);
    }

    private static void AssertThrows<TException>(Action action, string message) where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException("FAILED: " + message);
        }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal)) { throw; }
        catch (TException) { }
    }
}
