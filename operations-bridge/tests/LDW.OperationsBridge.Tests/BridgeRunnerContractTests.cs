using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;
using LDW.OperationsBridge.Runner;

internal static class BridgeRunnerContractTests
{
    public static void Run()
    {
        DragonflyBridgeContractTests.RunAsync().GetAwaiter().GetResult();

        var config = BridgeRunnerConfiguration.Parse(
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}");
        Assert(config.BridgeId == "ldw01-bridge", "runner accepts exact bridge identity");
        Assert(config.RelayConnectUri.Scheme == "wss", "runner accepts secure trusted endpoint");
        var connectHeaders = BridgeConnectIdentityHeaders.Create();
        Assert(connectHeaders.Count == 3, "connect identity contains only the three fixed metadata headers");
        Assert(connectHeaders["X-LDW-Protocol-Version"] == BridgeProtocol.Version, "connect protocol is sourced from BridgeProtocol");
        Assert(connectHeaders["X-LDW-Bridge-Runtime"] == BridgeProtocol.BridgeRuntime, "connect runtime is sourced from BridgeProtocol");
        Assert(connectHeaders["X-LDW-Bridge-Version"] == BridgeProtocol.BridgeRuntimeVersion, "connect runtime version is sourced from BridgeProtocol");

        foreach (var invalid in new[]
        {
            "{\"bridgeId\":\"other\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"ws://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://evil.example/relay/connect?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.attacker.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/dispatch?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=other\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://user:pass@ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\",\"token\":\"plaintext\"}",
            "{\"bridgeId\":\"ldw01-bridge\",\"bridgeId\":\"ldw01-bridge\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=ldw01-bridge\"}"
        })
        {
            AssertThrows<Exception>(() => BridgeRunnerConfiguration.Parse(invalid), "runner rejects invalid endpoint, identity, duplicate or extra secret fields");
        }

        var now = DateTimeOffset.Parse("2026-10-21T12:00:00Z");
        var fresh = "{\"state\":\"connected\",\"observedAt\":\"2026-10-21T12:00:00Z\",\"bridgeId\":\"ldw01-bridge\",\"runtime\":\"ldw-operations-bridge\",\"version\":\"1.0.0\"}";
        Assert(BridgeRunnerHealthStore.Interpret(fresh, now) == "connected", "runner health reads deterministic fresh connected state");
        var stale = fresh.Replace("2026-10-21T12:00:00Z", "2026-10-21T11:00:00Z", StringComparison.Ordinal);
        Assert(BridgeRunnerHealthStore.Interpret(stale, now) == "stale", "runner health marks old state stale");
        var wrongBridge = fresh.Replace("ldw01-bridge", "other", StringComparison.Ordinal);
        Assert(BridgeRunnerHealthStore.Interpret(wrongBridge, now) == "unknown", "runner health rejects wrong bridge identity");
        AssertThrows<Exception>(() => BridgeRunnerHealthStore.Interpret("{malformed", now), "runner health rejects malformed state");

        static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException("FAILED: " + message);
        }
        static void AssertThrows<TException>(Action action, string message) where TException : Exception
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
}
