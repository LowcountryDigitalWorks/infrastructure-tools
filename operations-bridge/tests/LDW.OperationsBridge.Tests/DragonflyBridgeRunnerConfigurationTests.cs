using LDW.OperationsBridge.Runner;

internal static class DragonflyBridgeRunnerConfigurationTests
{
    public static void Run()
    {
        const string exact = "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\"}";
        var config = DragonflyBridgeRunnerConfiguration.Parse(exact);
        Assert(config.BridgeId == "dragonfly-redrix-01", "Dragonfly config accepts only fixed bridge identity");
        Assert(config.RelayConnectUri.Scheme == "wss", "Dragonfly config requires secure WSS");
        Assert(config.RelayConnectUri.Host == "ldw-operations-bridge-relay.locodw.workers.dev", "Dragonfly config pins exact relay host");
        Assert(config.RelayConnectUri.AbsolutePath == "/relay/connect", "Dragonfly config pins exact relay path");
        Assert(config.RelayConnectUri.Query == "?bridgeId=dragonfly-redrix-01", "Dragonfly config pins exact server-bound bridge query");

        Assert(Path.IsPathFullyQualified(DragonflyBridgeRunnerConfiguration.ConfigurationDirectory), "Dragonfly config directory is absolute");
        Assert(Path.IsPathFullyQualified(DragonflyBridgeRunnerConfiguration.StateDirectory), "Dragonfly state directory is absolute");
        Assert(DragonflyBridgeRunnerConfiguration.ConfigurationPath.EndsWith(
            Path.Combine(".config", "ldw", "operations-bridge", "dragonfly", "config.json"),
            StringComparison.Ordinal), "Dragonfly config path is fixed under owner profile");
        Assert(DragonflyBridgeRunnerConfiguration.HealthPath.EndsWith(
            Path.Combine(".local", "state", "ldw", "operations-bridge", "dragonfly", "health.json"),
            StringComparison.Ordinal), "Dragonfly health path is fixed under owner profile");

        foreach (var invalid in new[]
        {
            "{\"bridgeId\":\"other\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"ws://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://evil.example/relay/connect?bridgeId=dragonfly-redrix-01\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/dispatch?bridgeId=dragonfly-redrix-01\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=other\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://user:pass@ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\",\"token\":\"plaintext\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\",\"secretPath\":\"/tmp/token\"}",
            "{\"bridgeId\":\"dragonfly-redrix-01\",\"bridgeId\":\"dragonfly-redrix-01\",\"relayConnectUri\":\"wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01\"}"
        })
        {
            AssertThrows<Exception>(() => DragonflyBridgeRunnerConfiguration.Parse(invalid), "Dragonfly config rejects alternate identity/endpoint/secret/duplicate fields");
        }

        IDragonflyBridgeSecretReader reader = new UnavailableDragonflyBridgeSecretReader();
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => reader.ReadToken(),
            "Dragonfly secret provider is unavailable by default");
    }

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
