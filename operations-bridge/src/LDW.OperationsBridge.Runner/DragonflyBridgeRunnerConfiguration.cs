using System.Text;
using System.Text.Json;

namespace LDW.OperationsBridge.Runner;

public sealed record DragonflyBridgeRunnerConfiguration(string BridgeId, Uri RelayConnectUri)
{
    public const string FixedBridgeId = "dragonfly-redrix-01";
    private const string WorkerHost = "ldw-operations-bridge-relay.locodw.workers.dev";

    public static string UserHome
    {
        get
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrWhiteSpace(home) || !Path.IsPathFullyQualified(home))
                throw new InvalidOperationException("Dragonfly owner home could not be resolved.");
            return Path.GetFullPath(home);
        }
    }

    public static string ConfigurationDirectory => Path.Combine(UserHome, ".config", "ldw", "operations-bridge", "dragonfly");
    public static string StateDirectory => Path.Combine(UserHome, ".local", "state", "ldw", "operations-bridge", "dragonfly");
    public static string ConfigurationPath => Path.Combine(ConfigurationDirectory, "config.json");
    public static string HealthPath => Path.Combine(StateDirectory, "health.json");

    public static DragonflyBridgeRunnerConfiguration Load()
    {
        var info = new FileInfo(ConfigurationPath);
        if (!info.Exists || info.Length is <= 0 or > 4096)
            throw new InvalidOperationException("Required Dragonfly bridge configuration is missing or outside its size bound.");
        return Parse(File.ReadAllText(ConfigurationPath, Encoding.UTF8));
    }

    public static DragonflyBridgeRunnerConfiguration Parse(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Dragonfly bridge configuration must be an object.");

        var names = root.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Length != 2 || names.Distinct(StringComparer.Ordinal).Count() != 2 ||
            !root.TryGetProperty("bridgeId", out var bridgeIdElement) ||
            !root.TryGetProperty("relayConnectUri", out var relayElement) ||
            bridgeIdElement.ValueKind != JsonValueKind.String ||
            relayElement.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("Dragonfly bridge configuration schema is invalid.");

        var bridgeId = bridgeIdElement.GetString();
        if (!string.Equals(bridgeId, FixedBridgeId, StringComparison.Ordinal))
            throw new InvalidOperationException("Bridge identity is not the reviewed REDRIX identity.");

        if (!Uri.TryCreate(relayElement.GetString(), UriKind.Absolute, out var relay) ||
            relay.Scheme != Uri.UriSchemeWss ||
            !string.Equals(relay.Host, WorkerHost, StringComparison.OrdinalIgnoreCase) ||
            relay.Port != 443 ||
            relay.UserInfo.Length != 0 ||
            relay.AbsolutePath != "/relay/connect" ||
            relay.Fragment.Length != 0 ||
            relay.Query != "?bridgeId=dragonfly-redrix-01")
            throw new InvalidOperationException("Relay endpoint is not the exact trusted Dragonfly connect route.");

        return new DragonflyBridgeRunnerConfiguration(FixedBridgeId, relay);
    }
}

public interface IDragonflyBridgeSecretReader
{
    string ReadToken();
}

public sealed class DragonflyBridgeSecretUnavailableException : Exception
{
    public DragonflyBridgeSecretUnavailableException()
        : base("No reviewed protected Dragonfly bridge credential provider is configured.")
    {
    }
}

public sealed class UnavailableDragonflyBridgeSecretReader : IDragonflyBridgeSecretReader
{
    public string ReadToken()
        => throw new DragonflyBridgeSecretUnavailableException();
}
