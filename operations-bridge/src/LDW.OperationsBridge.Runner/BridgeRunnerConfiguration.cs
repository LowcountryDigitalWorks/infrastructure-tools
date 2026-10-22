using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.Json;

namespace LDW.OperationsBridge.Runner;

public sealed record BridgeRunnerConfiguration(string BridgeId, Uri RelayConnectUri)
{
    private const string WorkerHost = "ldw-operations-bridge-relay.locodw.workers.dev";

    public static string StateDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LDW", "OperationsBridge");
    public static string ConfigurationPath => Path.Combine(StateDirectory, "config.json");
    public static string ProtectedTokenPath => Path.Combine(StateDirectory, "bridge-token.dpapi");
    public static string HealthPath => Path.Combine(StateDirectory, "health.json");

    public static BridgeRunnerConfiguration Load()
    {
        var info = new FileInfo(ConfigurationPath);
        if (!info.Exists || info.Length is <= 0 or > 4096)
            throw new InvalidOperationException("Required bridge configuration is missing or outside its size bound.");
        return Parse(File.ReadAllText(ConfigurationPath, Encoding.UTF8));
    }

    public static BridgeRunnerConfiguration Parse(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Bridge configuration must be an object.");
        var names = root.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Length != 2 || names.Distinct(StringComparer.Ordinal).Count() != 2 ||
            !root.TryGetProperty("bridgeId", out var bridgeIdElement) ||
            !root.TryGetProperty("relayConnectUri", out var relayElement) ||
            bridgeIdElement.ValueKind != JsonValueKind.String ||
            relayElement.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("Bridge configuration schema is invalid.");

        var bridgeId = bridgeIdElement.GetString();
        if (!string.Equals(bridgeId, "ldw01-bridge", StringComparison.Ordinal))
            throw new InvalidOperationException("Bridge identity is not the reviewed LDW01 identity.");

        if (!Uri.TryCreate(relayElement.GetString(), UriKind.Absolute, out var relay) ||
            relay.Scheme != Uri.UriSchemeWss ||
            !string.Equals(relay.Host, WorkerHost, StringComparison.OrdinalIgnoreCase) ||
            relay.Port != 443 ||
            relay.UserInfo.Length != 0 ||
            relay.AbsolutePath != "/relay/connect" ||
            relay.Fragment.Length != 0 ||
            relay.Query != "?bridgeId=ldw01-bridge")
            throw new InvalidOperationException("Relay endpoint is not the exact trusted Workers Free connect route.");

        return new BridgeRunnerConfiguration(bridgeId, relay);
    }
}

public sealed class CurrentUserDpapiSecretReader
{
    public string ReadToken(string path)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Bridge bearer protection requires Windows CurrentUser DPAPI.");
        var info = new FileInfo(path);
        if (!info.Exists || info.Length is <= 0 or > 8192)
            throw new InvalidOperationException("Protected bridge credential is missing or outside its size bound.");
        var ciphertext = File.ReadAllBytes(path);
        var inputPtr = Marshal.AllocHGlobal(ciphertext.Length);
        var input = new DataBlob { Length = ciphertext.Length, Data = inputPtr };
        try
        {
            Marshal.Copy(ciphertext, 0, inputPtr, ciphertext.Length);
            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out var output))
                throw new SecurityException("Current-user protected bridge credential could not be opened.");
            try
            {
                if (output.Length is <= 0 or > 1024)
                    throw new SecurityException("Decrypted bridge credential is outside its size bound.");
                var bytes = new byte[output.Length];
                Marshal.Copy(output.Data, bytes, 0, output.Length);
                var token = new UTF8Encoding(false, true).GetString(bytes);
                Array.Clear(bytes);
                if (token.Length is <= 0 or > 512 || token.Any(char.IsControl))
                    throw new SecurityException("Decrypted bridge credential is invalid.");
                return token;
            }
            finally
            {
                if (output.Data != IntPtr.Zero)
                {
                    ZeroMemory(output.Data, output.Length);
                    LocalFree(output.Data);
                }
            }
        }
        finally
        {
            ZeroMemory(inputPtr, ciphertext.Length);
            Marshal.FreeHGlobal(inputPtr);
            Array.Clear(ciphertext);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int Length; public IntPtr Data; }

    [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr optionalEntropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    private static void ZeroMemory(IntPtr destination, int length)
    {
        for (var index = 0; index < length; index++)
            Marshal.WriteByte(destination, index, 0);
    }
}

public sealed record BridgeRunnerHealth(string State, DateTimeOffset ObservedAt, string BridgeId, string Runtime, string Version);

public static class BridgeRunnerHealthStore
{
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
        { "starting", "connecting", "connected", "degraded", "blocked", "stopped" };

    public static void Write(string state, string bridgeId)
    {
        if (!States.Contains(state))
            throw new ArgumentOutOfRangeException(nameof(state));
        Directory.CreateDirectory(BridgeRunnerConfiguration.StateDirectory);
        var payload = JsonSerializer.Serialize(new BridgeRunnerHealth(
            state, DateTimeOffset.UtcNow, bridgeId, "ldw-operations-bridge", "1.0.0"),
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var temp = BridgeRunnerConfiguration.HealthPath + ".tmp";
        File.WriteAllText(temp, payload, new UTF8Encoding(false));
        File.Move(temp, BridgeRunnerConfiguration.HealthPath, overwrite: true);
    }

    public static string ReadState()
    {
        try
        {
            var info = new FileInfo(BridgeRunnerConfiguration.HealthPath);
            if (!info.Exists || info.Length is <= 0 or > 2048)
                return "unknown";
            return Interpret(File.ReadAllText(info.FullName), DateTimeOffset.UtcNow);
        }
        catch { return "unknown"; }
    }

    public static string Interpret(string json, DateTimeOffset now)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (!root.TryGetProperty("state", out var stateElement) ||
            !root.TryGetProperty("observedAt", out var observedElement) ||
            !root.TryGetProperty("bridgeId", out var bridgeElement) ||
            stateElement.ValueKind != JsonValueKind.String ||
            observedElement.ValueKind != JsonValueKind.String ||
            bridgeElement.GetString() != "ldw01-bridge" ||
            !DateTimeOffset.TryParse(observedElement.GetString(), out var observedAt) ||
            !States.Contains(stateElement.GetString() ?? string.Empty))
            return "unknown";
        if (now - observedAt > TimeSpan.FromSeconds(30) || observedAt > now.AddSeconds(10))
            return "stale";
        return stateElement.GetString()!;
    }
}
