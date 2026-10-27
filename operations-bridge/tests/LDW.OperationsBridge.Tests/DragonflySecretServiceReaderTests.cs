using LDW.OperationsBridge.Runner;

internal static class DragonflySecretServiceReaderTests
{
    public static void Run()
    {
        var startInfo = SecretServiceDragonflyBridgeSecretReader.CreateLookupStartInfo(1000);

        Assert(startInfo.FileName == "/usr/bin/secret-tool", "Secret Service reader pins exact secret-tool path");
        Assert(!startInfo.UseShellExecute, "Secret Service reader disables shell execution");
        Assert(!startInfo.RedirectStandardInput, "Secret Service reader does not feed the bearer through stdin");
        Assert(startInfo.RedirectStandardOutput, "Secret Service reader captures lookup output privately");
        Assert(startInfo.RedirectStandardError, "Secret Service reader captures and discards diagnostics privately");
        Assert(startInfo.CreateNoWindow, "Secret Service reader does not open an interactive process window");

        var expectedArguments = new[]
        {
            "lookup",
            "service",
            "ldw-operations-bridge",
            "bridge-id",
            "dragonfly-redrix-01"
        };
        Assert(startInfo.ArgumentList.SequenceEqual(expectedArguments), "Secret Service lookup argv is exact and contains no bearer");

        Assert(startInfo.Environment.Count == 2, "Secret Service reader passes only bounded session-bus environment");
        Assert(startInfo.Environment["XDG_RUNTIME_DIR"] == "/run/user/1000", "Secret Service reader derives fixed XDG runtime directory from effective uid");
        Assert(startInfo.Environment["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus", "Secret Service reader derives fixed user D-Bus address from effective uid");
        Assert(!startInfo.Environment.Keys.Any(key => key.Contains("TOKEN", StringComparison.OrdinalIgnoreCase) || key.Contains("SECRET", StringComparison.OrdinalIgnoreCase)), "Secret Service reader environment contains no secret/token variable");
        Assert(!startInfo.ArgumentList.Any(argument => argument.Contains("token", StringComparison.OrdinalIgnoreCase) || argument.Contains("secretPath", StringComparison.OrdinalIgnoreCase)), "Secret Service reader argv contains no bearer or caller secret path");

        AssertThrows<ArgumentOutOfRangeException>(
            () => SecretServiceDragonflyBridgeSecretReader.CreateLookupStartInfo(0),
            "Secret Service reader rejects root execution identity");

        const string token = "synthetic.bridge-token_123-ABC=";
        Assert(SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, token + "\n") == token, "Secret Service reader normalizes one trailing newline without exposing token");
        Assert(SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, token + "\r\n") == token, "Secret Service reader normalizes CRLF without changing token bytes");

        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(1, token),
            "Secret Service reader fails closed when lookup exits nonzero");
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, string.Empty),
            "Secret Service reader fails closed on empty lookup output");
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, "   \n"),
            "Secret Service reader fails closed on whitespace lookup output");
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, "abc\ndef\n"),
            "Secret Service reader fails closed on embedded newline output");
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, "abc\tdef\n"),
            "Secret Service reader fails closed on whitespace/control output");
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SecretServiceDragonflyBridgeSecretReader.NormalizeLookupResult(0, new string('x', SecretServiceDragonflyBridgeSecretReader.MaxTokenChars + 1)),
            "Secret Service reader fails closed on oversized bearer output");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAILED: " + message);
    }

    private static void AssertThrows<TException>(Action action, string message) where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException("FAILED: " + message);
        }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal))
        {
            throw;
        }
        catch (TException)
        {
        }
    }
}
