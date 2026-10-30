using LDW.OperationsBridge.Runner;

internal static class DragonflySystemdCredentialReaderTests
{
    public static void Run()
    {
        Assert(SystemdCredentialDragonflyBridgeSecretReader.CredentialSourceEnvironment == "LDW_DRAGONFLY_CREDENTIAL_SOURCE", "systemd credential selector name is fixed and non-secret");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.SystemdCredentialSource == "systemd", "systemd credential selector value is fixed");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.CredentialsDirectoryEnvironment == "CREDENTIALS_DIRECTORY", "systemd credential directory uses standard environment name");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.UnitName == "ldw-operations-bridge-dragonfly.service", "systemd credential reader binds exact unit name");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.CredentialName == "bridge-bearer", "systemd credential reader binds exact purpose name");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.ExpectedCredentialsDirectory == "/run/credentials/ldw-operations-bridge-dragonfly.service", "systemd credential directory is fixed rather than caller-controlled");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.ExpectedCredentialPath == "/run/credentials/ldw-operations-bridge-dragonfly.service/bridge-bearer", "systemd credential path is exact");

        Assert(
            SystemdCredentialDragonflyBridgeSecretReader.ResolveCredentialPath(
                "systemd",
                "/run/credentials/ldw-operations-bridge-dragonfly.service") ==
            SystemdCredentialDragonflyBridgeSecretReader.ExpectedCredentialPath,
            "exact systemd service context resolves only the reviewed credential path");

        foreach (var pair in new (string? Source, string? Directory)[]
        {
            (null, null),
            ("secret-service", "/run/credentials/ldw-operations-bridge-dragonfly.service"),
            ("systemd", null),
            ("systemd", "/tmp/credentials"),
            ("SYSTEMD", "/run/credentials/ldw-operations-bridge-dragonfly.service"),
        })
        {
            AssertThrows<DragonflyBridgeSecretUnavailableException>(
                () => SystemdCredentialDragonflyBridgeSecretReader.ResolveCredentialPath(pair.Source, pair.Directory),
                "systemd credential reader rejects selector/path drift");
        }

        const string token = "synthetic.systemd-token_123-ABC=";
        Assert(SystemdCredentialDragonflyBridgeSecretReader.NormalizeCredentialResult(token + "\n") == token, "systemd reader strips one trailing newline without changing token content");
        Assert(SystemdCredentialDragonflyBridgeSecretReader.NormalizeCredentialResult(token + "\r\n") == token, "systemd reader normalizes CRLF");
        foreach (var invalid in new[] { "", "   \n", "abc\ndef\n", "abc\tdef\n" })
        {
            AssertThrows<DragonflyBridgeSecretUnavailableException>(
                () => SystemdCredentialDragonflyBridgeSecretReader.NormalizeCredentialResult(invalid),
                "systemd reader rejects empty/whitespace/control-bearing credential content");
        }
        AssertThrows<DragonflyBridgeSecretUnavailableException>(
            () => SystemdCredentialDragonflyBridgeSecretReader.NormalizeCredentialResult(new string('x', SystemdCredentialDragonflyBridgeSecretReader.MaxTokenChars + 1)),
            "systemd reader rejects oversized credential content");
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
