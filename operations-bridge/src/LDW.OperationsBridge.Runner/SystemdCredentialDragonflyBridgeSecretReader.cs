using System.Security;
using System.Text;

namespace LDW.OperationsBridge.Runner;

public sealed class SystemdCredentialDragonflyBridgeSecretReader : IDragonflyBridgeSecretReader
{
    public const string CredentialName = "dragonfly-bridge-token";
    public const string UnitName = "ldw-operations-bridge-dragonfly.service";
    public const string ExpectedCredentialDirectory = "/run/credentials/" + UnitName;
    public const int MaxTokenChars = SecretServiceDragonflyBridgeSecretReader.MaxTokenChars;

    public string ReadToken()
    {
        if (!OperatingSystem.IsLinux())
            throw Unavailable();

        try
        {
            var directory = Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY");
            var path = CredentialPathForDirectory(directory);
            VerifyCredentialPath(path);
            return NormalizeCredentialText(File.ReadAllText(path, new UTF8Encoding(false, true)));
        }
        catch (DragonflyBridgeSecretUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or InvalidOperationException or DecoderFallbackException)
        {
            throw Unavailable();
        }
    }

    public static string CredentialPathForDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
            throw Unavailable();

        var canonical = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(canonical, ExpectedCredentialDirectory, StringComparison.Ordinal))
            throw Unavailable();

        return Path.Combine(canonical, CredentialName);
    }

    public static string NormalizeCredentialText(string value)
    {
        if (value.Length > MaxTokenChars + 2)
            throw Unavailable();

        var token = value.TrimEnd('\r', '\n');
        if (string.IsNullOrWhiteSpace(token) ||
            token.Length > MaxTokenChars ||
            token.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw Unavailable();

        return token;
    }

    public static bool IsExactCredentialMode(UnixFileMode mode)
        => mode == UnixFileMode.UserRead;

    private static void VerifyCredentialPath(string path)
    {
        var directory = new DirectoryInfo(ExpectedCredentialDirectory);
        directory.Refresh();
        if (!directory.Exists || directory.LinkTarget is not null)
            throw Unavailable();

        var info = new FileInfo(path);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > MaxTokenChars + 2)
            throw Unavailable();

        if (!IsExactCredentialMode(File.GetUnixFileMode(path)))
            throw Unavailable();
    }

    private static DragonflyBridgeSecretUnavailableException Unavailable()
        => new();
}

public static class DragonflyBridgeSecretReaderFactory
{
    public static IDragonflyBridgeSecretReader Create()
        => Create(Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY"));

    public static IDragonflyBridgeSecretReader Create(string? credentialDirectory)
        => string.IsNullOrEmpty(credentialDirectory)
            ? new SecretServiceDragonflyBridgeSecretReader()
            : new SystemdCredentialDragonflyBridgeSecretReader();
}
