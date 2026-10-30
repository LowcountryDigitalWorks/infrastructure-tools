using System.Runtime.InteropServices;
using System.Text;

namespace LDW.OperationsBridge.Runner;

public sealed class SystemdCredentialDragonflyBridgeSecretReader : IDragonflyBridgeSecretReader
{
    public const string CredentialSourceEnvironment = "LDW_DRAGONFLY_CREDENTIAL_SOURCE";
    public const string SystemdCredentialSource = "systemd";
    public const string CredentialsDirectoryEnvironment = "CREDENTIALS_DIRECTORY";
    public const string UnitName = "ldw-operations-bridge-dragonfly.service";
    public const string CredentialName = "bridge-bearer";
    public const string ExpectedCredentialsDirectory = "/run/credentials/" + UnitName;
    public const string ExpectedCredentialPath = ExpectedCredentialsDirectory + "/" + CredentialName;
    public const int MaxTokenChars = SecretServiceDragonflyBridgeSecretReader.MaxTokenChars;

    public string ReadToken()
    {
        if (!OperatingSystem.IsLinux())
            throw Unavailable();

        try
        {
            var effectiveUserId = GetEffectiveUserId();
            if (effectiveUserId != 1000)
                throw Unavailable();

            var path = ResolveCredentialPath(
                Environment.GetEnvironmentVariable(CredentialSourceEnvironment),
                Environment.GetEnvironmentVariable(CredentialsDirectoryEnvironment));

            var directory = new DirectoryInfo(ExpectedCredentialsDirectory);
            directory.Refresh();
            if (!directory.Exists || directory.LinkTarget is not null)
                throw Unavailable();

            var info = new FileInfo(path);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > MaxTokenChars + 2)
                throw Unavailable();

            var mode = File.GetUnixFileMode(path);
            if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                         UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw Unavailable();

            var text = File.ReadAllText(path, new UTF8Encoding(false, true));
            return NormalizeCredentialResult(text);
        }
        catch (DragonflyBridgeSecretUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or DecoderFallbackException or DllNotFoundException or EntryPointNotFoundException)
        {
            throw Unavailable();
        }
    }

    public static string ResolveCredentialPath(string? source, string? credentialsDirectory)
    {
        if (!string.Equals(source, SystemdCredentialSource, StringComparison.Ordinal) ||
            !string.Equals(credentialsDirectory, ExpectedCredentialsDirectory, StringComparison.Ordinal))
            throw Unavailable();

        return ExpectedCredentialPath;
    }

    public static string NormalizeCredentialResult(string text)
    {
        if (text.Length > MaxTokenChars + 2)
            throw Unavailable();

        var token = text.TrimEnd('\r', '\n');
        if (string.IsNullOrWhiteSpace(token) || token.Length > MaxTokenChars ||
            token.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw Unavailable();

        return token;
    }

    private static DragonflyBridgeSecretUnavailableException Unavailable()
        => new();

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}
