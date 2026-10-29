using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace LDW.OperationsBridge.Runner;

public sealed class SecretServiceDragonflyBridgeSecretReader : IDragonflyBridgeSecretReader
{
    public const string SecretToolPath = "/usr/bin/secret-tool";
    public const string ServiceAttribute = "ldw-operations-bridge";
    public const int MaxTokenChars = 4096;
    private const int MaxDiagnosticChars = 4096;
    private static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(10);

    public string ReadToken()
    {
        if (!OperatingSystem.IsLinux())
            throw Unavailable();

        // A system service with LoadCredentialEncrypted= is a separate trust mode.
        // Once systemd advertises a credential directory, fail closed inside that
        // provider and never fall back to the interactive Secret Service/keyring.
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY")))
            return new SystemdCredentialDragonflyBridgeSecretReader().ReadToken();

        try
        {
            VerifySecretTool();
            var effectiveUserId = GetEffectiveUserId();
            if (effectiveUserId == 0)
                throw Unavailable();

            return ReadTokenCoreAsync(effectiveUserId).GetAwaiter().GetResult();
        }
        catch (DragonflyBridgeSecretUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or SecurityException or InvalidOperationException or DllNotFoundException or EntryPointNotFoundException)
        {
            throw Unavailable();
        }
    }

    public static ProcessStartInfo CreateLookupStartInfo(uint effectiveUserId)
    {
        if (effectiveUserId == 0)
            throw new ArgumentOutOfRangeException(nameof(effectiveUserId), "Dragonfly Bridge must run as a normal user.");

        var runtimeDirectory = $"/run/user/{effectiveUserId}";
        var startInfo = new ProcessStartInfo
        {
            FileName = SecretToolPath,
            UseShellExecute = false,
            RedirectStandardInput = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        startInfo.ArgumentList.Add("lookup");
        startInfo.ArgumentList.Add("service");
        startInfo.ArgumentList.Add(ServiceAttribute);
        startInfo.ArgumentList.Add("bridge-id");
        startInfo.ArgumentList.Add(DragonflyBridgeRunnerConfiguration.FixedBridgeId);

        startInfo.Environment.Clear();
        startInfo.Environment["XDG_RUNTIME_DIR"] = runtimeDirectory;
        startInfo.Environment["DBUS_SESSION_BUS_ADDRESS"] = $"unix:path={runtimeDirectory}/bus";

        return startInfo;
    }

    public static string NormalizeLookupResult(int exitCode, string standardOutput)
    {
        if (exitCode != 0 || standardOutput.Length > MaxTokenChars + 2)
            throw Unavailable();

        var token = standardOutput.TrimEnd('\r', '\n');
        if (string.IsNullOrWhiteSpace(token) ||
            token.Length > MaxTokenChars ||
            token.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw Unavailable();

        return token;
    }

    private static void VerifySecretTool()
    {
        var info = new FileInfo(SecretToolPath);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null)
            throw Unavailable();

        var mode = File.GetUnixFileMode(SecretToolPath);
        if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw Unavailable();
    }

    private static async Task<string> ReadTokenCoreAsync(uint effectiveUserId)
    {
        using var timeout = new CancellationTokenSource(LookupTimeout);
        using var process = new Process { StartInfo = CreateLookupStartInfo(effectiveUserId) };

        if (!process.Start())
            throw Unavailable();

        try
        {
            var stdoutTask = ReadBoundedAsync(process.StandardOutput, MaxTokenChars + 2, timeout.Token);
            var stderrTask = DrainBoundedAsync(process.StandardError, MaxDiagnosticChars, timeout.Token);

            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var standardOutput = await stdoutTask.ConfigureAwait(false);
            await stderrTask.ConfigureAwait(false);

            return NormalizeLookupResult(process.ExitCode, standardOutput);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            TryKill(process);
            throw Unavailable();
        }
        catch (InvalidDataException)
        {
            TryKill(process);
            throw Unavailable();
        }
        finally
        {
            if (!process.HasExited)
                TryKill(process);
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        var buffer = new char[512];

        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (count == 0)
                return builder.ToString();
            if (builder.Length + count > maxChars)
                throw new InvalidDataException("Secret lookup output exceeded its bound.");
            builder.Append(buffer, 0, count);
        }
    }

    private static async Task DrainBoundedAsync(StreamReader reader, int maxChars, CancellationToken cancellationToken)
    {
        var total = 0;
        var buffer = new char[512];

        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (count == 0)
                return;
            total += count;
            if (total > maxChars)
                throw new InvalidDataException("Secret lookup diagnostic output exceeded its bound.");
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(1000);
            }
        }
        catch
        {
            // Fail closed; cleanup errors are intentionally not surfaced with raw process details.
        }
    }

    private static DragonflyBridgeSecretUnavailableException Unavailable()
        => new();

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}
