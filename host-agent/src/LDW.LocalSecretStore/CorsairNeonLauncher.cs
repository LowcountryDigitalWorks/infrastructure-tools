using System.Diagnostics;
using System.Text;

namespace LDW.LocalSecretStore;

public sealed record CorsairNeonLaunchResult(bool Success, int ExitCode, string SanitizedStdout, string SanitizedStderr, string? ErrorCode = null);

/// <summary>Runs only the fixed, non-networking secret-presence probe shipped beside the host.</summary>
public sealed class CorsairNeonLauncher
{
    public const string SecretEnvironmentVariable = "LDW_CORSAIR_NEON_SECRET";
    private const string ExpectedOutput = "SECRET_PRESENT";
    private const int MaximumCapturedCharacters = 256;
    private readonly LocalSecretStore _secretStore;

    public CorsairNeonLauncher(LocalSecretStore secretStore) =>
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));

    public async Task<CorsairNeonLaunchResult> LaunchProofProcessAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return Failure("UNSUPPORTED_PLATFORM");

        string? secret;
        try { secret = _secretStore.GetSecretValueInMemory(LocalSecretStore.FixedSecretIdCorsairNeon); }
        catch { return Failure("SECRET_STORE_UNAVAILABLE"); }
        if (string.IsNullOrEmpty(secret))
            return Failure("SECRET_MISSING");

        var probePath = Path.Combine(AppContext.BaseDirectory, "LDW.LocalSecretProbe.exe");
        if (!File.Exists(probePath))
            return Failure("PROBE_UNAVAILABLE");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = probePath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = AppContext.BaseDirectory
            }
        };
        process.StartInfo.Environment[SecretEnvironmentVariable] = secret;
        try
        {
            if (!process.Start()) return Failure("PROBE_START_FAILED");
            secret = null;
            var stdoutTask = ReadBoundedAsync(process.StandardOutput, MaximumCapturedCharacters, cancellationToken);
            var stderrTask = ReadBoundedAsync(process.StandardError, MaximumCapturedCharacters, cancellationToken);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            var success = process.ExitCode == 0 && !stdout.Truncated && !stderr.Truncated
                && string.Equals(stdout.Text.Trim(), ExpectedOutput, StringComparison.Ordinal)
                && string.IsNullOrEmpty(stderr.Text);
            return success
                ? new CorsairNeonLaunchResult(true, 0, ExpectedOutput, string.Empty)
                : Failure("PROBE_RESULT_INVALID", process.ExitCode);
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            return Failure("PROBE_CANCELLED");
        }
        catch
        {
            return Failure("PROBE_FAILED");
        }
        finally
        {
            process.StartInfo.Environment.Remove(SecretEnvironmentVariable);
            secret = null;
        }
    }

    private static CorsairNeonLaunchResult Failure(string code, int exitCode = -1) =>
        new(false, exitCode, string.Empty, string.Empty, code);

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(StreamReader reader, int maximumCharacters, CancellationToken cancellationToken)
    {
        var result = new StringBuilder(maximumCharacters);
        var buffer = new char[128];
        var truncated = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
        {
            var remaining = maximumCharacters - result.Length;
            if (remaining > 0) result.Append(buffer, 0, Math.Min(remaining, count));
            if (count > remaining) truncated = true;
        }
        return (result.ToString(), truncated);
    }
}
