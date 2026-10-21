using System.Diagnostics;

namespace LDW.LocalSecretStore;

public sealed record CorsairNeonLaunchResult(
    bool Success,
    int ExitCode,
    string SanitizedStdout,
    string SanitizedStderr,
    string? ErrorCode = null);

public sealed class CorsairNeonLauncher
{
    private readonly LocalSecretStore _secretStore;

    public CorsairNeonLauncher(LocalSecretStore secretStore)
    {
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
    }

    public async Task<CorsairNeonLaunchResult> LaunchProofProcessAsync(
        string executablePath,
        string[] arguments,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "EXECUTABLE_NOT_FOUND");
        }

        if ((Path.IsPathRooted(executablePath) || executablePath.Contains(Path.DirectorySeparatorChar)) && !File.Exists(executablePath))
        {
            return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "EXECUTABLE_NOT_FOUND");
        }

        var secretValue = _secretStore.GetSecretValueInMemory(LocalSecretStore.FixedSecretIdCorsairNeon);
        if (string.IsNullOrEmpty(secretValue))
        {
            return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "SECRET_NOT_FOUND");
        }

        using var process = new Process();
        process.StartInfo.FileName = executablePath;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.CreateNoWindow = true;

        foreach (var arg in arguments)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        // Inject secret as environment variable into child process
        process.StartInfo.EnvironmentVariables[LocalSecretStore.FixedSecretIdCorsairNeon] = secretValue;

        try
        {
            if (!process.Start())
            {
                return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "PROCESS_START_FAILED");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

            await process.WaitForExitAsync(timeoutCts.Token);

            var rawStdout = await stdoutTask;
            var rawStderr = await stderrTask;

            // Sanitize standard output and error to guarantee secret is never leaked
            var sanitizedStdout = SanitizeText(rawStdout, secretValue);
            var sanitizedStderr = SanitizeText(rawStderr, secretValue);

            return new CorsairNeonLaunchResult(
                process.ExitCode == 0,
                process.ExitCode,
                sanitizedStdout,
                sanitizedStderr,
                process.ExitCode == 0 ? null : $"PROCESS_EXIT_CODE_{process.ExitCode}");
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch { }

            return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "PROCESS_TIMED_OUT");
        }
        catch (Exception ex)
        {
            return new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, $"PROCESS_ERROR_{ex.GetType().Name}");
        }
    }

    public static string SanitizeText(string input, string? secretToRedact)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        if (string.IsNullOrEmpty(secretToRedact))
            return input;

        return input.Replace(secretToRedact, "[REDACTED_SECRET]", StringComparison.OrdinalIgnoreCase);
    }
}
