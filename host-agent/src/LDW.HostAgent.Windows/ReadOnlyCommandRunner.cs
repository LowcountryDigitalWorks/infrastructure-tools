using System.Diagnostics;
using System.Text;

namespace LDW.HostAgent.Windows;

internal sealed record CommandResult(int ExitCode, string StdOut, string StdErr, bool TimedOut)
{
    public bool Success => !TimedOut && ExitCode == 0;
}

internal sealed class ReadOnlyCommandRunner
{
    private const int MaxCapturedChars = 128 * 1024;

    public async ValueTask<CommandResult> RunAsync(
        string executable,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            }
        };
        foreach (var argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);

        try
        {
            if (!process.Start())
                return new CommandResult(-1, string.Empty, string.Empty, false);
        }
        catch
        {
            return new CommandResult(-1, string.Empty, string.Empty, false);
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new CommandResult(process.ExitCode, Limit(stdout), Limit(stderr), false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            return new CommandResult(-1, string.Empty, string.Empty, true);
        }
        catch
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            return new CommandResult(-1, string.Empty, string.Empty, false);
        }
    }

    private static string Limit(string value)
        => value.Length <= MaxCapturedChars ? value : value[..MaxCapturedChars];
}
