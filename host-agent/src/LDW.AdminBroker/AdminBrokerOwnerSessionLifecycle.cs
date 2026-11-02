namespace LDW.AdminBroker;

public enum AdminBrokerLifecycleState
{
    Starting,
    Ready,
    Recovering,
    Failed,
    Stopped
}

/// <summary>Runs one bounded owner-session pipe accept cycle at a time.</summary>
public static class AdminBrokerOwnerSessionLifecycle
{
    private const int MaximumConsecutiveFailures = 3;

    public static Task RunAsync(
        Func<CancellationToken, Task> serveOneRequestAsync,
        Action<AdminBrokerLifecycleState> reportState,
        CancellationToken cancellationToken) =>
        RunCoreAsync(serveOneRequestAsync, reportState, cancellationToken, MaximumConsecutiveFailures, Task.Delay);

    internal static async Task RunCoreAsync(
        Func<CancellationToken, Task> serveOneRequestAsync,
        Action<AdminBrokerLifecycleState> reportState,
        CancellationToken cancellationToken,
        int maximumConsecutiveFailures,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
    {
        ArgumentNullException.ThrowIfNull(serveOneRequestAsync);
        ArgumentNullException.ThrowIfNull(reportState);
        ArgumentNullException.ThrowIfNull(delayAsync);
        if (maximumConsecutiveFailures < 1) throw new ArgumentOutOfRangeException(nameof(maximumConsecutiveFailures));

        var failures = 0;
        var terminalFailure = false;
        reportState(AdminBrokerLifecycleState.Starting);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await serveOneRequestAsync(cancellationToken).ConfigureAwait(false);
                    failures = 0;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch
                {
                    failures++;
                    if (failures >= maximumConsecutiveFailures)
                    {
                        terminalFailure = true;
                        reportState(AdminBrokerLifecycleState.Failed);
                        return;
                    }

                    reportState(AdminBrokerLifecycleState.Recovering);
                    try
                    {
                        await delayAsync(TimeSpan.FromMilliseconds(250 * (1 << (failures - 1))), cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            if (!terminalFailure) reportState(AdminBrokerLifecycleState.Stopped);
        }
    }
}
