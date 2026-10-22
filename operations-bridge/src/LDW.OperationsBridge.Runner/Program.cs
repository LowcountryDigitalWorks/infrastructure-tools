using System.Security;
using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Runner;

internal static class Program
{
    private static readonly TimeSpan HealthInterval = TimeSpan.FromSeconds(10);
    private static readonly string MutexName = @"Local\LDW.OperationsBridge.Runner.BRIDGE001A";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--status")
        {
            Console.WriteLine("{\"state\":\"" + BridgeRunnerHealthStore.ReadState() + "\"}");
            return 0;
        }
        if (args.Length != 1 || args[0] != "--run")
        {
            Console.Error.WriteLine("Usage: LDW.OperationsBridge.Runner --run | --status");
            return 2;
        }
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Bridge runner requires Windows.");
            return 3;
        }

        using var singleInstance = new Mutex(false, MutexName);
        var ownsMutex = false;
        try
        {
            try { ownsMutex = singleInstance.WaitOne(0); }
            catch (AbandonedMutexException) { ownsMutex = true; }
            if (!ownsMutex)
            {
                Console.Error.WriteLine("Bridge runner is already active.");
                return 4;
            }

            using var cancellation = new CancellationTokenSource();
            ConsoleCancelEventHandler cancel = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };
            Console.CancelKeyPress += cancel;
            try { return await RunLoopAsync(cancellation.Token).ConfigureAwait(false); }
            finally
            {
                Console.CancelKeyPress -= cancel;
                BridgeRunnerHealthStore.Write("stopped", "ldw01-bridge");
            }
        }
        catch (Exception ex)
        {
            BridgeRunnerHealthStore.Write("blocked", "ldw01-bridge");
            Console.Error.WriteLine("Bridge runner failed closed: " + ex.GetType().Name);
            return 5;
        }
        finally
        {
            if (ownsMutex)
                singleInstance.ReleaseMutex();
        }
    }

    private static async Task<int> RunLoopAsync(CancellationToken cancellationToken)
    {
        var configuration = BridgeRunnerConfiguration.Load();
        var bearer = new CurrentUserDpapiSecretReader().ReadToken(BridgeRunnerConfiguration.ProtectedTokenPath);
        if (string.IsNullOrWhiteSpace(bearer))
            throw new SecurityException("Bridge credential is unavailable.");

        var adapter = new OperaDevtoolsMcpBrowserAdapter();
        var validator = new DispatchValidator([configuration.BridgeId], BridgeProtocol.AllowedReadOnlyOperations);
        var client = new OutboundBridgeClient(configuration.BridgeId, adapter, validator);
        var backoffSeconds = new[] { 2, 4, 8, 16, 30 };
        var attempt = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            BridgeRunnerHealthStore.Write("connecting", configuration.BridgeId);
            await using var transport = new ClientWebSocketBridgeTransport();
            client.Attach(transport);
            try
            {
                using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectTimeout.CancelAfter(TimeSpan.FromSeconds(20));
                await transport.ConnectAsync(configuration.RelayConnectUri, bearer,
                    [new TrustedRelayEndpoint(configuration.RelayConnectUri)], connectTimeout.Token).ConfigureAwait(false);
                attempt = 0;
                BridgeRunnerHealthStore.Write("connected", configuration.BridgeId);

                while (!cancellationToken.IsCancellationRequested && !transport.Completion.IsCompleted)
                {
                    var pulse = Task.Delay(HealthInterval, cancellationToken);
                    var finished = await Task.WhenAny(transport.Completion, pulse).ConfigureAwait(false);
                    if (finished == pulse && !cancellationToken.IsCancellationRequested)
                        BridgeRunnerHealthStore.Write("connected", configuration.BridgeId);
                }
                if (cancellationToken.IsCancellationRequested)
                    break;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch { BridgeRunnerHealthStore.Write("degraded", configuration.BridgeId); }

            if (cancellationToken.IsCancellationRequested)
                break;
            BridgeRunnerHealthStore.Write("degraded", configuration.BridgeId);
            var delay = backoffSeconds[Math.Min(attempt, backoffSeconds.Length - 1)];
            attempt = Math.Min(attempt + 1, backoffSeconds.Length - 1);
            try { await Task.Delay(TimeSpan.FromSeconds(delay), cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        }
        return 0;
    }
}
