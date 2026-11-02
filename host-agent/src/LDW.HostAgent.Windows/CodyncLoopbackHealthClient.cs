using System.Net.Sockets;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class CodyncLoopbackHealthClient : ICodyncHealthClient
{
    private readonly HttpClient _httpClient;

    public CodyncLoopbackHealthClient(HttpClient? httpClient = null)
    {
        if (httpClient is not null)
        {
            _httpClient = httpClient;
        }
        else
        {
            var handler = new SocketsHttpHandler
            {
                ConnectTimeout = TimeSpan.FromSeconds(2),
                AutomaticDecompression = System.Net.DecompressionMethods.None
            };
            _httpClient = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(3)
            };
        }
    }

    public async ValueTask<CodyncProbeResult> ProbeHealthAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Strictly hard-coded to the fixed loopback URI only. Never accepts caller URL input.
            using var response = await _httpClient.GetAsync(
                CodyncHealthContract.EndpointUri,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            // Strictly ignore/discard response body to prevent leakage. Only HTTP status code is captured.
            return new CodyncProbeResult((int)response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new CodyncProbeResult(null, TimedOut: true);
        }
        catch (HttpRequestException ex)
        {
            var isConnectionRefused = ex.InnerException is SocketException se &&
                se.SocketErrorCode is SocketError.ConnectionRefused;
            return new CodyncProbeResult(null, ConnectionRefused: isConnectionRefused, Unavailable: !isConnectionRefused);
        }
        catch (SocketException se) when (se.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return new CodyncProbeResult(null, ConnectionRefused: true);
        }
        catch
        {
            return new CodyncProbeResult(null, Unavailable: true);
        }
    }
}
