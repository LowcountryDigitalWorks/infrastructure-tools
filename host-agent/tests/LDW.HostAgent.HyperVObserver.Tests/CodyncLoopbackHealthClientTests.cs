using System.Net;
using System.Net.Sockets;
using LDW.HostAgent.Core;
using LDW.HostAgent.Windows;

namespace LDW.HostAgent.HyperVObserver.Tests;

internal static class CodyncLoopbackHealthClientTests
{
    internal static void Run(Action<bool, string> assert)
    {
        // 1. Verifies fixed loopback endpoint is targeted by the client
        HttpRequestMessage? capturedRequest = null;
        var handler = new MockHttpHandler(req =>
        {
            capturedRequest = req;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true,\"secret\":\"private-payload\"}")
            };
        });

        using (var httpClient = new HttpClient(handler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();

            assert(capturedRequest is not null, "client must send an HTTP request");
            assert(capturedRequest!.RequestUri == CodyncHealthContract.EndpointUri, "client must strictly target fixed loopback endpoint");
            assert(capturedRequest.Method == HttpMethod.Get, "client must use GET method");
            assert(capturedRequest.RequestUri!.Host == "127.0.0.1", "target host must be 127.0.0.1");
            assert(capturedRequest.RequestUri.Port == 19222, "target port must be 19222");
            assert(capturedRequest.RequestUri.AbsolutePath == "/health", "target path must be /health");
            assert(result.HttpStatusCode == 200, "successful probe must return HTTP 200");
            assert(!result.TimedOut && !result.ConnectionRefused && !result.Unavailable, "successful probe must not report failure flags");
        }

        // 2. Non-200 responses (e.g. 500, 404)
        var error500Handler = new MockHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("{\"error\":\"Internal server error details\"}")
        });
        using (var httpClient = new HttpClient(error500Handler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.HttpStatusCode == 500, "server error must report status code 500");
            assert(!result.TimedOut && !result.ConnectionRefused && !result.Unavailable, "server error reports code without socket failure flags");
        }

        var error404Handler = new MockHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using (var httpClient = new HttpClient(error404Handler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.HttpStatusCode == 404, "not found must report status code 404");
        }

        // 3. Timeout handling
        var timeoutHandler = new MockHttpHandler(_ => throw new TaskCanceledException("simulated client timeout"));
        using (var httpClient = new HttpClient(timeoutHandler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.TimedOut, "timeout exception must set TimedOut flag");
            assert(result.HttpStatusCode is null, "timed out probe has no status code");
        }

        // 4. Connection refused handling
        var connectionRefusedHandler = new MockHttpHandler(_ =>
            throw new HttpRequestException("connection refused", new SocketException((int)SocketError.ConnectionRefused)));
        using (var httpClient = new HttpClient(connectionRefusedHandler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.ConnectionRefused, "SocketError.ConnectionRefused must set ConnectionRefused flag");
            assert(!result.Unavailable, "connection refused must distinguish from generic unavailable");
        }

        // Direct SocketException with ConnectionRefused
        var directSocketRefusedHandler = new MockHttpHandler(_ =>
            throw new SocketException((int)SocketError.ConnectionRefused));
        using (var httpClient = new HttpClient(directSocketRefusedHandler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.ConnectionRefused, "direct SocketException with ConnectionRefused sets flag");
        }

        // 5. Generic network failure / unavailable
        var genericNetworkHandler = new MockHttpHandler(_ =>
            throw new HttpRequestException("network down"));
        using (var httpClient = new HttpClient(genericNetworkHandler))
        {
            var client = new CodyncLoopbackHealthClient(httpClient);
            var result = client.ProbeHealthAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            assert(result.Unavailable, "generic network error sets Unavailable flag");
            assert(!result.ConnectionRefused, "generic error is not connection refused");
        }

        // 6. Definition and Snapshot integration through HostAgentLiveSnapshotProvider
        var settingsResult = HostAgentSettingsLoader.Load();
        var mockHealthyClient = new MockCodyncHealthClient(new CodyncProbeResult(200));
        var provider = new HostAgentLiveSnapshotProvider(settingsResult, mockHealthyClient);

        // Verify Definition has dev.codync-host
        var snapshot = provider.ObserveAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        var codyncComponent = snapshot.Definition.Environments
            .SelectMany(e => e.Components)
            .FirstOrDefault(c => c.Id == HostAgentLiveSnapshotProvider.Ids.CodyncHost);

        assert(codyncComponent is not null, "Codync component must exist in DeviceDefinition");
        assert(codyncComponent!.Kind == ComponentKind.CodyncHost, "Codync component kind must be CodyncHost");
        assert(codyncComponent.DesiredState == DesiredState.RunningAfterLogin, "Codync desired state must be RunningAfterLogin");
        assert(codyncComponent.Required, "Codync must be a required component");

        // Verify Observation appears in Snapshot
        var codyncObservation = snapshot.Snapshot.Components
            .FirstOrDefault(o => o.ComponentId == HostAgentLiveSnapshotProvider.Ids.CodyncHost);
        assert(codyncObservation is not null, "Codync observation must appear in DeviceSnapshot");
        assert(codyncObservation!.State == ObservedState.Running, "Healthy Codync observation must be Running");
        assert(codyncObservation.Health == HealthState.Healthy, "Healthy Codync observation must be Healthy");
        assert(codyncObservation.Color == StatusColor.Green, "Healthy Codync observation must be Green");

        // When Codync fails connection refused post-login => snapshot reflects Failed
        var mockRefusedClient = new MockCodyncHealthClient(new CodyncProbeResult(null, ConnectionRefused: true));
        var failedProvider = new HostAgentLiveSnapshotProvider(settingsResult, mockRefusedClient);
        var failedSnapshot = failedProvider.ObserveAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        var failedObservation = failedSnapshot.Snapshot.Components
            .First(o => o.ComponentId == HostAgentLiveSnapshotProvider.Ids.CodyncHost);

        // Post-login active session without settle window fails
        if (failedSnapshot.RuntimeContext.OwnerSession == OwnerSessionState.Active && !failedSnapshot.RuntimeContext.OwnerSessionSettling)
        {
            assert(failedObservation.Health == HealthState.Failed, "failed Codync must evaluate to Failed post-login");
            assert(failedSnapshot.Snapshot.Health == HealthState.Failed, "device aggregate must be Failed when required Codync is failed");
            assert(failedSnapshot.Snapshot.Color == StatusColor.Red, "device aggregate color must be Red when required Codync is failed");
        }
    }

    private sealed class MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(send(request));
        }
    }

    private sealed class MockCodyncHealthClient(CodyncProbeResult result) : ICodyncHealthClient
    {
        public ValueTask<CodyncProbeResult> ProbeHealthAsync(CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(result);
        }
    }
}
