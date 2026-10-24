using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

/// <summary>
/// Smallest outbound ClientWebSocket transport for BRIDGE-001A receive/result flow.
/// No local inbound listener is created.
/// </summary>
public sealed class ClientWebSocketBridgeTransport : IBridgeTransport, IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly ClientWebSocket _socket = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveLoop;

    public event Func<BridgeDispatchRequest, string, CancellationToken, Task>? DispatchReceived;

    public bool IsConnected => _socket.State == WebSocketState.Open;

    public Task Completion => _receiveLoop ?? Task.CompletedTask;

    public async Task ConnectAsync(
        Uri relayConnectUri,
        string bridgeBearerToken,
        IReadOnlyCollection<TrustedRelayEndpoint> trustedRelayEndpoints,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(relayConnectUri);
        if (string.IsNullOrWhiteSpace(bridgeBearerToken))
        {
            throw new ArgumentException("Bridge bearer token is required.", nameof(bridgeBearerToken));
        }

        // Fail closed before attaching/sending the Bridge bearer token.
        BridgeConnectGuard.EnsureTrustedSecureEndpoint(relayConnectUri, trustedRelayEndpoints);

        if (_socket.State != WebSocketState.None)
        {
            throw new InvalidOperationException("Transport socket has already been used.");
        }

        _socket.Options.SetRequestHeader("Authorization", $"Bearer {bridgeBearerToken}");
        foreach (var header in BridgeConnectIdentityHeaders.Create())
        {
            _socket.Options.SetRequestHeader(header.Key, header.Value);
        }
        await _socket.ConnectAsync(relayConnectUri, cancellationToken).ConfigureAwait(false);

        _receiveCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _receiveLoop = ReceiveLoopAsync(_receiveCts.Token);
    }

    public async Task SendResultAsync(BridgeDispatchResult result, CancellationToken cancellationToken)
    {
        var wire = ToTerminalWireMessage(result);
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(wire, JsonOptions));
        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_socket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException("WebSocket is not open.");
            }

            await _socket.SendAsync(bytes, WebSocketMessageType.Text, endOfMessage: true, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _sendGate.Release();
        }
    }

    public static bool TryParseDispatchMessage(string json, out BridgeDispatchRequest? request, out string error)
    {
        request = null;
        error = "invalid-dispatch-message";
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (!root.TryGetProperty("type", out var typeElement) ||
                !string.Equals(typeElement.GetString(), "dispatch", StringComparison.Ordinal))
            {
                error = "not-dispatch";
                return false;
            }

            var protocolVersion = root.GetProperty("protocolVersion").GetString();
            var dispatchIdText = root.GetProperty("dispatchId").GetString();
            var bridgeId = root.GetProperty("bridgeId").GetString();
            var operationText = root.GetProperty("operation").GetString();
            var issuedAtText = root.GetProperty("issuedAt").GetString();
            var expiresAtText = root.GetProperty("expiresAt").GetString();
            var idempotencyKey = root.GetProperty("idempotencyKey").GetString();
            var correlationId = root.GetProperty("correlationId").GetString();

            if (!Guid.TryParse(dispatchIdText, out var dispatchId) ||
                !DateTimeOffset.TryParse(issuedAtText, out var issuedAt) ||
                !DateTimeOffset.TryParse(expiresAtText, out var expiresAt) ||
                !BridgeProtocol.TryParseWireOperation(operationText, out var operation) ||
                string.IsNullOrWhiteSpace(protocolVersion) ||
                string.IsNullOrWhiteSpace(bridgeId) ||
                string.IsNullOrWhiteSpace(idempotencyKey) ||
                string.IsNullOrWhiteSpace(correlationId))
            {
                error = "invalid-envelope-fields";
                return false;
            }

            var args = new Dictionary<string, string>(StringComparer.Ordinal);
            if (root.TryGetProperty("args", out var argsElement) && argsElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in argsElement.EnumerateObject())
                {
                    if (args.Count >= BridgeProtocol.MaxArgEntries)
                    {
                        error = "args-overflow";
                        return false;
                    }

                    var value = property.Value.ValueKind == JsonValueKind.String
                        ? property.Value.GetString() ?? string.Empty
                        : property.Value.ToString();
                    if (value.Length > (operation == BridgeOperation.CodyncSendExact && property.Name == "text"
                        ? BridgeProtocol.MaxCodyncSendTextLength
                        : BridgeProtocol.MaxArgValueLength))
                    {
                        error = "arg-value-too-long";
                        return false;
                    }

                    args[property.Name] = value;
                }
            }

            request = new BridgeDispatchRequest(
                protocolVersion,
                dispatchId,
                bridgeId,
                operation,
                issuedAt,
                expiresAt,
                idempotencyKey,
                correlationId,
                args);
            error = string.Empty;
            return true;
        }
        catch (Exception)
        {
            error = "parse-failed";
            return false;
        }
    }

    public static object ToTerminalWireMessage(BridgeDispatchResult result)
    {
        if (!result.StartedAt.HasValue ||
            !BridgeProtocol.TryObserveBridgeRuntime(result.BridgeRuntime, out var runtime) ||
            !BridgeProtocol.TryObserveBridgeVersion(result.BridgeVersion, out var version))
        {
            throw new InvalidOperationException("Client terminal wire requires observed startedAt/runtime/version.");
        }

        return new
        {
            type = "terminal",
            dispatchId = result.DispatchId.ToString("D"),
            idempotencyKey = result.IdempotencyKey,
            correlationId = result.CorrelationId,
            bridgeRuntime = runtime,
            bridgeVersion = version,
            operation = result.OperationClass,
            resultClass = result.ResultClass,
            status = BridgeProtocol.ToWireTerminalStatus(result.TerminalStatus),
            startedAt = result.StartedAt.Value.ToString("O"),
            completedAt = result.CompletedAt.ToString("O"),
            evidence = BridgeProtocol.BoundEvidence(result.Evidence),
            payload = BridgeProtocol.BoundPayload(result.Payload, result.Operation)
        };
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];
        var builder = new StringBuilder();

        while (!cancellationToken.IsCancellationRequested && _socket.State == WebSocketState.Open)
        {
            ValueWebSocketReceiveResult receive;
            try
            {
                receive = await _socket.ReceiveAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            if (receive.MessageType == WebSocketMessageType.Close)
            {
                break;
            }

            if (receive.MessageType != WebSocketMessageType.Text)
            {
                continue;
            }

            builder.Append(Encoding.UTF8.GetString(buffer, 0, receive.Count));
            if (!receive.EndOfMessage)
            {
                continue;
            }

            var message = builder.ToString();
            builder.Clear();

            if (!TryParseDispatchMessage(message, out var request, out _) || request is null)
            {
                continue;
            }

            var handler = DispatchReceived;
            if (handler is not null)
            {
                try
                {
                    await handler(request, "local-outbound", cancellationToken).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Adapter/handler faults must not leave the receive loop crashed without a
                    // terminal outcome; OutboundBridgeClient catches and emits FAILED. Any
                    // remaining fault is swallowed so the socket can continue for other work.
                }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_receiveCts is not null)
        {
            await _receiveCts.CancelAsync().ConfigureAwait(false);
        }

        if (_receiveLoop is not null)
        {
            try
            {
                await _receiveLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        if (_socket.State is WebSocketState.Open or WebSocketState.CloseReceived or WebSocketState.CloseSent)
        {
            try
            {
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "dispose", CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (WebSocketException)
            {
            }
        }

        _socket.Dispose();
        _sendGate.Dispose();
        _receiveCts?.Dispose();
    }
}

internal static class BridgeConnectIdentityHeaders
{
    public static IReadOnlyDictionary<string, string> Create() => new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["X-LDW-Protocol-Version"] = BridgeProtocol.Version,
        ["X-LDW-Bridge-Runtime"] = BridgeProtocol.BridgeRuntime,
        ["X-LDW-Bridge-Version"] = BridgeProtocol.BridgeRuntimeVersion
    };
}
