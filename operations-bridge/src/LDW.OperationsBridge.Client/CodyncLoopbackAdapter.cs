using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

/// <summary>
/// Narrow client for Codync's supported loopback HTTP/SSE API. The bearer is supplied
/// by the host's protected credential provider and is never included in results/errors.
/// </summary>
public sealed class CodyncLoopbackAdapter : ICodyncBridgeAdapter, IDisposable
{
    private static readonly Uri BaseUri = new("http://127.0.0.1:19222/");
    private static readonly TimeSpan MaxWait = TimeSpan.FromMinutes(4);
    private readonly HttpClient _http;
    private readonly Func<CancellationToken, ValueTask<string>> _readBearer;
    private readonly ConcurrentDictionary<string, CodyncEventSubscription> _subscriptions = new(StringComparer.Ordinal);

    public CodyncLoopbackAdapter(Func<CancellationToken, ValueTask<string>> readBearer)
        : this(readBearer, new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        })
    {
    }

    internal CodyncLoopbackAdapter(Func<CancellationToken, ValueTask<string>> readBearer, HttpMessageHandler handler)
    {
        _http = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _readBearer = readBearer;
    }

    public void Dispose()
    {
        foreach (var subscription in _subscriptions.Values)
            subscription.Dispose();
        _subscriptions.Clear();
        _http.Dispose();
    }

    public async Task<CodyncHostHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        using var request = await AuthorizedRequestAsync(HttpMethod.Get, "health", cancellationToken).ConfigureAwait(false);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        EnsureSuccess(response);
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        return new CodyncHostHealth(
            root.TryGetProperty("ok", out var ok) && ok.GetBoolean(),
            ReadString(root, "version"),
            root.TryGetProperty("busy", out var busy) && busy.GetBoolean());
    }

    public async Task<IReadOnlyList<CodyncDestination>> ListApprovedBotsGroupsAsync(CancellationToken cancellationToken)
    {
        var found = new List<JsonElement>();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(TimeSpan.FromSeconds(10));
        using var request = await AuthorizedRequestAsync(HttpMethod.Get, "events?since=0", bounded.Token).ConfigureAwait(false);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, bounded.Token).ConfigureAwait(false);
        EnsureSuccess(response);
        await using var stream = await response.Content.ReadAsStreamAsync(bounded.Token).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        while (found.Count < CodyncApprovedDestinations.All.Count)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(bounded.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (bounded.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new InvalidOperationException("Codync approved roster was incomplete at the bounded catch-up deadline.");
            }
            if (line is null)
            {
                throw new InvalidOperationException("Codync event stream ended before the approved roster was complete.");
            }
            if (!line.StartsWith("data:", StringComparison.Ordinal))
            {
                continue;
            }

            using var eventDocument = JsonDocument.Parse(line[5..].Trim());
            var root = eventDocument.RootElement;
            if (ReadString(root, "type") != "bot" || !root.TryGetProperty("bot", out var bot))
            {
                continue;
            }
            var id = ReadString(bot, "id");
            if (CodyncApprovedDestinations.All.Any(item => item.Name == ReadString(bot, "name")))
            {
                if (found.Any(existing => ReadString(existing, "id") == id))
                {
                    throw new InvalidOperationException("Codync returned a duplicate reviewer destination identity.");
                }
                found.Add(bot.Clone());
            }
        }

        var result = new List<CodyncDestination>(CodyncApprovedDestinations.All.Count);
        foreach (var approved in CodyncApprovedDestinations.All)
        {
            var matches = found.Where(bot => ReadString(bot, "name") == approved.Name).ToArray();
            if (matches.Length != 1 || ReadString(matches[0], "id") != approved.Id || ReadString(matches[0], "kind") != (approved.Kind == "group" ? "group" : "agent"))
            {
                throw new InvalidOperationException("An approved Codync destination is missing, duplicated, or has a changed identity.");
            }
            var members = ReadStringArray(matches[0], "members");
            if (!members.SequenceEqual(approved.Members, StringComparer.Ordinal))
            {
                throw new InvalidOperationException("An approved Codync group has changed membership.");
            }
            result.Add(approved);
        }
        return result.AsReadOnly();
    }

    public async Task<CodyncSendReceipt> SendExactAsync(
        string destinationId,
        string destinationName,
        string text,
        string clientNonce,
        IReadOnlyList<string> mentionedMemberIds,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > BridgeProtocol.MaxCodyncSendTextLength || string.IsNullOrWhiteSpace(clientNonce))
        {
            throw new InvalidOperationException("Codync send arguments are invalid or exceed the bound.");
        }
        var approved = (await ListApprovedBotsGroupsAsync(cancellationToken).ConfigureAwait(false))
            .Where(item => item.Id == destinationId && item.Name == destinationName && item.Enabled).ToArray();
        if (approved.Length != 1)
        {
            throw new InvalidOperationException("Codync destination did not resolve to exactly one current approved identity.");
        }
        var destination = approved[0];
        if (destination.Kind == "group")
        {
            if (mentionedMemberIds.Count == 0 || mentionedMemberIds.Distinct(StringComparer.Ordinal).Count() != mentionedMemberIds.Count ||
                mentionedMemberIds.Any(id => !destination.Members.Contains(id, StringComparer.Ordinal)))
            {
                throw new InvalidOperationException("Group send requires explicit approved member targeting.");
            }
            foreach (var memberId in mentionedMemberIds)
            {
                var member = CodyncApprovedDestinations.All.Single(item => item.Id == memberId);
                if (!text.Contains("@" + member.Name, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Group send text must explicitly mention every selected member.");
                }
            }
            foreach (var memberId in destination.Members.Except(mentionedMemberIds, StringComparer.Ordinal))
            {
                var unselected = CodyncApprovedDestinations.All.Single(item => item.Id == memberId);
                if (text.Contains("@" + unselected.Name, StringComparison.Ordinal))
                    throw new InvalidOperationException("Group send text mentions a member outside the explicit target set.");
            }
        }
        else if (mentionedMemberIds.Count != 0)
        {
            throw new InvalidOperationException("Member targeting applies only to a group destination.");
        }

        var subscription = await OpenEventsBeforeSendAsync(cancellationToken).ConfigureAwait(false);
        var submittedAt = DateTimeOffset.UtcNow;
        try
        {
            using var request = await AuthorizedRequestAsync(HttpMethod.Post, "api/send", cancellationToken).ConfigureAwait(false);
            request.Content = JsonContent.Create(new { botId = destination.Id, text, clientNonce });
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            EnsureSuccess(response);
            using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!document.RootElement.TryGetProperty("entry", out var entry) ||
                ReadString(entry, "botId") != destination.Id || ReadString(entry, "kind") != "user" ||
                !entry.TryGetProperty("data", out var data) || ReadString(data, "clientNonce") != clientNonce)
            {
                throw new InvalidOperationException("Codync did not return the exact nonce-correlated send receipt.");
            }
            var receipt = new CodyncSendReceipt(destination.Id, destination.Name, clientNonce,
                ReadString(entry, "id"), ReadInt64(entry, "seq"), ReadInt64(entry, "turn"), ReadInt64(entry, "rev"), submittedAt);
            if (string.IsNullOrWhiteSpace(receipt.RootEntryId) || receipt.RootTurn < 1 || !_subscriptions.TryAdd(receipt.RootEntryId, subscription))
                throw new InvalidOperationException("Codync send receipt was invalid or duplicated.");
            return receipt;
        }
        catch
        {
            subscription.Dispose();
            throw;
        }
    }

    public async Task<CodyncWaitResult> WaitReadExactAsync(
        CodyncSendReceipt receipt,
        string expectedAuthorId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero || timeout > MaxWait || string.IsNullOrWhiteSpace(expectedAuthorId))
        {
            throw new InvalidOperationException("Codync wait arguments are outside the allowed bound.");
        }
        if (!_subscriptions.TryRemove(receipt.RootEntryId, out var subscription))
            return new CodyncWaitResult(false, false, null, "subscription_missing", "No live event subscription is correlated with this accepted send.");
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        var startObserved = false;
        var needsInput = false;
        DateTimeOffset? startedAt = null;
        try
        {
            var current = (await ListApprovedBotsGroupsAsync(bounded.Token).ConfigureAwait(false))
                .Where(item => item.Id == receipt.DestinationId && item.Name == receipt.DestinationName).ToArray();
            if (current.Length != 1 || (current[0].Kind == "group"
                    ? !current[0].Members.Contains(expectedAuthorId, StringComparer.Ordinal)
                    : current[0].Id != expectedAuthorId))
            {
                return new CodyncWaitResult(false, false, null, "stale_identity", "Expected reply author or destination is no longer an exact approved identity.");
            }
            await VerifySendReceiptAsync(receipt, bounded.Token).ConfigureAwait(false);
            while (true)
            {
                var root = await subscription.ReadNextAsync(bounded.Token).ConfigureAwait(false);
                if (ReadString(root, "type") == "bot" && root.TryGetProperty("bot", out var eventBot))
                {
                    var botId = ReadString(eventBot, "id");
                    var workingChat = ReadString(eventBot, "workingChat");
                    if (string.IsNullOrEmpty(workingChat)) workingChat = botId;
                    var epoch = ReadNullableInt64(eventBot, "startedAt");
                    var observedStart = epoch is null ? (DateTimeOffset?)null : DateTimeOffset.FromUnixTimeMilliseconds(epoch.Value);
                    var workingTurn = ReadNullableInt64(eventBot, "workingTurn") ?? ReadNullableInt64(eventBot, "turn");
                    if (botId == expectedAuthorId && workingChat == receipt.DestinationId && workingTurn == receipt.RootTurn &&
                        observedStart is not null && observedStart >= receipt.SubmittedAt && ReadString(eventBot, "status") is "working" or "needsInput")
                    {
                        startObserved = true;
                        needsInput = ReadString(eventBot, "status") == "needsInput";
                        startedAt ??= observedStart;
                        if (needsInput)
                            return new CodyncWaitResult(true, true, null, "needs_input", "The expected provider is awaiting input in the exact destination.");
                    }
                }
                if (ReadString(root, "type") != "entry" || !root.TryGetProperty("entry", out var entry) ||
                    ReadString(entry, "botId") != receipt.DestinationId || ReadInt64(entry, "seq") <= receipt.RootSequence ||
                    ReadString(entry, "kind") != "agent" || ReadInt64(entry, "turn") != receipt.RootTurn || !entry.TryGetProperty("data", out var data) ||
                    !data.TryGetProperty("final", out var final) || !final.GetBoolean())
                {
                    continue;
                }
                var authorId = ReadString(data, "author");
                if (string.IsNullOrEmpty(authorId)) authorId = receipt.DestinationId;
                if (authorId != expectedAuthorId) continue;
                var text = ReadString(data, "text");
                if (text.Length > BridgeProtocol.MaxCodyncReplyLength) text = text[..BridgeProtocol.MaxCodyncReplyLength];
                var completed = DateTimeOffset.UtcNow;
                return new CodyncWaitResult(startObserved, false,
                    new CodyncCorrelatedReply(receipt.DestinationId, receipt.DestinationName, receipt.RootEntryId,
                        authorId, text, ReadInt64(entry, "seq"), startedAt ?? completed, completed, false),
                    "reply", startObserved ? "Provider start and exact correlated final reply observed." : "Exact correlated final reply observed; provider start event was not observed.");
            }
        }
        catch (OperationCanceledException) when (bounded.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return new CodyncWaitResult(startObserved, needsInput, null, needsInput ? "needs_input" : "timeout", needsInput ? "Provider requires input before a final reply." : startObserved ? "Provider start observed; no exact final reply before timeout." : "No provider start or exact final reply before timeout.");
        }
        catch (ChannelClosedException)
        {
            return new CodyncWaitResult(startObserved, needsInput, null, "connection_lost", "Codync event stream ended before a correlated reply.");
        }
        finally
        {
            subscription.Dispose();
        }
    }

    private async Task VerifySendReceiptAsync(CodyncSendReceipt receipt, CancellationToken cancellationToken)
    {
        using var request = await AuthorizedRequestAsync(HttpMethod.Post, "api/history", cancellationToken).ConfigureAwait(false);
        request.Content = JsonContent.Create(new { botId = receipt.DestinationId, limit = 500 });
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        EnsureSuccess(response);
        using var history = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!history.RootElement.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("Codync history did not return a bounded entry list.");
        var roots = entries.EnumerateArray().Where(entry =>
            ReadString(entry, "id") == receipt.RootEntryId &&
            ReadString(entry, "botId") == receipt.DestinationId &&
            ReadString(entry, "kind") == "user" &&
            ReadInt64(entry, "seq") == receipt.RootSequence &&
            ReadInt64(entry, "turn") == receipt.RootTurn &&
            entry.TryGetProperty("data", out var data) && ReadString(data, "clientNonce") == receipt.ClientNonce).ToArray();
        if (roots.Length != 1)
            throw new InvalidOperationException("Codync root entry does not exactly match the send dispatch correlation.");
    }

    private async Task<CodyncEventSubscription> OpenEventsBeforeSendAsync(CancellationToken cancellationToken)
    {
        long revision = -1;
        using (var bootstrapRequest = await AuthorizedRequestAsync(HttpMethod.Get, "events?since=0", cancellationToken).ConfigureAwait(false))
        {
            bootstrapRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            using var bootstrapResponse = await _http.SendAsync(bootstrapRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            EnsureSuccess(bootstrapResponse);
            await using var bootstrapStream = await bootstrapResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(bootstrapStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            using var bootstrapDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bootstrapDeadline.CancelAfter(TimeSpan.FromSeconds(10));
            while (true)
            {
                var line = await reader.ReadLineAsync(bootstrapDeadline.Token).ConfigureAwait(false);
                if (line is null) throw new InvalidOperationException("Codync event stream ended before its hello revision.");
                if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
                using var document = JsonDocument.Parse(line[5..].Trim());
                if (ReadString(document.RootElement, "type") != "hello" || !document.RootElement.TryGetProperty("rev", out var rev) || !rev.TryGetInt64(out revision))
                    throw new InvalidOperationException("Codync event stream did not begin with a valid hello revision.");
                break;
            }
        }

        using var request = await AuthorizedRequestAsync(HttpMethod.Get, $"events?since={revision}", cancellationToken).ConfigureAwait(false);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureSuccess(response);
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var subscription = new CodyncEventSubscription(response, stream);
            subscription.Start();
            return subscription;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private async Task<HttpRequestMessage> AuthorizedRequestAsync(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        var bearer = await _readBearer(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(bearer)) throw new InvalidOperationException("Codync credential is unavailable.");
        var request = new HttpRequestMessage(method, new Uri(BaseUri, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return request;
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Codync local API returned HTTP {(int)response.StatusCode}.");
        }
    }

    private static string ReadString(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
    private static long ReadInt64(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.TryGetInt64(out var result) ? result : 0;
    private static long? ReadNullableInt64(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.TryGetInt64(out var result) ? result : null;
    private static string[] ReadStringArray(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? string.Empty).ToArray()
            : [];

    private sealed class CodyncEventSubscription : IDisposable
    {
        private readonly HttpResponseMessage _response;
        private readonly StreamReader _reader;
        private readonly CancellationTokenSource _stop = new();
        private readonly Channel<JsonElement> _events = Channel.CreateBounded<JsonElement>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true
        });
        private Task? _pump;
        private int _disposed;

        public CodyncEventSubscription(HttpResponseMessage response, Stream stream)
        {
            _response = response;
            _reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        }

        public void Start() => _pump = PumpAsync();

        public ValueTask<JsonElement> ReadNextAsync(CancellationToken cancellationToken)
            => _events.Reader.ReadAsync(cancellationToken);

        private async Task PumpAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var line = await _reader.ReadLineAsync(_stop.Token).ConfigureAwait(false);
                    if (line is null) break;
                    if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
                    using var document = JsonDocument.Parse(line[5..].Trim());
                    await _events.Writer.WriteAsync(document.RootElement.Clone(), _stop.Token).ConfigureAwait(false);
                }
                _events.Writer.TryComplete();
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                _events.Writer.TryComplete();
            }
            catch (Exception exception)
            {
                _events.Writer.TryComplete(exception);
            }
            finally
            {
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _stop.Cancel();
            _reader.Dispose();
            _response.Dispose();
            _events.Writer.TryComplete();
            _stop.Dispose();
        }
    }
}
