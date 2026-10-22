using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

internal static class OperaMcpAdapterContractTests
{
    private const string InitializeResult =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{\"name\":\"chrome_devtools\",\"version\":\"0.7.0\"}}}";
    private const string GoodPages =
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[{\"id\":1,\"url\":\"https://chatgpt.com/c/secret?token=do-not-return#frag\",\"title\":\"tab title\",\"selected\":true}]}}}";

    public static async Task RunAsync()
    {
        var goodFactory = new FakeOperaProcessFactory(InitializeResult, GoodPages);
        var adapter = new OperaDevtoolsMcpBrowserAdapter(goodFactory, OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath());
        var health = await adapter.GetHealthAsync(CancellationToken.None);
        Assert(health.Ready && health.RuntimeVersion == "0.7.0", "pinned list_pages read produces deterministic ready health");
        var pages = await adapter.ListTabsAsync(CancellationToken.None);
        Assert(pages.Count == 1 && pages[0].TabId == "1" && pages[0].Selected, "structured id/title/url/selected metadata is mapped");
        Assert(pages[0].Url == "https://chatgpt.com/c/*" && pages[0].Title == "tab title", "existing URL/title sanitizer is preserved");
        Assert(goodFactory.Processes.All(process => process.Closed && process.Disposed), "stdio process closes cleanly after each operation");
        Assert(goodFactory.Processes.All(process => process.ToolCalls == 1), "adapter issues exactly one list_pages tool call per operation");
        Assert(goodFactory.Processes.SelectMany(process => process.Writes).All(line =>
            !line.Contains("evaluate_script", StringComparison.Ordinal) &&
            !line.Contains("snapshot", StringComparison.Ordinal) &&
            !line.Contains("cookies", StringComparison.Ordinal) &&
            !line.Contains("storage", StringComparison.Ordinal) &&
            !line.Contains("navigate_page", StringComparison.Ordinal) &&
            !line.Contains("click", StringComparison.Ordinal) &&
            !line.Contains("type", StringComparison.Ordinal)), "eval, snapshot, cookies, storage, navigation and input tools are unreachable");
        Assert(goodFactory.Processes.SelectMany(process => process.Writes)
            .Single(line => line.Contains("\"method\":\"tools/call\"", StringComparison.Ordinal))
            .Contains("\"name\":\"list_pages\"", StringComparison.Ordinal), "MCP tool name is a fixed literal");

        var wrongProfileRejected = false;
        try { _ = new OperaDevtoolsMcpBrowserAdapter(goodFactory, Path.Combine(Path.GetTempPath(), "personal-opera")); }
        catch (ArgumentException) { wrongProfileRejected = true; }
        Assert(wrongProfileRejected, "non-dedicated browser profile identity is rejected");

        foreach (var missing in new[] { "id", "url", "title", "selected" })
        {
            var fields = new Dictionary<string, string>
            {
                ["id"] = "\"id\":1",
                ["url"] = "\"url\":\"https://chatgpt.com/\"",
                ["title"] = "\"title\":\"title\"",
                ["selected"] = "\"selected\":true"
            };
            fields.Remove(missing);
            var malformed = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[{" +
                string.Join(",", fields.Values) + "}]}}}";
            await AssertThrowsAsync<InvalidOperationException>(
                () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(InitializeResult, malformed),
                    OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
                "missing " + missing + " page metadata is rejected");
        }

        await AssertThrowsAsync<System.Text.Json.JsonException>(
            () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(InitializeResult, "{malformed"),
                OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
            "malformed JSON response is rejected");

        var oversized = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[]}}}" + new string(' ', 70000);
        await AssertThrowsAsync<InvalidOperationException>(
            () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(InitializeResult, oversized),
                OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
            "oversized response line is rejected");

        var wrongVersion = InitializeResult.Replace("\"0.7.0\"", "\"0.8.0\"", StringComparison.Ordinal);
        var versionFactory = new FakeOperaProcessFactory(wrongVersion, GoodPages);
        await AssertThrowsAsync<InvalidOperationException>(
            () => new OperaDevtoolsMcpBrowserAdapter(versionFactory, OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath())
                .ListTabsAsync(CancellationToken.None),
            "unexpected server version is rejected");
        Assert(versionFactory.Processes[0].ToolCalls == 0, "version drift fails before any browser tool call");

        var versionFailureClient = new OutboundBridgeClient(
            "ldw01-bridge",
            new OperaDevtoolsMcpBrowserAdapter(versionFactory, OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()),
            new DispatchValidator(["ldw01-bridge"], BridgeProtocol.AllowedReadOnlyOperations));
        var versionFailureTransport = new FakeBridgeTransport();
        versionFailureClient.Attach(versionFailureTransport);
        var started = DateTimeOffset.UtcNow;
        await versionFailureTransport.DeliverAsync(new BridgeDispatchRequest(
            BridgeProtocol.Version, Guid.NewGuid(), "ldw01-bridge", BridgeOperation.BrowserHealth,
            started, started.AddMinutes(1), "opera-failure-idem", "opera-failure-correlation",
            new Dictionary<string, string>()), "fixture");
        Assert(versionFailureTransport.Results.Single().TerminalStatus == DispatchTerminalStatus.Failed,
            "browser process/version failure returns FAILED and cannot manufacture PASS");

        var extraSchema = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[{\"id\":1,\"url\":\"https://chatgpt.com/\",\"title\":\"title\",\"selected\":true,\"extra\":\"unexpected\"}]}}}";
        await AssertThrowsAsync<InvalidOperationException>(
            () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(InitializeResult, extraSchema),
                OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
            "unexpected page schema fields are rejected");

        var tooManyPages = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[" +
            string.Join(",", Enumerable.Range(1, 7).Select(id => "{\"id\":" + id +
                ",\"url\":\"https://chatgpt.com/\",\"title\":\"title\",\"selected\":false}")) + "]}}}";
        await AssertThrowsAsync<InvalidOperationException>(
            () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(InitializeResult, tooManyPages),
                OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
            "too many page metadata records are rejected");

        var wrongServer = InitializeResult.Replace("chrome_devtools", "unexpected_server", StringComparison.Ordinal);
        await AssertThrowsAsync<InvalidOperationException>(
            () => new OperaDevtoolsMcpBrowserAdapter(new FakeOperaProcessFactory(wrongServer, GoodPages),
                OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()).ListTabsAsync(CancellationToken.None),
            "unexpected MCP server identity is rejected");

        var disallowedUrl = new FakeOperaProcessFactory(InitializeResult,
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"pages\":[{\"id\":2,\"url\":\"https://evil.example/secret\",\"title\":\"private\",\"selected\":false}]}}}");
        Assert((await new OperaDevtoolsMcpBrowserAdapter(disallowedUrl, OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath())
            .ListTabsAsync(CancellationToken.None)).Count == 0, "non-allowlisted metadata is filtered before relay output");

        var cancelFactory = new FakeOperaProcessFactory(InitializeResult, null);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
        await AssertThrowsAsync<OperationCanceledException>(
            () => new OperaDevtoolsMcpBrowserAdapter(cancelFactory, OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath())
                .ListTabsAsync(cancel.Token),
            "cancellation interrupts a pending typed read");
        Assert(cancelFactory.Processes[0].Closed && cancelFactory.Processes[0].Disposed,
            "cancellation closes stdin and disposes the child process");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAILED: " + message);
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action, string message) where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
            throw new InvalidOperationException("FAILED: " + message + " (expected " + typeof(TException).Name + ")");
        }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal)) { throw; }
        catch (TException) { }
    }
}

internal sealed class FakeOperaProcessFactory(string initialize, string? pages) : IOperaMcpProcessFactory
{
    public List<FakeOperaProcess> Processes { get; } = [];

    public Task<IOperaMcpProcess> StartAsync(string profilePath, CancellationToken cancellationToken)
    {
        if (!string.Equals(Path.GetFullPath(profilePath),
            Path.GetFullPath(OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath()),
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("fake process received an unexpected profile");
        var process = new FakeOperaProcess(initialize, pages);
        Processes.Add(process);
        return Task.FromResult<IOperaMcpProcess>(process);
    }
}

internal sealed class FakeOperaProcess(string initialize, string? pages) : IOperaMcpProcess
{
    private readonly Queue<string> _responses = new();
    public List<string> Writes { get; } = [];
    public int ToolCalls { get; private set; }
    public bool Closed { get; private set; }
    public bool Disposed { get; private set; }

    public Task WriteLineAsync(string line, CancellationToken cancellationToken)
    {
        Writes.Add(line);
        if (line.Contains("\"method\":\"initialize\"", StringComparison.Ordinal))
            _responses.Enqueue(initialize);
        else if (line.Contains("\"method\":\"tools/call\"", StringComparison.Ordinal))
        {
            ToolCalls++;
            if (!line.Contains("\"name\":\"list_pages\"", StringComparison.Ordinal))
                throw new InvalidOperationException("unexpected tool call");
            if (pages is not null) _responses.Enqueue(pages);
        }
        return Task.CompletedTask;
    }

    public async Task<string?> ReadLineAsync(int maximumLength, CancellationToken cancellationToken)
    {
        while (_responses.Count == 0)
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        var response = _responses.Dequeue();
        if (response.Length > maximumLength)
            throw new InvalidOperationException("fixture response exceeds configured bound");
        return response;
    }

    public Task CloseInputAsync(CancellationToken cancellationToken)
    {
        Closed = true;
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}
