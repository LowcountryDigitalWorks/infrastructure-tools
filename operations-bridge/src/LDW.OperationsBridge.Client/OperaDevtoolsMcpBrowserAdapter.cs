using System.Diagnostics;
using System.Text;
using System.Text.Json;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

/// <summary>
/// Read-only metadata client for the pinned Opera DevTools MCP server. Its only public
/// operation invokes the literal typed "list_pages" tool through stdio JSON-RPC.
/// </summary>
public sealed class OperaDevtoolsMcpBrowserAdapter : IBridgeBrowserAdapter
{
    public const string PackageName = "opera-devtools-mcp";
    public const string PackageVersion = "0.7.0";
    public const string ProtocolVersion = "2024-11-05";
    public const int MaximumResponseLineLength = 65536;
    public const int MaximumPages = 6;
    private const string ServerName = "chrome_devtools";

    private readonly IOperaMcpProcessFactory _processFactory;
    private readonly string _profilePath;

    public OperaDevtoolsMcpBrowserAdapter()
        : this(new OperaMcpProcessFactory(), GetDedicatedProfilePath())
    {
    }

    public OperaDevtoolsMcpBrowserAdapter(IOperaMcpProcessFactory processFactory, string profilePath)
    {
        _processFactory = processFactory ?? throw new ArgumentNullException(nameof(processFactory));
        var expected = GetDedicatedProfilePath();
        if (!PathEquals(profilePath, expected))
        {
            throw new ArgumentException("Browser profile is not the dedicated LDW Auto Browser profile.", nameof(profilePath));
        }
        _profilePath = expected;
    }

    public async Task<BrowserHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        var pages = await ReadPagesAsync(cancellationToken).ConfigureAwait(false);
        return new BrowserHealth(true, PackageVersion, "Pinned Opera metadata adapter ready; pages=" + pages.Count);
    }

    public async Task<IReadOnlyList<BrowserTabMetadata>> ListTabsAsync(CancellationToken cancellationToken)
        => await ReadPagesAsync(cancellationToken).ConfigureAwait(false);

    public async Task<BrowserTabMetadata?> ReadTabMetadataAsync(string tabId, CancellationToken cancellationToken)
    {
        if (!int.TryParse(tabId, out var requestedId) || requestedId <= 0)
            return null;
        var pages = await ReadPagesAsync(cancellationToken).ConfigureAwait(false);
        return pages.SingleOrDefault(page => page.TabId == tabId);
    }

    private async Task<IReadOnlyList<BrowserTabMetadata>> ReadPagesAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        await using var process = await _processFactory.StartAsync(_profilePath, timeout.Token).ConfigureAwait(false);
        try
        {
            await process.WriteLineAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"ldw-operations-bridge\",\"version\":\"1.0.0\"}}}",
                timeout.Token).ConfigureAwait(false);
            var initialize = await ReadResponseAsync(process, 1, timeout.Token).ConfigureAwait(false);
            ValidateInitialize(initialize);

            await process.WriteLineAsync("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", timeout.Token)
                .ConfigureAwait(false);
            await process.WriteLineAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_pages\",\"arguments\":{}}}",
                timeout.Token).ConfigureAwait(false);
            var call = await ReadResponseAsync(process, 2, timeout.Token).ConfigureAwait(false);
            return ParsePages(call);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException("Opera metadata operation timed out.");
        }
        finally
        {
            await process.CloseInputAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static async Task<JsonElement> ReadResponseAsync(IOperaMcpProcess process, int expectedId, CancellationToken cancellationToken)
    {
        for (var i = 0; i < 16; i++)
        {
            var line = await process.ReadLineAsync(MaximumResponseLineLength, cancellationToken).ConfigureAwait(false);
            if (line is null)
                throw new InvalidOperationException("Opera metadata server exited before its response.");
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 12 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("Opera metadata response has an unexpected shape.");
            if (!root.TryGetProperty("id", out var id))
            {
                if (root.TryGetProperty("method", out _))
                    continue;
                throw new InvalidOperationException("Opera metadata response is missing its request identity.");
            }
            if (id.ValueKind != JsonValueKind.Number || !id.TryGetInt32(out var responseId) || responseId != expectedId)
                throw new InvalidOperationException("Opera metadata response identity does not match the request.");
            if (root.TryGetProperty("error", out _))
                throw new InvalidOperationException("Opera metadata server rejected the fixed request.");
            if (!root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("Opera metadata response is missing its result.");
            return result.Clone();
        }
        throw new InvalidOperationException("Opera metadata server emitted too many unrelated protocol messages.");
    }

    private static void ValidateInitialize(JsonElement result)
    {
        if (!result.TryGetProperty("protocolVersion", out var protocol) ||
            protocol.GetString() != ProtocolVersion ||
            !result.TryGetProperty("serverInfo", out var serverInfo) ||
            serverInfo.ValueKind != JsonValueKind.Object ||
            !serverInfo.TryGetProperty("name", out var name) ||
            name.GetString() != ServerName ||
            !serverInfo.TryGetProperty("version", out var version) ||
            version.GetString() != PackageVersion)
            throw new InvalidOperationException("Opera metadata server identity or protocol version drifted.");
    }

    private static IReadOnlyList<BrowserTabMetadata> ParsePages(JsonElement result)
    {
        if (result.TryGetProperty("isError", out var isError) && isError.ValueKind == JsonValueKind.True)
            throw new InvalidOperationException("Opera metadata tool returned an error.");
        if (!result.TryGetProperty("structuredContent", out var structured) ||
            structured.ValueKind != JsonValueKind.Object ||
            structured.EnumerateObject().Count() != 1 ||
            !structured.TryGetProperty("pages", out var pagesElement) ||
            pagesElement.ValueKind != JsonValueKind.Array ||
            pagesElement.GetArrayLength() > MaximumPages)
            throw new InvalidOperationException("Opera metadata structured page schema is invalid.");

        var pages = new List<BrowserTabMetadata>();
        var ids = new HashSet<int>();
        foreach (var page in pagesElement.EnumerateArray())
        {
            if (page.ValueKind != JsonValueKind.Object ||
                page.EnumerateObject().Count() != 4 ||
                !page.TryGetProperty("id", out var idElement) ||
                idElement.ValueKind != JsonValueKind.Number ||
                !idElement.TryGetInt32(out var id) || id <= 0 ||
                !page.TryGetProperty("url", out var urlElement) ||
                urlElement.ValueKind != JsonValueKind.String ||
                !page.TryGetProperty("title", out var titleElement) ||
                titleElement.ValueKind != JsonValueKind.String ||
                !page.TryGetProperty("selected", out var selectedElement) ||
                selectedElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new InvalidOperationException("Opera metadata page fields are missing or invalid.");

            if (!ids.Add(id))
                throw new InvalidOperationException("Opera metadata contains duplicate page identities.");
            var url = urlElement.GetString() ?? string.Empty;
            var title = titleElement.GetString() ?? string.Empty;
            if (url.Length is 0 or > 2048 || title.Length > 4096)
                throw new InvalidOperationException("Opera metadata field exceeds its bound.");

            var metadata = new BrowserTabMetadata(
                id.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "ldw-auto-browser",
                title,
                url)
            {
                Selected = selectedElement.GetBoolean()
            };
            var sanitized = SyntheticBrowserAdapter.SanitizeMetadata(metadata);
            if (sanitized is not null)
                pages.Add(sanitized);
        }
        return pages.AsReadOnly();
    }

    public static string GetDedicatedProfilePath()
        => Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LDW", "AutoBrowser", "bridge-001a-mcp-0.7.0"));

    private static bool PathEquals(string first, string second)
        => string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(first)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(second)),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}

public interface IOperaMcpProcessFactory
{
    Task<IOperaMcpProcess> StartAsync(string profilePath, CancellationToken cancellationToken);
}

public interface IOperaMcpProcess : IAsyncDisposable
{
    Task WriteLineAsync(string line, CancellationToken cancellationToken);
    Task<string?> ReadLineAsync(int maximumLength, CancellationToken cancellationToken);
    Task CloseInputAsync(CancellationToken cancellationToken);
}

internal sealed class OperaMcpProcessFactory : IOperaMcpProcessFactory
{
    private const string ExpectedPackageJsonName = "opera-devtools-mcp";
    private const string ExpectedPackageJsonVersion = "0.7.0";

    public async Task<IOperaMcpProcess> StartAsync(string profilePath, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("LDW Auto Browser requires the reviewed Windows Opera runtime.");
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var packageRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "npm", "node_modules", "opera-browser-cli", "node_modules", "opera-devtools-mcp");
        var packageJson = Path.Combine(packageRoot, "package.json");
        var serverScript = Path.Combine(packageRoot, "build", "src", "bin", "opera-devtools-mcp.js");
        var node = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "nodejs", "node.exe");
        var opera = Path.Combine(local, "Programs", "Opera", "opera.exe");
        if (!File.Exists(node) || !File.Exists(opera) || !File.Exists(serverScript) || !File.Exists(packageJson))
            throw new FileNotFoundException("Pinned Opera DevTools MCP runtime is unavailable.");

        using (var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(packageJson, cancellationToken).ConfigureAwait(false)))
        {
            var root = manifest.RootElement;
            if (!root.TryGetProperty("name", out var name) || name.GetString() != ExpectedPackageJsonName ||
                !root.TryGetProperty("version", out var version) || version.GetString() != ExpectedPackageJsonVersion)
                throw new InvalidOperationException("Pinned Opera DevTools MCP package identity drifted.");
        }

        var expectedProfile = OperaDevtoolsMcpBrowserAdapter.GetDedicatedProfilePath();
        if (!string.Equals(Path.GetFullPath(profilePath), expectedProfile, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing a non-dedicated Opera profile.");
        Directory.CreateDirectory(expectedProfile);
        for (var current = new DirectoryInfo(expectedProfile); current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Refusing an ambiguous Opera profile path.");
            if (PathEquals(current.FullName, local))
                break;
        }
        if (File.Exists(Path.Combine(expectedProfile, "DevToolsActivePort")))
            throw new InvalidOperationException("A browser process already owns the dedicated Opera profile.");

        var start = new ProcessStartInfo
        {
            FileName = node,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(serverScript);
        start.ArgumentList.Add("--executablePath");
        start.ArgumentList.Add(opera);
        start.ArgumentList.Add("--userDataDir");
        start.ArgumentList.Add(expectedProfile);
        start.ArgumentList.Add("--headless");
        start.ArgumentList.Add("--no-javascript-evaluation");
        start.ArgumentList.Add("--no-usage-statistics");
        start.ArgumentList.Add("--experimental-structured-content");

        var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        if (!process.Start())
            throw new InvalidOperationException("Pinned Opera metadata process did not start.");
        _ = DrainStandardErrorAsync(process.StandardError);
        return new OperaMcpProcess(process);
    }

    private static async Task DrainStandardErrorAsync(StreamReader reader)
    {
        var buffer = new char[1024];
        try
        {
            while (await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false) > 0) { }
        }
        catch (Exception ex) when (ex is ObjectDisposedException or IOException) { }
    }
}

internal sealed class OperaMcpProcess(Process process) : IOperaMcpProcess
{
    public async Task WriteLineAsync(string line, CancellationToken cancellationToken)
    {
        await process.StandardInput.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> ReadLineAsync(int maximumLength, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder(Math.Min(maximumLength, 4096));
        var single = new char[1];
        while (true)
        {
            var read = await process.StandardOutput.ReadAsync(single.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return builder.Length == 0 ? null : throw new InvalidOperationException("Opera metadata returned a partial JSON line.");
            if (single[0] == '\n')
            {
                if (builder.Length > 0 && builder[^1] == '\r')
                    builder.Length--;
                return builder.ToString();
            }
            if (builder.Length >= maximumLength)
                throw new InvalidOperationException("Opera metadata response exceeds its size bound.");
            builder.Append(single[0]);
        }
    }

    public async Task CloseInputAsync(CancellationToken cancellationToken)
    {
        await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
        process.StandardInput.Close();
    }

    public async ValueTask DisposeAsync()
    {
        if (!process.HasExited)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
        }
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        process.Dispose();
    }
}
