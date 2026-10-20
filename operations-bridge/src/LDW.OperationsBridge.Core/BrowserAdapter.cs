namespace LDW.OperationsBridge.Core;

public interface IBridgeBrowserAdapter
{
    Task<BrowserHealth> GetHealthAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<BrowserTabMetadata>> ListTabsAsync(CancellationToken cancellationToken);
    Task<BrowserTabMetadata?> ReadTabMetadataAsync(string tabId, CancellationToken cancellationToken);
}

public sealed class SyntheticBrowserAdapter : IBridgeBrowserAdapter
{
    private readonly Dictionary<string, BrowserTabMetadata> _tabs;

    public SyntheticBrowserAdapter(IEnumerable<BrowserTabMetadata> tabs)
    {
        _tabs = tabs.ToDictionary(tab => tab.TabId, StringComparer.Ordinal);
    }

    public Task<BrowserHealth> GetHealthAsync(CancellationToken cancellationToken)
        => Task.FromResult(new BrowserHealth(Ready: true, RuntimeVersion: "synthetic", Notes: "Read-only test adapter"));

    public Task<IReadOnlyList<BrowserTabMetadata>> ListTabsAsync(CancellationToken cancellationToken)
    {
        var sanitized = _tabs.Values
            .Select(Sanitize)
            .Where(tab => tab is not null)
            .Cast<BrowserTabMetadata>()
            .ToList()
            .AsReadOnly();
        return Task.FromResult<IReadOnlyList<BrowserTabMetadata>>(sanitized);
    }

    public Task<BrowserTabMetadata?> ReadTabMetadataAsync(string tabId, CancellationToken cancellationToken)
    {
        if (!_tabs.TryGetValue(tabId, out var tab))
        {
            return Task.FromResult<BrowserTabMetadata?>(null);
        }

        return Task.FromResult(Sanitize(tab));
    }

    private static BrowserTabMetadata? Sanitize(BrowserTabMetadata tab)
    {
        if (!Uri.TryCreate(tab.Url, UriKind.Absolute, out var parsed))
        {
            return null;
        }

        var host = parsed.Host.ToLowerInvariant();
        var allowlisted = IsAllowlistedHost(host, "chatgpt.com") ||
                          IsAllowlistedHost(host, "openai.com") ||
                          IsAllowlistedHost(host, "lowcountrydigitalworks.com");

        if (!allowlisted)
        {
            return null;
        }

        return tab with
        {
            Title = tab.Title.Length > 120 ? tab.Title[..120] : tab.Title
        };
    }

    private static bool IsAllowlistedHost(string host, string allowedDomain)
    {
        if (string.Equals(host, allowedDomain, StringComparison.Ordinal))
        {
            return true;
        }

        return host.EndsWith($".{allowedDomain}", StringComparison.Ordinal);
    }
}
