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

        // Strip userinfo/query/fragment, then apply a fail-closed path representation so
        // credential-bearing path segments cannot egress while short structural tab identity remains.
        var authority = parsed.GetComponents(
            UriComponents.Scheme | UriComponents.Host | UriComponents.Port,
            UriFormat.UriEscaped);
        var redactedUrl = authority + RedactPath(parsed.AbsolutePath);

        return tab with
        {
            Title = tab.Title.Length > 120 ? tab.Title[..120] : tab.Title,
            Url = redactedUrl
        };
    }

    private static string RedactPath(string absolutePath)
    {
        if (string.IsNullOrEmpty(absolutePath) || absolutePath == "/")
        {
            return string.IsNullOrEmpty(absolutePath) ? "/" : absolutePath;
        }

        // Fail-closed path representation: keep at most one short structural segment
        // (e.g. /c/*), then a single "*" placeholder. Token/reset/login path material
        // never egresses as raw segments; no exhaustive secret classifier required.
        var parts = absolutePath.Split('/');
        var output = new List<string>(parts.Length);
        var retainedStructural = false;
        var emittedPlaceholder = false;

        foreach (var segment in parts)
        {
            if (segment.Length == 0)
            {
                output.Add(segment);
                continue;
            }

            if (!retainedStructural && IsSafeStructuralPathSegment(segment))
            {
                output.Add(segment);
                retainedStructural = true;
                continue;
            }

            if (!emittedPlaceholder)
            {
                output.Add("*");
                emittedPlaceholder = true;
            }

            break;
        }

        return string.Join('/', output);
    }

    private static bool IsSafeStructuralPathSegment(string segment)
    {
        const int maxLength = 16;
        if (segment.Length > maxLength)
        {
            return false;
        }

        foreach (var ch in segment)
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_')
            {
                continue;
            }

            return false;
        }

        return true;
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
