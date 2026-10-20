namespace LDW.OperationsBridge.Client;

/// <summary>
/// Explicitly trusted Worker relay connect endpoint. Bearer credentials may only
/// be attached after the candidate URI is verified as secure <c>wss:</c> and an
/// exact match against one of these configured endpoints.
/// </summary>
public sealed class TrustedRelayEndpoint
{
    public TrustedRelayEndpoint(Uri connectUri)
    {
        ArgumentNullException.ThrowIfNull(connectUri);
        if (!string.Equals(connectUri.Scheme, Uri.UriSchemeWss, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Trusted relay endpoints must use the wss scheme.", nameof(connectUri));
        }

        if (!connectUri.IsAbsoluteUri)
        {
            throw new ArgumentException("Trusted relay endpoints must be absolute URIs.", nameof(connectUri));
        }

        ConnectUri = connectUri;
    }

    public Uri ConnectUri { get; }

    public bool Matches(Uri candidate)
    {
        if (candidate is null || !candidate.IsAbsoluteUri)
        {
            return false;
        }

        return string.Equals(candidate.Scheme, Uri.UriSchemeWss, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(Normalize(candidate), Normalize(ConnectUri), StringComparison.Ordinal);
    }

    private static string Normalize(Uri uri)
    {
        var builder = new UriBuilder(uri)
        {
            Scheme = Uri.UriSchemeWss,
            Port = uri.IsDefaultPort ? -1 : uri.Port,
            Fragment = string.Empty
        };
        return builder.Uri.AbsoluteUri.TrimEnd('/');
    }
}

public static class BridgeConnectGuard
{
    /// <summary>
    /// Fail closed before any credential attachment: require wss and an exact
    /// match to an explicitly trusted Worker endpoint configuration.
    /// </summary>
    public static void EnsureTrustedSecureEndpoint(
        Uri relayConnectUri,
        IReadOnlyCollection<TrustedRelayEndpoint> trustedEndpoints)
    {
        ArgumentNullException.ThrowIfNull(relayConnectUri);
        ArgumentNullException.ThrowIfNull(trustedEndpoints);

        if (!relayConnectUri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("Relay connect URI must be absolute.");
        }

        if (!string.Equals(relayConnectUri.Scheme, Uri.UriSchemeWss, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Relay connect URI must use secure wss scheme.");
        }

        if (trustedEndpoints.Count == 0)
        {
            throw new InvalidOperationException("No trusted Worker relay endpoints are configured.");
        }

        foreach (var trusted in trustedEndpoints)
        {
            if (trusted.Matches(relayConnectUri))
            {
                return;
            }
        }

        throw new InvalidOperationException("Relay connect URI is not an explicitly trusted Worker endpoint.");
    }
}
