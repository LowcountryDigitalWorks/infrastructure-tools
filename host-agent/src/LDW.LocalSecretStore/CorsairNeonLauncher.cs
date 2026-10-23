namespace LDW.LocalSecretStore;

public sealed record CorsairNeonLaunchResult(bool Success, int ExitCode, string SanitizedStdout, string SanitizedStderr, string? ErrorCode = null);

/// <summary>No frozen Corsair proof contract exists; launching is deliberately unavailable.</summary>
public sealed class CorsairNeonLauncher
{
    public CorsairNeonLauncher(LocalSecretStore secretStore) => ArgumentNullException.ThrowIfNull(secretStore);

    public Task<CorsairNeonLaunchResult> LaunchProofProcessAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(new CorsairNeonLaunchResult(false, -1, string.Empty, string.Empty, "NOT_IMPLEMENTED"));
}
