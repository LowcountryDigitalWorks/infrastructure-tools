using System.Diagnostics;

namespace LDW.HostAgent.Core;

/// <summary>Tracks one bounded post-login settle window using a monotonic clock.</summary>
public sealed class PostLoginSettleTracker
{
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromSeconds(120);

    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _window;
    private long? _activeSinceTimestamp;

    public PostLoginSettleTracker(TimeSpan? window = null, TimeProvider? timeProvider = null)
    {
        _window = window ?? DefaultWindow;
        if (_window <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(window), "The post-login settle window must be positive.");

        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public RuntimeContext Observe(OwnerSessionState ownerSession)
    {
        if (ownerSession == OwnerSessionState.Inactive)
        {
            _activeSinceTimestamp = null;
            return new RuntimeContext(ownerSession);
        }

        if (ownerSession == OwnerSessionState.Active)
        {
            var now = _timeProvider.GetTimestamp();
            _activeSinceTimestamp ??= now;
            var settling = _timeProvider.GetElapsedTime(_activeSinceTimestamp.Value, now) < _window;
            return new RuntimeContext(ownerSession, settling);
        }

        // Unknown telemetry must not extend or restart an already observed Active session.
        return new RuntimeContext(ownerSession);
    }
}
