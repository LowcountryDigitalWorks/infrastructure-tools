namespace LDW.HostAgent.Core;

/// <summary>Sanitized owner-facing copy for CI/JIT technical-detail surfaces. Does not change status resolution.</summary>
public static class CiJitTechnicalDetails
{
    public static string? UnknownOwnerNextCheck(CiJitStatusSnapshot ci)
    {
        if (ci.State != CiJitOwnerState.Unknown)
            return null;

        var countsVisible = ci.QueueState == CiJitQueueState.Fresh
            && ci.EligibleQueuedCount is not null
            && ci.HeldQueuedCount is not null;

        if (!countsVisible)
        {
            var reason = ci.QueueState switch
            {
                CiJitQueueState.Stale => "queue evidence is stale",
                CiJitQueueState.Unavailable => "queue evidence is unavailable",
                _ => "numerical queue evidence is unavailable",
            };
            return $"Queue counts are withheld because {reason}. Re-read the accepted CI/JIT status source before treating any prior count as current; no queue action was attempted.";
        }

        if (!ci.LocalStateFresh || ci.ReasonCode is "LOCAL_STATE_STALE" or "LOCAL_STATE_UNAVAILABLE")
        {
            return "CI/JIT owner state is unknown because local owner evidence is stale or unavailable; eligible and held counts above reflect fresh queue evidence only and are not authorization to dispatch or repair. Re-read the accepted CI/JIT status source; no queue action was attempted.";
        }

        return "CI/JIT owner state is unknown; eligible and held counts above are informational only and are not authorization to dispatch or repair. Re-read the accepted CI/JIT status source; no queue action was attempted.";
    }
}
