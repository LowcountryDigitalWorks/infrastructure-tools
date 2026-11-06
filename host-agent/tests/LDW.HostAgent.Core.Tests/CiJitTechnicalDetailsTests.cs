using System.Runtime.CompilerServices;
using LDW.HostAgent.Core;

internal static class CiJitTechnicalDetailsTests
{
    [ModuleInitializer]
    internal static void Run()
    {
        var now = DateTimeOffset.UtcNow;
        var assertions = 0;
        void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("CI/JIT technical details assertion failed: " + message);
            assertions++;
        }

        var staleQueue = CiJitStatusResolver.Resolve(new CiJitStatusInput(
            now, "ci10-test", true, true, true, false,
            CiJitQueueState.Stale, null, null, CiJitCapacityState.Ready, ReasonCode: "QUEUE_STALE"));
        Assert(staleQueue.State == CiJitOwnerState.Unknown, "stale queue maps to unknown owner");
        var staleMessage = CiJitTechnicalDetails.UnknownOwnerNextCheck(staleQueue);
        Assert(staleMessage is not null && staleMessage.Contains("withheld", StringComparison.OrdinalIgnoreCase), "stale queue next check withholds counts");
        Assert(staleMessage!.Contains("stale", StringComparison.OrdinalIgnoreCase), "stale queue next check names stale evidence");
        Assert(!staleMessage.Contains("fresh queue evidence", StringComparison.OrdinalIgnoreCase), "stale queue must not claim fresh queue counts");

        var freshLocalStale = CiJitStatusResolver.Resolve(new CiJitStatusInput(
            now, "ci10-test", true, LocalStateFresh: false, true, false,
            CiJitQueueState.Fresh, 2, 0, CiJitCapacityState.Ready, ReasonCode: "LOCAL_STATE_STALE"));
        Assert(freshLocalStale.State == CiJitOwnerState.Unknown && freshLocalStale.QueueState == CiJitQueueState.Fresh,
            "fresh queue with stale local owner stays unknown");
        Assert(freshLocalStale.EligibleQueuedCount == 2, "fresh queue counts remain visible in snapshot");
        var freshLocalStaleMessage = CiJitTechnicalDetails.UnknownOwnerNextCheck(freshLocalStale);
        Assert(freshLocalStaleMessage is not null, "unknown owner with fresh queue gets guidance");
        Assert(!freshLocalStaleMessage!.Contains("Queue counts are withheld", StringComparison.Ordinal),
            "fresh queue counts must not be described as withheld");
        Assert(freshLocalStaleMessage.Contains("fresh queue evidence", StringComparison.OrdinalIgnoreCase),
            "fresh queue counts are labeled non-actionable queue evidence");
        Assert(freshLocalStaleMessage.Contains("not authorization", StringComparison.OrdinalIgnoreCase),
            "fresh queue counts are not authorization to run");

        var queued = CiJitStatusResolver.Resolve(new CiJitStatusInput(
            now, "ci10-test", true, true, true, false,
            CiJitQueueState.Fresh, 1, 0, CiJitCapacityState.Ready));
        Assert(queued.State == CiJitOwnerState.Queued, "fixture maps to queued owner");
        Assert(CiJitTechnicalDetails.UnknownOwnerNextCheck(queued) is null, "non-unknown owner state has no unknown next check");

        Console.WriteLine($"CI/JIT technical details tests: {assertions} assertions passed.");
    }
}
