using System.Runtime.CompilerServices;
using LDW.HostAgent.Core;

internal static class CiJitLocalProjectionTests
{
    [ModuleInitializer]
    internal static void Run()
    {
        var now = new DateTimeOffset(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);
        var boot = now.AddHours(-6);
        var assertions = 0;
        void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("CI/JIT local projection assertion failed: " + message);
            assertions++;
        }

        string Projection(
            string queueState = "FRESH",
            string? queueObserved = null,
            string eligible = "1",
            string held = "0",
            string selectedProfile = "\"bizops-secret-scan\"",
            string selectedRun = "1001",
            string selectedJob = "2001",
            string controllerPhase = "null",
            string capacity = "READY",
            string reasonCode = "null",
            string provenance = "true",
            string failure = "false",
            DateTimeOffset? projectedBoot = null,
            DateTimeOffset? localObserved = null) => $$"""
        {
          "schema": 1,
          "source_version": "ci-jit-v1",
          "boot_started_utc": "{{(projectedBoot ?? boot):O}}",
          "local_observed_at_utc": "{{(localObserved ?? now):O}}",
          "provenance_valid": {{provenance}},
          "proven_failure": {{failure}},
          "controller_phase": {{controllerPhase}},
          "capacity": "{{capacity}}",
          "reason_code": {{reasonCode}},
          "queue_observed_at_utc": {{(queueState == "UNAVAILABLE" ? "null" : "\"" + (queueObserved ?? now.ToString("O")) + "\"")}},
          "queue_state": "{{queueState}}",
          "eligible_queued_count": {{(queueState == "UNAVAILABLE" ? "null" : eligible)}},
          "held_queued_count": {{(queueState == "UNAVAILABLE" ? "null" : held)}},
          "selected_profile": {{(queueState == "UNAVAILABLE" ? "null" : selectedProfile)}},
          "selected_run_id": {{(queueState == "UNAVAILABLE" ? "null" : selectedRun)}},
          "selected_job_id": {{(queueState == "UNAVAILABLE" ? "null" : selectedJob)}}
        }
        """;

        var queued = CiJitLocalProjection.Parse(Projection(), now, boot);
        Assert(queued.State == CiJitOwnerState.Queued, "fresh same-boot projection maps to queued");
        Assert(queued.SelectedProfile == "bizops-secret-scan" && queued.SelectedRunId == 1001 && queued.SelectedJobId == 2001,
            "fresh selected identity is preserved");
        Assert(queued.LocalStateFresh && queued.QueueState == CiJitQueueState.Fresh, "same-boot fresh sources stay fresh");

        var running = CiJitLocalProjection.Parse(Projection(controllerPhase: "\"Running\"", capacity: "BUSY", reasonCode: "\"BUSY\""), now, boot);
        Assert(running.State == CiJitOwnerState.Running && running.Capacity == CiJitCapacityState.Busy,
            "controller phase wins over queued backlog");

        var staleQueue = CiJitLocalProjection.Parse(Projection(queueObserved: now.AddMinutes(-3).ToString("O")), now, boot);
        Assert(staleQueue.QueueState == CiJitQueueState.Stale && staleQueue.State == CiJitOwnerState.Unknown,
            "reader downgrades aged queue evidence to stale");
        Assert(staleQueue.EligibleQueuedCount is null && staleQueue.SelectedRunId is null && staleQueue.ReasonCode == "QUEUE_STALE",
            "stale queue discards counts and selected identity");

        var oldBoot = CiJitLocalProjection.Parse(Projection(projectedBoot: boot.AddHours(-1)), now, boot);
        Assert(!oldBoot.LocalStateFresh && oldBoot.State == CiJitOwnerState.Unknown && oldBoot.ReasonCode == "LOCAL_STATE_STALE",
            "prior-boot projection fails closed");

        var unavailable = CiJitLocalProjection.Parse(Projection(
            queueState: "UNAVAILABLE",
            eligible: "null",
            held: "null",
            selectedProfile: "null",
            selectedRun: "null",
            selectedJob: "null"), now, boot);
        Assert(unavailable.QueueState == CiJitQueueState.Unavailable && unavailable.ReasonCode == "QUEUE_UNAVAILABLE",
            "unavailable queue remains explicit");

        var provenanceMismatch = CiJitLocalProjection.Parse(Projection(provenance: "false"), now, boot);
        Assert(provenanceMismatch.State == CiJitOwnerState.Unknown && provenanceMismatch.ReasonCode == "PROVENANCE_MISMATCH",
            "provenance mismatch fails closed");

        var missing = CiJitLocalProjection.Unavailable(now);
        Assert(missing.State == CiJitOwnerState.Unknown && missing.ReasonCode == "LOCAL_STATE_UNAVAILABLE",
            "missing local projection maps to unknown");

        var malformedCases = new[]
        {
            Projection().Replace("\"schema\": 1", "\"schema\": 2", StringComparison.Ordinal),
            Projection().Replace("\"source_version\": \"ci-jit-v1\"", "\"source_version\": \"deadbeef\"", StringComparison.Ordinal),
            Projection().Replace("\"capacity\": \"READY\"", "\"capacity\": \"EXECUTE\"", StringComparison.Ordinal),
            Projection().Replace("\"selected_job_id\": 2001", "\"selected_job_id\": null", StringComparison.Ordinal),
            Projection().Replace("\"selected_profile\": \"bizops-secret-scan\"", "\"selected_profile\": \"../../private\"", StringComparison.Ordinal),
            Projection().Replace("\"selected_job_id\": 2001", "\"selected_job_id\": 2001, \"raw_payload\": \"secret\"", StringComparison.Ordinal)
        };
        foreach (var malformed in malformedCases)
        {
            try
            {
                _ = CiJitLocalProjection.Parse(malformed, now, boot);
                throw new Exception("Expected malformed local projection to be rejected");
            }
            catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
            {
                assertions++;
            }
        }

        Console.WriteLine($"CI/JIT local projection tests: {assertions} assertions passed.");
    }
}
