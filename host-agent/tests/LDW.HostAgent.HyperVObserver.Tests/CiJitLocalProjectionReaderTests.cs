using System.Security.AccessControl;
using System.Security.Principal;
using LDW.HostAgent.Core;
using LDW.HostAgent.Windows;

internal static class CiJitLocalProjectionReaderTests
{
    internal static void Run(Action<bool, string> assert)
    {
        var system = new SecurityIdentifier("S-1-5-18");
        var admins = new SecurityIdentifier("S-1-5-32-544");
        var reader = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var stranger = new SecurityIdentifier("S-1-5-21-1-2-3-1002");

        var trustedRootRules = new[]
        {
            Rule(system, FileSystemRights.FullControl),
            Rule(admins, FileSystemRights.FullControl),
            Rule(reader, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)
        };
        assert(CiJitLocalProjectionReader.IsTrustedStatusAcl(
                admins, trustedRootRules, reader, FileSystemRights.ReadAndExecute,
                accessRulesProtected: true, requireProtectedAcl: true),
            "trusted root ACL permits the configured reader read-only");
        assert(!CiJitLocalProjectionReader.IsTrustedStatusAcl(
                reader, trustedRootRules, reader, FileSystemRights.ReadAndExecute,
                accessRulesProtected: true, requireProtectedAcl: true),
            "untrusted status-root owner is refused");

        var writableReaderRules = trustedRootRules.Append(
            Rule(reader, FileSystemRights.WriteData)).ToArray();
        assert(!CiJitLocalProjectionReader.IsTrustedStatusAcl(
                admins, writableReaderRules, reader, FileSystemRights.ReadAndExecute,
                accessRulesProtected: true, requireProtectedAcl: true),
            "reader write access is refused");

        var strangerRules = trustedRootRules.Append(
            Rule(stranger, FileSystemRights.ReadData)).ToArray();
        assert(!CiJitLocalProjectionReader.IsTrustedStatusAcl(
                admins, strangerRules, reader, FileSystemRights.ReadAndExecute,
                accessRulesProtected: true, requireProtectedAcl: true),
            "unexpected status-root reader is refused");
        var trustedFileRules = new[]
        {
            Rule(system, FileSystemRights.FullControl),
            Rule(admins, FileSystemRights.FullControl),
            Rule(reader, FileSystemRights.Read | FileSystemRights.Synchronize)
        };
        assert(CiJitLocalProjectionReader.IsTrustedStatusAcl(
                admins, trustedFileRules, reader, FileSystemRights.Read,
                accessRulesProtected: false, requireProtectedAcl: false),
            "trusted status file ACL permits the configured reader read-only");
        assert(!CiJitLocalProjectionReader.IsNoReparsePoint(FileAttributes.Directory | FileAttributes.ReparsePoint),
            "reparse status boundary is refused");
        assert(CiJitLocalProjectionReader.IsNoReparsePoint(FileAttributes.Directory),
            "ordinary status directory is not a reparse point");

        var parentRules = new[]
        {
            Rule(system, FileSystemRights.FullControl),
            Rule(admins, FileSystemRights.FullControl),
            Rule(reader, FileSystemRights.ReadAndExecute)
        };
        assert(CiJitLocalProjectionReader.IsTrustedParentAcl(admins, parentRules),
            "trusted parent permits normal-user read-only access");
        assert(!CiJitLocalProjectionReader.IsTrustedParentAcl(
                admins, parentRules.Append(Rule(stranger, FileSystemRights.DeleteSubdirectoriesAndFiles))),
            "replaceable status parent is refused");

        var now = new DateTimeOffset(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);
        var boot = now.AddHours(-2);
        var path = Path.Combine(Path.GetTempPath(), $"ci-jit-status-{Guid.NewGuid():N}.json");
        try
        {
            var missing = CiJitLocalProjectionReader.ReadProjection(path, now, boot, _ => true);
            assert(missing.State == CiJitOwnerState.Unknown,
                "missing projection maps to unknown");

            File.WriteAllText(path, "{ malformed");
            var malformed = CiJitLocalProjectionReader.ReadProjection(path, now, boot, _ => true);
            assert(malformed.State == CiJitOwnerState.Unknown && malformed.ReasonCode == "MALFORMED_STATE",
                "malformed projection maps to unknown");

            File.WriteAllText(path, Projection(now, boot));
            var untrusted = CiJitLocalProjectionReader.ReadProjection(path, now, boot, _ => false);
            assert(untrusted.State == CiJitOwnerState.Unknown && untrusted.ReasonCode == "SOURCE_UNAVAILABLE",
                "untrusted read boundary maps to source unavailable");

            var trusted = CiJitLocalProjectionReader.ReadProjection(path, now, boot, _ => true);
            assert(trusted.State == CiJitOwnerState.Queued,
                "trusted read-only projection is parsed without mutation");
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static FileSystemAccessRule Rule(SecurityIdentifier sid, FileSystemRights rights) =>
        new(sid, rights, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);

    private static string Projection(DateTimeOffset now, DateTimeOffset boot) => $$"""
        {
          "schema": 1,
          "source_version": "ci-jit-v1",
          "boot_started_utc": "{{boot:O}}",
          "local_observed_at_utc": "{{now:O}}",
          "provenance_valid": true,
          "proven_failure": false,
          "controller_phase": null,
          "capacity": "READY",
          "reason_code": null,
          "queue_observed_at_utc": "{{now:O}}",
          "queue_state": "FRESH",
          "eligible_queued_count": 1,
          "held_queued_count": 0,
          "selected_profile": "bizops-secret-scan",
          "selected_run_id": 1001,
          "selected_job_id": 2001
        }
        """;
}
