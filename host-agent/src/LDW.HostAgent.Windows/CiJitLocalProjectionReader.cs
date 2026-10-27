using System.Security.AccessControl;
using System.Security.Principal;
using System.Security;
using System.Text.Json;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class CiJitLocalProjectionReader
{
    internal static string ProjectionPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LDW",
        "CiJitStatus",
        "status.json");

    public CiJitStatusSnapshot Read()
    {
        var now = DateTimeOffset.UtcNow;
        var boot = now - TimeSpan.FromMilliseconds(Environment.TickCount64);
        return ReadProjection(ProjectionPath, now, boot, IsTrustedBoundary);
    }

    internal static CiJitStatusSnapshot ReadProjection(
        string path,
        DateTimeOffset now,
        DateTimeOffset boot,
        Func<string, bool> isTrustedBoundary)
    {
        try
        {
            if (!File.Exists(path))
                return CiJitLocalProjection.Unavailable(now);

            try
            {
                if (!isTrustedBoundary(path))
                    return CiJitLocalProjection.Unavailable(now, "SOURCE_UNAVAILABLE");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException
                or ArgumentException or InvalidOperationException or NotSupportedException)
            {
                return CiJitLocalProjection.Unavailable(now, "SOURCE_UNAVAILABLE");
            }

            var json = File.ReadAllText(path);
            return CiJitLocalProjection.Parse(json, now, boot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return CiJitLocalProjection.Unavailable(now, "SOURCE_UNAVAILABLE");
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or ArgumentException or OverflowException)
        {
            return CiJitLocalProjection.Unavailable(now, "MALFORMED_STATE");
        }
    }

    internal static bool IsNoReparsePoint(FileAttributes attributes) =>
        (attributes & FileAttributes.ReparsePoint) == 0;

    internal static bool IsTrustedParentAcl(
        SecurityIdentifier owner,
        IEnumerable<FileSystemAccessRule> rules)
    {
        if (!IsTrustedOwner(owner))
            return false;

        var replace = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        return !rules.Any(rule =>
            rule.AccessControlType == AccessControlType.Allow &&
            (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
            (rule.FileSystemRights & replace) != 0 &&
            !IsTrustedWriter(rule.IdentityReference.Value));
    }

    internal static bool IsTrustedStatusAcl(
        SecurityIdentifier owner,
        IEnumerable<FileSystemAccessRule> rules,
        SecurityIdentifier reader,
        FileSystemRights requiredReaderRights,
        bool accessRulesProtected,
        bool requireProtectedAcl)
    {
        if (!IsTrustedOwner(owner) || (requireProtectedAcl && !accessRulesProtected))
            return false;

        var write = FileSystemRights.Write | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;
        var readerRights = (FileSystemRights)0;
        foreach (var rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;

            var sid = rule.IdentityReference.Value;
            if (IsTrustedWriter(sid))
                continue;
            if (!string.Equals(sid, reader.Value, StringComparison.Ordinal) ||
                (rule.FileSystemRights & write) != 0)
                return false;

            readerRights |= rule.FileSystemRights;
        }

        return (readerRights & requiredReaderRights) == requiredReaderRights;
    }

    private static bool IsTrustedBoundary(string path)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(programData))
            return false;
        programData = Path.GetFullPath(programData);

        var ldwRoot = Path.Combine(programData, "LDW");
        var statusRoot = Path.Combine(ldwRoot, "CiJitStatus");
        var expectedPath = Path.Combine(statusRoot, "status.json");
        if (!string.Equals(Path.GetFullPath(path), expectedPath, StringComparison.OrdinalIgnoreCase))
            return false;

        for (var cursor = expectedPath; cursor is not null; cursor = Path.GetDirectoryName(cursor))
        {
            if (!IsNoReparsePoint(File.GetAttributes(cursor)))
                return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var reader = identity.User;
        if (reader is null)
            return false;

        return IsTrustedParentBoundary(programData) &&
            IsTrustedParentBoundary(ldwRoot) &&
            IsTrustedStatusPath(statusRoot, reader, FileSystemRights.ReadAndExecute, requireProtectedAcl: true) &&
            IsTrustedStatusPath(expectedPath, reader, FileSystemRights.Read, requireProtectedAcl: false);
    }

    private static bool IsTrustedParentBoundary(string path)
    {
        var item = new DirectoryInfo(path);
        var acl = FileSystemAclExtensions.GetAccessControl(item);
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>();
        return owner is not null && IsTrustedParentAcl(owner, rules);
    }

    private static bool IsTrustedStatusPath(
        string path,
        SecurityIdentifier reader,
        FileSystemRights requiredReaderRights,
        bool requireProtectedAcl)
    {
        FileSystemSecurity acl = Directory.Exists(path)
            ? FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path))
            : FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
        if (requireProtectedAcl && !acl.AreAccessRulesProtected)
            return false;

        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>();
        return owner is not null &&
            IsTrustedStatusAcl(owner, rules, reader, requiredReaderRights,
                acl.AreAccessRulesProtected, requireProtectedAcl);
    }

    private static bool IsTrustedOwner(SecurityIdentifier owner) =>
        owner.Value is "S-1-5-18" or "S-1-5-32-544";

    private static bool IsTrustedWriter(string sid) =>
        sid is "S-1-5-18" or "S-1-5-32-544";
}
