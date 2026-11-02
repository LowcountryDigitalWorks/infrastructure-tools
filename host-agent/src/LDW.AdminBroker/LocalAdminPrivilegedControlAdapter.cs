using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace LDW.AdminBroker;

internal interface IAdminPrivilegedOperationBoundary
{
    AdminPrivilegedControlResult Queue(string operationId, Guid correlationId, CancellationToken cancellationToken);
    AdminPrivilegedControlResult GetResult(Guid correlationId, CancellationToken cancellationToken);
}

public sealed class LocalAdminPrivilegedControlAdapter : IAdminPrivilegedControlAdapter
{
    private readonly IAdminPrivilegedOperationBoundary _boundary;

    public LocalAdminPrivilegedControlAdapter()
        : this(new ScheduledTaskAdminPrivilegedOperationBoundary())
    {
    }

    internal LocalAdminPrivilegedControlAdapter(IAdminPrivilegedOperationBoundary boundary)
    {
        _boundary = boundary ?? throw new ArgumentNullException(nameof(boundary));
    }

    public AdminPrivilegedControlResult RunReviewedOperation(string operationId, Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!AdminReviewedOperationRegistry.IsValidOperation(operationId))
        {
            return new AdminPrivilegedControlResult(false, "BLOCKED", "UNKNOWN_OPERATION", correlationId.ToString("D"), operationId);
        }

        return _boundary.Queue(operationId, correlationId, cancellationToken);
    }

    public AdminPrivilegedControlResult GetOperationResult(Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _boundary.GetResult(correlationId, cancellationToken);
    }
}

internal sealed class ScheduledTaskAdminPrivilegedOperationBoundary : IAdminPrivilegedOperationBoundary
{
    internal const int EnvelopeSchema = 1;
    private const int MaximumEnvelopeBytes = 16 * 1024;
    private const string TaskName = @"\LDW-ADMIN-REVIEWED-OPERATION";

    private readonly string _root;
    private readonly string _requestRoot;
    private readonly string _resultRoot;
    private readonly string _requestSlot;
    private readonly TimeSpan _executionTimeout;
    private readonly Func<string, CancellationToken, bool> _startTask;
    private readonly bool _skipAclCheckForTesting;

    public ScheduledTaskAdminPrivilegedOperationBoundary()
        : this(null, null, null, false)
    {
    }

    internal ScheduledTaskAdminPrivilegedOperationBoundary(
        string? rootOverride = null,
        TimeSpan? executionTimeoutOverride = null,
        Func<string, CancellationToken, bool>? startTaskOverride = null,
        bool skipAclCheckForTesting = false)
    {
        _root = rootOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LDW", "PrivilegedControl");
        _requestRoot = Path.Combine(_root, "requests");
        _resultRoot = Path.Combine(_root, "results");
        _requestSlot = Path.Combine(_requestRoot, "request.json");
        _executionTimeout = executionTimeoutOverride ?? TimeSpan.FromMinutes(15);
        _startTask = startTaskOverride ?? StartTask;
        _skipAclCheckForTesting = skipAclCheckForTesting;
    }

    public AdminPrivilegedControlResult Queue(string operationId, Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
            return new AdminPrivilegedControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);

        if (!AssertTrustBoundary())
            return new AdminPrivilegedControlResult(false, "BLOCKED", "PROVENANCE_MISMATCH", correlationId.ToString("D"), operationId);

        // Durable replay check: if result already exists, reject duplicate execution without overwriting
        var resultPath = Path.Combine(_resultRoot, correlationId.ToString("D") + ".json");
        if (File.Exists(resultPath))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "DUPLICATE_REQUEST", correlationId.ToString("D"), operationId);

        if (!IsDirectChild(_requestRoot, _requestSlot))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "PROVENANCE_MISMATCH", correlationId.ToString("D"), operationId);

        if (File.Exists(_requestSlot))
        {
            try
            {
                var slotInfo = new FileInfo(_requestSlot);
                if (DateTime.UtcNow - slotInfo.LastWriteTimeUtc >= _executionTimeout)
                {
                    // Stale stranded request detected; request privileged helper to execute demand-driven reconciliation
                    _startTask(TaskName, cancellationToken);
                }
            }
            catch { }
            return new AdminPrivilegedControlResult(false, "BLOCKED", "BUSY", correlationId.ToString("D"), operationId);
        }

        var envelope = new RequestEnvelope(
            EnvelopeSchema,
            correlationId.ToString("D"),
            operationId);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaximumEnvelopeBytes)
            return new AdminPrivilegedControlResult(false, "FAILED", "FAILED", correlationId.ToString("D"), operationId);

        var temp = Path.Combine(_requestRoot, ".pending-" + correlationId.ToString("N") + ".json");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temp, _requestSlot, false);

            var start = _startTask(TaskName, cancellationToken);
            if (!start)
            {
                TryDeleteOwned(_requestSlot);
                return new AdminPrivilegedControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);
            }
            return new AdminPrivilegedControlResult(true, "QUEUED", "NONE", correlationId.ToString("D"), operationId);
        }
        catch (OperationCanceledException)
        {
            TryDeleteOwned(temp);
            throw;
        }
        catch (IOException)
        {
            TryDeleteOwned(temp);
            return new AdminPrivilegedControlResult(false, "BLOCKED", "BUSY", correlationId.ToString("D"), operationId);
        }
        catch
        {
            TryDeleteOwned(temp);
            TryDeleteOwned(_requestSlot);
            return new AdminPrivilegedControlResult(false, "FAILED", "FAILED", correlationId.ToString("D"), operationId);
        }
    }

    public AdminPrivilegedControlResult GetResult(Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (correlationId == Guid.Empty)
            return new AdminPrivilegedControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND", correlationId.ToString("D"));

        if (!AssertTrustBoundary())
            return new AdminPrivilegedControlResult(false, "FAILED", "PROVENANCE_MISMATCH", correlationId.ToString("D"));

        var path = Path.Combine(_resultRoot, correlationId.ToString("D") + ".json");
        if (IsDirectChild(_resultRoot, path) && File.Exists(path))
        {
            try
            {
                var info = new FileInfo(path);
                if (info.Length <= 0 || info.Length > MaximumEnvelopeBytes)
                    return new AdminPrivilegedControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT", correlationId.ToString("D"));

                var result = JsonSerializer.Deserialize<ResultEnvelope>(File.ReadAllBytes(path), JsonOptions);
                if (result is null || result.Schema != EnvelopeSchema
                    || !string.Equals(result.CorrelationId, correlationId.ToString("D"), StringComparison.Ordinal)
                    || !AdminPrivilegedControlContract.IsResultState(result.ResultState)
                    || !AdminPrivilegedControlContract.IsReasonCode(result.ReasonCode))
                    return new AdminPrivilegedControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT", correlationId.ToString("D"));

                // In-flight state handling
                if (string.Equals(result.ResultState, "STARTED", StringComparison.Ordinal))
                {
                    if (DateTime.UtcNow - info.LastWriteTimeUtc < _executionTimeout)
                    {
                        return new AdminPrivilegedControlResult(true, "STARTED", "NONE", result.CorrelationId, result.OperationId, result.Details);
                    }
                    // In-flight action timed out / crashed; trigger fixed task for privileged reconciliation
                    _startTask(TaskName, cancellationToken);
                    return new AdminPrivilegedControlResult(false, "FAILED", "TIMEOUT", correlationId.ToString("D"), result.OperationId,
                        new Dictionary<string, string> { ["reconciliation"] = "TASK_TIMEOUT_OR_CRASH" });
                }

                var projected = new AdminPrivilegedControlResult(
                    result.Success,
                    result.ResultState,
                    result.ReasonCode,
                    result.CorrelationId,
                    result.OperationId,
                    result.Details);

                return AdminPrivilegedControlContract.IsSafeResult(projected)
                    ? projected
                    : new AdminPrivilegedControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT", correlationId.ToString("D"));
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                return new AdminPrivilegedControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT", correlationId.ToString("D"));
            }
        }

        // If result file does not exist, check if request is still queued in request.json
        if (IsDirectChild(_requestRoot, _requestSlot) && File.Exists(_requestSlot))
        {
            try
            {
                var slotInfo = new FileInfo(_requestSlot);
                var bytes = File.ReadAllBytes(_requestSlot);
                var req = JsonSerializer.Deserialize<RequestEnvelope>(bytes, JsonOptions);
                if (req is not null && string.Equals(req.CorrelationId, correlationId.ToString("D"), StringComparison.Ordinal))
                {
                    if (DateTime.UtcNow - slotInfo.LastWriteTimeUtc < _executionTimeout)
                    {
                        return new AdminPrivilegedControlResult(true, "QUEUED", "NONE", correlationId.ToString("D"), req.OperationId);
                    }
                    // Request expired without starting; prompt privileged task to reconcile
                    _startTask(TaskName, cancellationToken);
                    return new AdminPrivilegedControlResult(false, "FAILED", "TIMEOUT", correlationId.ToString("D"), req.OperationId,
                        new Dictionary<string, string> { ["reconciliation"] = "REQUEST_EXPIRED" });
                }
            }
            catch { }
        }

        return new AdminPrivilegedControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND", correlationId.ToString("D"));
    }

    private bool AssertTrustBoundary()
    {
        if (!IsExpectedDirectory(_requestRoot) || !IsExpectedDirectory(_resultRoot))
            return false;

        if (_skipAclCheckForTesting)
            return true;

        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            var allowedOwners = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-18", "S-1-5-32-544" };

            // 1. Verify resultRoot security:
            // Owner MUST be SYSTEM or Builtin Administrators.
            // Non-administrators MUST NOT have Write/Modify/Delete rights.
            var resultInfo = new DirectoryInfo(_resultRoot);
            var resultSecurity = resultInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var resultOwner = resultSecurity.GetOwner(typeof(SecurityIdentifier))?.Value;
            if (resultOwner is null || !allowedOwners.Contains(resultOwner))
                return false;

            const FileSystemRights writeRights = FileSystemRights.Write |
                FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership;

            foreach (FileSystemAccessRule rule in resultSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writeRights) != 0)
                {
                    var sid = rule.IdentityReference.Value;
                    if (!allowedOwners.Contains(sid))
                        return false;
                }
            }

            // 2. Verify requestRoot security:
            // Owner MUST be SYSTEM or Builtin Administrators.
            // Caller SID MUST be the only non-admin principal with Modify rights.
            // NO other non-admin principal may have any write/modify/delete rights.
            var requestInfo = new DirectoryInfo(_requestRoot);
            var requestSecurity = requestInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var requestOwner = requestSecurity.GetOwner(typeof(SecurityIdentifier))?.Value;
            if (requestOwner is null || !allowedOwners.Contains(requestOwner))
                return false;

            var currentSid = WindowsIdentity.GetCurrent().User?.Value;
            if (string.IsNullOrWhiteSpace(currentSid))
                return false;

            var currentOwnerHasModify = false;
            foreach (FileSystemAccessRule rule in requestSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Allow)
                {
                    var sid = rule.IdentityReference.Value;
                    if (string.Equals(sid, currentSid, StringComparison.OrdinalIgnoreCase))
                    {
                        if ((rule.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify)
                        {
                            currentOwnerHasModify = true;
                        }
                    }
                    else if (!allowedOwners.Contains(sid))
                    {
                        if ((rule.FileSystemRights & writeRights) != 0)
                        {
                            return false;
                        }
                    }
                }
            }

            if (!currentOwnerHasModify)
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool StartTask(string taskName, CancellationToken cancellationToken)
    {
        var executable = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        if (!File.Exists(executable)) return false;
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        process.StartInfo.ArgumentList.Add("/Run");
        process.StartInfo.ArgumentList.Add("/TN");
        process.StartInfo.ArgumentList.Add(taskName);
        if (!process.Start()) return false;
        process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, cancellationToken);
        process.StandardError.BaseStream.CopyToAsync(Stream.Null, cancellationToken);
        process.WaitForExit();
        cancellationToken.ThrowIfCancellationRequested();
        return process.ExitCode == 0;
    }

    private static bool IsExpectedDirectory(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            if (!info.Exists) return false;
            return !IsReparsePoint(path);
        }
        catch { return false; }
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            var cursor = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(cursor))
            {
                if (Directory.Exists(cursor) || File.Exists(cursor))
                {
                    var entry = new DirectoryInfo(cursor);
                    if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        return true;
                }
                var parent = Path.GetDirectoryName(cursor);
                if (string.IsNullOrEmpty(parent) || string.Equals(parent, cursor, StringComparison.Ordinal))
                    break;
                cursor = parent;
            }
            return false;
        }
        catch
        {
            return true;
        }
    }

    private static bool IsDirectChild(string parentDirectory, string candidatePath)
    {
        try
        {
            var parentFull = Path.GetFullPath(parentDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var candidateFull = Path.GetFullPath(candidatePath);
            var directParent = Path.GetDirectoryName(candidateFull)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(parentFull, directParent, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void TryDeleteOwned(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private sealed record RequestEnvelope(
        [property: JsonPropertyName("schema")] int Schema,
        [property: JsonPropertyName("correlationId")] string CorrelationId,
        [property: JsonPropertyName("operationId")] string OperationId);

    private sealed record ResultEnvelope(
        [property: JsonPropertyName("schema")] int Schema,
        [property: JsonPropertyName("correlationId")] string CorrelationId,
        [property: JsonPropertyName("operationId")] string OperationId,
        [property: JsonPropertyName("success")] bool Success,
        [property: JsonPropertyName("resultState")] string ResultState,
        [property: JsonPropertyName("reasonCode")] string ReasonCode,
        [property: JsonPropertyName("details")] IReadOnlyDictionary<string, string>? Details = null);
}
