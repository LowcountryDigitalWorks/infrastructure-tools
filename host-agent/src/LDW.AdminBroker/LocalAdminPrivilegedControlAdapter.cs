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
    private static readonly Regex GuidResultRegex = new(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly string _root;
    private readonly string _requestRoot;
    private readonly string _resultRoot;
    private readonly string _requestSlot;
    private readonly TimeSpan _executionTimeout;
    private readonly TimeSpan _retentionTtl;
    private readonly Func<string, CancellationToken, bool> _startTask;
    private readonly bool _skipAclCheckForTesting;

    public ScheduledTaskAdminPrivilegedOperationBoundary()
        : this(null, null, null, null, false)
    {
    }

    internal ScheduledTaskAdminPrivilegedOperationBoundary(
        string? rootOverride = null,
        TimeSpan? executionTimeoutOverride = null,
        TimeSpan? retentionTtlOverride = null,
        Func<string, CancellationToken, bool>? startTaskOverride = null,
        bool skipAclCheckForTesting = false)
    {
        _root = rootOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LDW", "PrivilegedControl");
        _requestRoot = Path.Combine(_root, "requests");
        _resultRoot = Path.Combine(_root, "results");
        _requestSlot = Path.Combine(_requestRoot, "request.json");
        _executionTimeout = executionTimeoutOverride ?? TimeSpan.FromMinutes(15);
        _retentionTtl = retentionTtlOverride ?? TimeSpan.FromHours(24);
        _startTask = startTaskOverride ?? StartTask;
        _skipAclCheckForTesting = skipAclCheckForTesting;
    }

    public AdminPrivilegedControlResult Queue(string operationId, Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
            return new AdminPrivilegedControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);

        ReconcileStaleStateAndPrune();

        if (!AssertTrustBoundary())
            return new AdminPrivilegedControlResult(false, "BLOCKED", "PROVENANCE_MISMATCH", correlationId.ToString("D"), operationId);

        // Durable replay check: if result already exists, reject duplicate execution
        var resultPath = Path.Combine(_resultRoot, correlationId.ToString("D") + ".json");
        if (File.Exists(resultPath))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "DUPLICATE_REQUEST", correlationId.ToString("D"), operationId);

        if (!IsDirectChild(_requestRoot, _requestSlot) || File.Exists(_requestSlot))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "BUSY", correlationId.ToString("D"), operationId);

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

        ReconcileStaleStateAndPrune();

        if (!AssertTrustBoundary())
            return new AdminPrivilegedControlResult(false, "FAILED", "PROVENANCE_MISMATCH", correlationId.ToString("D"));

        var path = Path.Combine(_resultRoot, correlationId.ToString("D") + ".json");
        if (!IsDirectChild(_resultRoot, path) || !File.Exists(path))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND", correlationId.ToString("D"));

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

    internal void ReconcileStaleStateAndPrune()
    {
        try
        {
            // 1. Demand-driven stale request reconciliation
            if (File.Exists(_requestSlot))
            {
                var info = new FileInfo(_requestSlot);
                if (DateTime.UtcNow - info.LastWriteTimeUtc >= _executionTimeout)
                {
                    string? strandedCorrId = null;
                    string? strandedOpId = null;
                    try
                    {
                        var bytes = File.ReadAllBytes(_requestSlot);
                        var req = JsonSerializer.Deserialize<RequestEnvelope>(bytes, JsonOptions);
                        if (req is not null && Guid.TryParseExact(req.CorrelationId, "D", out _))
                        {
                            strandedCorrId = req.CorrelationId;
                            strandedOpId = req.OperationId;
                        }
                    }
                    catch { }

                    if (strandedCorrId is not null && Directory.Exists(_resultRoot))
                    {
                        var targetResultPath = Path.Combine(_resultRoot, strandedCorrId + ".json");
                        if (!File.Exists(targetResultPath))
                        {
                            var timeoutEnvelope = new ResultEnvelope(
                                EnvelopeSchema,
                                strandedCorrId,
                                strandedOpId ?? "UNKNOWN",
                                false,
                                "FAILED",
                                "TIMEOUT",
                                new Dictionary<string, string> { ["reconciliation"] = "TASK_TIMEOUT_OR_CRASH" });
                            var timeoutBytes = JsonSerializer.SerializeToUtf8Bytes(timeoutEnvelope, JsonOptions);
                            var pendingPath = Path.Combine(_resultRoot, ".pending-" + strandedCorrId + ".json");
                            try
                            {
                                File.WriteAllBytes(pendingPath, timeoutBytes);
                                File.Move(pendingPath, targetResultPath, false);
                            }
                            catch { }
                        }
                    }

                    TryDeleteOwned(_requestSlot);
                }
            }

            // 2. Demand-driven result lifecycle pruning
            if (Directory.Exists(_resultRoot) && !IsReparsePoint(_resultRoot))
            {
                var dir = new DirectoryInfo(_resultRoot);
                foreach (var file in dir.EnumerateFiles("*.json", SearchOption.TopDirectoryOnly))
                {
                    if (file.Name.StartsWith(".pending", StringComparison.OrdinalIgnoreCase))
                    {
                        if (DateTime.UtcNow - file.LastWriteTimeUtc >= TimeSpan.FromMinutes(5))
                        {
                            try { file.Delete(); } catch { }
                        }
                        continue;
                    }

                    if (GuidResultRegex.IsMatch(file.Name))
                    {
                        if (DateTime.UtcNow - file.LastWriteTimeUtc >= _retentionTtl)
                        {
                            try { file.Delete(); } catch { }
                        }
                    }
                }
            }
        }
        catch { }
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

            // Verify resultRoot security: owner SYSTEM/Admins; non-admins MUST NOT have write permissions
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

            // Verify requestRoot security: owner SYSTEM/Admins
            var requestInfo = new DirectoryInfo(_requestRoot);
            var requestSecurity = requestInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var requestOwner = requestSecurity.GetOwner(typeof(SecurityIdentifier))?.Value;
            if (requestOwner is null || !allowedOwners.Contains(requestOwner))
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
                    var attr = File.GetAttributes(cursor);
                    if ((attr & FileAttributes.ReparsePoint) != 0)
                        return true;
                }
                var parent = Path.GetDirectoryName(cursor);
                if (string.IsNullOrEmpty(parent) || string.Equals(parent, cursor, StringComparison.OrdinalIgnoreCase))
                    break;
                cursor = parent;
            }
            return false;
        }
        catch { return true; }
    }

    private bool IsDirectChild(string parent, string child)
    {
        var expectedParent = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(child);
        return full.StartsWith(expectedParent, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetDirectoryName(full), expectedParent.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

    private void TryDeleteOwned(string path)
    {
        try { if (File.Exists(path) && IsDirectChild(_requestRoot, path)) File.Delete(path); } catch { }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal sealed record RequestEnvelope(
        int Schema,
        string CorrelationId,
        string OperationId);

    internal sealed record ResultEnvelope(
        int Schema,
        string CorrelationId,
        string OperationId,
        bool Success,
        string ResultState,
        string ReasonCode,
        IReadOnlyDictionary<string, string>? Details);
}
