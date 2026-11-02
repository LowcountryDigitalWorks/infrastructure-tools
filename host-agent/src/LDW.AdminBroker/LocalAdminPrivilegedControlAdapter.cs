using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

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

    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LDW", "PrivilegedControl");
    private static readonly string RequestRoot = Path.Combine(Root, "requests");
    private static readonly string ResultRoot = Path.Combine(Root, "results");
    private static readonly string RequestSlot = Path.Combine(RequestRoot, "request.json");

    public AdminPrivilegedControlResult Queue(string operationId, Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
            return new AdminPrivilegedControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);

        if (!IsExpectedDirectory(RequestRoot) || !IsExpectedDirectory(ResultRoot))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE", correlationId.ToString("D"), operationId);

        if (!IsDirectChild(RequestRoot, RequestSlot) || File.Exists(RequestSlot))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "BUSY", correlationId.ToString("D"), operationId);

        var envelope = new RequestEnvelope(
            EnvelopeSchema,
            correlationId.ToString("D"),
            operationId);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaximumEnvelopeBytes)
            return new AdminPrivilegedControlResult(false, "FAILED", "FAILED", correlationId.ToString("D"), operationId);

        var temp = Path.Combine(RequestRoot, ".pending-" + correlationId.ToString("N") + ".json");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temp, RequestSlot, false);

            var start = StartTask(TaskName, cancellationToken);
            if (!start)
            {
                TryDeleteOwned(RequestSlot);
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
            TryDeleteOwned(RequestSlot);
            return new AdminPrivilegedControlResult(false, "FAILED", "FAILED", correlationId.ToString("D"), operationId);
        }
    }

    public AdminPrivilegedControlResult GetResult(Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (correlationId == Guid.Empty || !IsExpectedDirectory(ResultRoot))
            return new AdminPrivilegedControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND", correlationId.ToString("D"));

        var path = Path.Combine(ResultRoot, correlationId.ToString("D") + ".json");
        if (!IsDirectChild(ResultRoot, path) || !File.Exists(path))
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
            return info.Exists && (info.Attributes & FileAttributes.ReparsePoint) == 0;
        }
        catch { return false; }
    }

    private static bool IsDirectChild(string parent, string child)
    {
        var expectedParent = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(child);
        return full.StartsWith(expectedParent, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetDirectoryName(full), expectedParent.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDeleteOwned(string path)
    {
        try { if (File.Exists(path) && IsDirectChild(RequestRoot, path)) File.Delete(path); } catch { }
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
