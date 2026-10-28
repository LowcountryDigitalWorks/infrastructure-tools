using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LDW.HostAgent.Core;

namespace LDW.AdminBroker;

internal enum CiJitFixedOperation
{
    Discover,
    RunOnce,
    Recover,
    AbortActive,
    ListStale,
    RetireStale
}

internal interface ICiJitOperationBoundary
{
    CiJitControlResult Queue(CiJitFixedOperation operation, long? runId, CancellationToken cancellationToken);
    CiJitControlResult GetResult(Guid operationId, CancellationToken cancellationToken);
}

internal interface ICiJitStatusSource
{
    CiJitStatusSnapshot Read(CancellationToken cancellationToken);
}

public sealed class LocalCiJitControlAdapter : ICiJitControlAdapter
{
    private readonly ICiJitStatusSource statusSource;
    private readonly ICiJitOperationBoundary boundary;

    public LocalCiJitControlAdapter()
        : this(new FixedCiJitStatusSource(), new ScheduledTaskCiJitOperationBoundary())
    {
    }

    internal LocalCiJitControlAdapter(ICiJitStatusSource statusSource, ICiJitOperationBoundary boundary)
    {
        this.statusSource = statusSource ?? throw new ArgumentNullException(nameof(statusSource));
        this.boundary = boundary ?? throw new ArgumentNullException(nameof(boundary));
    }

    public CiJitControlResult GetStatus(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new CiJitControlResult(true, "PASS", "NONE", Status: statusSource.Read(cancellationToken));
    }

    public CiJitControlResult Discover(CancellationToken cancellationToken) =>
        boundary.Queue(CiJitFixedOperation.Discover, null, cancellationToken);

    public CiJitControlResult RunOnce(CancellationToken cancellationToken) =>
        boundary.Queue(CiJitFixedOperation.RunOnce, null, cancellationToken);

    public CiJitControlResult Recover(CancellationToken cancellationToken) =>
        boundary.Queue(CiJitFixedOperation.Recover, null, cancellationToken);

    public CiJitControlResult AbortActive(CancellationToken cancellationToken) =>
        boundary.Queue(CiJitFixedOperation.AbortActive, null, cancellationToken);

    public CiJitControlResult ListStale(CancellationToken cancellationToken) =>
        boundary.Queue(CiJitFixedOperation.ListStale, null, cancellationToken);

    public CiJitControlResult RetireStale(long runId, CancellationToken cancellationToken)
    {
        if (runId <= 0) return new CiJitControlResult(false, "BLOCKED", "NOT_STALE");
        return boundary.Queue(CiJitFixedOperation.RetireStale, runId, cancellationToken);
    }

    public CiJitControlResult GetOperationResult(Guid operationId, CancellationToken cancellationToken) =>
        boundary.GetResult(operationId, cancellationToken);
}

internal sealed class FixedCiJitStatusSource : ICiJitStatusSource
{
    private static readonly string StatusPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LDW", "CiJitStatus", "status.json");

    public CiJitStatusSnapshot Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        if (!OperatingSystem.IsWindows() || !File.Exists(StatusPath))
            return CiJitLocalProjection.Unavailable(now);

        try
        {
            var info = new FileInfo(StatusPath);
            if (info.Length <= 0 || info.Length > 64 * 1024)
                return CiJitLocalProjection.Unavailable(now, "MALFORMED_STATE");
            var text = File.ReadAllText(StatusPath, Encoding.UTF8);
            var boot = now.AddMilliseconds(-Environment.TickCount64);
            return CiJitLocalProjection.Parse(text, now, boot);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return CiJitLocalProjection.Unavailable(now, "MALFORMED_STATE");
        }
    }
}

internal sealed class ScheduledTaskCiJitOperationBoundary : ICiJitOperationBoundary
{
    internal const int EnvelopeSchema = 1;
    private const int MaximumEnvelopeBytes = 16 * 1024;
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LDW", "CiJitControl");
    private static readonly string RequestRoot = Path.Combine(Root, "requests");
    private static readonly string ResultRoot = Path.Combine(Root, "results");

    private static readonly IReadOnlyDictionary<CiJitFixedOperation, string> TaskNames =
        new Dictionary<CiJitFixedOperation, string>
        {
            [CiJitFixedOperation.Discover] = @"\LDW-CI-JIT-DISCOVER",
            [CiJitFixedOperation.RunOnce] = @"\LDW-CI-JIT-RUN-ONCE",
            [CiJitFixedOperation.Recover] = @"\LDW-CI-JIT-RECOVER",
            [CiJitFixedOperation.AbortActive] = @"\LDW-CI-JIT-ABORT-ACTIVE",
            [CiJitFixedOperation.ListStale] = @"\LDW-CI-JIT-LIST-STALE",
            [CiJitFixedOperation.RetireStale] = @"\LDW-CI-JIT-RETIRE-STALE"
        };

    private static readonly IReadOnlyDictionary<CiJitFixedOperation, string> SlotNames =
        new Dictionary<CiJitFixedOperation, string>
        {
            [CiJitFixedOperation.Discover] = "discover.json",
            [CiJitFixedOperation.RunOnce] = "run-once.json",
            [CiJitFixedOperation.Recover] = "recover.json",
            [CiJitFixedOperation.AbortActive] = "abort-active.json",
            [CiJitFixedOperation.ListStale] = "list-stale.json",
            [CiJitFixedOperation.RetireStale] = "retire-stale.json"
        };

    public CiJitControlResult Queue(CiJitFixedOperation operation, long? runId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows() || !TaskNames.ContainsKey(operation))
            return new CiJitControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE");
        if ((operation == CiJitFixedOperation.RetireStale) != runId.HasValue || runId is <= 0)
            return new CiJitControlResult(false, "BLOCKED", "NOT_STALE");
        if (!IsExpectedDirectory(RequestRoot) || !IsExpectedDirectory(ResultRoot))
            return new CiJitControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE");

        var operationId = Guid.NewGuid();
        var envelope = new RequestEnvelope(
            EnvelopeSchema,
            operationId.ToString("D"),
            OperationToken(operation),
            runId);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaximumEnvelopeBytes)
            return new CiJitControlResult(false, "FAILED", "FAILED");

        var slot = Path.Combine(RequestRoot, SlotNames[operation]);
        if (!IsDirectChild(RequestRoot, slot) || File.Exists(slot))
            return new CiJitControlResult(false, "BLOCKED", "BUSY");

        var temp = Path.Combine(RequestRoot, ".pending-" + operationId.ToString("N") + ".json");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temp, slot, false);
            var start = StartTask(TaskNames[operation], cancellationToken);
            if (!start)
            {
                TryDeleteOwned(slot);
                return new CiJitControlResult(false, "BLOCKED", "ADAPTER_UNAVAILABLE");
            }
            return new CiJitControlResult(true, "QUEUED", "NONE", operationId.ToString("D"));
        }
        catch (OperationCanceledException)
        {
            TryDeleteOwned(temp);
            throw;
        }
        catch (IOException)
        {
            TryDeleteOwned(temp);
            return new CiJitControlResult(false, "BLOCKED", "BUSY");
        }
        catch
        {
            TryDeleteOwned(temp);
            TryDeleteOwned(slot);
            return new CiJitControlResult(false, "FAILED", "FAILED");
        }
    }

    public CiJitControlResult GetResult(Guid operationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (operationId == Guid.Empty || !IsExpectedDirectory(ResultRoot))
            return new CiJitControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND");

        var path = Path.Combine(ResultRoot, operationId.ToString("D") + ".json");
        if (!IsDirectChild(ResultRoot, path) || !File.Exists(path))
            return new CiJitControlResult(false, "BLOCKED", "OPERATION_NOT_FOUND");

        try
        {
            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > MaximumEnvelopeBytes)
                return new CiJitControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT");
            var result = JsonSerializer.Deserialize<ResultEnvelope>(File.ReadAllBytes(path), JsonOptions);
            if (result is null || result.Schema != EnvelopeSchema
                || !string.Equals(result.OperationId, operationId.ToString("D"), StringComparison.Ordinal)
                || !CiJitControlContract.IsResultState(result.ResultState)
                || !CiJitControlContract.IsReasonCode(result.ReasonCode))
                return new CiJitControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT");

            var projected = new CiJitControlResult(
                result.Success,
                result.ResultState,
                result.ReasonCode,
                result.OperationId,
                result.ProfileId,
                result.RunId,
                result.JobId,
                null,
                result.StaleItems);
            return CiJitControlContract.IsSafeResult(projected)
                ? projected
                : new CiJitControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT");
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return new CiJitControlResult(false, "FAILED", "INVALID_ADAPTER_RESULT");
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

    internal static string OperationToken(CiJitFixedOperation operation) => operation switch
    {
        CiJitFixedOperation.Discover => "DISCOVER",
        CiJitFixedOperation.RunOnce => "RUN_ONCE",
        CiJitFixedOperation.Recover => "RECOVER",
        CiJitFixedOperation.AbortActive => "ABORT_ACTIVE",
        CiJitFixedOperation.ListStale => "LIST_STALE",
        CiJitFixedOperation.RetireStale => "RETIRE_STALE",
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal sealed record RequestEnvelope(
        int Schema,
        string OperationId,
        string Operation,
        long? RunId);

    internal sealed record ResultEnvelope(
        int Schema,
        string OperationId,
        bool Success,
        string ResultState,
        string ReasonCode,
        string? ProfileId,
        long? RunId,
        long? JobId,
        string? StaleItems);
}