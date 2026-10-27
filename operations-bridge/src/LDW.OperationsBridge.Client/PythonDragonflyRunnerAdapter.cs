using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Client;

public sealed class PythonDragonflyRunnerAdapter : IDragonflyRunnerAdapter
{
    internal const string PythonPath = "/usr/bin/python3";
    internal const string AdapterRelativePath = ".local/lib/ldw-dragonfly-jit/bridge_adapter.py";
    internal const string ExpectedAdapterGitBlob = "9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf";
    internal const int MaxOutputChars = 4096;
    internal const int MaxDiagnosticChars = 2048;
    private static readonly TimeSpan InvocationTimeout = TimeSpan.FromSeconds(15);
    private static readonly UTF8Encoding StrictUtf8NoBom = new(false, true);
    private static readonly HashSet<string> AllowedOperations = new(StringComparer.Ordinal)
    {
        "dragonfly.runner.status",
        "dragonfly.runner.start",
        "dragonfly.runner.drain"
    };

    public Task<DragonflyRunnerStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken)
        => InvokeAsync(
            "dragonfly.runner.status",
            output => ParseStatusResult(output, "dragonfly.runner.status"),
            cancellationToken);

    public Task<DragonflyRunnerLifecycleResult> StartAsync(CancellationToken cancellationToken)
        => InvokeAsync(
            "dragonfly.runner.start",
            output => ParseLifecycleResult(output, "dragonfly.runner.start"),
            cancellationToken);

    public Task<DragonflyRunnerLifecycleResult> DrainAsync(CancellationToken cancellationToken)
        => InvokeAsync(
            "dragonfly.runner.drain",
            output => ParseLifecycleResult(output, "dragonfly.runner.drain"),
            cancellationToken);

    private static async Task<T> InvokeAsync<T>(
        string operation,
        Func<string, T> parser,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux())
            throw new DragonflyRunnerAdapterUnavailableException();

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home) || !Path.IsPathFullyQualified(home))
            throw new DragonflyRunnerAdapterUnavailableException();
        home = Path.GetFullPath(home);

        var adapterPath = Path.Combine(home, AdapterRelativePath);
        VerifyAdapter(adapterPath);

        using var process = new Process { StartInfo = CreateStartInfo(home, operation) };
        try
        {
            if (!process.Start())
                throw InvocationFailed();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            throw InvocationFailed();
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(InvocationTimeout);

        try
        {
            var request = BuildRequest(operation);
            await process.StandardInput.WriteAsync(request.AsMemory(), timeout.Token).ConfigureAwait(false);
            await process.StandardInput.FlushAsync(timeout.Token).ConfigureAwait(false);
            process.StandardInput.Close();

            var stdoutTask = ReadBoundedAsync(process.StandardOutput, MaxOutputChars, timeout.Token);
            var stderrTask = DrainBoundedAsync(process.StandardError, MaxDiagnosticChars, timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            await stderrTask.ConfigureAwait(false);

            if (process.ExitCode != 0)
                throw InvocationFailed();
            return parser(stdout);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw;
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw InvocationFailed();
        }
        catch (InvalidDataException)
        {
            TryKill(process);
            throw InvocationFailed();
        }
        finally
        {
            if (!process.HasExited)
                TryKill(process);
        }
    }

    internal static ProcessStartInfo CreateStartInfo(string home, string operation)
    {
        if (string.IsNullOrWhiteSpace(home) || !Path.IsPathFullyQualified(home))
            throw new ArgumentException("Owner home must be absolute.", nameof(home));
        if (!AllowedOperations.Contains(operation))
            throw new ArgumentOutOfRangeException(nameof(operation));

        var normalizedHome = Path.GetFullPath(home);
        var startInfo = new ProcessStartInfo
        {
            FileName = PythonPath,
            WorkingDirectory = normalizedHome,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardInputEncoding = StrictUtf8NoBom,
            StandardOutputEncoding = StrictUtf8NoBom,
            StandardErrorEncoding = StrictUtf8NoBom
        };
        startInfo.ArgumentList.Add(Path.Combine(normalizedHome, AdapterRelativePath));
        startInfo.Environment.Clear();
        startInfo.Environment["HOME"] = normalizedHome;
        startInfo.Environment["PATH"] = "/usr/bin:/bin";
        startInfo.Environment["LANG"] = "C.UTF-8";
        startInfo.Environment["LC_ALL"] = "C.UTF-8";
        return startInfo;
    }

    internal static string BuildRequest(string operation)
    {
        if (!AllowedOperations.Contains(operation))
            throw new ArgumentOutOfRangeException(nameof(operation));
        return JsonSerializer.Serialize(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["operation"] = operation,
            ["arguments"] = new Dictionary<string, object>(StringComparer.Ordinal)
        });
    }

    internal static DragonflyRunnerStatusSnapshot ParseStatusResult(string json, string expectedOperation)
    {
        using var document = ParseExactResult(json, expectedOperation,
            ["marker", "operation", "state", "reason", "visible_cpus", "mem_available_mib", "free_disk_gib", "load_fraction", "residue_count", "base_present"]);
        var root = document.RootElement;
        var result = new DragonflyRunnerStatusSnapshot(
            RequiredString(root, "state"),
            OptionalReason(root),
            RequiredInt32(root, "visible_cpus"),
            RequiredInt64(root, "mem_available_mib"),
            RequiredInt64(root, "free_disk_gib"),
            RequiredDouble(root, "load_fraction"),
            RequiredInt32(root, "residue_count"),
            RequiredBoolean(root, "base_present"));
        if (!DragonflyRunnerContract.IsSafeStatus(result))
            throw InvocationFailed();
        return result;
    }

    internal static DragonflyRunnerLifecycleResult ParseLifecycleResult(string json, string expectedOperation)
    {
        if (expectedOperation is not "dragonfly.runner.start" and not "dragonfly.runner.drain")
            throw new ArgumentOutOfRangeException(nameof(expectedOperation));
        using var document = ParseExactResult(json, expectedOperation, ["marker", "operation", "state", "reason"]);
        var root = document.RootElement;
        var result = new DragonflyRunnerLifecycleResult(RequiredString(root, "state"), OptionalReason(root));
        var safe = expectedOperation == "dragonfly.runner.start"
            ? DragonflyRunnerContract.IsSafeStartResult(result)
            : DragonflyRunnerContract.IsSafeDrainResult(result);
        if (!safe)
            throw InvocationFailed();
        return result;
    }

    private static JsonDocument ParseExactResult(string json, string expectedOperation, IReadOnlyCollection<string> exactFields)
    {
        if (json.Length is <= 0 or > MaxOutputChars)
            throw InvocationFailed();
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        }
        catch (JsonException)
        {
            throw InvocationFailed();
        }
        try
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw InvocationFailed();
            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            if (names.Length != exactFields.Count ||
                names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
                exactFields.Any(field => !root.TryGetProperty(field, out _)) ||
                RequiredString(root, "marker") != "DRAGONFLY-BRIDGE-001" ||
                RequiredString(root, "operation") != expectedOperation)
                throw InvocationFailed();
            return document;
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
            throw InvocationFailed();
        return element.GetString() ?? throw InvocationFailed();
    }

    private static string? OptionalReason(JsonElement root)
    {
        if (!root.TryGetProperty("reason", out var element))
            throw InvocationFailed();
        if (element.ValueKind == JsonValueKind.Null)
            return null;
        if (element.ValueKind != JsonValueKind.String)
            throw InvocationFailed();
        return element.GetString();
    }

    private static int RequiredInt32(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out var value))
            throw InvocationFailed();
        return value;
    }

    private static long RequiredInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value))
            throw InvocationFailed();
        return value;
    }

    private static double RequiredDouble(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetDouble(out var value) || !double.IsFinite(value))
            throw InvocationFailed();
        return value;
    }

    private static bool RequiredBoolean(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element) || element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw InvocationFailed();
        return element.GetBoolean();
    }

    internal static void VerifyNoSymlinkPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
            throw new DragonflyRunnerAdapterUnavailableException();

        var current = root;
        var remainder = fullPath[root.Length..];
        foreach (var component in remainder.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            FileSystemInfo info = Directory.Exists(current)
                ? new DirectoryInfo(current)
                : new FileInfo(current);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null)
                throw new DragonflyRunnerAdapterUnavailableException();
        }
    }

    private static void VerifyAdapter(string adapterPath)
    {
        try
        {
            VerifyNoSymlinkPath(adapterPath);
            var info = new FileInfo(adapterPath);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 64 * 1024)
                throw new DragonflyRunnerAdapterUnavailableException();
            var mode = File.GetUnixFileMode(adapterPath);
            if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                throw new DragonflyRunnerAdapterUnavailableException();
            var bytes = File.ReadAllBytes(adapterPath);
            try
            {
                var header = Encoding.ASCII.GetBytes($"blob {bytes.Length}\0");
                var combined = new byte[header.Length + bytes.Length];
                Buffer.BlockCopy(header, 0, combined, 0, header.Length);
                Buffer.BlockCopy(bytes, 0, combined, header.Length, bytes.Length);
                var digest = Convert.ToHexString(SHA1.HashData(combined)).ToLowerInvariant();
                Array.Clear(combined);
                if (!string.Equals(digest, ExpectedAdapterGitBlob, StringComparison.Ordinal))
                    throw new DragonflyRunnerAdapterUnavailableException();
            }
            finally
            {
                Array.Clear(bytes);
            }
        }
        catch (DragonflyRunnerAdapterUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            throw new DragonflyRunnerAdapterUnavailableException();
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        var buffer = new char[512];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0)
                return builder.ToString();
            if (builder.Length + count > maxChars)
                throw new InvalidDataException("Dragonfly adapter output exceeded its bound.");
            builder.Append(buffer, 0, count);
        }
    }

    private static async Task DrainBoundedAsync(StreamReader reader, int maxChars, CancellationToken cancellationToken)
    {
        var total = 0;
        var buffer = new char[512];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0)
                return;
            total += count;
            if (total > maxChars)
                throw new InvalidDataException("Dragonfly adapter diagnostic output exceeded its bound.");
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(1000);
            }
        }
        catch
        {
            // Fail closed; raw process errors are intentionally not surfaced.
        }
    }

    private static InvalidOperationException InvocationFailed()
        => new("Dragonfly runner adapter invocation failed closed.");
}
