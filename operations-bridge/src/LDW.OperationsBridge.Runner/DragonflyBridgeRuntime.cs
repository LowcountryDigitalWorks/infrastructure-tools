using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

namespace LDW.OperationsBridge.Runner;

internal static class DragonflyBridgeRuntime
{
    internal static readonly TimeSpan HealthInterval = TimeSpan.FromSeconds(10);
    internal static readonly int[] ReconnectBackoffSeconds = [2, 4, 8, 16, 30];

    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            return 3;

        await using var singleInstance = DragonflyBridgeSingleInstanceLock.Acquire();
        var configuration = DragonflyBridgeRunnerConfiguration.Load();
        var secretReader = new SecretServiceDragonflyBridgeSecretReader();
        var adapter = new PythonDragonflyRunnerAdapter();
        var validator = new DispatchValidator(
            [configuration.BridgeId],
            BridgeProtocol.AllowedDragonflyOwnerControlOperations);
        var client = new DragonflyOutboundBridgeClient(configuration.BridgeId, adapter, validator);
        var attempt = 0;

        DragonflyBridgeHealthStore.Write("starting", configuration.BridgeId);

        while (!cancellationToken.IsCancellationRequested)
        {
            string bearer;
            try
            {
                bearer = secretReader.ReadToken();
            }
            catch (DragonflyBridgeSecretUnavailableException)
            {
                DragonflyBridgeHealthStore.Write("blocked", configuration.BridgeId);
                return 6;
            }

            DragonflyBridgeHealthStore.Write("connecting", configuration.BridgeId);
            await using var transport = new ClientWebSocketBridgeTransport();
            client.Attach(transport);
            try
            {
                using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectTimeout.CancelAfter(TimeSpan.FromSeconds(20));
                await transport.ConnectAsync(
                    configuration.RelayConnectUri,
                    bearer,
                    [new TrustedRelayEndpoint(configuration.RelayConnectUri)],
                    connectTimeout.Token).ConfigureAwait(false);
                bearer = string.Empty;
                attempt = 0;
                DragonflyBridgeHealthStore.Write("connected", configuration.BridgeId);

                while (!cancellationToken.IsCancellationRequested && !transport.Completion.IsCompleted)
                {
                    var pulse = Task.Delay(HealthInterval, cancellationToken);
                    var finished = await Task.WhenAny(transport.Completion, pulse).ConfigureAwait(false);
                    if (finished == pulse && !cancellationToken.IsCancellationRequested)
                        DragonflyBridgeHealthStore.Write("connected", configuration.BridgeId);
                }

                if (cancellationToken.IsCancellationRequested)
                    break;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                bearer = string.Empty;
                DragonflyBridgeHealthStore.Write("degraded", configuration.BridgeId);
            }

            if (cancellationToken.IsCancellationRequested)
                break;

            DragonflyBridgeHealthStore.Write("degraded", configuration.BridgeId);
            var delay = ReconnectBackoffSeconds[Math.Min(attempt, ReconnectBackoffSeconds.Length - 1)];
            attempt = Math.Min(attempt + 1, ReconnectBackoffSeconds.Length - 1);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(delay), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }

        DragonflyBridgeHealthStore.Write("stopped", configuration.BridgeId);
        return 0;
    }
}

internal sealed class DragonflyBridgeSingleInstanceLock : IAsyncDisposable
{
    private readonly FileStream _stream;
    private bool _locked;

    private DragonflyBridgeSingleInstanceLock(FileStream stream)
    {
        _stream = stream;
        _locked = true;
    }

    internal static string RuntimeDirectoryForUid(uint effectiveUserId)
    {
        if (effectiveUserId == 0)
            throw new InvalidOperationException("Dragonfly Bridge refuses root execution.");
        return $"/run/user/{effectiveUserId}";
    }

    internal static string LockPathForUid(uint effectiveUserId)
        => Path.Combine(RuntimeDirectoryForUid(effectiveUserId), "ldw-operations-bridge-dragonfly.lock");

    public static DragonflyBridgeSingleInstanceLock Acquire()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();

        var uid = GetEffectiveUserId();
        var runtimeDirectory = RuntimeDirectoryForUid(uid);
        var directory = new DirectoryInfo(runtimeDirectory);
        directory.Refresh();
        if (!directory.Exists || directory.LinkTarget is not null)
            throw new InvalidOperationException("Trusted Dragonfly user runtime directory is unavailable.");

        var directoryMode = File.GetUnixFileMode(runtimeDirectory);
        var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((directoryMode & forbidden) != 0)
            throw new InvalidOperationException("Dragonfly user runtime directory is not private.");

        var lockPath = LockPathForUid(uid);
        var existing = new FileInfo(lockPath);
        existing.Refresh();
        if (existing.Exists && existing.LinkTarget is not null)
            throw new InvalidOperationException("Dragonfly Bridge lock path is a symlink.");

        var stream = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.ReadWrite,
            bufferSize: 1,
            FileOptions.None);
        try
        {
            File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            stream.Lock(0, 1);
            return new DragonflyBridgeSingleInstanceLock(stream);
        }
        catch
        {
            stream.Dispose();
            throw new InvalidOperationException("Dragonfly Bridge is already active or its lock is unavailable.");
        }
    }

    public ValueTask DisposeAsync()
    {
        if (_locked)
        {
            try { _stream.Unlock(0, 1); } catch { }
            _locked = false;
        }
        _stream.Dispose();
        return ValueTask.CompletedTask;
    }

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}

internal sealed record DragonflyBridgeHealth(
    string State,
    DateTimeOffset ObservedAt,
    string BridgeId,
    string Runtime,
    string Version);

internal static class DragonflyBridgeStatePath
{
    private static readonly UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    internal static string EnsurePrivateDirectory(string ownerHome, string targetDirectory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();

        var home = Path.GetFullPath(ownerHome);
        var target = Path.GetFullPath(targetDirectory);
        var prefix = home.EndsWith(Path.DirectorySeparatorChar)
            ? home
            : home + Path.DirectorySeparatorChar;
        if (!target.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("Dragonfly Bridge state directory must remain under owner home.");

        var homeInfo = new DirectoryInfo(home);
        homeInfo.Refresh();
        if (!homeInfo.Exists || homeInfo.LinkTarget is not null)
            throw new InvalidOperationException("Dragonfly owner home is unavailable or symlinked.");

        var relative = Path.GetRelativePath(home, target);
        if (relative is "." or ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidOperationException("Dragonfly Bridge state directory escaped owner home.");

        var current = home;
        foreach (var component in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            var info = new DirectoryInfo(current);
            info.Refresh();
            if (info.Exists)
            {
                if (info.LinkTarget is not null)
                    throw new InvalidOperationException("Dragonfly Bridge state path contains a symlink.");
                continue;
            }

            Directory.CreateDirectory(current);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null)
                throw new InvalidOperationException("Dragonfly Bridge state directory creation failed closed.");
            File.SetUnixFileMode(current, PrivateDirectoryMode);
        }

        var finalInfo = new DirectoryInfo(target);
        finalInfo.Refresh();
        if (!finalInfo.Exists || finalInfo.LinkTarget is not null)
            throw new InvalidOperationException("Dragonfly Bridge state directory is unavailable.");
        File.SetUnixFileMode(target, PrivateDirectoryMode);
        return target;
    }

    internal static string VerifyExistingPrivateDirectory(string ownerHome, string targetDirectory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();

        var home = Path.GetFullPath(ownerHome);
        var target = Path.GetFullPath(targetDirectory);
        var prefix = home.EndsWith(Path.DirectorySeparatorChar)
            ? home
            : home + Path.DirectorySeparatorChar;
        if (!target.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("Dragonfly Bridge state directory must remain under owner home.");

        var homeInfo = new DirectoryInfo(home);
        homeInfo.Refresh();
        if (!homeInfo.Exists || homeInfo.LinkTarget is not null)
            throw new InvalidOperationException("Dragonfly owner home is unavailable or symlinked.");

        var relative = Path.GetRelativePath(home, target);
        var current = home;
        foreach (var component in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            var info = new DirectoryInfo(current);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null)
                throw new InvalidOperationException("Dragonfly Bridge state path is missing or symlinked.");
        }

        var mode = File.GetUnixFileMode(target);
        var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((mode & forbidden) != 0)
            throw new InvalidOperationException("Dragonfly Bridge state directory is not private.");
        return target;
    }
}

internal static class DragonflyBridgeHealthStore
{
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
        { "starting", "connecting", "connected", "degraded", "blocked", "stopped" };

    public static void Write(string state, string bridgeId)
    {
        if (!States.Contains(state) || !string.Equals(bridgeId, DragonflyBridgeRunnerConfiguration.FixedBridgeId, StringComparison.Ordinal))
            throw new ArgumentOutOfRangeException(nameof(state));

        var directory = DragonflyBridgeStatePath.EnsurePrivateDirectory(
            DragonflyBridgeRunnerConfiguration.UserHome,
            DragonflyBridgeRunnerConfiguration.StateDirectory);

        var healthPath = DragonflyBridgeRunnerConfiguration.HealthPath;
        var current = new FileInfo(healthPath);
        current.Refresh();
        if (current.Exists && current.LinkTarget is not null)
            throw new InvalidOperationException("Dragonfly Bridge health path is a symlink.");

        var payload = JsonSerializer.Serialize(
            new DragonflyBridgeHealth(
                state,
                DateTimeOffset.UtcNow,
                bridgeId,
                BridgeProtocol.BridgeRuntime,
                BridgeProtocol.BridgeRuntimeVersion),
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        var temp = Path.Combine(directory, $".health-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false, true), leaveOpen: true))
            {
                writer.Write(payload);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, healthPath, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    public static string ReadState()
    {
        try
        {
            DragonflyBridgeStatePath.VerifyExistingPrivateDirectory(
                DragonflyBridgeRunnerConfiguration.UserHome,
                DragonflyBridgeRunnerConfiguration.StateDirectory);
            var info = new FileInfo(DragonflyBridgeRunnerConfiguration.HealthPath);
            info.Refresh();
            if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 2048)
                return "unknown";
            return Interpret(File.ReadAllText(info.FullName, Encoding.UTF8), DateTimeOffset.UtcNow);
        }
        catch
        {
            return "unknown";
        }
    }

    internal static string Interpret(string json, DateTimeOffset now)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return "unknown";
            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            if (names.Length != 5 || names.Distinct(StringComparer.Ordinal).Count() != 5 ||
                !root.TryGetProperty("state", out var stateElement) ||
                !root.TryGetProperty("observedAt", out var observedElement) ||
                !root.TryGetProperty("bridgeId", out var bridgeElement) ||
                !root.TryGetProperty("runtime", out var runtimeElement) ||
                !root.TryGetProperty("version", out var versionElement) ||
                stateElement.ValueKind != JsonValueKind.String ||
                observedElement.ValueKind != JsonValueKind.String ||
                bridgeElement.ValueKind != JsonValueKind.String ||
                runtimeElement.ValueKind != JsonValueKind.String ||
                versionElement.ValueKind != JsonValueKind.String ||
                !States.Contains(stateElement.GetString() ?? string.Empty) ||
                bridgeElement.GetString() != DragonflyBridgeRunnerConfiguration.FixedBridgeId ||
                runtimeElement.GetString() != BridgeProtocol.BridgeRuntime ||
                versionElement.GetString() != BridgeProtocol.BridgeRuntimeVersion ||
                !DateTimeOffset.TryParse(observedElement.GetString(), out var observedAt))
                return "unknown";

            if (now - observedAt > TimeSpan.FromSeconds(30) || observedAt > now.AddSeconds(10))
                return "stale";
            return stateElement.GetString()!;
        }
        catch
        {
            return "unknown";
        }
    }
}
