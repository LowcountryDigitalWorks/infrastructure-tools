using System.Text.Json;
using LDW.OperationsBridge.Core;
using LDW.OperationsBridge.Runner;

internal static class DragonflyLinuxRuntimeTests
{
    public static void Run()
    {
        Assert(DragonflyBridgeRuntime.HealthInterval == TimeSpan.FromSeconds(10), "Dragonfly Bridge health pulse is fixed");
        Assert(DragonflyBridgeRuntime.ReconnectBackoffSeconds.SequenceEqual(new[] { 2, 4, 8, 16, 30 }), "Dragonfly Bridge reconnect backoff is fixed and bounded");

        Assert(DragonflyBridgeSingleInstanceLock.RuntimeDirectoryForUid(1000) == "/run/user/1000", "Dragonfly Bridge runtime directory derives only from effective uid");
        Assert(DragonflyBridgeSingleInstanceLock.LockPathForUid(1000) == "/run/user/1000/ldw-operations-bridge-dragonfly.lock", "Dragonfly Bridge lock path is fixed under private user runtime directory");
        AssertThrows<InvalidOperationException>(
            () => DragonflyBridgeSingleInstanceLock.RuntimeDirectoryForUid(0),
            "Dragonfly Bridge refuses root runtime identity");

        if (OperatingSystem.IsLinux())
            VerifyStatePathHardening();

        var now = DateTimeOffset.Parse("2026-10-27T18:00:00Z");
        var exact = JsonSerializer.Serialize(new
        {
            state = "connected",
            observedAt = now,
            bridgeId = DragonflyBridgeRunnerConfiguration.FixedBridgeId,
            runtime = BridgeProtocol.BridgeRuntime,
            version = BridgeProtocol.BridgeRuntimeVersion
        });
        Assert(DragonflyBridgeHealthStore.Interpret(exact, now) == "connected", "Dragonfly Bridge health accepts exact fresh fixed identity/runtime state");

        var stale = JsonSerializer.Serialize(new
        {
            state = "connected",
            observedAt = now.AddMinutes(-1),
            bridgeId = DragonflyBridgeRunnerConfiguration.FixedBridgeId,
            runtime = BridgeProtocol.BridgeRuntime,
            version = BridgeProtocol.BridgeRuntimeVersion
        });
        Assert(DragonflyBridgeHealthStore.Interpret(stale, now) == "stale", "Dragonfly Bridge health rejects old state as stale");

        foreach (var invalid in new[]
        {
            exact.Replace("dragonfly-redrix-01", "other", StringComparison.Ordinal),
            exact.Replace(BridgeProtocol.BridgeRuntime, "other-runtime", StringComparison.Ordinal),
            exact.Replace(BridgeProtocol.BridgeRuntimeVersion, "9.9.9", StringComparison.Ordinal),
            exact.Replace("connected", "arbitrary", StringComparison.Ordinal),
            exact[..^1] + ",\"extra\":\"nope\"}",
            "{malformed"
        })
        {
            Assert(DragonflyBridgeHealthStore.Interpret(invalid, now) == "unknown", "Dragonfly Bridge health rejects wrong identity/runtime/version/state/extra/malformed data");
        }

        var future = JsonSerializer.Serialize(new
        {
            state = "connected",
            observedAt = now.AddMinutes(1),
            bridgeId = DragonflyBridgeRunnerConfiguration.FixedBridgeId,
            runtime = BridgeProtocol.BridgeRuntime,
            version = BridgeProtocol.BridgeRuntimeVersion
        });
        Assert(DragonflyBridgeHealthStore.Interpret(future, now) == "stale", "Dragonfly Bridge health rejects implausible future timestamps");
    }

    private static void VerifyStatePathHardening()
    {
        var root = Path.Combine(Path.GetTempPath(), "ldw-dragonfly-state-test-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(root, "home");
        var target = Path.Combine(home, ".local", "state", "ldw", "operations-bridge", "dragonfly");
        var outside = Path.Combine(root, "outside");
        var linkedHome = Path.Combine(root, "linked-home");
        try
        {
            Directory.CreateDirectory(home);
            Directory.CreateDirectory(outside);
            Directory.CreateDirectory(linkedHome);

            var created = DragonflyBridgeStatePath.EnsurePrivateDirectory(home, target);
            Assert(created == Path.GetFullPath(target), "Dragonfly state path creation stays under owner home");
            Assert(DragonflyBridgeStatePath.VerifyExistingPrivateDirectory(home, target) == created, "Dragonfly state path read verification accepts exact private path");
            var mode = File.GetUnixFileMode(target);
            var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            Assert((mode & forbidden) == 0, "Dragonfly final state directory is user-private");

            AssertThrows<InvalidOperationException>(
                () => DragonflyBridgeStatePath.EnsurePrivateDirectory(home, outside),
                "Dragonfly state path cannot escape owner home");

            var link = Path.Combine(linkedHome, ".local");
            Directory.CreateSymbolicLink(link, outside);
            var linkedTarget = Path.Combine(link, "state", "ldw", "operations-bridge", "dragonfly");
            AssertThrows<InvalidOperationException>(
                () => DragonflyBridgeStatePath.EnsurePrivateDirectory(linkedHome, linkedTarget),
                "Dragonfly state path rejects symlinked parent directory before write");
            AssertThrows<InvalidOperationException>(
                () => DragonflyBridgeStatePath.VerifyExistingPrivateDirectory(linkedHome, linkedTarget),
                "Dragonfly state read path rejects symlinked parent directory");
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAILED: " + message);
    }

    private static void AssertThrows<TException>(Action action, string message) where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException("FAILED: " + message);
        }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("FAILED:", StringComparison.Ordinal)) { throw; }
        catch (TException) { }
    }
}
