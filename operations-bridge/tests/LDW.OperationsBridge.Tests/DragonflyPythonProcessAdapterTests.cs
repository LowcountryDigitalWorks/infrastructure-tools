using System.Text.Json;
using LDW.OperationsBridge.Client;
using LDW.OperationsBridge.Core;

internal static class DragonflyPythonProcessAdapterTests
{
    public static void Run()
    {
        const string home = "/home/eddie";
        var startInfo = PythonDragonflyRunnerAdapter.CreateStartInfo(home, "dragonfly.runner.status");

        Assert(startInfo.FileName == "/usr/bin/python3", "Python adapter pins exact Python executable");
        Assert(startInfo.WorkingDirectory == home, "Python adapter pins owner home as cwd");
        Assert(!startInfo.UseShellExecute, "Python adapter disables shell execution");
        Assert(startInfo.RedirectStandardInput, "Python adapter uses bounded stdin request channel");
        Assert(startInfo.RedirectStandardOutput, "Python adapter captures bounded stdout");
        Assert(startInfo.RedirectStandardError, "Python adapter captures and discards bounded diagnostics");
        Assert(startInfo.CreateNoWindow, "Python adapter does not create an interactive child window");
        Assert(startInfo.StandardInputEncoding?.GetPreamble().Length == 0, "Python adapter JSON stdin encoding emits no UTF-8 BOM");
        Assert(startInfo.ArgumentList.Count == 1, "Python adapter child argv contains exactly one fixed script path");
        Assert(startInfo.ArgumentList[0] == "/home/eddie/.local/lib/ldw-dragonfly-jit/bridge_adapter.py", "Python adapter pins installed reviewed adapter path");
        Assert(startInfo.Environment.Count == 4, "Python adapter child environment is minimized");
        Assert(startInfo.Environment["HOME"] == home, "Python adapter pins HOME");
        Assert(startInfo.Environment["PATH"] == "/usr/bin:/bin", "Python adapter pins PATH");
        Assert(startInfo.Environment["LANG"] == "C.UTF-8", "Python adapter pins LANG");
        Assert(startInfo.Environment["LC_ALL"] == "C.UTF-8", "Python adapter pins LC_ALL");
        Assert(PythonDragonflyRunnerAdapter.ExpectedAdapterGitBlob == "9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf", "Python adapter pins exact reviewed bridge_adapter.py Git blob");

        using (var request = JsonDocument.Parse(PythonDragonflyRunnerAdapter.BuildRequest("dragonfly.runner.status")))
        {
            var root = request.RootElement;
            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            Assert(names.Length == 2 && names.Distinct(StringComparer.Ordinal).Count() == 2, "Python adapter request has exactly two fields");
            Assert(root.GetProperty("operation").GetString() == "dragonfly.runner.status", "Python adapter request pins status operation");
            Assert(root.GetProperty("arguments").ValueKind == JsonValueKind.Object && !root.GetProperty("arguments").EnumerateObject().Any(), "Python adapter request arguments are exactly empty");
        }

        foreach (var operation in new[] { "dragonfly.runner.status", "dragonfly.runner.start", "dragonfly.runner.drain" })
        {
            var info = PythonDragonflyRunnerAdapter.CreateStartInfo(home, operation);
            Assert(info.ArgumentList.SequenceEqual(new[] { "/home/eddie/.local/lib/ldw-dragonfly-jit/bridge_adapter.py" }), "All owner-control operations use same fixed adapter executable path");
            using var request = JsonDocument.Parse(PythonDragonflyRunnerAdapter.BuildRequest(operation));
            Assert(request.RootElement.GetProperty("operation").GetString() == operation, "Owner-control request preserves only reviewed operation");
        }

        AssertThrows<ArgumentOutOfRangeException>(
            () => PythonDragonflyRunnerAdapter.CreateStartInfo(home, "dragonfly.runner.recover"),
            "Python adapter rejects non-owner-control operation");
        AssertThrows<ArgumentOutOfRangeException>(
            () => PythonDragonflyRunnerAdapter.BuildRequest("dragonfly.runner.smoke"),
            "Python adapter cannot build smoke/recover/generic request");

        if (OperatingSystem.IsLinux())
            VerifySymlinkRefusal();

        const string statusJson = "{\"base_present\":true,\"free_disk_gib\":81,\"load_fraction\":0.021,\"marker\":\"DRAGONFLY-BRIDGE-001\",\"mem_available_mib\":12361,\"operation\":\"dragonfly.runner.status\",\"reason\":null,\"residue_count\":0,\"state\":\"STOPPED\",\"visible_cpus\":12}";
        var status = PythonDragonflyRunnerAdapter.ParseStatusResult(statusJson, "dragonfly.runner.status");
        Assert(status.State == "STOPPED" && status.VisibleCpus == 12 && status.MemAvailableMib == 12361 && status.FreeDiskGib == 81 && status.ResidueCount == 0 && status.BasePresent, "Python adapter parses bounded status projection");

        const string startJson = "{\"marker\":\"DRAGONFLY-BRIDGE-001\",\"operation\":\"dragonfly.runner.start\",\"reason\":null,\"state\":\"AVAILABLE\"}";
        var start = PythonDragonflyRunnerAdapter.ParseLifecycleResult(startJson, "dragonfly.runner.start");
        Assert(start.State == "AVAILABLE", "Python adapter parses only safe Start lifecycle result");

        const string drainJson = "{\"marker\":\"DRAGONFLY-BRIDGE-001\",\"operation\":\"dragonfly.runner.drain\",\"reason\":null,\"state\":\"STOPPED\"}";
        var drain = PythonDragonflyRunnerAdapter.ParseLifecycleResult(drainJson, "dragonfly.runner.drain");
        Assert(drain.State == "STOPPED", "Python adapter parses only safe Drain lifecycle result");

        foreach (var invalid in new[]
        {
            statusJson.Replace("DRAGONFLY-BRIDGE-001", "OTHER", StringComparison.Ordinal),
            statusJson.Replace("dragonfly.runner.status", "dragonfly.runner.start", StringComparison.Ordinal),
            statusJson.Replace("\"visible_cpus\":12", "\"visible_cpus\":0", StringComparison.Ordinal),
            statusJson[..^1] + ",\"extra\":\"nope\"}",
            "{\"result\":\"FAILED\",\"marker\":\"DRAGONFLY-BRIDGE-001\",\"reason\":\"CONTROLLER_FAILED\"}"
        })
        {
            AssertThrows<InvalidOperationException>(
                () => PythonDragonflyRunnerAdapter.ParseStatusResult(invalid, "dragonfly.runner.status"),
                "Python adapter rejects wrong marker/operation/unsafe/extra/failure status output");
        }

        AssertThrows<InvalidOperationException>(
            () => PythonDragonflyRunnerAdapter.ParseLifecycleResult(startJson.Replace("AVAILABLE", "RUNNING", StringComparison.Ordinal), "dragonfly.runner.start"),
            "Python adapter rejects uncertain Start state");
        AssertThrows<InvalidOperationException>(
            () => PythonDragonflyRunnerAdapter.ParseLifecycleResult(drainJson.Replace("STOPPED", "AVAILABLE", StringComparison.Ordinal), "dragonfly.runner.drain"),
            "Python adapter rejects unsafe Drain state");
        AssertThrows<ArgumentOutOfRangeException>(
            () => PythonDragonflyRunnerAdapter.ParseLifecycleResult(startJson, "dragonfly.runner.status"),
            "Python adapter lifecycle parser cannot be retargeted to status or arbitrary operation");
    }

    private static void VerifySymlinkRefusal()
    {
        var root = Path.Combine(Path.GetTempPath(), "ldw-dragonfly-adapter-test-" + Guid.NewGuid().ToString("N"));
        var realDirectory = Path.Combine(root, "real");
        var realFile = Path.Combine(realDirectory, "adapter.py");
        var directoryLink = Path.Combine(root, "linked");
        var fileLink = Path.Combine(root, "adapter-link.py");
        try
        {
            Directory.CreateDirectory(realDirectory);
            File.WriteAllText(realFile, "synthetic");
            PythonDragonflyRunnerAdapter.VerifyNoSymlinkPath(realFile);

            Directory.CreateSymbolicLink(directoryLink, realDirectory);
            AssertThrows<DragonflyRunnerAdapterUnavailableException>(
                () => PythonDragonflyRunnerAdapter.VerifyNoSymlinkPath(Path.Combine(directoryLink, "adapter.py")),
                "Python adapter rejects symlinked parent directory");

            File.CreateSymbolicLink(fileLink, realFile);
            AssertThrows<DragonflyRunnerAdapterUnavailableException>(
                () => PythonDragonflyRunnerAdapter.VerifyNoSymlinkPath(fileLink),
                "Python adapter rejects symlinked final file");
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
