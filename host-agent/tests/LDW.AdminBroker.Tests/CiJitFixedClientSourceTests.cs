using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

internal static class CiJitFixedClientSourceTests
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        var root = Directory.GetCurrentDirectory();
        var path = Path.Combine(root, "host-agent", "deploy", "Invoke-CiJitControlClient.ps1");
        if (!File.Exists(path)) throw new Exception("CI/JIT fixed client source is missing.");
        var source = File.ReadAllText(path);
        var assertions = 0;
        void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("CI/JIT fixed client source assertion failed: " + message);
            assertions++;
        }

        var paramEnd = source.IndexOf("Set-StrictMode", StringComparison.Ordinal);
        Assert(paramEnd > 0, "top-level parameter block precedes strict mode");
        var parameterSurface = source[..paramEnd];
        foreach (var allowed in new[] { "$Operation", "$RunId", "$OperationId" })
            Assert(parameterSurface.Contains(allowed, StringComparison.Ordinal), "expected parameter " + allowed + " exists");
        foreach (var forbidden in new[] { "$Pipe", "$Target", "$Json", "$Path", "$Command", "$Executable", "$Url", "$Timeout" })
            Assert(!parameterSurface.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "caller cannot select " + forbidden);

        Assert(source.Contains("$script:PipeName = 'LDW.AdminBroker.v1'", StringComparison.Ordinal), "pipe name is fixed");
        Assert(source.Contains("$script:TargetIdentity = 'local-ci-jit'", StringComparison.Ordinal), "target identity is fixed");
        Assert(source.Contains("$script:MaximumRequestCharacters = 16384", StringComparison.Ordinal), "request bound matches broker contract");
        Assert(source.Contains("$script:MaximumResponseCharacters = 32768", StringComparison.Ordinal), "response bound matches broker contract");
        Assert(source.Contains("$script:TimeoutMilliseconds = 5000", StringComparison.Ordinal), "transport timeout is fixed");
        Assert(source.Contains("NamedPipeClientStream", StringComparison.Ordinal), "client uses local named pipe transport");
        Assert(source.Contains("'.', $script:PipeName", StringComparison.Ordinal), "client connects only to local machine pipe");
        Assert(source.Contains("CLIENT_NORMAL_USER_REQUIRED", StringComparison.Ordinal), "client refuses elevated execution");
        Assert(source.Contains("WindowsBuiltInRole]::Administrator", StringComparison.Ordinal), "normal-user check evaluates administrator role");
        Assert(source.Contains("[guid]::NewGuid().ToString('D')", StringComparison.Ordinal), "request correlation UUID is generated locally");

        foreach (var operation in new[]
        {
            "CI_JIT_STATUS", "CI_JIT_DISCOVER", "CI_JIT_RUN_ONCE", "CI_JIT_RECOVER",
            "CI_JIT_ABORT_ACTIVE", "CI_JIT_LIST_STALE", "CI_JIT_RETIRE_STALE", "CI_JIT_GET_OPERATION_RESULT"
        })
            Assert(source.Contains(operation, StringComparison.Ordinal), "operation is fixed: " + operation);

        Assert(source.Contains("$RequestedRunId -le 0", StringComparison.Ordinal), "retire-stale requires positive run ID");
        Assert(source.Contains("$RequestedOperationId -eq [guid]::Empty", StringComparison.Ordinal), "result lookup requires operation UUID");
        Assert(source.Contains("CLIENT_ARGUMENT_REFUSED", StringComparison.Ordinal), "unexpected argument combinations fail closed");
        Assert(source.Contains("CLIENT_RESPONSE_CORRELATION_REFUSED", StringComparison.Ordinal), "response correlation mismatch fails closed");
        Assert(source.Contains("CLIENT_RESPONSE_TIMEOUT", StringComparison.Ordinal), "response timeout fails closed");
        Assert(source.Contains("CLIENT_BROKER_UNAVAILABLE", StringComparison.Ordinal), "unavailable broker fails closed");

        foreach (var detail in new[]
        {
            "reasonCode", "operationId", "profileId", "runId", "jobId", "staleItems", "observedAtUtc",
            "sourceVersion", "ownerState", "statusReasonCode", "localStateFresh", "queueState",
            "eligibleQueuedCount", "heldQueuedCount", "selectedProfile", "selectedRunId", "selectedJobId",
            "controllerPhase", "capacity"
        })
            Assert(source.Contains("'" + detail + "'", StringComparison.Ordinal), "detail allowlist contains " + detail);

        Assert(source.Contains("token|secret|password|authorization|bearer|connection", StringComparison.OrdinalIgnoreCase),
            "response projector rejects secret-shaped detail values");
        Assert(source.Contains("CI_JIT_CLIENT_RESULT=", StringComparison.Ordinal), "output uses one fixed result prefix");

        foreach (var forbidden in new[]
        {
            "Invoke-Expression", "Start-Process", "ProcessStartInfo", "Invoke-WebRequest", "Invoke-RestMethod",
            "Register-ScheduledTask", "New-ScheduledTask", "Start-ScheduledTask", "schtasks.exe", "HttpClient",
            "TcpClient", "TcpListener", "File.WriteAllText", "Set-Content", "Add-Content"
        })
            Assert(!source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "client excludes primitive " + forbidden);

        Assert(!Regex.IsMatch(parameterSurface, @"(?i)\[(?:string|object)\]\s*\$(?:Request|Response|Details|Summary|Error)"),
            "caller cannot inject raw broker envelopes or response fields");

        Console.WriteLine($"CI/JIT fixed client source tests: {assertions} assertions passed.");
    }
}
