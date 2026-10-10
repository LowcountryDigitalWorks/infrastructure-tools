using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LDW.HostAgent.Core;

public static class OwnerSessionStateMapper
{
    public static OwnerSessionState FromWtsConnectState(int? state) => state switch
    {
        0 => OwnerSessionState.Active,       // WTSActive
        4 or 5 => OwnerSessionState.Inactive, // WTSDisconnected / WTSIdle
        _ => OwnerSessionState.Unknown
    };
}

public sealed record TailscaleRuntimeStatus(string BackendState, bool SelfOnline, int HealthIssueCount)
{
    public bool Ready => string.Equals(BackendState, "Running", StringComparison.OrdinalIgnoreCase)
        && SelfOnline && HealthIssueCount == 0;
}

public static class TailscaleStatusParser
{
    public static TailscaleRuntimeStatus Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var backend = root.TryGetProperty("BackendState", out var backendElement)
            ? backendElement.GetString() ?? "Unknown"
            : "Unknown";
        var online = root.TryGetProperty("Self", out var self)
            && self.ValueKind == JsonValueKind.Object
            && self.TryGetProperty("Online", out var onlineElement)
            && onlineElement.ValueKind is JsonValueKind.True;
        var healthCount = root.TryGetProperty("Health", out var health) && health.ValueKind == JsonValueKind.Array
            ? health.GetArrayLength()
            : 0;
        return new TailscaleRuntimeStatus(backend, online, healthCount);
    }
}

public static class TailscalePrefsParser
{
    public static bool? ParseForceDaemon(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (!root.TryGetProperty("ForceDaemon", out var value))
            return null;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }
}
public sealed record WslDistroStatus(string Name, ObservedState State, int? Version);

public static partial class WslListParser
{
    [GeneratedRegex(@"^\s*\*?\s*(?<name>.+?)\s{2,}(?<state>Running|Stopped)\s+(?<version>\d+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex DistroLineRegex();

    public static IReadOnlyList<WslDistroStatus> Parse(string output)
    {
        var result = new List<WslDistroStatus>();
        foreach (var raw in output.Replace("\0", string.Empty, StringComparison.Ordinal)
                     .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.TrimEnd();
            if (line.Contains("NAME", StringComparison.OrdinalIgnoreCase)
                && line.Contains("STATE", StringComparison.OrdinalIgnoreCase))
                continue;
            var match = DistroLineRegex().Match(line);
            if (!match.Success)
                continue;
            var state = match.Groups["state"].Value.Equals("Running", StringComparison.OrdinalIgnoreCase)
                ? ObservedState.Running
                : ObservedState.Stopped;
            _ = int.TryParse(match.Groups["version"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var version);
            result.Add(new WslDistroStatus(match.Groups["name"].Value.Trim(), state, version));
        }
        return result;
    }
}

public static partial class ReadOnlyStatusParsers
{
    [GeneratedRegex(@"STATE\s*:\s*4\s+RUNNING", RegexOptions.IgnoreCase)]
    private static partial Regex ScRunningRegex();

    public static bool IsWindowsServiceRunning(string scOutput) => ScRunningRegex().IsMatch(scOutput);

    public static bool? IsWindowsServiceAutomatic(string scQcOutput)
    {
        if (scQcOutput.Contains("AUTO_START", StringComparison.OrdinalIgnoreCase))
            return true;
        if (scQcOutput.Contains("DEMAND_START", StringComparison.OrdinalIgnoreCase)
            || scQcOutput.Contains("DISABLED", StringComparison.OrdinalIgnoreCase))
            return false;
        return null;
    }

    public static bool? ParseScheduledTaskRunning(string csvOutput)
    {
        var line = csvOutput.Replace("\0", string.Empty, StringComparison.Ordinal).Trim();
        if (string.IsNullOrWhiteSpace(line))
            return null;
        if (line.Contains("\"Running\"", StringComparison.OrdinalIgnoreCase))
            return true;
        if (line.Contains("\"Ready\"", StringComparison.OrdinalIgnoreCase)
            || line.Contains("\"Disabled\"", StringComparison.OrdinalIgnoreCase))
            return false;
        return null;
    }

    public static ObservedState ParseSystemctlIsActive(string output) => output.Trim().ToLowerInvariant() switch
    {
        "active" => ObservedState.Running,
        "inactive" or "failed" or "deactivating" => ObservedState.Stopped,
        _ => ObservedState.Unknown
    };
}

public static class GitHubRunnerStatusParser
{
    public static GitHubRunnerTelemetry Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var id = root.GetProperty("id").GetInt64();
        var name = root.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "runner" : "runner";
        var online = root.TryGetProperty("status", out var statusElement)
            && string.Equals(statusElement.GetString(), "online", StringComparison.OrdinalIgnoreCase);
        var busy = root.TryGetProperty("busy", out var busyElement) && busyElement.ValueKind == JsonValueKind.True;
        var labels = new List<string>();
        if (root.TryGetProperty("labels", out var labelsElement) && labelsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var label in labelsElement.EnumerateArray())
            {
                if (label.ValueKind == JsonValueKind.String)
                    labels.Add(label.GetString() ?? string.Empty);
                else if (label.ValueKind == JsonValueKind.Object && label.TryGetProperty("name", out var labelName))
                    labels.Add(labelName.GetString() ?? string.Empty);
            }
        }
        return new GitHubRunnerTelemetry(id, name, online, busy, labels.Where(x => x.Length > 0).ToArray());
    }
}

public static class LinuxProbeParser
{
    public static LinuxNodeTelemetry Parse(string nodeId, string output, DateTimeOffset observedAt)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var index = raw.IndexOf('=');
            if (index <= 0)
                continue;
            values[raw[..index].Trim()] = raw[(index + 1)..].Trim();
        }

        var kernel = Require(values, "KERNEL");
        var uptimeSeconds = RequireDouble(values, "UPTIME_SECONDS");
        var load1 = RequireDouble(values, "LOAD1");
        var memoryAvailableKb = RequireULong(values, "MEM_AVAILABLE_KB");
        var swapTotal = RequireULong(values, "SWAP_TOTAL_KB");
        var swapFree = RequireULong(values, "SWAP_FREE_KB");
        var rootTotal = RequireULong(values, "ROOT_TOTAL_BYTES");
        var rootAvailable = RequireULong(values, "ROOT_AVAILABLE_BYTES");
        var runnerState = ReadOnlyStatusParsers.ParseSystemctlIsActive(Require(values, "RUNNER_SERVICE"));
        var reboot = Require(values, "REBOOT_REQUIRED");

        if (uptimeSeconds < 0 || load1 < 0 || swapFree > swapTotal || rootTotal == 0 || rootAvailable > rootTotal)
            throw new FormatException("Linux telemetry contains impossible core values.");
        if (reboot is not ("0" or "1"))
            throw new FormatException("Linux reboot-required state is invalid.");

        var units = new Dictionary<string, ObservedState>(StringComparer.OrdinalIgnoreCase)
        {
            ["github-runner"] = runnerState
        };

        return new LinuxNodeTelemetry(
            nodeId,
            observedAt,
            kernel,
            TimeSpan.FromSeconds(uptimeSeconds),
            load1,
            KbToBytes(memoryAvailableKb),
            KbToBytes(swapTotal - swapFree),
            [new DiskTelemetry("/", rootTotal, rootAvailable)],
            ParseOptionalDouble(values, "CPU_PSI_SOME_AVG10"),
            ParseOptionalDouble(values, "MEM_PSI_SOME_AVG10"),
            ParseOptionalDouble(values, "MEM_PSI_FULL_AVG10"),
            units,
            reboot == "1",
            true,
            ParseOptionalInt(values, "UPDATES_AVAILABLE"));
    }

    private static string Require(IReadOnlyDictionary<string, string> values, string key)
    {
        if (!values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Linux telemetry is missing required field {key}.");
        return value;
    }

    private static double RequireDouble(IReadOnlyDictionary<string, string> values, string key)
    {
        var value = Require(values, key);
        if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) || !double.IsFinite(parsed))
            throw new FormatException($"Linux telemetry field {key} is invalid.");
        return parsed;
    }

    private static ulong RequireULong(IReadOnlyDictionary<string, string> values, string key)
    {
        var value = Require(values, key);
        if (!ulong.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            throw new FormatException($"Linux telemetry field {key} is invalid.");
        return parsed;
    }

    private static double? ParseOptionalDouble(IReadOnlyDictionary<string, string> values, string key)
    {
        if (!values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            return null;
        if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) || !double.IsFinite(parsed))
            throw new FormatException($"Linux telemetry field {key} is invalid.");
        return parsed;
    }

    private static int? ParseOptionalInt(IReadOnlyDictionary<string, string> values, string key)
    {
        if (!values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            return null;
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
            throw new FormatException($"Linux telemetry field {key} is invalid.");
        return parsed;
    }

    private static ulong KbToBytes(ulong value) => checked(value * 1024UL);
}
