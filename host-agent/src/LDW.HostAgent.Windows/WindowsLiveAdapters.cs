using System.Diagnostics;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class WindowsLiveAdapters
{
    private readonly ReadOnlyCommandRunner _commands;
    private readonly HostAgentSettings _settings;

    public WindowsLiveAdapters(ReadOnlyCommandRunner commands, HostAgentSettings settings)
    {
        _commands = commands;
        _settings = settings;
    }

    public async ValueTask<ComponentObservation> ObserveTailscaleAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        var service = await QueryServiceAsync("Tailscale", cancellationToken);
        if (service.Installed == false)
            return Observation(component, ObservedState.Unavailable, runtime, "Tailscale service is not installed.");
        if (service.Running == false)
            return Observation(component, ObservedState.Stopped, runtime, "Tailscale service is installed but not running.");
        if (service.Running is null)
            return Unknown(component, "Tailscale service state could not be observed.");

        var executable = "tailscale.exe";
        var statusResult = await _commands.RunAsync(executable, ["status", "--json"], TimeSpan.FromSeconds(5), cancellationToken);
        if (!statusResult.Success)
        {
            var programFilesCli = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tailscale", "tailscale.exe");
            if (File.Exists(programFilesCli))
            {
                executable = programFilesCli;
                statusResult = await _commands.RunAsync(executable, ["status", "--json"], TimeSpan.FromSeconds(5), cancellationToken);
            }
        }
        if (!statusResult.Success || string.IsNullOrWhiteSpace(statusResult.StdOut))
            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow, "Tailscale service is running; CLI readiness is unavailable.");

        try
        {
            var status = TailscaleStatusParser.Parse(statusResult.StdOut);
            if (!status.Ready)
            {
                var health = string.Equals(status.BackendState, "Running", StringComparison.OrdinalIgnoreCase)
                    ? HealthState.Degraded
                    : HealthState.Failed;
                return new ComponentObservation(component.Id,
                    string.Equals(status.BackendState, "Running", StringComparison.OrdinalIgnoreCase) ? ObservedState.Running : ObservedState.Stopped,
                    health, DateTimeOffset.UtcNow,
                    status.HealthIssueCount > 0
                        ? "Tailscale is reachable locally but reports health attention."
                        : "Tailscale runtime is not ready/online.");
            }

            var prefsResult = await _commands.RunAsync(executable, ["debug", "prefs"], TimeSpan.FromSeconds(5), cancellationToken);
            bool? forceDaemon = null;
            if (prefsResult.Success && !string.IsNullOrWhiteSpace(prefsResult.StdOut))
            {
                try { forceDaemon = TailscalePrefsParser.ParseForceDaemon(prefsResult.StdOut); }
                catch { forceDaemon = null; }
            }

            if (service.Automatic == true && forceDaemon == true)
                return Observation(component, ObservedState.Running, runtime,
                    "Tailscale is running, online, automatic, and configured for unattended operation.");

            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow,
                forceDaemon == false
                    ? "Tailscale is online but unattended/server mode is not enabled."
                    : service.Automatic == false
                        ? "Tailscale is online but its Windows service is not automatic."
                        : "Tailscale is online; unattended startup posture could not be fully verified.");
        }
        catch
        {
            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow, "Tailscale service is running; status output could not be safely interpreted.");
        }
    }
    public async ValueTask<ComponentObservation> ObserveRustDeskAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        var service = await QueryServiceAsync("RustDesk", cancellationToken);
        var processRunning = IsProcessRunning("rustdesk");
        if (service.Running == true && service.Automatic == true)
            return Observation(component, ObservedState.Running, runtime,
                processRunning ? "RustDesk automatic service and runtime process are running." : "RustDesk automatic service is running.");
        if (service.Running == true)
            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow, "RustDesk service is running but automatic startup readiness could not be verified.");
        if (service.Installed == true && processRunning)
            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow, "RustDesk is running interactively but its service is not running; pre-login readiness is not met.");
        if (service.Installed == false && processRunning)
            return new ComponentObservation(component.Id, ObservedState.Running, HealthState.Degraded,
                DateTimeOffset.UtcNow, "RustDesk process is present but service-based unattended readiness is unavailable.");
        if (service.Installed == false)
            return Observation(component, ObservedState.Unavailable, runtime, "RustDesk service/runtime is not installed or observable.");
        if (service.Running == false)
            return Observation(component, ObservedState.Stopped, runtime, "RustDesk service is installed but not running.");
        return Unknown(component, "RustDesk readiness could not be observed.");
    }

    public async ValueTask<ComponentObservation> ObserveDesktopCommanderAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_settings.DesktopCommander.ScheduledTaskName))
            return Unknown(component, "Desktop Commander local scheduled-task name is not configured.");
        var result = await _commands.RunAsync("schtasks.exe",
            ["/Query", "/TN", _settings.DesktopCommander.ScheduledTaskName, "/FO", "CSV", "/NH"],
            TimeSpan.FromSeconds(5), cancellationToken);
        if (!result.Success)
            return Unknown(component, "Desktop Commander scheduled background task could not be observed.");
        var running = ReadOnlyStatusParsers.ParseScheduledTaskRunning(result.StdOut);
        if (running is null)
            return Unknown(component, "Desktop Commander scheduled-task state could not be interpreted.");
        return Observation(component, running.Value ? ObservedState.Running : ObservedState.Stopped, runtime,
            running.Value
                ? "Configured Desktop Commander background task is running."
                : "Configured Desktop Commander background task is not running.");
    }

    public async ValueTask<(ComponentObservation Observation, WslDistroStatus? Distro)> ObserveWslAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        var result = await _commands.RunAsync("wsl.exe", ["--list", "--verbose"], TimeSpan.FromSeconds(5), cancellationToken);
        if (!result.Success)
            return (Unknown(component, "WSL distro state could not be observed."), null);
        var distros = WslListParser.Parse(result.StdOut);
        var distro = distros.FirstOrDefault(x => x.Name.Equals(_settings.Wsl.DistroName, StringComparison.OrdinalIgnoreCase));
        if (distro is null)
            return (Observation(component, ObservedState.Unavailable, runtime, "Configured WSL distro is not present."), null);
        return (Observation(component, distro.State, runtime,
            distro.State == ObservedState.Running ? "Configured WSL distro is running." : "Configured WSL distro is stopped."), distro);
    }

    public async ValueTask<ComponentObservation> ObserveCursorWorkerAsync(
        ComponentDefinition component, RuntimeContext runtime, WslDistroStatus? distro, CancellationToken cancellationToken)
    {
        if (distro is null)
            return Observation(component, ObservedState.Unavailable, runtime, "Cursor Worker host distro is unavailable.");
        if (distro.State != ObservedState.Running)
            return Observation(component, ObservedState.Stopped, runtime,
                "Cursor Worker was not started for observation because its WSL distro is stopped.");
        if (string.IsNullOrWhiteSpace(_settings.Wsl.CursorWorkerService) || !IsSafeSystemdUnit(_settings.Wsl.CursorWorkerService))
            return Unknown(component, "Cursor Worker systemd service name is not configured or valid.");

        var result = await _commands.RunAsync("wsl.exe",
            ["-d", _settings.Wsl.DistroName, "--exec", "systemctl", "is-active", "--", _settings.Wsl.CursorWorkerService],
            TimeSpan.FromSeconds(5), cancellationToken);
        var state = ReadOnlyStatusParsers.ParseSystemctlIsActive(result.StdOut);
        if (state == ObservedState.Unknown && result.TimedOut)
            return Unknown(component, "Cursor Worker systemd state timed out.");
        return Observation(component, state, runtime,
            state == ObservedState.Running ? "Cursor Worker systemd service is active." : "Cursor Worker systemd service is not active.");
    }

    public async ValueTask<(ComponentObservation Observation, LinuxNodeTelemetry? Telemetry)> ObserveLinuxNodeAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        if (_settings.LinuxNode is null)
            return (Unknown(component, "Strict SSH Linux-node configuration is not present."), null);
        var telemetry = await new StrictSshLinuxNodeProbe(_commands, _settings.LinuxNode).ObserveAsync(cancellationToken);
        if (telemetry is null)
            return (Unknown(component, "Strict host-key-verified SSH observation is unavailable; Linux-node health was not fabricated."), null);
        var attention = telemetry.RebootRequired || telemetry.UpdatesAvailable is > 0;
        var runnerUnit = telemetry.SystemdUnits.TryGetValue("github-runner", out var unit) ? unit : ObservedState.Unknown;
        var health = attention || runnerUnit != ObservedState.Running ? HealthState.Degraded : HealthState.Healthy;
        var summary = attention
            ? "Linux node is reachable with update/reboot attention."
            : runnerUnit == ObservedState.Running
                ? "Linux node is reachable; core telemetry and runner service are healthy."
                : "Linux node is reachable; runner service state needs attention.";
        return (new ComponentObservation(component.Id, ObservedState.Running, health, DateTimeOffset.UtcNow, summary), telemetry);
    }

    public async ValueTask<(ComponentObservation Observation, GitHubRunnerTelemetry? Telemetry)> ObserveGitHubRunnerAsync(
        ComponentDefinition component, RuntimeContext runtime, CancellationToken cancellationToken)
    {
        var settings = _settings.GitHubRunner;
        if (settings is null || settings.RunnerId <= 0 || string.IsNullOrWhiteSpace(settings.Repository))
            return (Unknown(component, "GitHub Runner repository/runner identifier is not configured locally."), null);
        if (!IsRepositoryNameSafe(settings.Repository))
            return (Unknown(component, "GitHub Runner local repository setting is invalid."), null);

        var result = await _commands.RunAsync("gh.exe",
            ["api", $"repos/{settings.Repository}/actions/runners/{settings.RunnerId}"],
            TimeSpan.FromSeconds(8), cancellationToken);
        if (!result.Success || string.IsNullOrWhiteSpace(result.StdOut))
            return (Unknown(component, "GitHub Runner API status is unavailable through the existing local gh authentication."), null);
        try
        {
            var telemetry = GitHubRunnerStatusParser.Parse(result.StdOut);
            var state = telemetry.Online ? ObservedState.Running : ObservedState.Stopped;
            var health = DesiredStateEvaluator.Evaluate(component, state, runtime);
            return (new ComponentObservation(component.Id, state, health, DateTimeOffset.UtcNow,
                telemetry.Online
                    ? telemetry.Busy ? "GitHub Runner is online and busy." : "GitHub Runner is online and idle."
                    : "GitHub Runner is offline.",
                Activity: telemetry.Busy ? ActivityState.ActiveCiJob : ActivityState.None), telemetry);
        }
        catch
        {
            return (Unknown(component, "GitHub Runner API response could not be safely interpreted."), null);
        }
    }

    private static bool IsProcessRunning(string processName)
    {
        var processes = Process.GetProcessesByName(processName);
        try { return processes.Length > 0; }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }
    }
    private async ValueTask<(bool? Installed, bool? Running, bool? Automatic)> QueryServiceAsync(string serviceName, CancellationToken cancellationToken)
    {
        var result = await _commands.RunAsync("sc.exe", ["query", serviceName], TimeSpan.FromSeconds(4), cancellationToken);
        if (result.Success)
        {
            var qc = await _commands.RunAsync("sc.exe", ["qc", serviceName], TimeSpan.FromSeconds(4), cancellationToken);
            var automatic = qc.Success ? ReadOnlyStatusParsers.IsWindowsServiceAutomatic(qc.StdOut) : null;
            return (true, ReadOnlyStatusParsers.IsWindowsServiceRunning(result.StdOut), automatic);
        }
        if (result.StdOut.Contains("1060", StringComparison.OrdinalIgnoreCase)
            || result.StdErr.Contains("1060", StringComparison.OrdinalIgnoreCase)
            || result.StdOut.Contains("does not exist", StringComparison.OrdinalIgnoreCase))
            return (false, false, null);
        return (null, null, null);
    }
    private static ComponentObservation Observation(ComponentDefinition component, ObservedState state, RuntimeContext runtime, string summary)
        => new(component.Id, state, DesiredStateEvaluator.Evaluate(component, state, runtime), DateTimeOffset.UtcNow, summary);

    private static ComponentObservation Unknown(ComponentDefinition component, string summary)
        => new(component.Id, ObservedState.Unknown, HealthState.Unknown, DateTimeOffset.UtcNow, summary);

    private static bool IsSafeSystemdUnit(string value)
        => value.Length > 0
           && value[0] != '-'
           && value.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.' or '@');
    private static bool IsRepositoryNameSafe(string value)
    {
        var parts = value.Split('/');
        return parts.Length == 2 && parts.All(part => part.Length > 0 && part.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.'));
    }
}
