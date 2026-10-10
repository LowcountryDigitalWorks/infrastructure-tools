using System.Globalization;
using System.Text.RegularExpressions;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed partial class StrictSshLinuxNodeProbe
{
    private readonly ReadOnlyCommandRunner _commands;
    private readonly LinuxNodeSettings _settings;
    private readonly IHyperVObservationClient _hyperVObserver;

    public StrictSshLinuxNodeProbe(
        ReadOnlyCommandRunner commands,
        LinuxNodeSettings settings,
        IHyperVObservationClient? hyperVObserver = null)
    {
        _commands = commands;
        _settings = settings;
        _hyperVObserver = hyperVObserver ?? new HyperVObservationClient();
    }

    public async ValueTask<LinuxNodeTelemetry?> ObserveAsync(CancellationToken cancellationToken)
    {
        if (!TryValidateLocalConfiguration())
            return null;

        var policy = new StrictSshConnectionPolicy(
            _settings.KnownHostsFile!, _settings.IdentityFile!, true, true, true);
        policy.Validate();

        var targets = await ResolveTargetsAsync(cancellationToken);
        if (targets.Count == 0)
            return null;

        foreach (var targetHost in targets.Take(HyperVObserverContract.MaximumSshCandidates))
        {
            var telemetry = await ObserveTargetAsync(targetHost, cancellationToken);
            if (telemetry is not null)
                return telemetry;
        }

        return null;
    }

    private async ValueTask<IReadOnlyList<string>> ResolveTargetsAsync(CancellationToken cancellationToken)
    {
        if (!_settings.UseHyperVObserver)
            return string.IsNullOrWhiteSpace(_settings.Host) ? [] : [_settings.Host];

        var observation = await _hyperVObserver.ObserveAsync(cancellationToken);
        return observation is null
            ? []
            : HyperVObserverContract.SelectSshCandidates(observation);
    }

    private async ValueTask<LinuxNodeTelemetry?> ObserveTargetAsync(string host, CancellationToken cancellationToken)
    {
        if (!SafeSshHostRegex().IsMatch(host))
            return null;

        var target = $"{_settings.User}@{host}";
        var probe = BuildProbeCommand(_settings.RunnerService!);
        string[] arguments =
        [
            "-i", _settings.IdentityFile!,
            ..(_settings.Port.HasValue ? new[] { "-p", _settings.Port.Value.ToString(CultureInfo.InvariantCulture) } : Array.Empty<string>()),
            "-o", $"UserKnownHostsFile={_settings.KnownHostsFile}",
            ..(!string.IsNullOrWhiteSpace(_settings.HostKeyAlias)
                ? new[] { "-o", $"HostKeyAlias={_settings.HostKeyAlias}" }
                : Array.Empty<string>()),
            "-o", "StrictHostKeyChecking=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=6",
            "-o", "LogLevel=ERROR",
            target,
            probe
        ];
        var result = await _commands.RunAsync("ssh.exe", arguments, TimeSpan.FromSeconds(10), cancellationToken);
        if (!result.Success || string.IsNullOrWhiteSpace(result.StdOut))
            return null;

        try
        {
            return LinuxProbeParser.Parse("linux-ci-node", result.StdOut, DateTimeOffset.UtcNow);
        }
        catch
        {
            return null;
        }
    }

    private bool TryValidateLocalConfiguration()
    {
        if (string.IsNullOrWhiteSpace(_settings.User)
            || string.IsNullOrWhiteSpace(_settings.IdentityFile)
            || string.IsNullOrWhiteSpace(_settings.KnownHostsFile)
            || string.IsNullOrWhiteSpace(_settings.RunnerService))
            return false;
        if (_settings.Port is <= 0 or > 65535)
            return false;
        if (!File.Exists(_settings.IdentityFile) || !File.Exists(_settings.KnownHostsFile))
            return false;
        if (new FileInfo(_settings.KnownHostsFile).Length == 0)
            return false;
        if (!SafeSshUserRegex().IsMatch(_settings.User)
            || !SafeSystemdUnitRegex().IsMatch(_settings.RunnerService))
            return false;

        if (_settings.UseHyperVObserver)
        {
            return !string.IsNullOrWhiteSpace(_settings.HostKeyAlias)
                && SafeSshHostRegex().IsMatch(_settings.HostKeyAlias);
        }

        return !string.IsNullOrWhiteSpace(_settings.Host)
            && SafeSshHostRegex().IsMatch(_settings.Host)
            && (string.IsNullOrWhiteSpace(_settings.HostKeyAlias) || SafeSshHostRegex().IsMatch(_settings.HostKeyAlias));
    }

    private static string BuildProbeCommand(string runnerService)
    {
        // runnerService is regex-validated before it reaches this fixed, read-only remote probe.
        return "LC_ALL=C; " +
               "printf 'KERNEL=%s\\n' \"$(uname -r)\"; " +
               "printf 'UPTIME_SECONDS=%s\\n' \"$(cut -d' ' -f1 /proc/uptime)\"; " +
               "printf 'LOAD1=%s\\n' \"$(cut -d' ' -f1 /proc/loadavg)\"; " +
               "printf 'MEM_AVAILABLE_KB=%s\\n' \"$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)\"; " +
               "printf 'SWAP_TOTAL_KB=%s\\n' \"$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)\"; " +
               "printf 'SWAP_FREE_KB=%s\\n' \"$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)\"; " +
               "set -- $(df -B1 -P / | tail -n 1); printf 'ROOT_TOTAL_BYTES=%s\\nROOT_AVAILABLE_BYTES=%s\\n' \"$2\" \"$4\"; " +
               "printf 'CPU_PSI_SOME_AVG10=%s\\n' \"$(awk '/^some / {for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/^avg10=/,\"\",$i); print $i}}' /proc/pressure/cpu 2>/dev/null)\"; " +
               "printf 'MEM_PSI_SOME_AVG10=%s\\n' \"$(awk '/^some / {for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/^avg10=/,\"\",$i); print $i}}' /proc/pressure/memory 2>/dev/null)\"; " +
               "printf 'MEM_PSI_FULL_AVG10=%s\\n' \"$(awk '/^full / {for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/^avg10=/,\"\",$i); print $i}}' /proc/pressure/memory 2>/dev/null)\"; " +
               "printf 'UPDATES_AVAILABLE=%s\\n' \"$(apt list --upgradable 2>/dev/null | sed '1d' | wc -l)\"; " +
               "if [ -f /var/run/reboot-required ]; then echo 'REBOOT_REQUIRED=1'; else echo 'REBOOT_REQUIRED=0'; fi; " +
               $"printf 'RUNNER_SERVICE=%s\\n' \"$(systemctl is-active -- {runnerService} 2>/dev/null || true)\"";
    }

    [GeneratedRegex(@"^[A-Za-z0-9.:\[\]-]+$")]
    private static partial Regex SafeSshHostRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_.-]+$")]
    private static partial Regex SafeSshUserRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_.@-]+$")]
    private static partial Regex SafeSystemdUnitRegex();
}
