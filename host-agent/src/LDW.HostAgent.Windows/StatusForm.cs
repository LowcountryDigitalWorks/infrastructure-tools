using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class StatusForm : Form
{
    private readonly Label _device = new() { AutoSize = true, Font = new Font("Segoe UI", 15, FontStyle.Bold) };
    private readonly Label _overall = new() { AutoSize = true, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
    private readonly Label _session = new() { AutoSize = true };
    private readonly Label _configuration = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly FlowLayoutPanel _components = new()
    {
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        FlowDirection = FlowDirection.TopDown,
        WrapContents = false,
        MaximumSize = new Size(720, 0)
    };
    private readonly Label _statusLegend = new()
    {
        AutoSize = true,
        MaximumSize = new Size(700, 0),
        Text = "Status semantics: Green = desired state met; Blue = active CI job; Purple = CI Boost enabled; Yellow = degraded/attention; Red = confirmed failure/down; Gray = unknown/initializing. Text and reason are always shown so color is never the only signal."
    };

    public StatusForm()
    {
        Text = "LDW Host Agent — Status";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(760, 640);
        MinimumSize = new Size(700, 480);
        var layout = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            Padding = new Padding(20),
            WrapContents = false,
            AutoScroll = true
        };
        layout.Controls.AddRange([_device, _overall, _session, _configuration, _components, _statusLegend]);
        Controls.Add(layout);
    }

    public void UpdateSnapshot(HostAgentLiveSnapshot live)
    {
        _device.Text = $"{live.Definition.Name}  ·  Host Agent";
        _overall.Text = $"Overall: {live.Snapshot.Color.ToString().ToUpperInvariant()} · {live.Snapshot.Summary}";
        _overall.ForeColor = ColorFor(live.Snapshot.Color);
        _session.Text = $"Owner session context: {live.RuntimeContext.OwnerSession}";
        _configuration.Text = live.Configuration.Summary;

        _components.SuspendLayout();
        _components.Controls.Clear();
        var observations = live.Snapshot.Components.ToDictionary(o => o.ComponentId, StringComparer.OrdinalIgnoreCase);
        foreach (var environment in live.Definition.Environments)
        {
            _components.Controls.Add(new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Text = environment.Name,
                Margin = new Padding(0, 10, 0, 2)
            });
            foreach (var component in environment.Components)
            {
                if (!observations.TryGetValue(component.Id, out var observation))
                    continue;
                var nested = component.DependsOn is { Count: > 0 };
                _components.Controls.Add(new Label
                {
                    AutoSize = true,
                    MaximumSize = new Size(700, 0),
                    Margin = new Padding(nested ? 28 : 12, 2, 0, 2),
                    ForeColor = ColorFor(observation.Color),
                    Text = $"[{observation.Color.ToString().ToUpperInvariant()}] {component.Name} — {observation.Summary}"
                });

                if (component.Id == HostAgentLiveSnapshotProvider.Ids.LinuxNode && live.LinuxTelemetry is { } linux)
                    AddLinuxDetail(linux);
                if (component.Id == HostAgentLiveSnapshotProvider.Ids.GitHubRunner && live.GitHubRunnerTelemetry is { } runner)
                    AddRunnerDetail(runner);
            }
        }
        _components.ResumeLayout();
    }

    private void AddLinuxDetail(LinuxNodeTelemetry linux)
    {
        var root = linux.Disks.FirstOrDefault();
        var rootFree = root is { TotalBytes: > 0 } ? root.AvailableBytes * 100d / root.TotalBytes : (double?)null;
        _components.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Margin = new Padding(48, 0, 0, 2),
            Text = $"Kernel {linux.Kernel}; uptime {linux.Uptime.TotalHours:F1} h; load1 {linux.Load1:F2}; memory available {FormatBytes(linux.MemoryAvailableBytes)}; swap used {FormatBytes(linux.SwapUsedBytes)}; root free {(rootFree.HasValue ? $"{rootFree:F1}%" : "unknown")}; CPU PSI {FormatNullable(linux.CpuPsiSomeAverage10)}; memory PSI some/full {FormatNullable(linux.MemoryPsiSomeAverage10)}/{FormatNullable(linux.MemoryPsiFullAverage10)}; updates {(linux.UpdatesAvailable.HasValue ? linux.UpdatesAvailable.Value.ToString() : "unknown")}; reboot required {linux.RebootRequired}."
        });
    }

    private void AddRunnerDetail(GitHubRunnerTelemetry runner)
    {
        _components.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Margin = new Padding(48, 0, 0, 2),
            Text = $"Runner ID present {runner.Id > 0}; online {runner.Online}; busy {runner.Busy}; label count {runner.Labels.Count}."
        });
    }

    public void ShowError(string message)
    {
        _overall.Text = "Overall: GRAY · Status unavailable.";
        _overall.ForeColor = Color.DimGray;
        _configuration.Text = string.IsNullOrWhiteSpace(message) ? "Status refresh failed." : "Status refresh failed; sensitive details were suppressed.";
    }

    private static string FormatBytes(ulong bytes) => bytes >= 1024UL * 1024 * 1024
        ? $"{bytes / 1024d / 1024 / 1024:F2} GiB"
        : $"{bytes / 1024d / 1024:F1} MiB";

    private static string FormatNullable(double? value) => value.HasValue ? value.Value.ToString("F2") : "n/a";

    private static Color ColorFor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.DarkGreen,
        StatusColor.Blue => Color.RoyalBlue,
        StatusColor.Purple => Color.Purple,
        StatusColor.Yellow => Color.DarkGoldenrod,
        StatusColor.Red => Color.Firebrick,
        _ => Color.DimGray
    };
}
