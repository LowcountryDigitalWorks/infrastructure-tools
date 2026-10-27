using System.Text;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class StatusForm : Form
{
    private readonly Action _refresh;
    private readonly Action _copyDiagnostics;
    private readonly FlowLayoutPanel _content = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(22) };
    private readonly Label _name = new() { AutoSize = true, Font = new Font("Segoe UI", 17, FontStyle.Bold), ForeColor = Color.FromArgb(22, 44, 68) };
    private readonly Label _overall = new() { AutoSize = true, Font = new Font("Segoe UI", 12, FontStyle.Bold), Padding = new Padding(0, 8, 0, 2) };
    private readonly Label _summary = new() { AutoSize = true, MaximumSize = new Size(720, 0), ForeColor = Color.FromArgb(57, 72, 86) };
    private readonly Label _refreshed = new() { AutoSize = true, ForeColor = Color.FromArgb(85, 101, 116), Padding = new Padding(0, 4, 0, 10) };
    private readonly FlowLayoutPanel _groups = new() { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, FlowDirection = FlowDirection.TopDown, WrapContents = false, MaximumSize = new Size(760, 0) };
    private readonly Button _details = new() { Text = "Details and diagnostics", AutoSize = true, AccessibleName = "Show detailed telemetry and diagnostics", Margin = new Padding(0, 12, 8, 0), MinimumSize = new Size(150, 36) };
    private HostAgentLiveSnapshot? _live;

    public StatusForm(Action refresh, Action copyDiagnostics)
    {
        _refresh = refresh;
        _copyDiagnostics = copyDiagnostics;
        Text = "LDW Host Agent";
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(760, 680);
        MinimumSize = new Size(520, 500);
        BackColor = Color.FromArgb(246, 248, 249);
        Font = new Font("Segoe UI", 9.5f);
        KeyPreview = true;
        var header = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = Color.White, Padding = new Padding(16), MinimumSize = new Size(700, 0), MaximumSize = new Size(760, 0), Margin = new Padding(0, 12, 0, 14) };
        header.Width = 700;
        var headerLayout = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Dock = DockStyle.Fill };
        headerLayout.Controls.AddRange([_name, _overall, _summary, _refreshed]);
        var actions = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true, Margin = new Padding(0, 10, 0, 0) };
        var refreshButton = new Button { Text = "Refresh", AutoSize = true, MinimumSize = new Size(108, 38), AccessibleName = "Refresh Host Agent status" };
        var copyButton = new Button { Text = "Copy diagnostics", AutoSize = true, MinimumSize = new Size(145, 38) };
        refreshButton.Click += (_, _) => _refresh();
        copyButton.Click += (_, _) => _copyDiagnostics();
        _details.Click += (_, _) => ShowDetails();
        actions.Controls.AddRange([refreshButton, copyButton, _details]);
        headerLayout.Controls.Add(actions);
        header.Controls.Add(headerLayout);
        _content.Controls.Add(header);
        _content.Controls.Add(_groups);
        Controls.Add(_content);
        AcceptButton = refreshButton;
        Shown += (_, _) => refreshButton.Focus();
        UpdateSnapshot(null);
    }

    public void UpdateSnapshot(HostAgentLiveSnapshot? live)
    {
        _live = live;
        _groups.SuspendLayout();
        _groups.Controls.Clear();
        if (live is null)
        {
            SetOverall(StatusColor.Gray, "Status is starting. Waiting for the first observation.");
            _name.Text = "Host Agent";
            _refreshed.Text = "Last refreshed: Waiting";
            _groups.ResumeLayout();
            return;
        }

        _name.Text = $"{live.Definition.Name}  ·  LDW Host Agent";
        SetOverall(live.Snapshot.Color, live.Snapshot.Summary);
        _refreshed.Text = $"Last refreshed {live.Snapshot.ObservedAt.ToLocalTime():g}";
        _groups.Controls.Add(CreateCiJitCard(live.CiJitStatus));
        var observations = live.Snapshot.Components.ToDictionary(x => x.ComponentId, StringComparer.OrdinalIgnoreCase);
        foreach (var environment in live.Definition.Environments)
        {
            var card = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = Color.White, Padding = new Padding(15), Margin = new Padding(0, 0, 0, 12), MinimumSize = new Size(700, 0), MaximumSize = new Size(760, 0), Width = 700 };
            var rows = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, FlowDirection = FlowDirection.TopDown, WrapContents = false, Dock = DockStyle.Fill, MaximumSize = new Size(720, 0) };
            rows.Controls.Add(new Label { AutoSize = true, Font = new Font("Segoe UI", 11, FontStyle.Bold), ForeColor = Color.FromArgb(22, 44, 68), Text = environment.Id == "development-automation" ? "Development && Automation" : environment.Name, Padding = new Padding(0, 0, 0, 7) });
            foreach (var component in environment.Components)
            {
                observations.TryGetValue(component.Id, out var observation);
                var color = observation?.Color ?? StatusColor.Gray;
                var state = StatusPresentation.For(color);
                var row = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 2, Margin = new Padding(0, 3, 0, 7), MaximumSize = new Size(700, 0) };
                row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 122));
                row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                row.Controls.Add(new Label { AutoSize = true, Text = $"{state.Glyph}  {state.Word}", ForeColor = ColorFor(color), Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), AccessibleName = $"State: {state.Word}" }, 0, 0);
                row.Controls.Add(new Label { AutoSize = true, Text = component.Name, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), ForeColor = Color.FromArgb(30, 48, 65), MaximumSize = new Size(550, 0) }, 1, 0);
                row.SetColumnSpan(row.Controls[0], 1);
                row.Controls.Add(new Label { AutoSize = true, Text = observation?.Summary ?? "No observation available yet.", ForeColor = Color.FromArgb(70, 86, 101), MaximumSize = new Size(550, 0), Margin = new Padding(0, 1, 0, 0) }, 1, 1);
                rows.Controls.Add(row);
            }
            card.Controls.Add(rows);
            _groups.Controls.Add(card);
        }
        _groups.ResumeLayout();
    }

    public void ShowError(string message)
    {
        _live = StatusPresentation.SampleForDisplay(_live, observationSucceeded: false);
        _groups.Controls.Clear();
        SetOverall(StatusColor.Gray, string.IsNullOrWhiteSpace(message) ? "Status is unavailable." : "Status refresh failed; sensitive details are suppressed.");
        _refreshed.Text = "Last refreshed: unavailable";
    }

    private static Panel CreateCiJitCard(CiJitStatusSnapshot status)
    {
        var state = StatusPresentation.For(status.Color);
        var phase = status.ControllerPhase?.ToString() ?? "None";
        var detail = $"{status.State} · {status.QueueSummary} · capacity {status.Capacity} · phase {phase}";
        if (!string.IsNullOrWhiteSpace(status.ReasonCode)) detail += $" · {status.ReasonCode}";

        var card = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = Color.White, Padding = new Padding(15), Margin = new Padding(0, 0, 0, 12), MinimumSize = new Size(700, 0), MaximumSize = new Size(760, 0), Width = 700 };
        var rows = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, FlowDirection = FlowDirection.TopDown, WrapContents = false, Dock = DockStyle.Fill, MaximumSize = new Size(720, 0) };
        rows.Controls.Add(new Label { AutoSize = true, Font = new Font("Segoe UI", 11, FontStyle.Bold), ForeColor = Color.FromArgb(22, 44, 68), Text = "CI / JIT", Padding = new Padding(0, 0, 0, 7) });
        rows.Controls.Add(new Label { AutoSize = true, Text = $"{state.Glyph}  {status.State}", ForeColor = ColorFor(status.Color), Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), AccessibleName = $"CI JIT state: {status.State}" });
        rows.Controls.Add(new Label { AutoSize = true, Text = detail, ForeColor = Color.FromArgb(70, 86, 101), MaximumSize = new Size(650, 0), Margin = new Padding(0, 2, 0, 0) });
        card.Controls.Add(rows);
        return card;
    }

    private void SetOverall(StatusColor color, string summary)
    {
        var state = StatusPresentation.For(color);
        _overall.Text = $"{state.Glyph}  {state.Word}";
        _overall.ForeColor = ColorFor(color);
        _summary.Text = summary;
    }

    private void ShowDetails()
    {
        var text = new StringBuilder();
        if (_live is null) text.AppendLine("No telemetry sample is available yet.");
        else
        {
            text.AppendLine($"Observed (UTC): {_live.Snapshot.ObservedAt:O}");
            text.AppendLine($"Configuration: {_live.Configuration.Summary}");
            text.AppendLine($"Owner session: {_live.RuntimeContext.OwnerSession}");
            var ci = _live.CiJitStatus;
            text.AppendLine($"CI/JIT: state {ci.State}; queue {ci.QueueState}; eligible {(ci.EligibleQueuedCount?.ToString() ?? "unknown")}; held {(ci.HeldQueuedCount?.ToString() ?? "unknown")}; capacity {ci.Capacity}; phase {(ci.ControllerPhase?.ToString() ?? "none")}; profile {(ci.SelectedProfile ?? "none")}; run {(ci.SelectedRunId?.ToString() ?? "none")}; job {(ci.SelectedJobId?.ToString() ?? "none")}; reason {(ci.ReasonCode ?? "none")}.");
            if (_live.LinuxTelemetry is { } linux)
            {
                var root = linux.Disks.FirstOrDefault();
                var rootFree = root is { TotalBytes: > 0 } ? $"{root.AvailableBytes * 100d / root.TotalBytes:F1}%" : "unknown";
                text.AppendLine($"Linux: kernel {linux.Kernel}; uptime {linux.Uptime.TotalHours:F1} h; load1 {linux.Load1:F2}; memory available {FormatBytes(linux.MemoryAvailableBytes)}; swap used {FormatBytes(linux.SwapUsedBytes)}; root free {rootFree}; CPU PSI {FormatNullable(linux.CpuPsiSomeAverage10)}; memory PSI some/full {FormatNullable(linux.MemoryPsiSomeAverage10)}/{FormatNullable(linux.MemoryPsiFullAverage10)}; reboot required {linux.RebootRequired}; updates {(linux.UpdatesAvailable?.ToString() ?? "unknown")}.");
            }
            text.AppendLine($"System: physical memory {_live.SystemTelemetry.AvailablePercent:F1}% available; CPU sample {_live.SystemTelemetry.CpuBusyPercent?.ToString("F1") ?? "unknown"}%; { _live.SystemTelemetry.Disks.Count} disk(s); memory pressure {_live.SystemTelemetry.MemoryPressure.Summary}.");
            if (_live.GitHubRunnerTelemetry is { } runner)
                text.AppendLine($"Runner: ID present {runner.Id > 0}; online {runner.Online}; busy {runner.Busy}; label count {runner.Labels.Count}.");
            foreach (var observation in _live.Snapshot.Components)
                text.AppendLine($"{observation.ComponentId}: {observation.Color} / {observation.Health} — {observation.Summary}");
        }
        using var dialog = new Form { Text = "Host Agent details", StartPosition = FormStartPosition.CenterParent, ClientSize = new Size(680, 460), MinimumSize = new Size(500, 350), AutoScaleMode = AutoScaleMode.Dpi };
        var details = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true, AccessibleName = "Detailed Host Agent telemetry", Text = text.ToString(), Font = new Font("Consolas", 9) };
        var copy = new Button { Text = "Copy diagnostics", Dock = DockStyle.Bottom, Height = 42, MinimumSize = new Size(0, 38) };
        copy.Click += (_, _) => _copyDiagnostics();
        dialog.Controls.Add(details);
        dialog.Controls.Add(copy);
        dialog.ShowDialog(this);
    }

    private static string FormatBytes(ulong bytes) => bytes >= 1024UL * 1024 * 1024 ? $"{bytes / 1024d / 1024 / 1024:F2} GiB" : $"{bytes / 1024d / 1024:F1} MiB";
    private static string FormatNullable(double? value) => value?.ToString("F2") ?? "unknown";

    private static Color ColorFor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.FromArgb(0, 112, 96),
        StatusColor.Blue => Color.FromArgb(35, 91, 153),
        StatusColor.Purple => Color.FromArgb(110, 64, 139),
        StatusColor.Yellow => Color.FromArgb(142, 91, 0),
        StatusColor.Red => Color.FromArgb(173, 45, 49),
        _ => Color.FromArgb(91, 105, 119),
    };
}
