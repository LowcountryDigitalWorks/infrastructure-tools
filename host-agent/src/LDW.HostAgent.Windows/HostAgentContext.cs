using System.Globalization;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class HostAgentContext : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly ToolStripMenuItem _summaryItem;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly WindowsSystemProbe _probe = new();
    private StatusForm? _statusForm;
    private SystemTelemetry? _lastTelemetry;

    public HostAgentContext()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Status", null, (_, _) => ShowStatus());
        menu.Items.Add("Refresh Now", null, async (_, _) => await RefreshAsync());
        menu.Items.Add("Copy Diagnostics", null, (_, _) => CopyDiagnostics());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitThread());
        _summaryItem = new ToolStripMenuItem("Collecting status…") { Enabled = false };
        menu.Items.Insert(0, _summaryItem);
        menu.Items.Insert(1, new ToolStripSeparator());
        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "LDW Host Agent — collecting status",
            ContextMenuStrip = menu,
            Visible = true
        };
        _trayIcon.DoubleClick += (_, _) => ShowStatus();
        _timer = new System.Windows.Forms.Timer { Interval = 15_000 };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            _lastTelemetry = await _probe.ObserveAsync(CancellationToken.None);
            var pressure = MemoryPressureEvaluator.Evaluate(_lastTelemetry);
            var level = pressure switch
            {
                MemoryPressureLevel.Normal => "Healthy",
                MemoryPressureLevel.Elevated => "Attention",
                MemoryPressureLevel.Severe => "High pressure",
                _ => "Unknown"
            };
            _summaryItem.Text = $"Memory: {level}";
            _trayIcon.Text = $"LDW Host Agent — {level}";
            _statusForm?.UpdateTelemetry(Environment.MachineName, _lastTelemetry, pressure);
        }
        catch (Exception ex)
        {
            _summaryItem.Text = "Status unavailable";
            _trayIcon.Text = "LDW Host Agent — status unavailable";
            _statusForm?.ShowError(ex.Message);
        }
    }

    private void ShowStatus()
    {
        _statusForm ??= new StatusForm();
        _statusForm.FormClosed += (_, _) => _statusForm = null;
        if (_lastTelemetry is not null)
            _statusForm.UpdateTelemetry(Environment.MachineName, _lastTelemetry, MemoryPressureEvaluator.Evaluate(_lastTelemetry));
        _statusForm.Show();
        _statusForm.Activate();
    }

    private void CopyDiagnostics()
    {
        if (_lastTelemetry is null)
        {
            Clipboard.SetText("LDW Host Agent: no telemetry sample available.");
            return;
        }
        var t = _lastTelemetry;
        Clipboard.SetText(string.Join(Environment.NewLine,
            "LDW Host Agent local diagnostic snapshot",
            $"Device: {Environment.MachineName}",
            $"Observed (UTC): {t.ObservedAt:O}",
            $"Available memory: {FormatBytes(t.AvailablePhysicalBytes)} / {FormatBytes(t.TotalPhysicalBytes)} ({t.AvailablePercent:F1}% available)",
            $"CPU busy: {(t.CpuBusyPercent.HasValue ? t.CpuBusyPercent.Value.ToString("F1", CultureInfo.InvariantCulture) + "%" : "unknown")}",
            $"Pressure: {MemoryPressureEvaluator.Evaluate(t)} — {t.MemoryPressure.Summary}",
            $"Fixed disks: {t.Disks.Count}"));
    }

    private static string FormatBytes(ulong bytes) => $"{bytes / 1024d / 1024 / 1024:F2} GiB";

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _timer.Dispose();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _statusForm?.Close();
        base.ExitThreadCore();
    }
}
