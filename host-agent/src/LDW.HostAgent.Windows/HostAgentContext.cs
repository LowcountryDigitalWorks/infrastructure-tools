using System.Text;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class HostAgentContext : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly ToolStripMenuItem _summaryItem;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly HostAgentLiveSnapshotProvider _provider;
    private StatusForm? _statusForm;
    private HostAgentLiveSnapshot? _lastSnapshot;

    public HostAgentContext()
    {
        _provider = new HostAgentLiveSnapshotProvider(HostAgentSettingsLoader.Load());
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
        if (!await _refreshGate.WaitAsync(0))
            return;
        try
        {
            _lastSnapshot = await _provider.ObserveAsync(CancellationToken.None);
            _summaryItem.Text = $"{_lastSnapshot.Snapshot.Color}: {_lastSnapshot.Snapshot.Health}";
            _trayIcon.Text = LimitTrayText($"LDW Host Agent — {_lastSnapshot.Snapshot.Color} — {_lastSnapshot.Snapshot.Health}");
            _statusForm?.UpdateSnapshot(_lastSnapshot);
        }
        catch
        {
            _summaryItem.Text = "Status unavailable";
            _trayIcon.Text = "LDW Host Agent — status unavailable";
            _statusForm?.ShowError("Status refresh failed.");
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private void ShowStatus()
    {
        _statusForm ??= new StatusForm();
        _statusForm.FormClosed += (_, _) => _statusForm = null;
        if (_lastSnapshot is not null)
            _statusForm.UpdateSnapshot(_lastSnapshot);
        _statusForm.Show();
        _statusForm.Activate();
    }

    private void CopyDiagnostics()
    {
        if (_lastSnapshot is null)
        {
            Clipboard.SetText("LDW Host Agent: no sanitized telemetry sample available.");
            return;
        }

        var builder = new StringBuilder();
        builder.AppendLine("LDW Host Agent sanitized diagnostic snapshot");
        builder.AppendLine($"Observed (UTC): {_lastSnapshot.Snapshot.ObservedAt:O}");
        builder.AppendLine($"Overall: {_lastSnapshot.Snapshot.Color} / {_lastSnapshot.Snapshot.Health} — {_lastSnapshot.Snapshot.Summary}");
        builder.AppendLine($"Owner session: {_lastSnapshot.RuntimeContext.OwnerSession}");
        builder.AppendLine($"Configuration: {_lastSnapshot.Configuration.Summary}");
        foreach (var observation in _lastSnapshot.Snapshot.Components)
            builder.AppendLine($"{observation.ComponentId}: {observation.Color} / {observation.State} / {observation.Health} — {observation.Summary}");
        if (_lastSnapshot.LinuxTelemetry is { } linux)
            builder.AppendLine($"linux: kernel={linux.Kernel}; uptimeHours={linux.Uptime.TotalHours:F1}; load1={linux.Load1:F2}; memoryAvailableBytes={linux.MemoryAvailableBytes}; swapUsedBytes={linux.SwapUsedBytes}; cpuPsiKnown={linux.CpuPsiSomeAverage10.HasValue}; memoryPsiKnown={linux.MemoryPsiSomeAverage10.HasValue}; updates={(linux.UpdatesAvailable.HasValue ? linux.UpdatesAvailable.Value.ToString() : "unknown")}; rebootRequired={linux.RebootRequired}");
        if (_lastSnapshot.GitHubRunnerTelemetry is { } runner)
            builder.AppendLine($"github-runner: idPresent={runner.Id > 0}; online={runner.Online}; busy={runner.Busy}; labelCount={runner.Labels.Count}");
        builder.AppendLine("Machine-local addresses, SSH targets/paths, credentials, GitHub auth, and raw adapter output are intentionally omitted.");
        Clipboard.SetText(builder.ToString());
    }

    private static string LimitTrayText(string value) => value.Length <= 63 ? value : value[..63];

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _timer.Dispose();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _statusForm?.Close();
        _refreshGate.Dispose();
        base.ExitThreadCore();
    }
}
