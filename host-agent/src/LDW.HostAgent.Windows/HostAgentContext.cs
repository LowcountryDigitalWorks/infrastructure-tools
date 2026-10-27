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
        _trayIcon = new NotifyIcon { Icon = TrayIconFactory.Create(StatusColor.Gray), Text = "LDW Host Agent — Unknown", ContextMenuStrip = menu, Visible = true };
        _trayIcon.DoubleClick += (_, _) => ShowStatus();
        _timer = new System.Windows.Forms.Timer { Interval = 15_000 };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (!await _refreshGate.WaitAsync(0)) return;
        try
        {
            _lastSnapshot = await _provider.ObserveAsync(CancellationToken.None);
            var state = StatusPresentation.For(_lastSnapshot.Snapshot.Color);
            _summaryItem.Text = $"{state.Word}: {_lastSnapshot.Snapshot.Summary}";
            _trayIcon.Text = LimitTrayText($"LDW Host Agent — {state.Word}");
            ReplaceTrayIcon(_lastSnapshot.Snapshot.Color);
            _statusForm?.UpdateSnapshot(_lastSnapshot);
        }
        catch
        {
            ClearSnapshotAfterObservationFailure(ref _lastSnapshot);
            _summaryItem.Text = "Status unavailable";
            _trayIcon.Text = "LDW Host Agent — Unknown";
            ReplaceTrayIcon(StatusColor.Gray);
            _statusForm?.ShowError("Status refresh failed.");
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    internal static void ClearSnapshotAfterObservationFailure(ref HostAgentLiveSnapshot? snapshot) => snapshot = null;

    private void ShowStatus()
    {
        _statusForm ??= new StatusForm(() => _ = RefreshAsync(), CopyDiagnostics);
        _statusForm.FormClosed += (_, _) => _statusForm = null;
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
        var ci = _lastSnapshot.CiJitStatus;
        builder.AppendLine($"ci-jit: state={ci.State}; queue={ci.QueueState}; eligible={(ci.EligibleQueuedCount?.ToString() ?? "unknown")}; held={(ci.HeldQueuedCount?.ToString() ?? "unknown")}; capacity={ci.Capacity}; phase={(ci.ControllerPhase?.ToString() ?? "none")}; profile={(ci.SelectedProfile ?? "none")}; run={(ci.SelectedRunId?.ToString() ?? "none")}; job={(ci.SelectedJobId?.ToString() ?? "none")}; reason={(ci.ReasonCode ?? "none")}");
        foreach (var observation in _lastSnapshot.Snapshot.Components)
            builder.AppendLine($"{observation.ComponentId}: {observation.Color} / {observation.State} / {observation.Health} — {observation.Summary}");
        if (_lastSnapshot.LinuxTelemetry is { } linux)
            builder.AppendLine($"linux: kernel={linux.Kernel}; uptimeHours={linux.Uptime.TotalHours:F1}; load1={linux.Load1:F2}; memoryAvailableBytes={linux.MemoryAvailableBytes}; swapUsedBytes={linux.SwapUsedBytes}; cpuPsiKnown={linux.CpuPsiSomeAverage10.HasValue}; memoryPsiKnown={linux.MemoryPsiSomeAverage10.HasValue}; updates={(linux.UpdatesAvailable.HasValue ? linux.UpdatesAvailable.Value.ToString() : "unknown")}; rebootRequired={linux.RebootRequired}");
        if (_lastSnapshot.GitHubRunnerTelemetry is { } runner)
            builder.AppendLine($"github-runner: idPresent={runner.Id > 0}; online={runner.Online}; busy={runner.Busy}; labelCount={runner.Labels.Count}");
        builder.AppendLine("Machine-local addresses, SSH targets/paths, credentials, GitHub auth, raw controller state, and raw adapter output are intentionally omitted.");
        Clipboard.SetText(builder.ToString());
    }

    private void ReplaceTrayIcon(StatusColor color)
    {
        var previous = _trayIcon.Icon;
        _trayIcon.Icon = TrayIconFactory.Create(color);
        previous?.Dispose();
    }

    private static string LimitTrayText(string text) => text.Length <= 63 ? text : text[..63];

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
