using System.Text;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class StatusForm : Form
{
    private static readonly Color EstuaryNavy = Color.FromArgb(16, 42, 58);
    private static readonly Color CypressTeal = Color.FromArgb(47, 118, 111);
    private static readonly Color WarmOyster = Color.FromArgb(243, 239, 230);
    private static readonly Color SoftWhite = Color.FromArgb(247, 248, 246);
    private static readonly Color Border = Color.FromArgb(218, 224, 226);
    private static readonly Color BodyText = Color.FromArgb(37, 54, 67);
    private static readonly Color MutedText = Color.FromArgb(91, 105, 116);

    private readonly Action _refresh;
    private readonly Action _copyDiagnostics;
    private readonly TableLayoutPanel _dashboard = new()
    {
        Dock = DockStyle.Top,
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        ColumnCount = 2,
        RowCount = 0,
        Margin = Padding.Empty,
        Padding = Padding.Empty
    };
    private readonly Panel _scrollHost = new()
    {
        Dock = DockStyle.Fill,
        AutoScroll = true,
        BackColor = SoftWhite,
        Padding = new Padding(16, 10, 16, 12),
        Margin = Padding.Empty
    };
    private readonly PictureBox _brand = new()
    {
        Size = new Size(44, 44),
        SizeMode = PictureBoxSizeMode.Zoom,
        Margin = new Padding(0, 0, 12, 0),
        TabStop = false,
        AccessibleName = "LDW Host Agent mark"
    };
    private readonly Label _title = new()
    {
        AutoSize = true,
        Font = new Font("Segoe UI", 17, FontStyle.Bold),
        ForeColor = EstuaryNavy,
        Text = "LDW Host Agent"
    };
    private readonly Label _machine = new()
    {
        AutoSize = true,
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
        ForeColor = MutedText,
        Padding = new Padding(0, 1, 0, 0)
    };
    private readonly Label _overallChip = new()
    {
        AutoSize = false,
        Size = new Size(132, 34),
        TextAlign = ContentAlignment.MiddleCenter,
        Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
        BorderStyle = BorderStyle.FixedSingle,
        Margin = new Padding(12, 2, 0, 0),
        AccessibleName = "Overall Host Agent state"
    };
    private readonly Label _summary = new()
    {
        AutoSize = true,
        Dock = DockStyle.Fill,
        MaximumSize = new Size(760, 0),
        ForeColor = BodyText,
        Font = new Font("Segoe UI", 10f, FontStyle.Regular),
        Padding = new Padding(0, 7, 0, 0)
    };
    private readonly Label _refreshed = new()
    {
        AutoSize = true,
        ForeColor = MutedText,
        Font = new Font("Segoe UI", 8.75f),
        TextAlign = ContentAlignment.MiddleLeft,
        Anchor = AnchorStyles.Left
    };
    private readonly Button _refreshButton;
    private readonly Button _copyButton;
    private readonly Button _detailsButton;
    private readonly Bitmap _brandImage;
    private Icon? _windowIcon;
    private HostAgentLiveSnapshot? _live;
    private Control? _remoteSection;
    private Control? _developmentSection;
    private Control? _systemSection;
    private Control? _placeholderSection;

    public StatusForm(Action refresh, Action copyDiagnostics)
    {
        _refresh = refresh;
        _copyDiagnostics = copyDiagnostics;

        Text = "LDW Host Agent";
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = GetInitialClientSize();
        MinimumSize = new Size(620, 500);
        BackColor = SoftWhite;
        Font = new Font("Segoe UI", 9.25f);
        KeyPreview = true;

        _brandImage = TrayIconFactory.CreateBrandBitmap(44);
        _brand.Image = _brandImage;
        SetWindowIcon(StatusColor.Gray);

        _refreshButton = CreateActionButton("&Refresh", primary: true);
        _refreshButton.AccessibleName = "Refresh Host Agent status";
        _copyButton = CreateActionButton("&Copy diagnostics");
        _copyButton.AccessibleName = "Copy sanitized Host Agent diagnostics";
        _detailsButton = CreateActionButton("&Technical details");
        _detailsButton.AccessibleName = "Show technical Host Agent details";

        _refreshButton.Click += (_, _) => _refresh();
        _copyButton.Click += (_, _) => _copyDiagnostics();
        _detailsButton.Click += (_, _) => ShowDetails();

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
            BackColor = SoftWhite
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.Controls.Add(CreateHeader(), 0, 0);

        _scrollHost.Controls.Add(_dashboard);
        root.Controls.Add(_scrollHost, 0, 1);
        Controls.Add(root);
        _scrollHost.Resize += (_, _) => ArrangeDashboard();

        AcceptButton = _refreshButton;
        Shown += (_, _) => _refreshButton.Focus();
        KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Escape) return;
            Close();
            e.Handled = true;
        };
        FormClosed += (_, _) =>
        {
            _brandImage.Dispose();
            _windowIcon?.Dispose();
        };

        UpdateSnapshot(null);
    }

    public void UpdateSnapshot(HostAgentLiveSnapshot? live)
    {
        _live = live;
        _dashboard.SuspendLayout();
        _dashboard.Controls.Clear();
        _dashboard.RowStyles.Clear();
        _dashboard.ColumnStyles.Clear();
        _dashboard.RowCount = 0;
        _remoteSection = null;
        _developmentSection = null;
        _systemSection = null;
        _placeholderSection = null;

        if (live is null)
        {
            _machine.Text = "Waiting for first observation";
            SetOverall(StatusColor.Gray, "Collecting the first trustworthy status sample.");
            _refreshed.Text = "Updated: waiting";
            _placeholderSection = CreateNoticeCard("Collecting status", "The status overview will populate as soon as a trustworthy observation is available.");
            ArrangeDashboard();
            _dashboard.ResumeLayout();
            return;
        }

        _machine.Text = live.Definition.Name;
        SetOverall(live.Snapshot.Color, live.Snapshot.Summary);
        _refreshed.Text = $"Updated {live.Snapshot.ObservedAt.ToLocalTime():g}";

        var observations = live.Snapshot.Components.ToDictionary(x => x.ComponentId, StringComparer.OrdinalIgnoreCase);
        Control? remote = null;
        Control? development = null;
        Control? system = null;
        foreach (var environment in live.Definition.Environments)
        {
            var rows = new List<Control>();
            foreach (var component in environment.Components)
            {
                observations.TryGetValue(component.Id, out var observation);
                rows.Add(CreateComponentRow(component, observation));
            }

            if (environment.Id == "development-automation")
                rows.Add(CreateCiJitRow(live.CiJitStatus));

            var title = environment.Id == "development-automation"
                ? "Development & Automation"
                : environment.Name;
            var section = CreateSectionCard(title, rows);
            switch (environment.Id)
            {
                case "remote-access": remote = section; break;
                case "development-automation": development = section; break;
                case "system": system = section; break;
            }
        }

        _remoteSection = remote ?? CreateNoticeCard("Remote Access", "No status is available.");
        _developmentSection = development ?? CreateNoticeCard("Development & Automation", "No status is available.");
        _systemSection = system ?? CreateNoticeCard("System", "No status is available.");
        ArrangeDashboard();
        _dashboard.ResumeLayout();
    }

    public void ShowError(string message)
    {
        _live = StatusPresentation.SampleForDisplay(_live, observationSucceeded: false);
        _dashboard.SuspendLayout();
        _dashboard.Controls.Clear();
        _dashboard.RowStyles.Clear();
        _dashboard.ColumnStyles.Clear();
        _dashboard.RowCount = 0;
        _machine.Text = "Status unavailable";
        SetOverall(StatusColor.Gray, string.IsNullOrWhiteSpace(message)
            ? "Status is unavailable."
            : "Status refresh failed; sensitive details are suppressed.");
        _refreshed.Text = "Updated: unavailable";
        _remoteSection = null;
        _developmentSection = null;
        _systemSection = null;
        _placeholderSection = CreateNoticeCard("Status unavailable", "The last observation was not trustworthy, so prior health is not being displayed as current.");
        ArrangeDashboard();
        _dashboard.ResumeLayout();
    }

    private Control CreateHeader()
    {
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 3,
            RowCount = 3,
            BackColor = Color.White,
            Padding = new Padding(20, 17, 20, 15),
            Margin = Padding.Empty
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 56));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        header.Controls.Add(_brand, 0, 0);
        header.SetRowSpan(_brand, 2);

        var identity = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
            Dock = DockStyle.Fill
        };
        identity.Controls.Add(_title);
        identity.Controls.Add(_machine);
        header.Controls.Add(identity, 1, 0);
        header.Controls.Add(_overallChip, 2, 0);

        header.Controls.Add(_summary, 1, 1);
        header.SetColumnSpan(_summary, 2);

        var metaActions = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            RowCount = 1,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 11, 0, 0),
            Padding = Padding.Empty
        };
        metaActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        metaActions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        metaActions.Controls.Add(_refreshed, 0, 0);

        var actions = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
            Anchor = AnchorStyles.Right
        };
        actions.Controls.Add(_refreshButton);
        actions.Controls.Add(_copyButton);
        actions.Controls.Add(_detailsButton);
        metaActions.Controls.Add(actions, 1, 0);

        header.Controls.Add(metaActions, 1, 2);
        header.SetColumnSpan(metaActions, 2);
        return header;
    }

    private void ArrangeDashboard()
    {
        _dashboard.SuspendLayout();
        _dashboard.Controls.Clear();
        _dashboard.RowStyles.Clear();
        _dashboard.ColumnStyles.Clear();
        if (_placeholderSection is not null)
        {
            _dashboard.ColumnCount = 1;
            _dashboard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            _dashboard.Controls.Add(_placeholderSection, 0, 0);
            _dashboard.ResumeLayout();
            return;
        }

        var wide = _scrollHost.ClientSize.Width >= 820;
        _dashboard.ColumnCount = wide ? 2 : 1;
        _dashboard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, wide ? 50 : 100));
        if (wide) _dashboard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        if (wide)
        {
            _dashboard.RowCount = 2;
            _dashboard.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _dashboard.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            if (_remoteSection is not null) _dashboard.Controls.Add(_remoteSection, 0, 0);
            if (_systemSection is not null) _dashboard.Controls.Add(_systemSection, 0, 1);
            if (_developmentSection is not null)
            {
                _dashboard.Controls.Add(_developmentSection, 1, 0);
                _dashboard.SetRowSpan(_developmentSection, 2);
            }
        }
        else
        {
            _dashboard.RowCount = 3;
            _dashboard.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _dashboard.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _dashboard.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            if (_remoteSection is not null) _dashboard.Controls.Add(_remoteSection, 0, 0);
            if (_developmentSection is not null) _dashboard.Controls.Add(_developmentSection, 0, 1);
            if (_systemSection is not null) _dashboard.Controls.Add(_systemSection, 0, 2);
            if (_developmentSection is not null) _dashboard.SetRowSpan(_developmentSection, 1);
        }
        _dashboard.ResumeLayout();
    }

    private static Size GetInitialClientSize()
    {
        var workArea = Screen.PrimaryScreen?.WorkingArea;
        return workArea is null
            ? new Size(1260, 840)
            : new Size(Math.Min(1260, Math.Max(620, workArea.Value.Width - 48)),
                Math.Min(840, Math.Max(500, workArea.Value.Height - 80)));
    }

    private static Control CreateSectionCard(string title, IReadOnlyList<Control> rows)
    {
        var card = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            RowCount = 0,
            Dock = DockStyle.Top,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Margin = new Padding(0, 0, 0, 12),
            Padding = Padding.Empty,
            AccessibleName = $"{title} status group"
        };
        card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var heading = new Label
        {
            Text = title,
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 31,
            Padding = new Padding(11, 6, 10, 0),
            Font = new Font("Segoe UI", 9.75f, FontStyle.Bold),
            ForeColor = EstuaryNavy,
            BackColor = SoftWhite,
            UseMnemonic = false
        };
        AddCardControl(card, heading);

        for (var i = 0; i < rows.Count; i++)
        {
            AddCardControl(card, rows[i]);
            if (i < rows.Count - 1)
                AddCardControl(card, new Panel { Height = 1, Dock = DockStyle.Top, BackColor = Border, Margin = new Padding(12, 0, 12, 0) });
        }

        return card;
    }

    private static Control CreateComponentRow(ComponentDefinition component, ComponentObservation? observation)
    {
        var color = observation?.Color ?? StatusColor.Gray;
        var state = StatusPresentation.For(color);
        var summary = observation?.Summary ?? "No trustworthy observation is available yet.";
        return CreateStatusRow(state.Glyph, state.Word, color, component.Name, summary, $"{component.Name}: {state.Word}");
    }

    private static Control CreateCiJitRow(CiJitStatusSnapshot status)
    {
        var presentation = StatusPresentation.For(status.Color);
        var stateWord = status.State.ToString();
        var reason = string.IsNullOrWhiteSpace(status.ReasonCode)
            ? null
            : status.ReasonCode.Replace('_', ' ').ToLowerInvariant();
        var summary = reason is null ? status.QueueSummary : $"{status.QueueSummary} · {reason}";
        return CreateStatusRow(presentation.Glyph, stateWord, status.Color, "CI / JIT", summary, $"CI JIT: {stateWord}");
    }

    private static Control CreateStatusRow(string glyph, string stateWord, StatusColor color, string name, string summary, string accessibleName)
    {
        var row = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 4,
            RowCount = 1,
            Dock = DockStyle.Top,
            Margin = Padding.Empty,
            Padding = new Padding(8, 4, 8, 4),
            AccessibleName = accessibleName
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 34));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 108));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var glyphLabel = new Label
        {
            Text = glyph,
            AutoSize = false,
            Size = new Size(24, 24),
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI Symbol", 9.5f, FontStyle.Bold),
            ForeColor = ColorFor(color),
            BackColor = TintFor(color),
            BorderStyle = BorderStyle.FixedSingle,
            Margin = new Padding(0, 0, 8, 0),
            AccessibleName = $"State symbol: {stateWord}"
        };
        var nameLabel = new Label
        {
            Text = name,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = BodyText,
            Margin = new Padding(0, 3, 10, 0)
        };
        var stateLabel = new Label
        {
            Text = stateWord,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Font = new Font("Segoe UI", 9.25f, FontStyle.Bold),
            ForeColor = ColorFor(color),
            Margin = new Padding(0, 3, 10, 0),
            AccessibleName = $"State: {stateWord}"
        };
        var summaryLabel = new Label
        {
            Text = summary,
            AutoSize = true,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9f),
            ForeColor = MutedText,
            Margin = new Padding(0, 3, 0, 0),
            MaximumSize = new Size(420, 0)
        };

        row.Controls.Add(glyphLabel, 0, 0);
        row.Controls.Add(nameLabel, 1, 0);
        row.Controls.Add(stateLabel, 2, 0);
        row.Controls.Add(summaryLabel, 3, 0);
        return row;
    }

    private static Control CreateNoticeCard(string title, string message)
    {
        var card = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            RowCount = 2,
            Dock = DockStyle.Top,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Margin = new Padding(0, 0, 0, 12),
            Padding = new Padding(14)
        };
        card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        card.Controls.Add(new Label { AutoSize = true, Text = title, Font = new Font("Segoe UI", 10.25f, FontStyle.Bold), ForeColor = EstuaryNavy }, 0, 0);
        card.Controls.Add(new Label { AutoSize = true, Text = message, MaximumSize = new Size(720, 0), ForeColor = MutedText, Margin = new Padding(0, 5, 0, 0) }, 0, 1);
        return card;
    }

    private static void AddCardControl(TableLayoutPanel card, Control control)
    {
        var row = card.RowCount++;
        card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        card.Controls.Add(control, 0, row);
    }

    private void SetOverall(StatusColor color, string summary)
    {
        var state = StatusPresentation.For(color);
        _overallChip.Text = $"{state.Glyph}  {state.Word}";
        _overallChip.ForeColor = ColorFor(color);
        _overallChip.BackColor = TintFor(color);
        _summary.Text = summary;
        SetWindowIcon(color);
    }

    private void SetWindowIcon(StatusColor color)
    {
        var previous = _windowIcon;
        _windowIcon = TrayIconFactory.Create(color);
        Icon = _windowIcon;
        previous?.Dispose();
    }

    private void ShowDetails()
    {
        var text = new StringBuilder();
        if (_live is null)
        {
            text.AppendLine("No telemetry sample is available yet.");
        }
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
            text.AppendLine($"System: physical memory {_live.SystemTelemetry.AvailablePercent:F1}% available; CPU sample {_live.SystemTelemetry.CpuBusyPercent?.ToString("F1") ?? "unknown"}%; {_live.SystemTelemetry.Disks.Count} disk(s); memory pressure {_live.SystemTelemetry.MemoryPressure.Summary}.");
            if (_live.GitHubRunnerTelemetry is { } runner)
                text.AppendLine($"Runner: ID present {runner.Id > 0}; online {runner.Online}; busy {runner.Busy}; label count {runner.Labels.Count}.");
            foreach (var observation in _live.Snapshot.Components)
            {
                text.AppendLine($"{observation.ComponentId}: {observation.Color} / {observation.Health} — {observation.Summary}");
                var nextCheck = NextCheckFor(observation.ComponentId, observation.Health);
                if (nextCheck is not null)
                    text.AppendLine($"  Next check: {nextCheck}");
            }
            if (ci.State == CiJitOwnerState.Unknown)
                text.AppendLine("  Next check: Queue counts are withheld while queue/local evidence is stale or unavailable. Re-read the accepted CI/JIT status source before treating any prior count as current; no queue action was attempted.");
        }

        using var dialog = new Form
        {
            Text = "LDW Host Agent — Technical details",
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(720, 500),
            MinimumSize = new Size(520, 360),
            AutoScaleMode = AutoScaleMode.Dpi,
            BackColor = SoftWhite,
            Font = new Font("Segoe UI", 9.25f)
        };
        using var dialogIcon = TrayIconFactory.Create(_live?.Snapshot.Color ?? StatusColor.Gray);
        dialog.Icon = dialogIcon;

        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(16), BackColor = SoftWhite };
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.Controls.Add(new Label
        {
            AutoSize = true,
            Text = "Sanitized technical telemetry",
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            ForeColor = EstuaryNavy,
            Margin = new Padding(0, 0, 0, 9)
        }, 0, 0);

        var details = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            WordWrap = true,
            AccessibleName = "Detailed Host Agent telemetry",
            Text = text.ToString(),
            Font = new Font("Consolas", 9),
            BackColor = Color.White,
            ForeColor = BodyText,
            BorderStyle = BorderStyle.FixedSingle
        };
        shell.Controls.Add(details, 0, 1);

        var copy = CreateActionButton("&Copy diagnostics", primary: true);
        copy.AccessibleName = "Copy sanitized Host Agent diagnostics";
        copy.Margin = new Padding(0, 10, 0, 0);
        copy.Click += (_, _) => _copyDiagnostics();
        shell.Controls.Add(copy, 0, 2);
        dialog.Controls.Add(shell);
        dialog.ShowDialog(this);
    }

    private static Button CreateActionButton(string text, bool primary = false)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            MinimumSize = new Size(0, 34),
            Padding = new Padding(10, 3, 10, 3),
            FlatStyle = FlatStyle.Flat,
            BackColor = primary ? CypressTeal : Color.White,
            ForeColor = primary ? Color.White : EstuaryNavy,
            UseVisualStyleBackColor = false,
            Margin = new Padding(6, 0, 0, 0)
        };
        button.FlatAppearance.BorderColor = primary ? CypressTeal : Border;
        button.FlatAppearance.BorderSize = 1;
        button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(40, 105, 99) : WarmOyster;
        button.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(34, 91, 86) : Color.FromArgb(234, 230, 222);
        return button;
    }

    private static string FormatBytes(ulong bytes) => bytes >= 1024UL * 1024 * 1024
        ? $"{bytes / 1024d / 1024 / 1024:F2} GiB"
        : $"{bytes / 1024d / 1024:F1} MiB";

    private static string FormatNullable(double? value) => value?.ToString("F2") ?? "unknown";

    private static string? NextCheckFor(string componentId, HealthState health)
    {
        if (health is HealthState.Healthy)
            return null;

        return componentId switch
        {
            "dev.cursor-worker" => "After the accepted post-login settle window, inspect the existing LDW Cursor Worker scheduled task and confirm Ubuntu/systemd recovery. Host Agent does not start the WSL distro.",
            "dev.linux-ci-node" when health == HealthState.Unknown => "Verify the existing known-hosts entry or HostKeyAlias against the approved host-key source. Strict SSH verification remains enabled; Host Agent will not accept a new key automatically.",
            _ => null
        };
    }

    private static Color ColorFor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.FromArgb(0, 108, 82),
        StatusColor.Blue => Color.FromArgb(35, 91, 153),
        StatusColor.Purple => Color.FromArgb(110, 64, 139),
        StatusColor.Yellow => Color.FromArgb(137, 86, 0),
        StatusColor.Red => Color.FromArgb(166, 42, 47),
        _ => Color.FromArgb(82, 96, 107),
    };

    private static Color TintFor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.FromArgb(232, 246, 241),
        StatusColor.Blue => Color.FromArgb(232, 240, 249),
        StatusColor.Purple => Color.FromArgb(243, 237, 247),
        StatusColor.Yellow => Color.FromArgb(255, 246, 226),
        StatusColor.Red => Color.FromArgb(253, 237, 238),
        _ => Color.FromArgb(239, 242, 244),
    };
}
