using LDW.HostAgent.Core;
using LDW.HostAgent.Windows;

if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: LDW.HostAgent.UxEvidence <output-directory>");
    return 2;
}

System.Windows.Forms.Application.EnableVisualStyles();
System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
Directory.CreateDirectory(args[0]);
var definitions = new[]
{
    new ComponentDefinition("remote.tailscale", "Tailscale", ComponentKind.Tailscale, DesiredState.Running),
    new ComponentDefinition("remote.rustdesk", "RustDesk", ComponentKind.RustDesk, DesiredState.Running),
    new ComponentDefinition("remote.desktop-commander", "Desktop Commander", ComponentKind.DesktopCommander, DesiredState.RunningAfterLogin),
    new ComponentDefinition("dev.wsl-ubuntu", "Ubuntu (Cursor)", ComponentKind.WslUbuntu, DesiredState.OnDemand, Required: false),
    new ComponentDefinition("dev.cursor-worker", "Cursor Worker", ComponentKind.CursorWorker, DesiredState.RunningAfterLogin),
    new ComponentDefinition("dev.codync-host", "Codync background host", ComponentKind.CodyncHost, DesiredState.RunningAfterLogin, Required: true),
    new ComponentDefinition("dev.linux-ci-node", "CI-RUNNER-001", ComponentKind.LinuxNode, DesiredState.Reachable),
    new ComponentDefinition("dev.github-runner", "GitHub Runner", ComponentKind.GithubRunner, DesiredState.Running),
    new ComponentDefinition("system.memory", "Memory / commit pressure", ComponentKind.Memory, DesiredState.Running),
    new ComponentDefinition("system.disk", "Disk", ComponentKind.Disk, DesiredState.Running),
    new ComponentDefinition("system.cpu", "CPU / pressure state", ComponentKind.Cpu, DesiredState.Running),
};
var environments = new[]
{
    new EnvironmentDefinition("remote-access", "Remote Access", definitions[..3]),
    new EnvironmentDefinition("development-automation", "Development / Automation", definitions[3..8]),
    new EnvironmentDefinition("system", "System", definitions[8..]),
};
var device = new DeviceDefinition("fixture", "LDW01", DevicePlatform.Windows, environments);
var systemTelemetry = new SystemTelemetry(DateTimeOffset.UtcNow, 16UL * 1024 * 1024 * 1024, 8UL * 1024 * 1024 * 1024, 12.5, [], new MemoryPressureTelemetry(50, 0, 0, 0, 0, TimeSpan.Zero, "Normal"));
var ciJitStatus = new CiJitStatusSnapshot(
    DateTimeOffset.UtcNow,
    "fixture-v1",
    CiJitOwnerState.Idle,
    StatusColor.Green,
    null,
    true,
    CiJitQueueState.Fresh,
    0,
    0,
    null,
    null,
    null,
    null,
    CiJitCapacityState.Ready);
var snapshots = new[]
{
    ("healthy", StatusColor.Green, HealthState.Healthy, "All required components are healthy. Optional Ubuntu remains stopped until needed.", StatusColor.Green),
    ("attention-unknown", StatusColor.Yellow, HealthState.Degraded, "Remote access needs attention. SSH and CI/JIT evidence is unknown.", StatusColor.Yellow),
    ("failed", StatusColor.Red, HealthState.Failed, "Cursor Worker is expected after sign-in; Linux and CI/JIT evidence remains unknown.", StatusColor.Red),
};
HostAgentLiveSnapshot? priorHealthySnapshot = null;
foreach (var (file, overallColor, health, summary, exceptionColor) in snapshots)
{
    var observations = definitions.Select((component, index) =>
    {
        var color = file switch
        {
            "healthy" => component.Kind == ComponentKind.GithubRunner ? StatusColor.Blue : StatusColor.Green,
            "attention-unknown" => component.Id == "remote.tailscale" ? StatusColor.Yellow
                : component.Id is "dev.linux-ci-node" or "dev.github-runner" ? StatusColor.Gray : StatusColor.Green,
            _ => component.Id == "dev.cursor-worker" ? StatusColor.Red
                : component.Id is "dev.linux-ci-node" or "dev.github-runner" ? StatusColor.Gray : StatusColor.Green,
        };
        var componentHealth = color switch { StatusColor.Red => HealthState.Failed, StatusColor.Yellow => HealthState.Degraded, StatusColor.Gray => HealthState.Unknown, _ => HealthState.Healthy };
        var state = component.Id == "dev.wsl-ubuntu" && file != "healthy" ? ObservedState.Stopped
            : color == StatusColor.Green ? ObservedState.Running
            : color == StatusColor.Gray ? ObservedState.Unknown
            : color == StatusColor.Red ? ObservedState.Stopped : ObservedState.Unavailable;
        var summary = componentHealth switch
        {
            HealthState.Failed => "Worker remains stopped after the post-login settle window; Host Agent did not start WSL.",
            HealthState.Degraded => "Service is running with a reported issue.",
            HealthState.Unknown when component.Id == "dev.linux-ci-node" => "Strict SSH host-key verification is unavailable; Linux health was not fabricated.",
            HealthState.Unknown => "No trustworthy observation is available.",
            _ when component.Id == "dev.wsl-ubuntu" && state == ObservedState.Stopped => "Configured WSL distro is stopped; it is available on demand.",
            _ => component.Kind == ComponentKind.GithubRunner && color == StatusColor.Blue ? "GitHub Runner is online and busy." : "Ready."
        };
        return new ComponentObservation(component.Id, state, componentHealth, DateTimeOffset.UtcNow, summary, Activity: color == StatusColor.Blue ? ActivityState.ActiveCiJob : ActivityState.None);
    }).ToArray();
    var snapshot = new DeviceSnapshot("fixture", DateTimeOffset.Now, observations, health, overallColor, summary);
    var currentCiJit = file == "healthy" ? ciJitStatus : ciJitStatus with
    {
        State = CiJitOwnerState.Unknown,
        Color = StatusColor.Gray,
        ReasonCode = "LOCAL_STATE_STALE",
        LocalStateFresh = false,
        QueueState = CiJitQueueState.Stale,
        EligibleQueuedCount = null,
        HeldQueuedCount = null,
        Capacity = CiJitCapacityState.Unknown
    };
    var live = new HostAgentLiveSnapshot(device, snapshot, systemTelemetry, new RuntimeContext(OwnerSessionState.Active), new HostAgentSettingsLoadResult(new HostAgentSettings(), false, true, "Synthetic fixture."), null, null, currentCiJit);
    if (file == "healthy") priorHealthySnapshot = live;
    using var form = new StatusForm(() => { }, () => { });
    form.UpdateSnapshot(live);
    form.Show();
    Application.DoEvents();

    var refreshButton = Descendants(form).OfType<Button>().Single(x => x.Text.Contains("Refresh", StringComparison.OrdinalIgnoreCase));
    if (!refreshButton.Focused)
        throw new InvalidOperationException("The owner window must place initial keyboard focus on Refresh.");
    foreach (var button in Descendants(form).OfType<Button>())
    {
        if (string.IsNullOrWhiteSpace(button.AccessibleName))
            throw new InvalidOperationException($"Action button is missing an accessible name: {button.Text}");
    }

    AssertNoVerticalScroll(form, "standard desktop window");

    using var image = new Bitmap(form.Width, form.Height);
    form.DrawToBitmap(image, new Rectangle(Point.Empty, image.Size));
    image.Save(Path.Combine(args[0], $"{file}.png"));

    form.Size = form.MinimumSize;
    Application.DoEvents();
    AssertNoHorizontalScroll(form, "minimum supported size");

    // LDW01 currently renders at 96 DPI, so exercise a deterministic 200% scale pass
    // as a layout smoke rather than claiming the local monitor proves high-DPI behavior.
    form.Scale(new SizeF(2f, 2f));
    form.PerformLayout();
    Application.DoEvents();
    AssertNoHorizontalScroll(form, "simulated 200% scale");

    form.Hide();
}

HostAgentContext.ClearSnapshotAfterObservationFailure(ref priorHealthySnapshot);
if (priorHealthySnapshot is not null)
    throw new InvalidOperationException("A failed observation must not retain a prior healthy snapshot for reopen or diagnostics copy.");

using (var sheet = new Bitmap(680, 112))
using (var graphics = Graphics.FromImage(sheet))
using (var font = new Font("Segoe UI", 9))
{
    graphics.Clear(Color.FromArgb(246, 248, 249));
    var colors = Enum.GetValues<StatusColor>();
    for (var i = 0; i < colors.Length; i++)
    {
        using var icon = TrayIconFactory.Create(colors[i]);
        var x = 8 + i * 110;
        graphics.DrawString(StatusPresentation.For(colors[i]).Word, font, Brushes.Black, x, 8);
        foreach (var size in new[] { 16, 20, 24, 32 })
            graphics.DrawIcon(icon, new Rectangle(x, 28 + (32 - size) / 2, size, size));
    }
    sheet.Save(Path.Combine(args[0], "tray-icon-sizes.png"));
}
Console.WriteLine($"Fixture evidence saved to {Path.GetFullPath(args[0])}");
return 0;

static void AssertNoHorizontalScroll(Control root, string context)
{
    var horizontalScroll = Descendants(root)
        .OfType<ScrollableControl>()
        .FirstOrDefault(x => x.HorizontalScroll.Visible);
    if (horizontalScroll is not null)
        throw new InvalidOperationException($"Horizontal scrolling is not allowed at {context}: {horizontalScroll.GetType().Name}");
}

static void AssertNoVerticalScroll(Control root, string context)
{
    var verticalScroll = Descendants(root)
        .OfType<ScrollableControl>()
        .FirstOrDefault(x => x.VerticalScroll.Visible);
    if (verticalScroll is not null)
        throw new InvalidOperationException($"Vertical scrolling is not allowed at {context}: {verticalScroll.GetType().Name}");
}

static IEnumerable<Control> Descendants(Control root)
{
    foreach (Control child in root.Controls)
    {
        yield return child;
        foreach (var descendant in Descendants(child))
            yield return descendant;
    }
}
