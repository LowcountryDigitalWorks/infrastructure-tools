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
    new ComponentDefinition("tailscale", "Tailscale", ComponentKind.Tailscale, DesiredState.Running),
    new ComponentDefinition("rustdesk", "RustDesk", ComponentKind.RustDesk, DesiredState.Running),
    new ComponentDefinition("desktop-commander", "Desktop Commander", ComponentKind.DesktopCommander, DesiredState.RunningAfterLogin),
    new ComponentDefinition("wsl", "Ubuntu (Cursor)", ComponentKind.WslUbuntu, DesiredState.OnDemand, Required: false),
    new ComponentDefinition("cursor-worker", "Cursor Worker", ComponentKind.CursorWorker, DesiredState.RunningAfterLogin),
    new ComponentDefinition("linux-node", "Linux CI node", ComponentKind.LinuxNode, DesiredState.Reachable),
    new ComponentDefinition("github-runner", "GitHub Runner", ComponentKind.GithubRunner, DesiredState.Running),
    new ComponentDefinition("memory", "Memory / commit pressure", ComponentKind.Memory, DesiredState.Running),
    new ComponentDefinition("disk", "Disk", ComponentKind.Disk, DesiredState.Running),
    new ComponentDefinition("cpu", "CPU / pressure state", ComponentKind.Cpu, DesiredState.Running),
};
var environments = new[]
{
    new EnvironmentDefinition("remote-access", "Remote Access", definitions[..3]),
    new EnvironmentDefinition("development-automation", "Development / Automation", definitions[3..7]),
    new EnvironmentDefinition("system", "System", definitions[7..]),
};
var device = new DeviceDefinition("fixture", "LDW01", DevicePlatform.Windows, environments);
var systemTelemetry = new SystemTelemetry(DateTimeOffset.UtcNow, 16UL * 1024 * 1024 * 1024, 8UL * 1024 * 1024 * 1024, 12.5, [], new MemoryPressureTelemetry(50, 0, 0, 0, 0, TimeSpan.Zero, "Normal"));
var snapshots = new[]
{
    ("healthy", StatusColor.Green, HealthState.Healthy, "Your system is ready to use.", StatusColor.Green),
    ("attention-unknown", StatusColor.Yellow, HealthState.Degraded, "Remote access needs attention. Linux node status is unknown.", StatusColor.Yellow),
    ("failed", StatusColor.Red, HealthState.Failed, "A required component has failed.", StatusColor.Red),
};
HostAgentLiveSnapshot? priorHealthySnapshot = null;
foreach (var (file, overallColor, health, summary, exceptionColor) in snapshots)
{
    var observations = definitions.Select((component, index) =>
    {
        var color = file switch
        {
            "healthy" => component.Kind == ComponentKind.GithubRunner ? StatusColor.Blue : StatusColor.Green,
            "attention-unknown" => index == 0 ? StatusColor.Yellow : index == 5 ? StatusColor.Gray : StatusColor.Green,
            _ => index == 0 ? StatusColor.Red : index == 5 ? StatusColor.Gray : StatusColor.Green,
        };
        var componentHealth = color switch { StatusColor.Red => HealthState.Failed, StatusColor.Yellow => HealthState.Degraded, StatusColor.Gray => HealthState.Unknown, _ => HealthState.Healthy };
        return new ComponentObservation(component.Id, color == StatusColor.Green ? ObservedState.Running : color == StatusColor.Gray ? ObservedState.Unknown : ObservedState.Unavailable, componentHealth, DateTimeOffset.UtcNow, componentHealth switch { HealthState.Failed => "Required service is unavailable.", HealthState.Degraded => "Service is running with a reported issue.", HealthState.Unknown => "No trustworthy observation is available.", _ => component.Kind == ComponentKind.WslUbuntu ? "Available on demand." : "Ready." }, Activity: color == StatusColor.Blue ? ActivityState.ActiveCiJob : ActivityState.None);
    }).ToArray();
    var snapshot = new DeviceSnapshot("fixture", DateTimeOffset.Now, observations, health, overallColor, summary);
    var live = new HostAgentLiveSnapshot(device, snapshot, systemTelemetry, new RuntimeContext(OwnerSessionState.Active), new HostAgentSettingsLoadResult(new HostAgentSettings(), false, true, "Synthetic fixture."), null, null);
    if (file == "healthy") priorHealthySnapshot = live;
    using var form = new StatusForm(() => { }, () => { });
    form.UpdateSnapshot(live);
    form.Show();
    Application.DoEvents();
    using var image = new Bitmap(form.Width, form.Height);
    form.DrawToBitmap(image, new Rectangle(Point.Empty, image.Size));
    image.Save(Path.Combine(args[0], $"{file}.png"));
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
