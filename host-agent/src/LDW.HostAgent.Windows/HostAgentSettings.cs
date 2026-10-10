using System.Text.Json;

namespace LDW.HostAgent.Windows;

internal sealed record HostAgentSettings
{
    public string? DeviceDisplayName { get; init; }
    public DesktopCommanderSettings DesktopCommander { get; init; } = new();
    public WslSettings Wsl { get; init; } = new();
    public LinuxNodeSettings? LinuxNode { get; init; }
    public GitHubRunnerSettings? GitHubRunner { get; init; }
}

internal sealed record DesktopCommanderSettings
{
    public string? ScheduledTaskName { get; init; }
}

internal sealed record WslSettings
{
    public string DistroName { get; init; } = "Ubuntu";
    public string? CursorWorkerService { get; init; }
}

internal sealed record LinuxNodeSettings
{
    public string DisplayName { get; init; } = "Linux CI node";
    public string? Host { get; init; }
    public int? Port { get; init; }
    public string? User { get; init; }
    public string? IdentityFile { get; init; }
    public string? KnownHostsFile { get; init; }
    public string? HostKeyAlias { get; init; }
    public string? RunnerService { get; init; }
}

internal sealed record GitHubRunnerSettings
{
    public string DisplayName { get; init; } = "GitHub Runner";
    public string? Repository { get; init; }
    public long RunnerId { get; init; }
}

internal sealed record HostAgentSettingsLoadResult(HostAgentSettings Settings, bool Found, bool Valid, string Summary);

internal static class HostAgentSettingsLoader
{
    private const string FileName = "host-agent.Local.json";

    public static HostAgentSettingsLoadResult Load()
    {
        var candidates = new List<string>();
        var explicitPath = Environment.GetEnvironmentVariable("LDW_HOST_AGENT_CONFIG");
        if (!string.IsNullOrWhiteSpace(explicitPath))
            candidates.Add(explicitPath);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localAppData))
            candidates.Add(Path.Combine(localAppData, "LowcountryDigitalWorks", "HostAgent", FileName));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, FileName));

        var path = candidates.FirstOrDefault(File.Exists);
        if (path is null)
            return new HostAgentSettingsLoadResult(new HostAgentSettings(), false, true,
                "No machine-local configuration found; configured adapters will report Unknown until local settings are supplied.");

        try
        {
            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<HostAgentSettings>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            }) ?? new HostAgentSettings();
            return new HostAgentSettingsLoadResult(settings, true, true, "Machine-local configuration loaded.");
        }
        catch
        {
            return new HostAgentSettingsLoadResult(new HostAgentSettings(), true, false,
                "Machine-local configuration exists but could not be loaded; private path/details were suppressed.");
        }
    }
}
