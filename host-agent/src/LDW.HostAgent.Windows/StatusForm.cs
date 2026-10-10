using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class StatusForm : Form
{
    private readonly Label _device = new() { AutoSize = true, Font = new Font("Segoe UI", 15, FontStyle.Bold) };
    private readonly Label _memory = new() { AutoSize = true };
    private readonly Label _cpu = new() { AutoSize = true };
    private readonly Label _pressure = new() { AutoSize = true };
    private readonly Label _statusLegend = new()
    {
        AutoSize = true,
        MaximumSize = new Size(520, 0),
        Text = "Status semantics: Green = desired state met; Blue = active CI job; Purple = CI Boost enabled; Yellow = degraded/attention; Red = confirmed failure/down; Gray = unknown/initializing. Status text and reason remain available so color is never the only signal."
    };
    private readonly Label _integrations = new()
    {
        AutoSize = true,
        MaximumSize = new Size(520, 0),
        Text = "Integrations: Tailscale, RustDesk, Desktop Commander Remote, WSL Ubuntu/Cursor Worker, and CI-RUNNER-001/GitHub Runner are represented by read-only probe contracts. Local adapters are configured per device."
    };

    public StatusForm()
    {
        Text = "LDW Host Agent — Status";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(560, 330);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(20), WrapContents = false, AutoScroll = true };
        layout.Controls.AddRange([_device, _memory, _cpu, _pressure, _statusLegend, _integrations]);
        Controls.Add(layout);
    }

    public void UpdateTelemetry(string deviceName, SystemTelemetry telemetry, MemoryPressureLevel level)
    {
        _device.Text = $"{deviceName}  ·  Windows system";
        _memory.Text = $"Memory available: {Format(telemetry.AvailablePhysicalBytes)} of {Format(telemetry.TotalPhysicalBytes)} ({telemetry.AvailablePercent:F1}% available)";
        _cpu.Text = $"CPU busy: {(telemetry.CpuBusyPercent.HasValue ? $"{telemetry.CpuBusyPercent:F1}% over 250 ms" : "unknown")}";
        _pressure.Text = $"Memory pressure: {level}. {telemetry.MemoryPressure.Summary}";
    }

    public void ShowError(string message) => _pressure.Text = $"Status unavailable: {message}";

    private static string Format(ulong bytes) => $"{bytes / 1024d / 1024 / 1024:F2} GiB";
}
