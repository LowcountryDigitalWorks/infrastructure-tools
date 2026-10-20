# Host Agent UX candidate evidence

These captures use synthetic, sanitized observations rendered by the actual WinForms status form and tray icon factory. They do not query the local machine, start Host Agent, or change telemetry. The tray sheet shows the LDW icon family at 16, 20, 24, and 32 pixels.

Regenerate on Windows with:

```powershell
dotnet run --project host-agent/tools/LDW.HostAgent.UxEvidence/LDW.HostAgent.UxEvidence.csproj -c Release -- host-agent/evidence/ux-005
```

`healthy.png` includes the initial keyboard focus on Refresh. The status form uses DPI auto-scaling, a 520-pixel minimum window width, wrapped rows, and a vertically scrollable content surface.
