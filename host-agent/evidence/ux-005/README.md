# Host Agent UX evidence

These captures use synthetic, sanitized observations rendered by the actual WinForms `StatusForm` and `TrayIconFactory`. They do not query the local machine, start Host Agent, mutate telemetry, or touch deployment/runtime state.

## UX v2 evidence

The current evidence demonstrates the owner-facing v2 presentation:
- a shared LDW/Tidal mark for the tray, title bar, and status-window header;
- a compact overall-state chip and subdued refresh metadata;
- dense left-to-right component rows that keep glyph, component, state, and reason together;
- CI/JIT integrated into `Development & Automation` instead of rendered as a separate card;
- truthful Healthy / Attention / Failed / Unknown states with text + glyph + color;
- native Segoe UI / WinForms controls only;
- keyboard mnemonics for Refresh, Copy diagnostics, and Technical details;
- vertically scrollable owner surface with no intentional horizontal scrolling.

For the one-screen desktop overview follow-up and its synthetic evidence, see [`ux-006`](../ux-006/README.md).

The tray sheet renders every accepted `StatusColor` presentation at 16, 20, 24, and 32 pixels from one stable tidal base mark with non-color-only state overlays.

Regenerate on Windows with:

```powershell
dotnet run --project host-agent/tools/LDW.HostAgent.UxEvidence/LDW.HostAgent.UxEvidence.csproj -c Release -- host-agent/evidence/ux-005
```

Expected files:
- `healthy.png`
- `attention-unknown.png`
- `failed.png`
- `tray-icon-sizes.png`

The evidence tool is also exercised by the hosted Host Agent validation workflow so model/schema drift cannot silently break screenshot generation.
