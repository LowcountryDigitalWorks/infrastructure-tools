# Host Agent one-screen status overview

These screenshots use synthetic sanitized observations rendered by the actual Windows Forms status surface. They do not inspect a live machine or change services, WSL, SSH trust, CI/JIT state, or startup configuration.

At the standard desktop window size, Remote Access, Development & Automation, and System appear together without vertical scrolling. The narrow-window layout keeps every section and may scroll vertically when the viewport cannot fit the content. Status meaning remains visible as text and a glyph as well as color.

The failed example shows the accepted policy distinction: stopped Ubuntu is healthy because it is optional/on-demand; Cursor Worker is required after sign-in and remains failed after the accepted 120-second settle window. Technical details points to the existing startup task for inspection. It does not start the distro.

The unknown example retains strict SSH host-key verification and stale CI/JIT evidence. Unknown does not become healthy, stale or unavailable queue counts are withheld, fresh queue counts may appear when local owner evidence is stale but are not authorization to run, and no SSH trust or queue mutation is offered.

Regenerate from the repository root on Windows with:

```powershell
dotnet run --project host-agent/tools/LDW.HostAgent.UxEvidence/LDW.HostAgent.UxEvidence.csproj -c Release -- host-agent/evidence/ux-006
```
