# Normal-user tray autostart

`LDW.HostAgent.Windows` is a per-user, unelevated desktop tray. This lifecycle uses one managed Scheduled Task at `\LowcountryDigitalWorks\HostAgent\Tray` with an `AtLogOn` trigger bound to the explicitly supplied owner SID. The task uses `Interactive` logon and `Limited` run level, starts only the fixed executable under Program Files, and uses `IgnoreNew` so repeated triggers do not create parallel task instances.

The fixed binary path is:

```text
%ProgramFiles%\LowcountryDigitalWorks\HostAgent\Windows\LDW.HostAgent.Windows.exe
```

The SID is supplied at operation time and is never written to the repository. Mutating operations require an elevated installer session running as the same account whose SID is supplied. The scheduled task itself still runs in that account's interactive session at limited privilege. There are no stored credentials, machine-wide autostart shortcuts, service changes, SYSTEM tasks, or tray privilege changes.

## Read-only plan and status

Run from an elevated PowerShell 7 session under the owner account after the approved binary exists at the fixed path:

```powershell
.
Manage-TrayAutostart.ps1 -Action Plan -OwnerSid '<owner SID>'
Manage-TrayAutostart.ps1 -Action Status -OwnerSid '<owner SID>'
```

`Plan` reports the exact task contract and any existing identity drift. `Status` reads the exact task and run state. Neither command mutates the task.

## Managed lifecycle

After source merge and independent review, the bounded operations are:

- `Install`: creates the task once or verifies and re-enables the exact existing task; it refuses to repair or overwrite drifted/ambiguous state.
- `Disable`: stops the exact managed task if running and disables future logon starts.
- `Enable`: re-enables the exact managed task without changing its identity.
- `Uninstall`: stops and removes only the exact managed task; it does not delete the installed application.

Each mutation reads the exact task identity first and verifies readback afterward. Failed installation removes only a task whose full expected identity can still be proven; otherwise it leaves that state untouched and reports that reconciliation is required. Repeated-instance policy is `IgnoreNew`. The source implementation does not install or alter anything on LDW01; installation, ordinary-user logon, reboot, and rollback proofs remain separate post-merge acceptance gates.
