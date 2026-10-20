# Normal-user tray autostart

`LDW.HostAgent.Windows` is a per-user, unelevated desktop tray. It must never run as SYSTEM or at Highest privilege. The program holds one session-local mutex so logon startup and manual starts cannot create duplicate tray processes.

## Select exactly one startup registration

The source-controlled selector uses this order:

1. If the accepted task `\\LowcountryDigitalWorks\\HostAgent\\Tray` already exists, `Manage-TrayAutostart.ps1` validates and manages that exact task. It never creates a new Scheduled Task.
2. If that accepted task is absent, the same entry point delegates to `Manage-TrayAutostartRunKey.ps1`, which manages one value in the current user's `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` key.

The Run-key value name is `LDW.HostAgent.Windows`. Its data is exactly the quoted fixed executable path under Program Files, with no arguments. The script uses the current user's HKCU and does not accept a target SID or another user's hive. Any existing value with a different command, an access error, or an existing accepted task causes a fail-closed result; it does not overwrite or create a duplicate registration.

The protected binary path is:

```text
%ProgramFiles%\\LowcountryDigitalWorks\\HostAgent\\Windows\\LDW.HostAgent.Windows.exe
```

The binary must already be installed at this path. Neither lifecycle script installs the application, starts the current process, or creates a shortcut. A new Run-key registration takes effect on the next user logon.

## Read-only plan and status

Run the accepted-task selector from PowerShell 7 after the approved binary exists at the fixed path:

```powershell
.\\Manage-TrayAutostart.ps1 -Action Plan -OwnerSid '<owner SID>'
.\\Manage-TrayAutostart.ps1 -Action Status -OwnerSid '<owner SID>'
```

The supplied SID must match the current user for any task-backed operation. If the accepted task is absent, the selector uses the current user's Run-key path and the SID is not written to the registry or repository.

`Plan` and `Status` are read-only. The Run-key manager supports the same `Plan`, `Install`, `Status`, `Disable`, `Enable`, and `Uninstall` actions directly when the accepted task is absent. It verifies exact readback after a write and removes only the exact value it owns. Failed writes attempt bounded rollback and leave drifted/ambiguous state untouched.

## Mutation and rollback

For an existing accepted task, mutation operations require an elevated installer session running as the same account whose SID is supplied. The task itself remains `Interactive` / `Limited`; only an identity-matched existing task may be enabled or disabled. Uninstall removes only that task.

For the no-task path, the Run-key registration is scoped to the current user and needs no elevation. `Install` and `Enable` set the exact value; `Disable` and `Uninstall` remove it. They never stop or kill a running process and never delete the application. Repeating an operation is safe. If the Run-key write cannot be verified, rollback removes the value only when its exact expected command is still present.

No deployment or LDW01 state is changed by source validation. Live installation, normal-user logon, reboot, visible status, single-process, and rollback proof remain separate post-review acceptance gates.
