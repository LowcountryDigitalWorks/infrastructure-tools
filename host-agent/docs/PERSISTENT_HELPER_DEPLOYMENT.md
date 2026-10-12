# Persistent Hyper-V observer deployment

Status: repository-side candidate for `LowcountryDigitalWorks/infrastructure-tools#6`, under the accepted `LowcountryDigitalWorks/business-operations#554` Host Agent boundary.

## Purpose

This candidate turns the already-accepted read-only `LDW.HostAgent.HyperVObserver` helper into a deterministic startup deployment without elevating the normal Host Agent tray.

It does **not** authorize installation on LDW01 by itself. Persistent deployment remains a separate post-review gate.

## Security and authority boundary

The deployment preserves the existing helper contract:

- Host Agent tray and LiveProbe remain normal-user processes;
- only the narrow Hyper-V observer runs as `LocalSystem`;
- helper transport remains the existing local named pipe with explicit caller authorization and independent server-token validation;
- Hyper-V scope remains the fixed read-only `CI-RUNNER-001` observation path already accepted in PR #5;
- no VM, service, runner, CI, network, power, group-membership, App Control, UAC, Defender, or firewall mutation is added;
- no TCP/HTTP listener is added;
- no dynamic guest address is persisted;
- no SSH identity, known-hosts file, private trust material, secret, customer data, or machine-private identifier is copied into the install area or committed;
- incremental runtime cost remains `$0`.

If App Control blocks the reviewed helper, stop and adjudicate that policy separately. Do not weaken App Control, execution policy, Defender, UAC, or group membership to make this deployment pass.

## Deterministic identity

The managed Scheduled Task has one accepted identity:

- path: `\LowcountryDigitalWorks\HostAgent\`
- name: `HyperVObserver`
- principal: `SYSTEM`, service-account logon, highest run level;
- trigger: system startup;
- action: the exact content-addressed staged observer executable;
- argument: explicit machine-local `--config` path;
- hidden task;
- start-when-available;
- three restart attempts at one-minute intervals;
- unlimited execution time for the long-running observer;
- duplicate starts ignored.

Status, disable, enable, uninstall, and install-idempotence paths validate the full managed identity before mutating the task. Drift fails closed rather than replacing or unregistering a same-named task.

## Protected machine-local layout

Executable content:

`%ProgramFiles%\LowcountryDigitalWorks\HostAgent\HyperVObserver\releases\<release-id>`

Helper-only machine configuration/state:

`%ProgramData%\LowcountryDigitalWorks\HostAgent\HyperVObserver`

These roots use protected ACLs limited to `LocalSystem` and local Administrators. The intended owner's explicit SID is accepted only at install/plan time and written only to the protected machine-local helper config. Lifecycle/status output does not echo that SID.

The deployment does not touch the already-normalized owner-local SSH identity or known-hosts state.

## Release identity and staging boundary

`Publish-HyperVObserver.ps1` publishes the accepted project as a framework-dependent `win-x64` Release build with debug symbols disabled. The deployment accepts exactly five root-level publish payload files:

- `LDW.HostAgent.Core.dll`
- `LDW.HostAgent.HyperVObserver.deps.json`
- `LDW.HostAgent.HyperVObserver.dll`
- `LDW.HostAgent.HyperVObserver.exe`
- `LDW.HostAgent.HyperVObserver.runtimeconfig.json`

Subdirectories, reparse-point files, and any extra file fail closed. This deliberately prevents an unrelated key, known-hosts file, trust artifact, log, or other staging content from being copied merely because it was adjacent to the helper.

Each payload file is SHA-256 hashed. A deterministic fingerprint over the sorted filename/hash set defines the release identity; the first 16 hexadecimal characters are used as the release directory name. Therefore a changed dependency DLL changes the release identity even if the native apphost EXE bytes do not.

`deployment-manifest.json` records the non-secret release fingerprint and exact bounded file inventory, and is verified before and after protected staging.

## Repository-side lifecycle

All scripts live in `host-agent/deploy`.

Safe before the LDW01 deployment gate:

```powershell
pwsh ./host-agent/deploy/Publish-HyperVObserver.ps1 -OutputDirectory <fresh-local-staging-directory>
pwsh ./host-agent/deploy/Plan-HyperVObserverDeployment.ps1 -PublishedDirectory <fresh-local-staging-directory> -PermittedCallerSid <exact-owner-sid>
```

`Plan-HyperVObserverDeployment.ps1` is non-mutating. Do not paste or commit a real owner SID into GitHub, chat, logs, or test fixtures.

The following are host mutations and therefore must **not** be run on LDW01 until the exact candidate has passed independent review and the deployment gate is accepted:

```powershell
pwsh ./host-agent/deploy/Install-HyperVObserver.ps1 ...
pwsh ./host-agent/deploy/Get-HyperVObserverStatus.ps1
pwsh ./host-agent/deploy/Disable-HyperVObserver.ps1
pwsh ./host-agent/deploy/Enable-HyperVObserver.ps1
pwsh ./host-agent/deploy/Uninstall-HyperVObserver.ps1
```

The mutating lifecycle requires an elevated session. Normal Host Agent tray use remains unelevated.

## Install behavior

Install is fail-closed and idempotent for the same exact managed deployment:

1. validate the explicit caller SID without printing it;
2. validate the exact bounded publish manifest;
3. refuse a pre-existing managed task or helper root that lacks valid deployment state;
4. stage only manifest-listed files under a protected temporary release directory;
5. verify hashes/fingerprint after staging;
6. atomically promote the content-addressed release directory;
7. write protected helper config and deployment state;
8. register the exact startup task;
9. read back and validate full task identity before starting it;
10. start and require the task to remain `Running`;
11. revalidate the complete managed context.

Re-running install with the same release and same authorized caller validates the existing deployment and returns it rather than replacing the task or files. A different release/caller requires explicit reviewed rollback first.

If installation fails after task registration, automatic cleanup unregisters the task only after proving that it still has the exact expected identity. If ownership cannot be proven, cleanup fails closed and leaves evidence for reconciliation instead of unregistering an ambiguous task.

## Readback and drift handling

`Get-HyperVObserverStatus.ps1` validates:

- deployment-state identity;
- content-addressed installed manifest and file hashes;
- helper config schema without disclosing its SID;
- protected ACLs on roots/config/state/release files;
- full Scheduled Task identity and lifecycle settings.

A partial, missing, or drifted managed deployment throws rather than reporting healthy state.

## Disable / enable

Disable and enable first validate the complete deployment and task identity. Only then may they stop/disable or enable/start the one exact managed task. They re-read task identity after mutation.

No other task, service, VM, runner, or host control is in scope.

## Rollback

`Uninstall-HyperVObserver.ps1` is the bounded rollback path.

It is idempotent when the deployment is already cleanly absent. Otherwise it requires valid deployment state, installed release integrity, protected ACLs, helper config validity, and exact Scheduled Task identity **before** task mutation. It then:

1. stops the exact managed task if running;
2. unregisters that exact task;
3. proves the task is gone;
4. removes only the helper-specific ProgramData root;
5. removes only the helper-specific Program Files root.

It never touches normalized SSH trust, Hyper-V guest state, runner state, App Control, groups, UAC, or other Host Agent configuration.

If artifacts remain but ownership/identity cannot be proven, rollback fails closed for explicit reconciliation rather than deleting or unregistering guessed resources.

## Repository validation

`host-agent/deploy/tests/Test-DeploymentContracts.ps1` provides deterministic no-install tests for:

- deterministic namespaced task identity;
- Program Files / helper-specific ProgramData placement;
- protected ACL construction;
- exact bounded publish inventory;
- content-addressed release identity across dependency changes;
- rejection of unexpected trust-like files and nested content;
- task action/principal/hidden/restart drift detection;
- proof that disable/enable/uninstall validate managed identity before task mutation;
- absence of forbidden VM/App Control/group/firewall/trust/listener primitives in deployment PowerShell.

The repository workflow also performs PowerShell parse validation, Release build, existing Host Agent core tests, existing Hyper-V observer tests, a real publish plus non-mutating plan using a synthetic SID, and `git diff --check`.

## Separate LDW01 post-review proof

Only after exact-head independent review and accepted deployment authority:

1. install from accepted `main` only;
2. verify helper startup as LocalSystem without owner logon/UAC;
3. keep tray/LiveProbe unelevated;
4. prove pipe caller authorization and server identity validation;
5. prove current CI-RUNNER-001 observation and strict SSH/Linux telemetry through the persistent helper;
6. reboot through the separately accepted host-maintenance path and prove automatic helper return before/independent of tray logon;
7. prove rollback removes only the managed task/helper roots and leaves normalized SSH trust untouched;
8. verify App Control and other security controls remain unchanged.

Repository acceptance is not evidence that those live-host proofs have already occurred.
