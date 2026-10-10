# Persistent Hyper-V observer deployment

Status: candidate design for `LowcountryDigitalWorks/infrastructure-tools#6` and `LowcountryDigitalWorks/business-operations#554`.

## Goal

Run the already-reviewed read-only `LDW.HostAgent.HyperVObserver` continuously on an owner-controlled Windows Hyper-V host without elevating the Host Agent tray and without requiring a routine UAC prompt at each owner login.

The helper remains a narrow privileged observation process. This deployment design does not add VM controls, runner controls, power controls, a network listener, or a new trust system.

## Chosen runtime model

Use a Windows **Scheduled Task at system startup** running as `LocalSystem` with highest privileges.

This is intentionally preferred over converting the current helper into a Windows Service in this slice because:

- the existing executable already behaves as a long-running named-pipe server;
- the Host Agent client already accepts a LocalSystem server only after independently validating the server process token;
- the server independently validates the connecting owner's explicit SID after the pipe ACL check;
- a startup task provides deterministic pre-login launch and restart-on-failure without adding Service Control Manager lifecycle code;
- rollback is bounded to stopping/unregistering one task plus removing the staged helper/config;
- the normal-user tray remains unelevated.

A future service conversion is justified only if measured Scheduled Task recovery/lifecycle behavior proves inadequate.

## Filesystem placement

The deployment separates executable code, privileged configuration, and SSH trust:

- helper binaries: `%ProgramFiles%\LowcountryDigitalWorks\HostAgent\HyperVObserver\releases\<release-id>`;
- helper caller allowlist: `%ProgramData%\LowcountryDigitalWorks\HostAgent\hyperv-observer.Local.json`;
- normalized SSH identity/known-hosts: remain in the already-accepted owner-local protected trust location and are **not** copied into Program Files or ProgramData by this deployment.

The helper install/config directories are protected against inherited broad access. The deployment scripts grant filesystem access only to LocalSystem and local Administrators. The explicit owner SID exists only inside the helper's machine-local caller-allowlist JSON; it is not committed.

## Release identity

The installer computes SHA-256 over `LDW.HostAgent.HyperVObserver.exe` and uses the first 16 hex characters as the release-directory identifier. It then verifies that the staged executable hash matches the source executable hash before task registration/start.

The release identifier is operational provenance, not a secret. The installer does not use it as a security boundary.

## Scheduled Task contract

Default task name:

`LDW Host Agent Hyper-V Observer`

Required task properties:

- trigger: system startup;
- principal: `SYSTEM` / service-account logon;
- run level: highest;
- action: the staged `LDW.HostAgent.HyperVObserver.exe`;
- argument: explicit `--config` pointing to the machine-local ProgramData allowlist;
- start when available;
- restart on failure, bounded to three retries with one-minute intervals;
- unlimited execution time for the intended long-running process;
- ignore duplicate start attempts;
- hidden/no interactive owner window.

The helper itself still fails closed unless it is elevated and its local configuration contains at least one safe explicit user SID.

## App Control / security-policy boundary

The deployment scripts do **not** modify Windows Defender Application Control, AppLocker, Defender exclusions, SmartScreen, execution policy, local groups, Hyper-V groups, or UAC settings.

If the accepted helper binary is blocked by current policy, deployment stops and returns the policy block for separate adjudication. Do not add a broad path allow rule or weaken a policy merely to make deployment pass.

If signing/allowlisting becomes necessary, prefer a narrowly scoped trusted-publisher/hash/catalog mechanism compatible with the existing policy. Treat that as a separately reviewed security change.

## Install flow

From an elevated PowerShell 7 session on the owner-controlled host:

1. build/test the exact accepted repository candidate;
2. publish the helper to a local staging directory using `deploy/Publish-HyperVObserver.ps1`;
3. obtain the intended owner's exact SID locally without copying it into GitHub/chat;
4. run `deploy/Install-HyperVObserver.ps1` with the staging directory and explicit owner SID;
5. run `deploy/Test-HyperVObserverDeployment.ps1`;
6. from an **unelevated** owner session, run the Host Agent/LiveProbe chain and confirm pipe-server identity, caller authorization, Hyper-V observation, strict SSH, and Linux telemetry.

The installer refuses to silently replace an existing task whose action or principal differs from the desired deployment. Roll back the prior deployment explicitly before replacing it.

## Daily-use acceptance proof

Repository acceptance and local installation are not enough. LDW01 daily-use acceptance requires all of the following:

- helper task running under LocalSystem;
- Host Agent tray/LiveProbe running unelevated;
- pipe caller authorization passes for the intended owner;
- client independently validates the helper server token;
- `CI-RUNNER-001` state/target observation works through the helper;
- dynamic guest address remains transient;
- normalized existing SSH trust remains authoritative and strict;
- kernel, uptime/load, memory, swap, root disk, PSI where available, update/reboot attention, and runner systemd state remain observable;
- no persistent interactive admin shell is required;
- no App Control/group/UAC weakening;
- no VM/runner/service/CI mutation.

## Reboot / recovery proof

Before calling the deployment operationally accepted:

1. confirm the task is registered and running;
2. reboot LDW01 through the separately accepted normal host-maintenance path;
3. before relying on an owner-launched helper, verify the startup task returned automatically;
4. after owner login, verify the normal-user Host Agent can use the already-running helper without a new UAC prompt;
5. verify CI-RUNNER-001/runner observation and strict SSH telemetry again;
6. verify no duplicate helper instances/tasks exist.

A reboot itself is an operational action and must follow the current owner/workstream reboot gate.

## Rollback

`deploy/Uninstall-HyperVObserver.ps1`:

- stops the task if present;
- unregisters the task;
- removes only the helper-specific ProgramData config file;
- removes only the helper-specific Program Files install root;
- does not modify or remove the normalized SSH trust;
- does not modify the guest, runner, Hyper-V VM, App Control, groups, UAC, or Host Agent owner-local configuration.

After rollback, the Host Agent must fail closed to Unknown for helper-dependent CI-RUNNER-001 telemetry rather than weakening SSH or fabricating state.

## Legacy trust-copy LOW

The previously identified unsuitable legacy SSH trust copies remain a separate LOW cleanup item. Persistent-helper deployment does not require deleting them. Remove an obsolete copy only after a conclusive local dependency/reference check confirms that no accepted task/config/script still references it. Do not claim secure erasure.
