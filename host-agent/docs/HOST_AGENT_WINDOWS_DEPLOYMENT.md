# Host Agent Windows package and deployment

The normal-user `LDW.HostAgent.Windows.exe` tray has a deterministic source-controlled package/install/readback path. This path installs only the tray application bytes; it does not create or modify startup registration, start or stop the tray, touch the privileged Hyper-V observer, or change machine-local configuration.

## Package

`deploy/Publish-HostAgentWindowsPackage.ps1` freezes the exact clean Git commit, materializes that commit through `git archive` into a random temporary source root, and publishes `src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj` from that immutable materialization as a Release `win-x64` self-contained single-file executable. Build intermediates therefore stay below the temporary materialization rather than the mutable working tree. The publisher rechecks the original checkout commit/tree/cleanliness after the build and before creating package output.

The requested output parent must already exist and its existing ancestor chain must be free of reparse points. The output contains exactly:

- `LDW.HostAgent.Windows.exe`
- `manifest.json`

The manifest records the exact source commit/tree, runtime, executable SHA-256, and byte length. Machine-local configuration is never packaged. The publisher reports the manifest SHA-256, executable SHA-256, and executable byte length so an acceptance/review packet can freeze those identities independently of the package's own manifest fields.

Example source-only package build:

```powershell
pwsh ./deploy/Publish-HostAgentWindowsPackage.ps1 -OutputDirectory C:\LDW\artifacts\host-agent-windows
```

## Plan and status

`deploy/Manage-HostAgentWindowsDeployment.ps1` owns only the fixed application path:

```text
%ProgramFiles%\LowcountryDigitalWorks\HostAgent\Windows\LDW.HostAgent.Windows.exe
```

A candidate package is not authorized merely because its self-declared manifest contains an accepted source commit/tree. `Plan` and `Install` require an independently supplied accepted package identity that binds all of:

- exact source commit;
- exact source tree;
- exact manifest SHA-256;
- exact executable SHA-256;
- exact executable byte length.

Example read-only Plan:

```powershell
pwsh ./deploy/Manage-HostAgentWindowsDeployment.ps1 `
  -Action Plan `
  -PackageDirectory C:\LDW\artifacts\host-agent-windows `
  -ExpectedSourceCommit <40-hex accepted commit> `
  -ExpectedSourceTree <40-hex accepted tree> `
  -ExpectedManifestSha256 <64-hex accepted manifest digest> `
  -ExpectedExecutableSha256 <64-hex accepted executable digest> `
  -ExpectedExecutableBytes <accepted byte length>
```

`Plan` and `Status` are read-only. `Status` reports only bounded provenance/readback facts for the managed executable and the exact validated rollback identity when one exists.

## Install trust and serialization

`Install` and `Rollback` require an elevated installer process because the managed bytes live under Program Files. The tray itself remains normal-user and refuses elevated runtime execution.

Before creating any managed directory, the helper validates the existing Program Files ancestry for expected directory type, reparse state, and broad mutation ACLs. Newly created product/install/transaction directories are validated immediately. Managed executable/manifest files and rollback files refuse reparse/hard-link indirection before hashing, copying, replacing, or deleting them.

Every mutating transaction obtains one fixed bounded exclusive file lock under protected Program Files. After the lock is held, the helper re-reads tray process state, package identity, installed state, and rollback state before mutation. It checks the tray again immediately before activation. Concurrent install/rollback attempts therefore fail/queue at the bounded lock rather than racing managed state. The helper never kills or restarts the tray.

Installation fails closed when:

- the package boundary or externally supplied accepted package identity does not match the package bytes;
- the fixed install root or any existing managed parent/path violates directory, reparse, hard-link, or broad-write protections;
- installed or rollback managed state is partial/ambiguous;
- the package, installed state, rollback state, or tray-running state changes across the transaction boundary;
- `LDW.HostAgent.Windows` is currently running;
- the installed tray predates deployment manifests unless the deployment packet separately pins its exact accepted legacy executable SHA-256 plus accepted source commit/tree.

The legacy-adoption inputs are intentionally separate from the new package identity. They exist only to migrate a previously accepted exact binary into the rollback model; a hash mismatch refuses the update. Failed migration restores the original legacy shape without leaving a new deployment manifest behind when restoration can be positively proven.

The deployment helper does not create, enable, disable, remove, or rewrite the existing Scheduled Task/HKCU Run startup owner.

## Post-install normal-user relaunch

The package manager intentionally does not start or stop the tray. After a reviewed install/rollback transaction has completed and the owning live gate still requires the tray to be started, use the separate bounded helper:

```powershell
pwsh ./deploy/Start-HostAgentWindowsTray.ps1 -Action Plan
pwsh ./deploy/Start-HostAgentWindowsTray.ps1 -Action Start
```

The relaunch helper has no executable-path, argument, user, or session override. It reuses the fixed managed Program Files identity and requires the installation to validate as `Managed`. `Plan` is read-only and refuses an already-running tray, session 0/non-interactive execution, or the absence of a same-session non-elevated Windows Explorer owner shell.

`Start` delegates the fixed executable to the existing owner Explorer shell rather than directly launching the tray from an elevated deployment shell. It then performs bounded process readback and accepts only exactly one newly launched process at the fixed path, in the expected interactive session, whose token is positively proven non-elevated. An elevated or token-ambiguous exact candidate is stopped and the helper fails closed; multiple exact candidates are cleaned up and refused. Identity/session/path ambiguity is never treated as successful activation.

This helper does not alter HKCU Run, Scheduled Tasks, services, configuration, deployment manifests, rollback state, credentials, or provider state. It is a post-transaction activation/readback helper only. The normal-user tray itself still independently refuses elevated execution.

## Rollback and recovery evidence

When replacing a validated existing installation, the immediately prior validated executable and deployment manifest become the single rollback package. A deliberate `Rollback` also requires an independently supplied exact rollback identity: source commit/tree, manifest SHA-256, executable SHA-256, and byte length. This prevents a locally substituted rollback directory from becoming privileged merely because it is present.

A normal successful rollback swaps the current and prior validated packages so the just-replaced build remains available for deterministic forward recovery.

Failed install/rollback transactions attempt exact restoration and require positive readback. Rollback recovery restores the original installed bytes only from a completed, identity-verified current-state backup. That backup may still be at its transaction path or, after the transaction positively records the normal backup promotion, at the rollback root; the actual recovery source is re-read and must match the original installed identity before restoration. If the backup was never completed, the live installation must still match the original identity and the preexisting rollback target is never substituted as a recovery source. Temporary staging/previous/rollback evidence is deleted only after the new transaction is marked committed or restoration was positively proven, so cleanup failure cannot trigger reversal that depends on the evidence being deleted. If restoration is ambiguous or cannot be proven, the helper fails closed and deliberately retains bounded transaction/recovery evidence for later exact reconciliation rather than deleting the only validated recovery copy.

`deploy/tests/Test-HostAgentWindowsDeploymentBehavioral.ps1` executes the production manager/module under a synthetic protected Program Files root and behaviorally proves Absent -> Install A -> Install B -> Rollback to A, real transaction-lock contention (`HOST_AGENT_WINDOWS_TRANSACTION_BUSY`), destination trust refusal before managed mutation, and a deterministic mid-transaction install failure branch that restores both the prior installed identity and the preexisting rollback identity. The behavioral harness intentionally does not force corruption of the final recovery source branch because that branch is designed to preserve bounded evidence for manual reconciliation, and forcing it in CI would make safe automatic cleanup ambiguous.

## Configuration and boundaries

Machine-local configuration remains outside the package and is not read, copied, overwritten, or removed by deployment. Existing configuration lookup remains:

1. `LDW_HOST_AGENT_CONFIG` when explicitly set;
2. `%LOCALAPPDATA%\LowcountryDigitalWorks\HostAgent\host-agent.Local.json`;
3. `host-agent.Local.json` beside the executable when already managed separately.

The deployment helper does not manage the third location. It modifies only the executable, deployment manifest, bounded transaction lock, and bounded rollback/transaction directories under the fixed Program Files trust boundary.

No service, Scheduled Task, registry startup value, public listener, network fetch, credential, Hyper-V/CI/JIT state, customer/private data, or paid dependency is introduced by this deployment path.

## Acceptance boundary

Source/package validation is not LDW01 deployment acceptance. A live update requires the owning Host Agent/#554 gate, an independently frozen exact accepted package identity, a fresh owner-activity/collision check, no surprise reboot or process termination, post-install readback, rollback identity capture, and separate real UX evidence. Natural login/reboot proof remains deferred to the next normal owner login/reboot rather than being forced for acceptance.
