# Disposable Hyper-V runner candidate

Work item: `LowcountryDigitalWorks/infrastructure-tools#7`.
Dispatcher work item: `LowcountryDigitalWorks/infrastructure-tools — CI-RUNNER-DISPATCH-001`.
Architecture and workflow acceptance: `LowcountryDigitalWorks/business-operations#552`.

This is an elevated, owner-controlled, bounded controller and dispatcher system. It creates a
fresh Linux guest and a repository-scoped GitHub JIT runner for exactly one
identified job. It does not install a standing unprivileged daemon or broad background service. Run it from
PowerShell 7 on the approved Hyper-V host, using the existing `gh` session.

## Security boundary

- The normal repository allowlist starts with `business-operations`. An operator
  can supply an explicit approved private-repository allowlist for future accepted
  workflows. The implementation is parameterized; this is not acceptance of any
  additional workflow or credential use.
- The public implementation repository has a narrowly scoped synthetic exception:
  its exact proof workflow, a push to the implementation branch, one job, exact
  head SHA, and the expected isolation labels. No production workload or secret
  is added to this exception.
- The opaque per-run label correlates a queued job with its temporary runner. It
  is not durable identity or an authorization boundary. Exact repository, workflow,
  event, head repository, commit, job count, runner identity, and local ownership
  records must also match.
- The guest receives only short-lived encoded JIT configuration. The controller
  checks the in-memory configuration for the correct repository, one-job ephemeral
  behavior, and disabled runner auto-update. It refuses an incompatible contract.
- There is no host filesystem mount, Docker socket, owner session, host SSH
  identity, or long-lived GitHub credential in the guest. The runner is a dedicated
  non-root account without sudo. The root-owned bootstrap and systemd service
  cannot be rewritten by the job. The service never restarts the runner.
- Only the built-in NAT switch is used. SSH services are masked. Before starting
  the runner, nftables drops inbound administration and blocks private networks,
  host addresses, metadata/link-local ranges, and IPv6. DHCP, loopback, and DNS
  only to the guest's assigned IPv4 resolvers remain available. Public outbound
  access supports GitHub and verified tool downloads;
  this prototype does not enforce a domain-level outbound allowlist.
- VM guest integration services except heartbeat are disabled. No inherited
  management credential or public inbound administration is configured.
- Hyper-V separates candidate code from the host. A guest compromise can still
  consume its bounded resources and access its job token and JIT material. It
  must not receive customer or regulated-data authority.

## Verified base and downloads

`Prepare-Base.ps1` obtains the official generic Ubuntu Noble cloud image from
`https://cloud-images.ubuntu.com/releases/noble/release-20260926/`.
The exact source image is `ubuntu-24.04-server-cloudimg-amd64.img`, SHA-256
`6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`.
Preparation verifies that pin against the authoritative `SHA256SUMS` over HTTPS
and hashes the download before conversion. The detached signature is available
upstream but is not verified by this Windows prototype; no GPG trust chain is
claimed. Acceptance should decide whether detached-signature verification is
required in addition to the pinned hash and authoritative HTTPS source.

The generic `.img` is a bootable QCOW2 disk. The generic tarball contains a raw
root partition and is unsuitable as the boot disk. The small read-only converter
in `Native.cs` handles standard uncompressed, zero, and raw-deflate QCOW2 clusters.
It refuses backing files, encryption, incompatible features, malformed bounds,
and unsupported flags. It appends a fixed VHD footer, then uses the built-in
Hyper-V `Convert-VHD` to produce a dynamic VHDX. The resulting hash, source hash,
release, and virtual size are recorded in a local protected provenance manifest.
The VHDX has a bounded 16 GiB virtual capacity, is sealed read-only, rehashed
before each run, and never booted directly. Preparation may explicitly expand
an already verified smaller prototype base using `-ExpandVerifiedBase`, only
with no disposable instances and no attached reference to that base.
Every job uses a fresh differencing disk. This base has never executed a job.

The runner is pinned to `v2.338.0`, Linux X64, from the official `actions/runner`
release. Its SHA-256 is
`af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32`.
Bootstrap verifies the archive before extracting it. System dependencies come
from Ubuntu's signed package repositories. No paid software or cloud compute is
used. Local CPU, RAM, disk, and outbound bandwidth are the runtime resources.
Incremental cash is `$0`; no Actions overage setting is changed.

## Artifact provenance

Controller and dispatcher components are checked against `provenance.json` before execution:
- `CiRunner.psm1`
- `Invoke-IsolatedRunner.ps1`
- `Invoke-Ci7Dispatcher.ps1`
- `Native.cs`
- `Prepare-Base.ps1`
- `guest/*` scripts and service unit definitions

Both `Invoke-IsolatedRunner.ps1` and `Invoke-Ci7Dispatcher.ps1` enforce `Assert-Ci7Provenance` at startup. If any script, module, or definition file is tampered with or missing, the controller/dispatcher fails closed without making API or provisioning calls.

## Trusted dispatcher (CI-RUNNER-DISPATCH-001)

`Invoke-Ci7Dispatcher.ps1` provides the host-side daily-use control plane layer that detects eligible queued jobs from allowed repositories and invokes the accepted one-job controller primitive.

### Key Dispatcher Guarantees

1. **Explicit Code-Reviewed Allowlist:** Only repositories and workflow paths explicitly registered in the allowlist (`Get-Ci7DispatcherAllowlist`) are polled. Broad organization-wide scanning or "all queued self-hosted jobs" rules are refused.
2. **Deterministic Selection:** If multiple eligible queued jobs are detected, the dispatcher selects the oldest candidate (`created_at` / `run_number`) first.
3. **Double Verification Before Launch:** Re-reads the queued job state via GitHub API immediately prior to controller invocation to confirm the job remains queued, unassigned, and matching the isolated label contract.
4. **Capacity & Exclusive Mutex:** Uses `dispatch.lock` to ensure only one dispatcher instance polls or provisions at a time, permitting at most one active disposable runner VM on LDW01.
5. **Safe Reconciliation:** Runs `Invoke-IsolatedRunner.ps1 -Mode Reap` before launching a guest to reconcile any stale or interrupted resources from a prior run crash.
6. **No Credential Export:** Reuses the trusted owner's non-interactive `gh` session on LDW01 control plane. Tokens are never written to disk, exported to environment files, or passed to guests.

### Dispatcher Modes & Operations

- **Verify:** Confirms owner `gh` authentication status, allowlist profile integrity, component provenance, and storage root ACLs.
  ```powershell
  ./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode Verify
  ```
- **PollOnce:** Performs a single reconciliation and queue poll cycle, provisioning exactly one job if queued and allowed.
  ```powershell
  ./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode PollOnce
  ```
- **Service:** Continuous polling loop on the host (at bounded interval, e.g., 30s).
  ```powershell
  ./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode Service -PollIntervalSeconds 30
  ```
- **RegisterTask (Phase A Daily Use):** Registers a Windows Scheduled Task (`LDW-CiRunner-Dispatcher`) under the current owner identity with `Highest` privileges, configured to start at owner logon.
  ```powershell
  ./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode RegisterTask
  ```
- **UnregisterTask:** Cleanly unregisters and removes the Scheduled Task.
  ```powershell
  ./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode UnregisterTask
  ```

### Phase A Daily Use Scope
Phase A installs an owner-session Scheduled Task running under the existing owner identity. It runs non-interactively without UAC prompts per JIT job, with zero embedded passwords or tokens. It provides daily-use acceptance during owner sessions, but is explicitly reported as not covering pre-login host reboots (which is preserved for a future Phase B gate).

## Lifecycle and bootstrap

1. Read-only planning verifies elevation, base provenance, component hashes, queued job identity,
   a two-CPU allocation, a 2–4 GiB guest, at least 4 GiB free host RAM after the
   allocation, CPU load at most 70%, and at least 40 GiB free disk.
2. The controller snapshots the persistent runner/VM configuration locally and
   creates a protected ownership manifest and exclusive controller locks. A
   global lock serializes provisioning and reap; a per-run lock protects recovery.
3. GitHub generates a repository-level JIT configuration. Its runner ID and name
   are recorded before provisioning. The material is never logged.
4. Windows IMAPI creates a NoCloud `cidata` ISO from fixed guest files and the
   JIT configuration. Plain seed staging files are immediately removed. The ISO,
  VM, differencing disk, and manifest live inside one protected owned directory.
  Automatic checkpoints are disabled on the disposable VM.
5. The guest creates the non-root account, hardens networking and administration,
  downloads and verifies the runner, and starts its one-job service. Cloud-init
  and runner bootstrap output are suppressed rather than retained as raw logs.
  A local Hyper-V serial pipe filters fixed bootstrap phase/failure codes; every
  other console line is discarded in memory, never printed or stored.
6. The controller polls only the exact intended run/job. It refuses a different
   runner assignment, unexpected job count, source drift, or timeout.
7. After job completion, it confirms/removes only its registration, removes the
   VM and disposable disk/media, checks the persistent baseline, and removes
   transient state. The immutable base, sanitized evidence, empty dispatcher mutex,
   and empty global mutex file survive; mutex files contain no run or credential state.

GitHub job/check logs provide job evidence. Local JSONL evidence (`evidence/<run-id>.jsonl` and `evidence/dispatcher.jsonl`) retains only
opaque run IDs, fixed phase classifications, profiles, and UTC timing. Ownership manifests
contain local resource references but remain in ACL-protected local storage and
are removed on successful cleanup. They are never GitHub artifacts. No detector
finding contents, raw API response bodies, or raw bootstrap logs are retained.

## Failure and interrupted cleanup

Failure cancels the intended run where possible and tears down conclusively owned
local resources. A cleanup or registration uncertainty returns failure and retains
the local ownership manifest. It never declares success based on an offline runner.
Deletion requires the exact local run ID, dedicated storage root, recorded VM ID,
VM name and notes marker, disk attachment, media attachment, repository runner ID,
runner name, and label set. Reparse paths and unknown transient files are refused.
The persistent `CI-RUNNER-001` / `ldw01-ci-01` resources cannot match these guards.

After an interrupted process or host reboot, run `Reap` or a specific `Cleanup`.
The exclusive lock prevents cleanup racing a live controller. Cleanup is
idempotent for already absent owned resources. A prefixed VM without conclusive
state is an explicit blocker, never automatic deletion authority. The dispatcher
automatically invokes `Reap` before candidate discovery on every poll cycle.

## Validation and proof procedure

```powershell
./ci-runner/tests/Test-Controller.ps1
./ci-runner/tests/Test-Dispatcher.ps1
./ci-runner/tests/Test-Native.ps1
python3 -m unittest discover -s ci-runner/tests
./ci-runner/Prepare-Base.ps1
```

To test dispatcher verification and single-poll execution:

```powershell
./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode Verify -AllowPublicSyntheticProof
./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode PollOnce -AllowPublicSyntheticProof
```

To register or unregister the Phase A Scheduled Task:

```powershell
./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode RegisterTask
./ci-runner/Invoke-Ci7Dispatcher.ps1 -Mode UnregisterTask
```

## Betterleaks proof scope

After the synthetic boundary proof passes, the same one-job workflow replays the
six original Bash blocks from the exact reusable-workflow commit currently pinned
by the private caller: `d8a2f4ed8a7a56b996c2e6c99cdde9fcf39bb744`. The fetched
workflow bytes must match SHA-256
`e87c43b9811e443a4697d70e28a84797b8f602dc9674eee126aebfc988001608`.
The replay verifies the checkout and permission contract, preserves Betterleaks
`1.7.4` and its accepted archive hash, enables all runtime canaries, and executes
the original revision resolution, history scan, and candidate-tree scan scripts.
It emits only fixed proof classifications and discards all script/tool output.
There is no durable copy of scanner logic in this repository.

This replay uses this public synthetic caller's full Git history. It demonstrates
scanner semantics and isolation; it does not demonstrate a private
`business-operations` check or its actual PR base/head history. That target remains
`PARTIAL` until the owning workflow workstream supplies a bounded routing proof.
The smallest proposed next gate is an optional execution-target input on the
shared workflow, preserving its GitHub-hosted public default, plus an explicit
private caller selection of the accepted isolated labels and per-run correlation
label. The caller must pin the reviewed shared-workflow change. ORCH01 and the
owning workflow workstream retain acceptance and migration authority; PR #559
is outside this implementation.
