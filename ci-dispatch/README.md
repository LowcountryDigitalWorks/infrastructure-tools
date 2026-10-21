# Trusted queue dispatcher candidate

Implementation authority: infrastructure-tools #10. The accepted #7 controller
and PR #8 remain unchanged. Cross-LDW acceptance belongs to business-operations
#552 / ORCH01. This candidate installs no standing task and changes no production
workflow, Royal profile, or PR #559.

## Admission and discovery

`profiles.json` admits the harmless public infrastructure-tools synthetic profile
and the bounded `ci10-bo-secret-scan` business-operations profile. The synthetic
profile binds the exact repository, workflow, push event, source branch, reviewed
source SHA `6bf0fc0de72c7cef3cea7c3c054ba2326fdbfe26`. The production profile binds
the exact private repository/workflow, pull-request and main push events, same-repo
head repository, immutable run/job head SHA equality, job name, seven static labels,
`ci7-run-<run-id>`, one unassigned queued job, CPU/RAM/timeout, no Docker, no
workflow secrets or private production state, and the accepted egress/controller
profile. The module validates this exact registry contract. Unknown profiles and
fork pull requests are refused; no arbitrary caller-supplied allowlist is accepted.

Polling reads only that repository's specific workflow/branch/event queue, at most
three pages of 100 runs per poll. An incomplete/unstable listing fails closed. It
reads latest-attempt jobs, rejects duplicate candidate IDs, and orders eligible
jobs by creation UTC, run ID, then job ID. Unrelated jobs are never cancelled.
GitHub can populate `started_at` while a job is still queued; assignment is checked
using status and runner ID/name/group, rather than interpreting that timestamp as
assignment. Selection captures run ID, SHA, attempt, job ID and creation UTC. The
selected run/job are re-read immediately before launch; any drift aborts dispatch.

The existing synthetic push workflow is reused by rerunning its accepted run.
No synthetic workflow or controller exception change was needed. A rerun keeps
its original event, branch, immutable head and run ID, with a new attempt/job ID.
The production profile derives its candidate SHA from each queued run and requires
the job SHA to match it. The dispatcher accepts no run ID/SHA input; only the
registry supplies source policy. The profile is source-only: this change does not
execute a real scan, install/enable a host task, or activate production routing.

## Protected provenance

`Publish-Bundle.ps1 -Commit <exact-commit> -Tree <exact-tree>` stages an allowlisted
runtime in the dedicated ProgramData-style dispatcher root. It verifies the
repository origin and requested commit/tree. Controller acceptance comes from the
source-controlled snapshot registry in `Dispatch.psm1`, which currently recognizes
only the original accepted controller (`49f39f5d3a66251ed18c2e776d843feb25f65fe1`
/ `4d241fe9bc0fbf190daf2e36be0e9c52966c5a7b`) and the independently reviewed Royal
PR #42 controller (`54b9343af44c70db1d1403cf7f45cfc11e8bf167` /
`beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec`). The publisher hashes every controller
runtime file and requires one complete snapshot match; unknown or mixed files fail
closed. The manifest records that exact matched commit/tree and per-file SHA-256.

For compatibility with already accepted target commits, the publisher sources
`Dispatch.psm1` and `verifier-provenance.json` only when the accepted repository paths
resolve at `HEAD` to their fixed reviewed Git blob IDs and SHA-256 digests. The
publisher extracts those exact `HEAD` blobs into protected staging, checks their
SHA-256 digests, and imports the dispatcher only from that verified staged path. It
never executes the ambient working-tree dispatcher, even when a hidden
`skip-worktree` edit leaves Git status clean. This identity survives squash merge and
a main-only checkout because it pins durable file blobs, not transient PR-history
commits. The provenance record identifies the dispatcher blob and digest; the
protected manifest records that identity, and `Assert-Ci10Bundle` checks the record,
manifest fields, and actual verifier file hash. All other runtime files remain
sourced from the exact requested target commit/tree.
The manifest hashes the complete runtime file set. No `.git`, credentials or machine
settings enter the bundle. An existing release must already match; publication never
overwrites it.

The publisher defines its minimal elevation and owned-path/reparse-point guards
locally. It never imports `ci-runner/CiRunner.psm1` from the ambient checkout;
controller files enter a release only from one complete accepted snapshot, and
unknown or mixed controller files are refused before publication.

The root, release parents and contents are owned by Administrators, with only
Administrators and SYSTEM allowed to write. Before it creates staging or imports
the verified dispatcher, the publisher checks the root parent and grandparent
owners and rejects user replacement rights. Reparse paths, untrusted ownership,
missing required ACL principals, missing/extra files, manifest/hash drift and
commit/tree/controller provenance mismatch are refused. The entry authenticates
the manifest and dispatcher scripts before module import, then verifies the full
bundle before every poll and again before controller launch. Exact commit/tree
and manifest hash are external invocation pins, also placed in the proposed task
arguments. Hashes detect drift; a malicious elevated administrator is already
inside the trusted host boundary. No new signing or credential infrastructure is used.

Runtime execution starts exclusively from the protected release, never the
development checkout. Development tests and publication tooling are preparation
operations. Runtime requires PowerShell 7.5+ (`ConvertFrom-Json -DateKind String`),
existing `gh` authentication and the accepted Hyper-V controller prerequisites.

## Locks, capacity and recovery

A separate exclusive dispatcher file lock serializes pollers. The accepted
controller's global lock remains authoritative for VM creation and Reap. The
dispatcher briefly probes that lock, validates local state and capacity, and
releases the probe before launch. The controller independently reacquires its
lock and repeats exact job validation; a competing controller wins or loses that
lock without a second guest. A busy controller or unavailable capacity leaves
eligible jobs queued. Maximum active disposable guests is one.

The dispatcher refuses orphan `ci7-` VMs/runners or ambiguous state. It delegates
conclusively owned stale synthetic state to accepted per-run `Cleanup`; it does not implement
prefix-only deletion. Nonprofile stale state is refused. A fresh locked snapshot
supplies exact local run IDs to Cleanup, so a different workload appearing after
the probe cannot enter a root-wide Reap operation. The accepted Cleanup may
cancel only the exact interrupted owned job as part of its cleanup; the dispatcher
itself has only GET API operations. Cleanup must complete before another launch.

The controller is a separate hidden child process. Dispatcher interruption does
not intentionally stop it. A new dispatcher respects its global/per-run lock.
If the controller was interrupted, accepted state/ownership checks and Cleanup
reconcile the guest, runner, disk, media and JIT material before discovery resumes.
`-Mode Recover` performs only reconciliation and never selects or launches a job.
Ambiguous cleanup blocks subsequent dispatch and preserves authoritative state.

`Discover` selects and revalidates without creating JIT/VM resources. Its optional
0–30 second `DiscoverHoldSeconds` permits a bounded interruption proof while
holding only the dispatcher lock; the parameter is refused in every other mode.
`Once` makes
one bounded poll/dispatch. `Poll` permits 1–60 polls, separated by 15–300 seconds;
it is synchronous and never launches a second job before first cleanup completes.
There is no hosted/persistent fallback and incremental cash remains `$0`.

## Diagnostics

The persistent JSONL log contains only UTC, a fixed phase classification, the
static synthetic profile ID and numeric workflow run ID. Three files are retained,
rotating at 256 KiB plus at most one bounded record. API bodies, exception text,
stdout/stderr from the controller, tokens, JIT, findings, addresses, private paths
and owner details are not persisted. Child streams drain directly into the null
stream. The accepted controller retains its separate sanitized lifecycle evidence;
GitHub retains normal job/check evidence. No raw guest diagnostics are captured.

## Proof and task packet

Run `tests/Test-ControllerSnapshots.ps1`, `tests/Test-Dispatch.ps1` and the existing
`ci-runner/tests` suites. The snapshot suite runs without host ACL or Hyper-V access;
the full dispatcher suite still requires its protected-path Windows fixture. Tests cover
verifier source immutability, verifier manifest/hash drift, profile/queue identity,
ordering, immediate re-read races, API failure, capacity,
actual exclusive locks, stale state/ownership, provenance/hash/file-set/ACL drift,
redaction/rotation and task acceptance guards. The live proof should:

1. Requeue the accepted synthetic run, then start the protected `Discover` entry
   with only commit/tree/manifest pins. Confirm it remains queued with zero guests.
2. Hold the accepted global lock and run the protected entry: expect BUSY, job
   still queued, zero new resources. Release the lock.
3. Run the protected `Once` entry. Require discovered IDs, normal successful
   GitHub check, exact deregistration and zero guest/disk/media/transient state.
4. Requeue the accepted surface for a second attempt and repeat. A fresh opaque
   controller run ID and the guest's previous-workspace marker assertion prove
   a fresh guest. Lock refusal supplies the bounded overlapping-capacity proof.
5. Prove interruption before launch and accepted controller interruption/reap
   without manufacturing ambiguous state. Requeue only the owned synthetic proof
   if accepted Reap cancelled that interrupted attempt.
6. Compare the protected persistent runner/VM baseline, verify zero owned JIT
   registrations/VMs/run directories and remove transient proof artifacts/tasks.

### CURRENT

Manual dispatcher only. No standing scheduled dispatcher task is installed.
Owner-session highest-privilege authentication was proven with a transient
one-shot silent read task; it was immediately removed. No token was exported/copied.

### PROPOSED (requires ORCH01/owner acceptance before installation)

`Manage-Task.ps1` prepares Plan/Status/Install/Disable/Enable/Uninstall tooling.
Future `LDW-CI10-Dispatcher` uses the current owner identity, InteractiveToken and
highest privileges, an owner-logon trigger and a daily repeating one-minute poll.
Each invocation runs protected exact bundle `Once`; IgnoreNew prevents overlapping
task instances, with a 25-minute task limit. No password/token is in its definition.
Install/Enable explicitly require `-OwnerAccepted`. Plan/Status do not install it.
`PRE_LOGIN_REBOOT_INDEPENDENT=NO`: Phase A requires the owner to be logged in.

### ROLLBACK

Disable the exact pinned task. Uninstall first stops its dispatcher instance,
then invokes protected Recover. A live controller remains authoritative; BUSY or
uncertain recovery fails closed and requires waiting for completion or accepted
owned Reap. Remove the exact task only after reconciliation, verify task absence,
zero owned guest/runner/run state and released dispatcher/controller locks. Retain
the protected immutable bundle and sanitized evidence for review/rollback; no
recursive release deletion occurs in task management.
