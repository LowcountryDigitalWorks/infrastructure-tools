# LDW Commander — disposable process containment proof

**Gate C-preparation source only — NOT privileged, NOT deployed, NOT a general sandbox.**

Owning issue: infrastructure-tools #209. This source is stacked on PR #219 (synthetic host journal), which depends on #217 (local user-mode), #215 (signed synthetic owner decisions), and #214 (still independently unaccepted security contract). It must not advance ahead of those author-independent gates.

## What is actually executed

`process_containment.py` runs **one hardcoded, harmless Python worker with exactly one hardcoded descendant**, under a private temporary test folder. The supervisor never accepts model-selected source code, arbitrary executable paths or command arguments; neither process receives inherited customer files or model credentials.

- **Linux / POSIX:** starts the fixed worker in a fresh process group. The worker starts the test child, and on SIGTERM shuts down and reaps its own child. The supervisor waits for the worker to exit, then checks that its OS process group no longer exists. The recovery fallback may SIGKILL the group, but a forced attempt alone never constitutes verified drain.
- **Windows:** creates a private Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the worker blocks on a private startup gate until successfully assigned to the Job. The child starts only after assignment, inheriting the Job. Termination uses `TerminateJobObject`; the supervisor waits for its direct process, then requires OS Job accounting to show `ActiveProcesses = 0` before declaring verified drain.
- Both: the only source-visible states are `NEW`, `RUNNING`, `DRAINED_VERIFIED`, `QUARANTINED`. An unverified process exit, clock rollback, timeout or failed cleanup becomes quarantined; it cannot re-open itself. Session expiry uses an injected monotonic clock for deterministic tests. Health wire never emits process PID, host address, shell output or credentials.
- The fixed worker emits only a child-PID marker inside the private temporary folder; the marker is not exposed in normal status and is removed with the fixture after cleanup.

Run (after the inherited test dependency is installed):

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

The existing Commander synthetic workflow runs this on Windows and Ubuntu. Tests prove normal parent+child drain, denied reuse, expiry-triggered cleanup, deliberately failed verification forcing quarantine, clock rollback refusal, and no arbitrary shell interface.

## Explicitly NOT proven

- No Administrator/root, protected Windows service, protected Linux cgroup, remote command or connected ChatGPT plugin.
- **Windows Job assignment after worker process creation** is safe for this fixed worker only because it blocks on a private stdin gate before launching its child. This is not atomic admission for untrusted code. Actual arbitrary privileged executables need protected OS creation/admission and an independently reviewed service architecture.
- A normal-user POSIX process group can be escaped by arbitrary/privileged code, and Windows Administrator/SYSTEM processes can create detached services/jobs or break out of ordinary process containment. These tests use trusted fixed code only; do not call the mechanisms non-bypassable for general administration.
- Process group readback and Job accounting do not audit irreversible files, scheduled tasks or services. Production `DRAINED_VERIFIED` must include independent process, service, task, side-effect and host-journal readback, protected from the privileged payload.
- No host-side state persistence or coupling to PR #219's synthetic journal in this slice; it is an independent bounded OS-process demonstration. Do not assume a passing process test releases a previously quarantined host journal.
- Windows runner's job nesting and OS policy must be validated in hosted CI. Failure to assign must fail closed, not skip Windows or fall back to uncontained process start.

Future integration requires protecting session/owner consent, external egress isolation, encrypted authenticated transport, OS-specific job/cgroup helpers, trusted owner-authenticated recovery, and Host Agent read-only status only through the existing business-operations #554 owning lane. No second dashboard, restart manager or unauthorized host mutation.

**No new cost, production host settings, credentials, customer/regulated data, remote listener, machine packages, or privileged agent installation.** Source author GM17 cannot terminally self-review.
