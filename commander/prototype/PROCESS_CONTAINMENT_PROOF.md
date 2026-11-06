# LDW Commander — disposable process containment proof

**Gate C-preparation source only — NOT privileged, NOT deployed, NOT a general sandbox.**

Owning issue: infrastructure-tools #209. This source extends the independently source-reviewed and merged actual-main foundation: Gate A architecture PR #214, signed synthetic owner decision/issuer journal PR #237, disposable local user-mode PR #217, and synthetic host journal PR #219 (main merge ae4f6d94c5ab070a8306eac81d2c5a08cfdb620a). This draft nonprivileged process-containment proof requires its own exact-head tests and independent security review.

## What is actually executed

`process_containment.py` runs **one hardcoded, harmless Python worker with exactly one hardcoded descendant**, under a private temporary test folder. The supervisor never accepts model-selected source code, arbitrary executable paths or command arguments; neither process receives inherited customer files or model credentials.

- **Linux / POSIX:** starts the fixed worker in a fresh process group. The worker starts the test child, and on SIGTERM shuts down and reaps its own child. The supervisor waits for the worker to exit, then checks that its OS process group no longer exists. The recovery fallback may SIGKILL the group, but a forced attempt alone never constitutes verified drain.
- **Windows:** creates a private Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the worker blocks on a private startup gate until successfully assigned to the Job. The child starts only after assignment, inheriting the Job. Termination uses `TerminateJobObject`; the supervisor waits for its direct process, then requires OS Job accounting to show `ActiveProcesses = 0` before declaring verified drain.
- Both: the only source-visible states are `NEW`, `RUNNING`, `DRAINED_VERIFIED`, `QUARANTINED`. An unverified process exit, clock rollback, timeout or failed cleanup becomes quarantined; it cannot re-open itself. Session expiry uses an injected monotonic clock for deterministic tests. Health wire never emits process PID, host address, shell output or credentials.
- The fixed worker emits only a child-PID marker inside the private temporary folder; the marker is not exposed in normal status and is removed with the fixture after cleanup.

Run (after the inherited test dependency is installed):

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

The existing Commander synthetic workflow runs this on Windows and Ubuntu. Tests prove normal parent+child drain, denied reuse, expiry-triggered cleanup, deliberately failed verification forcing quarantine, clock rollback refusal, and no arbitrary shell interface.

## Coupled host-journal evidence (same synthetic source stack)

`session_process_canary.py` links the existing signed `JournalBoundSyntheticAgent` to this real fixed-process supervisor, **without granting the agent arbitrary command or OS privilege**. The integration now demonstrates the required ordering:

1. Verify the signed synthetic owner decision/session and record the host's one-use `OPEN` tombstone **before** launching the fixed child.
2. Launch one nonprivileged parent/child fixture; Host Agent or a ChatGPT tool cannot directly choose its commands.
3. On explicit revoke or session expiry, wait for **actual OS-backed** `DRAINED_VERIFIED` from the process supervisor.
4. **Only then** call the host journal's synthetic verified revoke, transitioning its status to `NO_UNVERIFIED_SESSIONS`.
5. If process exit cannot be verified, or the journal update fails, return `HOST_QUARANTINED`; the OPEN tombstone remains, and no other grant may be admitted on the same synthetic host.

Additional cross-platform tests cover normal drain-before-release, expiration, forged grant refusing process spawn, deliberately ambiguous cleanup, and host-journal write failure. This is a useful proof of **cross-layer ordering**. It does *not* demonstrate OS-protected integrity of either Python process or SQLite file, durable service task tracking, or real Administrator/root containment.

## Explicitly NOT proven

- No Administrator/root, protected Windows service, protected Linux cgroup, remote command or connected ChatGPT plugin.
- **Windows Job assignment after worker process creation** is safe for this fixed worker only because it blocks on a private stdin gate before launching its child. This is not atomic admission for untrusted code. Actual arbitrary privileged executables need protected OS creation/admission and an independently reviewed service architecture.
- A normal-user POSIX process group can be escaped by arbitrary/privileged code, and Windows Administrator/SYSTEM processes can create detached services/jobs or break out of ordinary process containment. These tests use trusted fixed code only; do not call the mechanisms non-bypassable for general administration.
- Process group readback and Job accounting do not audit irreversible files, scheduled tasks or services. Production `DRAINED_VERIFIED` must include independent process, service, task, side-effect and host-journal readback, protected from the privileged payload.
- The new synthetic ordering integration links the accepted-main PR #219 host journal to this fixed process and only releases after positive OS drain. It still does not implement a protected durable runtime ledger or a recovery path for a genuinely privileged host.
- Windows runner's job nesting and OS policy must be validated in hosted CI. Failure to assign must fail closed, not skip Windows or fall back to uncontained process start.

Future integration requires protecting session/owner consent, external egress isolation, encrypted authenticated transport, OS-specific job/cgroup helpers, trusted owner-authenticated recovery, and Host Agent read-only status only through the existing business-operations #554 owning lane. No second dashboard, restart manager or unauthorized host mutation.

**No new cost, production host settings, credentials, customer/regulated data, remote listener, machine packages, or privileged agent installation.** Source author GM17 and main integrator GM20 cannot terminally self-review; source-only acceptance requires fresh exact-head H0/M0, CI and final main race checks.
