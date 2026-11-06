# LDW Commander: first real user-mode file and process proof

**STATUS: DRAFT SOURCE-ONLY / NO REMOTE ACCESS / NO ADMINISTRATOR-ROOT EXECUTION / NO HOST INSTALLATION**

Owning issue: infrastructure-tools #209. Accepted main foundation: Gate A security design PR #214 and the independently reviewed synthetic signed-session mainline PR #237 (merge `39af719c6f38b96ce52affd065639f778181f44e`). This disposable file/process proof extends those source-only contracts and does not itself grant runtime or privileged authority.

## Actual operation introduced

Unlike the earlier in-memory CANARY_ECHO, this executable local test harness performs real operating-system work **only against a disposable temporary fixture created by the test/CLI**:

- A signed, role-and-host-bound MAINTAIN grant opens a session with the public-key-only verifying agent.
- FILE_CREATE writes a new bounded .txt fixture, refuses overwrite, path traversal and symlinks.
- FILE_READ reads back the fixture and returns the matching SHA-256 digest.
- FIXED_PROCESS launches the current Python interpreter as a real child process with one hardcoded harmless print program, no shell, no arbitrary argv, no inherited environment secrets, no stdin, an execution timeout, and fixed, checked output.
- A command ID retries idempotently for identical operations; a changed command with the same ID is refused.
- Grants are checked before each operation, including revocation, expiry, operator and exact host. A fixed three-command budget is applied.

## Local CLI demonstration

After provisioning Python 3.11+ with the already-pinned test dependency:

    python -m pip install -r commander/prototype/requirements.txt
    python commander/prototype/local_cli.py --synthetic-demo

It prints a sanitized, tiny JSON result containing LOCAL_USER_MODE_PROOF_COMPLETE, file integrity PASS, child process PASS and session REVOKED. It creates and destroys a temporary test directory and ephemeral test signing key. It does not expose a private key, user data, actual host target, portable admin credential, remote service or unrestricted terminal.

## Tests

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

The hosted source workflow runs the full prototype tests under **Ubuntu and Windows**. Coverage includes real file write/read/sha, fixed child process, duplicate IDs, attempted overwrite, traversal/symlink/oversize refusal, wrong operator/host, forged grants, expiry/revoke and CLI smoke.

## Why this is not a security boundary

A user-mode child process is not isolated by merely choosing a temporary working directory. This version **does not accept arbitrary commands**; that is intentionally out of scope until the Commander privileged-session threat model, host enrollment, protected service and sensitive-output decisions have been independently accepted.

The current prototype holds its in-process session lock through the fixed process, and error/crash persistence is not a production idempotency journal. These are explicitly unresolved for a future general executor. No claim of immutable audit, durable delivery, remote recovery, privileged isolation, or safe arbitrary process interruption.

## End-state preserved

User goal remains a genuine first-party multi-host remote Desktop Commander replacement, with arbitrary **owner-authorized** Administrator/root terminal/file/service/desktop operations within separately admitted, short-lived and revocable sessions; no third-party Desktop Commander subscription/quota and no Work/GitHub runtime message bus. This local step proves actual OS calls but not those outcomes.

**Do not merge before fresh exact-head CI and independent whole-delta security/source review** on the reconciled main-targeted PR #217. Source-only merge is distinct from deployment and any real host-specific protected installation, owner authentication, arbitrary commands, remote networking or elevated execution. No new software subscriptions, customer/regulated data, secret export or standing schedule. Target incremental cost $0.
