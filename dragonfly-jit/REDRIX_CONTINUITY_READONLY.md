# REDRIX Crostini R2 passive health observation

Owner: infrastructure-tools #192 (continuity). Related: #96 (local disposable host),
#139 (protected Gate B), #10 (single trusted dispatch authority), #115
(constrained transport). This document is **SOURCE-ONLY** and grants no runtime
installation, recovery, restart, GitHub runner, VM, or failover authority.

## Supported, non-mutating manual readback

After Eddie signs into ChromeOS and explicitly starts the Linux/Crostini
environment, a normal-user operator can run the repository-local script:

```sh
python3 dragonfly-jit/redrix_continuity_health.py --samples 3 --interval-seconds 2
```

The script performs three short bounded *read-only* snapshots of
`tailscale status --json`, `systemctl is-active/is-enabled` for
`tailscaled` and `ssh`, `pgrep`, `/dev/kvm` access, and the accepted
Dragonfly controller's existing state file and run-directory metadata.
It does **not** call the existing `dragonfly_jit.py status` because that
controller method can create/chmod its state roots. It does not hash the
large base image; exact base digest verification remains a separate
admission control. It does not connect to GitHub or other remote peers.

Only category and static reason codes are printed. No raw Tailscale status,
peer addresses, key material, health warning strings, PIDs, job IDs, or
controller state JSON are echoed. A missing or malformed Tailscale `Health`
field fails closed to `DEGRADED_NETWORK` rather than claiming no warnings.

## Truthful outcomes

- `LOCAL_SERVICES_HEALTHY_UNVERIFIED`: three local observations show the daemon
  active/enabled, Tailscale backend `Running` and `Self.Online=true` with
  a present empty `Health` warning list, SSH active/enabled, /dev/kvm accessible, QEMU absent,
  accepted existing JIT state STOPPED/AVAILABLE and zero run residue.
  **Still no CI admission, full-process visibility, or proof that LDW01 sees the peer.**
- `DEGRADED_NETWORK`: any sample has Tailscale offline, control backend
  not Running, or warnings, even if `tailscaled.service` is active or a
  previous TSMP ping succeeded.
- `DEGRADED_SERVICE`: required service is not both active and enabled.
- `DEGRADED_HOST`: KVM access is not available.
- `HOLD`: incomplete/malformed observations, unknown/contaminated JIT
  state, live QEMU, controller residue or unsafe baseline.

The script intentionally does not report `ONLINE_READY`,
`LOGIN_REQUIRED`, or `CROSTINI_STOPPED` from *inside* a running Crostini
VM. After ChromeOS logout, the local script is simply not running, so an
external trusted monitor must distinguish ChromeOS login from the
Crostini-unavailable state using separately accepted evidence. No ChromeOS
pre-login autorun is assumed. There is no sampling cron/timer/watchdog.

## Acceptance still separate

For #139 Gate B, a trusted A4 process/FD visibility proof is still
mandatory: normal-user pgrep can miss other-user processes. The trusted
LDW01 dispatcher must independently verify
the exact queue/run/job/runner identity and current REDRIX peer reachability
under its accepted controls. A local health readback cannot authorize JIT
minting, guest launch or live GitHub execution. It is intentionally hard-coded
to output `ci_dispatch_authorized=false` and
`peer_side_corrob=UNVERIFIED`, and
`process_visibility=UNVERIFIED` in every branch.

The observer's **exit code is 0 only for `LOCAL_SERVICES_HEALTHY_UNVERIFIED`**;
`HOLD`, degraded classifications and sampling failures return nonzero.
This success exit code is strictly local-diagnostic, **never CI/JIT permission**.
Malformed CLI arguments return the parser's exit code 2 without structured
JSON; consumers must treat any absent/malformed JSON as HOLD. Unexpected
sampling exceptions emit one bounded, sanitized `HOLD/SAMPLE_FAILED` JSON
record without printing exception detail.

The state reader refuses symlinks in ancestor paths and uses Linux no-follow,
non-blocking file-descriptor reads with a 16 KiB cap. If the Linux no-follow
primitive is unavailable, it fails closed. This is a read-only diagnostic;
it does not establish full privileged process visibility or protect against
concurrent user-controlled controller state modifications.

This proof does not install any systemd unit, restart tailscaled, disable
the ChromeOS Android Tailscale node, write a credential, alter routing,
open a listener, register a runner, modify network/firewall/SSH settings,
or touch any protected publication. No auto-repair is implemented.

The current owner-approved HP REDRIX architecture **retains ChromeOS**;
native-Linux firmware replacement remains not planned under closed issue
#81. The older Lenovo Chromebook's separate, still-unverified Linux
conversion candidate belongs to #89. MrChromebox board-level UEFI support
does not override these accepted device roles or authorize firmware changes.

## Local and hosted validation

```sh
python3 -m unittest discover -s dragonfly-jit/tests -p 'test_redrix_continuity_health.py' -v
```

Unit tests use synthetic data and disposable temporary directories.
They assert fail-closed stale-control-map, jitter/offline, each controller
state/schema/marker/job-ownership field, missing or oversized/nonregular
state, run-entry contamination, parent symlinks, missing Tailscale health,
minimum samples, subprocess timeout, sanitized error output, absent service,
KVM, and live QEMU cases.
The regular Dragonfly hosted workflow already runs the Dragonfly test
directory; no new workflow trigger/permission or schedule is needed.

Before a live use, verify the exact source commit and independent review
and run from a controlled checkout; this is not yet an accepted installed
operator tool. If an actual reboot/restart recovery proof is needed,
stage it separately under #192 with owner approval for the specific
consequential action, not as a side effect of this helper.
