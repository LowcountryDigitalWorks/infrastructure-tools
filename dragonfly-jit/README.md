# Dragonfly disposable KVM host

Work item: `LowcountryDigitalWorks/infrastructure-tools#96`.
Transport design slice: `LowcountryDigitalWorks/infrastructure-tools#115`.
Cross-LDW acceptance/evidence: `LowcountryDigitalWorks/business-operations#552`.
Existing queue/discovery/auth control plane: `ci-dispatch` / issue #10.

This directory is the source-controlled host foundation for the HP Elite Dragonfly
Chromebook REDRIX Crostini execution host. It does **not** register a GitHub
runner, poll GitHub, store a GitHub credential, install a standing task, or alter
workflow routing. LDW01 remains the trusted dispatcher/control owner.

## Local lifecycle

`dragonfly_jit.py` provides a closed local lifecycle surface:

- `verify-base` — verify the exact pinned Debian 13 genericcloud base image;
- `start` — mark Dragonfly capacity locally AVAILABLE after provenance and
  resource admission checks; it does not poll or launch work;
- `drain` — refuse new work; if a guest is active, move to DRAINING and let the
  accepted lifecycle finish; otherwise move to STOPPED;
- `status` — emit only bounded local state/resource/provenance fields;
- `smoke` — run one credential-free disposable QEMU/KVM guest using the pinned
  base, a fresh qcow2 overlay and fresh NoCloud seed, then destroy owned
  transient artifacts;
- `recover` — reconcile only conclusively owned transient state; ambiguous or
  live state fails closed rather than deleting by prefix.

The smoke command exists to exercise the host primitive. It is not a GitHub
Actions runner and is not workload authorization.

## Pinned base

Accepted local base filename:

`debian-13-genericcloud-amd64.qcow2`

Pinned SHA-512:

`3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e`

The image was acquired from Debian's `trixie/latest` genericcloud location and
verified against Debian's published SHA512SUMS during the live feasibility proof.
The mutable `latest` locator is provenance only; runtime trust is the exact digest.
This source does not auto-refresh or silently accept a newer image.

Default local paths use XDG locations and contain no machine address or secret:

- base: `${XDG_DATA_HOME:-~/.local/share}/ldw-jit/base/`
- state: `${XDG_STATE_HOME:-~/.local/state}/ldw-dragonfly-jit/`

The base is never booted directly. Every smoke run uses a fresh qcow2 overlay.

## Safety boundary

- one active local controller/guest maximum via an exclusive file lock;
- exact base digest verification before launch;
- symlink substitution is refused for owned runtime files;
- owned run directories use a fixed marker and manifest schema;
- cleanup may delete only manifest-declared files inside the exact owned run
  directory;
- no host filesystem share, Docker socket, SSH forwarding, public listener, or
  inbound port forward is created by the controller;
- QEMU user-mode networking supplies outbound guest networking without exposing
  an inbound host listener;
- no raw guest console is persisted by the controller;
- no GitHub token, customer data, private repository payload, or provider
  response is accepted by the host foundation;
- ambiguous state enters HOLD/FAILED and requires explicit reconciliation.

The initial conservative smoke envelope is 2 vCPU / 2 GiB RAM, with at least
8 GiB additional Crostini `MemAvailable`, at least 16 GiB free storage, and a
1-minute load average no greater than 70% of visible CPUs. These are admission
bounds, not final production tuning or a stronger workload/security certification.

## Owner controls

`owner_controls.py` is a presentation-only wrapper over the co-installed local
controller. `install_owner_controls.py` installs a user-level copy under
`~/.local/lib/ldw-dragonfly-jit/` and creates **exactly three** Linux application
launchers under `~/.local/share/applications/`:

1. **Start LDW Runner** -> local `start` semantics;
2. **Drain & Stop LDW Runner** -> local `drain` semantics;
3. **LDW Runner Status** -> local `status` semantics.

The launchers use `Terminal=true` and a bounded short linger so the owner can see
the result before the terminal closes. Status renders only the controller's
bounded state/resource fields. Unrecognized fields are not displayed.

The installer is user-level only. It creates no service, daemon, task, schedule,
queue poller, listener, provider integration, credential, auto-recovery path, or
emergency force-stop launcher. If an unexpected `ldw-runner-*.desktop` entry is
already present, installation fails closed instead of deleting it.

Source-tree install/check commands:

```bash
python3 dragonfly-jit/install_owner_controls.py install
python3 dragonfly-jit/install_owner_controls.py check
```

Installation copies the reviewed controller and owner wrapper into the user-level
application directory; the launchers invoke that local copy rather than a mutable
working-tree path.

## Transport-neutral handoff

`handoff_contract.py` is the accepted V6 application-level capsule boundary. It
is deliberately independent of any network transport. It accepts one bounded
closed JSON capsule from stdin, binds the dispatch to the fixed REDRIX target and
exact synthetic job identity, enforces a <=5 minute TTL plus bounded skew, keeps
`opaque_bootstrap` out of sanitized output/replay state, and creates a durable
one-time replay claim under the owner state root.

Authenticated transport never replaces those checks. A future transport must
deliver exactly the already-validated capsule bytes and preserve claim-time
identity/expiry/replay enforcement.

## #115 forced-command SSH source design

Issue #115 records the preferred first authenticated LDW01 -> REDRIX transport
shape, subject to a later sanitized live capability/security readback:

`LDW01/#10 -> private Tailscale reachability -> dedicated OpenSSH key -> fixed forced receiver -> handoff claim`

The source in this slice is intentionally **non-operational**:

- `ssh_transport_contract.py` opens no socket and invokes no process. It validates
  only the exact owner-local non-secret config shape and returns the fixed
  Windows OpenSSH argv plan for later use.
- The plan fixes `C:\Windows\System32\OpenSSH\ssh.exe`, remote user `eddie`,
  port 22, one fixed sentinel command, batch mode, strict host-key checking,
  dedicated known-hosts/private-key paths, identities-only, no agent forwarding,
  clear-all-forwardings, no local command and no TTY. Capsule/bootstrap bytes are
  never represented in argv.
- The private endpoint and trusted ED25519 host-key fingerprint belong only in a
  future owner-local config under `%LOCALAPPDATA%\LDW\CI-JIT\DragonflyTransport`.
  This public repository contains neither value and does not infer that an
  arbitrary endpoint is private/Tailscale-reachable.
- `ssh_forced_receiver.py` opens no listener. It accepts only
  `SSH_ORIGINAL_COMMAND=ldw-dragonfly-jit-handoff-v1`, refuses a CLI surface,
  requires the normal `eddie` Linux identity when used without test injection,
  pins the accepted `handoff_contract.py` Git blob
  `2f7892275bacd9f56abaa0cdf204f46f79c046c0`, then reuses that contract's
  bounded stdin validation and durable claim path. Raw bootstrap is never emitted.

The fixed client sentinel is defense in depth: if a future dedicated key were
accidentally installed without its server-side forced command, the client still
does not request an interactive shell. The future REDRIX key restriction must
independently force the reviewed receiver and disable PTY, agent/X11 forwarding,
TCP/streamlocal forwarding, SFTP/subsystem and arbitrary commands. Exact
`restrict`/authorized-key syntax is **not** accepted by this source alone; #115
requires live verification against the actual REDRIX OpenSSH build first.

This source does not create a key, `known_hosts`, `authorized_keys`, sshd state,
Tailscale/ACL/firewall state, private endpoint, network connection, runner/JIT
registration, service, schedule, or provider call. The separate #98 Operations
Bridge bearer remains owner/GM Status/Start/Drain only and is not reused for JIT
bootstrap material.

## Validation

Source validation:

```bash
python3 -m py_compile \
  dragonfly-jit/dragonfly_jit.py \
  dragonfly-jit/owner_controls.py \
  dragonfly-jit/install_owner_controls.py \
  dragonfly-jit/bridge_adapter.py \
  dragonfly-jit/handoff_contract.py \
  dragonfly-jit/ssh_transport_contract.py \
  dragonfly-jit/ssh_forced_receiver.py

python3 -m unittest discover -s dragonfly-jit/tests -p 'test_*.py' -v
```

The hosted workflow performs these source checks only. It does not use KVM,
OpenSSH networking, Tailscale, secrets, or any self-hosted runner and does not
route work to Dragonfly.

The #115 transport tests verify exact config closure, endpoint/option-injection
refusal, strict host-key/fixed-key/no-forwarding/no-PTY plan construction,
stdin-only capsule posture, fixed-sentinel receiver behavior, bootstrap
sanitization, handoff error sanitization and exact accepted handoff-source blob
pinning. They do not prove private reachability or server-side OpenSSH policy.

## Next gates

1. obtain fresh hosted validation and independence-clean exact-head review of the
   #115 source-only transport contract;
2. from a trusted REDRIX local console, collect the sanitized #115 capability
   readback: exact OpenSSH server version/restriction support, current sshd
   posture, private Tailscale reachability, ED25519 host-key SHA-256 fingerprint,
   owner `.ssh` permission posture, exact receiver/handoff provenance and final
   STOPPED/no-QEMU-residue state;
3. only under separate security/runtime authorization, provision a dedicated
   constrained transport key/known-host identity and prove the forced receiver
   with a synthetic credential-free capsule;
4. integrate one short-lived JIT bootstrap only after exact #10 job re-read and
   accepted transport proof;
5. use a harmless secretless one-job GitHub synthetic profile and require
   provider-positive assignment/start/terminal result plus deterministic runner,
   guest, overlay, seed, bootstrap and state cleanup;
6. obtain fresh independent exact-head review before assigning any stronger
   isolation/security label or routing real private security work.

No production routing, customer/regulated workload, standing poller, public SSH,
generic shell/admin RPC, security weakening, paid capacity, or claim of
Hyper-V-equivalent isolation is authorized by this source slice.
