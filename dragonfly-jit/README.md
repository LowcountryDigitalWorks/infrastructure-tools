# Dragonfly disposable KVM host

Work item: `LowcountryDigitalWorks/infrastructure-tools#96`.
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
  inbound port forward is created;
- QEMU user-mode networking supplies outbound guest networking without exposing
  an inbound host listener;
- no raw guest console is persisted by the controller;
- no GitHub token, JIT configuration, customer data, private repository payload,
  or provider response is accepted by this slice;
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

## Validation

Source validation:

```bash
python3 -m py_compile \
  dragonfly-jit/dragonfly_jit.py \
  dragonfly-jit/owner_controls.py \
  dragonfly-jit/install_owner_controls.py

python3 -m unittest discover -s dragonfly-jit/tests -p 'test_*.py' -v
```

The hosted workflow performs these source checks only. It does not use KVM or any
self-hosted runner and does not route work to Dragonfly.

## Next gates

After the owner-control source and local installation behavior are independently
reviewed and proven on REDRIX:

1. define the authenticated **LDW01 -> Dragonfly** exact host-target handoff
   without copying broad GitHub auth to Dragonfly;
2. add a harmless secretless one-job GitHub synthetic profile;
3. prove provider-positive one-job assignment/start/success plus interruption,
   duplicate-launch refusal, drain and destructive cleanup;
4. obtain fresh independent exact-head review before assigning any stronger
   isolation/security label or routing real private security work.

No production routing, customer/regulated workload, standing poller, security
weakening, paid capacity, or claim of Hyper-V-equivalent isolation is authorized
by this source slice.
