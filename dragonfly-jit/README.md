# Dragonfly REDRIX disposable KVM host

Owning work: `LowcountryDigitalWorks/infrastructure-tools#96`.
Quota-independent owner/GM control: `#98`.
Trusted GitHub queue/auth/dispatch authority: `#10`.
Cross-LDW runner/capacity authority: `LowcountryDigitalWorks/business-operations#552`.

This directory is the source-controlled host foundation for the HP Elite Dragonfly
Chromebook REDRIX Crostini execution host. ChromeOS remains the primary device OS;
Linux execution stays inside Crostini. This source does **not** give Dragonfly an
independent GitHub queue selector, broad GitHub credential, standing CI poller, or
production/customer workload authority. LDW01/#10 remains the GitHub auth, queue
re-read, selection and arbitration owner.

## Accepted live foundation

The exact REDRIX/Crostini environment has already proven:

- hardware-backed nested KVM via `/dev/kvm`;
- a pinned Debian 13 genericcloud guest with fresh qcow2 overlay + NoCloud seed;
- controlled cloud-init boot, outbound guest networking and poweroff;
- deterministic overlay/seed cleanup with no QEMU residue;
- exact local controller Start -> AVAILABLE and Drain -> STOPPED;
- exactly three owner launchers installed and proven on REDRIX;
- a transport-neutral synthetic handoff capsule validate/claim/replay proof.

Those proofs establish capability and local lifecycle behavior. They do **not**
certify Hyper-V-equivalent hostile-workload isolation or authorize GitHub runner
routing by themselves.

## Local lifecycle

`dragonfly_jit.py` provides the closed local lifecycle surface:

- `verify-base` — verify the exact pinned Debian genericcloud base image;
- `start` — make local Dragonfly capacity AVAILABLE after provenance/resource
  admission checks; it does not discover or launch GitHub work;
- `drain` — refuse new work and allow accepted active work to finish before
  converging to STOPPED;
- `status` — emit only bounded local lifecycle/resource/provenance fields;
- `smoke` — run one credential-free disposable QEMU/KVM guest, then destroy the
  conclusively owned transient artifacts;
- `recover` — reconcile only conclusively owned local state; ambiguous/live
  state fails closed rather than deleting by prefix.

The smoke operation is a host primitive, not a GitHub Actions runner and not a
workload authorization mechanism.

## Pinned base

Accepted local base filename:

`debian-13-genericcloud-amd64.qcow2`

Pinned SHA-512:

`3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e`

The mutable Debian `trixie/latest` locator is acquisition provenance only.
Runtime trust is the exact digest. This source has no automatic image refresh or
silent replacement path.

Default local paths use XDG/user-local locations and contain no machine address or
secret:

- base: `${XDG_DATA_HOME:-~/.local/share}/ldw-jit/base/`
- lifecycle state: `${XDG_STATE_HOME:-~/.local/state}/ldw-dragonfly-jit/`

The base is never booted directly. Disposable guest work uses fresh overlays.

## Lifecycle safety boundary

- one active local controller/guest maximum via an exclusive guest lock;
- exact base digest verification before guest execution;
- symlink substitution refusal for owned runtime state;
- fixed marker/schema/ownership manifest and UUID run directories;
- cleanup limited to exact manifest-declared artifacts inside the validated owned
  run directory;
- manifest PID + QEMU pidfile + Linux parent-death signal checks;
- no host filesystem share, Docker socket, SSH/host forwarding, public listener,
  inbound port forward, or persisted raw guest console;
- QEMU user-mode networking only for the current disposable host primitive;
- ambiguous lifecycle/cleanup state enters HOLD/FAILED instead of guessing;
- successful Recover converges to STOPPED and requires explicit later Start.

The initial conservative envelope remains 2 vCPU / 2 GiB guest RAM, at least
8 GiB additional Crostini `MemAvailable`, at least 16 GiB free Linux storage and
normalized one-minute load <=70% of visible CPUs. These are admission bounds, not
final production tuning or stronger workload/security certification.

## Owner controls

`owner_controls.py` is a presentation-only wrapper. `install_owner_controls.py`
installs the reviewed controller/wrapper into the fixed user-level application
root and creates exactly three Linux application launchers:

1. **Start LDW Runner** -> `start` only;
2. **Drain & Stop LDW Runner** -> `drain` only;
3. **LDW Runner Status** -> `status` only.

The installer verifies exact copied script bytes and exact launcher contents and
fails closed on unexpected `ldw-runner-*.desktop` entries. It creates no daemon,
service, timer, cron, queue poller, provider integration, credential, Recover
launcher or force-stop launcher.

These controls have been installed and live-proven on REDRIX. Desktop Commander
is not a lifecycle dependency.

## Transport-neutral handoff contract

`handoff_contract.py` is the application-level contract for a future exact
LDW01-selected job handoff delivered over a **separately authenticated** channel.
It does not authenticate a transport by itself.

The contract is closed to a fixed REDRIX target and bounded synthetic profile,
with exact repository/workflow/run/attempt/job/head/job-name/labels identity,
canonical UUIDv4 dispatch ID, <=5 minute TTL and bounded clock skew.

The opaque bootstrap value is bounded but never emitted in sanitized validation
output or persisted replay state. Claim-time validation rechecks identity and
expiry before filesystem mutation.

Replay persistence is fail-closed:

- exclusive claim-file creation refuses duplicate dispatch IDs;
- claim file contents are flushed/fsync'd;
- state-root, claims-directory and claim-file directory entries are fsync'd;
- final claims-directory durability failure leaves the exclusive marker in place,
  so an in-process retry remains `HANDOFF_REPLAY` rather than being treated as
  unclaimed;
- symlink/path substitution is refused.

This contract still contains no network client/listener, GitHub API, provider
call, runner registration, queue polling, QEMU launch, daemon or recurrence.

## Local typed Operations Bridge adapter

`bridge_adapter.py` is the closed local endpoint intended for the separate
DRAGONFLY-BRIDGE-001 owner/GM control path. It accepts one bounded JSON request on
stdin with exactly an empty `arguments` object and one of:

- `dragonfly.runner.status`
- `dragonfly.runner.start`
- `dragonfly.runner.drain`

Production invocation has no caller-controlled executable/path/home/cwd/env/runner
or command override. It verifies the fixed installed controller as a non-symlink
regular file with the exact accepted Git blob before execution, uses fixed
`/usr/bin/python3` + argv/no shell, a minimal environment and bounded timeout.

Status output is projected to bounded lifecycle/resource fields only. PID, run ID,
private paths, arbitrary controller JSON and raw stderr are not forwarded.
Recognized bounded controller errors remain bounded; unexpected internal failures
collapse to `ADAPTER_FAILED` instead of default traceback/path leakage.

The adapter source has independent review acceptance, but its REDRIX local
installation/proof is a separate runtime gate. The merged Operations Bridge core
seam on `main` remains unavailable-by-default until that runtime proof and later
Linux credential/runtime gates are accepted.

## Operations Bridge separation

Owner/GM lifecycle control and CI/JIT bootstrap are deliberately separate:

- owner/GM path: owner-private LDW Operations gateway -> authenticated Operations
  Bridge -> typed REDRIX status/start/drain adapter;
- CI/JIT path: LDW01/#10 exact queue/job selection -> separately authenticated
  narrow handoff -> disposable KVM/JIT guest.

Do not route short-lived JIT bootstrap material through the owner-control Bridge
merely for convenience. Do not turn the Bridge into a generic shell.

## Validation

Source validation:

```bash
python3 -m py_compile \
  dragonfly-jit/dragonfly_jit.py \
  dragonfly-jit/owner_controls.py \
  dragonfly-jit/install_owner_controls.py \
  dragonfly-jit/bridge_adapter.py \
  dragonfly-jit/handoff_contract.py

python3 -m unittest discover -s dragonfly-jit/tests -p 'test_*.py' -v
```

The hosted workflow uses GitHub-hosted runners, read-only checkout permissions and
no persisted checkout credentials. It does not use REDRIX KVM, a self-hosted
runner, a Bridge credential or provider mutation.

## Next gates

### Owner/GM remote control (#98)

1. prove the exact reviewed `bridge_adapter.py` locally on REDRIX;
2. prove a supported protected Linux/Crostini credential mechanism separately;
3. add a fixed Dragonfly Operations Bridge runner/process binding only after those
   gates are accepted;
4. manually prove one outbound typed status round trip, then bounded Start/Drain;
5. only later consider autostart and owner-private Site/relay exposure through
   separately reviewed provider/version changes.

Desktop Commander remains optional troubleshooting/break-glass convenience.

### CI/JIT integration (#96/#10)

1. integrate the fsync-hardened handoff source with the current-main Dragonfly
   source tree and require fresh comprehensive exact-head review;
2. define/prove the narrow authenticated LDW01 -> Dragonfly transport without
   placing broad GitHub authority on Dragonfly;
3. add short-lived JIT/bootstrap material only after transport acceptance;
4. use a harmless secretless synthetic GitHub job first;
5. require provider-positive exact assignment/start/terminal result plus runner,
   guest, overlay, seed and state cleanup;
6. obtain fresh review before stronger workload/security labels or real private
   security work.

No public ingress, generic shell, production/customer/regulated workload, standing
poller, security weakening, paid capacity, or claim of Hyper-V-equivalent
isolation is authorized by this source tree.
