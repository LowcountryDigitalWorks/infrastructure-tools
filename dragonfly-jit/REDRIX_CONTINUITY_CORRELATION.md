# REDRIX R1/R2 cross-endpoint evidence correlation

Owner: infrastructure-tools #192. Related: #96, #139, #98, #115, #10.
This note is source-only. It does not authorize a reboot, a Crostini start,
a Tailscale or SSH change, a runner, a poller, or failover.

The HP REDRIX device stays a ChromeOS/Crostini machine. This repository does
not plan a native Linux wipe. ChromeOS logout stops Crostini, so a Linux-only
sample cannot see pre-login state and must not be described as 24x7 coverage.
A pre-login check can require the owner. Do not promise unattended recovery
from inside the VM.

## What the reconciler is

`dragonfly-jit/redrix_continuity_reconcile.py` compares two injected
dictionaries:

- the accepted local health classification
  (`LOCAL_SERVICES_HEALTHY_UNVERIFIED`, `DEGRADED_HOST`, `DEGRADED_SERVICE`,
  `DEGRADED_NETWORK`, or `HOLD`);
- a future LDW01/provider reachability and owner-session receipt.

It does not read files, call the network, or run device commands. Matching
inputs return `DATA_ONLY_NOT_AUTHORIZED`. They never return `JIT_READY`,
`ONLINE_READY`, or `LOGIN_REQUIRED`. `ci_dispatch_authorized` stays false.
`process_visibility` stays `UNVERIFIED`. A simulated provider flag may set
`peer_side_corroboration` to `SIMULATED_FIELD_ONLY`; that is still not an
authenticated channel. JSON alone is not a live Tailscale, SSH, or ChromeOS
session.

The fixed device id is the synthetic fixture
`synthetic-redrix-continuity-fixture`. A caller-chosen id does not select
another machine.

## R1 readback matrix

Run a row only after a separate owner-approved, non-destructive proof.
Do not reboot, Powerwash, or change firmware as part of this source.

| Check | When | Allowed observation | Not claimed |
| --- | --- | --- | --- |
| ChromeOS session | Before login and after login | Owner records whether the screen is waiting for login | Linux code does not infer this |
| Crostini | After the owner starts Linux manually | Local health script may then be run by hand | Logout or a stopped VM is not a Linux result |
| Tailscale and SSH | While Crostini is up | Active/enabled and self-online categories only | No peer addresses or keys |
| Secret Service | Locked and unlocked states the owner chooses to inspect | Locked vs unlocked as an owner note | No secret material |
| LDW01 / HostAgent | Separate external corroboration | A second receipt with the same nonce and boot id | One side does not authorize dispatch |
| A4 process view | Only an accepted Gate A4 proof | Absence stays `UNVERIFIED` | Normal-user pgrep is not A4 |
| QEMU / JIT residue | Same manual health read | Residue is `DEGRADED` or `HOLD` | No cleanup action |
| Reboot | Not part of this packet | Requires its own gate | Do not reboot to collect this table |

## R4 failover options

Do not enable any of these until a later reviewed design says so.
REDRIX must not hold GitHub queue credentials or run a second poller.

1. One central lease. A controller outside REDRIX names the single executor.
   REDRIX stays compute-only. Ambiguous lease is `SPLIT_BRAIN` and does not fail over.
2. Sealed standby. REDRIX keeps a dormant controller that starts only with an
   explicit leased token, then stops on failback. No token is defined here.
3. Second controller elsewhere. Another reviewed node owns the queue, and
   REDRIX only executes. Two active dispatchers are a split brain.

Loss of LDW01 is not, by itself, permission for REDRIX to dispatch.

## Validation

```sh
python3 -m unittest discover -s dragonfly-jit/tests -p test_redrix_continuity_reconcile.py -v
```

The Dragonfly source workflow already discovers `dragonfly-jit/tests/test_*.py`.
No workflow, timer, or service is added.
