# REDRIX Operations Bridge systemd lifecycle

This directory contains the reviewed **source-only** system-manager lifecycle for the REDRIX Operations Bridge.

It does not authorize runtime installation, credential migration, service enablement, service start, provider changes, Tailscale/SSH changes, JIT work, or customer/private workload execution.

## Architecture

```text
Crostini starts
  -> system manager loads an encrypted `bridge-bearer` credential
  -> payload runs as `eddie` / uid 1000
  -> existing `--dragonfly-run` Bridge connects outbound to the fixed relay
```

The normal foreground Bridge path remains unchanged: when `LDW_DRAGONFLY_CREDENTIAL_SOURCE` is absent, `--dragonfly-run` uses the accepted Secret Service lookup. The system unit sets the fixed non-secret selector `LDW_DRAGONFLY_CREDENTIAL_SOURCE=systemd`; the bearer itself is supplied only through `LoadCredentialEncrypted=` and systemd's per-unit credential directory.

## Fixed paths

- Unit: `/etc/systemd/system/ldw-operations-bridge-dragonfly.service`
- Encrypted credential: `/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred`
- Decrypted per-unit credential: `/run/credentials/ldw-operations-bridge-dragonfly.service/bridge-bearer`
- Bridge package root: `/home/eddie/.local/lib/ldw/operations-bridge/dragonfly`
- Bridge config: `/home/eddie/.config/ldw/operations-bridge/dragonfly/config.json`
- Bridge state: `/home/eddie/.local/state/ldw/operations-bridge/dragonfly`
- Dragonfly controller state: `/home/eddie/.local/state/ldw-dragonfly-jit`
- Credential lifecycle serialization lock: `/run/user/1000/ldw-operations-bridge-dragonfly-credential.lock`

The system unit keeps the home directory read-only except for the fixed Bridge state and fixed Dragonfly controller state. The owner-local credential lifecycle lock under `/run/user/1000` is used only by the separately gated migration helper and is not a service writable-path exception.

## Source helpers

`operations-bridge/scripts/redrix-systemd-bridge-credential.py`

- `migrate` — takes an owner-local exclusive operation lock, reads the accepted Secret Service item through the fixed lookup, encrypts it directly through an OS pipe with the host systemd credential key, publishes the encrypted artifact without clobbering an existing path, retains the published inode identity, verifies equality by digest, and leaves Secret Service unchanged.
- `verify` — under the same serialization lock, compares the current Secret Service value and decrypted encrypted artifact by digest without printing either value and requires stable credential identity across verification.
- `rollback` — only while the service is conclusively inactive/disabled and under the same lock, verifies equality and removes the encrypted artifact only if its identity is unchanged. Secret Service remains the rollback source.
- Any post-publication verification or temporary-cleanup failure unwinds only the matching published credential identity; an identity replacement is refused rather than deleted.

`operations-bridge/scripts/redrix-systemd-bridge-service.py`

- `preflight` — verifies the exact unit source, **every file** in the installed Bridge payload against the package manifest with no missing/extra payload files, fixed config, root-only encrypted artifact metadata, and a conclusively inactive/disabled or not-yet-installed unit state.
- `install` — installs only the exact unit and performs `daemon-reload`; it does **not** enable or start the service.
- `verify` — verifies the installed unit, complete package provenance, credential metadata, inactive/disabled state, and `systemd-analyze verify`.
- `rollback` — removes only the exact reviewed unit while conclusively inactive/disabled, then performs `daemon-reload`.

All helper output is bounded PASS/HOLD classification. No bearer, bearer digest, private key, provider token, endpoint credential, or Secret Service content is emitted.

## Required future runtime sequencing

A separately owner-authorized runtime gate should fail closed on any drift and use this order:

1. Fresh read-only REDRIX preflight: accepted Bridge package/config, complete payload manifest equality, Secret Service item available, systemd host credential key present/private, Bridge not running, target unit absent or exact/inactive/disabled, and accepted Dragonfly controller state path available.
2. `redrix-systemd-bridge-credential.py migrate`
3. `redrix-systemd-bridge-credential.py verify`
4. `redrix-systemd-bridge-service.py preflight`
5. `redrix-systemd-bridge-service.py install`
6. `redrix-systemd-bridge-service.py verify`
7. Re-read foreground Secret Service path to prove rollback remains intact.
8. **Stop for a separate enable/start gate.** Installation alone does not enable or start the service.

Only after those artifacts are accepted should a later gate enable/start the exact unit and prove the Bridge connects, exposes only the accepted typed operations, survives a bounded restart, and can be rolled back without deleting the Secret Service source until unattended lifecycle acceptance is complete.

## Fail-closed boundaries

- Unknown selector or credential directory: credential unavailable; no fallback.
- Existing encrypted credential path: migration refuses to clobber it.
- Concurrent credential lifecycle operation: HOLD.
- Published credential identity replacement: HOLD; cleanup refuses to delete the replacement.
- Ambiguous/failed systemd state query: HOLD.
- Active, activating, failed, masked, static, generated, or otherwise non-disabled target unit: HOLD.
- Installed package manifest, any payload file, or payload file set mismatch: HOLD.
- Unit source/hash/metadata mismatch: HOLD.
- Credential directory/file metadata mismatch: HOLD.
- Encryption/decryption/digest/process timeout: HOLD.
- Secret Service is never cleared or rewritten by these helpers.
- No helper calls `systemctl enable`, `start`, `restart`, or `--now`.
