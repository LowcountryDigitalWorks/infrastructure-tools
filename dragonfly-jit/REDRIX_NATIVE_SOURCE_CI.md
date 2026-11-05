# REDRIX native source CI — private checkout proof (no GitHub runner)

Work item: infrastructure-tools #96. Existing queue, authentication, JIT and protected publication remain owned by #10 / #139.

This is a **one-shot, normal-user, public-main-only source verification** helper for the existing ChromeOS → Crostini Debian 13 (`penguin`) system. It makes no ChromeOS installation, firmware, Developer Mode, Powerwash, or memory-allocation changes.

## Why

REDRIX's interactive Crostini shell was observed with `umask 0002`. A normal disposable Git checkout inherited group-writable `0664` source files. Dragonfly's accepted `ssh_forced_receiver.py` and `canary_executor.py` correctly refused these files with `*_SOURCE_UNTRUSTED` despite matching Git object hashes.

In a separate temporary **process-scoped `umask 0077`** checkout, the same exact accepted source passed all 136 existing Dragonfly Python tests. This helper formalizes that narrow private checkout proof without weakening the source mode/owner/hash checks.

## Bounded command

Run from a reviewed checkout of this helper on the owner-controlled REDRIX normal-user Linux session, with an **explicitly verified full 40-character current main SHA**:

```bash
/usr/bin/python3 dragonfly-jit/redrix_native_source_ci.py --head <verified-40-character-main-sha>
```

The script checks that the supplied commit is exactly the current public `LowcountryDigitalWorks/infrastructure-tools` `refs/heads/main` before checkout **and again after testing**, fails closed if it moves, and runs only the fixed Dragonfly Python unittest suite. It returns one sanitized JSON result, never raw test stderr/stdout.

The script:
- refuses root, non-Linux systems, invalid hashes and any moved main;
- sets `umask 0077` only inside this process and restores its prior mask;
- creates and removes one private temporary checkout;
- uses fixed GitHub public URL, fixed tests, bounded subprocess timeouts and no shell command evaluation;
- strips inherited GitHub/provider credentials and arbitrary Git/Python environment settings from subprocesses, limits Git protocol to HTTPS and disables Git hooks/global/system config;
- refuses source files with wrong owners, group/world write or symlink ancestry;
- does **not** install packages, launch QEMU, register a runner, generate JIT credentials, create schedules, change SSH/Tailscale, alter GitHub workflows, update accepted source pins, or promote a CI security class.

Successful local source CI is `PASS_SOURCE_ONLY` only and is **never** GitHub Actions provider-positive job assignment, JIT admission, production/privileged release authorization, or equivalent to an ephemeral nested-KVM guest.

## Validation and controls

```bash
/usr/bin/python3 -m unittest discover -s dragonfly-jit/tests -p 'test_redrix_native_source_ci.py' -q
```

Review the entire diff and run exact-head hosted Dragonfly validation, mandatory security scanning, and influence-clean source review before merging or relying on the tool. REDRIX-native tests are author-side evidence only. Keep the existing 2 GiB guest + 8 GiB host reserve; revisit the memory threshold only upon measured recurring admission failures. Do not attempt to solve source permission hygiene by changing accepted source-integrity checks or global ChromeOS/Crostini security settings.

**Cost:** $0 incremental/included. **Owner action:** none for source QA; runtime GitHub Gate B remains under its separate exact one-off owner authorization and accepted protection gates.
