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

The script checks that the supplied commit is exactly the current public `LowcountryDigitalWorks/infrastructure-tools` `refs/heads/main` before checkout **and again after testing**, and fails closed if it moves. The default remains the original fixed Dragonfly Python unittest suite. It also accepts exactly two **additional, fixed-name, source-reviewed local proof profiles**:

| `--suite` | Bounded work | Network and execution boundary |
| --- | --- | --- |
| `dragonfly` (default) | Existing Dragonfly Python source contract tests | Source-only local, no QEMU or provider |
| `chat-relay` | Standard-library Chat Relay tests | Temporary `127.0.0.1` loopback-only sockets close during tests; no public listener or standing service |
| `browser-static` | Static Browser Isolation boundary tests | No Docker container, network probe or live browser |
| `all` | All three exact reviewed suites in fixed Dragonfly → Chat Relay → Browser-static order, one private checkout | Preflights all pinned source files before tests, then runs each in a bounded (120s) subprocess; no JIT/provider action |

Examples from a reviewed helper checkout, replacing the hash with exact current verified main:

```bash
/usr/bin/python3 dragonfly-jit/redrix_native_source_ci.py --head <verified-40-char-main-sha> --suite chat-relay
/usr/bin/python3 dragonfly-jit/redrix_native_source_ci.py --head <verified-40-char-main-sha> --suite browser-static
```

The fixed `--suite all` option is intended for routine one-shot REDRIX source CI: one exact current-main checkout, **all three** approved file/ownership checks *before* any tests, three fixed commands, one final main-identity recheck, and one sanitized aggregate report. It returns `suite_counts` and `tests_passed` only after every suite passes; a single failed/missing/changed source or a moved main returns `HOLD` with no partial PASS. No new GitHub runner, scheduler, credential or mutable workflow authority is created.

```bash
/usr/bin/python3 dragonfly-jit/redrix_native_source_ci.py --head <verified-40-char-main-sha> --suite all
```

`--suite` argument uses a closed parser choice, **not** a caller-selected script, executable, test directory, URL, checkout or environment. Each profile has a fixed `/usr/bin/python3 -m unittest discover` command and fixed source ownership/mode/symlink pins, with the existing one-time, private uncredentialed checkout/cleanup. All profiles emit one sanitized result without raw test stderr/stdout and **never grant GitHub/JIT authority**. The limited source file-mode checks are not equivalent to verifying an arbitrary repository tree and must not be reused as untrusted-PR admission.

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
