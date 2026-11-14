# REDRIX Gate A4: descriptor-bound fixed package reader (source only)

**Status: REAL READ-ONLY FILESYSTEM SOURCE; NO PROTECTED INSTALL, NO ROOT ISSUER, NO A4 OR JIT AUTHORITY.** Owning issues: [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96). This is a bounded source implementation, not an active launcher.

## Fixed contract

`tools/dragonfly_gate_a4_fixed_package_verify.py` uses real Linux `open`/`fstat`/`stat`/`read` syscalls (O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC, parent-directory file descriptors) against ONLY fixed `/usr/libexec/ldw-redrix-a4/dragonfly_gate_a4_live_evidence.py` from its public `observe_fixed_package()` entrypoint. It requires root UID/GID ownership, non-writable ancestors and leaf, one hardlink, stable descriptor/path identity before and after reading, fixed exact 8107-byte length, accepted Git blob `a939c5204f3164a6e21dc8c6998260332d1ffd24` and SHA256 `da0f4ea038cc623424bdff16b0971b15ddbc0babc541b7094c0c1d1a6030cdcc` of the existing accepted A4 collector at infrastructure-tools main 83b88ad677d3c6d833bb2fb976711572fdd4fdd7. The bytes are **never imported or executed**.

Failures are bounded sanitized reason codes, not raw paths, exception text, process identities or secrets. Both deployment flags are hardcoded false and there is no CLI, sudo, subprocess, socket, root helper install or physical mutation. EVERY result, including a completely matching fake or real package, has `a4Pass=false`, `runtimeAuthority=false`, `privilegedChannelAuthenticated=false`, `jitAdmissionAuthorized=false`, `physicalExecutionAuthorized=false` and `protectedInstallAuthorized=false`.

## Why this is not yet an independent root issuer

[Independent #139 challenge](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6867926496) returned DESIGN_BLOCKED_NEW_OWNER_POLICY H2/M1/L0: compromised UID1000 with unrestricted NOPASSWD ALL can obtain root and replace any alleged protected package/replay store. An accepted owner-controlled Linux privilege-policy/bootstrap change is required before future file identity checks can mean independent provenance. Do not silently change sudoers or interpret a source pin as authorization.

Still missing and explicitly HOLD: external independently trusted first-install issuer and protected interpreter/dependencies; real fixed no-argument launcher; verified receiver-measured one-shot channel (SO_PEERCRED alone is insufficient); nonce/TTL/replay/peer PID/starttime/pidfd binding; real effective capabilities in matching user/PID/mount namespaces; complete paired process/FD readback without inaccessible entries, races or renamed-QEMU evasion; exact current UID1000 A4 pairing and teardown. There is NO positive physical A4 observation here.

## Validation

`tests/dragonfly-canary-publication/test_a4_fixed_package_verify.py` contains 27 normal-user Linux hostile tests using only temporary fake root trees. Test-only path/UID injection is not a runtime admission API and remains non-authorizing. Require hosted exact-head Dragonfly tests, Secret Scan, CodeQL JS/C# and a distinct author-excluded H0/M0 review before any source-only merge. No physical install or elevated test is authorized.

Independent gates remain Windows #186/#269, CI7 retained VM #264, accepted 10240 MiB Crostini-visible floor, ChromeOS host browser measurement, separate #10 GitHub job and #139 single conditional one-shot secretless JIT and cleanup. No new spend, recurring schedule, VM/QEMU, SSH, firmware, ChromeOS developer mode or memory policy changes.
