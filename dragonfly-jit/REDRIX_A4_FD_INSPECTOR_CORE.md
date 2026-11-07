# REDRIX Gate A4 — FD inspector core (source-only)

**Status: DATA-ONLY / NOT RUNTIME AUTHORITY / NOT MERGED UNTIL INDEPENDENT REVIEW**

`tools/dragonfly_gate_a4_fd_inspector_core.py` is a fixed, non-authorizing proc/FD inspection core for [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139). It does not replace or modify pinned `tools/dragonfly_gate_a0.py` or `tools/dragonfly_gate_a4.py`. There is no `__main__`, CLI, provider channel, network, shell, install path, or production A4 integration in this slice.

Effective **UID** is read only from `/proc/<pid>/status` (`Uid:` real/effective/saved/fs), not from `/proc/stat` (field 14 is **utime**) and not from `/proc/<pid>` directory ownership (which may become **root:root** for non-dumpable processes). Paired FD readback binds stable **PID, all four status UIDs, and starttime**; **utime** may change between samples. Synthetic output marks **`complementaryA0QemuEnumerationRequired: true`** because accepted A0 still performs mandatory all-PID QEMU enumeration at runtime.

Successful synthetic zero-QEMU/zero-KVM-FD inspection returns **`DATA_ONLY_NOT_AUTHORIZED`** only. It never returns runtime A4 PASS, root attestation, or privileged channel authentication. Continuous `/proc` churn on Linux may produce conservative **`HOLD`** between paired snapshots; future **pidfd** anchoring may be required for stronger live-host stability.

Deterministic negatives and the clean fixture are exercised in `tests/dragonfly-canary-publication/test_gate_a4_fd_inspector_core.py` against the matrix in `dragonfly-jit/REDRIX_A4_PRIVILEGED_FD_PROOF_CONTRACT.md`.
