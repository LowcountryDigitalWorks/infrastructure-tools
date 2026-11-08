# REDRIX offline single-guest capacity benchmark

Status: SOURCE-ONLY DRAFT. Not a physical run, not #139 Gate B, and not a change to the protected 2 GiB guest plus 8 GiB reserve controller.

The module plans one fixed offline experiment: a 2 GiB, 2 vCPU disposable guest, no network, no SSH, and a 210 second bound. The research memory floor is 8192 MiB (`2048 + 6144`). The accepted controller floor stays 10240 MiB. `dragonfly_jit.py` is not imported and is not modified. Its expected git blob is `dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a`.

`main` always returns a refusal. QEMU is not spawned by this draft. A later one-shot still needs an independent exact-head review, hosted source, secret scan, and CodeQL success, a merge, and a separate ORCH runtime admission. Until `subprocess` is bound in a reviewed change, a passing injected evidence result only means the decision table accepted a fake outcome.

The experiment must take the controller's existing `guest.lock`, use its own overlay, and fail closed on symlink, lock collision, an existing QEMU process, controller state other than `STOPPED` or `AVAILABLE`, a base SHA-512 or controller blob mismatch, any memory sample below 8192 MiB, PSI or balloon movement, a missing OOM counter, or a CPU or disk miss. Uncertain child ownership keeps evidence. It does not delete an overlay it does not own.

ChromeOS host capacity is not evidence for the Crostini guest. Privileged A4, the protected V2 publisher, and the GitHub provider gate stay outside this module.
