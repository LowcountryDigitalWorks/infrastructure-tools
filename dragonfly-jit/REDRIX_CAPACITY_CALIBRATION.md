# REDRIX capacity calibration — observer only

Owner: infrastructure-tools #96 / #192; controller #10; Gate B #139.

The original 2 GiB guest plus 8 GiB untouched host reserve was an **initial conservative smoke envelope**, not an empirically optimized allocation for every future CI job. Do not lower the accepted controller limits merely because one idle snapshot has low Linux memory pressure.

## Nov 2026 physical observations (normal-user penguin, read-only)

Authorized passive readback on physical REDRIX (Crostini) recorded approximately **29.5 GiB** total guest-visible memory and **~9.4 GiB** `MemAvailable` at sample time. A **virtio balloon** driver device was present in guest sysfs. Cumulative **`balloon_inflate` / `balloon_deflate` vmstat page counters** showed substantial historical guest page reclaim activity (on the order of millions of 4 KiB pages inflated and hundreds of thousands deflated over the life of the VM). These counters are **cumulative totals**, not the current inflated balloon size and **not** ChromeOS host spare memory. Crostini does not expose trusted host `resourced` spare-RAM readback from this observer.

Memory PSI averages (`some`/`full` avg10) were readable at **0.00** during the observation window on both cgroup and proc interfaces where present. Root cgroup **`memory.events` was absent** on this container layout; absent OOM counters must be reported **UNAVAILABLE**, never fabricated as zero. KVM remained accessible with **zero** QEMU processes; Tailscale/SSH were active. Effective **CAP_SYS_PTRACE / DAC_READ_SEARCH** were absent for the normal-user probe path.

**Interpretation:** guest-visible `MemAvailable` and zero PSI are **necessary but insufficient** for admission or reserve reduction. Balloon vmstat deltas are **indicative guest-VM activity only**. ChromeOS/Crostini host corroboration and guest RSS peaks remain **UNVERIFIED** / **UNMEASURED**.

## Research-only observation

From a trusted, verified, temporary source checkout after independent source review, without starting any runner:

    python3 dragonfly-jit/redrix_capacity_calibration.py --samples 3 --interval-seconds 1

The probe parses only literal memory constants from the adjacent dragonfly_jit.py source and passively reads guest memory/pressure signals, optional virtio balloon **presence** (bounded scan of the fixed kernel driver path for `virtioN` bindings, including normal sysfs symlinks—device index not hard-coded), and cumulative balloon vmstat page counters when exposed. It prefers cgroup memory PSI and falls back to `/proc/pressure/memory` when bounded and readable. Missing cgroup `memory.events` is reported **UNAVAILABLE** (not zero). Missing balloon counters are **UNVERIFIED**; malformed or non-monotonic balloon counters yield balloon-specific **HOLD** wording while keeping admission flags false.

Output compares the accepted 2 GiB guest + 8 GiB reserve with a **hypothetical research-only 2 GiB guest + 6 GiB reserve**. Neither result is admission authority: `ci_dispatch_authorized=false`, `jit_admission_authorized=false`, `candidate_is_policy=false`; ChromeOS host corroboration and guest peak remain unverified. An idle threshold comparison does not qualify real workloads.

## Evidence for a lower resource profile

Before requesting a policy adjustment, require a separately designed and reviewed proof with:

- a source-controlled single-job synthetic-only KVM guest, pinned base/image, exact state/lock/teardown and rollback;
- representative actual CPU, RSS, cgroup/host memory pressure, OOM events, disk and boot/runtime peaks before, during and after guest boot and synthetic tests;
- ChromeOS/Crostini host memory and owner-interactivity observation, not Linux MemAvailable alone;
- at least two workload classes (minimal runtime/test and representative CI), with bounded repeatability under normal owner load and failure-induced cleanup;
- no new persistent runner, broad auth, secret/client workloads, privileged changes, scheduler, fallback or new cost;
- independent source/security review and an explicit accepted profile/label change before any production CI/JIT admission.

### Two-step validation plan (not authorized by this document)

1. **Research-only comparison (existing observer):** run the passive probe under normal owner load; compare accepted **2+8** floor vs hypothetical **2+6** research profile. Record indicative balloon vmstat deltas and PSI; **do not** treat as admission.
2. **Separately reviewed nested proof:** bounded synthetic **2 GiB** nested KVM guest under owner-active representative load; collect pre/during/after guest QEMU RSS, PSI/OOM, ChromeOS owner-interactivity and **host-side corroborated** memory **if obtainable** from outside Crostini; verify teardown and no residue. Update trusted controller constants and **all** dependent blob pins only after distinct review/security sign-off—never silently lower the protected **8192** MiB reserve.

**Rollback / protection:** preserve ChromeOS memory pressure safeguards; do not change Termina VM memory settings or third-party tools without physical ChromeOS host proof. Do not treat ChromeOS standby/swap surfaces as free headroom.

A hypothetical 6 GiB reserve is a *test hypothesis*, not a recommendation to change a protected operating threshold. Preserve #139's separate V2 and Gate B gates and #10's sole queue/controller authority. No waiver of the LDW01 Hyper-V local 6 GiB floor is implied.
