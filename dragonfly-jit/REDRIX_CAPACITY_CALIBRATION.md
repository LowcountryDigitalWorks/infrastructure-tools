# REDRIX capacity calibration — observer only

## Required interpretation — ChromeOS is not RAM-starved based on Crostini alone

The [owning REDRIX #96 top-of-issue policy](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96) is canonical. REDRIX has **32 GB physical RAM**, and Eddie has **consistently observed ~17–20 GB available RAM on ChromeOS**, rather than a one-time peak. This recurring owner-side historical observation is useful planning evidence, not a same-time attested host telemetry sample. Never add it to guest-visible `MemAvailable` or claim it can all be immediately assigned to a nested guest.

Crostini has separately reported ~9,378 MiB Linux `MemAvailable` with no observed short-window PSI pressure and a present virtio balloon driver. The accepted Linux controller has an idle threshold of **2 GiB nested guest + 8 GiB Linux reserve = 10,240 MiB**. Being below this guest-visible threshold must be described as `GUEST_FLOOR_BELOW_POLICY_NOT_HOST_EXHAUSTION`, **not** as "the Dragonfly has insufficient physical RAM", "ChromeOS has no free memory", "Crostini can never serve JIT", or a reason to stop source/hosted validation, demand additional owner memory screenshots/SSH work, or purchase a new asset. A valid **above-floor** guest reading is likewise not evidence of ChromeOS host capacity or runtime admission.

The passive report codifies the distinction in `memory_sample_scope=CROSTINI_GUEST_VISIBLE_ONLY`, `chromeos_physical_ram_shortage_from_guest=NOT_INFERABLE`, and `guest_idle_memory_floor_disposition`; it always keeps `chromeos_host_corroboration=UNVERIFIED` without an independently accepted host source. Synthetic tests cover both floor outcomes and missing evidence. **The actual protected controller must still refuse launching a 2 GiB guest if its accepted 10,240 MiB guest-visible admission threshold is unmet at that instant.** This observer is not a workaround or permission to overcommit, lower the reserve to 6 GiB, force balloon changes, or consume the Gate B canary.

When guest-only admission blocks an eligible task, **continue the independent source/test and bounded offline load-proof lanes** rather than relabeling the hardware as RAM-starved. Next accepted proof must correlate *during* a bounded workload the ChromeOS host memory/interactivity with Linux pressure, RAM/RSS/OOM, observed balloon activity and cleanup. Only a separately reviewed exact controller/profile/publisher change may revise admission policy. Keep ChromeOS, avoid new spend, and do not re-ask Eddie to explain the same host RAM observation.


Owner: infrastructure-tools #96 / #192; controller #10; Gate B #139.

The original 2 GiB guest plus 8 GiB untouched host reserve was an **initial conservative smoke envelope**, not an empirically optimized allocation for every future CI job. Do not lower the accepted controller limits merely because one idle snapshot has low Linux memory pressure.

## Nov 2026 physical observations (normal-user penguin, read-only)

Authorized passive readback on physical REDRIX (Crostini) recorded approximately **29.5 GiB** total guest-visible memory and **~9.4 GiB** `MemAvailable` at sample time. A **virtio balloon** driver device was present in guest sysfs. Cumulative **`balloon_inflate` / `balloon_deflate` vmstat page counters** showed substantial historical guest page reclaim activity (on the order of millions of 4 KiB pages inflated and hundreds of thousands deflated over the life of the VM). These counters are **cumulative totals**, not the current inflated balloon size and **not** ChromeOS host spare memory. Crostini does not expose trusted host `resourced` spare-RAM readback from this observer.

Memory PSI averages (`some`/`full` avg10) were readable at **0.00** during the observation window on both cgroup and proc interfaces where present. Root cgroup **`memory.events` was absent** on this container layout; absent OOM counters must be reported **UNAVAILABLE**, never fabricated as zero. KVM remained accessible with **zero** QEMU processes; Tailscale/SSH were active. Effective **CAP_SYS_PTRACE / DAC_READ_SEARCH** were absent for the normal-user probe path.

**Interpretation:** guest-visible `MemAvailable` and zero PSI are **necessary but insufficient** for admission or reserve reduction. Balloon vmstat deltas are **indicative guest-VM activity only**. ChromeOS/Crostini host corroboration and guest RSS peaks remain **UNVERIFIED** / **UNMEASURED**.

## Research-only observation

From a trusted, verified, temporary source checkout after independent source review, without starting any runner:

    python3 dragonfly-jit/redrix_capacity_calibration.py --samples 3 --interval-seconds 1

The probe parses only literal memory constants from the adjacent dragonfly_jit.py source and passively reads guest memory/pressure signals, optional virtio balloon **presence** (bounded scan of the fixed kernel driver path for `virtioN` bindings, including normal sysfs symlinks—device index not hard-coded), and cumulative balloon vmstat page counters when exposed. It prefers cgroup memory PSI and falls back to `/proc/pressure/memory` when bounded and readable. Missing cgroup `memory.events` is reported **UNAVAILABLE** (not zero). Valid sampled OOM/oom_kill counters are compared **at every adjacent sample**; a reset/decline, malformed or negative counter reports `HOLD` (`OOM_COUNTER_NONMONOTONIC` or `OOM_COUNTER_INVALID`) and **never clamps a negative delta to zero**. True observed increases are labeled `INCREASED`, not treated as proof of safe capacity. Missing balloon counters are **UNVERIFIED**; malformed or non-monotonic balloon counters yield balloon-specific **HOLD** wording while keeping admission flags false.

Output compares the accepted 2 GiB guest + 8 GiB reserve with a **hypothetical research-only 2 GiB guest + 6 GiB reserve**. Neither result is admission authority: `ci_dispatch_authorized=false`, `jit_admission_authorized=false`, `candidate_is_policy=false`; ChromeOS host corroboration and guest peak remain unverified. An idle threshold comparison does not qualify real workloads. The passive CLI additionally records a bounded `capture_started_utc`/`capture_finished_utc` window in ISO-8601 UTC, duration in milliseconds, and `capture_clock_source=PENGUIN_UTC_WALLCLOCK_UNATTESTED` so a later independently collected ChromeOS-host observation can be dated against the **same guest sampling window**. Clock values come only from untrusted Crostini guest wall time. Missing, reversed, non-UTC or over-60-second intervals fail closed; no system time or ChromeOS API is changed. The observer still reports `chromeos_host_corroboration=UNVERIFIED`: timestamps cannot attest host available memory, balloon deflation or owner interactivity, and the historically owner-observed ~17–20 GB ChromeOS available RAM must not be added to guest `MemAvailable`.

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
