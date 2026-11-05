# REDRIX capacity calibration — observer only

Owner: infrastructure-tools #96 / #192; controller #10; Gate B #139.

The original 2 GiB guest plus 8 GiB untouched host reserve was an **initial conservative smoke envelope**, not an empirically optimized allocation for every future CI job. Do not lower the accepted controller limits merely because one idle snapshot has low Linux memory pressure.

## Research-only observation

From a trusted, verified, temporary source checkout after independent source review, without starting any runner:

    python3 dragonfly-jit/redrix_capacity_calibration.py --samples 3 --interval-seconds 1

The probe parses only literal memory constants from the adjacent dragonfly_jit.py source and passively reads /proc/meminfo, the cgroup memory pressure gauge and cgroup OOM event counters. Missing or malformed memory/pressure data returns HOLD; unavailable OOM counters are reported as unavailable. It has no command runner, custom file path, privilege, service, network, credential, guest, GitHub, scheduler, or write capability.

Output compares the accepted 2 GiB guest + 8 GiB reserve with a **hypothetical research-only 2 GiB guest + 6 GiB reserve**. Neither result is admission authority: ci_dispatch_authorized=false, jit_admission_authorized=false, candidate_is_policy=false; ChromeOS host corroboration and guest peak remain unverified. An idle threshold comparison does not qualify real workloads.

## Evidence for a lower resource profile

Before requesting a policy adjustment, require a separately designed and reviewed proof with:

- a source-controlled single-job synthetic-only KVM guest, pinned base/image, exact state/lock/teardown and rollback;
- representative actual CPU, RSS, cgroup/host memory pressure, OOM events, disk and boot/runtime peaks before, during and after guest boot and synthetic tests;
- ChromeOS/Crostini host memory and owner-interactivity observation, not Linux MemAvailable alone;
- at least two workload classes (minimal runtime/test and representative CI), with bounded repeatability under normal owner load and failure-induced cleanup;
- no new persistent runner, broad auth, secret/client workloads, privileged changes, scheduler, fallback or new cost;
- independent source/security review and an explicit accepted profile/label change before any production CI/JIT admission.

A hypothetical 6 GiB reserve is a *test hypothesis*, not a recommendation to change a protected operating threshold. Preserve #139's separate V2 and Gate B gates and #10's sole queue/controller authority. No waiver of the LDW01 Hyper-V local 6 GiB floor is implied.
