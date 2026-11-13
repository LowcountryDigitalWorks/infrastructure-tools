# REDRIX host and guest memory evidence correlation — offline research only

Owning issue: https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96. Gate B: #139. Controller: #10.

## Purpose and proof boundaries

REDRIX (HP Elite Dragonfly Chromebook, 32 GiB physical RAM) has two different memory ledgers:

- ChromeOS host: the separate Chrome system.memory API reports physical capacity and available bytes from the Chrome browser OS context. The accepted PR #308 popup produces five local transient measurements. Its clock, host identity and available capacity semantics are not independently attested.
- Crostini guest: the accepted redrix_capacity_calibration.py measures Linux MemAvailable and PSI, samples virtio balloon counters, and compares the accepted 2,048 MiB nested guest + 8,192 MiB Crostini-visible reserve = 10,240 MiB minimum. Balloon net-page estimates are neither ChromeOS host available RAM nor permission to change balloon state.

Official Chrome API: https://developer.chrome.com/docs/extensions/reference/api/system/memory
Merged source observer: https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/308

This standard-library read-only helper compares independently captured JSON exports only. It never reads host system state itself, launches QEMU, manipulates memory or calls GitHub. It does not install an extension. Inputs, browser and Crostini wall clocks, and device identity are untrusted. Even overlapping UTC windows do not establish host identity, memory causality, durable admission or trusted A4.

## Bounded offline invocation

Only after a real ChromeOS Chrome user-level observer installation and independently witnessed owner session:

1. Collect the host JSON from ChromeOS Chrome's Measure host memory popup. Keep the file private; never commit real captures to GitHub. The popup retains no history.
2. Separately run the accepted bounded guest observer from a verified temporary checkout under normal Linux user, ideally overlapping with the host popup capture:

       python3 -B dragonfly-jit/redrix_capacity_calibration.py --samples 3 --interval-seconds 1

3. Save each JSON to a local private folder. Run this offline helper on a reviewed checkout:

       python3 -B dragonfly-jit/redrix_host_guest_evidence.py --host /private/host.json --guest /private/guest.json

The helper accepts two regular non-symlink files of at most 32 KiB each, rejects duplicate JSON keys and nonfinite numeric tokens (including finite-size exponent overflow to infinity), JSON nesting greater than 64 levels and integer/float numeric tokens longer than 40 characters, validates source markers, observed scopes, false authority flags, production memory profile, summary integrity and bounded timestamp sequence. It never prints raw input, file content, paths, addresses or credentials. On errors it prints only an enumerated sanitized HOLD reason. It writes no artifacts.

The minimum timestamp overlap is 1,000 ms on the two UNATTESTED wall clocks. The host browser's millisecond ISO timestamps and elapsed field must match exactly. The accepted guest producer calculates elapsed from microsecond clock values but serializes timestamps to milliseconds, so the offline validator permits at most 1 ms quantization difference for the guest capture only. This tolerance does not attest synchronized clocks or authorize a policy change. A positive result is explicitly WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED; it is not GATE_B_PASS, CHROMEOS_HOST_ATTESTED or READY. A no-overlap or implausible capture is HOLD. This helper rejects a frozen browser wall clock (capture less than 3,000 ms), unlike PR308's intentionally permissive source-only popup. Production memory thresholds do not change.

Even exact UTC overlap cannot prove that the two clocks are synchronized, that readings came from the same physical Chromebook, or that the two different memory ledgers share a memory model. A security-approved host/device/time attestation and real workload proof would be independent future work.

## Non-negotiable restrictions

ci_dispatch_authorized=false, jit_admission_authorized=false, memory_policy_change_authorized=false on every output, including observed overlap. Production protected controller is authoritative; this passive helper may not be plugged into its admission path. Any future memory policy change needs separately accepted identity/time proof, real host/guest workload peaks and security review. This tool does not resolve #186 protected issuer, #264 retained CI7 guest, #269 immutable controller trust, independent Linux A4, V2 installed receiver, or exact #10 GitHub provider one-job lifecycle/cleanup.

Owner approved normal ChromeOS browser-extension installation, NOT ChromeOS OS Developer Mode, firmware/wipe, privileged root services, or memory policy changes. No spending, new accounts, credentials, background schedules, host networking, client data or live system mutations are introduced by this source-only helper.

## Source validation

       python3 -m unittest discover -s dragonfly-jit/tests -p test_redrix_host_guest_evidence.py -v

Twelve synthetic/adversarial tests cover bounded overlap, nonoverlap, above/below memory threshold with false admission flags, forged scope/status/permission, replayed or frozen timestamps, invalid profile, impossible memory totals, duplicate/nonfinite JSON, oversized/symlinked files, genuine guest microsecond-to-millisecond quantization, boolean schema/summary spoofing and secret-containing input without output reflection.

Exact-head GitHub CI/security and author-excluded independent H0/M0 review are required before merge; source approval does not authorize physical deployment or JIT.
