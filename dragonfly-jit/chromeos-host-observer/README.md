# REDRIX ChromeOS host-memory observer — source-only research proof

**Status: DRAFT / NOT INSTALLED / NOT LIVE ACCEPTED / NO JIT AUTHORITY.**
Owning issues: infrastructure-tools #96 / #139. CI umbrella: business-operations #552.

## Purpose

Actual ChromeOS *host* memory and Crostini Linux MemAvailable are different memory ledgers.
The accepted Dragonfly calibration observer captures only guest-visible memory, PSI and virtio balloon evidence.
Chrome's documented system.memory.getInfo extension API returns physical memory capacity and available capacity in bytes from the Chrome browser's OS context. On REDRIX this would be a **ChromeOS browser-host report**, not Termina/penguin memory, and still not an independently attested host reading.

Reference: https://developer.chrome.com/docs/extensions/reference/api/system/memory

This proof implements a **manual five-sample host-side local readout** using only the system.memory permission.
There is no host permission, service worker, storage, network, analytics, account/token/key, scheduler, ChromeOS policy change, shell, balloon control or privileged operation.
The popup is dark by default with a transient light-mode toggle. Closing the popup discards the observations.

## Strict boundaries

- Status is **HOST_REPORTED_NOT_ATTESTED**. Data is observational, with an untrusted browser wall clock.
- The output does not prove Crostini guest headroom, live runner admission, ChromeOS host attestation, QEMU/runner cleanup, or safety of altering the memory reserve.
- All authorization flags remain false. Do not lower the accepted 2 GiB guest plus 8 GiB reserve floor.
- This pull request does not install or launch an extension on a physical Chromebook or grant any browser/extension permission. Later physical installation is separate, owner-controlled and review-gated.
- Never perform ChromeOS Developer Mode, firmware, Powerwash, SSH or privileged changes to install this proof.

## Validation

From this source folder: node --test tests/observer.test.mjs

Deterministic tests cover positive 5-sample output, byte-to-MiB conversion, invalid/oversized/bool/NaN values, clock/capacity anomalies, provider failures, and a static manifest/code audit for absence of extra permissions, network and persistence.

This source proof is intentionally **not** an authenticated A4 or trusted release issuer. Exact-head CI and author-excluded independent H0/M0 review are required before source acceptance.

## Independent read-only alternative

For a *single* host-side operator observation, ChromeOS Crosh includes a meminfo command that prints host /proc/meminfo where supported. In an existing signed-in ChromeOS session, Ctrl+Alt+T opens Crosh; meminfo is read-only. ChromiumOS source: https://chromium.googlesource.com/chromiumos/platform2/+/03b54c868e08e0839d0aa78c4b157890f8b98bd5/crosh/crosh

The ChromeOS Diagnostics **memory test** and Crosh memory_test run memory tests and are not needed to observe passive available memory.

## Later independent correlation gate (NOT PERFORMED)

After authorized local installation and independent acceptance, capture the ChromeOS host readings near a separately authorized existing penguin guest calibration window. Align source timestamps and sample windows, consider ChromeOS UI responsiveness, check that readings are actually overlapping, and reject impossible/missing/drifting clocks. Neither this host-only report nor a guest-only report authorizes Gate B.

Physical trusted issuer, independent A4 process/FD evidence, immutable protected V2, exact #10 provider job identity, accepted existing guest reserve, #264/#269 trust and residue, and complete teardown all remain independent HOLDs. No new spend.
