# Genuine Chromium inside external network-none guest — synthetic proof (#210)

**STACKED SOURCE PROOF / NOT A PRODUCTION BROWSER.** This is a new downstream slice from `browser-isolation/` PR #224's reviewed candidate. It does **not** change parent files or the blocked in-browser-only PR #211. Gate A parent #224 must be independently accepted before this child is eligible for its own review/merge.

## What it proves when hosted CI passes

- Runs **real Chromium**, not a mocked Playwright route, inside Docker `--network=none` with immutable image-ID admission, non-root user, read-only rootfs, no mount/host profile/Docker socket, no external ports, no host IPC, no capabilities and bounded resources.
- Browser uses an embedded `127.0.0.1` standard-library HTTP fixture. Positive proof must navigate, fill, click, read DOM and generate screenshot digest with an actual browser.
- The same browser attempts `navigator.sendBeacon`, link `ping`, `fetch(keepalive)`, WebSocket, image resource and Service Worker fetch to a synthetic private **host-side** listener. It also tries a 302 redirect off-guest. A direct Node TCP attempt inside the same guest is a baseline; failed host TCP is mandatory.
- Host listener is bound **only** to Docker's private bridge address on the ephemeral disposable GitHub runner. The host first proves the listener actually receives its own positive connection, then asserts **zero additional connections** after guest/browser exit. This host-side readback—not browser interception counts alone—is the negative control.
- Guest requires `chromiumSandbox: true` for the non-root browser. **No automatic `--no-sandbox` fallback**. A Docker engine, user namespace, seccomp, or Chromium incompatibility returns NO_START, not a fabricated PASS. `sandbox_requested: true` is a command-contract check, not full kernel attestation of a browser sandbox. Browser sandbox needs separate independent audit.
- It uses Microsoft's published [Playwright 1.64.1 Ubuntu Noble image](https://mcr.microsoft.com/en-us/artifact/mar/playwright/tag/v1.64.1-noble) pinned to OCI index `sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f`; matching JavaScript package `playwright@1.64.1` is installed in the **build phase** using public npm. Container **runtime** cannot reach npm or any host/internet address. Immutable build inputs and npm integrity lock still require separate source-chain review before production.

## Exact code boundaries

- `probe.js`: only synthetic local pages, ephemeral guest-side HTTP service and fixed off-guest attempt vectors; no owner login, profile, credentials, real target URLs, persistent listener or model-supplied command.
- `host_proof.py`: fixed Docker flags, expected exact locally built image SHA, synthetic Docker-bridge host socket and post-run independently checked host connection count; never prints raw Chromium stderr, page content or attempted addresses.
- `Dockerfile`: pinned upstream version+digest, non-root uid 10001, no browser package at runtime download.
- `test_host_proof.py`: strict command admission, mandatory vector set and evidence-schema negatives.
- `.github/workflows/browser-chromium-isolated.yml`: disposable Ubuntu PR-only job, normal contents:read GitHub token, public base-image download and source build.

**All successful outputs are labelled `SYNTHETIC_GUEST_ONLY`**. While the guest intentionally attempts to contact the disposable **host-side fixture** and documentation-range address, Docker network-none should prevent actual contact. No real external website is ever visited or requested. Source/CI result is not a production host sandbox authorization.

## HARD RELEASE HOLDS

- Existing PR #211 empirical H2/M3/L6 remains **CHANGES_REQUIRED** until the actual first-party controller is run **inside a reviewed sandbox** and independent adversarial tests verify every bypass against real socket/packet evidence, including navigation cancellation, Service Worker persistence, browser process descendants, host DNS and redirect races.
- Real untrusted-web browsing requires a separately reviewed Chrome sandbox/user namespace+seccomp policy and immutable browser image/dependency integrity, signed owner/device identity, allowed domain/redirect policies, external private-network protection, browser-profile isolation, auth/IPC, action approval, screenshot/content redaction, time/CPU/storage budgets, and clean teardown. The official Playwright test image is **not recommended for untrusted sites** by its maintainers. This fixture is *trusted*, synthetic and finite.
- This source does not establish ordinary ChatGPT Chat custom MCP availability, plug-in connection, login, or recipient wake. It does not authorize a real website, owner system, customer/PHI/CUI material or protected runner.
- Require parent #224 merge first; then child exact-head CI, independent source-review H/M/L, final branch/main race and owner/security gates before a future integration. GM18 authored this child and is **not its independent reviewer**. No new recurring schedule, provider credit, subscription or account mutation. $0 incremental.

Authority: infrastructure-tools issue #210 and authoritative live PRs #211 / #224; cross-LDW IR coordination existing business-operations #470.
