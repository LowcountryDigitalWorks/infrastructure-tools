# LDW Auto Browser — synthetic interactive proof

Status: SOURCE-ONLY / SYNTHETIC; not deployed, not a supported ChatGPT Chat tool, and not a production browser.

Owner target (infrastructure-tools #210): LDW-owned browser automation from ordinary ChatGPT Chat without Work, GitHub/runtime third-party Desktop Commander, or paid RPA subscriptions. The final system must navigate pages, click/type/select/scroll, capture screenshots, and handle approved uploads/downloads and multi-step site workflows.

This V0 is an isolated Playwright+Chromium adapter that **actually fills and clicks DOM elements**, reads a result and generates an image digest. It does not reuse Eddie's signed-in profile or the operations-bridge's accepted read-only V1 browser profile.

## Test

Install the Python Playwright 1.57.0 package and its supported Chromium browser through the official Playwright installer, then:

    python3 -m unittest discover -s auto-browser -p test_controller.py -v

The tests:
- render a bounded synthetic HTML fixture in an isolated nonpersistent context, fill an input, click a button, read its result and obtain a screenshot digest;
- reject external or unsafe URL targets before navigation;
- reject oversized input and selectors.

The source has a localhost-only navigate method for future lower-layer tests. The author-side execution environment's browser policy returned net::ERR_BLOCKED_BY_ADMINISTRATOR for a localhost HTTP navigation, so **real URL navigation has not passed there**. The synthetic page click/type/screenshot proof passed. Never misrepresent a test of set_content as a live site-navigation pass.

## Author-side response to independent network-isolation finding

Independent GM Status06 reviewed prior head `197dc073...` as CHANGES_REQUIRED H0/M1/L2: an HTTP-only Playwright route did not cover WebSockets or service-worker-intercepted requests.

The new source now initializes the **nonpersistent** context with `service_workers="block"` and installs both the exact-loopback HTTP routing guard and a **deny-all** `route_web_socket("**/*", handler)` before constructing a page. The WebSocket handler closes the routed connection without opening a server connection, including localhost sockets. Only denied request counts are available; attempted URLs and message payloads are not emitted by the diagnostic method.

**Important incomplete proof:** the new source has passed the inherited synthetic interaction tests, but the proposed adversarial browser-test addition was refused by the repository tool. Therefore the M1 independent-review gate remains **OPEN**, and current CI does **not** establish a verified negative external-WebSocket, browser-initiated HTTP or Service Worker test. A local author environment also timed out when attempting a direct Chromium/WebSocket diagnostic; no positive egress-denial result was established there. Do not confuse API configuration with tested network isolation.

Playwright documents that `context.route()` does not intercept all Service Worker requests and that WebSockets require a separately registered `route_web_socket()`; neither mechanism is a replacement for actual OS/container-level egress isolation. Further review must prove that no disallowed browser-initiated traffic leaves the process using a deterministic offline fixture/host-controlled network observation. This V0 is still **SYNTHETIC_SET_CONTENT_ONLY** as to proven browser effects; live local HTTP navigation remains a separate dependent PR #213.

## Integration gates

1. Retain the existing exact BRIDGE-001A read-only contract and complete its genuine owner-private runtime/readback.
2. Separately review one reversible BRIDGE-001B synthetic real navigation + click/type + terminal correlation. Reuse the dedicated automation profile instead of copying an owner's daily browser cookies or exposing DevTools remotely.
3. Expand the approved operation catalog for screenshots/downloads/uploads, website identity, bounds, timeout/abort, and no unsafe duplicate writes.
4. Connect the accepted browser tool through an owner-private supported plugin/MCP interface usable in a normal ChatGPT Chat. Source/CI success here does not establish this connection.
5. Security review must assess browser prompt injection, authenticated site data, consent, cross-origin redirects/WebSockets, output privacy, third-party terms, and permitted download/file paths before real sites.

No live runtime, plugin install, provider credential, external site operation, standing schedule, customer/private/regulated data, or production mutation is authorized here. Goal: $0 incremental.
