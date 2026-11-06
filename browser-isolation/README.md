# Auto Browser: outside-browser network-isolation canary (#210)

Status: **NEW SOURCE-ONLY DRAFT / NOT A BROWSER / NOT A PRODUCTION SANDBOX**.

This is an independent, nonoverlapping infrastructure proof for the **outer network boundary** demanded by the H2/M3 security review of Auto Browser PR #211. It is not part of PR #211's Playwright code and changes none of that candidate's four files.

## What this tests

- Build a tiny synthetic **Go standard-library-only** binary into an offline `FROM scratch` OCI image; run it as an unprivileged UID with Docker `--network=none`.
- A host fixture listens **only on the Docker private bridge gateway** for the proof, never `0.0.0.0` or a public listener. A positive host connection verifies that the listener is real and accepting connections.
- A guest-local HTTP fixture succeeds, while a connection from inside that guest to the host's private bridge listener and a TEST-NET target must fail. The host verifies that its listener did not accept guest connections, rather than trusting only a guest's claimed `BLOCKED` response.
- The launcher fixes `--network=none`, `--pull=never`, `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, unprivileged UID and process/memory limits, with **no mounts, exposed ports, Docker socket or host IPC**. Only a locally prebuilt exact `sha256:<image-id>` is admitted, never a mutable tag or model-supplied Docker option.
- Docker daemon, source build, bridge gateway and host are trusted for this **synthetic-only** proof. Any missing prerequisite produces `NO_START`, not fallback to host networking. No untrusted website or real service is contacted.

## Run on a disposable CI runner with Docker and Go

```bash
mkdir -p browser-isolation/bin
CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o browser-isolation/bin/canary ./browser-isolation/canary/main.go
python3 -m unittest discover -s browser-isolation -p 'test_*.py' -v
docker build --network none --pull=false -f browser-isolation/Dockerfile -t ldw-browser-isolation-canary:local browser-isolation
image_id="$(docker image inspect --format '{{.Id}}' ldw-browser-isolation-canary:local)"
python3 browser-isolation/run_canary.py "$image_id"
```

The pull-request CI job executes only synthetic network denial on a disposable GitHub-hosted Linux runner. It does **not** start LDW01, REDRIX, protected JIT, Chromium, an owner account or customer material. No security settings, persistent host service or paid plan are introduced.

## Remaining security acceptance

**This isolated network canary does not close PR #211's findings.** Future independently reviewed source must run actual Chromium/Playwright **inside the enforced guest** with a reviewed untrusted-content sandbox and immutable image, no host/browser-profile mounts, and safe authenticated IPC/result boundaries. Adversarial integration must attempt `navigator.sendBeacon`, link `ping`, `fetch(keepalive)`, redirects, WebSocket, Service Worker and direct TCP access to unapproved host and external endpoints, with **actual host-side socket/packet negative evidence**. It must prove deliberate same-guest positive navigation, containment during the entire process lifecycle, cancellation and no external/host traffic.

Do not run untrusted pages with the default root/no-sandbox Playwright test image: the official Playwright Docker guidance cautions against such use. Passing this network canary alone does not authorize PR #211 merge, normal ChatGPT browser integration, unrestricted site navigation, service installation, host privilege, customer data or production deployment. Require a later independent exact-head security review. Cost: $0 incremental.

Authority: infrastructure-tools issue #210; PR #211 independent H2/M3 security findings. Live GitHub/system evidence overrides this draft.
