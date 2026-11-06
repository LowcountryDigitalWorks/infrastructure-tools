# Closed operation request shape (not authorization)

**Scope:** infrastructure-tools #186. This is a source-only shape check that must precede any future protected V2 publisher. It does not implement that publisher.

## What is implemented

`PromotionClosedOperationRequest.Validate(byte[]?)` reads caller-supplied bytes and returns only `BLOCKED` or `DATA_ONLY_REQUEST_SHAPE_NOT_AUTHORIZED`. The only non-blocked shape is schema `1`, intent exactly `DRAGONFLY_V2_PUBLISH_REVIEWED`, and `arguments` exactly `[]`, with no other fields.

That intent is **not** added to `AdminReviewedOperationRegistry`. The registry remains `ELEVATED_IDENTITY_PROOF` only. This method does not call the broker, a task, PowerShell, `gh`, Git, or the network, and it does not read the environment or a file.

It fails closed, without interpreting a caller value as something to run, when the document selects an executable, script, path, Git ref, URL, package digest, provider authorization, or environment-provided executable; when a field is unknown or duplicated; when identity, replay, or TTL is present in any partial or complete form; or when the intent does not match the fixed name.

## Trust and rollout limits

`DATA_ONLY_REQUEST_SHAPE_NOT_AUTHORIZED` means the JSON shape matched. It does **not** mean AUTHORIZED, READY, PASS, reviewed, installed, or safe to publish.

Still required before any protected publisher, each as its own reviewed gate:

- a fixed closed launcher, permanently disabled until a separate owner grant
- an authenticated 165-W issuer and the consequential App repository-scope decision
- protected admin-only state, emergency disable, and recovery
- exact package identity and readback, not a digest chosen by the caller
- exact-head hosted CI, secret scan, and influence-clean independent review

No production key, ledger, ACL, schedule, or host change is configured here.

**Spend:** $0. **Runtime status:** NOT_IMPLEMENTED.
