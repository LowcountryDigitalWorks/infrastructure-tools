CI/JIT Phase-2 observe proof helper

This source-only helper is intentionally non-mutating.
It does not install tasks, start the Admin Broker, launch a JIT job, recover or abort work, retire stale work, download artifacts, or cross UAC.

Prerequisites are the separately reviewed Phase-2 local bootstrap and a running accepted normal-user Admin Broker proof package.

From a clean, current main checkout in a normal (non-elevated) PowerShell 7 session:

  pwsh ./host-agent/deploy/Invoke-CiJitPhase2ObserveProof.ps1

The helper proves only STATUS -> DISCOVER -> correlated GET_OPERATION_RESULT plus sanitized audit readback. It emits bounded fixed state/IDs only and redacts the owner SID.

Any later RUN_ONCE, RECOVER, ABORT_ACTIVE, LIST_STALE, RETIRE_STALE, installation, rollback, or Operations Bridge exposure remains a separate accepted gate under infrastructure-tools #92 / #10 / #52.
