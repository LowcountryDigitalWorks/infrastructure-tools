# LDW Infrastructure Tools

The [disposable CI runner candidate](ci-runner/README.md) implements a bounded
Hyper-V guest and repository-level JIT lifecycle for CI-RUNNER-EPHEMERAL-001 (#7).
The [trusted queue dispatcher candidate](ci-dispatch/README.md) adds a reviewed
synthetic profile, automatic discovery and protected runtime/task tooling (#10).

Reusable LDW-owned utilities for local computers, CI runners, and Linux nodes. This repository is public: keep host addresses, inventories, credentials, private connection details, and customer or regulated data out of Git.

## Current tools

- [LDW Host Agent](host-agent/README.md) — the device-first, unelevated Windows tray/status surface with read-only local adapters plus strict-SSH Linux/off-site node contracts. Includes the deterministic [Local Admin Broker & DPAPI Secret Handoff](host-agent/docs/ADMIN_BROKER.md) (`LDW01-OWNER-ADMIN-BROKER-001`) for owner-authorized operations (`CODYNC_BOT_*`, `HOST_AGENT_*`, `CORSAIR_NEON_DATABASE_URL`).
- [Operations Bridge](operations-bridge/README.md) — bounded read-only BRIDGE-001A source candidate for authenticated bridge protocol, transport correlation, and sanitized browser metadata operations.
- [CI runner benchmarks](benchmarks/README.md) and [profiles](profiles/README.md) — reusable capacity evidence and profile documentation.
- [Architecture and operations docs](docs/README.md).

Machine-specific settings belong in local secure configuration. GitHub issues and repository documentation define accepted operating state; Host Agent is an observation surface, not a control plane.
