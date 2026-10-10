# LDW Infrastructure Tools

Reusable LDW-owned utilities for local computers, CI runners, and Linux nodes. This repository is public: keep host addresses, inventories, credentials, private connection details, and customer or regulated data out of Git.

## Current tools

- [LDW Host Agent](host-agent/README.md) — the device-first Windows tray/status foundation and shared Linux/off-site node contracts. It runs unelevated and reports state; V0.1 does not mutate services or machine power state.
- [CI runner benchmarks](benchmarks/README.md) and [profiles](profiles/README.md) — reusable capacity evidence and profile documentation.
- [Architecture and operations docs](docs/README.md).

Machine-specific settings belong in local secure configuration. GitHub issues and repository documentation define accepted operating state; Host Agent is an observation surface, not a control plane.
