# LDW Service Monitor — Host Agent integration contract (source-only)

## Owner directive (November 3, 2026)

**LDW Host Agent is the common host/device/service observer for all LDW-managed services**, including the eventual first-party LDW Commander. Keep the existing Host Agent tray/Details and device -> environment -> service hierarchy. Do not create a second dashboard, polling daemon or privileged observer to implement this requirement.

### Source scope

`commander/monitoring/service_health.py` is a portable, **read-only synthetic integration source**. It samples one allowlisted local Windows SCM or Linux systemd service through the OS service manager, evaluates the observed state against the trusted expected state, and produces one sanitized versioned status envelope. This is not yet wired into the Host Agent runtime, and is **not installed on any owner host**. It neither launches Commander, establishes a Commander session, nor grants admin/root.

Owner requirements currently map into existing `host-agent/src/LDW.HostAgent.Core/DeviceModel.cs`:

- `DeviceDefinition -> EnvironmentDefinition -> ComponentDefinition`;
- `ComponentKind.Custom` until a specific kind is accepted;
- `DesiredState.Running / OnDemand / Disabled` and `ObservedState.Running / Stopped / Unknown`;
- `HealthState.Healthy / Degraded / Failed / Unknown` with freshness/requiredness;
- existing user tray/Details and **existing** Host Agent refresh owner.

## Fixed wire shape

`to_wire()` returns exactly these benign fields; all lowercase keys:

| Field | Allowed content |
| --- | --- |
| `contract` | `ldw.service-status.v1` |
| `service_id` | allowlisted stable service key, e.g. `ldw-commander` |
| `manager` | `WINDOWS_SCM` or `LINUX_SYSTEMD` |
| `desired_state` | `RUNNING`, `ON_DEMAND`, `DISABLED` |
| `required` | boolean |
| `observed_state` | `RUNNING`, `STOPPED`, `ABSENT`, `UNKNOWN` |
| `health_state` | `HEALTHY`, `DEGRADED`, `FAILED`, `UNKNOWN` |
| `observed_at_utc` | UTC ISO 8601 timestamp |
| `evidence_code` | fixed status code such as `SCM_RUNNING`, `SYSTEMD_NOT_ACTIVE`, `PROBE_UNAVAILABLE` or `STALE_OR_CLOCK_UNTRUSTED` |

Do not emit raw service logs, stdout/stderr, command line, full paths, host address, user, PID, credential, bearer, process environment, private state or customer data. `health_state=HEALTHY` means the *OS manager's desired liveness state matches policy*, **not** that application-level readiness, auth, model processing or remote access has passed. A separate readiness probe is necessary if the monitored service can run while not accepting work.

A manager observation older than 30 seconds, more than 5 seconds in the future, cross-platform, unverified or unavailable becomes `UNKNOWN`, never a cached Green. A configured Running service observed Stopped becomes Failed for a required component, Degraded if optional. A stopped OnDemand service can be Healthy for desired state; an absent/not-installed OnDemand service must not be silently Healthy. Do not configure an **uninstalled** Commander as required/running until the actual reviewed runtime is installed.

## Safe monitoring origins

The Host Agent observer must not trust a service to self-declare Green. The *observer process* samples its independent OS manager using a trusted per-host service registry. This proof uses **no shell**, one fixed executable+typed arguments, 2-second deadline, no TCP listener, no mutation/restarts, no remote enumeration or discovery of arbitrary services. Model messages may not create service IDs, select service names or provide command arguments. Process/service identity must be read back from host enrollment and accepted install provenance before authoritative Commander admission claims.

Monitoring additions for other service types must reuse the same contract semantics and Host Agent owner UI:
- Windows Service / Linux systemd: first read-only observer contract here;
- owner-user scheduled task, containers, launch agent, background process and remote enrolled host: each needs an independently reviewed *typed*, bounded evidence adapter, not a generic `exec(string)`;
- readiness/response time, last successful job, restart count, resource use and logs: optional structured diagnostics behind Details, after source/evidence review; no customer payload;
- health warning/alerts: use accepted Host Agent states and owner-by-exception reporting, not another alert system.

This status contract does not confer stop/restart/control authority. When a service is unhealthy, Host Agent reports it, and any recovery action stays with the independently accepted Commander/Admin Broker action policy. **Host Agent must not become a full-admin transport**.

## Next integration owner and gates

Implementation of `HostAgentLiveSnapshotProvider`, component registration, configuration and Windows/Linux deployed probes belongs to existing `business-operations#554` and the owning Host Agent/HW&VM workstream. GM17 can produce source/contract and route an exact handoff but must not silently overwrite active Host Agent work or merge an unreviewed competing status plugin.

1. Independent exact-head review of the monitoring-only source and its tests.
2. Host Agent owner adopts fixed config and source/adapters using `ComponentKind.Custom` initially, without new tray/widget/poller or privileged code.
3. Monitor a **deployed** reviewed Commander service using actual service-manager evidence; separately prove process stopped, host offline, stale status, expected OnDemand idle, service-running-but-not-ready and failover.
4. Repeat for LDW Chat Relay, Auto Browser, Codync, JIT/runner and other deployed services only when their accepted runtime identity and desired state are known.
5. Confirm deployed Host Agent version, exact source binary/readback and no conflicting existing probes; preserve Codync status integration from merged PR #183.

Initial test:

    python3 -m unittest discover -s commander/monitoring -p 'test_*.py' -v

No added Python packages, external services, standing schedules, credentials, billing, admin/root execution or public ports. Incremental cash target: **$0**. Linked: infra #209 (Commander), business-operations #554 (Host Agent), infra #207 (Relay), infra #210 (Auto Browser).
