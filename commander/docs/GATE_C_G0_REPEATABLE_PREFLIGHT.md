# Commander Gate C — repeatable read-only host preflight

Status: **SOURCE ONLY / DATA_ONLY_POLICY_SOURCE_UNVERIFIED / NO HOST ADMISSION**. Owning issue: infrastructure-tools #209. This is a reproducible implementation of the earlier one-off, non-elevated G0 capability/provenance read. It does not change the accepted [policy enrollment/rollback plan](GATE_C_POLICY_ENROLLMENT_PLAN.md), nor replace the fixed seven-value device-policy auditor or deterministic change packet.

## When to run

**Only when the owner has said they are present on the approved Windows host, after confirming the exact accepted source/head.** The accepted remote/CLI actor may run the following once without elevation and without installing anything:

```powershell
python commander/prototype/gate_c_host_g0_readonly.py
```

The module invokes one fixed, no-profile, non-interactive Windows PowerShell command (never `shell=True`) and reads only bounded local operating-system signals:

The wrapper creates a minimal explicit process environment from the OS-selected system PowerShell path (`SystemRoot`, `windir`, `PATH`, `PSModulePath`), never inherited from caller variables. The fixed probe imports `CimCmdlets` from the actual `$PSHOME` system module path and checks local `Registry.pol` using `[Environment]::SystemDirectory` instead of inherited `SystemRoot`. Missing trusted executable layout or failed system module import returns sanitized HOLD. These user-mode hints do not prove an OS/ACL protected source or feature/policy authority.

| Signal | Read method | Sanitized categories |
| --- | --- | --- |
| Joined to a Windows domain | `Win32_ComputerSystem.PartOfDomain` | `YES`, `NO`, `UNKNOWN` |
| Windows Sandbox feature state | `Win32_OptionalFeature` exact `Containers-DisposableClientVM` | `ENABLED`, `DISABLED`, `UNKNOWN` |
| Current device PolicyManager WindowsSandbox key | Registry64 read-only `OpenSubKey` | `PRESENT`, `ABSENT`, `UNAVAILABLE` |
| Count of seven known Sandbox device-policy names | `GetValueNames()` intersect fixed allowlist | integer `0` to `7`; **no values read** |
| Local machine `Registry.pol` file existence | `Test-Path` fixed relative path | `PRESENT`, `ABSENT`, `UNAVAILABLE` |
| Current process token elevated | WindowsPrincipal role membership | `YES`, `NO`, `UNKNOWN` |

The script never prints machine/domain/user identifiers, raw HKLM data, policy file paths, tokens, customer content, registry exports, provider exceptions, or privilege-bearing commands. The Python wrapper refuses unknown fields, duplicate JSON keys, malformed or large results, non-Windows runs, and CLI arguments. Every returned record **always** has `management_source_verified=false`, `effective_policy_proven=false`, `guest_isolation_proven=false`, `physical_change_executed=false`, and `admin_session_authorized=false`. A successful read is a **hint only**, not host enrollment, trusted attestations, proof of effective policy, or approval to act.

The prior non-elevated LDW01 one-off probe documented in [#209 comment 6996385419](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/209#issuecomment-6996385419) found `windows_sandbox_feature=DISABLED`, no PolicyManager key or machine `Registry.pol`, domain-join hint `NO` and non-elevated token. These are **previous observations, not default values and not indefinite truth**; the accepted module does not hardcode them.

## Optional Microsoft tooling: no automatic installation

Microsoft also documents `winapp target snapshot sandbox --json`, which reports Windows build, Sandbox feature/client availability, `wsb` command support and pending restart without starting or reconnecting a guest. The tool may not be installed on the host. **Do not install, update, or invoke winapp automatically**; if already available and separately accepted, use a manual read-only prerequisite comparison and classify all identifiers as private. It does **not** establish a boot-unique guest identity, independently enforced no-egress/no-share policy, a protected owner signer, or unrestricted Administrator trust.

- [Windows Sandbox execution — winapp target snapshot](https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/sandbox-execution)
- [Windows Sandbox Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowssandbox)
- [Windows Sandbox CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)

## Real next Gate C milestones

1. **G0 repeatable source**: this module and its negative tests approved; execute the accepted read exactly once on the selected host when owner present. No system change.
2. **G1 protected provenance/owner gate**: identify the authoritative policy manager, exact host, installed feature and restart impact, secure preimage store, independently protected issuer and signer, explicit host-bound owner decision. An untrusted Python/PowerShell report cannot satisfy this.
3. **G2 policy and feature change**: only a separately approved protected actor applies the exact seven policy restrictions and any required Sandbox feature enable/restart, preserving the **original** values for rollback. Never set all seven registry values directly merely because a code-generated plan says so.
4. **G3/G4**: verify actual post-change policy and effective guest isolation by negative tests for `wsb share` after startup, network egress and other sharing surfaces; use a disposable secret-free guest and trustworthy guest/session correlation. A requested `.wsb` configuration does not establish effective controls.
5. **G5 protected confined command**: only after signer, issuer, immutable batch, service and rollback/cleanup security admission, one harmless elevated command inside the *confined guest*. Real workstation unrestricted Administrator belongs to Gate F, not this test.

**No connected host was contacted to build or test this source.** The unit tests use synthetic PowerShell outputs and do not invoke native OS commands, alter host settings, create a VM, install a service or spend money. Cost: $0 incremental.
