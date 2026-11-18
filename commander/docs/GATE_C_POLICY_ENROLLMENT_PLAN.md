# Commander Gate C — Windows Sandbox policy enrollment and rollback plan

Status: **SOURCE-ONLY DESIGN / NOT AUTHORIZED TO APPLY** (November 18, 2026 ET).
Owner: infrastructure-tools [#209](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/209).
Existing accepted read-only probe: [PR #329](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/329), `commander/prototype/gate_c_sandbox_device_policy.py`.
This document does not approve GPO, CSP, HKLM, OS feature, Windows Sandbox, service, privilege, networking, credential, signing, or protected issuer changes.

## Why enrollment is blocked today

The owner-authorized normal-user LDW01 read in [#209, Nov 18](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/209#issuecomment-6993893367) confirmed a build supporting Windows 11 24H2 machine mapped-folder policy (build 26100 or later), but the **seven fixed device policy values are each NOT_CONFIGURED**. Consequently `all_seven_explicit_deny=false`, `effective_enforcement_proven=false`, `guest_isolation_proven=false`, and `admin_authorized=false`. The read was native PowerShell with fixed read-only 64-bit HKLM accesses, **not** execution of the merged Python script. There was no host mutation.

Microsoft's [WindowsSandbox Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowssandbox) documents device-wide Group Policy mappings and `0 = Not allowed`. An unconfigured policy does not satisfy LDW's explicit-deny prerequisite even when that particular feature defaults off. Networking, mapped folders and clipboard can be enabled by default when unconfigured. Microsoft also documents [post-start `wsb share`](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli); therefore a restrictive launch-time `.wsb` file alone is not evidence of effective host-folder denial.

## Fixed intended deny-policy set

All entries use the Windows Sandbox device-level policy namespace. Current readback is **NOT_CONFIGURED for each**; this table describes a desired future state, not a change made by this file.

| Device policy registry value under 64-bit HKLM `SOFTWARE\Policies\Microsoft\Windows\Sandbox` | Future required state | Reason |
| --- | --- | --- |
| `AllowMappedFolders` | `REG_DWORD 0` | Deny host-folder mapping, including post-start host share paths |
| `AllowNetworking` | `REG_DWORD 0` | Disable Sandbox network access |
| `AllowClipboardRedirection` | `REG_DWORD 0` | Deny clipboard host/guest sharing |
| `AllowAudioInput` | `REG_DWORD 0` | Deny host microphone/input exposure |
| `AllowVideoInput` | `REG_DWORD 0` | Deny host camera/input exposure |
| `AllowPrinterRedirection` | `REG_DWORD 0` | Deny host printer sharing |
| `AllowVGPU` | `REG_DWORD 0` | Reduce guest access to virtualized GPU |

The Group Policy path is **Computer Configuration → Administrative Templates → Windows Components → Windows Sandbox**, using the policy with the matching name. If managed by domain policy or MDM/Policy CSP, resolve **effective source and precedence** first; a local GPO selection may not control the device. Do not write raw registry values to bypass managed policy. `AllowWriteToMappedFolders` is not a substitute for denying `AllowMappedFolders`.

## Gate sequence — no physical mutation until separately approved

1. **G0, evidence freeze:** Verify the *current* trusted host/platform/build, owner-host identity and policy issuer/source with read-only tooling. Record only sanitized classifications, policy provenance, whether enterprise/MDM policy may override local GPO, current Sandbox sessions/features, and the existing private rollback destination. Preserve actual prechange settings **in an approved protected store**, not in public repo or logs. The November 18 snapshot is a baseline, not an indefinitely current reading.
2. **G1, explicit policy-change approval:** Obtain an exact separate owner/security approval naming the specific Windows host, the seven device-level Sandbox settings, authorized protected actor, reason, maintenance window, rollback conditions, and how the authorization is verified. This source-only PR, prior test acceptance or generic permission to continue implementation is **not** that approval. Hold if protected issuer, provenance or owner presence cannot be established.
3. **G2, scoped enrollment by protected actor only:** Under the approved, trusted Windows management source (local Computer GPO *only if authoritative*, otherwise approved managed policy), set exactly the seven Sandbox device policies to **Disabled / not allowed**. No generic registry mutation script, privilege escalation workaround, installer, Sandbox launch, Windows feature change or unrelated settings. Record the approved change transaction privately with preimages and rollback ownership. If a policy cannot be changed exactly or is immediately overridden, stop with `HOLD_POLICY_PROVENANCE`; do not silently swap management source.
4. **G3, post-change readback:** Only after policy application and supported Windows Sandbox restart/reinitialization, independently run the accepted fixed-name read-only audit. Require seven `EXPLICIT_DENY` states and valid Windows build. Missing, invalid, inaccessible, allowed or contradictory policy is a fail-closed `HOLD_POLICY_INCOMPLETE`. A registry pass is **still not effective-enforcement proof**.
5. **G4, isolated *negative* guest tests:** Only under a separately accepted protected temporary guest test plan, verify host folder mapping refusal **both initially and after guest startup** (including the documented `wsb share` entry point), absence of unintended guest egress, clipboard/input/printer/vGPU denials as relevant, no existing host sharing, no extra provider/guest launch capability, full disposable teardown, and no host data movement. Use synthetic artifacts and a specifically approved harmless test destination; never use customer/private host paths. Test failures or inability to inspect is `HOLD_GUEST_ISOLATION`, not PASS. Keep WSB `exec -r System` and all guest privileged work outside this policy-only proof unless separately gated.
6. **G5, independent acceptance:** Require author-excluded R3 security review of the *exact* host change/test artifacts, verified owner-presence signature and immutable issuer/guest binding, source checks, audit/revocation/rollback, and actual runtime evidence. Preserve the Commander Gate A/B/E/F boundaries. No normal ChatGPT tool access, full Administrator operation or CI7/REDRIX controller permission follows from policy enrollment.

## Rollback and failure hygiene

- Keep the authorized prior source-of-truth settings and preimage externally in an approved secure host/admin record; **do not** commit raw registry exports, policies containing secrets, host IDs or snapshots to GitHub.
- On a reviewed stop/rollback, the **same protected management authority** restores **the exact prior settings/source** (the observed preimage was NOT_CONFIGURED; never blindly set every value to 1), follows documented restart/refresh behavior, and confirms fresh sanitized readback. Do not remove unrelated managed policies or roll back during another owner workload.
- No automation may treat a failed or partial rollback as success. Record `HOLD_ROLLBACK_UNVERIFIED`, keep Gate C closed and require a new exact owner/security decision if the authorized rollback path is unavailable.
- Network/device policy is not enough to protect against a malicious host process, guest impersonation, owner-token spoofing or post-start privileged control. Keep protected issuer, hardware-backed owner presence, fixed-command allowlists, local credential custody, external nonshared guest boundary, and teardown gates separate and unresolved until actually proven.

## Evidence/acceptance return

The exact next implementable deliverable is an **owner-reviewable change packet**: sanitized device policy provenance (local GPO/domain/MDM), exact authorized source and rollback actor, preimage classifications, seven-policy allowlist, postchange readback expectations, isolated negative-test protocol and explicit no-change abort criteria. Source acceptance is not physical approval. Report `SOURCE_PLAN_READY` or one specific `HOLD_*` classification; never infer `GATE_C_PASS` from a policy document or registry view.

Cost: **$0 incremental**. No new accounts, privileged actor, registry change, installed service, agent routine, background job, paid provider, customer data or production mutation authorized.
