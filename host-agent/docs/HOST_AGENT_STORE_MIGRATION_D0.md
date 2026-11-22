# Host Agent — Store MSIX migration D0 contract (SOURCE ONLY)

**Status:** DRAFT DESIGN / NEGATIVE-FIRST ACCEPTANCE MATRIX / NOT AN INSTALLER / NOT A STORE DECISION

**Owner and authority:** infrastructure-tools #50; Business Operations #554. This contract is a disjoint, doc-only candidate after the structural MSIX feasibility proof in PR #317. The independently accepted fixed-path Host Agent deployment, PR #316 UX candidate, privileged Hyper-V Observer, and protected Admin Broker are unchanged. No Store account, Store submission, certificate, installation, startup mutation, runtime privilege or production cutover is authorized by this document.

## 1. Concrete problem and source anchors

The owner-observed Host Agent normal-user tray remains blocked under enforced Windows Smart App Control. The accepted executable is unsigned. Microsoft Store signing is a possible $0 incremental **MSIX-only** route after Store certification, not a way to make the already installed unsigned EXE trusted or prove that all payloads run under Smart App Control.

| Existing source | Bound invariant / migration hazard |
| --- | --- |
| host-agent/deploy/HostAgentWindowsDeployment.psm1 | Exact Program Files install path, externally accepted source/tree/manifest/EXE hashes, elevated deploy and byte-accurate rollback. This does **not** implement MSIX install or rollback. |
| host-agent/deploy/HostAgentWindowsTrayLaunch.psm1 | Fixed installed EXE identity, owner-session Explorer launch and non-elevated token readback; cannot validate versioned WindowsApps activation as-is. |
| host-agent/docs/TRAY_AUTOSTART.md | Exactly one accepted Scheduled Task or HKCU Run value; existing HKCU Run points to fixed Program Files EXE. No second startup owner is allowed. |
| host-agent/src/LDW.HostAgent.Windows/Program.cs | Session-local named mutex and elevation refusal. Mutex is defense in depth; it does not authorize multiple startup registrations. |
| host-agent/src/LDW.HostAgent.Windows/HostAgentSettings.cs | Precedence: explicit LDW_HOST_AGENT_CONFIG, LocalApplicationData LDW HostAgent config, executable-directory fallback. Packaged executable directory is read-only. |
| host-agent/src/LDW.HostAgent.Windows/HostAgentContext.cs | Normal-user tray owns owner-session Admin Broker lifecycle; never mistake this for authorization to package or reinstall the separate protected Hyper-V Observer. |
| host-agent/src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj | Windows .NET 10 WinForms executable with Core/AdminBroker project references; actual signed full-trust package/runtime dependency compatibility is unproven. |

The existing installed fixed-path bytes are currently **not known to be a runnable rollback under Smart App Control**. Preserving those bytes is a recovery/provenance measure, not an availability guarantee.

## 2. Separate trust/decision gates

| Gate | Required independently verifiable evidence | If missing |
| --- | --- | --- |
| G0: Product/privacy suitability | Owner/Product decision permitting a **limited private-audience test** with personal Microsoft Account acquisition, Microsoft certification of app metadata/binaries, a public privacy-policy URL, and accepted business identity. No assumption this is permanent LOB distribution. | HOLD_NO_STORE_ACCOUNT |
| G1: Publisher | Official company Partner Center identity verified; real Name/Publisher/PublisherDisplayName/Package Family Name reserved, accepted provenance, no fabricated synthetic identity. | HOLD_PUBLISHER_UNVERIFIED |
| G2: Source package | Reviewed exact source commit and tree, fixed signed-input payload inventory, legitimate capabilities, deterministic manifest and expected dependency set; no machine-local config, host IDs, customer data, credential or private logs. | HOLD_PACKAGE_SCOPE |
| G3: Platform certification | Provider-positive certification, genuine Microsoft Store MSIX signing and exact package family/version/identity readback. Unsigned MakeAppx synthetic PR #317 output does not satisfy this. | HOLD_CERTIFICATION |
| G4: Isolated runtime | On an approved, recoverable test Windows account/device: owner-acquired package, Smart App Control trust evidence, one normal-user process, supported activation, tray and owner-session broker lifecycle, package data behavior, full keyboard/100%/150% DPI QA. | HOLD_RUNTIME_UNVERIFIED |
| G5: Cutover | A separately reviewed and approved **single-startup-owner** transition, immutable pre-cutover evidence and restoration method, owner window/consent, no protected observer/broker mutation and no forced reboot. | HOLD_CUTOVER |
| G6: Acceptance | Physical source/package/process/signature/CodeIntegrity evidence, next natural login and negative/regression cases, with no double startup and explicit recovery state. | HOLD_OPERATIONAL_QA |

**No gate in this document is itself a protected control, Store API operation, Windows deployment action, or approval.** Synthetic success is always SOURCE_ONLY.

## 3. Proposed non-executable transition phases

These are **review gates**, not commands and not an unattended migration recipe.

1. **Inventory and freeze (read-only):** independently pin current installed EXE hash/bytes, accepted deployment manifest and rollback hash, owner SID/session, current tray process identity, exact accepted task-vs-HKCU startup entry, config *presence and path-class only*, and protected observer/broker state. Do not record secrets or private paths in GitHub. If any identity is ambiguous, HOLD before any startup mutation.
2. **Qualify MSIX in isolation:** select the official signed, owner-acquired package by exact package family, publisher, full name, version, source manifest and catalog signature. Prove standard-user process token, package activation and runtime AppData/config behavior in a segregated test context. An installed signed MSIX alone is not proof of an LDW01 tray launch or Smart App Control compatibility.
3. **Prepare approved reversible switch:** document a one-transaction sequence that has exactly one active registration at every committed boundary. Existing Scheduled Task or HKCU Run cannot coexist in **enabled** state with an MSIX StartupTask. Do not rely on the application mutex to recover a split-brain registration. Activation must not run in the privileged installer session.
4. **Switch only under separate host approval:** after the signing/SAC and owner activity gates, obtain checked owner-scoped before-state, positively quiesce the single tray, retire exactly the accepted old startup registration, enable exactly one packaged startup mechanism, and read back both registrations and the new normal-user process. Never destroy the old accepted bytes or source of recovery evidence during this phase.
5. **If any step fails:** stop further changes, preserve exact transaction/diagnostic evidence, and **do not silently declare a rollback success**. A return to the legacy HKCU/Task mechanism may still launch an SAC-blocked unsigned executable; report that as SERVICE_UNAVAILABLE if verified. No automatic policy disable, unsafe trust-root install, surprise reboot, unverified registration recreation or arbitrary package downgrade.
6. **After acceptance:** document package updates separately from fixed-path deployment, verify next natural owner login (not forced reboot), confirm exactly one process/startup owner, approved UI and data persistence. Preserve existing separate protected Hyper-V Observer/CI/JIT policies and source histories.

### MSIX-specific data/rollback constraints

- Store packages normally install per user under versioned protected WindowsApps and cannot write into their own payload directory. Full-trust AppData handling and MSIX redirection can differ by OS/app packaging details; **test the actual intended access path**. Do not blindly copy local config into the package, mutate the real config without a reviewed migration, or assert missing config means healthy adapters.
- Keep explicit LDW_HOST_AGENT_CONFIG precedence and accurate invalid/missing config reporting. Test that local configuration remains inaccessible to other ordinary users and no private values are emitted by Host Agent summaries, package assets or process command lines.
- An existing Program Files deployment-manager Rollback is **not** a Store package downgrade. Microsoft documents version/data behavior that varies by update method. In Store distribution, simply submitting an older version does not necessarily roll back installed users; a certified newer-version repair may be required. Require explicit data-schema compatibility and independently approved recovery before any live transition.
- Preserve the current fixed-path install/rollback helper unchanged until an explicitly distinct implementation is independently accepted. Never reinterpret package family or per-user writable paths as authorization for privileged source promotion.

## 4. Deterministic negative-first test matrix (not yet executed)

This matrix defines required **future** synthetic tests plus separate physical acceptance. Each ID is stable for downstream evidence; no row is a report of a passed test.

| ID | Scenario / stimulus | Required verdict |
| --- | --- | --- |
| HAMS-01 | No official Store identity or synthetic CN=NOT-FOR-PRODUCTION publisher | HOLD_PUBLISHER_UNVERIFIED; no install |
| HAMS-02 | Package structurally valid but unsigned, Store uncertified or fake signature | HOLD_CERTIFICATION; no SAC claim |
| HAMS-03 | Source/package/manifest/EXE byte identity mismatch | HOLD_PACKAGE_SCOPE; no use of substituted bytes |
| HAMS-04 | Existing owner task and HKCU Run both present or one differs from pinned command | HOLD_CUTOVER; no blind deletion/rewrite |
| HAMS-05 | Legacy startup and packaged startup both enabled | HOLD_CUTOVER; do not rely on mutex |
| HAMS-06 | Package process elevated, wrong user/session, missing or ambiguous executable/package identity | HOLD_RUNTIME_UNVERIFIED |
| HAMS-07 | Explicit config absent, malformed or LocalAppData redirected | truthful UNKNOWN/INVALID; no copying private data |
| HAMS-08 | AppContext.BaseDirectory points into read-only WindowsApps | never write there; prove actual load behavior |
| HAMS-09 | MSIX loses owner-session Admin Broker startup/teardown or changes protected Observer | HOLD_RUNTIME_UNVERIFIED |
| HAMS-10 | Owner acquisition uses Entra/work-school account, wrong private audience or unlisted public route | HOLD_NO_STORE_ACCOUNT |
| HAMS-11 | SAC CodeIntegrity blocks actual signed packaged payload or dependency | HOLD_RUNTIME_UNVERIFIED; preserve SAC |
| HAMS-12 | Store install/uninstall or interrupted update leaves no working tray | SERVICE_UNAVAILABLE; positive identity/readback required |
| HAMS-13 | Proposed rollback points to SAC-blocked legacy EXE | SERVICE_UNAVAILABLE, **not** ROLLBACK_PASS |
| HAMS-14 | Lower Store package submitted while higher version remains installed | do not claim installed rollback; verify repair path |
| HAMS-15 | New package changes config format; previous package cannot read it | HOLD_CUTOVER until backwards-compatible restore |
| HAMS-16 | Power loss or logoff during startup-owner switch | fail closed; preserve checked registration state and evidence |
| HAMS-17 | Package manifest includes machine-local/private config, SSH identity, host ID or customer data | HOLD_PACKAGE_SCOPE; never publish |
| HAMS-18 | Synthetic MakeAppx passes but no real signed/SAC/natural-login test | SOURCE_ONLY, not operational PASS |
| HAMS-19 | 100% DPI passes but 150% DPI, keyboard/focus or no-scroll owner UX fails | HOLD_OPERATIONAL_QA |
| HAMS-20 | Actual next natural login produces two tray processes or zero verified owner-scoped tray processes | HOLD_OPERATIONAL_QA; no false success |

Synthetic tests must never run the production JIT writer, installer, Store API, signer, Windows policy mutation, system startup change or protected service. Any future test executor must inject inert host/provider boundaries and hold on ambient authentication, rather than relying on today's guards to remain correct.

## 5. Minimum reviewer evidence / transition exit

**Source-only D0 acceptance:** one frozen PR (docs/matrix only), exact base/head/tree/changed paths, source citations, independent author-excluded H0/M0 review, deterministic Markdown/contract checks and required hosted security checks. Review must explicitly assess scope ambiguity, migration atomicity, same-user ownership, false rollback-success, Store version behavior, startup conflict and data privacy.

**D1 implementation is separately gated:** only after G0 Product/security decision, document/introduce an independently reviewed *non-mutating* readiness inventory with no credential or private host-path disclosure. Live Store registration/certification, any Windows registration rewrite and package deployment each need their own exact owner approval and independently witnessed host readback. This D0 source cannot approve or perform them.

**Status taxonomy:** SOURCE_DESIGN_ACCEPTED is never STORE_APPROVED, MICROSOFT_SIGNED, SAC_TRUST_PASS, HOST_AGENT_RUNNING, OWNER_LOGIN_VERIFIED or PRODUCTION_ACCEPTED.

## 6. References (background, not automatic authority)

- [Microsoft Store — private audience and personal Microsoft account requirement](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/visibility-options)
- [Microsoft Store — automatic MSIX signing after certification](https://learn.microsoft.com/en-us/windows/apps/publish/faq/get-started-with-the-microsoft-store)
- [Microsoft — MSIX containerization and full trust](https://learn.microsoft.com/en-us/windows/msix/msix-containerization-overview)
- [Microsoft — packaged desktop app data and VFS](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes)
- [Microsoft — Store package version rollback limitations](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements)
- [Existing source structural MSIX proof: PR #317](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/317)
- [Owning technical issue #50](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/50)

**Decision:** D0 design can be reviewed independently; it may never be used as an installation or Store permission packet. $0/included only.
