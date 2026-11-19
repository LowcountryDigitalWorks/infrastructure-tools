# REDRIX D0 — immutable first-install source gate (source-only implementation)

**Current disposition: SOURCE-ONLY DRAFT / D0_TRUST_ROOT_ABSENT / HOLD_SECURITY.** Controlling [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), [owner A0 source-only acceptance](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051), [owner permits SYSTEM task creation](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6999867314), independent [Gate A architecture PR #333](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/333) and [actual ephemeral SYSTEM task proof PR #335](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/335#issuecomment-7000157107). No actual protected LDW01 task installed.

## Problem and one smallest safe implementation

The hosted #335 proof established SYSTEM task mechanics (54 WinPS5.1 assertions and exact GUID cleanup), but not an authentic immutable source location on LDW01. Merely running as SYSTEM does not authenticate the installer; a source hash supplied by the same caller is not provenance, and the currently owner-writable ProgramData LDW ancestor cannot be used to bootstrap authority.

This PR adds two **source-only production-adjacent read-only entrypoints** and one synthetic test:
- `host-agent/deploy/RedrixD0FirstInstallReadOnly.psm1`: pure descriptor contract and OS-known Program Files fixed child path assessment, plus explicit `Get-D0FirstInstallSourcePlan` that **never** returns permission to install.
- `host-agent/deploy/Plan-RedrixD0SystemTaskFirstInstall.ps1`: zero-argument WinPS5.1 Plan; no external executable, Git, network, task registration, ProgramData, write, privilege check/escalation, user-selected pin or caller-supplied path.
- `host-agent/deploy/tests/Test-RedrixD0FirstInstallSourceGate.ps1`: native hosted Windows 5.1 synthetic TEMP-only source DACL and path tests. No task creation, no admin operation, no protected LDW folders.
- Exactly one new step in the existing hosted Windows Host Agent workflow to test source-negative behavior. No additional workflow permissions, secrets, schedules, executors or spend.

## Frozen policy

The only proposed staging location is an exact child of the OS Program Files known folder: `%ProgramFiles%\LowcountryDigitalWorks\RedrixD0`. The Plan requires its components to exist as ordinary non-reparse directories; no auto-create or inherit source from checkout. The final staging directory must have owner/group SYSTEM or Builtin Administrators, a protected DACL, and **exactly two explicit inheritable allow FullControl ACEs**, SYSTEM and Administrators. This is a *source staging directory* descriptor, not the distinct frozen journal SDDL. Any inherited ACE, duplicate, normal-user write, unprotected DACL, wrong owner/group, owner-controlled path, missing component or reparse is HOLD.

This is a **point-in-time read-only snapshot**, not a held-handle atomic namespace trust guarantee. The published user-mode `NtCreateFile` source-contract limitation and active race remain [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6994028541). A normal-user-writable checkout cannot automatically become trusted just because it creates a matching directory or produces self-consistent hashes.

Critically, even with an exact protected staging DACL the Plan emits `D0_INDEPENDENT_SOURCE_PIN_ABSENT`, not PASS. Before any physical install, Product/security still must define the **independent authenticated source identifier**, pinned exact installer/worker bytes and review signature, protected first-install verifier path and source/manifest validity, and actual owner-attended installation/rollback policy. No certificate or external trust root was invented by this PR.

## Strict physical admission order

1. **Now:** source review, exact-head hosted CI, author-excluded H0/M0 acceptance of Plan and negative fixtures. Keep DRAFT/UNMERGED. Zero actual LDW01 operations.
2. **First-install trust root:** independent accepted commit/tree/blob/artifact package and verifier source that cannot be replaced by owner-writable LDW ancestry; owner-attended source-authenticated staging outside LDW; safe exact write/rollback plan; no self-selected SHA, mutable Git checkout task action, generic updater, ambient PowerShell script execution or paid signing tool without owner choice.
3. **Device proof:** authenticate LDW01 actual machine identity. Read current V1 owner-SID no-trigger task, current source, six protected child SDDL pins and ProgramData parent preimage without triggering it. Previous Codync physical inventory was `BLOCKED_CANNOT_VERIFY`; Desktop Commander account reported `remote_calls_left_pct=0`, so do not infer state.
4. **SYSTEM task install:** only a separately reviewed fixed no-trigger identity-only or strictly approved single-purpose operation, trusted protected first-install bytes, exact Task Scheduler principal/Action/arguments and strict task object ACL (BA owner/group, protected SY/BA FullControl); registration readback, one-run if separately admitted and exact task removal. The owner has authorized creating SYSTEM tasks in general, **not** bypassing root trust or performing the parent ACL mutation. Existing V1 principal remains owner SID.
5. **Parent ACL and journal:** distinct exact owner-admin physical approval for the reviewed one parent-only transaction. Frozen journal creation must have **SYSTEM owner AND group** with protected two-ACE DACL `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)` **at creation**, same-handle readback and durable PREPARED before parent mutation, six-child/task parity and COMMITTED. No after-the-fact journal ownership or implicit privilege enablement.
6. **CI7/REDRIX downstream:** #269 independent protected six-file controller/issuer, #264 specific powered-off guest cleanup with lock-proof and bounded LOCAL_GUEST_REMOVE, #139 A4/FD and #96 guest-visible >=10,240MiB idle floor, then one already-conditionally-authorized provider-confirmed secretless JIT + cleanup. `DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND` hold stays in production until upstream gates PASS.

## Trusted-provider references

- [Microsoft Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-5.1): signature validity can support independent publisher authentication, but this PR creates **no signing key**, signature or external acceptance.
- [Microsoft WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust): trustworthy signer/validation is a separate explicit step.
- [Microsoft TaskFolder.RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition): an execution principal and task ACL do not independently verify the source code selected as the task action.
- [Microsoft App Control code signing guidance](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-code-signing-to-simplify-application-control-for-classic-windows-applications): a signed installer does not automatically authenticate every loose installed file.

**No protected host action, schedule, Task Scheduler registration, token elevation, ACL mutation, journal, new signer, GitHub JIT, VM, CI7 delete, paid service or secret. $0/included.**
