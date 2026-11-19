# REDRIX D0 — disposable Windows SYSTEM task execution proof

**Status: DRAFT / HOSTED SYNTHETIC ONLY / NO LDW01 INSTALL.** Owner authority: [#186 A0](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051), [Gate A PR333](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/333), [new owner SYSTEM-task permission](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6999867314). CI7 #269/#264 and REDRIX #139/#96 remain HOLD.

## Experiment

The new zero-argument, native Windows PowerShell 5.1 x64 file is host-agent/deploy/tests/Test-RedrixD0HostedSystemTask.ps1. It requires a GitHub Actions Windows job, an exact github-hosted runner metadata flag supplied by the workflow, and Administrator capability on that **disposable hosted runner only**. Environment checks are accidental-invocation guards, NOT cryptographic host attestation.

1. Determine the fixed signed non-reparse Windows native PowerShell executable from the system known folder; never call an ambient PATH alias or mutable checkout script as SYSTEM.
2. Create exactly one unpredictable GUID-named task in the hosted runner's Task Scheduler root using TASK_CREATE (not CREATE_OR_UPDATE). Set its principal to LocalSystem, TASK_LOGON_SERVICE_ACCOUNT=5, highest run level, one source-fixed Exec action, no triggers or polling, execution <=30 seconds, and no network requirement.
3. The only SYSTEM command is fixed UTF-16LE encoded inline PowerShell: check the process account SID equals S-1-5-18, sleep briefly to permit observing RUNNING, then return 0 if SYSTEM or 41 otherwise. No caller input, external script, file access, ProgramData, task changes, ACL mutation, provider call, credential, VM or JIT.
4. Bind the task security descriptor to exactly SYSTEM + Builtin Administrators full-control, protected DACL, no owner or normal-user ACE. Read back owner/group, all ACEs, principal, logon type, one exact action program and arguments, and zero triggers before invoking.
5. Invoke this one short-lived task on demand, require RUNNING actually observed then terminal and LastTaskResult=0. Delete ONLY the fixture's GUID task and prove it is absent even among hidden tasks. Any registration, readback, run, or cleanup failure fails the Windows job.

Existing Windows Host Agent workflow gets one step gated by runner.environment == github-hosted. No GitHub permission, schedule, secret, runner registration, or protected production entrypoint changes.

## Security boundaries

This is an actual Task Scheduler SYSTEM registration and one execution on a GitHub-hosted disposable Windows VM, **not** a new protected LDW01 issuer. The task has no mutator logic, and its temporary SDDL is task-registration security, not proof of the specified real journal ACL. Success proves the tested host's Task Scheduler mechanics, not permanent trust, real owner-writable LDW ancestor safety, installed source provenance, accepted signer, at-create SYSTEM journal owner/group/DACL, interrupted physical recovery, or REDRIX provider JIT.

Task Scheduler registration by an Administrator does not authenticate the executable. The exact first-install source outside owner-writable ancestry, immutable protected action path, trusted source selection and rollback remain separate Gate D0 conditions. V1 owner-SID closed no-trigger broker stays unchanged. Nothing here authorizes changing its registry, turning it into SYSTEM, enabling privileges or interpreting a source/test PASS as a physical permission to mutate parent ACL.

The user's explicit new permission to create SYSTEM tasks does not by itself supply trusted first-install bytes; the current Desktop Commander account reports zero remote-call allowance. No elevated remote workaround, no spend or paid agent. Existing Codync read-only inventory is not a SYSTEM issuer.

## Next stage

Require all exact-head hosted workflow results, actual Windows job markers, and fresh independent H0/M0 security source review. Keep DRAFT and UNMERGED pending owning product/security decision.

For a future owner-attended actual LDW01 installation: freeze independently reviewed source commit/tree/blob and OS-owned bootstrap path, validate protected parents and SYSTEM task action and task ACL before installation, require no ambient triggers, exact source readback and single-shot deauthorization. Only a further distinct exact-action authorization can permit the protected parent ACL transaction using at-create journal O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA), same-handle verification, durable PREPARED and six child/task pins. Existing Nov9 V2 and Nov4 JIT approvals remain distinct.

Microsoft primary docs: [service-account principal](https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-logontype), [TaskFolder.RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition), [Task Scheduler security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), [GetSecurityDescriptor](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-getsecuritydescriptor). Cost $0/included; no LDW01 SYSTEM task was installed.
