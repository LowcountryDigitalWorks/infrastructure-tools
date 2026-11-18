# LDW Commander Gate C — non-launching disposable Windows Sandbox profile

Status: **SOURCE_CONFIGURATION_ONLY_NOT_GUEST_ADMITTED**. Owning issue: infrastructure-tools #209. Controlling contract: `commander/docs/SESSION_TRUST_CONTRACT.md` (Gate C). This is **not** an installed or operational privileged agent.

## Design reference

Microsoft documents `.wsb` XML for Windows Sandbox. The default Sandbox configuration enables networking, vGPU, microphone, and clipboard. Our static profile `commander/prototype/gate_c_disposable_nohostshare.wsb` therefore explicitly specifies:

| Setting | Fixed source value |
| --- | --- |
| vGPU, Networking, AudioInput, VideoInput | Disable |
| ProtectedClient | Enable |
| PrinterRedirection, ClipboardRedirection | Disable |
| MappedFolders, LogonCommand | ABSENT (not even read-only host sharing or automatic commands) |

Sources: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file and https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install.

`gate_c_sandbox_profile.py` validates one fixed XML source reference using Python stdlib and rejects missing/duplicated/unknown elements, mapped host folders, commands, DTDs, comments, processing instructions and settings that weaken the reference. It never launches Windows Sandbox, accepts target paths, requests privilege, or updates Windows. A passed validator is **only a consistency check on repository bytes**; source code, XML and CLI output are not hardware attestations, cannot constrain what Windows launches, and must not become authorization to issue a session.

## Mandatory independent evidence BEFORE a confined Gate C test

1. An eligible Windows edition and Windows Sandbox optional feature must be separately verified by an authorized provider. Earlier normal-user LDW01 optional-feature read returned `UNAVAILABLE_NONADMIN`; do not bypass it or assume Sandbox installed because a hypervisor is detected.
2. The actual disposable, **secret-free** guest must be created through an independently approved and protected owner/admin workflow. Explicitly verify effective guest settings, no host folders/clipboard/devices, no model-supplied logon command, and **external** network/egress confinement with negative tests. A `.wsb` line claiming `Disable` is not a packet-level proof.
3. Prove source/guest identity, exact immutable signed work batch, genuine out-of-band human owner-presence signer, independent issuer, bounded TTL/revocation, Job Object child-process containment and recovery, with author-excluded R3 security acceptance. Then run at most one harmless elevated operation *inside the guest*, not on the owner's primary host.
4. Gate F's unrestricted workstation session requires fresh separately bound owner approval and Gates A–E. This profile never authorizes it.

Do not double-click or launch the profile as part of source CI. No installation, new task, enrollment, credentials, protected service, Windows optional-feature changes, network change, remote shell or paid resource is included. $0 incremental.
