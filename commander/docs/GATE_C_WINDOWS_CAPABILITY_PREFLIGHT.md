# Commander Gate C — read-only Windows capability hints

Status: **DATA_ONLY_GATE_C_NOT_AUTHORIZED**. Parent: infrastructure-tools #209 and the canonical commander/docs/SESSION_TRUST_CONTRACT.md.

This stdlib-only source *does not* implement or approve Gate C. It reads two documented native Windows APIs without requesting credentials, opening owner files, installing software, elevating privileges, creating a service, or contacting a network. It emits a fixed sanitized JSON projection and accepts no command-line arguments. Non-Windows platforms produce unknown hints.

## Evidence and limits

- WebAuthNGetApiVersionNumber is loaded from the Windows System32 webauthn.dll. A reported API version is only a native WebAuthn API capability. **It does not establish an enrolled non-exportable hardware signer, fresh owner presence, user verification for this application, or an independently displayed and signed exact transaction digest.**
- IsProcessorFeaturePresent is loaded from Windows System32 kernel32.dll with PF_VIRT_FIRMWARE_ENABLED (21) and PF_SECOND_LEVEL_ADDRESS_TRANSLATION (20). These are virtualization **hints only**. They do not establish a disposable Windows guest, independently protected hypervisor, network egress denial, VM recovery, or a trusted Administrator installer.
- A local same-user process could modify Python code, inject a fake DLL loader or alter JSON output. This is **unauthenticated data**, never trusted attestation. A model or ordinary CLI caller cannot promote positive hints into an Administrator grant.
- All owner-presence, protected-issuer, external-guest-isolation, and admin-session-authorization fields are permanently false, even when Win32 APIs report positive hints. Missing functions or errors return null hints rather than bypasses.

## Source and validation

Source: commander/prototype/windows_gate_c_capability.py
Tests: commander/prototype/test_windows_gate_c_capability.py

From an existing authorized checkout with Python already installed:

    python commander/prototype/windows_gate_c_capability.py
    cd commander/prototype
    python -m unittest test_windows_gate_c_capability -v

No arguments, credentials, host IDs, local paths, private account data or special privileges are used. The script makes no changes.

## Required subsequent gates

1. Independently select and review a **non-scriptable hardware-/device-backed, transaction-bound owner-presence** proof, with separate protected issuer authority, exact host enrollment and negative same-user process tests (Gate A1/A1b). WebAuthn API availability does not satisfy this.
2. Source and review a distinct protected Windows service and exact signed-command verifier in a **secret-free disposable Windows guest**, with *external* network confinement, Job Object descendant drain and audited revocation (Gate C). This source does none of those things and must not be used for LDW01 production installation.
3. Obtain author-excluded exact-head R3 security review, required Windows/Linux hosted checks and separate owner/security admission before any protected guest install. Later Gate F real-host unrestricted use requires an independent fresh human-verified owner transaction, not this JSON report.

Microsoft primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetapiversionnumber
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent

No new relay, schedule, server, signing key, OS service, account, package, existing Admin Broker/REDRIX privilege change or incremental spend.
