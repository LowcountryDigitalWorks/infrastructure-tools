# Commander Gate C — read-only Windows Sandbox device-policy audit

**Status: `POLICY_DATA_ONLY_GUEST_NOT_ADMITTED`**. Authoritative work item: infrastructure-tools #209; prerequisite source-only config: PR #327 (`commander/prototype/gate_c_disposable_nohostshare.wsb`). This source audit does not grant host, guest, Administrator, signing, network or release authority.

## Why a separate device-level audit matters

Microsoft's Windows Sandbox CLI supports post-start `wsb share` mappings and `wsb exec` (including a guest `System` context) on supported Windows versions. A no-share/no-network `.wsb` file is a useful initial configuration but **does not independently prevent a privileged host actor from changing a running guest**. Microsoft also documents device-level Windows Sandbox Group Policy / Policy CSP restrictions on networking, clipboard, host-folder mappings, input and vGPU. This module checks whether the operating system exposes *explicitly configured deny* values; it **does not set them** or prove the OS is enforcing them.

Reference: [Microsoft WindowsSandbox Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowssandbox) (updated October 2026) and [Windows Sandbox CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli).

## Fixed machine-policy observations

On Windows, a normal-user Python process performs a **read-only** Windows registry query in the 64-bit HKLM view at `SOFTWARE\Policies\Microsoft\Windows\Sandbox`, using only `winreg.KEY_READ | winreg.KEY_WOW64_64KEY`. Seven explicitly named `REG_DWORD` policies are inspected. This is a fixed allowlist; there is no caller-selected hive, path or value name.

| Required restrictive policy | Expected registry value for an explicit deny |
| --- | --- |
| `AllowMappedFolders` | `REG_DWORD 0` |
| `AllowNetworking` | `REG_DWORD 0` |
| `AllowClipboardRedirection` | `REG_DWORD 0` |
| `AllowAudioInput` | `REG_DWORD 0` |
| `AllowVideoInput` | `REG_DWORD 0` |
| `AllowPrinterRedirection` | `REG_DWORD 0` |
| `AllowVGPU` | `REG_DWORD 0` |

The `AllowMappedFolders` device policy only applies beginning with Windows 11 **24H2 / build 26100**. On older, unknown or non-Windows platforms, the probe does not claim a supported policy surface. Values that are missing, inaccessible, enabled or incorrectly typed cannot satisfy the explicit-deny check. Missing policy generally means the feature is not explicitly denied and some features are enabled by default; this probe intentionally takes the stricter position. `AllowWriteToMappedFolders` does **not** substitute for `AllowMappedFolders=0`; Microsoft documents a dependency on mapped folders being enabled for the write-specific setting.

## Execution and limits

With pre-existing Python and authorized local checkout, invoke `python commander/prototype/gate_c_sandbox_device_policy.py` **without arguments**. The tool emits sanitized JSON containing policy names and classifications only: `EXPLICIT_DENY`, `ALLOWED`, `NOT_CONFIGURED`, `INVALID`, `UNAVAILABLE`, or `NOT_INSPECTED`. It reveals no machine identities, user names, paths from the host, registry content beyond the seven binary policy classifications, or secrets. It cannot install software, enable Sandbox, run a guest, launch a process, authenticate an owner, write registry values or request UAC. All *authorization* and *runtime-enforcement* fields are unconditionally false even when every policy is explicitly denied. This is **not an attestation**, and an untrusted same-user process could modify the code, registry reader, output or results.

Run `python -m unittest test_gate_c_sandbox_device_policy -v` from `commander/prototype` to check the deterministic negative cases. A successful test suite verifies only the source logic. Do not treat `all_required_policies_explicitly_deny=true` as a Gate C pass.

## Still needed for a real Gate C admission

1. Verify Windows Sandbox feature eligibility and actual device-policy enforcement through a separately trusted host/operator, including post-start `wsb share` / interactive share negatives. **No machine-policy write is authorized here.**
2. Independently provision a **secret-free disposable Windows guest** with external network/egress denial, no host sharing, no unreviewed post-start CLI access, a fixed immutable signed work batch and full teardown/revoke evidence.
3. Prove a genuine non-scriptable, out-of-band hardware/device-backed owner-presence signature, protected issuer and exact host/guest identity. Then perform a single harmless elevated command *inside the confined guest* only after the exact protected implementation/security/owner gates have passed.
4. Real LDW01 unrestricted Administrator execution is Gate F, not Gate C. Do not deploy the Commander protected service, alter security/Windows features, or widen existing Admin Broker #52 / REDRIX here.

Cost $0 incremental. This source cannot authorize or automate GitHub merge/host installation.
