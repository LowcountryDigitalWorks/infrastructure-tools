# Host Agent — $0 Microsoft Store MSIX structural feasibility (SOURCE ONLY)

**Owning authority:** [infrastructure-tools #50](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/50) and [Business Operations #554](https://github.com/LowcountryDigitalWorks/business-operations/issues/554). This is an **unsigned synthetic packaging experiment**, not a second production Host Agent, an approved installer, or an authorization to publish to the Store.

## Why test this path?

The installed LDW01 `LDW.HostAgent.Windows.exe` is unsigned and Windows Smart App Control's enforced `VerifiedAndReputableDesktop` policy blocked actual execution. Windows Smart App Control has **no supported per-app exception**. Free SignPath Foundation signing requires OSS license/released-project conditions that are not established for LDW's current internal product. Microsoft offers **free registration for Company Microsoft Store developer accounts** and **free trusted re-signing for certified Store-distributed MSIX packages**. The Store **does not sign EXE/MSI installers** and does not sign MSIX distributed outside the Store.

Authoritative Microsoft references:

- [Free Company developer registration](https://learn.microsoft.com/en-us/windows/apps/publish/whats-new-company-developer)
- [Windows code-signing routes](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [WinForms and WPF MSIX packaging](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/dotnet/package-app)
- [MakeAppx structural packaging](https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool)
- [MSIX installation behavior](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes)
- [Packaged desktop startup task](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.startuptask)

## Non-authorizing CI proof

`.github/workflows/host-agent-store-msix-feasibility.yml` is a dedicated, PR-only, Windows-hosted proof.

1. Check out exact proposed source head with no persisted GitHub credentials.
2. Build via the **existing immutable archive** `Publish-HostAgentWindowsPackage.ps1` (no second application publisher).
3. Make a separate `$RUNNER_TEMP` staging root containing **only** the existing self-contained normal-user tray EXE, synthetic solid-color icon files, and a synthetic identity manifest.
4. Use the Windows SDK `MakeAppx.exe` to check whether that WinForms EXE can be structurally packaged as a **full-trust medium-integrity** MSIX.
5. Inspect the unsigned package container for expected files, report a bounded Boolean result and delete it from the ephemeral runner. Do **not** sign with test/local keys, install, launch, upload a package artifact, reserve a Store name, open an account, submit to certification, grant permissions, change Windows security policy, or copy customer/private data.

The manifest publisher is deliberately `CN=NOT-FOR-PRODUCTION`; it is **not** a Partner Center identity or an accepted customer-facing app. A passing `MakeAppx` structural proof is neither Store certification, trusted signature, Smart App Control execution proof, nor a real LDW01 normal-login UX PASS.

## Decision gates still open

- **P0 signing feasibility:** owner-approved Company Partner Center identity verification and a reserved *real* app package identity, only after privacy/IP/certification suitability review. No account or publisher is created by this PR.
- **Actual Store acceptance:** validated supported full-trust capability, package certification, Microsoft-signed MSIX and real signing chain/provenance. Microsoft may reject app capabilities or distribution model.
- **No silent deployment-model swap:** current accepted `host-agent/deploy/HostAgentWindowsDeployment.psm1` pins `%ProgramFiles%\LowcountryDigitalWorks\HostAgent\Windows\LDW.HostAgent.Windows.exe` and a byte-accurate rollback manifest. A Store MSIX normally lives under versioned `WindowsApps`, is per-user/read-only and has different activation/update semantics; current fixed-path relaunch helper and HKCU Run cannot simply be reused unchanged.
- **Single startup owner:** any later packaged desktop `windows.startupTask` must replace, not duplicate, the accepted normal-user startup owner, and must be validated after actual owner login without surprise reboot.
- **Local trust boundaries:** preserve normal-user elevation refusal, separate privileged Hyper-V observer/Admin Broker, existing config precedence, audit, cleanup and rollback. Never install privileged broker via this proof.
- **Release acceptance:** independent source/security review, exact current GitHub checks and Product acceptance precede any production implementation. Do not conflate PR #316 UX source proof with this packaging feasibility.

**Decision rule:** Structural PASS permits only a separately reviewed, owner-authorized packaging design iteration. Structural FAIL returns the specific incompatibility without weakening application policy or opening a paid subscription. No minimum-production exit criterion is met by this test alone.
