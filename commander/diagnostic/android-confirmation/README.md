# Offline Android confirmation-support diagnostic

Status: SOURCE-ONLY / NOT AN APPROVAL / NOT INSTALLED

This app reports `ConfirmationPrompt.isSupported` as `SUPPORTED`, `UNSUPPORTED`, or `UNKNOWN`, plus the device API level. It does not show a confirmation prompt, touch the keystore, collect a device identity, or grant a Commander session.

`UNSUPPORTED` can occur while an accessibility service is running. That result does not show whether secure hardware is present. The app does not read accessibility settings and does not ask anyone to turn accessibility off.

`minSdk` is 28, the first API that includes `android.security.ConfirmationPrompt`. The activity still treats any linkage or runtime failure as `UNKNOWN` and does not print the exception. Below API 28 the package is not installable.

The manifest declares no `uses-permission`, one exported launcher activity, `allowBackup=false`, and `usesCleartextTraffic=false`. There is no service, provider, or receiver.

Pinned toolchain, from Android's AGP 8.13 compatibility notes and the official distribution checksums:

- Android Gradle Plugin `8.13.2` from Google Maven
- Gradle `8.13` from `services.gradle.org`, SHA-256 `20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78`
- Gradle wrapper jar from the `gradle/gradle` tag `v8.13.0`, SHA-256 `81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f`
- JDK 17
- `compileSdk` / `targetSdk` 36
- Android command-line tools `commandlinetools-linux-15859902_latest.zip`, SHA-256 `4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583`

CI checks the checked-in Gradle wrapper jar SHA-256 before it runs that jar. It then builds a debug APK and checks the packaged manifest. The log prints two commits: `CHECKOUT_SHA` is the workflow checkout, which for a pull request is GitHub's synthetic merge commit, and `PR_SOURCE_HEAD` is the branch head from the pull request event. The printed APK SHA-256 is the ephemeral debug-signed file from that runner. It is not stable across debug signers, it is not uploaded, and it is not an installable release. Installation stays on hold. No handset was queried by this source task.

After the existing digest line, CI writes a **release-neutral provenance manifest** JSON (runner temp only; not committed) capturing accepted `git_commit`, `git_tree`, `pr_source_head`, allowed `application_id`, permission-negative manifest policy, pinned Gradle wrapper SHA-256, ephemeral debug APK path/name/size/digest, and toolchain versions. `release_neutral.install_approved` and `protected_confirmation_claimed` remain false; artifact scan and explicit owner approval are required before any sideload. Hostile-input unit tests fail closed with explicit `PROV_ERR_*` codes.

Cost: $0.
