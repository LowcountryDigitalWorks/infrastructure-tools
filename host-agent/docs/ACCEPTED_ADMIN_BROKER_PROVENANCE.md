# Exact accepted Admin Broker artifact provenance (#92)

This contract is read-only source/artifact evidence. It does not authorize a
listener, task invocation, deployment, Observe, or queue service. Current #92/#10
dispositions and fresh independent exact-head review remain required. App Control,
Defender, UAC, task ACLs and the fixed worker boundary remain unchanged.

## Decision and historical evidence

Use path 1: reuse only the previously accepted exact bytes when the complete
repository broker input closure is unchanged. Do not rebuild merely because
repository HEAD changed. Do not substitute a locally built or newly unsigned EXE.
This is deterministic artifact selection/readback, **not** a reproducible-build
claim or a declaration that Smart App Control will permit future execution.

The acceptance chain is #92 comments
[6515945879](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/92#issuecomment-6515945879)
(independent review, accepted merge, five successful post-merge checks, archive
and internal hashes) and
[6538870973](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/92#issuecomment-6538870973)
(qualified owner-local observation with this exact broker hash). The later
[6539076274](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/92#issuecomment-6539076274)
requires this source correction before further runtime proof.

One release is fixed in `deploy/AcceptedAdminBrokerProvenance.psm1`:

| Identity | Accepted value |
| --- | --- |
| Source commit | `ae2c7a564d7ea3d31f4c4961c681ae72d43e5f80` |
| Source tree | `b44453f6c2767d2f7c1e845e2f87850461e942f2` |
| Workflow run | [41009831428](https://github.com/LowcountryDigitalWorks/infrastructure-tools/actions/runs/41009831428) |
| Artifact ID | `12956139605` |
| Artifact name | `ldw-admin-broker-proof-ae2c7a564d7ea3d31f4c4961c681ae72d43e5f80` |
| ZIP SHA-256 | `874b26bfe5fee9dc27fea115214da255d2433504339887abd39f53cf0e56b0de` |
| Manifest SHA-256 | `fa4a884d69e3d2d36fbd6bfbcdd149034cb5416c64771144d4e6d844cad062d6` |
| Broker SHA-256 / bytes | `72ea1fafb2a483bf22770618f09b6cabcb14385794460f2104885af59a36ec96` / 37706854 |
| Probe SHA-256 / bytes | `fe9a4ca642180af14491c6183334728d70d1bc96a418aa9d66ca0edd76b69120` / 37630999 |

The exact 639-byte manifest binds schema 1, package `ldw-admin-broker-proof`,
`win-x64`, that source commit/tree, `foreground_only=true`, `autostart=false`,
`service=false`, and both executable hashes/sizes. Pinning its exact hash also
rejects altered fields, duplicate JSON properties, or a fabricated manifest.
The archive is retained by GitHub until 2026-11-06; expiry/missing bytes means
HOLD, never a rebuild or alternate artifact. A verified retained local copy has
the same fixed content identity; no mutable registry/allowlist is consulted.

## Material build inputs and comparison

`LDW.AdminBroker.Host.csproj` references `LDW.AdminBroker`, `LDW.LocalSecretStore`
and `LDW.LocalSecretProbe`; the broker also references `LDW.HostAgent.Core`, and
the probe references the secret store. There are five distinct projects. The
closure contains all 30 tracked files in those five project directories: all
C# source, project files, assembly attributes and any future resources/imports.
Every file and mode must match, including additions and removals.

The readback additionally compares every direct tracked file at repository root,
`host-agent/` and `host-agent/src/` (all project ancestors). This conservatively
includes solution files and README, plus any newly introduced `global.json`,
`NuGet.Config`, `Directory.Build.props/targets/rsp`, `Directory.Packages.props`,
response files and attributes. Existing project files contain no extra external
imports. A new project reference/import changes the pinned project file and is
refused. Symlink/submodule/non-regular input modes are refused. The publisher
and its exact workflow are included. Worktree/index/untracked dirt is refused.
The canonical fingerprint is SHA-256 of ordinal Git tree rows (mode, blob,
repository path), sorted case-sensitively, LF-delimited, with a final LF.

Between `ae2c7a56` and accepted main
`024e7c0af1adc9c3cdfbb50a2710e2f0fd9446ef` / tree
`1fccccaebce1b83d87490a1688dd810a648a95fd`, all these inputs match. The two
changed files under `host-agent/` are bootstrap and its deployment tests; they
are not compiler inputs. Dispatcher/controller/bootstrap trust is separately
checked by the existing protected task/worker contract; artifact readback never
accepts or replaces those components.

Other inputs materially affecting a **new build** are the .NET SDK/MSBuild/Roslyn
and SDK-generated assembly metadata (including Git revision), targeting/runtime
and apphost packs, System.Security.Cryptography.ProtectedData 9.0.0 and restored
NuGet content, SDK/NuGet feed configuration, publish properties, environment,
OS/architecture, source paths and any ambient imports. The historical workflow
uses Windows and floating `10.0.x`; the publisher uses Release, win-x64,
self-contained single-file, native self-extract, compression, DebugType=None and
DebugSymbols=false. No lockfile/global.json or complete historical environment
attestation exists. Equal source files therefore cannot prove equal rebuilt
bytes. The different fresh EXE hash alone does not establish the precise cause.

The contract avoids that gap by accepting only the **already independently
accepted exact archive** from the fixed historical source/workflow, with no new
restore/build/toolchain/environment participating in reuse. Historical build
environment is provenance context, not a caller-controlled compatibility input.
If policy requires reconstructing that historical environment or bit-for-bit
rebuilding rather than exact accepted-output reuse, this path must remain HOLD;
do not silently broaden its claim.

## Readback contract (no runtime authority)

After normal accepted-source/main reconciliation, put only the verified GitHub
archive at the fixed owner-local content-addressed cache location:

`LocalApplicationData/LowcountryDigitalWorks/AdminBroker/accepted/874b26bfe5fee9dc27fea115214da255d2433504339887abd39f53cf0e56b0de/package.zip`.

Import the reviewed module and call `Test-AcceptedAdminBrokerProvenance` with no
arguments. It emits only PASS, source head, canonical input fingerprint and fixed
release/archive/manifest/broker hashes, plus `RUNTIME_AUTHORIZED=False`. Missing
or changed inputs, source ancestry, archive, inventory, member hash or size cause
an exception before PASS. Reparse points at the archive or any ancestor are
refused. Archive and members are hashed through one locked stream; no extraction,
download, process launch, generic shell, task operation or provider call occurs.
The function has no caller-selectable executable/path/hash/release parameters.

This readback does not make an arbitrary candidate accepted main. At any later
runtime gate, independently reconcile clean current GitHub main, exact accepted
review/checks, latest #92/#10 authority, installed tasks/protected bundle, local
capacity/ownership/residue and GitHub run/job identity. Keep the archive and any
future extracted bytes verified at time of use; a prior PASS is not protection
against later replacement. There is no launcher in this correction. Existing
typed fixed request/result operations, least privilege, fail-closed provider
identity revalidation, and one-controller/one-JIT ceiling are unchanged.

## Validation

`deploy/tests/Test-AcceptedAdminBrokerProvenance.ps1` creates only inert archives
and disposable Git fixtures. It covers source closure changes, ancestor build
configuration, publisher/workflow drift, deletion/addition, unrelated deployment
HEAD movement, exact ZIP/member integrity, duplicate/extra/traversal/case-variant
entries and the parameterless exported boundary. Optional test-only
`-AcceptedArchive` also verifies the actual historical ZIP and all three members;
it never executes them. Hosted tests need no historical artifact download.

No source-only PASS restores admission. A separately accepted runtime disposition
and successful bounded proof are still required. #742 remains untouched and WQT
#52 remains unpublished. No signing enrollment/purchase, credential/certificate,
security-policy, Bridge/Site, Dragonfly/REDRIX, or customer-data action is needed
or authorized. Incremental cash remains $0.
