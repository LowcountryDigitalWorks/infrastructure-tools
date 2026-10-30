param(
    [Parameter(Mandatory)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedControllerHeadSha,

    [switch]$A0Confirmed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-LdwGateA1Pass {
    param([Parameter(Mandatory)][string]$Name)
    Write-Output ($Name + '=PASS')
}

function Get-LdwGateA1RelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $pathFull = [IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'GATE_A1_TREE_PATH_OUTSIDE_ROOT' }
    $pathFull.Substring($prefix.Length).Replace('\','/')
}

function Get-LdwGateA1TreeDigest {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw 'GATE_A1_TREE_ROOT_MISSING' }
    $records = foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force | Sort-Object FullName) {
        $relative = Get-LdwGateA1RelativePath -Root $Root -Path $file.FullName
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$relative`0$hash"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]::Join("`n",@($records)))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-LdwGateA1Repository {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedHead
    )
    $rootPath = [IO.Path]::GetFullPath($Root)
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) { throw 'GATE_A1_REPOSITORY_MISSING' }
    $origin = & git -C $rootPath remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or ([string]$origin).Trim() -cnotmatch '^(https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(\.git)?$') {
        throw 'GATE_A1_REPOSITORY_REFUSED'
    }
    $status = & git -C $rootPath status --porcelain --untracked-files=normal 2>$null
    if ($LASTEXITCODE -ne 0 -or $status) { throw 'GATE_A1_SOURCE_WORKTREE_DIRTY' }
    $head = (& git -C $rootPath rev-parse HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[0-9a-f]{40}$') { throw 'GATE_A1_SOURCE_HEAD_INVALID' }
    if ($head -cne $ExpectedHead) { throw 'GATE_A1_CONTROLLER_HEAD_MISMATCH' }
    [pscustomobject]@{ Root=$rootPath; Head=$head }
}

function Assert-LdwGateA1Elevation {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'GATE_A1_WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'GATE_A1_ADMINISTRATOR_REQUIRED'
    }
}

function Assert-LdwGateA1TailscaleStatusObject {
    param([Parameter(Mandatory)][object]$Status)
    if ($Status.BackendState -cne 'Running' -or $null -eq $Status.Self -or -not [bool]$Status.Self.Online) {
        throw 'GATE_A1_TAILSCALE_LOCAL_NOT_READY'
    }
    if ($null -eq $Status.Peer) { throw 'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE' }
    $matches = @()
    foreach ($prop in $Status.Peer.PSObject.Properties) {
        $peer = $prop.Value
        $hostName = [string]$peer.HostName
        $dnsName = [string]$peer.DNSName
        if ($hostName -in @('redrix','penguin') -or
            $dnsName.StartsWith('redrix.',[StringComparison]::OrdinalIgnoreCase) -or
            $dnsName.StartsWith('penguin.',[StringComparison]::OrdinalIgnoreCase)) {
            $matches += $peer
        }
    }
    if ($matches.Count -ne 1 -or -not [bool]$matches[0].Online) { throw 'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE' }
    $ipv4 = @($matches[0].TailscaleIPs | Where-Object {
        $parsed = $null
        [Net.IPAddress]::TryParse([string]$_,[ref]$parsed) -and
        $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $parsed.GetAddressBytes()[0] -eq 100 -and
        $parsed.GetAddressBytes()[1] -ge 64 -and
        $parsed.GetAddressBytes()[1] -le 127
    })
    if ($ipv4.Count -ne 1) { throw 'GATE_A1_REDRIX_PRIVATE_TAILSCALE_IPV4_NOT_UNIQUE' }
    [pscustomobject]@{ PeerDiscovered=$true; PrivateIPv4Present=$true }
}

function Get-LdwGateA1TailscaleStatus {
    $service = Get-Service -Name Tailscale -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'GATE_A1_TAILSCALE_SERVICE_NOT_RUNNING' }
    $tailscale = (Get-Command tailscale.exe -ErrorAction Stop).Source
    $raw = & $tailscale status --json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { throw 'GATE_A1_TAILSCALE_STATUS_FAILED' }
    try { $status = $raw | ConvertFrom-Json }
    catch { throw 'GATE_A1_TAILSCALE_STATUS_INVALID' }
    Assert-LdwGateA1TailscaleStatusObject -Status $status
}

function Invoke-LdwDragonflyGateA1 {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedHead,
        [Parameter(Mandatory)][bool]$A0IsConfirmed
    )

    if (-not $A0IsConfirmed) { throw 'GATE_A1_A0_CONFIRMATION_REQUIRED' }
    Write-Output 'A0_REDRIX_RUNTIME_BASELINE_CONFIRMED_BY_ORCHESTRATOR=yes'

    Assert-LdwGateA1Elevation
    Write-LdwGateA1Pass 'ADMINISTRATOR_SHELL'

    $null = Get-Command git.exe -ErrorAction Stop
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { $pythonCommand = Get-Command python3.exe -ErrorAction Stop }
    $python = $pythonCommand.Source
    Write-LdwGateA1Pass 'GIT_PRESENT'
    Write-LdwGateA1Pass 'PYTHON_PRESENT'

    $repo = Assert-LdwGateA1Repository -Root $Root -ExpectedHead $ExpectedHead
    Write-LdwGateA1Pass 'SOURCE_ORIGIN'
    Write-LdwGateA1Pass 'SOURCE_WORKTREE_CLEAN'
    Write-LdwGateA1Pass 'CONTROLLER_HEAD_PINNED'
    Write-Output ('GATE_A1_CONTROLLER_HEAD=' + $repo.Head)

    $dispatcherRoot = Join-Path $env:ProgramData 'LDW\CiRunnerDispatch'
    if (-not (Test-Path -LiteralPath $dispatcherRoot -PathType Container)) { throw 'GATE_A1_CI10_DISPATCHER_ROOT_MISSING' }
    if ((Get-Item -LiteralPath $dispatcherRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'GATE_A1_CI10_DISPATCHER_ROOT_REPARSE'
    }
    $uncertainty = Join-Path $dispatcherRoot 'dragonfly-canary-registration-uncertain.json'
    if (Test-Path -LiteralPath $uncertainty) { throw 'GATE_A1_DRAGONFLY_UNCERTAINTY_PRESENT' }
    $ci10Before = Get-LdwGateA1TreeDigest -Root $dispatcherRoot
    Write-LdwGateA1Pass 'CI10_BASELINE_CAPTURED'
    Write-LdwGateA1Pass 'DRAGONFLY_CANARY_UNCERTAINTY_ABSENT'

    $transportRoot = Join-Path $env:LOCALAPPDATA 'LDW\CI-JIT\DragonflyTransport'
    $privateKey = Join-Path $transportRoot 'id_ed25519'
    $knownHosts = Join-Path $transportRoot 'known_hosts'
    foreach ($path in @($privateKey,$knownHosts)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'GATE_A1_TRANSPORT_ARTIFACT_MISSING' }
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'GATE_A1_TRANSPORT_REPARSE_POINT'
        }
    }
    $privateKeyBefore = (Get-FileHash -LiteralPath $privateKey -Algorithm SHA256).Hash.ToLowerInvariant()
    $knownHostsBefore = (Get-FileHash -LiteralPath $knownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-LdwGateA1Pass 'TRANSPORT_BASELINE_CAPTURED'

    $null = Get-LdwGateA1TailscaleStatus
    Write-LdwGateA1Pass 'TAILSCALE_LOCAL_READY'
    Write-LdwGateA1Pass 'REDRIX_TAILSCALE_PEER_DISCOVERED'
    Write-LdwGateA1Pass 'REDRIX_PRIVATE_TAILSCALE_IPV4_PRESENT'

    $taskRoot = Join-Path $env:TEMP ('ldw-dragonfly-gatea1-' + [Guid]::NewGuid().ToString('N'))
    $packageOutput = Join-Path $taskRoot ('redrix-package-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $taskRoot
    if (Test-Path -LiteralPath $packageOutput) { throw 'GATE_A1_PACKAGE_OUTPUT_ALREADY_EXISTS' }

    $builder = Join-Path $repo.Root 'tools\dragonfly_canary_publication.py'
    if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) { throw 'GATE_A1_PUBLICATION_HELPER_MISSING' }
    $buildOutput = & $python $builder --repo-root $repo.Root build-redrix $packageOutput 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'GATE_A1_REDRIX_PACKAGE_BUILD_FAILED' }
    $null = $buildOutput
    Write-LdwGateA1Pass 'REDRIX_PACKAGE_BUILD'

    $archive = Join-Path $packageOutput 'ldw-dragonfly-canary-source-v1.tar.gz'
    $checksum = $archive + '.sha256'
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf) -or -not (Test-Path -LiteralPath $checksum -PathType Leaf)) {
        throw 'GATE_A1_REDRIX_PACKAGE_OUTPUT_MISSING'
    }
    $verifyOutput = & $python $builder --repo-root $repo.Root verify-redrix $archive $checksum 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'GATE_A1_REDRIX_PACKAGE_VERIFY_FAILED' }
    $null = $verifyOutput
    Write-LdwGateA1Pass 'REDRIX_PACKAGE_VERIFY'

    $archiveSha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $archiveSize = (Get-Item -LiteralPath $archive).Length
    if ($archiveSha -cnotmatch '^[a-f0-9]{64}$' -or $archiveSize -le 0) { throw 'GATE_A1_REDRIX_PACKAGE_IDENTITY_INVALID' }
    Write-Output ('LDW01_REDRIX_ARCHIVE_SHA256=' + $archiveSha)
    Write-Output ('LDW01_REDRIX_ARCHIVE_SIZE_BYTES=' + $archiveSize)

    $publisherPath = Join-Path $repo.Root 'ci-dispatch\DragonflyCanaryAdjunctPublisher.psm1'
    if (-not (Test-Path -LiteralPath $publisherPath -PathType Leaf)) { throw 'GATE_A1_ADJUNCT_PUBLISHER_MISSING' }
    Import-Module $publisherPath -Force
    $publication = Publish-LdwDragonflyCanaryAdjunct -RepositoryRoot $repo.Root
    if ($null -eq $publication -or $publication.Published -ne $true) { throw 'GATE_A1_ADJUNCT_PUBLICATION_FAILED' }
    $manifestSha = [string]$publication.ManifestSha256
    if ($manifestSha -cnotmatch '^[a-f0-9]{64}$') { throw 'GATE_A1_ADJUNCT_MANIFEST_SHA_INVALID' }
    Write-LdwGateA1Pass 'ADJUNCT_PUBLICATION'

    $readback = Test-LdwDragonflyCanaryAdjunct -ManifestSha256 $manifestSha
    if ($null -eq $readback -or $readback.Valid -ne $true) { throw 'GATE_A1_ADJUNCT_READBACK_FAILED' }
    Write-LdwGateA1Pass 'ADJUNCT_READBACK'
    Write-Output ('ADJUNCT_CANARY_COMMIT=' + [string]$readback.CanaryCommit)
    Write-Output ('ADJUNCT_MANIFEST_SHA256=' + $manifestSha)

    $ci10After = Get-LdwGateA1TreeDigest -Root $dispatcherRoot
    if ($ci10After -cne $ci10Before) { throw 'GATE_A1_CI10_PROTECTED_BUNDLE_CHANGED' }
    Write-LdwGateA1Pass 'CI10_PROTECTED_BUNDLE_UNCHANGED'

    $privateKeyAfter = (Get-FileHash -LiteralPath $privateKey -Algorithm SHA256).Hash.ToLowerInvariant()
    $knownHostsAfter = (Get-FileHash -LiteralPath $knownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($privateKeyAfter -cne $privateKeyBefore) { throw 'GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED' }
    if ($knownHostsAfter -cne $knownHostsBefore) { throw 'GATE_A1_TRANSPORT_KNOWN_HOSTS_CHANGED' }
    Write-LdwGateA1Pass 'TRANSPORT_PRIVATE_KEY_UNCHANGED'
    Write-LdwGateA1Pass 'TRANSPORT_KNOWN_HOSTS_UNCHANGED'

    if (Test-Path -LiteralPath $uncertainty) { throw 'GATE_A1_DRAGONFLY_UNCERTAINTY_CREATED' }
    Write-LdwGateA1Pass 'DRAGONFLY_CANARY_UNCERTAINTY_ABSENT_AFTER'

    Write-Output 'GITHUB_PROVIDER_ACTIONS_INVOKED_BY_HARNESS=no'
    Write-Output 'WORKFLOW_DISPATCH_INVOKED_BY_HARNESS=no'
    Write-Output 'SSH_TRANSPORT_INVOKED_BY_HARNESS=no'
    Write-Output 'REDRIX_INSTALL_INVOKED_BY_HARNESS=no'
    Write-Output 'QEMU_INVOKED_BY_HARNESS=no'
    Write-Output 'GATE_B_ACTIONS_INVOKED_BY_HARNESS=no'
    Write-Output 'GATE_A1_LDW01=PASS'
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Write-Output '=== LDW Dragonfly Gate A1 operator ==='
        Invoke-LdwDragonflyGateA1 -Root $RepositoryRoot -ExpectedHead $ExpectedControllerHeadSha -A0IsConfirmed ([bool]$A0Confirmed)
    }
    catch {
        Write-Output ('HOLD:' + $_.Exception.Message)
        Write-Output 'GATE_A1_LDW01=HOLD'
        exit 1
    }
}
