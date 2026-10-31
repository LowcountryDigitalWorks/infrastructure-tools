$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$path = Join-Path $repo 'ci-dispatch/Invoke-DragonflyGateA1.ps1'
$text = Get-Content -LiteralPath $path -Raw

function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ThrowsMessage([scriptblock]$Action,[string]$Expected) {
    $message = $null
    try { & $Action | Out-Null } catch { $message = $_.Exception.Message }
    Assert-True ($message -ceq $Expected) ('EXPECTED:' + $Expected + ';ACTUAL:' + $message)
}

function Invoke-Git([string[]]$GitArgs) {
    $result = & git @GitArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'GATE_A1_TEST_GIT_FAILED' }
    $result
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $path,
    [ref]$tokens,
    [ref]$errors
)
Assert-True (@($errors).Count -eq 0) 'GATE_A1_OPERATOR_PARSE_FAILED'

$paramBlock = $ast.ParamBlock
Assert-True ($null -ne $paramBlock) 'GATE_A1_OPERATOR_PARAM_BLOCK_MISSING'
$params = @($paramBlock.Parameters)
Assert-True ($params.Count -eq 3) 'GATE_A1_OPERATOR_PARAMETER_SURFACE_DRIFT'
Assert-True ($params[0].Name.VariablePath.UserPath -ceq 'RepositoryRoot') 'GATE_A1_OPERATOR_PARAMETER_NAME_DRIFT'
Assert-True ($params[1].Name.VariablePath.UserPath -ceq 'ExpectedControllerHeadSha') 'GATE_A1_OPERATOR_EXPECTED_HEAD_PARAMETER_MISSING'
Assert-True ($params[2].Name.VariablePath.UserPath -ceq 'A0Confirmed') 'GATE_A1_OPERATOR_A0_PARAMETER_MISSING'

$required = @(
    'GATE_A1_A0_CONFIRMATION_REQUIRED',
    'A0_REDRIX_RUNTIME_BASELINE_CONFIRMED_BY_ORCHESTRATOR=yes',
    'GATE_A1_WINDOWS_REQUIRED',
    'GATE_A1_ADMINISTRATOR_REQUIRED',
    'GATE_A1_REPOSITORY_REFUSED',
    'GATE_A1_SOURCE_WORKTREE_DIRTY',
    'GATE_A1_CONTROLLER_HEAD_MISMATCH',
    'GATE_A1_DRAGONFLY_UNCERTAINTY_PRESENT',
    'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE',
    'GATE_A1_REDRIX_PRIVATE_TAILSCALE_IPV4_NOT_UNIQUE',
    'tools\dragonfly_canary_publication.py',
    'build-redrix',
    'verify-redrix',
    'ci-dispatch\DragonflyCanaryAdjunctPublisher.psm1',
    'Publish-LdwDragonflyCanaryAdjunct',
    'Test-LdwDragonflyCanaryAdjunct',
    'CI10_PROTECTED_BUNDLE_UNCHANGED',
    'TRANSPORT_PRIVATE_KEY_UNCHANGED',
    'TRANSPORT_KNOWN_HOSTS_UNCHANGED',
    'TRANSPORT_PUBLIC_IDENTITY_SHA256=',
    'TRANSPORT_KEY_PROVENANCE=gate-a1-ldw01-transport-private-key-unchanged-contract',
    'TRANSPORT_PUBLIC_IDENTITY_DERIVED',
    'GATE_A1_TRANSPORT_IDENTITY_RECORD=',
    'dragonfly_gate_a1_transport_identity.py',
    'derive-bound',
    'write-bound-record',
    'GITHUB_PROVIDER_ACTIONS_INVOKED_BY_HARNESS=no',
    'WORKFLOW_DISPATCH_INVOKED_BY_HARNESS=no',
    'SSH_TRANSPORT_INVOKED_BY_HARNESS=no',
    'REDRIX_INSTALL_INVOKED_BY_HARNESS=no',
    'QEMU_INVOKED_BY_HARNESS=no',
    'GATE_B_ACTIONS_INVOKED_BY_HARNESS=no',
    'GATE_A1_LDW01=PASS',
    'GATE_A1_LDW01=HOLD'
)
foreach ($value in $required) {
    Assert-True $text.Contains($value) ('GATE_A1_OPERATOR_REQUIRED_MISSING:' + $value)
}

$forbidden = @(
    'gh api',
    'generate-jitconfig',
    'encoded_jit_config',
    'Invoke-DragonflyCanaryProduction',
    'dragonfly_canary_redrix_install.py',
    'qemu-system',
    'ssh.exe',
    'authorized_keys',
    'Start-Service',
    'Stop-Service',
    'Set-Service',
    'Remove-Item -LiteralPath $privateKey',
    'Remove-Item -LiteralPath $knownHosts',
    '[IO.Path]::GetRelativePath',
    'REAL_JIT_CONFIG_GENERATED=no',
    'RUNNER_REGISTERED=no',
    'WORKFLOW_DISPATCHED=no',
    'REDRIX_MUTATED=no'
)
foreach ($value in $forbidden) {
    Assert-True (-not $text.Contains($value)) ('GATE_A1_OPERATOR_FORBIDDEN_PRESENT:' + $value)
}

$build = $text.IndexOf('build-redrix',[StringComparison]::Ordinal)
$verify = $text.IndexOf('verify-redrix',[StringComparison]::Ordinal)
$publish = $text.IndexOf('Publish-LdwDragonflyCanaryAdjunct',[StringComparison]::Ordinal)
$readback = $text.IndexOf('Test-LdwDragonflyCanaryAdjunct',[StringComparison]::Ordinal)
Assert-True ($build -ge 0 -and $verify -gt $build -and $publish -gt $verify -and $readback -gt $publish) 'GATE_A1_OPERATOR_SEQUENCE_INVALID'
Assert-True (-not $text.Contains("New-Item -ItemType Directory -Path `$packageOutput")) 'GATE_A1_OPERATOR_PRECREATES_PACKAGE_OUTPUT'
Assert-True ($text.Contains("Write-Output ('HOLD:' + `$_.Exception.Message)")) 'GATE_A1_OPERATOR_HOLD_OUTPUT_MISSING'
Assert-True ($text.Contains('exit 1')) 'GATE_A1_OPERATOR_FAIL_CLOSED_EXIT_MISSING'

# Dot-source only; the script's dot-source guard must prevent machine execution.
. $path -RepositoryRoot $repo -ExpectedControllerHeadSha ('0' * 40)

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-gatea1-operator-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    # PS 5.1-safe path/digest behavior: no Path.GetRelativePath dependency.
    $treeRoot = Join-Path $root 'tree'
    $nested = Join-Path $treeRoot 'nested'
    $null = New-Item -ItemType Directory -Path $nested -Force
    $leaf = Join-Path $nested 'value.txt'
    [IO.File]::WriteAllText($leaf,'one',[Text.UTF8Encoding]::new($false))
    $relative = Get-LdwGateA1RelativePath -Root $treeRoot -Path $leaf
    Assert-True ($relative -ceq 'nested/value.txt') 'GATE_A1_RELATIVE_PATH_INVALID'
    $digest1 = Get-LdwGateA1TreeDigest -Root $treeRoot
    $digest2 = Get-LdwGateA1TreeDigest -Root $treeRoot
    Assert-True ($digest1 -ceq $digest2) 'GATE_A1_TREE_DIGEST_NONDETERMINISTIC'
    [IO.File]::WriteAllText($leaf,'two',[Text.UTF8Encoding]::new($false))
    $digest3 = Get-LdwGateA1TreeDigest -Root $treeRoot
    Assert-True ($digest3 -cne $digest1) 'GATE_A1_TREE_DIGEST_CHANGE_NOT_DETECTED'
    Assert-ThrowsMessage { Get-LdwGateA1RelativePath -Root $treeRoot -Path (Join-Path $root 'outside.txt') } 'GATE_A1_TREE_PATH_OUTSIDE_ROOT'

    # Controller identity is exact, not merely trusted-origin + clean.
    $fixture = Join-Path $root 'repo with spaces'
    $null = Invoke-Git @('init','--quiet',$fixture)
    $null = Invoke-Git @('-C',$fixture,'config','user.name','Synthetic Gate A1 Test')
    $null = Invoke-Git @('-C',$fixture,'config','user.email','synthetic@example.invalid')
    [IO.File]::WriteAllText((Join-Path $fixture 'fixture.txt'),'fixture',[Text.UTF8Encoding]::new($false))
    $null = Invoke-Git @('-C',$fixture,'add','fixture.txt')
    $null = Invoke-Git @('-C',$fixture,'commit','--quiet','-m','fixture')
    $null = Invoke-Git @('-C',$fixture,'remote','add','origin','https://github.com/LowcountryDigitalWorks/infrastructure-tools.git')
    $head = ([string](Invoke-Git @('-C',$fixture,'rev-parse','HEAD'))).Trim()
    $actual = Assert-LdwGateA1Repository -Root $fixture -ExpectedHead $head
    Assert-True ($actual.Head -ceq $head) 'GATE_A1_CONTROLLER_HEAD_NOT_RETURNED'
    Assert-ThrowsMessage { Assert-LdwGateA1Repository -Root $fixture -ExpectedHead ('0' * 40) } 'GATE_A1_CONTROLLER_HEAD_MISMATCH'
    [IO.File]::WriteAllText((Join-Path $fixture 'untracked.txt'),'dirty',[Text.UTF8Encoding]::new($false))
    Assert-ThrowsMessage { Assert-LdwGateA1Repository -Root $fixture -ExpectedHead $head } 'GATE_A1_SOURCE_WORKTREE_DIRTY'
    Remove-Item -LiteralPath (Join-Path $fixture 'untracked.txt') -Force

    # A0 confirmation must stop execution before Windows/elevation checks or mutation.
    Assert-ThrowsMessage {
        Invoke-LdwDragonflyGateA1 -Root $fixture -ExpectedHead $head -A0IsConfirmed:$false
    } 'GATE_A1_A0_CONFIRMATION_REQUIRED'

    # Pure Tailscale-status behavior: exactly one online REDRIX/penguin peer and one CGNAT IPv4.
    $goodPeer = [pscustomobject]@{
        HostName='redrix'; DNSName='redrix.example.ts.net'; Online=$true; TailscaleIPs=@('100.64.1.2')
    }
    $goodStatus = [pscustomobject]@{
        BackendState='Running'; Self=[pscustomobject]@{Online=$true}; Peer=[pscustomobject]@{ one=$goodPeer }
    }
    $ts = Assert-LdwGateA1TailscaleStatusObject -Status $goodStatus
    Assert-True ($ts.PeerDiscovered -eq $true -and $ts.PrivateIPv4Present -eq $true) 'GATE_A1_TAILSCALE_GOOD_STATUS_REFUSED'

    $duplicateStatus = [pscustomobject]@{
        BackendState='Running'; Self=[pscustomobject]@{Online=$true}; Peer=[pscustomobject]@{ one=$goodPeer; two=$goodPeer }
    }
    Assert-ThrowsMessage { Assert-LdwGateA1TailscaleStatusObject -Status $duplicateStatus } 'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE'

    $badIpPeer = [pscustomobject]@{
        HostName='penguin'; DNSName='penguin.example.ts.net'; Online=$true; TailscaleIPs=@('192.0.2.10')
    }
    $badIpStatus = [pscustomobject]@{
        BackendState='Running'; Self=[pscustomobject]@{Online=$true}; Peer=[pscustomobject]@{ one=$badIpPeer }
    }
    Assert-ThrowsMessage { Assert-LdwGateA1TailscaleStatusObject -Status $badIpStatus } 'GATE_A1_REDRIX_PRIVATE_TAILSCALE_IPV4_NOT_UNIQUE'

    $offlineStatus = [pscustomobject]@{
        BackendState='Running'; Self=[pscustomobject]@{Online=$true}; Peer=[pscustomobject]@{ one=[pscustomobject]@{HostName='redrix';DNSName='';Online=$false;TailscaleIPs=@('100.64.1.2')} }
    }
    Assert-ThrowsMessage { Assert-LdwGateA1TailscaleStatusObject -Status $offlineStatus } 'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE'

    'GATE_A1_OPERATOR_CONTRACT=PASS'
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -cnotmatch '^ldw-gatea1-operator-[a-f0-9]{32}$') {
        throw 'GATE_A1_TEST_CLEANUP_PATH_REFUSED'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
