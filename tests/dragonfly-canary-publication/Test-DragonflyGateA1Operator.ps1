$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$path = Join-Path $repo 'ci-dispatch/Invoke-DragonflyGateA1.ps1'
$text = Get-Content -LiteralPath $path -Raw

function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
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
Assert-True ($params.Count -eq 1) 'GATE_A1_OPERATOR_PARAMETER_SURFACE_DRIFT'
Assert-True ($params[0].Name.VariablePath.UserPath -ceq 'RepositoryRoot') 'GATE_A1_OPERATOR_PARAMETER_NAME_DRIFT'

$required = @(
    'GATE_A1_WINDOWS_REQUIRED',
    'GATE_A1_ADMINISTRATOR_REQUIRED',
    'GATE_A1_REPOSITORY_REFUSED',
    'GATE_A1_SOURCE_WORKTREE_DIRTY',
    'GATE_A1_DRAGONFLY_UNCERTAINTY_PRESENT',
    'GATE_A1_REDRIX_TAILSCALE_PEER_NOT_UNIQUE',
    'GATE_A1_REDRIX_PRIVATE_TAILSCALE_IPV4_NOT_UNIQUE',
    'tools\\dragonfly_canary_publication.py',
    'build-redrix',
    'verify-redrix',
    'ci-dispatch\\DragonflyCanaryAdjunctPublisher.psm1',
    'Publish-LdwDragonflyCanaryAdjunct',
    'Test-LdwDragonflyCanaryAdjunct',
    'CI10_PROTECTED_BUNDLE_UNCHANGED',
    'TRANSPORT_PRIVATE_KEY_UNCHANGED',
    'TRANSPORT_KNOWN_HOSTS_UNCHANGED',
    'REAL_JIT_CONFIG_GENERATED=no',
    'RUNNER_REGISTERED=no',
    'WORKFLOW_DISPATCHED=no',
    'QEMU_LAUNCHED=no',
    'REDRIX_MUTATED=no',
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
    'Remove-Item -LiteralPath $knownHosts'
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

'GATE_A1_OPERATOR_CONTRACT=PASS'
