Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$worker = Join-Path $deployRoot 'Invoke-CiJitControlTask.ps1'

$script:Assertions = 0
$script:Fixture = $null

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Value,
        [Parameter(Mandatory)][string]$Message
    )

    $script:Assertions++
    if (-not $Value) { throw "ASSERTION_FAILED: $Message" }
}

function Assert-Result {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$Reason
    )

    Assert-True ($Result.Success -eq $Success) "success expected $Success"
    Assert-True ($Result.State -ceq $State) "state expected $State"
    Assert-True ($Result.Reason -ceq $Reason) "reason expected $Reason"
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $worker,
    [ref]$tokens,
    [ref]$errors
)

Assert-True (@($errors).Count -eq 0) 'CI/JIT worker must parse'

function Get-FunctionAst {
    param([Parameter(Mandatory)][string]$Name)

    $node = $ast.Find(
        {
            param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $n.Name -ceq $Name
        },
        $false
    )

    Assert-True ($null -ne $node) "worker function $Name must exist"
    $node
}

$invokeChildAst = Get-FunctionAst 'Invoke-Child'
$getOutputAst = Get-FunctionAst 'Get-OutputValue'
$mapAst = Get-FunctionAst 'Convert-DispatcherClassificationToReason'
$dispatcherModeAst = Get-FunctionAst 'Invoke-DispatcherMode'

$invokeChildSource = $invokeChildAst.Extent.Text
Assert-True (
    $invokeChildSource.Contains(
        '$process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)',
        [StringComparison]::Ordinal
    )
) 'child stderr must remain discarded'
Assert-True (
    $invokeChildSource.Contains(
        "'^CLASSIFICATION='",
        [StringComparison]::Ordinal
    )
) 'classification handling must be explicit and case-sensitive'
Assert-True (
    $invokeChildSource.Contains(
        '$script:DispatcherClassificationPattern',
        [StringComparison]::Ordinal
    )
) 'classification handling must use the bounded pattern'
Assert-True (
    $invokeChildSource.Contains(
        'ClassificationInvalid=$classificationInvalid',
        [StringComparison]::Ordinal
    )
) 'malformed classification state must be carried only as a boolean diagnostic'
Assert-True (
    -not $invokeChildSource.Contains(
        'StandardError.ReadToEnd',
        [StringComparison]::Ordinal
    )
) 'raw stderr must not become readable output'

$workerSource = Get-Content -LiteralPath $worker -Raw
Assert-True (
    $workerSource.Contains(
        "$script:DispatcherClassificationPattern = '[A-Z][A-Z0-9_]{0,63}'",
        [StringComparison]::Ordinal
    )
) 'classification must remain bounded to 1-64 uppercase token characters'

# Load only the pure/synthetic-testable functions, never worker top-level runtime.
. ([scriptblock]::Create($getOutputAst.Extent.Text))
. ([scriptblock]::Create($mapAst.Extent.Text))
. ([scriptblock]::Create($dispatcherModeAst.Extent.Text))

$script:CapacitySubreasonPattern = 'CAPACITY_RAM_RESERVE_4GIB_REQUIRED|CAPACITY_CPU_RESERVE_REQUIRED|CAPACITY_CPU_LOAD_TOO_HIGH|CAPACITY_DISK_RESERVE_40GIB_REQUIRED|DEFAULT_NAT_SWITCH_REQUIRED'
$script:DispatcherClassificationPattern = '[A-Z][A-Z0-9_]{0,63}'
$ManifestSha = 'a' * 64
$Commit = 'b' * 40
$Tree = 'c' * 40
$dispatcher = 'C:\synthetic\Invoke-Dispatcher.ps1'

function Invoke-Child {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    if ($Path -cne $dispatcher) { throw 'SYNTHETIC_DISPATCHER_PATH_MISMATCH' }
    $script:Fixture
}

function Invoke-Fixture {
    param(
        [Parameter(Mandatory)][ValidateSet('Discover','Once','Recover')][string]$Mode,
        [Parameter(Mandatory)][int]$ExitCode,
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][bool]$ClassificationInvalid
    )

    $script:Fixture = [pscustomobject]@{
        ExitCode = $ExitCode
        Lines = @($Lines)
        ClassificationInvalid = $ClassificationInvalid
    }

    Invoke-DispatcherMode $Mode
}

# Known bounded failure families map only to existing typed reasons.
$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=PREFLIGHT_PROVENANCE_MISMATCH'
) $false
Assert-Result $result $false 'FAILED' 'PROVENANCE_MISMATCH'

$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN'
) $false
Assert-Result $result $false 'FAILED' 'LOCK_OR_RESIDUE_UNCERTAIN'

$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=QUEUE_UNAVAILABLE'
) $false
Assert-Result $result $false 'FAILED' 'QUEUE_UNAVAILABLE'

$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=CAPACITY_RAM_RESERVE_4GIB_REQUIRED'
) $false
Assert-Result $result $false 'FAILED' 'CAPACITY_RAM_RESERVE_4GIB_REQUIRED'

# Valid but unknown classification is never promoted into a new external reason.
$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=SOME_FUTURE_INTERNAL_FAILURE'
) $false
Assert-Result $result $false 'FAILED' 'FAILED'

# Missing, duplicate, or malformed classifications fail closed.
$result = Invoke-Fixture Recover 1 @('DISPATCHER_RESULT=FAIL') $false
Assert-Result $result $false 'FAILED' 'FAILED'

$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=QUEUE_UNAVAILABLE',
    'CLASSIFICATION=QUEUE_UNAVAILABLE'
) $false
Assert-Result $result $false 'FAILED' 'FAILED'

$result = Invoke-Fixture Recover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=QUEUE_UNAVAILABLE'
) $true
Assert-Result $result $false 'FAILED' 'FAILED'

# The new diagnostic mapping is RECOVER-only; other operation failures remain generic.
$result = Invoke-Fixture Discover 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=QUEUE_UNAVAILABLE'
) $false
Assert-Result $result $false 'FAILED' 'FAILED'

$result = Invoke-Fixture Once 1 @(
    'DISPATCHER_RESULT=FAIL',
    'CLASSIFICATION=PREFLIGHT_PROVENANCE_MISMATCH'
) $false
Assert-Result $result $false 'FAILED' 'FAILED'

# Existing successful Recover semantics remain PASS/NONE.
$previousProgramData = $env:ProgramData
$tempProgramData = Join-Path ([IO.Path]::GetTempPath()) ('ldw-recover-contract-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $tempProgramData -Force | Out-Null
    $env:ProgramData = $tempProgramData
    $result = Invoke-Fixture Recover 0 @('DISPATCHER_RESULT=RECOVERED') $false
    Assert-Result $result $true 'PASS' 'NONE'
}
finally {
    $env:ProgramData = $previousProgramData
    if (Test-Path -LiteralPath $tempProgramData) {
        Remove-Item -LiteralPath $tempProgramData -Recurse -Force
    }
}

# The protected dispatcher still treats CAPACITY as an accepted Recover gate.
$repoRoot = (& git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or -not $repoRoot) { throw 'RECOVER_REPO_ROOT_REQUIRED' }
$protectedDispatcher = Join-Path $repoRoot 'ci-dispatch/Invoke-Dispatcher.ps1'
$protectedSource = Get-Content -LiteralPath $protectedDispatcher -Raw
Assert-True (
    $protectedSource.Contains(
        "if (`$gate -notin @('READY','CAPACITY')) { throw 'RECOVERY_BUSY_OR_UNCERTAIN' }",
        [StringComparison]::Ordinal
    )
) 'protected Recover gate must continue accepting READY or CAPACITY'
Assert-True (
    $protectedSource.Contains(
        "'DISPATCHER_RESULT=RECOVERED'",
        [StringComparison]::Ordinal
    )
) 'protected Recover must continue emitting RECOVERED on accepted gate'

Write-Host "CI_JIT_RECOVER_CLASSIFICATION_CONTRACT=PASS ASSERTIONS=$script:Assertions"
