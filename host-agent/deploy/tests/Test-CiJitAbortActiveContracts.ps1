Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$worker = Join-Path $deployRoot 'Invoke-CiJitControlTask.ps1'
$bootstrap = Join-Path $deployRoot 'Bootstrap-CiJitControlTasks.ps1'

$workerRelative = 'host-agent/deploy/Invoke-CiJitControlTask.ps1'
$expectedCandidateWorkerBlob = '28e2d52ad1fa48ffacdf9fa69e1e4984f3a5ea38'
$expectedAcceptedWorkerBlob = 'a0a79f92d31859dd4a930b358b10c7b4cf11db48'

$script:Assertions = 0
$script:CleanupCalls = [Collections.Generic.List[object]]::new()
$script:CapturedResult = $null

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Value,
        [Parameter(Mandatory)][string]$Message
    )

    $script:Assertions++

    if (-not $Value) {
        throw "ASSERTION_FAILED: $Message"
    }
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

Assert-True (
    @($errors).Count -eq 0
) 'ABORT worker must parse'

$helper = $ast.Find(
    {
        param($n)

        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -ceq 'Invoke-AbortActive'
    },
    $false
)

Assert-True (
    $null -ne $helper
) 'Invoke-AbortActive helper must exist'

$abortSwitches = @(
    $ast.FindAll(
        {
            param($n)

            if (
                $n -isnot
                [Management.Automation.Language.SwitchStatementAst]
            ) {
                return $false
            }

            @(
                $n.Clauses |
                    Where-Object {
                        $_.Item1.Extent.Text -cin @(
                            "'ABORT_ACTIVE'",
                            '"ABORT_ACTIVE"'
                        )
                    }
            ).Count -eq 1
        },
        $true
    )
)

Assert-True (
    $abortSwitches.Count -eq 1
) 'production ABORT_ACTIVE switch must be uniquely discoverable'

$abortClauses = @(
    $abortSwitches[0].Clauses |
        Where-Object {
            $_.Item1.Extent.Text -cin @(
                "'ABORT_ACTIVE'",
                '"ABORT_ACTIVE"'
            )
        }
)

Assert-True (
    $abortClauses.Count -eq 1
) 'production ABORT_ACTIVE clause must be unique'

$abortCalls = @(
    $abortClauses[0].Item2.FindAll(
        {
            param($n)

            $n -is [Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -ceq 'Invoke-AbortActive'
        },
        $true
    )
)

Assert-True (
    $abortCalls.Count -eq 1
) 'production ABORT_ACTIVE clause must call helper exactly once'

$actualAbortCall = (
    $abortCalls[0].Extent.Text -replace '\s+', ' '
).Trim()

$expectedAbortCall =
    "Invoke-AbortActive (Join-Path `$controllerRoot 'runs') `$runnerEntry"

Assert-True (
    $actualAbortCall -ceq $expectedAbortCall
) 'production ABORT_ACTIVE helper wiring must remain exact'

# Candidate/runtime provenance split.
$bootstrapTokens = $null
$bootstrapErrors = $null

$bootstrapAst = [Management.Automation.Language.Parser]::ParseFile(
    $bootstrap,
    [ref]$bootstrapTokens,
    [ref]$bootstrapErrors
)

Assert-True (
    @($bootstrapErrors).Count -eq 0
) 'CI/JIT bootstrap must parse'

$acceptedWorkerAssignment = $bootstrapAst.Find(
    {
        param($n)

        $n -is
            [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq '$acceptedWorkerBlob'
    },
    $false
)

Assert-True (
    $null -ne $acceptedWorkerAssignment
) 'bootstrap accepted worker assignment must exist'

$acceptedWorkerMatch = [regex]::Match(
    $acceptedWorkerAssignment.Extent.Text,
    '^\s*\$acceptedWorkerBlob\s*=\s*''([a-f0-9]{40})''\s*$',
    [Text.RegularExpressions.RegexOptions]::CultureInvariant
)

Assert-True (
    $acceptedWorkerMatch.Success
) 'bootstrap accepted worker pin must remain a literal'

$acceptedWorkerBlob =
    [string]$acceptedWorkerMatch.Groups[1].Value

$repoRoot = (
    & git -C $PSScriptRoot rev-parse --show-toplevel
).Trim()

if ($LASTEXITCODE -ne 0 -or -not $repoRoot) {
    throw 'ABORT_REPO_ROOT_REQUIRED'
}

$currentWorkerBlob = (
    & git -C $repoRoot hash-object -- $workerRelative
).Trim()

Assert-True (
    $LASTEXITCODE -eq 0 -and
    $currentWorkerBlob -ceq $expectedCandidateWorkerBlob
) 'source-review worker must be exact #168 candidate blob'

Assert-True (
    $acceptedWorkerBlob -ceq $expectedAcceptedWorkerBlob
) 'runtime bootstrap must remain pinned to prior accepted worker'

Assert-True (
    $acceptedWorkerBlob -cne $currentWorkerBlob
) 'candidate and accepted runtime worker identities must remain split'

$bootstrapSource = Get-Content -LiteralPath $bootstrap -Raw

Assert-True (
    -not $bootstrapSource.Contains(
        $expectedCandidateWorkerBlob,
        [StringComparison]::Ordinal
    )
) 'runtime bootstrap must not promote #168 candidate before provenance refresh'

$guard = $bootstrapAst.Find(
    {
        param($n)

        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -ceq 'Assert-AcceptedCheckout'
    },
    $false
)

Assert-True (
    $null -ne $guard
) 'bootstrap accepted-checkout guard must exist'

Assert-True (
    $guard.Extent.Text.Contains(
        '$workerBlob -cne $acceptedWorkerBlob',
        [StringComparison]::Ordinal
    )
) 'bootstrap guard must reject candidate worker until provenance refresh'

# Load only the helper function, never the worker top-level runtime.
. ([scriptblock]::Create($helper.Extent.Text))

$abortClauseBody = $abortClauses[0].Item2.Extent.Text

$script:AbortSwitchBlock = [scriptblock]::Create(
    "switch ('ABORT_ACTIVE') { 'ABORT_ACTIVE' $abortClauseBody }"
)

function Reset-CleanupCalls {
    $script:CleanupCalls.Clear()
}

function Invoke-Child {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $script:CleanupCalls.Add(
        [pscustomobject]@{
            Path = $Path
            Arguments = @($Arguments)
        }
    )

    [pscustomobject]@{
        ExitCode = 0
        Lines = @('CLEANUP_IDEMPOTENT=PASS')
    }
}

function Write-Result {
    param(
        [bool]$Success,
        [string]$State,
        [string]$Reason
    )

    $script:CapturedResult = [pscustomobject]@{
        Success = $Success
        State = $State
        Reason = $Reason
    }
}

function Invoke-AbortSwitchFixture {
    param(
        [Parameter(Mandatory)][string]$ControllerRoot,
        [Parameter(Mandatory)][string]$RunnerPath
    )

    $script:CapturedResult = $null

    $controllerRoot = $ControllerRoot
    $runnerEntry = $RunnerPath

    & $script:AbortSwitchBlock

    if ($null -eq $script:CapturedResult) {
        throw 'ABORT_SWITCH_RESULT_REQUIRED'
    }

    $script:CapturedResult
}

$tempRoot = Join-Path (
    [IO.Path]::GetTempPath()
) ('ldw-ci-jit-abort-' + [guid]::NewGuid().ToString('N'))

$runsPath = Join-Path $tempRoot 'runs'
$runnerPath = 'C:\synthetic\Invoke-IsolatedRunner.ps1'

try {
    New-Item -ItemType Directory -Path $tempRoot -Force |
        Out-Null

    # Missing runs directory.
    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $false 'BLOCKED' 'NO_ACTIVE_JOB'
    Assert-True (
        $script:CleanupCalls.Count -eq 0
    ) 'missing runs path must not invoke cleanup'

    # Unexpected non-directory runs path.
    New-Item -ItemType File -Path $runsPath -Force |
        Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $false 'BLOCKED' 'LOCK_OR_RESIDUE_UNCERTAIN'
    Assert-True (
        $script:CleanupCalls.Count -eq 0
    ) 'non-directory runs path must not invoke cleanup'

    Remove-Item -LiteralPath $runsPath -Force

    # Existing but empty runs directory.
    New-Item -ItemType Directory -Path $runsPath -Force |
        Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $false 'BLOCKED' 'NO_ACTIVE_JOB'
    Assert-True (
        $script:CleanupCalls.Count -eq 0
    ) 'empty runs path must not invoke cleanup'

    # One exact owned run.
    $validRun = 'a' * 32
    $validPath = Join-Path $runsPath $validRun

    New-Item -ItemType Directory -Path $validPath |
        Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $true 'PASS' 'NONE'

    Assert-True (
        $script:CleanupCalls.Count -eq 1
    ) 'one valid run must invoke cleanup exactly once'

    $call = $script:CleanupCalls[0]

    Assert-True (
        $call.Path -ceq $runnerPath
    ) 'cleanup must use exact runner path'

    Assert-True (
        ($call.Arguments -join '|') -ceq (
            '-Mode|Cleanup|-LocalRunId|' + $validRun
        )
    ) 'cleanup must target only the exact valid local run'

    Remove-Item -LiteralPath $validPath -Recurse -Force

    # Multiple valid run identities.
    foreach ($name in @(
        ('b' * 32),
        ('c' * 32)
    )) {
        New-Item -ItemType Directory -Path (
            Join-Path $runsPath $name
        ) | Out-Null
    }

    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $false 'AMBIGUOUS' 'IDENTITY_MISMATCH'

    Assert-True (
        $script:CleanupCalls.Count -eq 0
    ) 'multiple runs must not invoke cleanup'

    Get-ChildItem -LiteralPath $runsPath -Directory |
        Remove-Item -Recurse -Force

    # One malformed run identity.
    New-Item -ItemType Directory -Path (
        Join-Path $runsPath 'not-a-valid-local-run'
    ) | Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortSwitchFixture $tempRoot $runnerPath
    Assert-Result $result $false 'AMBIGUOUS' 'IDENTITY_MISMATCH'

    Assert-True (
        $script:CleanupCalls.Count -eq 0
    ) 'malformed run identity must not invoke cleanup'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "CI_JIT_ABORT_ACTIVE_CONTRACT=PASS ASSERTIONS=$script:Assertions"
