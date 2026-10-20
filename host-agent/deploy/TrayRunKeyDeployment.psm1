#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$script:RunValueName = 'LDW.HostAgent.Windows'

function Get-TrayAutostartRunCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExecutablePath)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath) -or -not [IO.Path]::IsPathFullyQualified($ExecutablePath)) {
        throw 'The Run-key executable path must be absolute.'
    }
    if ($ExecutablePath -match '"') { throw 'Executable path contains unsupported quote characters.' }
    return '"{0}"' -f [IO.Path]::GetFullPath($ExecutablePath)
}

function Get-TrayAutostartRunEntry {
    [CmdletBinding()]
    param(
        [string]$Path = $script:RunKeyPath,
        [string]$Name = $script:RunValueName
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject]@{ Present = $false; Value = $null; Path = $Path; Name = $Name }
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ Present = $false; Value = $null; Path = $Path; Name = $Name }
    }
    $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    [pscustomobject]@{ Present = $true; Value = [string]$value; Path = $Path; Name = $Name }
}

function Test-TrayAutostartRunEntryMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$ExpectedValue
    )
    return [string]::Equals($Value, $ExpectedValue, [StringComparison]::OrdinalIgnoreCase)
}

function Set-TrayAutostartRunEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [string]$Path = $script:RunKeyPath,
        [string]$Name = $script:RunValueName
    )

    $expected = Get-TrayAutostartRunCommand -ExecutablePath $ExecutablePath
    $existing = Get-TrayAutostartRunEntry -Path $Path -Name $Name
    if ($existing.Present -and -not (Test-TrayAutostartRunEntryMatches -Value $existing.Value -ExpectedValue $expected)) {
        throw 'Existing per-user Host Agent startup value drifted; no mutation was performed.'
    }
    if ($existing.Present) {
        return [pscustomobject]@{ Present = $true; Changed = $false; Path = $Path; Name = $Name }
    }

    $createdKey = $false
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            $createdKey = $true
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $expected -PropertyType String -Force -ErrorAction Stop | Out-Null
        $readback = Get-TrayAutostartRunEntry -Path $Path -Name $Name
        if (-not $readback.Present -or -not (Test-TrayAutostartRunEntryMatches -Value $readback.Value -ExpectedValue $expected)) {
            throw 'Per-user Host Agent startup value failed exact readback.'
        }
        return [pscustomobject]@{ Present = $true; Changed = $true; Path = $Path; Name = $Name }
    } catch {
        $installError = $_
        $current = Get-TrayAutostartRunEntry -Path $Path -Name $Name
        if ($current.Present -and (Test-TrayAutostartRunEntryMatches -Value $current.Value -ExpectedValue $expected)) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        }
        if ($createdKey -and (Test-Path -LiteralPath $Path -PathType Container)) {
            $remaining = @(Get-ItemProperty -LiteralPath $Path -ErrorAction Stop | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' })
            if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $Path -ErrorAction SilentlyContinue }
        }
        throw $installError
    }
}

function Remove-TrayAutostartRunEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [string]$Path = $script:RunKeyPath,
        [string]$Name = $script:RunValueName
    )

    $expected = Get-TrayAutostartRunCommand -ExecutablePath $ExecutablePath
    $existing = Get-TrayAutostartRunEntry -Path $Path -Name $Name
    if (-not $existing.Present) {
        return [pscustomobject]@{ Present = $false; Changed = $false; Path = $Path; Name = $Name }
    }
    if (-not (Test-TrayAutostartRunEntryMatches -Value $existing.Value -ExpectedValue $expected)) {
        throw 'Existing per-user Host Agent startup value drifted; no mutation was performed.'
    }
    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    $readback = Get-TrayAutostartRunEntry -Path $Path -Name $Name
    if ($readback.Present) { throw 'Per-user Host Agent startup removal failed exact readback.' }
    [pscustomobject]@{ Present = $false; Changed = $true; Path = $Path; Name = $Name }
}

Export-ModuleMember -Function Get-TrayAutostartRunCommand, Get-TrayAutostartRunEntry, Test-TrayAutostartRunEntryMatches, Set-TrayAutostartRunEntry, Remove-TrayAutostartRunEntry
