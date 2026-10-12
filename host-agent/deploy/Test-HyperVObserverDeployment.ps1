[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$status = & (Join-Path $PSScriptRoot 'Get-HyperVObserverStatus.ps1')
if (-not $status.Installed -or $status.DriftDetected -or [string]$status.TaskState -ne 'Running') {
    throw 'Persistent Hyper-V observer deployment verification failed. Do not weaken local security policy to force a pass.'
}

$status
