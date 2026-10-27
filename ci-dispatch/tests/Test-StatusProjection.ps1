[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$sandbox=Join-Path ([IO.Path]::GetTempPath()) ('ldw-ci-jit-status-'+[guid]::NewGuid().ToString('N'))
$oldProgramData=$env:ProgramData
$total=0
function Check([string]$Name,[scriptblock]$Body){$script:case=$Name;& $Body;$script:total++;'PASS '+$Name}
function Assert([bool]$Condition){if(-not $Condition){throw ('TEST_ASSERTION_FAILED:'+ $script:case)}}
try {
    $env:ProgramData=$sandbox
    $parent=Join-Path $sandbox 'LDW'
    $null=New-Item -ItemType Directory -Path $parent -Force
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $acl.SetOwner($admin)
        foreach($sid in @($admin,$system)){
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $parent -AclObject $acl
    }
    Import-Module (Join-Path $repo 'ci-dispatch/StatusProjection.psm1') -Force
    $fresh=[pscustomobject]@{Schema='ci10-queue-v1';QueueState='FRESH';EligibleQueuedCount=1;HeldQueuedCount=0;HeldReasonCounts=@();Selected=[pscustomobject]@{ProfileId='ci10-bo-secret-scan';RunId=101;JobId=202}}
    Check 'fresh queue projection is bounded and sanitized' {
        Set-Ci10StatusQueueProjection -QueueSnapshot $fresh -Capacity READY -ProvenanceValid
        $status=Get-Content -LiteralPath (Get-Ci10StatusProjectionPath) -Raw|ConvertFrom-Json
        Assert ($status.schema -eq 1 -and $status.source_version -ceq 'ci-jit-v1')
        Assert ($status.queue_state -ceq 'FRESH' -and $status.eligible_queued_count -eq 1 -and $status.selected_run_id -eq 101)
        Assert ($status.capacity -ceq 'READY' -and $null -eq $status.reason_code)
    }
    Check 'active controller phase wins over concurrent READY queue refresh' {
        Set-Ci10StatusControllerPhase -Phase Running -ProvenanceValid
        Set-Ci10StatusQueueProjection -QueueSnapshot $fresh -Capacity READY -ProvenanceValid
        $status=Get-Content -LiteralPath (Get-Ci10StatusProjectionPath) -Raw|ConvertFrom-Json
        Assert ($status.controller_phase -ceq 'Running' -and $status.capacity -ceq 'BUSY' -and $status.reason_code -ceq 'BUSY')
    }
    Check 'lock-only BUSY without controller phase fails closed to UNKNOWN' {
        Set-Ci10StatusControllerPhase -Phase Complete -ProvenanceValid
        Set-Ci10StatusQueueProjection -QueueSnapshot $fresh -Capacity BUSY -ProvenanceValid
        $status=Get-Content -LiteralPath (Get-Ci10StatusProjectionPath) -Raw|ConvertFrom-Json
        Assert ($status.capacity -ceq 'UNKNOWN' -and $status.reason_code -ceq 'UNKNOWN')
    }
    Check 'unavailable queue drops all prior queue identity' {
        $unavailable=[pscustomobject]@{Schema='ci10-queue-v1';QueueState='UNAVAILABLE';EligibleQueuedCount=$null;HeldQueuedCount=$null;HeldReasonCounts=@();Selected=$null}
        Set-Ci10StatusQueueProjection -QueueSnapshot $unavailable -Capacity READY -ProvenanceValid
        $status=Get-Content -LiteralPath (Get-Ci10StatusProjectionPath) -Raw|ConvertFrom-Json
        Assert ($status.queue_state -ceq 'UNAVAILABLE' -and $null -eq $status.eligible_queued_count -and $null -eq $status.selected_run_id)
        Assert ($status.reason_code -ceq 'QUEUE_UNAVAILABLE')
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Check 'reader SID receives read-only rights and no mutation rights' {
            $sid='S-1-5-21-1000000000-1000000001-1000000002-1001'
            Set-Ci10StatusReaderAcl -ReaderSid $sid
            $acl=Get-Acl -LiteralPath (Split-Path (Get-Ci10StatusProjectionPath) -Parent)
            $rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow'})
            Assert ($rules.Count -eq 1)
            $rights=$rules[0].FileSystemRights
            $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
            Assert (($rights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute)
            Assert (($rights -band $write) -eq 0)
        }
    }
    'STATUS_PROJECTION_TESTS='+$total
} finally {
    Remove-Module StatusProjection -ErrorAction SilentlyContinue
    $env:ProgramData=$oldProgramData
    if(Test-Path -LiteralPath $sandbox){Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue}
}
