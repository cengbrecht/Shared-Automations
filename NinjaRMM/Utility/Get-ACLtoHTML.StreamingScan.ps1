function Get-AclAuditChildPaths {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [bool]$FoldersOnly
    )

    $childPaths = [System.Collections.Generic.List[string]]::new()

    try {
        $supportsEnumerationOptions = $null -ne ('System.IO.EnumerationOptions' -as [type])

        if ($supportsEnumerationOptions) {
            $enumerationOptions = [System.IO.EnumerationOptions]::new()
            $enumerationOptions.AttributesToSkip = [System.IO.FileAttributes]::System
            $enumerationOptions.IgnoreInaccessible = $true
            $enumerationOptions.RecurseSubdirectories = $false
            $enumerationOptions.ReturnSpecialDirectories = $false

            foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($Path, '*', $enumerationOptions)) {
                if ($FoldersOnly -and -not [System.IO.Directory]::Exists($childPath)) {
                    continue
                }

                [void]$childPaths.Add($childPath)
            }
        } else {
            foreach ($childItem in (Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
                if (($childItem.Attributes -band [System.IO.FileAttributes]::System) -ne 0) {
                    continue
                }

                if ($FoldersOnly -and -not $childItem.PSIsContainer) {
                    continue
                }

                [void]$childPaths.Add($childItem.FullName)
            }
        }
    } catch {
        Write-Warning "Unable to enumerate children for '$Path': $($_.Exception.Message)"
    }

    return ,$childPaths
}

function Get-AclAuditNodeRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [bool]$IsContainer
    )

    $itemType = if ($IsContainer) { "Folder" } else { "File" }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $permissions = foreach ($entry in $acl.Access) {
            [PSCustomObject]@{
                IdentityReference = $entry.IdentityReference.Value
                FileSystemRights  = $entry.FileSystemRights.ToString()
                AccessControlType = $entry.AccessControlType.ToString()
                IsInherited       = $entry.IsInherited
            }
        }

        return [PSCustomObject]@{
            Path        = $Path
            ItemType    = $itemType
            Owner       = $acl.Owner
            Permissions = @($permissions)
            Error       = $null
        }
    } catch {
        return [PSCustomObject]@{
            Path        = $Path
            ItemType    = $itemType
            Owner       = $null
            Permissions = @()
            Error       = $_.Exception.Message
        }
    }
}

function Update-StreamingAclProgress {
    param(
        [Parameter(Mandatory)]
        [hashtable]$State,

        [Parameter(Mandatory)]
        [string]$CurrentPath,

        [switch]$Force
    )

    $shouldUpdate = $Force.IsPresent -or $State.ProcessedCount -le 3 -or (($State.ProcessedCount % $State.ProgressInterval) -eq 0)
    if (-not $shouldUpdate) {
        return
    }

    Write-Progress -Activity "Collecting ACLs" -Status "$($State.ProcessedCount) items processed - $CurrentPath"
}

function Invoke-StreamingAclScan {
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [bool]$FoldersOnly,

        [Parameter(Mandatory)]
        [scriptblock]$OnNodeStart,

        [Parameter(Mandatory)]
        [scriptblock]$OnNodeEnd,

        [Parameter()]
        [object]$CallbackContext
    )

    $resolvedRootPath = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path

    if (-not [System.IO.Directory]::Exists($resolvedRootPath) -and -not [System.IO.File]::Exists($resolvedRootPath)) {
        throw "Audit path does not exist: $resolvedRootPath"
    }

    if ($FoldersOnly -and -not [System.IO.Directory]::Exists($resolvedRootPath)) {
        throw "Root path is not a folder: $resolvedRootPath"
    }

    $state = @{
        ProcessedCount    = 0
        ErrorCount        = 0
        ProgressInterval  = 100
    }

    function Invoke-StreamingAclNode {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $isContainer = [System.IO.Directory]::Exists($Path)
        $record = Get-AclAuditNodeRecord -Path $Path -IsContainer:$isContainer
        $childPaths = if ($isContainer) {
            Get-AclAuditChildPaths -Path $Path -FoldersOnly:$FoldersOnly
        } else {
            [System.Collections.Generic.List[string]]::new()
        }

        $state.ProcessedCount++
        if ($record.Error) {
            $state.ErrorCount++
        }

        Update-StreamingAclProgress -State $state -CurrentPath $record.Path
        & $OnNodeStart $record $childPaths $CallbackContext

        foreach ($childPath in $childPaths) {
            Invoke-StreamingAclNode -Path $childPath
        }

        & $OnNodeEnd $record $childPaths $CallbackContext
    }

    Invoke-StreamingAclNode -Path $resolvedRootPath
    Update-StreamingAclProgress -State $state -CurrentPath $resolvedRootPath -Force
    Write-Progress -Activity "Collecting ACLs" -Completed

    return [PSCustomObject]@{
        RootPath       = $resolvedRootPath
        ProcessedCount = $state.ProcessedCount
        ErrorCount     = $state.ErrorCount
    }
}
