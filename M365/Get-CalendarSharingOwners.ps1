<#
.SYNOPSIS
Collects Exchange Online calendar folder sharing details for mailboxes.

.DESCRIPTION
Queries mailbox calendar folders, resolves each folder to a Get-MailboxCalendarFolder identity,
and exports a unified CSV containing folder metadata, sharing properties, inferred owner details,
and any errors encountered.

The script first checks for working Exchange Online access. If access is missing,
it prompts for authentication automatically.

.PARAMETER UseDeviceAuthentication
Uses device code authentication when connecting to Exchange Online.
Used only when authentication is needed.

.PARAMETER ExchangeOnlineUserPrincipalName
Optional UPN to pass to Connect-ExchangeOnline.
Used only when authentication is needed and UseDeviceAuthentication is not used.

.PARAMETER RecipientTypeDetails
Mailbox recipient types to query with Get-Mailbox.
Defaults to UserMailbox and SharedMailbox.

.PARAMETER MailboxUPNFilter
Optional wildcard filter for mailbox UserPrincipalName values.
Example: "*@contoso.com" or "a.user@contoso.com"

.PARAMETER SkipBirthdays
When true, skips Birthday calendars to avoid potential query stalls.
Defaults to true.

.PARAMETER OutputCsvPath
Output path for the unified CSV report.
Defaults to .\calendar-report.csv.

.OUTPUTS
System.Management.Automation.PSCustomObject
Also writes a CSV file containing all result rows.

.EXAMPLE
.\groupcal.ps1
Uses the current Exchange Online session and exports to the default CSV path.

.EXAMPLE
.\groupcal.ps1 -UseDeviceAuthentication
If not already connected, authenticates with device login, then processes mailboxes.

.EXAMPLE
.\groupcal.ps1 -ExchangeOnlineUserPrincipalName admin@contoso.com -MailboxUPNFilter "b.scherger@necltd.ca" -OutputCsvPath .\calendar-report.csv
If not already connected, authenticates using the provided UPN, filters to a specific mailbox, and exports to a custom CSV path.

.NOTES
Requires ExchangeOnlineManagement module cmdlets such as Connect-ExchangeOnline,
Get-Mailbox, Get-MailboxFolderStatistics, and Get-MailboxCalendarFolder.
#>
[CmdletBinding()]
param(
    [switch]$UseDeviceAuthentication,
    [string]$ExchangeOnlineUserPrincipalName,
    [string[]]$RecipientTypeDetails = @("UserMailbox", "SharedMailbox"),
    [string]$MailboxUPNFilter,
    [bool]$SkipBirthdays = $true,
    [string]$OutputCsvPath = ".\calendar-report.csv"
)

if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
    throw "Connect-ExchangeOnline cmdlet is not available. Install/import ExchangeOnlineManagement first."
}

$hasExchangeOnlineAccess = $false
try {
    Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
    $hasExchangeOnlineAccess = $true
    Write-Output "[INFO] Existing Exchange Online access confirmed."
}
catch {
    Write-Output "[INFO] No active Exchange Online access detected. Starting authentication..."
}

if (-not $hasExchangeOnlineAccess) {
    try {
        if ($UseDeviceAuthentication) {
            Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        }
        elseif (-not [string]::IsNullOrWhiteSpace($ExchangeOnlineUserPrincipalName)) {
            Connect-ExchangeOnline -UserPrincipalName $ExchangeOnlineUserPrincipalName -ShowBanner:$false -ErrorAction Stop
        }
        else {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }

        Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
        Write-Output "[INFO] Exchange Online authentication successful."
    }
    catch {
        throw "Failed to authenticate to Exchange Online. $($_.Exception.Message)"
    }
}

try {
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails -ErrorAction Stop
}
catch {
    throw "Failed to retrieve mailboxes. $($_.Exception.Message)"
}

if (-not [string]::IsNullOrWhiteSpace($MailboxUPNFilter)) {
    $Mailboxes = $Mailboxes | Where-Object { $_.UserPrincipalName -like $MailboxUPNFilter }
}

$calendarResults = @()
$totalMailboxes = @($Mailboxes).Count
$mailboxIndex = 0
$successCount = 0
$errorCount = 0
$skippedCount = 0

if ($totalMailboxes -eq 0) {
    Write-Output "[WARN] No mailboxes matched the current filters."
    return
}

Write-Output ("[INFO] Starting calendar folder discovery for {0} mailbox(es)." -f $totalMailboxes)
foreach ($Mailbox in $Mailboxes) {
    $mailboxIndex++
    Write-Output ("[INFO] Processing mailbox {0}/{1}: {2}" -f $mailboxIndex, $totalMailboxes, $Mailbox.UserPrincipalName)

    try {
        $mailboxCals = Get-MailboxFolderStatistics -Identity $Mailbox.UserPrincipalName -FolderScope Calendar -ErrorAction Stop
    }
    catch {
        $errorCount++
        Write-Output ("[ERROR] Failed to get calendar folder statistics for {0}. {1}" -f $Mailbox.UserPrincipalName, $_.Exception.Message)
        continue
    }

    $mailboxCalendarCount = @($mailboxCals).Count
    Write-Output ("[INFO] Found {0} calendar folder(s) in {1}." -f $mailboxCalendarCount, $Mailbox.UserPrincipalName)

    foreach ($cal in $mailboxCals) {
        $normalizedFolderPath = ($cal.FolderPath -replace '/', '\').TrimStart('\')
        $subPath = $normalizedFolderPath
        if ($subPath -eq "Calendar") {
            $calendarPathForIdentity = "Calendar"
        }
        elseif ($subPath -like "Calendar\*") {
            $calendarPathForIdentity = $subPath
        }
        else {
            $calendarPathForIdentity = "Calendar\{0}" -f $subPath
        }

        $calendarIdentity = "{0}:\{1}" -f $Mailbox.UserPrincipalName, $calendarPathForIdentity

        if ($SkipBirthdays -and ($cal.FolderType -eq "BirthdayCalendar" -or $normalizedFolderPath -match '(^|\\)Birthdays($|\\)')) {
            $skippedCount++
            Write-Output ("[WARN] Skipping Birthdays folder: {0}" -f $calendarIdentity)
            $calendarResults += [PSCustomObject]@{
                MailboxDisplayName = $Mailbox.DisplayName
                MailboxUPN = $Mailbox.UserPrincipalName
                Name = $cal.Name
                FolderPath = $cal.FolderPath
                CreationTime = $cal.CreationTime
                LastModifiedTime = $cal.LastModifiedTime
                FolderType = $cal.FolderType
                CalendarIdentity = $calendarIdentity
                Owner = $Mailbox.UserPrincipalName
                OwnerInferredFromMailbox = $true
                Permissions = $null
                SharingLevel = $null
                SharingFlags = $null
                Error = "Skipped Birthdays folder"
            }
            continue
        }

        Write-Output ("[INFO] Querying calendar folder: {0}" -f $calendarIdentity)

        try {
            $calendarFolder = Get-MailboxCalendarFolder -Identity $calendarIdentity -ErrorAction Stop
            $owner = $calendarFolder.CalendarSharingOwnerSmtpAddress
            $permissions = $calendarFolder.CalendarSharingPermissionLevel
            $ownerInferredFromMailbox = $false

            if ([string]::IsNullOrWhiteSpace([string]$owner) -or $null -eq $permissions) {
                $owner = $Mailbox.UserPrincipalName
                $ownerInferredFromMailbox = $true
            }

            $successCount++
            Write-Output ("[INFO] Success: {0}" -f $calendarIdentity)
            $calendarResults += [PSCustomObject]@{
                MailboxDisplayName = $Mailbox.DisplayName
                MailboxUPN = $Mailbox.UserPrincipalName
                Name = $cal.Name
                FolderPath = $cal.FolderPath
                CreationTime = $cal.CreationTime
                LastModifiedTime = $cal.LastModifiedTime
                FolderType = $cal.FolderType
                CalendarIdentity = $calendarIdentity
                Owner = $owner
                OwnerInferredFromMailbox = $ownerInferredFromMailbox
                Permissions = $permissions
                SharingLevel = $calendarFolder.SharingLevelOfDetails
                SharingFlags = $calendarFolder.CalendarSharingPermissionFlags
                Error = $null
            }
        }
        catch {
            $errorCount++
            Write-Output ("[ERROR] Failed: {0}. {1}" -f $calendarIdentity, $_.Exception.Message)
            $calendarResults += [PSCustomObject]@{
                MailboxDisplayName = $Mailbox.DisplayName
                MailboxUPN = $Mailbox.UserPrincipalName
                Name = $cal.Name
                FolderPath = $cal.FolderPath
                CreationTime = $cal.CreationTime
                LastModifiedTime = $cal.LastModifiedTime
                FolderType = $cal.FolderType
                CalendarIdentity = $calendarIdentity
                Owner = $Mailbox.UserPrincipalName
                OwnerInferredFromMailbox = $true
                Permissions = $null
                SharingLevel = $null
                SharingFlags = $null
                Error = $_.Exception.Message
            }
        }
    }
}
Write-Output ("[INFO] Completed. Successful folder queries: {0}. Skipped: {1}. Errors: {2}." -f $successCount, $skippedCount, $errorCount)
$calendarResults | Export-Csv -Path $OutputCsvPath -NoTypeInformation
$outputCount = @($calendarResults).Count
Write-Output ("[INFO] Wrote {0} row(s) to {1}" -f $outputCount, $OutputCsvPath)
$calendarResults | Format-Table