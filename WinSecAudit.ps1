##WinSecAudit 

[CmdletBinding()]
param(
    [string]$CsvReportPath = ".\reports\WinSecAudit-Report.csv",
    [string]$HtmlReportPath = ".\reports\WinSecAudit-Report.html",
    [int]$DaysBack = 7,
    [switch]$RedactSensitiveOutput
)

Set-StrictMode -Version Latest
$findings = New-Object System.Collections.Generic.List[Object]

##Klassen Finding Analyse

function Add-Finding {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Severity,
        [string]$Details,
        [string]$Recommendation
    )

    $findings.Add([PSCustomObject]@{
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Severity       = $Severity
        Details        = $Details
        Recommendation = $Recommendation
    })
}

##Farben

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { '#7f1d1d' }
        'High'     { '#b91c1c' }
        'Medium'   { '#b45309' }
        'Low'      { '#1d4ed8' }
        default    { '#166534' }
    }
}

function Escape-Html {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Value)
}

function Ensure-OutputDirectory {
    param([string]$PathValue)
    $directory = Split-Path -Path $PathValue -Parent
    if ([string]::IsNullOrWhiteSpace($directory)) { return }
    if (-not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
}

##Admincheck

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

##cmdcheck

function Test-CmdletAvailability {
    param(
        [string]$CommandName,
        [string]$Category,
        [string]$Purpose
    )

    if (Get-Command -Name $CommandName -ErrorAction SilentlyContinue) {
        Add-Finding 'Prerequisites' $CommandName 'Available' 'Info' "$Purpose cmdlet is available." 'No action required.'
        return $true
    }
    else {
        Add-Finding 'Prerequisites' $CommandName 'Missing' 'Low' "$Purpose cmdlet is not available on this system." 'Run the script on a supported Windows edition or skip this check.'
        return $false
    }
}

Write-Host 'Starting WinSecAudit (hardened version)...' -ForegroundColor Cyan

Ensure-OutputDirectory -PathValue $CsvReportPath
Ensure-OutputDirectory -PathValue $HtmlReportPath

##Aufbau FUnktion If-else

if ($PSVersionTable.PSVersion.Major -ge 5) {
    Add-Finding 'Prerequisites' 'PowerShell Version' 'Supported' 'Info' "Detected PowerShell version $($PSVersionTable.PSVersion)." 'No action required.'
}
else {
    Add-Finding 'Prerequisites' 'PowerShell Version' 'Unsupported' 'High' "Detected PowerShell version $($PSVersionTable.PSVersion)." 'Use Windows PowerShell 5.1 or PowerShell 7+.'
}

if (Test-IsAdministrator) {
    Add-Finding 'Prerequisites' 'Administrator Rights' 'Elevated' 'Info' 'Script is running with administrative privileges.' 'No action required.'
}
else {
    Add-Finding 'Prerequisites' 'Administrator Rights' 'Limited' 'Medium' 'Script is not running with administrative privileges; some checks may be incomplete.' 'Run PowerShell as Administrator for fuller results.'
}

$mpAvailable = Test-CmdletAvailability -CommandName 'Get-MpComputerStatus' -Category 'Endpoint Protection' -Purpose 'Microsoft Defender'
$fwAvailable = Test-CmdletAvailability -CommandName 'Get-NetFirewallProfile' -Category 'Network Security' -Purpose 'Windows Firewall'
$bitlockerAvailable = Test-CmdletAvailability -CommandName 'Get-BitLockerVolume' -Category 'Data Protection' -Purpose 'BitLocker'
$localGroupAvailable = Test-CmdletAvailability -CommandName 'Get-LocalGroupMember' -Category 'Identity & Access' -Purpose 'Local group review'
$localUserAvailable = Test-CmdletAvailability -CommandName 'Get-LocalUser' -Category 'Identity & Access' -Purpose 'Local user review'
$featureAvailable = Test-CmdletAvailability -CommandName 'Get-WindowsOptionalFeature' -Category 'Network Security' -Purpose 'Windows feature review'
$eventAvailable = Test-CmdletAvailability -CommandName 'Get-WinEvent' -Category 'Monitoring' -Purpose 'Security log review'

if ($mpAvailable) {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled) {
            Add-Finding 'Endpoint Protection' 'Microsoft Defender Real-Time Protection' 'Enabled' 'Info' 'Real-time protection is enabled.' 'Maintain current protection settings.'
        }
        else {
            Add-Finding 'Endpoint Protection' 'Microsoft Defender Real-Time Protection' 'Disabled' 'High' 'Real-time protection is disabled.' 'Enable Microsoft Defender real-time protection.'
        }

        if ($mp.AntivirusEnabled) {
            Add-Finding 'Endpoint Protection' 'Microsoft Defender Antivirus' 'Enabled' 'Info' 'Microsoft Defender Antivirus is enabled.' 'No action required.'
        }
        else {
            Add-Finding 'Endpoint Protection' 'Microsoft Defender Antivirus' 'Disabled' 'High' 'Microsoft Defender Antivirus is disabled.' 'Enable antivirus protection or verify an approved alternative.'
        }
    }
    catch {
        Add-Finding 'Endpoint Protection' 'Microsoft Defender Status' 'Error' 'Medium' $_.Exception.Message 'Verify Defender availability and permissions.'
    }
}

##Firewall

if ($fwAvailable) {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $profiles) {
            if ($profile.Enabled) {
                Add-Finding 'Network Security' "Firewall Profile: $($profile.Name)" 'Enabled' 'Info' "Firewall profile '$($profile.Name)' is enabled." 'No action required.'
            }
            else {
                Add-Finding 'Network Security' "Firewall Profile: $($profile.Name)" 'Disabled' 'High' "Firewall profile '$($profile.Name)' is disabled." "Enable the $($profile.Name) firewall profile."
            }
        }
    }
    catch {
        Add-Finding 'Network Security' 'Firewall Profiles' 'Error' 'Medium' $_.Exception.Message 'Verify firewall cmdlet availability and permissions.'
    }
}

##Bitlocker

if ($bitlockerAvailable) {
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($volume in $volumes) {
            $mount = if ($volume.MountPoint) { $volume.MountPoint } else { 'Unknown' }
            $status = [string]$volume.ProtectionStatus
            if ($status -eq 'On' -or $status -eq '1') {
                Add-Finding 'Data Protection' "BitLocker: $mount" 'Protected' 'Info' "BitLocker protection is enabled on $mount." 'No action required.'
            }
            else {
                Add-Finding 'Data Protection' "BitLocker: $mount" 'Not Protected' 'Medium' "BitLocker protection is not enabled on $mount." 'Enable BitLocker for sensitive endpoints where appropriate.'
            }
        }
    }
    catch {
        Add-Finding 'Data Protection' 'BitLocker Status' 'Error' 'Medium' $_.Exception.Message 'Verify BitLocker support and permissions.'
    }
}

##Patch Management

try {
    $wua = Get-Service -Name 'wuauserv' -ErrorAction Stop
    if ($wua.StartType -eq 'Disabled') {
        Add-Finding 'Patch Management' 'Windows Update Service' 'Disabled' 'High' 'Windows Update service is disabled.' 'Set Windows Update service to Manual or Automatic.'
    }
    else {
        Add-Finding 'Patch Management' 'Windows Update Service' 'Available' 'Info' "Windows Update service start type: $($wua.StartType); current status: $($wua.Status)." 'Verify updates are regularly applied.'
    }
}
catch {
    Add-Finding 'Patch Management' 'Windows Update Service' 'Error' 'Medium' $_.Exception.Message 'Verify service query permissions.'
}

if ($localGroupAvailable) {
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $count = ($admins | Measure-Object).Count
        $adminNames = ($admins | Select-Object -ExpandProperty Name) -join '; '
        if ($RedactSensitiveOutput) {
            $adminNames = '[REDACTED]'
        }

        if ($count -gt 3) {
            Add-Finding 'Identity & Access' 'Local Administrators Group' 'Review Needed' 'Medium' "Administrators group has $count member(s): $adminNames" 'Review privileged access and remove unnecessary accounts.'
        }
        else {
            Add-Finding 'Identity & Access' 'Local Administrators Group' 'OK' 'Info' "Administrators group members: $adminNames" 'Keep privileged group membership minimal.'
        }
    }
    catch {
        Add-Finding 'Identity & Access' 'Local Administrators Group' 'Error' 'Medium' $_.Exception.Message 'Verify local group access and privileges.'
    }
}

##localuser

if ($localUserAvailable) {
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        if ($guest.Enabled) {
            Add-Finding 'Identity & Access' 'Guest Account' 'Enabled' 'Medium' 'Local Guest account is enabled.' 'Disable the Guest account unless explicitly required.'
        }
        else {
            Add-Finding 'Identity & Access' 'Guest Account' 'Disabled' 'Info' 'Local Guest account is disabled.' 'No action required.'
        }
    }
    catch {
        Add-Finding 'Identity & Access' 'Guest Account' 'Error' 'Low' $_.Exception.Message 'Verify local user access and privileges.'
    }
}

try {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
    if ($uac.EnableLUA -eq 1) {
        Add-Finding 'System Hardening' 'User Account Control (UAC)' 'Enabled' 'Info' 'User Account Control is enabled.' 'No action required.'
    }
    else {
        Add-Finding 'System Hardening' 'User Account Control (UAC)' 'Disabled' 'High' 'User Account Control is disabled.' 'Enable UAC to reduce unauthorized elevation risk.'
    }
}
catch {
    Add-Finding 'System Hardening' 'User Account Control (UAC)' 'Error' 'Medium' $_.Exception.Message 'Verify registry access and permissions.'
}

##SMBv1

if ($featureAvailable) {
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
        if ($smb1.State -eq 'Enabled') {
            Add-Finding 'Network Security' 'SMBv1 Protocol' 'Enabled' 'High' 'SMBv1 is enabled.' 'Disable SMBv1 unless a documented legacy dependency exists.'
        }
        else {
            Add-Finding 'Network Security' 'SMBv1 Protocol' 'Disabled' 'Info' "SMBv1 state: $($smb1.State)" 'No action required.'
        }
    }
    catch {
        Add-Finding 'Network Security' 'SMBv1 Protocol' 'Error' 'Low' $_.Exception.Message 'Verify feature query availability and permissions.'
    }
}

if ($eventAvailable) {
    try {
        $startTime = (Get-Date).AddDays(-$DaysBack)
        $failedEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $startTime } -ErrorAction Stop
        $count = ($failedEvents | Measure-Object).Count
        if ($count -gt 20) {
            Add-Finding 'Monitoring' 'Failed Logon Events (4625)' 'Elevated' 'Medium' "$count failed logon events detected in the last $DaysBack day(s)." 'Review authentication failures for brute-force or misconfiguration patterns.'
        }
        else {
            Add-Finding 'Monitoring' 'Failed Logon Events (4625)' 'Observed' 'Info' "$count failed logon events detected in the last $DaysBack day(s)." 'Monitor trends and investigate unusual spikes.'
        }
    }
    catch {
        Add-Finding 'Monitoring' 'Failed Logon Events (4625)' 'Error' 'Low' $_.Exception.Message 'Verify Security log access; Administrator rights may be required.'
    }
}

try {
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 0) {
        Add-Finding 'Remote Access' 'Remote Desktop (RDP)' 'Enabled' 'Low' 'Remote Desktop is enabled.' 'Confirm RDP is required and protected with MFA, firewall restrictions, and monitoring.'
    }
    else {
        Add-Finding 'Remote Access' 'Remote Desktop (RDP)' 'Disabled' 'Info' 'Remote Desktop is disabled.' 'No action required.'
    }
}
catch {
    Add-Finding 'Remote Access' 'Remote Desktop (RDP)' 'Error' 'Low' $_.Exception.Message 'Verify registry access and permissions.'
}

$findings | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8

$rows = foreach ($item in $findings) {
    $color = Get-SeverityColor -Severity $item.Severity
    $category = Escape-Html -Value $item.Category
    $check = Escape-Html -Value $item.Check
    $status = Escape-Html -Value $item.Status
    $severity = Escape-Html -Value $item.Severity
    $details = Escape-Html -Value $item.Details
    $recommendation = Escape-Html -Value $item.Recommendation
    "<tr><td>$category</td><td>$check</td><td>$status</td><td style='color:$color;font-weight:600;'>$severity</td><td>$details</td><td>$recommendation</td></tr>"
}

$hostDisplay = if ($RedactSensitiveOutput) { '[REDACTED]' } else { $env:COMPUTERNAME }
$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>WinSecAudit Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }
h1 { margin-bottom: 6px; }
p.meta { color: #4b5563; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
th, td { border: 1px solid #d1d5db; padding: 10px; text-align: left; vertical-align: top; }
th { background: #111827; color: white; }
tr:nth-child(even) { background: #f9fafb; }
.code { font-family: Consolas, monospace; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
<h1>WinSecAudit Report</h1>
<p class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p class='meta'>Computer: $(Escape-Html -Value $hostDisplay) | Findings: $($findings.Count) | Lookback: $DaysBack day(s)</p>
<table>
<thead>
<tr>
<th>Category</th>
<th>Check</th>
<th>Status</th>
<th>Severity</th>
<th>Details</th>
<th>Recommendation</th>
</tr>
</thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
</body>
</html>
"@

Set-Content -Path $HtmlReportPath -Value $html -Encoding UTF8

Write-Host "CSV report saved to: $CsvReportPath" -ForegroundColor Green
Write-Host "HTML report saved to: $HtmlReportPath" -ForegroundColor Green
Write-Host 'WinSecAudit completed.' -ForegroundColor Cyan
