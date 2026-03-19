# WinSecAudit


WinSecAudit is a PowerShell-based Windows security audit script built for learning, lab use, and portfolio presentation. It reviews common hardening and security-relevant settings on a Windows system and exports the findings to structured CSV and HTML reports.

---

## Security-focused improvements

This hardened version includes:

- Targeted `try/catch` blocks instead of globally suppressing errors
- Prerequisite checks for PowerShell version, admin rights, and cmdlet availability
- Safe HTML encoding for report values before writing the HTML report
- Optional `-RedactSensitiveOutput` switch to mask hostnames and local administrator names
- Default output to a dedicated `reports` folder
- Structured error findings instead of silent failures

---

## Features

WinSecAudit currently checks the following areas:

- Microsoft Defender status and real-time protection
- Windows Firewall profile status
- BitLocker protection state
- Windows Update service configuration
- Local Administrators group membership
- Guest account status
- User Account Control (UAC)
- SMBv1 protocol status
- Failed logon events (Event ID 4625)
- Remote Desktop (RDP) status

Each finding includes:

- Category
- Check
- Status
- Severity
- Details
- Recommendation

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Windows endpoint
- Local permissions to query system settings
- Administrator privileges recommended for full results

---

## Quick start

Run the script with default output paths:

```powershell
.\WinSecAudit.ps1
```

Run with custom output paths and a longer event log review window:

```powershell
.\WinSecAudit.ps1 -CsvReportPath ".\reports\WinSecAudit-Report.csv" -HtmlReportPath ".\reports\WinSecAudit-Report.html" -DaysBack 14
```

Run with sensitive output redacted:

```powershell
.\WinSecAudit.ps1 -RedactSensitiveOutput
```

---

## Security notes

- The script is read-only and does not change firewall rules, registry values, accounts, or services.
- It writes findings only to CSV and HTML output files.
- Reports may contain sensitive audit information and should not be committed publicly if they were generated from real systems.
- A `.gitignore` entry for the `reports/` directory is recommended.

Recommended `.gitignore` entry:

```gitignore
reports/
```

---

## Suggested CV description

**WinSecAudit** - Developed a hardened PowerShell-based Windows security audit script with prerequisite checks, structured error handling, safe HTML reporting, and export to CSV and HTML for audit-style documentation.
