# WinSecAudit von Elias

WinSecAudit is a PowerShell-based Windows security audit script built for learning purposes, lab environments, and portfolio presentation. It checks common hardening and security-relevant settings on a Windows system and exports the results into structured CSV and HTML reports.

---

## Security-Focused Improvements

This hardened version includes:

- Targeted `try/catch` blocks instead of global error suppression
- Prerequisite checks for PowerShell version, administrator privileges, and cmdlet availability
- Safe HTML encoding of report values before HTML output
- An optional `-RedactSensitiveOutput` switch to mask hostnames and local administrator names
- Default output to a dedicated `reports` folder
- Structured error findings instead of silent failures

---

## Features

WinSecAudit currently checks the following areas:

- Microsoft Defender status and real-time protection
- Windows Firewall profile status
- BitLocker protection status
- Windows Update service configuration
- Local Administrators group membership
- Guest account status
- User Account Control (UAC)
- SMBv1 protocol status
- Failed logon events (Event ID 4625)
- Remote Desktop (RDP) status

Each finding includes:

| Field | Description |
|---|---|
| **Category** | Area of the check |
| **Check** | Name of the performed control |
| **Status** | Result of the check |
| **Severity** | Critical / High / Medium / Low |
| **Details** | Additional technical information |
| **Recommendation** | Suggested action |

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Windows endpoint
- Local permissions to query system settings
- Administrator privileges recommended for complete results

---

## Quick Start

Run the script with default output paths:

```powershell
.\WinSecAudit.ps1
```

Run the script with custom output paths and an extended event log lookback period:

```powershell
.\WinSecAudit.ps1 -CsvReportPath ".\reports\WinSecAudit-Report.csv" -HtmlReportPath ".\reports\WinSecAudit-Report.html" -DaysBack 14
```

Run the script with sensitive output redacted:

```powershell
.\WinSecAudit.ps1 -RedactSensitiveOutput
```

---

## Security Notes

- The script is **read-only** and does not modify firewall rules, registry values, accounts, or services.
- It only writes findings to CSV and HTML output files.
- Reports may contain sensitive audit information and should **not be committed publicly** when generated on real systems.
- A `.gitignore` entry for the `reports/` directory is recommended.

Recommended `.gitignore` entry:

```gitignore
reports/
```
