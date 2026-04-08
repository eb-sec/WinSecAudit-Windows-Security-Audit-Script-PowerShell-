# WinSecAudit

WinSecAudit ist ein PowerShell-basiertes Windows-Sicherheitsaudit-Skript, das für Lernzwecke, Lab-Umgebungen und die Portfolio-Präsentation entwickelt wurde. Es überprüft gängige Härtungs- und sicherheitsrelevante Einstellungen auf einem Windows-System und exportiert die Ergebnisse in strukturierte CSV- und HTML-Berichte.

---

## Sicherheitsorientierte Verbesserungen

Diese gehärtete Version enthält:

- Gezielte `try/catch`-Blöcke anstelle einer globalen Fehlerunterdrückung
- Voraussetzungsprüfungen für PowerShell-Version, Administratorrechte und Cmdlet-Verfügbarkeit
- Sichere HTML-Kodierung von Berichtswerten vor der HTML-Ausgabe
- Optionalen `-RedactSensitiveOutput`-Schalter zum Maskieren von Hostnamen und lokalen Administratornamen
- Standardmäßige Ausgabe in einen dedizierten `reports`-Ordner
- Strukturierte Fehlerbefunde statt stiller Fehler

---

## Funktionen

WinSecAudit prüft aktuell folgende Bereiche:

- Microsoft Defender-Status und Echtzeitschutz
- Windows-Firewall-Profilstatus
- BitLocker-Schutzstatus
- Konfiguration des Windows-Update-Dienstes
- Mitgliedschaft in der lokalen Administratorengruppe
- Gastkonto-Status
- Benutzerkontensteuerung (UAC)
- SMBv1-Protokollstatus
- Fehlgeschlagene Anmeldeereignisse (Event ID 4625)
- Remotedesktop (RDP)-Status

Jeder Befund enthält:

| Feld | Beschreibung |
|---|---|
| **Kategorie** | Themenbereich der Prüfung |
| **Prüfung** | Name der durchgeführten Kontrolle |
| **Status** | Ergebnis der Prüfung |
| **Schweregrad** | Kritisch / Hoch / Mittel / Niedrig |
| **Details** | Technische Zusatzinformationen |
| **Empfehlung** | Vorgeschlagene Maßnahme |

---

## Voraussetzungen

- Windows PowerShell 5.1 oder PowerShell 7+
- Windows-Endgerät
- Lokale Berechtigungen zur Abfrage von Systemeinstellungen
- Administratorrechte für vollständige Ergebnisse empfohlen

---

## Schnellstart

Skript mit Standardausgabepfaden ausführen:

```powershell
.\WinSecAudit.ps1
```

Mit benutzerdefinierten Ausgabepfaden und erweitertem Ereignisprotokoll-Zeitraum:

```powershell
.\WinSecAudit.ps1 -CsvReportPath ".\reports\WinSecAudit-Report.csv" -HtmlReportPath ".\reports\WinSecAudit-Report.html" -DaysBack 14
```

Mit maskierter sensibler Ausgabe:

```powershell
.\WinSecAudit.ps1 -RedactSensitiveOutput
```

---

## Sicherheitshinweise

- Das Skript ist **schreibgeschützt** und nimmt keine Änderungen an Firewall-Regeln, Registrierungswerten, Konten oder Diensten vor.
- Es schreibt Befunde ausschließlich in CSV- und HTML-Ausgabedateien.
- Berichte können sensible Audit-Informationen enthalten und sollten bei Erstellung auf echten Systemen **nicht öffentlich committet** werden.
- Ein `.gitignore`-Eintrag für das `reports/`-Verzeichnis wird empfohlen.

Empfohlener `.gitignore`-Eintrag:

```gitignore
reports/
```



