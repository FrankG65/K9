<#
  Testlauf "Schalter und Manipulationsschutz" IN DER WINDOWS-SANDBOX (offline, frische Sandbox,
  ca. 15 Minuten, zwei Klicks im Bestaetigungsfenster).
  Ein Schadprogramm mit normalen Benutzerrechten schaltet Schutzfunktionen in config.toml ab -
  der Dienst muss den Schutz behalten und Alarm geben. Nur harmlose, selbst erzeugte Test-Schritte.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    S1 k9 funktion anhalten/virustotal an (zweimal) -> config.toml gueltig, je Abschnitt einmal;
       Dienst-Log "VirusTotal-Abfrage: aktiv" OHNE Neustart; bestaetigter Stand enthaelt beide = true
    S2 "Schadprogramm" setzt beide in config.toml auf false (direkt in der Datei, nicht ueber k9)
       -> Log "Abschwaechende Aenderung ... gilt erst nach Bestaetigung", Fund EINSTELLUNG:SICHERHEIT (Hoch),
          KEIN Log "VirusTotal-Abfrage: aus", "k9 funktion status": "an - Ausschalten wartet ..."
    S3 Testprogramm aus dem Internet startet eine Kette bis zu den Zugangsdaten
       -> Kritisch und ANGEHALTEN (Anhalten gilt weiter, obwohl config.toml "false" sagt)
    S4 Dienst neu starten -> Log "Nicht bestaetigte Sicherheitseinstellungen gelten nicht", VirusTotal weiter aktiv
    S5 "k9 entscheiden <Nr> freigabe" + im Bestaetigungsfenster "Ja"
       -> Log "VirusTotal-Abfrage: aus", Status "aus"
    S6 Erster Dienst-Schluessel ohne Rueckfrage; zweiter (ersetzen) -> Bestaetigungsfenster, dort "Nein"
       -> Fehler, Schluessel bleibt der erste
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
$logs = 'C:\ProgramData\K9\logs\*'
$bestaetigt = 'C:\ProgramData\K9\einstellungen-bestaetigt.json'
Start-Transcript -Path (Join-Path $out 'protokoll-schalter.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Check([bool]$ok, [string]$what) { Write-Host ("  [{0}] {1}" -f $(if ($ok) { 'OK' } else { 'FEHLER' }), $what) }
function InLog([string]$pattern) { [bool](Select-String -Path $logs -Pattern $pattern -Quiet) }
function Suspended([int]$id) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $p) { return -1 }
    @($p.Threads | Where-Object { $_.WaitReason -eq 'Suspended' }).Count
}

Step 'A K9 installieren'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 40 'Agent legt config.toml an, Dienst uebernimmt den Ausgangsstand'
$cfg = Join-Path $env:APPDATA 'K9\config.toml'
Check (Test-Path $bestaetigt) 'bestaetigter Stand vom Dienst angelegt'

Step 'S1 Einschalten mit k9 funktion (zweimal), ohne Neustart'
Run $k9 funktion anhalten an
Run $k9 funktion virustotal an
Run $k9 funktion virustotal an
Run $k9 status
Check ($LASTEXITCODE -eq 0) 'config.toml gueltig'
Check (@(Select-String -Path $cfg -Pattern '^\[quellen\]').Count -eq 1) '[quellen] genau einmal'
Wait 45 'Dienst prueft config.toml alle 30 s'
Check (InLog 'VirusTotal-Abfrage: aktiv') 'VirusTotal ohne Neustart aktiv'
$j = Get-Content $bestaetigt -Raw
Check ($j -match '"echtzeit.kritische_prozesse_anhalten": true' -and $j -match '"quellen.virustotal_aktiv": true') 'Einschalten ist der neue bestaetigte Stand'
Run $k9 funktion status

Step 'S2 Schadprogramm schaltet ab (direkt in config.toml, normale Rechte)'
(Get-Content $cfg) -replace '^kritische_prozesse_anhalten = true', 'kritische_prozesse_anhalten = false' `
    -replace '^virustotal_aktiv = true', 'virustotal_aktiv = false' | Set-Content -Path $cfg -Encoding UTF8
Select-String -Path $cfg -Pattern '^kritische_prozesse_anhalten|^virustotal_aktiv' | ForEach-Object { Write-Host "  $($_.Line)" }
Wait 45 'Dienst prueft config.toml'
Check (InLog 'Abschw.+chende .+nderung in config.toml \(gilt erst nach Best.+tigung\)') 'Alarm im Dienst-Log'
Check (-not (InLog 'vt: VirusTotal-Abfrage: aus')) 'VirusTotal bleibt aktiv'
$liste = & $k9 erkennungen 2>&1 | Out-String
Write-Host $liste
$nr = ($liste -split "`n" | Where-Object { $_ -match 'EINSTELLUNG:SICHERHEIT' } |
    ForEach-Object { if ($_ -match '^\s*#(\d+)') { [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
Check ([bool]$nr) "Fund EINSTELLUNG:SICHERHEIT offen (Nr. $nr)"
$st = & $k9 funktion status 2>&1 | Out-String
Write-Host $st
Check ($st -match 'anhalten\s+.*wartet auf deine Bestaetigung') 'Status: Anhalten wartet auf Bestaetigung'

Step 'S3 Anhalten gilt weiter'
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
New-Item -ItemType Directory -Force (Split-Path $chrome -Parent) | Out-Null
$b = New-Object byte[] 4096; (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes($chrome, $b)
$chromeCs = $chrome.Replace('\', '\\')
$src = @"
using System.Diagnostics;
public static class Prg {
    public static void Main() {
        var a = Process.Start("schtasks.exe", "/create /tn VS-Test-Aufgabe3 /tr notepad.exe /sc once /st 23:59 /f"); a.WaitForExit();
        var b = Process.Start("powershell.exe", "-NoProfile -Command [IO.File]::OpenRead('$chromeCs').Close()"); b.WaitForExit();
        System.Threading.Thread.Sleep(120000);
    }
}
"@
$tool = Join-Path $env:USERPROFILE 'Downloads\mod-tool3.exe'
Add-Type -TypeDefinition $src -OutputAssembly $tool -OutputType ConsoleApplication
Set-Content -Path "${tool}:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://beispiel.invalid/mod-tool3.exe`r`n"
$p = Start-Process -FilePath $tool -PassThru
Wait 25 'Kette bis zu den Zugangsdaten'
$s = Suspended $p.Id
Check ($s -gt 0) "Testprogramm angehalten ($s Threads)"
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
schtasks.exe /delete /tn VS-Test-Aufgabe3 /f | Out-Null

Step 'S4 Dienst neu starten: nicht bestaetigte Abschwaechung gilt auch beim Start nicht'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 8 'gestoppt'
Run sc.exe start 'K9-Dienst'
Wait 45 'Start'
Check (InLog 'Nicht best.+tigte Sicherheitseinstellungen gelten nicht') 'Start-Log nennt die zurueckgehaltene Aenderung'
$last = Select-String -Path $logs -Pattern 'vt: VirusTotal-Abfrage: (aktiv|aus)' | Select-Object -Last 1
Check ($last.Line -match 'Abfrage: aktiv') "VirusTotal nach Neustart: $($last.Line)"

Step 'S5 Bestaetigen'
Write-Host '  >>> Meldefenster der Einstellung (falls offen): "Spaeter". Gleich erscheint das kleine Bestaetigungsfenster: bitte "Ja" klicken.'
if ($nr) { Run $k9 entscheiden $nr freigabe }
Wait 45 'Dienst uebernimmt'
$last = Select-String -Path $logs -Pattern 'vt: VirusTotal-Abfrage: (aktiv|aus)' | Select-Object -Last 1
Check ($last.Line -match 'Abfrage: aus') "nach Bestaetigung: $($last.Line)"
$st = & $k9 funktion status 2>&1 | Out-String
Write-Host $st
Check ($st -match 'anhalten\s+Kritische Programme anhalten\s+aus') 'Status: Anhalten aus'
$liste = & $k9 erkennungen 2>&1 | Out-String
Check (-not ($liste -match 'EINSTELLUNG:SICHERHEIT')) 'Fund EINSTELLUNG:SICHERHEIT entschieden (nicht mehr offen)'

Step 'S6 Schluessel ersetzen braucht Bestaetigung'
'dummy-eins-nur-sandbox' | & $k9 geheimnis virustotal-key --aus-eingabe 2>&1 | Out-String | Write-Host
Check ($LASTEXITCODE -eq 0) 'erster Schluessel ohne Rueckfrage gespeichert'
Write-Host '  >>> Gleich erscheint das Bestaetigungsfenster "Schluessel ersetzen?": bitte "Nein" klicken.'
'dummy-zwei-nur-sandbox' | & $k9 geheimnis virustotal-key --aus-eingabe 2>&1 | Out-String | Write-Host
Check ($LASTEXITCODE -ne 0) 'Ersetzen abgelehnt'
Check (@(Select-String -Path $logs -Pattern 'Schl.+ssel virustotal-key gespeichert').Count -eq 1) 'nur einmal gespeichert'
Select-String -Path $logs -Pattern 'Schl.+ssel virustotal-key|Best.+tigung' | ForEach-Object { Write-Host "  $($_.Line)" }

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen-schalter.txt')
Copy-Item $cfg (Join-Path $out 'config-schalter.toml')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-schalter-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
