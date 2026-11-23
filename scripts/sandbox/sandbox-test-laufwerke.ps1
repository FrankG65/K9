<#
  Kurzlauf "Schattenkopien auf mehreren Laufwerken" IN DER WINDOWS-SANDBOX (offline, frische
  Sandbox, ca. 10 Minuten, keine Klicks noetig). Die Sandbox hat nur C:, darum wird F: hier nur
  als "gibt es nicht" geprueft; das Entfernen eines Laufwerks wird mit C: geprueft.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    L1 schattenkopien an, laufwerke C: (zweimal)   -> Log "aktiv (C:, alle 24 h)", Datei gueltig, [schutz] einmal
    L2 laufwerke C: Z:                             -> Fehler "gibt es auf diesem PC nicht", nichts geschrieben
    L3 laufwerke C:; "x"                           -> Fehler "Ungueltiges Laufwerk", nichts geschrieben
    L4 Schadprogramm leert die Liste in config.toml -> Alarm "Laufwerk fuer Schattenkopien entfernt: C:",
                                                     Status-Zeile weiter "C:", Dienst sichert C: weiter (kein "aus" im Log)
    L5 k9 dienst status                         -> Zeile "Schattenkopien: C: ..." (ohne doppelten Doppelpunkt)
    W1 Firewall-Sperre an (lokale Test-Liste)      -> Regel "K9 - Botnetz-Server gesperrt (Port 4444)", Gruppe
       "K9", Beschreibung mit Stand; alte Regel "Virenscanner C2-Sperre" ersetzt; fremde Regeln bleiben
    W2 k9 firewall entfernen                    -> nur eigene Regeln weg
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
Start-Transcript -Path (Join-Path $out 'protokoll-laufwerke.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Check([bool]$ok, [string]$what) { Write-Host ("  [{0}] {1}" -f $(if ($ok) { 'OK' } else { 'FEHLER' }), $what) }
function InLog([string]$pattern) { [bool](Select-String -Path $logs -Pattern $pattern -Quiet) }

Step 'A K9 installieren'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 40 'Agent legt config.toml an'
$cfg = Join-Path $env:APPDATA 'K9\config.toml'

Step 'L1 Einschalten und Laufwerk C: (zweimal)'
Run $k9 funktion schattenkopien an
Run $k9 funktion schattenkopien laufwerke C:
Run $k9 funktion schattenkopien laufwerke c
Run $k9 status
Check ($LASTEXITCODE -eq 0) 'config.toml gueltig'
Check (@(Select-String -Path $cfg -Pattern '^\[schutz\]').Count -eq 1) '[schutz] genau einmal'
Wait 45 'Dienst prueft config.toml'
Check (InLog 'schattenkopie: Schattenkopien im Leerlauf: aktiv \(C:, alle 24 h\)') 'Schattenkopien aktiv fuer C:'

Step 'L2 Laufwerk, das es nicht gibt'
$vorher = Get-Content $cfg -Raw
Run $k9 funktion schattenkopien laufwerke C: Z:
Check ($LASTEXITCODE -ne 0) 'abgelehnt'
Check ((Get-Content $cfg -Raw) -eq $vorher) 'config.toml unveraendert'

Step 'L3 Ungueltige Angabe'
Run $k9 funktion schattenkopien laufwerke 'C:;' x
Check ($LASTEXITCODE -ne 0) 'abgelehnt'
Check ((Get-Content $cfg -Raw) -eq $vorher) 'config.toml unveraendert'

Step 'L4 Schadprogramm entfernt C: aus der Liste (direkt in config.toml)'
(Get-Content $cfg) -replace '^schattenkopien_laufwerke = .*$', 'schattenkopien_laufwerke = []' | Set-Content -Path $cfg -Encoding UTF8
Select-String -Path $cfg -Pattern '^schattenkopien_laufwerke' | ForEach-Object { Write-Host "  $($_.Line)" }
Wait 45 'Dienst prueft config.toml'
Check (InLog 'Laufwerk f.+r Schattenkopien entfernt: C:') 'Alarm nennt das entfernte Laufwerk'
Check (-not (InLog 'schattenkopie: Schattenkopien im Leerlauf: aus')) 'Dienst sichert C: weiter'
$st = & $k9 funktion status 2>&1 | Out-String
Write-Host $st
Check ($st -match 'Laufwerke der Schattenkopien\s+C:\s+\(config.toml:') 'Status: gilt weiter C:, Entfernen wartet'

Step 'L5 Dienst-Status'
$ds = & $k9 dienst status 2>&1 | Out-String
Write-Host $ds
Check ($ds -match 'Schattenkopien: C: ' -and -not ($ds -match 'C:: ')) 'Statuszeile ohne doppelten Doppelpunkt'

Step 'W1 Firewall-Sperre: neue Namen, alte Regel ersetzt, fremde Regeln bleiben'
# Lokale Test-Liste statt Download (Sandbox offline): eine oeffentliche Adresse mit Port.
$heute = Get-Date -Format 'yyyy-MM-dd'
$tf = 'C:\ProgramData\K9\quellen\abusech\threatfox.json'
New-Item -ItemType Directory -Force (Split-Path $tf -Parent) | Out-Null
@{ '45.67.89.10:4444' = @{ typ = 'ip'; malware = 'Test'; first_seen = $heute; threat_type = 'botnet_cc'; confidence = 100; last_seen = $heute } } |
    ConvertTo-Json | Set-Content -Path $tf -Encoding ASCII
# Regel einer aelteren Version und zwei fremde Regeln (gleiche Gruppe / aehnlicher Name).
netsh advfirewall firewall add rule name="Virenscanner C2-Sperre" dir=out action=block protocol=TCP remoteport=4444 remoteip=45.67.89.10 | Out-Null
New-NetFirewallRule -DisplayName 'Fremd in Gruppe K9' -Group 'K9' -Direction Outbound -Action Block -Protocol TCP -RemotePort 1 -RemoteAddress 45.1.1.1 | Out-Null
New-NetFirewallRule -DisplayName 'Virenscanner C2-Sperre alt' -Direction Outbound -Action Block -Protocol TCP -RemotePort 2 -RemoteAddress 45.1.1.2 | Out-Null
$gesamtVorher = @(Get-NetFirewallRule).Count
Run $k9 funktion firewall an
Wait 60 'Dienst legt die Regeln an'
$alle = Get-NetFirewallRule -Direction Outbound
$neu = @($alle | Where-Object { $_.DisplayName -like 'K9*Botnetz-Server gesperrt (Port 4444)' -and $_.Group -eq 'K9' })
Check ($neu.Count -eq 1) 'Regel "K9 - Botnetz-Server gesperrt (Port 4444)" in Gruppe K9'
if ($neu.Count -ge 1) { Write-Host "  Beschreibung: $($neu[0].Description)" }
Check ($neu.Count -ge 1 -and $neu[0].Description -match 'Stand: \d{4}-\d\d-\d\d' -and $neu[0].Description -match 'k9 firewall entfernen') 'Beschreibung mit Stand und Entfernen-Befehl'
Check (@($alle | Where-Object DisplayName -eq 'Virenscanner C2-Sperre').Count -eq 0) 'Regel der alten Version ersetzt'
Check (@($alle | Where-Object DisplayName -eq 'Fremd in Gruppe K9').Count -eq 1) 'fremde Regel in derselben Gruppe bleibt'
Check (@($alle | Where-Object DisplayName -eq 'Virenscanner C2-Sperre alt').Count -eq 1) 'fremde Regel mit aehnlichem Namen bleibt'
Run $k9 firewall status

Step 'W2 k9 firewall entfernen: nur eigene Regeln'
Run $k9 firewall entfernen
$alle = Get-NetFirewallRule -Direction Outbound
Check (@($alle | Where-Object { $_.DisplayName -like 'K9*Botnetz-Server gesperrt*' }).Count -eq 0) 'eigene Regeln entfernt'
Check (@($alle | Where-Object DisplayName -eq 'Fremd in Gruppe K9').Count -eq 1 -and @($alle | Where-Object DisplayName -eq 'Virenscanner C2-Sperre alt').Count -eq 1) 'fremde Regeln noch da'
Check (@(Get-NetFirewallRule).Count -eq $gesamtVorher - 1) "Gesamtzahl: vorher $gesamtVorher (mit alter Regel), jetzt $(@(Get-NetFirewallRule).Count)"
Remove-NetFirewallRule -DisplayName 'Fremd in Gruppe K9', 'Virenscanner C2-Sperre alt' -ErrorAction SilentlyContinue

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen-laufwerke.txt')
Copy-Item $cfg (Join-Path $out 'config-laufwerke.toml')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-laufwerke-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
