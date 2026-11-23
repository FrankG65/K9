<#
  Nachtest zu Lauf 18 IN DERSELBEN WINDOWS-SANDBOX (nach sandbox-test-schalter.ps1, ca. 5 Minuten,
  zwei Klicks): Uebernehmen einer abgeschwaechten Einstellung mit der korrigierten Version.
  Ausgangslage: config.toml sagt "aus" fuer Anhalten und VirusTotal, der Dienst haelt beide an.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    B0 Aktualisierung auf die neue Version -> Abschwaechung gilt weiter nicht (Start-Log), Fund offen
    B1 Bestaetigungsfenster "Nein"         -> nichts geaendert: Status "wartet", Fund offen, bestaetigter Stand "true"
    B2 Bestaetigungsfenster "Ja"           -> Log "vt: VirusTotal-Abfrage: aus", Status "aus", Fund entschieden,
                                              bestaetigter Stand "false"
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
Start-Transcript -Path (Join-Path $out 'protokoll-bestaetigen.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Check([bool]$ok, [string]$what) { Write-Host ("  [{0}] {1}" -f $(if ($ok) { 'OK' } else { 'FEHLER' }), $what) }
function OpenNr {
    $l = & $k9 erkennungen 2>&1 | Out-String
    ($l -split "`n" | Where-Object { $_ -match 'EINSTELLUNG:SICHERHEIT' } |
        ForEach-Object { if ($_ -match '^\s*#(\d+)') { [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
}
function Confirmed([string]$key) { (Get-Content $bestaetigt -Raw) -match ('"' + [regex]::Escape($key) + '": true') }

Step 'B0 Neue Version einspielen'
$vorher = @(Select-String -Path $logs -Pattern 'Nicht best.+tigte Sicherheitseinstellungen gelten nicht').Count
Run "$prog\k9.exe" dienst aktualisieren
Wait 45 'Dienst und Agent starten'
Check (@(Select-String -Path $logs -Pattern 'Nicht best.+tigte Sicherheitseinstellungen gelten nicht').Count -gt $vorher) 'Abschwaechung gilt nach der Aktualisierung weiter nicht'
$nr = OpenNr
Check ([bool]$nr) "Fund EINSTELLUNG:SICHERHEIT offen (Nr. $nr)"
Check ((Confirmed 'echtzeit.kritische_prozesse_anhalten') -and (Confirmed 'quellen.virustotal_aktiv')) 'bestaetigter Stand: beide an'

Step 'B1 Ablehnen im Bestaetigungsfenster'
Write-Host '  >>> Meldefenster (falls offen): "Spaeter". Kleines Fenster "Aenderung uebernehmen bestaetigen?": bitte "Nein".'
Run $k9 entscheiden $nr freigabe
Check ($LASTEXITCODE -ne 0) 'abgelehnt'
Wait 35 'Dienst prueft config.toml'
$st = & $k9 funktion status 2>&1 | Out-String
Check ($st -match 'virustotal\s+.*wartet auf deine Bestaetigung') 'VirusTotal bleibt an (wartet)'
Check ([bool](OpenNr)) 'Fund weiter offen'
Check (Confirmed 'quellen.virustotal_aktiv') 'bestaetigter Stand unveraendert'

Step 'B2 Uebernehmen im Bestaetigungsfenster'
Write-Host '  >>> Kleines Fenster "Aenderung uebernehmen bestaetigen?": bitte "Ja".'
Run $k9 entscheiden $nr freigabe
Check ($LASTEXITCODE -eq 0) 'uebernommen'
Wait 40 'VirusTotal-Schleife'
$last = Select-String -Path $logs -Pattern 'vt: VirusTotal-Abfrage: (aktiv|aus)' | Select-Object -Last 1
Check ($last.Line -match 'Abfrage: aus') "VirusTotal: $($last.Line)"
$st = & $k9 funktion status 2>&1 | Out-String
Write-Host $st
Check ($st -match 'anhalten\s+Kritische Programme anhalten\s+aus') 'Status: Anhalten aus'
Check (-not (OpenNr)) 'Fund entschieden'
Check (-not (Confirmed 'quellen.virustotal_aktiv') -and -not (Confirmed 'echtzeit.kritische_prozesse_anhalten')) 'bestaetigter Stand: beide aus'
Select-String -Path $logs -Pattern 'Best.+tigt|bernommen' | Select-Object -Last 6 | ForEach-Object { Write-Host "  $($_.Line)" }

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen-bestaetigen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-bestaetigen-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
