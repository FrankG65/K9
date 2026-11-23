<#
  Lauf 20 "Umstellung Virenscanner -> K9" IN DER WINDOWS-SANDBOX (offline, frische Sandbox,
  ca. 20 Minuten, keine Klicks noetig).
  Zuerst wird die alte Version (21b0cdc, C:\Testlabor\alt) mit echten Daten eingerichtet, dann mit
  der neuen Version (C:\Testlabor\programm) umgestellt und alles geprueft.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    U1 Alte Version: Fund (Testsignatur) in Quarantaene, Entscheidung, Dummy-Schluessel, Firewall-Regel,
       Anhalten an, Schattenkopien C:
    U2 k9 dienst aktualisieren -> "Selbsttest von K9: in Ordnung", alte Teile entfernt, Sicherung *.alt
    U3 Daten uebernommen: gleiche Zahl Funde und Entscheidungen, Entscheidungen gueltig, Quarantaene-Datei
       unter C:\ProgramData\K9, Schluessel (virustotal-key) beim Dienst, Einstellungen (anhalten an), Laufwerke C:
    U4 Kein "Virenscanner" mehr in Diensten, Registry, Autostart, Firewall, Verknuepfungen, Programmordnern
       (ausser den Sicherungen *.alt); Firewall-Regel unter K9
    U5 Kein falscher Alarm: Dienststart "Update", kein SELBSTSCHUTZ-Fund
    U6 Echte Manipulation alarmiert weiter: k9.exe veraendert + Dienstneustart -> Kritisch DATEIEN-VERAENDERT
    U7 Zweite Aktualisierung: keine zweite Uebernahme
    U8 k9 alte-installation entfernen --ja -> Sicherungen und alte Anmeldeinformationen weg
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$alt = 'C:\Testlabor\alt'
$neu = 'C:\Testlabor\programm'
$oldCli = 'C:\Program Files\Virenscanner\vscan.exe'
$k9 = 'C:\Program Files\K9\k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll-umzug.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Check([bool]$ok, [string]$what) { Write-Host ("  [{0}] {1}" -f $(if ($ok) { 'OK' } else { 'FEHLER' }), $what) }

Step 'U1 Alte Version einrichten und Daten anlegen'
Run "$alt\vscan.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process vs-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 40 'Agent und Dienst bereit'
$cfgOld = Join-Path $env:APPDATA 'Virenscanner\config.toml'
# Testsignatur (harmlos, im Programm verschleiert; hier zur Laufzeit zusammengesetzt)
$sig = 'VIRENSCANNER-' + 'TESTSIGNATUR-' + 'HARMLOS-2026'
$probe = Join-Path $env:USERPROFILE 'Downloads\umzug-probe.txt'
Set-Content -Path $probe -Value ("Test " + $sig) -Encoding ASCII
Run $oldCli scan $probe
$liste = & $oldCli erkennungen 2>&1 | Out-String
$nr = ($liste -split "`n" | Where-Object { $_ -match 'Testsignatur' } | ForEach-Object { if ($_ -match '^\s*#(\d+)') { [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
Write-Host "  Fund Nr. $nr"
if ($nr) { Run $oldCli entscheiden $nr quarantaene }
'dummy-vt-nur-sandbox' | & $oldCli geheimnis virustotal-key --aus-eingabe 2>&1 | Out-String | Write-Host
'dummy-ntfy-nur-sandbox' | & $oldCli geheimnis ntfy-token --aus-eingabe 2>&1 | Out-String | Write-Host
Run $oldCli funktion anhalten an
Run $oldCli funktion schattenkopien laufwerke C:
$heute = Get-Date -Format 'yyyy-MM-dd'
$tf = 'C:\ProgramData\Virenscanner\quellen\abusech\threatfox.json'
New-Item -ItemType Directory -Force (Split-Path $tf -Parent) | Out-Null
@{ '45.67.89.10:4444' = @{ typ = 'ip'; malware = 'Test'; first_seen = $heute; threat_type = 'botnet_cc'; confidence = 100; last_seen = $heute } } |
    ConvertTo-Json | Set-Content -Path $tf -Encoding ASCII
Run $oldCli funktion firewall an
Wait 60 'alter Dienst legt Firewall-Regel und bestaetigten Stand an'
$vorFunde = (& $oldCli erkennungen --alle 2>&1 | Out-String) -split "`n" | Where-Object { $_ -match '^\s*#\d+' }
$vorEnt = (& $oldCli entscheidungen 2>&1 | Out-String) -split "`n" | Where-Object { $_ -match '^\s*#\d+' }
Write-Host "  vorher: $(@($vorFunde).Count) Funde, $(@($vorEnt).Count) Entscheidungen"
$alteOrdner = @('C:\ProgramData', $env:APPDATA, $env:LOCALAPPDATA | Where-Object { Test-Path (Join-Path $_ 'Virenscanner') })
Write-Host "  alte Ordner: $($alteOrdner -join ', ')"
Check (@(Get-NetFirewallRule -Group 'Virenscanner' -ErrorAction SilentlyContinue).Count -ge 1) 'alte Firewall-Regel vorhanden'
Check (Test-Path 'C:\ProgramData\Virenscanner\einstellungen-bestaetigt.json') 'alter bestaetigter Stand vorhanden'
Check ([bool]$nr -and @(Get-ChildItem 'C:\ProgramData\Virenscanner\quarantaene' -Filter *.vsq -ErrorAction SilentlyContinue).Count -ge 1) 'alte Quarantaene-Datei vorhanden'

Step 'U2 Umstellung auf K9'
$ausgabe = & "$neu\k9.exe" dienst aktualisieren 2>&1 | Out-String
Write-Host $ausgabe
Check ($ausgabe -match 'Selbsttest von K9: in Ordnung') 'Selbsttest in Ordnung'
Check ($ausgabe -match 'Alter Dienst .* entfernt') 'alter Dienst entfernt'
Check ($ausgabe -match 'Sicherung der alten Daten') 'Sicherung angelegt'
for ($i = 0; $i -lt 30 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
Check ([bool](Get-Process k9-agent -ErrorAction SilentlyContinue)) 'K9-Agent laeuft'
Wait 45 'K9 erneuert die Firewall-Regeln'

Step 'U3 Daten uebernommen'
$nachFunde = (& $k9 erkennungen --alle 2>&1 | Out-String) -split "`n" | Where-Object { $_ -match '^\s*#\d+' }
$entText = & $k9 entscheidungen 2>&1 | Out-String
Write-Host $entText
$nachEnt = $entText -split "`n" | Where-Object { $_ -match '^\s*#\d+' }
Check (@($nachFunde).Count -ge @($vorFunde).Count) "Funde: vorher $(@($vorFunde).Count), nachher $(@($nachFunde).Count)"
Check (@($nachEnt).Count -eq @($vorEnt).Count) "Entscheidungen: vorher $(@($vorEnt).Count), nachher $(@($nachEnt).Count)"
Check (-not ($entText -match 'nicht vom Dienst unterschrieben')) 'alle Entscheidungen gueltig unterschrieben'
$log = (Get-Content 'C:\ProgramData\K9\logs\*' -Raw) -join "`n"
Check ($log -match 'Selbsttest beim Start: in Ordnung') 'Selbsttest im Dienst-Log'
Check (@(Get-ChildItem 'C:\ProgramData\K9\quarantaene' -Filter *.vsq -ErrorAction SilentlyContinue).Count -ge 1) 'Quarantaene-Datei unter C:\ProgramData\K9'
Run $k9 quarantaene
$st = & $k9 funktion status 2>&1 | Out-String
Write-Host $st
Check ($st -match '(?m)^\s*anhalten\s+Kritische Programme anhalten\s+an\s*$') 'Anhalten weiter an'
Check ($st -match 'virustotal-key\s+.*gespeichert') 'VirusTotal-Schluessel beim Dienst'
Check ($st -match 'Laufwerke der Schattenkopien\s+C:') 'Laufwerke C:'
$cred = cmdkey /list | Out-String
Check (-not ($cred -match 'virustotal-key\.K9')) 'VirusTotal-Schluessel nicht in der Anmeldeinformationsverwaltung (nur beim Dienst)'
Check ($cred -match 'ntfy-token\.K9') 'ntfy-token unter K9 uebernommen'
Check ((Get-Content (Join-Path $env:APPDATA 'K9\config.toml') -Raw) -match 'kritische_prozesse_anhalten = true') 'config.toml uebernommen'
Check ([bool](& $k9 status 2>&1 | Out-String)) 'k9 status laeuft'

Step 'U4 Keine alten Namen mehr (ausser Sicherungen)'
Check (-not (Get-Service 'Virenscanner-Dienst' -ErrorAction SilentlyContinue)) 'kein Dienst Virenscanner-Dienst'
Check ([bool](Get-Service 'K9-Dienst' -ErrorAction SilentlyContinue)) 'Dienst K9-Dienst da'
Check (-not (Test-Path 'HKLM:\SOFTWARE\Virenscanner')) 'kein HKLM\SOFTWARE\Virenscanner'
Check (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Virenscanner-Dienst')) 'kein Dienst-Schluessel in HKLM\SYSTEM'
$run = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Check (-not ($run.PSObject.Properties.Name -match 'Virenscanner')) 'kein alter Autostart'
Check (-not (Test-Path 'HKCU:\Software\Classes\AppUserModelId\Virenscanner.Agent')) 'keine alte Benachrichtigungs-Kennung'
$fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Virenscanner*' -or $_.Group -like '*Virenscanner*' }
Check (@($fw).Count -eq 0) 'keine Firewall-Regel mit Virenscanner'
Check (@(Get-NetFirewallRule -Group 'K9' -ErrorAction SilentlyContinue).Count -ge 1) 'Firewall-Regel in Gruppe K9'
$links = Get-ChildItem ([Environment]::GetFolderPath('Desktop')), ([Environment]::GetFolderPath('Programs')) -Filter '*Virenscanner*' -ErrorAction SilentlyContinue
Check (@($links).Count -eq 0) 'keine alte Verknuepfung'
Check (Test-Path ([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'K9-Dashboard.lnk'))) 'Verknuepfung K9-Dashboard'
Check (-not (Test-Path 'C:\Program Files\Virenscanner')) 'kein C:\Program Files\Virenscanner'
# Programmsymbol: in allen drei Programmen eingebettet, die Verknuepfung nutzt es
Add-Type -AssemblyName System.Drawing
foreach ($e in 'k9.exe', 'k9-agent.exe', 'k9-dienst.exe') {
    $b = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Program Files\K9\$e").ToBitmap()
    $px = $b.GetPixel(16, 22)
    Check ($px.R -eq 255 -and $px.G -eq 107 -and $px.B -eq 0) "Symbol (orange Pfote) in $e"
}
$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'K9-Dashboard.lnk'))
Check ($lnk.IconLocation -match 'K9\\k9\.exe') "Verknuepfung nutzt das Symbol von k9.exe ($($lnk.IconLocation))"
$agentLog = Get-Content (Join-Path $env:LOCALAPPDATA 'K9\logs\*') -Raw -ErrorAction SilentlyContinue
Check (-not ($agentLog -match 'Infobereich nicht verf')) 'Symbol im Infobereich angelegt'
foreach ($d in 'C:\ProgramData', $env:APPDATA, $env:LOCALAPPDATA) {
    Check (-not (Test-Path (Join-Path $d 'Virenscanner'))) "kein $d\Virenscanner"
    if ($alteOrdner -contains $d) { Check (Test-Path (Join-Path $d 'Virenscanner.alt')) "Sicherung $d\Virenscanner.alt" }
}
$acl = (Get-Acl 'C:\ProgramData\Virenscanner.alt\geheim').Access | Where-Object { $_.IdentityReference -match 'Benutzer|Users' }
Check (@($acl).Count -eq 0) 'Sicherung des geheimen Ordners bleibt fuer Benutzer gesperrt'

Step 'U5 Kein falscher Alarm'
Check ($log -match 'Dienststart Update') 'Dienststart als Aktualisierung'
$f = & $k9 erkennungen 2>&1 | Out-String
Check (-not ($f -match 'SELBSTSCHUTZ')) 'kein Selbstschutz-Fund'
Check (-not ($f -match 'EINSTELLUNG:SICHERHEIT')) 'kein Fehlalarm "Sicherheitseinstellung abgeschwaecht" (config.toml uebernommen)'

Step 'U6 Echte Manipulation alarmiert weiter'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 8 'gestoppt'
Add-Content -Path $k9 -Value 'manipulation'
Run sc.exe start 'K9-Dienst'
Wait 45 'Pruefung beim Start'
$f = & $k9 erkennungen 2>&1 | Out-String
Check ($f -match 'SELBSTSCHUTZ:DATEIEN-VERAENDERT') 'Kritisch: Programmdateien veraendert'

Step 'U7 Zweite Aktualisierung: keine zweite Uebernahme'
$ausgabe = & "$neu\k9.exe" dienst aktualisieren 2>&1 | Out-String
Write-Host $ausgabe
Check (-not ($ausgabe -match 'Bisherige Installation')) 'keine zweite Uebernahme'
Check ($ausgabe -match 'Dienst l.+uft') 'Dienst laeuft'

Step 'U8 Sicherung entfernen'
Run $k9 alte-installation entfernen --ja
foreach ($d in 'C:\ProgramData', $env:APPDATA, $env:LOCALAPPDATA) {
    Check (-not (Test-Path (Join-Path $d 'Virenscanner.alt'))) "Sicherung $d\Virenscanner.alt entfernt"
}

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen-umzug.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-umzug-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
