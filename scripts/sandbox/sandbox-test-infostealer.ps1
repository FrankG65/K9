<#
  Testlauf "Schutz vor Datendieben" IN DER WINDOWS-SANDBOX (offline reicht).
  Nur Schein-Dateien mit Zufallsinhalt, keine echten Zugangsdaten, keine Schadsoftware.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Aufruf (Sandbox, Administrator, ueber wsb exec):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-infostealer.ps1

  Erwartung:
    T1 Kopie von k9.exe aus "Downloads" liest Chrome-Schein-Datei   -> Kritisch (unsigniert, Benutzerordner)
    T2 PowerShell liest Chrome-, dann Steam-Schein-Datei               -> Hoch, dann Kritisch (mehrere Speicher)
    T3 cmd.exe liest die Chrome-Datei mit kleingeschriebenem Pfad      -> Hoch (prueft Gross-/Kleinschreibung im Filter)
    T3b certutil liest die Chrome-Datei als "uSeR dAtA"                -> Hoch (gemischte Schreibweise)
    T3c esentutl kopiert die Steam-Datei als "sTeAm"                   -> Hoch
    T4 Edge unsichtbar mit Fernsteuerung (Remote-Debugging) gestartet  -> Kritisch BROWSER:FERNSTEUERUNG
    T5 Edge normal gestartet (liest seine eigenen Dateien)             -> keine Meldung
    Danach 10 Minuten Ruhe fuer die Statistik im Dienst-Protokoll.
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Dummy([string]$path) {
    New-Item -ItemType Directory -Force (Split-Path $path -Parent) | Out-Null
    $b = New-Object byte[] 4096; (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes($path, $b)
    Write-Host "  Schein-Datei: $path"
}

# Before the scanner is installed: creating them is not reported.
Step 'A Schein-Profile anlegen'
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
$steam = Join-Path ${env:ProgramFiles(x86)} 'Steam\config\loginusers.vdf'
Dummy $chrome
Dummy $steam

Step 'B K9 installieren'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'ETW-Sitzung des Dienstes'

Step 'T1 Unbekanntes, unsigniertes Programm aus Downloads liest Chrome-Datei'
$fremd = Join-Path $env:USERPROFILE 'Downloads\unbekannt.exe'
Copy-Item "$prog\k9.exe" $fremd -Force
Run $fremd scan $chrome
Wait 10 'Meldung'

Step 'T2 PowerShell liest Chrome-, dann Steam-Datei'
Run powershell.exe -NoProfile -Command "[IO.File]::OpenRead('$chrome').Close()"
Wait 5 'kurz'
Run powershell.exe -NoProfile -Command "[IO.File]::OpenRead('$steam').Close()"
Wait 10 'Meldung'

Step 'T3 cmd liest die Chrome-Datei mit kleingeschriebenem Pfad'
Run cmd.exe /c "type `"$($chrome.ToLower())`" > nul"
Wait 10 'Meldung'

Step 'T3b certutil liest die Chrome-Datei mit gemischter Schreibweise (uSeR dAtA)'
$gemischt = $chrome -replace 'User Data', 'uSeR dAtA' -replace 'Google', 'gOOGLE'
Run certutil.exe -hashfile $gemischt SHA256
Wait 10 'Meldung'

Step 'T3c esentutl kopiert die Steam-Datei mit gemischter Schreibweise (User data / sTeAm)'
$kopie = Join-Path $env:TEMP 'vs-probe-kopie.bin'
Run esentutl.exe /y ($steam -replace 'Steam', 'sTeAm') /d $kopie
Remove-Item $kopie -Force -ErrorAction SilentlyContinue
Wait 10 'Meldung'

Step 'T4 Edge unsichtbar mit Fernsteuerung'
$edge = (Get-Command msedge.exe -ErrorAction SilentlyContinue).Source
if (-not $edge) { $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' }
$p = Start-Process -FilePath $edge -ArgumentList '--headless', '--remote-debugging-port=9333', 'about:blank' -PassThru
Wait 15 'Programmstart-Pruefung'
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*remote-debugging-port=9333*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Step 'T5 Edge normal (kein Fund erwartet)'
$p = Start-Process -FilePath $edge -ArgumentList 'about:blank' -PassThru
Wait 20 'Edge liest seine eigenen Dateien'
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Step 'C Ruhe fuer die 10-Minuten-Statistik des Dienstes'
Wait 620 'Statistik'

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
& $k9 status *> (Join-Path $out 'status.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
