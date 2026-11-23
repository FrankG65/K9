<#
  Testlauf "Browser-Erweiterungen" IN DER WINDOWS-SANDBOX (offline reicht).
  Nur selbst angelegte Test-Eintraege, die nichts tun (Platzhalter-IDs, ungueltige Adressen).
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Aufruf (Sandbox, Administrator, ueber wsb exec):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-erweiterungen.ps1

  Erwartung:
    E1 Richtlinie ExtensionInstallForcelist mit fremder Update-Adresse  -> Kritisch ERWEITERUNG:RICHTLINIE
    E2 Registry-Installation mit lokalem Pfad                          -> Hoch ERWEITERUNG:REGISTRY
    E3 Desktop-Verknuepfung msedge.exe --load-extension=...            -> Hoch ERWEITERUNG:VERKNUEPFUNG
    E4 Edge mit --load-extension aus dem Benutzerordner gestartet      -> Hoch BROWSER:ERWEITERUNG-GELADEN
    E5 Erweiterungs-Liste im Dashboard (Edge-Grundzustand)             -> keine weiteren Meldungen
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
$edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'

Step 'A Edge einmal starten (legt das Profil an)'
$p = Start-Process -FilePath $edge -ArgumentList '--headless', 'about:blank' -PassThru
Wait 15 'Profil'
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Step 'B Test-Eintraege anlegen (tun nichts)'
$extDir = Join-Path $env:LOCALAPPDATA 'TestErweiterung'
New-Item -ItemType Directory -Force $extDir | Out-Null
Set-Content (Join-Path $extDir 'manifest.json') '{"manifest_version":3,"name":"Testerweiterung","version":"1.0","host_permissions":["<all_urls>"],"permissions":["cookies"]}' -Encoding ASCII
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
New-Item -Force $pol | Out-Null
New-ItemProperty -Force -Path $pol -Name '1' -Value 'aaaabbbbccccddddeeeeffffgggghhhh;https://beispiel.invalid/update.xml' | Out-Null
$reg = 'HKCU:\Software\Microsoft\Edge\Extensions\bbbbccccddddeeeeffffgggghhhhiiii'
New-Item -Force $reg | Out-Null
New-ItemProperty -Force -Path $reg -Name 'path' -Value (Join-Path $extDir 'test.crx') | Out-Null
New-ItemProperty -Force -Path $reg -Name 'version' -Value '1.0' | Out-Null
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Edge-Test.lnk'))
$lnk.TargetPath = $edge
$lnk.Arguments = "--load-extension=$extDir"
$lnk.Save()
Write-Host '  Richtlinie, Registry-Eintrag, Verknuepfung und Test-Ordner angelegt.'

Step 'C K9 installieren'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'Agent bereit'

Step 'E4 Edge mit --load-extension aus dem Benutzerordner'
$p = Start-Process -FilePath $edge -ArgumentList '--headless', "--load-extension=$extDir", 'about:blank' -PassThru
Wait 15 'Programmstart-Pruefung'
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Step 'D Erste Erweiterungs-Pruefung des Agents abwarten (2 Minuten nach dem Start)'
Wait 150 'Pruefung'

Step 'Aufraeumen der Test-Eintraege'
Remove-Item -Force -Recurse $pol -ErrorAction SilentlyContinue
Remove-Item -Force -Recurse $reg -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Edge-Test.lnk') -ErrorAction SilentlyContinue

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
& $k9 status *> (Join-Path $out 'status.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
