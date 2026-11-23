<#
  Testlauf "Ausbau Phase 2" IN DER WINDOWS-SANDBOX (offline reicht, frische Sandbox, ca. 20 Minuten).
  Nur harmlose, selbst erzeugte Test-Schritte. VirusTotal und Firewall-Sperre brauchen Internet
  bzw. einen Schluessel und werden hier nur auf "aus" und Status geprueft.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    E1 Anhalten eingeschaltet; Testprogramm aus dem Internet startet eine Kette bis zu den
       Zugangsdaten                      -> KETTE:ANGRIFF Kritisch, Testprogramm ANGEHALTEN (Threads "Suspended")
    E2 PowerShell (Microsoft-signiert) liest Zugangsdaten mehrerer Programme
                                         -> Kritisch, aber NICHT angehalten (Log "Nicht angehalten")
    E3 "k9 entscheiden <Nr> einmalig" -> Testprogramm laeuft weiter und endet
    H1 Schattenkopien eingeschaltet, Leerlauf -> Kopie angelegt ODER Hinweis "kein Speicher"; Zeile in "k9 dienst status"
    G2 Firewall-Sperre mit lokaler Liste -> Regel nur fuer 45.67.89.10 Port 4444 (nicht privat, nicht Loopback, nicht zu alt)
    G3 k9 firewall entfernen          -> 0 eigene Regeln, Gesamtzahl der Regeln wie vorher
    F1 VirusTotal offline, Dummy-Schluessel -> nur Log "fehlgeschlagen", kein Fund, kein Absturz
    H2 Schattenkopien                    -> Anzahl nie durch K9 verringert
    Regression Phase 1:
    R1 Skriptblock FromBase64String + VirtualAlloc -> Hoch SKRIPT:SPEICHER-LADEN
    R2 eigene Aktualisierung                       -> Dienststart "Update", kein Selbstschutz-Alarm
    R3 Austausch + Neustart                        -> Kritisch SELBSTSCHUTZ:DATEIEN-VERAENDERT (nur k9.exe), Mittel DIENST-NEUSTART
    (die Angriffskette aus E1 deckt Phase 1c ab)
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
function Suspended([int]$id) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $p) { return 'beendet' }
    $s = @($p.Threads | Where-Object { $_.WaitReason -eq 'Suspended' }).Count
    "$s von $($p.Threads.Count) Threads angehalten"
}

Step 'A Schein-Dateien und Testprogramm'
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
$steam = Join-Path ${env:ProgramFiles(x86)} 'Steam\config\loginusers.vdf'
foreach ($f in $chrome, $steam) {
    New-Item -ItemType Directory -Force (Split-Path $f -Parent) | Out-Null
    $b = New-Object byte[] 4096; (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes($f, $b)
}
$chromeCs = $chrome.Replace('\', '\\')
$src = @"
using System.Diagnostics;
public static class Prg {
    public static void Main() {
        var a = Process.Start("schtasks.exe", "/create /tn VS-Test-Aufgabe2 /tr notepad.exe /sc once /st 23:59 /f"); a.WaitForExit();
        var b = Process.Start("powershell.exe", "-NoProfile -Command [IO.File]::OpenRead('$chromeCs').Close()"); b.WaitForExit();
        System.Threading.Thread.Sleep(120000);
    }
}
"@
$tool = Join-Path $env:USERPROFILE 'Downloads\mod-tool2.exe'
Add-Type -TypeDefinition $src -OutputAssembly $tool -OutputType ConsoleApplication
Set-Content -Path "${tool}:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://beispiel.invalid/mod-tool2.exe`r`n"

Step 'B K9 installieren, Eingriffe einschalten (Anhalten, Schattenkopien), Dienst neu starten'
Run "$prog\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 20 'Agent legt config.toml an'
$cfg = Join-Path $env:APPDATA 'K9\config.toml'
$regelnVorher = @(Get-NetFirewallRule).Count
Write-Host "  Firewall-Regeln vorher (alle): $regelnVorher"
# F1: VirusTotal mit Dummy-Schluessel (Sandbox ist offline: Abfrage muss sauber scheitern)
'dummy-schluessel-nur-sandbox' | & $k9 geheimnis virustotal-key --aus-eingabe 2>&1 | Out-String | Write-Host
# G2: lokale Test-Liste statt Download (oeffentlich+Port, privat, Loopback, zu alt)
$heute = Get-Date -Format 'yyyy-MM-dd'
$alt = (Get-Date).AddDays(-60).ToString('yyyy-MM-dd')
$tf = 'C:\ProgramData\K9\quellen\abusech\threatfox.json'
New-Item -ItemType Directory -Force (Split-Path $tf -Parent) | Out-Null
$liste = [ordered]@{
    '45.67.89.10:4444' = @{ typ = 'ip'; malware = 'Test'; first_seen = $heute; threat_type = 'botnet_cc'; confidence = 100; last_seen = $heute }
    '192.168.10.20:4444' = @{ typ = 'ip'; malware = 'Test'; first_seen = $heute; threat_type = 'botnet_cc'; confidence = 100; last_seen = $heute }
    '127.0.0.2:4444' = @{ typ = 'ip'; malware = 'Test'; first_seen = $heute; threat_type = 'botnet_cc'; confidence = 100; last_seen = $heute }
    '45.67.89.11:5555' = @{ typ = 'ip'; malware = 'Test'; first_seen = $alt; threat_type = 'botnet_cc'; confidence = 100; last_seen = $alt }
}
$liste | ConvertTo-Json | Set-Content -Path $tf -Encoding ASCII
(Get-Content $cfg) -replace '^kritische_prozesse_anhalten = false', 'kritische_prozesse_anhalten = true' -replace '^schattenkopien = false', 'schattenkopien = true' `
    -replace '^firewall_sperre = false', 'firewall_sperre = true' -replace '^virustotal_aktiv = false', 'virustotal_aktiv = true' |
    Set-Content -Path $cfg -Encoding UTF8
Select-String -Path $cfg -Pattern '^kritische_prozesse_anhalten|^schattenkopien =|^firewall_sperre|^virustotal_aktiv' | ForEach-Object { Write-Host "  $($_.Line)" }
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 5 'gestoppt'
Run sc.exe start 'K9-Dienst'
Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force   # Agent liest config.toml neu (die Wache startet ihn)
Wait 60 'Dienst und Agent bereit'

Step 'G2 Firewall-Sperre mit lokaler Test-Liste'
netsh advfirewall firewall show rule name="Virenscanner C2-Sperre" verbose | Select-String 'Regelname|Rule Name|RemoteIP|Remote IP|Remoteport|RemotePort|Richtung|Direction|Aktion|Action' | ForEach-Object { Write-Host "  $($_.Line.Trim())" }
Run $k9 firewall status

Step 'E1 Testprogramm aus dem Internet starten (Kette bis zu den Zugangsdaten)'
$p = Start-Process -FilePath $tool -PassThru
Wait 15 'Kette und Anhalten'
Write-Host "  Testprogramm (PID $($p.Id)): $(Suspended $p.Id)"

Step 'E2 PowerShell liest Chrome- und Steam-Datei (Microsoft-signiert: nicht anhalten)'
Run powershell.exe -NoProfile -Command "[IO.File]::OpenRead('$chrome').Close(); [IO.File]::OpenRead('$steam').Close(); Start-Sleep 10"
Wait 5 'Meldung'

Step 'E3 Entscheidung "nur diesmal" fuer die Angriffskette'
$liste = & $k9 erkennungen 2>&1 | Out-String
Write-Host $liste
$nr = ($liste -split "`n" | Where-Object { $_ -match 'KETTE:ANGRIFF' -and $_ -match 'Kritisch' } | Select-Object -First 1) -replace '^\s*#(\d+).*', '$1'
Write-Host "  Kette: Nr. $nr"
if ($nr -match '^\d+$') { Run $k9 entscheiden $nr einmalig }
Wait 5 'fortgesetzt'
Write-Host "  Testprogramm (PID $($p.Id)): $(Suspended $p.Id)"
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
schtasks.exe /delete /tn VS-Test-Aufgabe2 /f | Out-Null

Step 'H1 Schattenkopien im Leerlauf (bis zu 8 Minuten)'
for ($i = 0; $i -lt 16; $i++) {
    Start-Sleep 30
    if (Select-String -Path 'C:\ProgramData\K9\logs\*' -Pattern 'Schattenkopie angelegt|kein Speicher|nicht angelegt' -Quiet) { break }
}
Run $k9 dienst status

Step 'G3 Firewall-Regeln entfernen'
Run $k9 firewall entfernen
Run $k9 firewall status
$regelnNachher = @(Get-NetFirewallRule).Count
Write-Host "  Firewall-Regeln nachher (alle): $regelnNachher (vorher $regelnVorher)"

Step 'F1 VirusTotal offline mit Dummy-Schluessel'
Select-String -Path 'C:\ProgramData\K9\logs\*' -Pattern 'VirusTotal' | ForEach-Object { Write-Host "  $($_.Line)" }

Step 'H2 Keine Schattenkopie geloescht'
Write-Host "  Schattenkopien jetzt: $(@(Get-CimInstance Win32_ShadowCopy).Count)"
Select-String -Path 'C:\ProgramData\K9\logs\*' -Pattern 'Schattenkopie' | ForEach-Object { Write-Host "  $($_.Line)" }

Step 'R1 Regression Phase 1: Skriptblock FromBase64String + VirtualAlloc (ohne Richtlinie)'
$w = 'Virtual' + 'Alloc'
& ([scriptblock]::Create("`$b = [Convert]::FromBase64String('QUFBQQ=='); `$f = '$w'; [void]`$b.Length"))
Wait 10 'Meldung'

Step 'R2 Regression Phase 1: eigene Aktualisierung mit veraenderten Dateien (kein Alarm)'
$neu = 'C:\VS-Update'
New-Item -ItemType Directory -Force $neu | Out-Null
Copy-Item "$prog\*.exe" $neu
foreach ($f in 'k9.exe', 'k9-agent.exe', 'k9-dienst.exe') { Add-Content -Path (Join-Path $neu $f) -Value 'aktualisierung' }
Run "$neu\k9.exe" dienst aktualisieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'Dienst und Agent laufen wieder'

Step 'R3 Regression Phase 1: Dienst stoppen, k9.exe austauschen, sofort starten (Alarm)'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 5 'gestoppt'
Add-Content -Path $k9 -Value 'austausch'
Run sc.exe start 'K9-Dienst'
Wait 40 'Pruefung beim Start'

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
