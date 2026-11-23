<#
  Zweiter Testlauf IN DER WINDOWS-SANDBOX (mit Netzwerk). Nur offizielle Testdateien/-seiten und
  harmlose Atomic-Red-Team-Tests; alles wird in der Sandbox geladen, nichts auf dem PC bereitgelegt.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Aufruf in der Sandbox (Administrator):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-online.ps1

  Quellen:
    EICAR-Testdateien:   https://amtso.eicar.org/eicar.com, https://secure.eicar.org/eicar_com.zip
    AMTSO-Pruefseiten:   http://amtso.eicar.org/PotentiallyUnwanted.exe, https://www.amtso.org/check-desktop-phishing-page/
    Atomic Red Team:     nur YAML-Dateien und eine src-Datei aus github.com/redcanaryco/atomic-red-team,
                         fester Stand (Commit) unten; kein Zip, keine Binaerdateien, kein Zusatzmodul.
  Ergebnisse (nur Text) in C:\Ergebnis. Dauer etwa 35 Minuten.
  -Teil Gezielt: nur Aufgaben (T1053.005), mshta und rundll32 erneut (etwa 5 Minuten; setzt einen
  vorherigen Lauf in derselben Sandbox voraus).
#>
param([ValidateSet('Alles', 'Gezielt')][string]$Teil = 'Alles')
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$prog = 'C:\Testlabor\programm'
$inst = 'C:\Program Files\K9'
$k9 = Join-Path $inst 'k9.exe'
$artCommit = 'a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6'
$artBase = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$artCommit/atomics"
$atomics = 'C:\Atomics'
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
# Downloads: only the outcome is logged, never the content.
function Fetch([string]$url, [string]$file) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file -TimeoutSec 60
        Write-Host "  geladen: $url -> $file ($((Get-Item $file).Length) Bytes)"
    } catch { Write-Host "  nicht geladen: $url ($($_.Exception.Message))" }
}
function Present([string]$file) { Write-Host "  Datei noch vorhanden: $(Test-Path $file) ($file)" }

# Minimal reader for one test of an Atomic Red Team YAML file (only the fields needed here).
function Get-Atomic([string]$tech, [string]$guid) {
    $lines = Get-Content (Join-Path $atomics "$tech\$tech.yaml")
    $start = ($lines | Select-String -SimpleMatch "auto_generated_guid: $guid").LineNumber
    if (-not $start) { return $null }
    $end = $lines.Count
    for ($i = $start; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^- name:') { $end = $i; break } }
    $block = $lines[($start - 1)..($end - 1)]
    $t = @{ Args = @{}; Command = @(); Cleanup = @(); Executor = '' }
    $section = ''; $arg = ''
    foreach ($l in $block) {
        if ($l -match '^  input_arguments:') { $section = 'args'; continue }
        if ($l -match '^  executor:') { $section = 'exec'; continue }
        if ($l -match '^  \S') { $section = ''; continue }
        if ($section -eq 'args') {
            if ($l -match '^    ([\w-]+):\s*$') { $arg = $Matches[1] }
            elseif ($l -match '^      default:\s*(.*)$') { $t.Args[$arg] = $Matches[1].Trim().Trim("'").Trim('"') }
        } elseif ($section -eq 'exec') {
            if ($l -match '^    (command|cleanup_command):\s*\|') { $section = "exec-$($Matches[1])"; continue }
            if ($l -match "^    command:\s*'(.*)'\s*$") { $t.Command = @($Matches[1]); continue }
            if ($l -match '^    name:\s*(\S+)') { $t.Executor = $Matches[1] }
        } elseif ($section -like 'exec-*') {
            if ($l -match '^      (.*)$') {
                if ($section -eq 'exec-command') { $t.Command += $Matches[1] } else { $t.Cleanup += $Matches[1] }
            } elseif ($l -match '^    (\S+):') {
                $section = 'exec'
                if ($l -match '^    (command|cleanup_command):\s*\|') { $section = "exec-$($Matches[1])" }
                elseif ($l -match '^    name:\s*(\S+)') { $t.Executor = $Matches[1] }
            }
        }
    }
    foreach ($k in 'Command', 'Cleanup') {
        $t[$k] = @($t[$k] | ForEach-Object {
            $c = $_ -replace 'PathToAtomicsFolder', $atomics
            foreach ($a in $t.Args.Keys) { $c = $c.Replace("#{$a}", $t.Args[$a]) }
            $c
        })
    }
    return $t
}

function Invoke-Atomic([string]$tech, [string]$guid, [string]$name, [switch]$Cleanup) {
    $t = Get-Atomic $tech $guid
    if (-not $t -or $t.Command.Count -eq 0) { Write-Host "  $tech $guid nicht gefunden - uebersprungen"; return }
    $part = if ($Cleanup) { $t.Cleanup } else { $t.Command }
    if ($part.Count -eq 0) { Write-Host '  (keine Aufraeumbefehle)'; return }
    Write-Host "  $tech $name ($guid) $(if ($Cleanup) { 'Aufraeumen' } else { 'Ausfuehren' }), Ausfuehrung: $($t.Executor)"
    $file = Join-Path $env:TEMP ("atomic-$tech-" + $(if ($Cleanup) { 'cleanup' } else { 'run' }))
    if ($t.Executor -eq 'powershell') {
        Set-Content "$file.ps1" ($part -join "`r`n") -Encoding UTF8
        Run powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$file.ps1"
    } else {
        Set-Content "$file.cmd" ($part -join "`r`n") -Encoding ASCII
        Run cmd.exe /c "$file.cmd"
    }
}

function Collect {
    Step 'Ergebnisse sammeln'
    & $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
    & $k9 status *> (Join-Path $out 'status.txt')
    & $k9 quellen *> (Join-Path $out 'quellen.txt')
    Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
    Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-' + $_.BaseName + '.log')) }
    Stop-Transcript | Out-Null
    Write-Host "`nFertig. Ergebnisse in C:\Ergebnis."
}

if ($Teil -eq 'Gezielt') {
    # Tasks first: the update restarts the agent, whose first round is complete (tasks too).
    Step 'G1 T1053.005 Geplante Aufgaben anlegen'
    Invoke-Atomic 'T1053.005' 'fec27f65-db86-4c2d-b66c-61945aee87c2' 'Scheduled Task Startup Script'
    Step 'G2 Neue Version installieren'
    Run "$prog\k9.exe" dienst installieren
    Write-Host '  warte, bis der Agent laeuft (hoechstens 300 s)'
    for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
    Wait 60 'erste vollstaendige Autostart-Runde des Agents'
    Step 'G3 T1218.005 mshta mit VBScript'
    Invoke-Atomic 'T1218.005' '906865c3-e05f-4acc-85c4-fbc185455095' 'Mshta executes VBScript'
    Wait 10 'Programmstart-Pruefung'
    Step 'G4 T1218.011 rundll32 mit VBScript'
    Invoke-Atomic 'T1218.011' '638730e7-7aed-43dc-bf8c-8117f805f5bb' 'Rundll32 execute VBscript command'
    Wait 10 'Programmstart-Pruefung'
    Get-Process calc*, CalculatorApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Step 'G5 Aufgaben wieder entfernen'
    Invoke-Atomic 'T1053.005' 'fec27f65-db86-4c2d-b66c-61945aee87c2' 'Scheduled Task Startup Script' -Cleanup
    Collect
    exit 0
}

Step 'A K9 installieren und Quellen laden'
Run "$prog\k9.exe" dienst installieren
Run $k9 quellen aktualisieren
Write-Host '  warte, bis der Agent laeuft (hoechstens 300 s)'
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 15 'Echtzeitschutz des Agents startet'
Run $k9 status

Step 'B EICAR-Testdateien (offizielle Quelle) nach Downloads'
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $dl | Out-Null
$e1 = Join-Path $dl 'eicar-test.com'; $e2 = Join-Path $dl 'eicar-test.zip'
Fetch 'https://amtso.eicar.org/eicar.com' $e1
Fetch 'https://secure.eicar.org/eicar_com.zip' $e2
Wait 20 'Echtzeitpruefung'
Present $e1; Present $e2

Step 'C AMTSO: PUA-Testdatei und Phishing-Testseite'
$pua = Join-Path $dl 'amtso-pua-test.exe'
Fetch 'http://amtso.eicar.org/PotentiallyUnwanted.exe' $pua
try { $r = Invoke-WebRequest -UseBasicParsing -Uri 'https://www.amtso.org/check-desktop-phishing-page/' -TimeoutSec 60; Write-Host "  Phishing-Testseite: HTTP $($r.StatusCode)" } catch { Write-Host "  Phishing-Testseite nicht geladen: $($_.Exception.Message)" }
Wait 20 'Echtzeitpruefung'
Present $pua

Step 'D Atomic Red Team: Testbeschreibungen laden (nur YAML + src, fester Stand)'
foreach ($tech in 'T1547.001', 'T1053.005', 'T1059.001', 'T1218.005', 'T1218.011', 'T1490') {
    New-Item -ItemType Directory -Force (Join-Path $atomics $tech) | Out-Null
    Fetch "$artBase/$tech/$tech.yaml" (Join-Path $atomics "$tech\$tech.yaml")
}
New-Item -ItemType Directory -Force (Join-Path $atomics 'T1218.005\src') | Out-Null
Fetch "$artBase/T1218.005/src/powershell.ps1" (Join-Path $atomics 'T1218.005\src\powershell.ps1')

Step 'D1 T1547.001 Run-Schluessel'
Invoke-Atomic 'T1547.001' 'e55be3fd-3521-4610-9d1a-e210e42dcf05' 'Reg Key Run'
Wait 45 'Autostart-Pruefung alle 30 s'
Step 'D2 T1053.005 Geplante Aufgaben'
Invoke-Atomic 'T1053.005' 'fec27f65-db86-4c2d-b66c-61945aee87c2' 'Scheduled Task Startup Script'
Step 'D3 T1059.001 PowerShell mit kodiertem Befehl'
Invoke-Atomic 'T1059.001' 'a538de64-1c74-46ed-aa60-b995ed302598' 'PowerShell Command Execution'
Wait 10 'Programmstart-Pruefung'
Step 'D4 T1218.005 mshta mit VBScript'
Invoke-Atomic 'T1218.005' '906865c3-e05f-4acc-85c4-fbc185455095' 'Mshta executes VBScript'
Wait 10 'Programmstart-Pruefung'
Step 'D5 T1218.011 rundll32 mit VBScript'
Invoke-Atomic 'T1218.011' '638730e7-7aed-43dc-bf8c-8117f805f5bb' 'Rundll32 execute VBscript command'
Wait 10 'Programmstart-Pruefung'
Step 'D6 T1490 Schattenkopien loeschen'
Invoke-Atomic 'T1490' '43819286-91a9-4369-90ed-d31fb4da2c01' 'Delete Volume Shadow Copies'
Wait 10 'Programmstart-Pruefung'
Get-Process calc*, CalculatorApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Step 'D7 Run-Schluessel wieder entfernen (Meldung soll sich selbst erledigen)'
Invoke-Atomic 'T1547.001' 'e55be3fd-3521-4610-9d1a-e210e42dcf05' 'Reg Key Run' -Cleanup

Step 'E Ohne Agent: Datei kommt an, Dienst-Neustart, Treiber in der Startphase des Dienstes'
Rename-Item (Join-Path $inst 'k9-agent.exe') 'k9-agent.exe.pause' -ErrorAction SilentlyContinue
Run taskkill.exe /F /IM k9-agent.exe
# E1: arrives while no agent runs -> must be found by the check after the agent start.
$e3 = Join-Path $dl 'eicar-nachpruefung.com'
Fetch 'https://amtso.eicar.org/eicar.com' $e3
Wait 40 'Hinweis "Agent beendet" wartet in der Warteschlange des Dienstes'
# K9 refuses a plain stop request since 0.33.0: stop through k9.
Run $k9 dienst stoppen
Wait 10 'Dienst gestoppt'
Run sc.exe start K9-Dienst
# E2: a new driver service right in the service's start-up phase -> must count as new.
$tag = Get-Date -Format HHmmss
$sys = Join-Path $env:SystemRoot "System32\drivers\vs-start-test-$tag.sys"
Copy-Item "$prog\k9.exe" $sys -Force
Run sc.exe create "VsStartTest$tag" type= kernel start= demand binPath= $sys
Rename-Item (Join-Path $inst 'k9-agent.exe.pause') 'k9-agent.exe' -ErrorAction SilentlyContinue
Wait 400 'Agent-Wache startet den Agent (bis 180 s), Nachpruefung nach 60 s, Treiberwache nach 300 s'
Present $e3

Step 'F Aufraeumen der geplanten Aufgaben'
Invoke-Atomic 'T1053.005' 'fec27f65-db86-4c2d-b66c-61945aee87c2' 'Scheduled Task Startup Script' -Cleanup
Wait 420 'Autostart-Meldungen erledigen sich (Pruefung alle 10 Minuten)'

Collect
