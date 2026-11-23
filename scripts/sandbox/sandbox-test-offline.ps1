<#
  Erster Testlauf IN DER WINDOWS-SANDBOX (offline). Nur harmlose Tests, keine Angriffs-Inhalte.
  Laeuft nur im Sandbox-Konto WDAGUtilityAccount; auf dem PC bricht es sofort ab.

  Aufruf in der Sandbox (PowerShell als Administrator):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-offline.ps1

  Tests: 1 Dienst installieren, 2 Echtzeit-Fund mit eigener Testsignatur (kein EICAR),
  3 Ransomware-Verhalten (Zufallsdaten in einem Testordner), 4 Selbstschutz (Agent beenden),
  5 neuer Treiberdienst (nur Registry-Eintrag, wird nie geladen). Dauer etwa 12 Minuten.
  Ergebnisse (nur Text) in C:\Ergebnis.
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount') { Write-Host 'Nur in der Windows-Sandbox ausfuehren.'; exit 1 }
$out = 'C:\Ergebnis'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
# Native programs: output into the transcript (Start-Transcript does not record it otherwise).
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }

Step '1 Dienst installieren'
Run "$prog\k9.exe" dienst installieren
Run $k9 dienst status
Wait 200 'Agent-Wache startet den Agent nach spaetestens 180 s'
Run $k9 status

Step '2 Echtzeit: Datei mit der eigenen Testsignatur in Downloads'
$sig = 'K9-' + 'TESTSIGNATUR-' + 'HARMLOS-2026'
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $dl | Out-Null
[IO.File]::WriteAllText((Join-Path $dl 'sandbox-probe.txt'), "Sandbox $sig Test")
Wait 20 'Echtzeitpruefung'

Step '3 Ransomware-Verhalten: 30 Dateien in Dokumente mit Zufallsdaten ueberschreiben'
$doc = Join-Path $env:USERPROFILE 'Documents\vs-ransomware-test'
New-Item -ItemType Directory -Force $doc | Out-Null
$rnd = New-Object Random
for ($i = 0; $i -lt 30; $i++) { [IO.File]::WriteAllText((Join-Path $doc "dokument$i.txt"), "Text $i") }
Start-Sleep 3
for ($i = 0; $i -lt 30; $i++) { $b = New-Object byte[] 8192; $rnd.NextBytes($b); [IO.File]::WriteAllBytes((Join-Path $doc "dokument$i.txt"), $b) }
Wait 30 'Ransomware-Erkennung'

Step '4 Selbstschutz: Agent hart beenden'
Run taskkill.exe /F /IM k9-agent.exe
Wait 60 'Agent-Wache: Neustart sofort, Hinweis nach 30 s'
Get-Process k9-agent -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table | Out-String | Write-Host

Step '5 Neuer Treiberdienst (harmlose Datei, nur eingetragen, nie gestartet)'
# A new name per run: the service remembers drivers it has seen before.
$tag = Get-Date -Format HHmmss
$sys = Join-Path $env:SystemRoot "System32\drivers\vs-sandbox-test-$tag.sys"
Copy-Item "$prog\k9.exe" $sys -Force
Run sc.exe create "VsSandboxTest$tag" type= kernel start= demand binPath= $sys
Wait 420 'Treiberwache: 5 Minuten Startpause, dann jede Minute'

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
& $k9 status *> (Join-Path $out 'status.txt')
& $k9 dienst status *> (Join-Path $out 'dienst.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ($_.BaseName + '.log')) }
Stop-Transcript | Out-Null
Write-Host "`nFertig. Ergebnisse in C:\Ergebnis. Das Sandbox-Fenster kann jetzt geschlossen werden."
