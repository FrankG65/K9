<#
  Lauf 21 "K9-Update (8e36b67 -> neu), Pause beenden, Ton" IN DER WINDOWS-SANDBOX (offline, frische
  Sandbox, ca. 10 Minuten, ein Klick: "Ja" im Bestaetigungsfenster "K9-Agent pausieren?").
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung:
    K1 Installierte Version (8e36b67, wie auf dem PC) mit Autostart, Funktionen an
    K2 Update auf die neue Version -> keine Uebernahme, Dienststart "Update", kein Fehlalarm, Autostart bleibt
    K3 Testmeldung -> Agent-Protokoll "Ton: SystemAsterisk"
    K4 k9 agent-beenden --minuten 30 (Klick "Ja") -> Agent aus; k9 pause-beenden -> "Pause beendet, Agent laeuft."
       Dienst-Protokoll "Agent-Pause vorzeitig beendet"; zweiter Aufruf -> "Keine Pause aktiv, Agent laeuft bereits."
    K5 Agent danach hart beenden -> Dienst startet ihn neu (Wache wieder aktiv, Pause wirklich beendet)
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$alt = 'C:\Testlabor\alt-k9'
$neu = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll-update-k9.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Start-Sleep -Seconds $s }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
function Check([bool]$ok, [string]$what) { Write-Host ("  [{0}] {1}" -f $(if ($ok) { 'OK' } else { 'FEHLER' }), $what) }
function DienstLog { (Get-Content 'C:\ProgramData\K9\logs\*' -Raw -ErrorAction SilentlyContinue) -join "`n" }
function AgentLog { (Get-Content (Join-Path $env:LOCALAPPDATA 'K9\logs\*') -Raw -ErrorAction SilentlyContinue) -join "`n" }

Step 'K1 Installierte Version wie auf dem PC'
Run "$alt\k9.exe" dienst installieren
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 5 }
Wait 30 'Agent bereit'
Run $k9 autostart-agent an
Run $k9 funktion anhalten an
Run $k9 funktion schattenkopien laufwerke C:
Wait 40 'Dienst uebernimmt'

Step 'K2 Update auf die neue Version'
$ausgabe = & "$neu\k9.exe" dienst aktualisieren 2>&1 | Out-String
Write-Host $ausgabe
Check (-not ($ausgabe -match 'Bisherige Installation')) 'keine Uebernahme (K9 -> K9)'
Check ($ausgabe -match 'Dienst l.+uft') 'Dienst laeuft'
Wait 30 'Agent startet'
Check ([bool](Get-Process k9-agent -ErrorAction SilentlyContinue)) 'Agent laeuft'
Check ((DienstLog) -match 'Dienststart Update') 'Dienststart als Aktualisierung'
$f = & $k9 erkennungen 2>&1 | Out-String
Check (-not ($f -match 'SELBSTSCHUTZ|EINSTELLUNG:SICHERHEIT')) 'kein Fehlalarm'
Check ((& $k9 autostart-agent status 2>&1 | Out-String) -match 'eingeschaltet') 'Autostart bleibt an'
Check ((& $k9 funktion status 2>&1 | Out-String) -match '(?m)^\s*anhalten\s+Kritische Programme anhalten\s+an\s*$') 'Anhalten bleibt an'

Step 'K3 Ton beim Meldefenster'
# Das Beispiel-Fenster zeigt k9.exe selbst; die Protokollzeile kommt mit K9_LOG=info auf stderr.
# Das Fenster wird danach geschlossen (Prozess beendet), es ist kein Klick noetig.
$env:K9_LOG = 'info'
$err = Join-Path $env:TEMP 'k9-ton.txt'
$p = Start-Process -FilePath $k9 -ArgumentList 'test-meldung', 'fenster' -PassThru -RedirectStandardError $err -WindowStyle Hidden
Wait 8 'Fenster erscheint'
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Remove-Item Env:\K9_LOG
$ton = Get-Content $err -Raw -ErrorAction SilentlyContinue
Write-Host "  $ton"
Check ($ton -match 'Ton: SystemAsterisk') 'Protokoll: Ton: SystemAsterisk (Testmeldung)'

Step 'K4 Pausieren und Pause vorzeitig beenden'
Write-Host '  >>> Gleich: "j" wird automatisch eingegeben, danach im Fenster "K9-Agent pausieren?" bitte "Ja".'
'j' | & $k9 agent-beenden --minuten 30 2>&1 | Out-String | Write-Host
Wait 10 'Agent beendet'
Check (-not (Get-Process k9-agent -ErrorAction SilentlyContinue)) 'Agent pausiert (beendet)'
$r = & $k9 pause-beenden 2>&1 | Out-String
Write-Host $r
Check ($r -match 'Pause beendet, Agent laeuft') 'pause-beenden: "Pause beendet, Agent laeuft."'
Check ((DienstLog) -match 'Agent-Pause vorzeitig beendet') 'Dienst-Protokoll: Pause vorzeitig beendet'
$r = & $k9 pause-beenden 2>&1 | Out-String
Check ($r -match 'Keine Pause aktiv, Agent laeuft bereits') 'zweiter Aufruf: keine Pause aktiv'

Step 'K5 Wache wieder aktiv'
Wait 35 'Pause ist im Dienst sicher aufgehoben'
Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Wait 30 'Dienst startet den Agent neu'
Check ([bool](Get-Process k9-agent -ErrorAction SilentlyContinue)) 'Dienst hat den Agent neu gestartet'

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen-update-k9.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-update-k9-' + $_.BaseName + '.log')) }
Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-update-k9-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
