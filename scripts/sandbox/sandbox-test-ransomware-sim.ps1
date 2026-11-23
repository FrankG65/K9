<#
  Wie schnell ist K9 bei Ransomware? Messung IN DER WINDOWS-SANDBOX (offline) mit dem harmlosen
  Testprogramm k9-testsim.exe - keine Schadsoftware, kein Netzwerk. Das Testprogramm ueberschreibt
  Schein-Dateien in einem markierten Testordner so schnell wie Ransomware und tut sonst nichts.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Start: Doppelklick auf scripts\sandbox\k9-test-ransomware-sim.wsb (startet dieses Skript selbst).

  Sechs Durchgaenge (R4 wiederholt R2; in R5 wird der K9-Agent unmittelbar vorher beendet - dann muss
  die Erkennung des Dienstes greifen; R6: ein Programm, das K9 kennt, wird schon beim Start angehalten;
  R7: harmloses Entpacken darf keinen Alarm ausloesen; R8: Ransomware, die Kopien schreibt und Originale loescht), je 400 Schein-Dokumente, 40 Dateien pro Sekunde (10 Sekunden bis zum Ende):
    R1 Ransomware-Anhalten AUS                         -> Alarm, aber alle Dateien ueberschrieben
    R2 Ransomware-Anhalten AN                          -> Alarm, Testprogramm eingefroren, die meisten Dateien heil
    R3 Ransomware-Anhalten AN, mit "vssadmin delete"   -> schon beim Loeschversuch der Wiederherstellung eingefroren
    R10 Programm aus dem Internet, Agent wird 2 s nach dem Start von aussen beendet (Muster Conti)
                                                       -> Angriffskette "K9-Agent von aussen beendet", eingefroren, keine Datei verloren
    R11 wie R10, aber "sc stop K9-Dienst"              -> Stopp abgelehnt, Angriffskette, eingefroren, keine Datei verloren
    R12 wie R10, aber K9-Dienst gewaltsam beendet      -> Dienst nach 1 s wieder da, Angriffskette, eingefroren
    R13 wie R10, aber ohne Internet-Kennzeichnung      -> Angriffskette "(neu im Benutzerordner)", eingefroren
    R14 wie R12, aber ohne Internet-Kennzeichnung      -> ebenso
    R15 Wiederherstellung ueber cmd.exe geloescht, 6 s spaeter die Dateien (Muster Babuk)
                                                       -> beim Loeschversuch eingefroren, keine Datei verloren
    R16 neues unsigniertes Programm legt sofort los    -> nach 2 statt 12 verschluesselten Dateien eingefroren
    R17 wie R16, ohne Internet-Kennzeichnung           -> ebenso
    R18 wie R16, sperrt zuerst eine Koederdatei        -> genauso schnell eingefroren (kein Warten auf die Koederdatei)
    R19 Schalter neue-programme an, sonst wie R16      -> beim Start eingefroren, (fast) keine Datei verloren
    R20 wie R19 mit 200 Dateien je Sekunde             -> ebenso
    R21 Freigabe eines beim Start angehaltenen Programms -> laeuft weiter; zweiter Start ohne Anhalten
  Gemessen: wie viele Dateien unveraendert bleiben, ob das Testprogramm angehalten wurde, was K9 meldet.
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis\ransomware-sim'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
New-Item -ItemType Directory -Force $out | Out-Null
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
# A click into the window must not stop the script (quick edit mode off).
try {
    Add-Type -Namespace K9 -Name Konsole -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int n); [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m); [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);'
    $eingabe = [K9.Konsole]::GetStdHandle(-10)
    $modus = 0
    if ([K9.Konsole]::GetConsoleMode($eingabe, [ref]$modus)) { [void][K9.Konsole]::SetConsoleMode($eingabe, ($modus -band (-bnot 0x40)) -bor 0x80) }
} catch {}
$beginn = Get-Date
Write-Host "TEST GESTARTET um $(Get-Date -Format HH:mm:ss) Uhr am $(Get-Date -Format dd.MM.yyyy)" -ForegroundColor Cyan
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Warten([int]$sekunden, [string]$text) {
    $z = '|', '/', '-', '\'
    for ($i = 0; $i -lt $sekunden * 2; $i++) {
        try { [Console]::Write("`r  $($z[$i % 4]) $text - noch $([int](($sekunden * 2 - $i) / 2)) s   ") } catch {}
        try { $Host.UI.RawUI.WindowTitle = "K9-Test seit $($beginn.ToString('HH:mm')) Uhr - $text" } catch {}
        Start-Sleep -Milliseconds 500
    }
    try { [Console]::Write("`r" + (' ' * 100) + "`r") } catch {}
}
# Whole lines of the findings list: the same rule fires in every run, the number in front differs.
function Funde { try { @((& $k9 erkennungen --alle 2>$null) | Where-Object { $_ -match '\|' }) } catch { @() } }

Step 'A K9 installieren'
& "$prog\k9.exe" dienst installieren 2>&1 | Out-String | Write-Host
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
& $k9 --version
$toml = Join-Path $env:APPDATA 'K9\config.toml'
for ($i = 0; $i -lt 30 -and -not (Test-Path $toml); $i++) { Start-Sleep 2 }
Warten 40 'K9 startet seine Ueberwachung'

# Switches the freeze and lets service and agent take it over.
function Anhalten([string]$wert) {
    & $k9 funktion ransomware-anhalten $wert 2>&1 | Out-String | Write-Host
    if ($wert -eq 'aus') {
        # Switching off is a weakening that needs a confirmation window: for the test the value
        # is "aus" from the start (default), so this branch only documents the state.
    }
    Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 3
    for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
    Warten 45 "Ransomware-Anhalten $wert - Dienst und Agent uebernehmen die Einstellung"
    Write-Host "  config.toml: $((Select-String -Path $toml -Pattern '^ransomware_prozess_anhalten' | Select-Object -First 1).Line)"
}

# R21 (since 0.44.0): does a frozen program really run on after "Freigabe"? Until 0.37.1 one
# release took back only one of several freezes. The switch "neue-programme" is on here: the
# program is frozen at its start; then the message is decided with "k9 entscheiden <Nr> freigabe"
# (the same code path as the button in the message window). Proof that it runs on: it starts
# overwriting its test files (and is then caught by the ransomware protection, as it should be).
# A second start of the same file must not be frozen at the start again (decision remembered).
function FreigabeTest {
    Step 'R21 Freigabe: angehaltenes Programm laeuft nach der Freigabe weiter'
    $dir = Join-Path $env:USERPROFILE 'Documents\K9-Test-Freigabe'
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-Content (Join-Path $dir 'K9-TESTORDNER.txt') 'K9-Testordner: Dateien hier duerfen vom Testprogramm ueberschrieben werden' -Encoding ASCII
    $text = ('Rechnung Nr. 2026-1147 an Max Mustermann, Musterstrasse 1, 12345 Musterstadt. Betrag 119,00 EUR. ' * 200)
    1..400 | ForEach-Object { Set-Content -LiteralPath (Join-Path $dir ('Rechnung{0:000}.docx' -f $_)) $text -Encoding ASCII }
    Warten 25 'K9 prueft die neuen Schein-Dokumente'
    $sim = Join-Path $env:USERPROFILE 'Downloads\freigabe-test.exe'
    Copy-Item "$prog\k9-testsim.exe" $sim -Force
    Set-Content -LiteralPath $sim -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://beispiel.invalid/freigabe-test.exe" -Encoding ASCII
    $heil = { @(Get-ChildItem -LiteralPath $dir -Filter '*.docx' -File).Count }
    $vorher = @(Funde)
    $p = Start-Process $sim -ArgumentList "`"$dir`"", '--pro-sekunde', '20' -PassThru -WindowStyle Hidden
    Start-Sleep 8
    $heil1 = & $heil
    $steht = -not $p.HasExited
    $zeile = @(Funde | Where-Object { $vorher -notcontains $_ -and $_ -match 'DOWNLOAD:ANGEHALTEN' }) | Select-Object -First 1
    $nr = if ($zeile) { (($zeile -split '\|')[0] -replace '[^0-9]', '') } else { '' }
    Write-Host "  nach 8 s: $heil1 von 400 heil, Programm steht: $steht, Meldung: $zeile"
    # A release is confirmed by the user in a window of the service (so that malware cannot
    # release itself) - this part needs a person in front of the sandbox. Seen on 22.11.2026:
    # without a click "k9 entscheiden <Nr> freigabe" ends with "Nicht bestaetigt".
    Write-Host ''
    Write-Host '  >>> JETZT BIST DU DRAN (hoechstens 5 Minuten):' -ForegroundColor Green
    Write-Host '  >>> K9 zeigt immer nur EIN Meldefenster. Zeigt es zuerst eine andere Meldung (z. B. "Der K9-Agent wurde' -ForegroundColor Green
    Write-Host '  >>> unerwartet beendet" - das kommt vom Testskript): dort "Spaeter" waehlen, dann kommt die naechste Meldung.' -ForegroundColor Green
    Write-Host '  >>> Im Meldefenster von K9 zur Meldung "Neues unsigniertes Programm aus dem Internet angehalten: freigabe-test.exe"' -ForegroundColor Green
    Write-Host '  >>> die Schaltflaeche "Freigabe (genau diese Programmdatei)" waehlen und das kleine Bestaetigungsfenster mit "Ja" beantworten.' -ForegroundColor Green
    Write-Host '  >>> Kommen mehrere Meldungen: nur diese eine freigeben, die anderen mit "Spaeter" liegen lassen.' -ForegroundColor Green
    $heil2 = $heil1
    for ($w = 0; $w -lt 300; $w++) {
        Start-Sleep 1
        $heil2 = & $heil
        if ($heil2 -lt $heil1) { break }
    }
    Write-Host "  $w s nach der Aufforderung: $heil2 von 400 heil, Programm beendet: $($p.HasExited)"
    Start-Sleep 6
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep 3
    # Second start of the same file: remembered, no freeze at the start.
    $vorher2 = @(Funde)
    $p2 = Start-Process $sim -ArgumentList "`"$dir`"", '--pro-sekunde', '20' -PassThru -WindowStyle Hidden
    Start-Sleep 8
    $neu2 = @(Funde | Where-Object { $vorher2 -notcontains $_ } | ForEach-Object { ($_ -split '\|')[1].Trim() } | Select-Object -Unique)
    $heil3 = & $heil
    if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
    $lief = ($heil1 -eq 400) -and $steht -and ($heil2 -lt $heil1)
    $zeile = "R21 Freigabe | vor der Freigabe: $heil1 von 400 heil, Programm steht: $steht | nach der Freigabe: $heil2 von 400 heil -> $(if ($lief) { 'LAEUFT WEITER (bestanden)' } else { 'NICHT BESTANDEN' }) | zweiter Start: $heil3 von 400 heil, neue Meldungen: $(if ($neu2.Count) { $neu2 -join '; ' } else { 'keine' }) -> $(if ($neu2 -notcontains 'DOWNLOAD:ANGEHALTEN') { 'nicht erneut beim Start angehalten (bestanden)' } else { 'ERNEUT ANGEHALTEN (nicht bestanden)' })"
    Write-Host "  $zeile" -ForegroundColor Yellow
    $script:ergebnis += $zeile
}

$ergebnis = @()
function Durchgang([string]$name, [string]$zusatz, [bool]$bekannt = $false) {
    Step $name
    # Every run needs the service: a run before may have ended it (seen on 21.11.2026, when a
    # stop request that should have been refused ended the service and the next run had none).
    if ((Get-Service 'K9-Dienst' -ErrorAction SilentlyContinue).Status -ne 'Running') {
        Write-Host "  ACHTUNG: K9-Dienst lief vor diesem Durchgang nicht - wird gestartet" -ForegroundColor Red
        $script:ergebnis += "    ACHTUNG: K9-Dienst lief vor '$name' nicht und wurde gestartet"
        & sc.exe start 'K9-Dienst' | Out-Null
        Warten 40 'Dienst und Agent starten'
    }
    $dir = Join-Path $env:USERPROFILE "Documents\K9-Test-$($script:nr)"
    $script:nr++
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-Content (Join-Path $dir 'K9-TESTORDNER.txt') 'K9-Testordner: Dateien hier duerfen vom Testprogramm ueberschrieben werden' -Encoding ASCII
    $text = ('Rechnung Nr. 2026-1147 an Max Mustermann, Musterstrasse 1, 12345 Musterstadt. Betrag 119,00 EUR. ' * 200)
    1..400 | ForEach-Object { Set-Content -LiteralPath (Join-Path $dir ('Rechnung{0:000}.docx' -f $_)) $text -Encoding ASCII }
    Warten 25 'K9 prueft die neuen Schein-Dokumente'
    $sim = Join-Path $env:USERPROFILE "Downloads\unbekannt$($script:nr).exe"
    Copy-Item "$prog\k9-testsim.exe" $sim -Force
    if ($script:ausInternet) {
        # The mark Windows gives to a downloaded file ("from the internet"): K9 then follows the
        # program and what it starts as a possible attack chain.
        Set-Content -LiteralPath $sim -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://beispiel.invalid/unbekannt.exe" -Encoding ASCII
    }
    if ($bekannt) {
        # A copy that K9 knows: K9's own harmless test signature is appended to the program file
        # (put together here from parts, so that this script itself is not a finding).
        $marke = 'K9-' + 'TESTSIGNATUR-' + 'HARMLOS-' + '2026'
        $fs = [IO.File]::Open($sim, 'Append'); $bytes = [Text.Encoding]::ASCII.GetBytes($marke); $fs.Write($bytes, 0, $bytes.Length); $fs.Close()
        Warten 12 'K9 prueft die neue Programmdatei'
    }
    $vorher = @(Funde)
    $argumente = @("`"$dir`"", '--pro-sekunde', '40') + $(if ($zusatz) { @($zusatz -split ' ') } else { @() })
    if ($script:agentWeg) { Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force; Write-Host "  Agent beendet: $(-not (Get-Process k9-agent -ErrorAction SilentlyContinue))" }
    $p = Start-Process $sim -ArgumentList $argumente -PassThru -WindowStyle Hidden
    $start = Get-Date
    if ($script:agentNachStart -gt 0) {
        Start-Sleep -Seconds $script:agentNachStart
        if ($script:angriff -eq 'dienst-stopp') {
            # The ordinary way through Windows, as "net stop" or the Restart Manager do it.
            $aus = (& sc.exe stop 'K9-Dienst' 2>&1 | Out-String).Trim() -replace '\s+', ' '
            Write-Host "  sc stop K9-Dienst $($script:agentNachStart) s nach dem Start: Exitcode $LASTEXITCODE - $aus"
            Start-Sleep 1
            Write-Host "  Dienst danach: $((Get-Service 'K9-Dienst').Status)"
        } elseif ($script:angriff -eq 'dienst-gewalt') {
            $alt = (Get-Process k9-dienst -ErrorAction SilentlyContinue | Select-Object -First 1).Id
            Get-Process k9-dienst -ErrorAction SilentlyContinue | Stop-Process -Force
            Write-Host "  K9-Dienst (PID $alt) $($script:agentNachStart) s nach dem Start gewaltsam beendet"
            for ($w = 0; $w -lt 20; $w++) {
                Start-Sleep -Milliseconds 250
                $neuPid = (Get-Process k9-dienst -ErrorAction SilentlyContinue | Select-Object -First 1).Id
                if ($neuPid -and $neuPid -ne $alt) { Write-Host "  Dienst laeuft wieder (PID $neuPid) nach $([Math]::Round(((Get-Date) - $start).TotalSeconds - $script:agentNachStart, 1)) s"; break }
            }
        } else {
            Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
            Write-Host "  K9-Agent $($script:agentNachStart) s nach dem Start des Testprogramms von aussen beendet"
        }
    }
    $verlauf = @()
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        $heil = @(Get-ChildItem -LiteralPath $dir -Filter '*.docx' -File).Count
        $verlauf += "$([Math]::Round(((Get-Date) - $start).TotalSeconds, 1))s:$heil"
    }
    $heil = @(Get-ChildItem -LiteralPath $dir -Filter '*.docx' -File).Count
    $lebt = -not $p.HasExited
    # A frozen program does not finish: it is still there although its 10 seconds are long over.
    $neu = @(Funde | Where-Object { $vorher -notcontains $_ } | ForEach-Object { ($_ -split '\|')[1].Trim() } | Select-Object -Unique)
    if ($lebt) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    $zeile = "$name | unveraendert: $heil von 400 | Testprogramm nach 20 s: $(if ($lebt) { 'ANGEHALTEN (lief nicht zu Ende)' } else { 'zu Ende gelaufen' }) | K9: $(if ($neu.Count) { $neu -join '; ' } else { 'keine Meldung' })"
    Write-Host "  $zeile" -ForegroundColor Yellow
    Write-Host "  Verlauf (Sekunden:heile Dateien): $($verlauf -join ' ')"
    $script:ergebnis += $zeile
    $script:ergebnis += "    Verlauf: $($verlauf -join ' ')"
    Warten 25 'Pause vor dem naechsten Durchgang'
}
$script:nr = 1
$script:agentWeg = $false
$script:ausInternet = $false
$script:agentNachStart = 0
$script:angriff = 'agent'

# Short run for development (file ransomware-sim-kurz.txt next to this script): only the runs
# with the freeze on, without the comparison run and without vssadmin.
$kurz = Test-Path 'C:\Testlabor\ransomware-sim-kurz.txt'
# Only the run R10 (file ransomware-sim-nur-r10.txt next to this script): the defence against
# malware that ends the K9 agent first.
$nurR10 = Test-Path 'C:\Testlabor\ransomware-sim-nur-r10.txt'
function R10 {
    # As Conti did on 21.11.2026: the program comes from the internet, the K9 agent is ended from
    # outside while it runs, a few seconds later the files are overwritten. Since 0.32.0 the
    # service takes the end of the agent as a critical step of the attack chain and freezes the
    # program (with "Kritische Programme anhalten") before it starts: no file may be lost.
    $script:ausInternet = $true
    $script:agentNachStart = 2
    Durchgang 'R10 Programm aus dem Internet, Agent 2 s nach dem Start von aussen beendet, wartet 6 s' '--warten 6'
    # Since 0.33.0: the attack goes at the service itself.
    # R11: a stop request through Windows - the service refuses it and freezes the program.
    $script:angriff = 'dienst-stopp'
    Durchgang 'R11 Programm aus dem Internet, 2 s nach dem Start "sc stop K9-Dienst", wartet 6 s' '--warten 6'
    # R12: the service is ended by force - Windows starts it again after a second, and the
    # service then freezes what is running from the internet.
    $script:angriff = 'dienst-gewalt'
    Durchgang 'R12 Programm aus dem Internet, 2 s nach dem Start K9-Dienst gewaltsam beendet, wartet 6 s' '--warten 6'
    $script:angriff = 'agent'
    # Since 0.34.0: the same without the mark "from the internet" - the program file is new and
    # lies in the user's Downloads folder, as if unpacked from an archive.
    $script:ausInternet = $false
    Durchgang 'R13 Programm OHNE Internet-Kennzeichnung (neu im Benutzerordner), Agent 2 s nach dem Start beendet, wartet 6 s' '--warten 6'
    $script:angriff = 'dienst-gewalt'
    Durchgang 'R14 Programm OHNE Internet-Kennzeichnung, 2 s nach dem Start K9-Dienst gewaltsam beendet, wartet 6 s' '--warten 6'
    $script:angriff = 'agent'
    $script:agentNachStart = 0
    # Since 0.36.0: the pattern of Babuk (test of 21.11.2026) - the program has a short-lived
    # cmd.exe delete the recovery data and starts on the files six seconds later. K9 itself is
    # left alone. Expected: frozen at the deletion, no file lost.
    $script:ausInternet = $true
    Durchgang 'R15 Programm aus dem Internet, loescht ueber cmd.exe die Wiederherstellung, 6 s spaeter die Dateien' '--wiederherstellung-cmd --pause 6'
    # Since 0.37.0: the pattern of BlackBasta - the program starts on the files at once and
    # leaves everything else alone. A new unsigned program is frozen after two files that look
    # encrypted instead of twelve. Measured before (R2, 40 files a second): 12 of 400 lost.
    Durchgang 'R16 Programm aus dem Internet, legt sofort los (40 Dateien je Sekunde)' ''
    $script:ausInternet = $false
    Durchgang 'R17 Programm OHNE Internet-Kennzeichnung (neu im Benutzerordner), legt sofort los' ''
    # Since 0.37.1: the program hits one of K9's canary files first and keeps it locked for
    # 0.8 seconds while it is already overwriting the files (BlackBasta, 22.11.2026). With
    # 0.37.0 K9's file watch waited for the locked canary and checked nothing else meanwhile.
    # Expected: frozen as fast as in R16.
    $script:ausInternet = $true
    $koeder = Join-Path $env:USERPROFILE 'Documents\!vs-koeder-nicht-loeschen.docx'
    Durchgang 'R18 Programm aus dem Internet, sperrt zuerst eine Koederdatei (0,8 s) und legt sofort los' "--koeder `"$koeder`" --sperren-ms 800"
    # Since 0.39.0: the switch "neue-programme" - an unsigned program from the internet is
    # frozen at its first start, before it touches a file. The agent reads the switch at its
    # start. Compare with R16 (the same program without the switch).
    & $k9 funktion neue-programme an 2>&1 | Out-String | Write-Host
    Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 3
    for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
    Warten 45 'Schalter neue-programme an - der Agent uebernimmt die Einstellung'
    Durchgang 'R19 Schalter neue-programme AN: Programm aus dem Internet, legt sofort los' ''
    Durchgang 'R20 Schalter neue-programme AN: dasselbe mit 200 Dateien je Sekunde' '--pro-sekunde 200'
    $script:ausInternet = $false
}
# Only the release test (file ransomware-sim-nur-freigabe.txt next to this script): needs a
# person who clicks in the sandbox, about five minutes.
if (Test-Path 'C:\Testlabor\ransomware-sim-nur-freigabe.txt') {
    Anhalten 'an'
    & $k9 funktion anhalten an 2>&1 | Out-String | Write-Host
    & $k9 funktion neue-programme an 2>&1 | Out-String | Write-Host
    Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 3
    for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
    Warten 45 'Schalter an - Dienst und Agent uebernehmen die Einstellung'
    FreigabeTest
} elseif ($nurR10) {
    Anhalten 'an'
    & $k9 funktion anhalten an 2>&1 | Out-String | Write-Host
    Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 3
    for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
    Warten 45 'Kritische Programme anhalten an - Dienst und Agent uebernehmen die Einstellung'
    R10
} else {
if (-not $kurz) { Durchgang 'R1 Anhalten AUS, nur ueberschreiben' '' }
Anhalten 'an'
Durchgang 'R2 Anhalten AN, nur ueberschreiben' ''
if (-not $kurz) { Durchgang 'R3 Anhalten AN, mit vssadmin delete shadows' '--wiederherstellung' }
Durchgang 'R4 Anhalten AN, nur ueberschreiben (Wiederholung von R2)' ''
# R5: malware that ends the agent before it encrypts (as Conti presumably does). The service
# starts the agent again only after some seconds - the detection has to come from the service.
$script:agentWeg = $true
Durchgang 'R5 Anhalten AN, Agent unmittelbar vorher beendet' ''
$script:agentWeg = $false
# R6: a program K9 knows (test signature) that waits 8 seconds before it starts, as real ransomware
# does (measured: 5 to 74 seconds). With "anhalten" on it is frozen at its start: no file is lost.
& $k9 funktion anhalten an 2>&1 | Out-String | Write-Host
Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
Warten 45 'Kritische Programme anhalten an - Agent uebernimmt die Einstellung'
Durchgang 'R6 bekanntes Programm (Testsignatur), wartet 8 s vor dem Ueberschreiben' '--warten 8' $true
# R7: harmless look-alike - an unsigned program creates 300 NEW packed files, as when an archive
# is unpacked. Nothing that existed is touched: no alarm, nothing frozen.
Durchgang 'R7 HARMLOS: 300 neue gepackte Dateien (wie Entpacken) - kein Alarm erwartet' '--entpacken 300'
# R8: ransomware that writes an encrypted copy and deletes the original.
Durchgang 'R8 Anhalten AN, verschluesselte Kopie schreiben und Original loeschen' '--kopieren'
# R9: a program K9 knows that starts overwriting at once (no waiting): how many files are lost
# until it is frozen at its start?
Durchgang 'R9 bekanntes Programm (Testsignatur), legt sofort los' '' $true
R10
}

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }
Get-ChildItem (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('agent-' + $_.BaseName + '.log')) }
# Who raised the alarms: the service names the program, the agent stays silent then.
$ergebnis += ''
$ergebnis += 'Alarme laut Protokoll (Dienst und Agent):'
$ergebnis += @(Get-ChildItem 'C:\ProgramData\K9\logs', (Join-Path $env:LOCALAPPDATA 'K9\logs') -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName -ErrorAction SilentlyContinue } | Where-Object { $_ -match 'RANSOMWARE-VERDACHT|angehalten bis zur Entscheidung|Dienst hat bereits gemeldet|Ransomware-Wache: [0-9]+ Benutzer|Bekannte Schadsoftware gestartet' } | ForEach-Object { '  ' + $_ })
$ergebnis | Set-Content (Join-Path $out 'ergebnis.txt') -Encoding UTF8
Stop-Transcript | Out-Null
Write-Host "`n================ ERGEBNIS ================" -ForegroundColor Cyan
$ergebnis | ForEach-Object { Write-Host $_ }
Write-Host "`nTest gestartet um $($beginn.ToString('HH:mm:ss')) Uhr, beendet um $(Get-Date -Format HH:mm:ss) Uhr."
Write-Host 'Fertig. Ergebnisse liegen auf dem PC in Dokumente\Virenscanner-Sandbox-Ergebnis\ransomware-sim. Die Sandbox schliesst sich in 60 Sekunden.'
& shutdown.exe /s /f /t 60
