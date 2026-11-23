<#
  Testlauf "Skript aus dem Internet gestartet" IN DER WINDOWS-SANDBOX (offline).
  Nur harmlose Skripte, die ein paar Sekunden warten und sich beenden - keine Schadsoftware,
  kein Netzwerk. Der Internet-Vermerk (Zone.Identifier) wird von Hand angehaengt.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Start: Doppelklick auf scripts\sandbox\k9-test-skriptherkunft.wsb (startet dieses Skript selbst).

  Erwartung (Meldung DOWNLOAD:SKRIPT-GESTARTET, Schwere Hoch):
    T1 rechnung.js   mit Vermerk ueber wscript      -> Meldung
    T2 liste.js      mit Vermerk ueber cscript      -> Meldung
    T3 formular.hta  mit Vermerk ueber mshta        -> Meldung
    T4 einrichten.ps1 mit Vermerk ueber powershell  -> Meldung
    T5 start.bat     mit Vermerk ueber cmd          -> Meldung
    T6 rechnung.js   noch einmal                    -> KEINE zweite Meldung (einmal je Skript)
    T7 eigenes.js    OHNE Vermerk ueber wscript     -> keine Meldung
    T8 Die Download-Adresse steht ohne den Teil nach "?" in der Meldung (kein "geheim").
    T9 kurz.js / kurz.bat mit Vermerk, nur mit dem Dateinamen aus dem Ordner Downloads gestartet -> Meldung (ab 0.21.0)
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis\skriptherkunft'
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
New-Item -ItemType Directory -Force $out | Out-Null
Start-Transcript -Path (Join-Path $out 'protokoll.txt') | Out-Null
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
# Sign of life: a turning wheel with what is running and how long it still takes. Written
# directly to the window (not into the protocol); the window title shows the overall progress.
$script:radBeginn = Get-Date
# A click into a console window selects text and STOPS the script until Esc is pressed
# ("Auswaehlen" in the title): switch this quick edit mode off for this window.
try {
    Add-Type -Namespace K9 -Name Konsole -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int n); [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m); [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);'
    $eingabe = [K9.Konsole]::GetStdHandle(-10)
    $modus = 0
    if ([K9.Konsole]::GetConsoleMode($eingabe, [ref]$modus)) { [void][K9.Konsole]::SetConsoleMode($eingabe, ($modus -band (-bnot 0x40)) -bor 0x80) }
} catch {}
Write-Host "TEST GESTARTET um $(Get-Date -Format HH:mm:ss) Uhr am $(Get-Date -Format dd.MM.yyyy)" -ForegroundColor Cyan
Write-Host 'Ein drehendes Rad zeigt, dass der Test arbeitet. Steht im Fenstertitel "Auswaehlen", haelt ein Mausklick den Test an: Esc druecken.' -ForegroundColor Cyan
function Titel([string]$t) { try { $Host.UI.RawUI.WindowTitle = "K9-Test seit $($script:radBeginn.ToString('HH:mm')) Uhr ($([int]((Get-Date) - $script:radBeginn).TotalMinutes) min) - $t" } catch {} }
function Rad([string]$text, [scriptblock]$fertig, [int]$hoechstens) {
    $z = '|', '/', '-', '\'
    $start = Get-Date
    $i = 0
    while ($true) {
        $vergangen = [int]((Get-Date) - $start).TotalSeconds
        if ($vergangen -ge $hoechstens -or (& $fertig)) { break }
        $rest = $hoechstens - $vergangen
        $zeile = "  $($z[$i % 4]) $text - noch hoechstens $([int][Math]::Floor($rest / 60)):$('{0:00}' -f ($rest % 60)) min  ($(Get-Date -Format HH:mm:ss))"
        try { [Console]::Write("`r" + $zeile.PadRight(110).Substring(0, 110)) } catch {}
        Titel $text
        Start-Sleep -Milliseconds 500
        $i++
    }
    try { [Console]::Write("`r" + (' ' * 110) + "`r") } catch {}
}
# Waits the given seconds with the wheel.
function Warten([int]$sekunden, [string]$text) { Rad $text { $false } $sekunden }
# Starts a program and shows the wheel until it has ended (at most the given seconds).
function Laeuft([string]$text, [int]$hoechstens, [string]$exe, [string]$argumente) {
    $p = Start-Process $exe -ArgumentList $argumente -PassThru -WindowStyle Hidden
    Rad $text { $p.HasExited } $hoechstens
    if (-not $p.HasExited) { Write-Host "  $text dauert laenger als erwartet - es geht trotzdem weiter." }
}
function Wait([int]$s, [string]$why) { Write-Host "  warte $s s ($why)"; Warten $s $why }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host; Write-Host "  (Exitcode $LASTEXITCODE)" }
# Appends the mark Windows sets for files from the internet (zone 3) with a download address.
function Vermerk([string]$path) {
    $name = Split-Path $path -Leaf
    Set-Content -Path $path -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://post.beispiel.example/anhang/$($name)?schluessel=geheim"
}

Step 'A K9 installieren'
Run "$prog\k9.exe" dienst installieren
Rad 'Warte auf den K9-Agenten' { [bool](Get-Process k9-agent -ErrorAction SilentlyContinue) } 300
Wait 30 'ETW-Sitzung des Dienstes'
Run $k9 --version

Step 'B Harmlose Skripte in Downloads anlegen'
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $dl | Out-Null
$js = Join-Path $dl 'rechnung.js'
$js2 = Join-Path $dl 'liste.js'
$hta = Join-Path $dl 'formular.hta'
$ps1 = Join-Path $dl 'einrichten.ps1'
$bat = Join-Path $dl 'start.bat'
$eigen = Join-Path $dl 'eigenes.js'
$kurz = Join-Path $dl 'kurz.js'
$kurzbat = Join-Path $dl 'kurz.bat'
Set-Content $js 'WScript.Sleep(4000);' -Encoding ASCII
Set-Content $js2 'WScript.Sleep(4000);' -Encoding ASCII
Set-Content $eigen 'WScript.Sleep(4000);' -Encoding ASCII
Set-Content $hta '<html><head><title>K9-Test</title><script>setTimeout(function(){window.close();},4000);</script></head><body>K9-Test (schliesst sich selbst)</body></html>' -Encoding ASCII
Set-Content $ps1 'Start-Sleep -Seconds 4' -Encoding ASCII
Set-Content $bat "@echo off`r`nping -n 5 127.0.0.1 > nul" -Encoding ASCII
Set-Content $kurz 'WScript.Sleep(4000);' -Encoding ASCII
Set-Content $kurzbat "@echo off`r`nping -n 5 127.0.0.1 > nul" -Encoding ASCII
foreach ($f in $js, $js2, $hta, $ps1, $bat, $kurz, $kurzbat) { Vermerk $f }
Get-ChildItem $dl | ForEach-Object { Write-Host "  $($_.Name)  Vermerk: $([bool](Get-Item $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue))" }
Wait 15 'Dateipruefung des Agenten'

Step 'T1 rechnung.js ueber wscript'
Start-Process wscript.exe -ArgumentList "`"$js`"" -Wait
Wait 8 'Meldung'
Step 'T2 liste.js ueber cscript'
Start-Process cscript.exe -ArgumentList '//nologo', "`"$js2`"" -Wait -WindowStyle Hidden
Wait 8 'Meldung'
Step 'T3 formular.hta ueber mshta'
$p = Start-Process mshta.exe -ArgumentList "`"$hta`"" -PassThru
Wait 12 'Meldung'
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Step 'T4 einrichten.ps1 ueber powershell'
Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ps1`"" -Wait -WindowStyle Hidden
Wait 8 'Meldung'
Step 'T5 start.bat ueber cmd'
Start-Process cmd.exe -ArgumentList '/c', "`"$bat`"" -Wait -WindowStyle Hidden
Wait 8 'Meldung'
Step 'T6 rechnung.js noch einmal (keine zweite Meldung erwartet)'
Start-Process wscript.exe -ArgumentList "`"$js`"" -Wait
Wait 8 'Meldung'
Step 'T7 eigenes.js ohne Internet-Vermerk (keine Meldung erwartet)'
Start-Process wscript.exe -ArgumentList "`"$eigen`"" -Wait
Wait 15 'Meldung'

Step 'T9 kurz.js und kurz.bat nur mit dem Dateinamen (Arbeitsordner Downloads)'
Start-Process wscript.exe -ArgumentList 'kurz.js' -WorkingDirectory $dl -Wait
Wait 8 'Meldung'
Start-Process cmd.exe -ArgumentList '/c', '.\kurz.bat' -WorkingDirectory $dl -Wait -WindowStyle Hidden
Wait 15 'Meldung'

Step 'Ergebnisse sammeln'
& $k9 erkennungen --alle *> (Join-Path $out 'erkennungen.txt')
& $k9 status *> (Join-Path $out 'status.txt')
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst-' + $_.BaseName + '.log')) }

# Evaluation from the service log (one line per reported script) and the list of findings.
$log = (Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue | Get-Content -ErrorAction SilentlyContinue) -join "`n"
$alles = (Get-Content (Join-Path $out 'erkennungen.txt') -ErrorAction SilentlyContinue) -join "`n"
function Anzahl([string]$name) { ([regex]::Matches($log, [regex]::Escape("Skript aus dem Internet gestartet: $dl\$name"))).Count }
$zeilen = @()
$ok = $true
foreach ($t in @(@('T1', 'rechnung.js', 'wscript'), @('T2', 'liste.js', 'cscript'), @('T3', 'formular.hta', 'mshta'), @('T4', 'einrichten.ps1', 'powershell'), @('T5', 'start.bat', 'cmd'), @('T9', 'kurz.js', 'wscript'), @('T9', 'kurz.bat', 'cmd'))) {
    $n = Anzahl $t[1]
    $gut = $n -ge 1
    if (-not $gut) { $ok = $false }
    $zeilen += ('{0} {1,-15} ueber {2,-10}: {3}' -f $t[0], $t[1], $t[2], $(if ($gut) { 'GEMELDET' } else { 'NICHT gemeldet  <-- FEHLER' }))
}
$n = Anzahl 'rechnung.js'
if ($n -gt 1) { $ok = $false }
$zeilen += ('T6 rechnung.js zweimal gestartet     : {0} Meldung(en) {1}' -f $n, $(if ($n -eq 1) { '- richtig, nur einmal' } else { ' <-- FEHLER (erwartet: 1)' }))
$n = Anzahl 'eigenes.js'
if ($n -ne 0) { $ok = $false }
$zeilen += ('T7 eigenes.js ohne Vermerk           : {0}' -f $(if ($n -eq 0) { 'keine Meldung - richtig' } else { 'GEMELDET  <-- FEHLER' }))
$geheim = ($alles -match 'geheim') -or ($log -match 'schluessel=geheim')
if ($geheim) { $ok = $false }
$zeilen += ('T8 Adresse ohne Zusatz nach "?"      : {0}' -f $(if ($geheim) { '"geheim" steht in der Ausgabe  <-- FEHLER' } else { 'richtig' }))
$zeilen += ''
$zeilen += $(if ($ok) { 'GESAMT: BESTANDEN' } else { 'GESAMT: NICHT BESTANDEN' })
$zeilen | Set-Content (Join-Path $out 'ergebnis.txt') -Encoding UTF8
Stop-Transcript | Out-Null
Write-Host "`nTest gestartet um $($script:radBeginn.ToString('HH:mm:ss')) Uhr, beendet um $(Get-Date -Format HH:mm:ss) Uhr."
Write-Host "`n================ ERGEBNIS ================" -ForegroundColor Cyan
$zeilen | ForEach-Object { Write-Host $_ }
Write-Host "`nFertig. Ergebnisse liegen auf dem PC in Dokumente\Virenscanner-Sandbox-Ergebnis\skriptherkunft."
Write-Host 'Die Sandbox kannst du jetzt schliessen.'
