# End-to-End-Test von K9 (Schritt 1)
#
# Läuft komplett in einem temporären Ordner (K9_HOME), nutzt die
# harmlose eigene Testsignatur (kein EICAR), startet den Agent nur für die
# Dauer des Tests und räumt danach alles wieder auf.
#
# Aufruf:  powershell -ExecutionPolicy Bypass -File scripts\e2e-test.ps1 [-Profil release|debug]

param([string]$Profil = "release")

$ErrorActionPreference = "Stop"
# k9 schreibt UTF-8; so kommen Umlaute beim Auswerten korrekt an.
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "target\$Profil"
$k9 = Join-Path $bin "k9.exe"
$agentExe = Join-Path $bin "k9-agent.exe"
if (-not (Test-Path $k9) -or -not (Test-Path $agentExe)) { throw "Bitte zuerst bauen: cargo build --$Profil" }

$port = 47199
$suffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
# Testordner im Projekt (target\e2e), nicht in %TEMP%: ein laufender Agent ueberwacht %TEMP%
# in Echtzeit und wuerde sonst die Testdateien melden.
$e2eRoot = Join-Path $root "target\e2e"
New-Item -ItemType Directory -Force $e2eRoot | Out-Null
$home_ = Join-Path $e2eRoot "vs-e2e-$suffix"
# Der Datenordner wird nie gescannt, daher liegt der Scanordner daneben.
$scanDir = Join-Path $e2eRoot "vs-e2e-scan-$suffix"
New-Item -ItemType Directory -Force $home_ | Out-Null
New-Item -ItemType Directory -Force $scanDir | Out-Null
# Echtzeit-Testordner (nur dieser wird vom Echtzeitschutz überwacht)
$rtDir = Join-Path $e2eRoot "vs-e2e-echtzeit-$suffix"
New-Item -ItemType Directory -Force $rtDir | Out-Null
$env:K9_HOME = $home_
# Der Test prüft die deutschen Texte, auch auf einem Windows in anderer Sprache.
$env:K9_SPRACHE = "de"
# Nie echte Benutzerdaten: Profile (Browser, Steam, Discord, Verknuepfungen) und TEMP zeigen
# fuer Agent und k9 auf leere Testordner. Ein echter Dienst sieht so keine Zugriffe auf
# echte Zugangsdaten, und clamd legt seine Temp-Dateien nicht in deinem TEMP ab.
$profil = Join-Path $e2eRoot "vs-e2e-profil-$suffix"
$alteUmgebung = @{}
foreach ($v in 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'TEMP', 'TMP') {
    $alteUmgebung[$v] = [Environment]::GetEnvironmentVariable($v)
    $ordner = Join-Path $profil $v
    New-Item -ItemType Directory -Force $ordner | Out-Null
    [Environment]::SetEnvironmentVariable($v, $ordner)
}

# Eigene Testkonfiguration: nur Dashboard-Kanal, kein Gaming-Modus, keine Zeitpläne.
@"
zeitplan = []
[meldungen]
kanaele = ["dashboard"]
[gaming]
aktiv = false
[dashboard]
port = $port
[quellen]
# Eigener clamd-Port: nie den clamd des installierten K9 benutzen – der legt seine
# Temp-Dateien (mit den Testmustern) im echten TEMP ab, und der Echtzeitschutz meldet sie.
clamav_port = 3399
[echtzeit]
ordner = ['$rtDir']
prozesse = false
autostart = false
netzwerk = false
usb = false
ransomware = true
"@ | Out-File -Encoding utf8 (Join-Path $home_ "config.toml")

# Testsignatur zusammengesetzt, damit dieses Skript selbst sie nicht enthält.
$signatur = "K9-" + "TESTSIGNATUR-" + "HARMLOS-2026"
$hashInhalt = "K9-" + "HASHTEST-" + "HARMLOS-2026"

$script:ok = 0; $script:fail = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { $script:ok++; Write-Host "  [OK]     $msg" -ForegroundColor Green }
    else {
        $script:fail++; Write-Host "  [FEHLER] $msg" -ForegroundColor Red
        # Failing checks are also kept in a file (to find tests that fail only sometimes).
        $log = Join-Path $PSScriptRoot '..\target\e2e-fehler.log'
        Add-Content -Path $log -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}
# k9 ueber cmd.exe aufrufen (in dieser Umgebung wird der direkte Aufruf
# frisch gebauter Programme per "&" manchmal mit "Zugriff verweigert" abgelehnt).
function K9 { $a = ($args | ForEach-Object { "`"$_`"" }) -join ' '; cmd /c "`"$k9`" $a" | Out-String }
function Scan { K9 scan $scanDir }
function NewCount([string]$out) { if ($out -match "Neue Erkennungen: (\d+)") { [int]$Matches[1] } else { -1 } }
function Api { Invoke-RestMethod -UseBasicParsing "http://127.0.0.1:$port/api/status?t=$token" }
function Post([string]$path, [hashtable]$body) {
    $body.t = $token
    Invoke-WebRequest -UseBasicParsing -Method Post -Body $body "http://127.0.0.1:$port$path" | Out-Null
}
function WriteFile([string]$name, [string]$content) {
    $p = Join-Path $scanDir $name
    [IO.File]::WriteAllBytes($p, [Text.Encoding]::ASCII.GetBytes($content))
    $p
}
function RawStatus([string]$hostHeader) {
    $c = New-Object Net.Sockets.TcpClient("127.0.0.1", $port)
    $s = $c.GetStream()
    $req = [Text.Encoding]::ASCII.GetBytes("GET /api/status?t=$token HTTP/1.1`r`nHost: $hostHeader`r`nConnection: close`r`n`r`n")
    $s.Write($req, 0, $req.Length)
    $r = New-Object IO.StreamReader($s)
    $line = $r.ReadLine()
    # Bei einem Fehler auch den Text der Antwort zeigen (steht hinter der Leerzeile).
    if ($line -notmatch ' (200|401|403) ') { $rest = $r.ReadToEnd(); $line = "$line | " + (($rest -split "`r`n`r`n", 2)[-1] -replace '\s+', ' ') }
    $c.Close()
    $line
}

$agent = $null
try {
    Write-Host "Testordner: $home_"
    # Direkt per CreateProcess starten (ShellExecute wird bei frisch gebauten,
    # unsignierten Programmen manchmal mit "Zugriff verweigert" abgelehnt).
    # Programme hier nur über Diagnostics.Process starten: Webabfragen plus das
    # Start-Cmdlet im selben Skript meldet die PowerShell-Skriptprüfung als
    # "lädt Code aus dem Internet" – der Test darf keine Funde beim Nutzer erzeugen.
    $before = Get-Date
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo $agentExe, "--ohne-zeitplan"
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $agent = [Diagnostics.Process]::Start($psi)
    } catch {
        # Fallback über cmd.exe (manche Umgebungen erlauben nur das).
        $psi = New-Object Diagnostics.ProcessStartInfo "$env:SystemRoot\System32\cmd.exe", "/c `"`"$agentExe`" --ohne-zeitplan`""
        $psi.UseShellExecute = $true
        $psi.WindowStyle = 'Hidden'
        [Diagnostics.Process]::Start($psi) | Out-Null
        Start-Sleep -Seconds 2
        $agent = Get-Process k9-agent -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $agentExe -and $_.StartTime -ge $before } | Select-Object -First 1
    }
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try { $t = New-Object Net.Sockets.TcpClient("127.0.0.1", $port); $t.Close(); break } catch { Start-Sleep -Milliseconds 300 }
    }
    $token = (Get-Content (Join-Path $home_ "dashboard-token.txt") -Raw).Trim()
    Check ($token.Length -eq 64) "Agent gestartet, Dashboard-Token vorhanden"

    Write-Host "`n1) Sicherheit des Dashboards"
    $denied = $false
    try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/?t=falsch" | Out-Null } catch { $denied = $_.Exception.Response.StatusCode.value__ -eq 401 }
    Check $denied "Falscher Token wird abgewiesen (401)"
    Check ((RawStatus "evil.example:$port") -match " 403 ") "Fremder Host-Header wird abgewiesen (403, DNS-Rebinding-Schutz)"
    $antwort = RawStatus "127.0.0.1:$port"
    Check ($antwort -match " 200 ") "Korrekter Host + Token wird akzeptiert$(if ($antwort -notmatch ' 200 ') { " (Antwort: $antwort)" })"
    $postUrl = "http://127.0.0.1:$port/test"
    $body = @{ t = $token; kanal = "dashboard" }
    $evil = $false
    try { Invoke-WebRequest -UseBasicParsing -Method Post -Body $body -Headers @{ Origin = "http://evil.example"; "Sec-Fetch-Site" = "cross-site" } $postUrl | Out-Null } catch { $evil = $_.Exception.Response.StatusCode.value__ -eq 403 }
    Check $evil "POST von fremder Seite wird abgewiesen (403)"
    $own = Invoke-WebRequest -UseBasicParsing -Method Post -Body $body -Headers @{ Origin = "http://127.0.0.1:$port"; "Sec-Fetch-Site" = "same-origin" } $postUrl
    Check ($own.StatusCode -eq 200) "POST aus dem eigenen Dashboard (wie im Browser) wird akzeptiert"
    $startPage = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/?t=$token"
    Check ($startPage.Headers["Referrer-Policy"] -eq "same-origin") "Referrer-Policy same-origin (Browser sendet echte Origin)"

    Write-Host "`n2) Erkennung -> Meldung im Dashboard -> Freigabe -> keine neue Meldung"
    $f1 = WriteFile "freigabe-test.txt" "Hallo $signatur Welt"
    $out = Scan
    Check ((NewCount $out) -eq 1) "Erster Scan meldet 1 neue Erkennung"
    Check (Test-Path $f1) "Datei wurde NICHT automatisch verschoben/gelöscht"
    $st = Api
    Check (@($st.offen).Count -eq 1) "Dashboard-API zeigt 1 offene Erkennung"
    $html = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/?t=$token").Content
    Check ($html -match "Testsignatur" -and $html -match "Quarant" -and $html -match "Freigabe") "Dashboard-Seite zeigt Erkennung mit den drei Schaltflächen"
    $id = @($st.offen)[0].id
    $confirm = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/entscheiden?t=$token&id=$id&aktion=freigabe").Content
    Check ($confirm -match "Entscheidung best") "Popup-Link öffnet Bestätigungsseite (ändert selbst nichts)"
    Check (@((Api).offen).Count -eq 1) "Nach Aufruf des Links ist die Erkennung weiterhin offen"
    Post "/aktion" @{ id = $id; aktion = "freigabe" }
    $st = Api
    Check (@($st.offen).Count -eq 0 -and @($st.entscheidungen).Count -eq 1) "Freigabe gespeichert, keine offene Erkennung mehr"
    $out = Scan
    Check ((NewCount $out) -eq 0 -and $out -match "freigegeben \(ignoriert\): 1") "Erneuter Scan: keine neue Meldung (Freigabe greift)"
    Check (Test-Path $f1) "Freigegebene Datei bleibt unverändert"

    Write-Host "`n3) Quarantäne -> automatisch erneut anwenden -> Wiederherstellen"
    $f2 = WriteFile "quarantaene-test.txt" "Andere Datei $signatur Ende"
    $out = Scan
    Check ((NewCount $out) -eq 1) "Neue Datei mit anderer Prüfsumme wird gemeldet"
    $id2 = @((Api).offen)[0].id
    Post "/aktion" @{ id = $id2; aktion = "quarantaene"; notiz = "E2E-Test" }
    Check (-not (Test-Path $f2)) "Datei nach Bestätigung in Quarantäne verschoben"
    $q = @((Api).quarantaene)
    Check ($q.Count -eq 1) "Quarantäne enthält 1 Eintrag"
    $stored = Get-ChildItem (Join-Path $home_ "quarantaene") -Filter *.vsq
    $raw = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($stored[0].FullName))
    Check (-not $raw.Contains($signatur)) "Quarantänedatei ist verschleiert (Signatur nicht im Klartext)"
    $f2b = WriteFile "quarantaene-test.txt" "Andere Datei $signatur Ende"
    $out = Scan
    Check ((NewCount $out) -eq 0 -and $out -match "automatisch behandelt: 1") "Gleicher Fund erneut: still erneut in Quarantäne, keine Meldung"
    Check (-not (Test-Path $f2b)) "Wiederaufgetauchte Datei wurde automatisch verschoben"
    $q = @((Api).quarantaene)
    Post "/wiederherstellen" @{ id = $q[0].id }
    Check (Test-Path $f2) "Wiederherstellen legt Datei am Originalpfad an"
    Check ((Get-Content $f2 -Raw) -match "Andere Datei") "Wiederhergestellter Inhalt ist korrekt"
    $out = Scan
    Check ((NewCount $out) -eq 1) "Nach Wiederherstellen (ohne Freigabe) wird wieder gefragt"
    $id3 = @((Api).offen)[0].id
    Post "/aktion" @{ id = $id3; aktion = "quarantaene" }
    $q = @((Api).quarantaene) | Where-Object { $_.original_path -eq $f2 } | Select-Object -First 1
    Post "/wiederherstellen" @{ id = $q.id; freigeben = "1" }
    $out = Scan
    Check ((Test-Path $f2) -and (NewCount $out) -eq 0) "Wiederherstellen + Freigeben: keine Meldung mehr"

    Write-Host "`n4) Hashliste + Löschen, Widerruf über CLI"
    $f3 = WriteFile "hash-test.bin" $hashInhalt
    $out = Scan
    Check ((NewCount $out) -eq 1 -and $out -match "Hash") "Hashlisten-Treffer wird gemeldet"
    $id4 = @((Api).offen)[0].id
    K9 entscheiden $id4 loeschen | Out-Null
    Check (-not (Test-Path $f3)) "Löschen per CLI entfernt die Datei"
    $decs = K9 entscheidungen
    Check ($decs -match "Freigabe" -and $decs -match "schen") "k9 entscheidungen listet die Entscheidungen"
    $freigabeId = (@((Api).entscheidungen) | Where-Object { $_.action -eq "freigabe" -and $_.note -eq $null } | Select-Object -First 1).id
    K9 entscheidungen widerrufen $freigabeId | Out-Null
    $out = Scan
    Check ((NewCount $out) -eq 1) "Nach Widerruf der Freigabe wird die Datei wieder gemeldet"

    Write-Host "`n5) Phishing-Adresse in einer Verknüpfung (lokale Testliste, kein Internet)"
    $feedDir = Join-Path $home_ "quellen\openphish"
    New-Item -ItemType Directory -Force $feedDir | Out-Null
    $bad = "http://beispiel-phishing.invalid/login.php"
    [IO.File]::WriteAllText((Join-Path $feedDir "feed.txt"), "$bad`n")
    # passender Statuseintrag, als wäre die Liste regulär geladen worden
    [IO.File]::WriteAllText((Join-Path $home_ "quellen\status.json"), '{"openphish":{"last_update":"2026-11-13 10:00:00","entries":1,"files":[]}}')
    $lnk = WriteFile "Bank.url" "[InternetShortcut]`r`nURL=$bad`r`n"
    $out = Scan
    Check ((NewCount $out) -eq 1 -and $out -match "Phishing") "Verknüpfung mit bekannter Phishing-Adresse wird gemeldet"
    Check (Test-Path $lnk) "Verknüpfung bleibt bis zur Entscheidung unverändert"
    $id5 = (@((Api).offen) | Where-Object { $_.rule_id -like "URL:*" } | Select-Object -First 1).id
    K9 entscheiden $id5 quarantaene | Out-Null
    Check (-not (Test-Path $lnk)) "Quarantäne der Verknüpfung per CLI"
    $q = K9 quellen
    Check ($q -match "OpenPhish") "k9 quellen zeigt die Quellen"
    Check ($q -match "Erkennungsdaten" -and $q -match "Schad-/Phishing-Adressen\s+: 1 ") "k9 quellen zeigt die Erkennungsdaten-Übersicht (1 Testadresse)"
    $ed = (Api).erkennungsdaten
    Check ($ed.openphish_adressen -eq 1 -and @($ed.quellen).Count -eq 15) "Dashboard-API liefert die Erkennungsdaten"
    $html = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/?t=$token").Content
    Check ($html -match "Erkennungsdaten" -and $html -match "ClamAV-Signaturen") "Dashboard zeigt den Kasten Erkennungsdaten"


    Write-Host "`n6) Echtzeitschutz (nur Testordner)"
    function WaitFor([scriptblock]$cond, [int]$seconds) {
        $end = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $end) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 500 }
        return $false
    }
    $canary = Join-Path $rtDir "~vs-koeder-nicht-loeschen.docx"
    Check (WaitFor { Test-Path $canary } 20) "Köderdatei im überwachten Ordner angelegt"
    $rtFile = Join-Path $rtDir "echtzeit-probe.txt"
    [IO.File]::WriteAllBytes($rtFile, [Text.Encoding]::ASCII.GetBytes("Echtzeit $signatur Test"))
    Check (WaitFor { @((Api).offen | Where-Object { $_.path -eq $rtFile }).Count -eq 1 } 20) "Neue Datei mit Testsignatur wird ohne Scan-Befehl gemeldet"
    Check (Test-Path $rtFile) "Echtzeit-Fund bleibt unverändert bis zur Entscheidung"
    # simulierte Ransomware: 30 Dokumente werden schnell mit Zufallsdaten überschrieben
    # Die Dokumente müssen vorher schon da sein: K9 zählt nur Dateien, die es schon gab
    # (neu angelegte gepackte Dateien – Entpacken, Download – sind kein Ransomware-Zeichen).
    for ($i = 0; $i -lt 30; $i++) { Set-Content -LiteralPath (Join-Path $rtDir "dokument$i.txt") ("Brief Nr. $i an Max Mustermann. " * 200) -Encoding ASCII }
    Start-Sleep -Seconds 10
    $rnd = New-Object Random
    for ($i = 0; $i -lt 30; $i++) {
        $b = New-Object byte[] 8192; $rnd.NextBytes($b)
        [IO.File]::WriteAllBytes((Join-Path $rtDir "dokument$i.txt"), $b)
    }
    Check (WaitFor { @((Api).offen | Where-Object { $_.rule_id -eq "RANSOMWARE:VERHALTEN" }).Count -ge 1 } 30) "Massenverschlüsselung löst Ransomware-Alarm aus"
    Set-Content $canary "manipuliert"
    Check (WaitFor { @((Api).offen | Where-Object { $_.rule_id -eq "RANSOMWARE:VERHALTEN" -and $_.path -like "*datei wurde ver*" }).Count -ge 1 } 20) "Veränderte Köderdatei löst Alarm aus"
    $alarm = @((Api).offen | Where-Object { $_.rule_id -eq "RANSOMWARE:VERHALTEN" })[0]
    Check ($alarm.severity -eq "kritisch" -and $alarm.kind -eq "prozess") "Ransomware-Alarm ist kritisch und bietet Prozess-Aktionen"

    $status = K9 status
    Check ($status -match "Agent\s+: (läuft|laeuft)") "k9 status erkennt laufenden Agent"

    Write-Host "`n7) Englische Oberfläche (Sprachschalter im Dashboard)"
    # Nur der sichtbare Text der Seite (ohne Skript, Stil und HTML-Zeichen).
    function PageText {
        $h = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/?t=$token").Content
        $h = [regex]::Replace($h, '(?s)<(script|style)[^>]*>.*?</\1>', ' ')
        $h = [regex]::Replace($h, '<[^>]+>', ' ')
        [Net.WebUtility]::HtmlDecode($h) -replace '\s+', ' '
    }
    Post "/sprache" @{ sprache = "en" }
    $en = PageText
    if ($env:K9_E2E_EN_TEXT) { [IO.File]::WriteAllText($env:K9_E2E_EN_TEXT, $en, [Text.Encoding]::UTF8) }
    Check ($en -match "Security check" -and $en -match "Open findings" -and $en -match "Language:") "Schalter „English“ stellt das Dashboard sofort auf Englisch um"
    $deutsch = @("Sicherheits-Check", "Letzte Aktionen", "Erkennungsdaten", "Quellen aktuell", "Offene Erkennungen", "Gespeicherte Entscheidungen",
        "Einstellungen", "Zeitpläne", "Schnellscan", "Noch nicht geprüft", "Stand:", "Virenschutz", "Datensicherung", "Was tun?") | Where-Object { $en.Contains($_) }
    Check (@($deutsch).Count -eq 0) "Englische Seite enthält keine deutschen Bereichstexte$(if (@($deutsch).Count) { " (gefunden: $($deutsch -join ', '))" })"
    Post "/sprache" @{ sprache = "de" }
    Check ((PageText) -match "Sicherheits-Check") "Schalter „Deutsch“ stellt wieder auf Deutsch um"
}
finally {
    if ($agent -and -not $agent.HasExited) { Stop-Process -Id $agent.Id -Force; $agent.WaitForExit() }
    # Auch ein Test-Agent, der verspätet gestartet ist (z. B. weil ein Virenschutz den Start erst
    # nach einer Rückfrage erlaubt hat): nur genau dieses Programm aus dem Bauordner, gestartet
    # seit Testbeginn - nie der installierte Agent. Sonst bleibt er liegen und sperrt den nächsten Bau.
    Get-Process k9-agent -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $agentExe -and $_.StartTime -ge $before } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:\K9_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:\K9_SPRACHE -ErrorAction SilentlyContinue
    foreach ($v in $alteUmgebung.Keys) { [Environment]::SetEnvironmentVariable($v, $alteUmgebung[$v]) }
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $home_, $scanDir, $rtDir, $profil -ErrorAction SilentlyContinue
    Write-Host "`nAufgeräumt: Agent beendet, Testordner gelöscht ($(-not (Test-Path $home_) -and -not (Test-Path $scanDir)))."
}

Write-Host "`nErgebnis: $script:ok bestanden, $script:fail fehlgeschlagen"
if ($script:fail -gt 0) { exit 1 }
