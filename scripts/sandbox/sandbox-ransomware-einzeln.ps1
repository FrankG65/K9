<#
  EINE echte Ransomware-Probe je Sandbox - NUR IN DER WINDOWS-SANDBOX und NUR mit Zustimmung
  des Nutzers fuer genau diesen Tag (C:\Testlabor\vergleich\ZUSTIMMUNG.txt mit dem Datum und den
  Zeilen "starten" und "ransomware"). Gestartet wird dieses Skript von ransomware-reihe.ps1 auf dem
  PC, das je Probe eine frische Sandbox oeffnet (siehe docs\SANDBOX-TESTPLAN.md).

  Warum eine Probe je Sandbox: Ransomware beendet Programme (auch das Testfenster), verschluesselt
  alles Erreichbare und raeumt den Desktop ab - danach ist die Sandbox fuer weitere Proben unbrauchbar.

  Ablauf:
    0  Notbremse: eine Windows-Aufgabe faehrt die Sandbox nach 20 Minuten in jedem Fall herunter
    A  Probe waehlen (neueste .exe der Familie bei MalwareBazaar) und laden; K9 und 7-Zip einrichten;
       -Anhalten an: K9 friert Verdaechtige bei Ransomware-Verdacht ein (ransomware_prozess_anhalten)
    B  NETZWERK AUS (dreifach), geprueft durch einen echten Verbindungsversuch
    C  Koeder: Schein-Browserprofile und 160 Schein-Dokumente
    D  Probe entpacken (erkennt K9 die Datei?), starten und -Minuten lang alle 5 Sekunden den Stand
       aufschreiben: wie viele Schein-Dokumente sind unveraendert, was hat K9 gemeldet
    E  Ergebnis, Sandbox faehrt herunter

  Der Stand steht in $out\stand.txt (nur Text). Beendet die Probe dieses Skript, bleibt der letzte
  Stand erhalten; ransomware-reihe.ps1 kopiert ihn auf dem PC laufend weg.
#>
param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9]+$')][string]$Familie, [ValidateSet('an', 'aus')][string]$Anhalten = 'aus', [ValidateRange(1, 8)][int]$Minuten = 3,
    # Switch "neue-programme" on (since 0.39.0): unsigned programs from the internet are frozen at their start.
    [switch]$NeueProgramme)
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$cfg = 'C:\Testlabor\vergleich'
$heute = Get-Date -Format 'dd.MM.yyyy'
$zustimmung = Join-Path $cfg 'ZUSTIMMUNG.txt'
$z = if (Test-Path $zustimmung) { Get-Content $zustimmung -Raw } else { '' }
if ($z -notmatch [regex]::Escape($heute) -or $z -notmatch '(?im)^\s*starten\s*$' -or $z -notmatch '(?im)^\s*ransomware\s*$') {
    Write-Host "Keine Zustimmung fuer heute ($heute) mit den Zeilen 'starten' und 'ransomware' in $zustimmung - Abbruch."
    exit 1
}
# The folder with the scripts and keys must not be writable from here.
try { Set-Content 'C:\Testlabor\schreibtest.txt' 'x' -ErrorAction Stop; Remove-Item 'C:\Testlabor\schreibtest.txt'; Write-Host 'Testordner ist beschreibbar - Abbruch.'; exit 1 } catch {}

# 0 Emergency brake: whatever the sample does to this window, the sandbox ends.
$ende = (Get-Date).AddMinutes(20).ToString('HH:mm')
& schtasks.exe /create /tn 'K9-Test-Ende' /sc once /st $ende /ru SYSTEM /tr 'shutdown.exe /s /f /t 0' /f | Out-Null

$out = if (Test-Path 'C:\Ergebnis') { 'C:\Ergebnis' } else { 'C:\K9-Testergebnis' }
New-Item -ItemType Directory -Force $out | Out-Null
$standDatei = Join-Path $out 'stand.txt'
$script:stand = New-Object System.Collections.Generic.List[string]
# Every line goes to the window and to the file (written completely each time: plain ASCII, small).
function Stand([string]$t, [string]$farbe = 'Gray') {
    $zeile = "$(Get-Date -Format HH:mm:ss) $t"
    Write-Host $zeile -ForegroundColor $farbe
    $script:stand.Add($zeile)
    try { [IO.File]::WriteAllLines($standDatei, $script:stand, [Text.Encoding]::ASCII) } catch {}
}
function Schluss([string]$t) {
    Stand "ENDE: $t" 'Yellow'
    Start-Sleep 3
    & shutdown.exe /s /f /t 5
    exit 0
}

# A click into the window must not stop the script (quick edit mode off).
try {
    Add-Type -Namespace K9 -Name Konsole -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int n); [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m); [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);'
    $eingabe = [K9.Konsole]::GetStdHandle(-10)
    $modus = 0
    if ([K9.Konsole]::GetConsoleMode($eingabe, [ref]$modus)) { [void][K9.Konsole]::SetConsoleMode($eingabe, ($modus -band (-bnot 0x40)) -bor 0x80) }
} catch {}
$beginn = Get-Date
function Titel([string]$t) { try { $Host.UI.RawUI.WindowTitle = "K9 Ransomware-Test $Familie (Anhalten $Anhalten) seit $($beginn.ToString('HH:mm')) Uhr - $t" } catch {} }
function Warten([int]$sekunden, [string]$text) {
    $z = '|', '/', '-', '\'
    for ($i = 0; $i -lt $sekunden * 2; $i++) {
        try { [Console]::Write("`r  $($z[$i % 4]) $text - noch $([int](($sekunden * 2 - $i) / 2)) s   ") } catch {}
        Titel $text
        Start-Sleep -Milliseconds 500
    }
    try { [Console]::Write("`r" + (' ' * 100) + "`r") } catch {}
}
function Erreichbar {
    foreach ($ziel in @('1.1.1.1', 443), @('8.8.8.8', 53), @('9.9.9.9', 443)) {
        try {
            $c = New-Object Net.Sockets.TcpClient
            $a = $c.BeginConnect($ziel[0], $ziel[1], $null, $null)
            $ok = $a.AsyncWaitHandle.WaitOne(1500) -and $c.Connected
            $c.Close()
            if ($ok) { return $true }
        } catch {}
    }
    $false
}

Stand "TEST GESTARTET am ${heute}: Familie $Familie, Ransomware-Anhalten $Anhalten, Beobachtung $Minuten min" 'Cyan'
Stand "Notbremse: die Sandbox faehrt um $ende Uhr in jedem Fall herunter"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$keyFile = Join-Path $cfg 'abusech-key.txt'
if (-not (Test-Path $keyFile)) { Schluss 'Schluessel fehlt' }
$abuseKey = (Get-Content $keyFile -Raw).Trim()
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $dl | Out-Null

# --- A sample, K9, 7-Zip
Titel 'Probe wird gewaehlt'
$zip = 'C:\probe.zip'
# Cache (a USB stick, mapped read-only as C:\Proben): a sample is fetched from MalwareBazaar
# only once - the service limits the downloads per day. The archive stays encrypted there and
# is never unpacked outside a sandbox.
$lager = "C:\Proben\$Familie.zip"
$lagerInfo = "C:\Proben\$Familie.txt"
if ((Test-Path $lager) -and (Test-Path $lagerInfo)) {
    Copy-Item $lager $zip -Force
    Stand "Probe aus dem Zwischenspeicher: $((Get-Content $lagerInfo -TotalCount 1) -replace '[^ -~]', '?')"
} else {
    $sig = $null
    foreach ($versuch in 1..3) {
        try { $sig = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_siginfo'; signature = $Familie; limit = '100' } -TimeoutSec 120; break }
        catch { Stand "MalwareBazaar, Versuch ${versuch}: $($_.Exception.Message)"; Start-Sleep 5 }
    }
    $probe = @($sig.data | Where-Object { $_.file_type -eq 'exe' -and $_.first_seen } | Sort-Object first_seen -Descending | Select-Object -First 1)[0]
    if (-not $probe) { Schluss "keine Probe der Familie $Familie erhalten" }
    Stand "Probe: $($probe.sha256_hash) (erstmals gesehen $($probe.first_seen))"
    # MalwareBazaar limits requests per minute (429): up to four attempts, one minute apart.
    $geladen = $false
    foreach ($versuch in 1..4) {
        try { Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_file'; sha256_hash = $probe.sha256_hash } -OutFile $zip -TimeoutSec 120; $geladen = $true; break }
        catch { Stand "Probe laden, Versuch ${versuch}: $($_.Exception.Message)"; if ($versuch -lt 4) { Warten 60 'Pause vor dem naechsten Versuch' } }
    }
    if (-not $geladen) { Schluss 'Probe nicht geladen' }
    # Hand the still encrypted archive to the PC for the cache - now, long before the sample
    # runs, and wait until the PC has taken it: the sample never gets to touch it.
    if ((Test-Path 'C:\Proben') -and (Test-Path 'C:\Ergebnis')) {
        try {
            Set-Content -LiteralPath "C:\Ergebnis\probe-$Familie.txt" "$($probe.sha256_hash) (erstmals gesehen $($probe.first_seen))" -Encoding ASCII
            Copy-Item $zip "C:\Ergebnis\probe-$Familie.teil" -Force
            Rename-Item "C:\Ergebnis\probe-$Familie.teil" "probe-$Familie.zip"
            for ($i = 0; $i -lt 30 -and (Test-Path "C:\Ergebnis\probe-$Familie.zip"); $i++) { Start-Sleep 2 }
            Stand "Archiv an den Zwischenspeicher uebergeben: $(-not (Test-Path "C:\Ergebnis\probe-$Familie.zip"))"
            Remove-Item "C:\Ergebnis\probe-$Familie.zip", "C:\Ergebnis\probe-$Familie.txt" -Force -ErrorAction SilentlyContinue
        } catch { Stand "Zwischenspeicher: $(($_.Exception.Message) -replace '[^ -~]', '?')" }
    }
}
Titel '7-Zip und K9 werden eingerichtet'
$msi = Join-Path $env:TEMP '7z-x64.msi'
try { Invoke-WebRequest -UseBasicParsing 'https://www.7-zip.org/a/7z2409-x64.msi' -OutFile $msi -TimeoutSec 120 } catch {}
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn" -Wait
$7z = 'C:\Program Files\7-Zip\7z.exe'
if (-not (Test-Path $7z)) { Schluss '7-Zip fehlt' }
& "$prog\k9.exe" dienst installieren 2>&1 | Out-Null
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
Stand "K9 installiert: $((& $k9 --version 2>&1 | Out-String).Trim()), Agent laeuft: $([bool](Get-Process k9-agent -ErrorAction SilentlyContinue))"
& $k9 quellen aktualisieren yara_forge 2>&1 | Out-Null   # YARA rules (a few MB); no hash lists, no ClamAV
& $k9 funktion anhalten an 2>&1 | Out-Null               # as on the test PC
if ($NeueProgramme) { Stand "Schalter neue-programme: $((& $k9 funktion neue-programme an 2>&1 | Out-String).Trim() -replace '\s+', ' ' -replace '[^ -~]', '?')" }
$toml = Join-Path $env:APPDATA 'K9\config.toml'
for ($i = 0; $i -lt 30 -and -not (Test-Path $toml); $i++) { Start-Sleep 2 }
if ($Anhalten -eq 'an') {
    $t = Get-Content $toml -Raw
    if ($t -match '(?m)^ransomware_prozess_anhalten\s*=') { $t = $t -replace '(?m)^ransomware_prozess_anhalten\s*=.*$', 'ransomware_prozess_anhalten = true' }
    else { $t = $t -replace '(?m)^\[echtzeit\]\s*$', "[echtzeit]`r`nransomware_prozess_anhalten = true" }
    [IO.File]::WriteAllText($toml, $t, (New-Object Text.UTF8Encoding($false)))
}
# The agent reads this setting at its start: the service starts it again.
Get-Process k9-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3
for ($i = 0; $i -lt 60 -and -not (Get-Process k9-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep 2 }
Stand "Einstellung in config.toml: $((Select-String -Path $toml -Pattern '^ransomware_prozess_anhalten' | Select-Object -First 1).Line); Agent laeuft: $([bool](Get-Process k9-agent -ErrorAction SilentlyContinue))"
Warten 30 'K9 startet seine Ueberwachung'

# --- B network off
Titel 'Netzwerk wird gesperrt'
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
& netsh advfirewall set allprofiles state on | Out-Null
& netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | ForEach-Object { & pnputil /remove-device $_.InstanceId 2>&1 | Out-Null }
Start-Sleep 5
if (Erreichbar) { Schluss 'NETZWERK IST NOCH AN - nichts wurde entpackt' }
Stand 'Netzwerk aus (Verbindungsversuch gescheitert)'

# --- C decoys (random or invented content only)
$koederOrdner = @("$env:USERPROFILE\Documents\Rechnungen", "$env:USERPROFILE\Documents\Steuer 2025", "$env:USERPROFILE\Desktop\Projekt Haus", "$env:USERPROFILE\Pictures\Urlaub 2026")
$koederText = ('Rechnung Nr. 2026-1147 an Max Mustermann, Musterstrasse 1, 12345 Musterstadt. Betrag 119,00 EUR. ' * 120)
function KoederHeil {
    $n = 0
    foreach ($dir in $koederOrdner) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch '^Datei\d{3}\.(docx|xlsx|pdf|jpg|txt)$') { continue }
            try { $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite'); $b = New-Object byte[] 12; [void]$fs.Read($b, 0, 12); $fs.Close(); if ([Text.Encoding]::ASCII.GetString($b) -eq 'Rechnung Nr.') { $n++ } } catch {}
        }
    }
    $n
}
$rnd = New-Object Random
foreach ($p in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data", "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State", "$env:APPDATA\Mozilla\Firefox\Profiles\k9test.default-release\logins.json")) {
    New-Item -ItemType Directory -Force (Split-Path $p -Parent) | Out-Null
    $b = New-Object byte[] 8192; $rnd.NextBytes($b); try { [IO.File]::WriteAllBytes($p, $b) } catch {}
}
foreach ($dir in $koederOrdner) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    $i = 0
    foreach ($ext in 'docx', 'xlsx', 'pdf', 'jpg', 'txt') { 1..8 | ForEach-Object { $i++; Set-Content -LiteralPath (Join-Path $dir ('Datei{0:000}.{1}' -f $i, $ext)) $koederText -Encoding ASCII } }
}
Stand "Koeder angelegt: $(KoederHeil) Schein-Dokumente"
Warten 20 'K9 prueft die Koeder'

# What K9 has reported so far: rule ids of all findings (second column of "k9 erkennungen").
function Regeln {
    try { @((& $k9 erkennungen --alle 2>$null) | ForEach-Object { $t = ($_ -split '\|'); if ($t.Count -gt 1) { $t[1].Trim() } } | Where-Object { $_ } | Select-Object -Unique) } catch { @() }
}
$vorher = @(Regeln)

# --- D unpack, start, watch
Titel 'Probe wird entpackt'
& $7z e -pinfected -y "-o$dl" $zip | Out-Null
$datei = @(Get-ChildItem $dl -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1)[0]
if (-not $datei) { Schluss 'Probe nicht entpackt (von Windows Defender entfernt?)' }
Warten 30 'K9 prueft die entpackte Datei'
$alsDatei = @(Regeln | Where-Object { $vorher -notcontains $_ })
Stand "Als Datei erkannt (vor dem Start): $(if ($alsDatei.Count) { $alsDatei -join '; ' } else { 'nein' })"
if (-not (Test-Path $datei.FullName)) { Schluss 'Datei nach der Pruefung nicht mehr da (von Windows Defender entfernt)' }
$f = $datei.FullName
if ([IO.Path]::GetExtension($f) -ne '.exe') { try { Rename-Item $f "$f.exe" -ErrorAction Stop; $f = "$f.exe" } catch {} }
try { Set-Content -Path $f -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -ErrorAction Stop } catch {}
if (Erreichbar) { Schluss 'NETZWERK IST WIEDER AN - Probe wurde nicht gestartet' }
$bekannt = @(Regeln)
$heilVorher = KoederHeil
try { $p = Start-Process $f -PassThru -ErrorAction Stop } catch { Schluss "Probe liess sich nicht starten: $($_.Exception.Message)" }
$start = Get-Date
Stand "PROBE GESTARTET (PID $($p.Id)); Schein-Dokumente unveraendert: $heilVorher" 'Red'
$ersteMeldung = $null; $ersterSchaden = $null; $gemeldet = @()
while (((Get-Date) - $start).TotalSeconds -lt $Minuten * 60) {
    Start-Sleep 5
    $s = [int]((Get-Date) - $start).TotalSeconds
    $heil = KoederHeil
    $neu = @(Regeln | Where-Object { $bekannt -notcontains $_ -and $gemeldet -notcontains $_ })
    if ($neu.Count) { $gemeldet += $neu; if (-not $ersteMeldung) { $ersteMeldung = $s } }
    if ($heil -lt $heilVorher -and -not $ersterSchaden) { $ersterSchaden = $s }
    $lebt = try { -not $p.HasExited } catch { $false }
    Titel "Probe laeuft seit $s s"
    $agentDa = [bool](Get-Process k9-agent -ErrorAction SilentlyContinue)
    $dienstDa = [bool](Get-Process k9-dienst -ErrorAction SilentlyContinue)
    Stand "+$s s | unveraendert: $heil von $heilVorher | Probe laeuft: $lebt | Agent: $agentDa | Dienst: $dienstDa | K9 neu: $(if ($neu.Count) { $neu -join '; ' } else { '-' })"
}

# --- E result
$heil = KoederHeil
Stand '--- ERGEBNIS ---' 'Cyan'
Stand "Familie: $Familie | Ransomware-Anhalten: $Anhalten | als Datei erkannt: $(if ($alsDatei.Count) { 'ja' } else { 'nein' })"
Stand "Schein-Dokumente unveraendert: $heil von $heilVorher"
Stand "Erste K9-Meldung nach: $(if ($ersteMeldung) { "$ersteMeldung s" } else { 'keine' }) | erster Schaden nach: $(if ($ersterSchaden) { "$ersterSchaden s" } else { 'keiner' })"
Stand "K9-Meldungen: $(if ($gemeldet.Count) { $gemeldet -join '; ' } else { 'keine' })"
Stand "Netzwerk am Ende erreichbar: $(Erreichbar)"

# --- Diagnosis (plain ASCII only): why did K9 report what it reported?
# What do the decoys look like now: name, age of the last write, how random the content is.
function Entropie([string]$path) {
    try {
        $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite'); $b = New-Object byte[] 4096; $n = $fs.Read($b, 0, 4096); $fs.Close()
        if ($n -le 0) { return 'leer' }
        $z = New-Object int[] 256; for ($i = 0; $i -lt $n; $i++) { $z[$b[$i]]++ }
        $e = 0.0; foreach ($c in $z) { if ($c -gt 0) { $q = $c / $n; $e -= $q * [Math]::Log($q, 2) } }
        '{0:N2}' -f $e
    } catch { 'nicht lesbar' }
}
function Ascii([string]$t) { -join ($t.ToCharArray() | ForEach-Object { if ([int]$_ -ge 32 -and [int]$_ -le 126) { $_ } else { '?' } }) }
Stand '--- DIAGNOSE ---' 'Cyan'
$jetzt = Get-Date
foreach ($dir in $koederOrdner | Select-Object -First 2) {
    $alle = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)
    Stand (Ascii "Ordner $(Split-Path $dir -Leaf): $($alle.Count) Eintraege")
    foreach ($f in $alle | Select-Object -First 4) {
        Stand (Ascii "  $($f.Name) | $($f.Length) Bytes | geschrieben vor $([int]($jetzt - $f.LastWriteTime).TotalSeconds) s (Probe gestartet vor $([int]($jetzt - $start).TotalSeconds) s) | Entropie $(Entropie $f.FullName) | versteckt: $([bool]($f.Attributes -band [IO.FileAttributes]::Hidden))")
    }
}
# K9's own canary files (hidden) in the user's folders.
foreach ($k in @(Get-ChildItem -LiteralPath "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Pictures" -Force -Filter '~vs-koeder*' -ErrorAction SilentlyContinue)) {
    Stand (Ascii "K9-Koederdatei $($k.FullName) | $($k.Length) Bytes | geschrieben vor $([int]($jetzt - $k.LastWriteTime).TotalSeconds) s | Entropie $(Entropie $k.FullName)")
}
Stand "Agent laeuft: $([bool](Get-Process k9-agent -ErrorAction SilentlyContinue)) | Dienst laeuft: $([bool](Get-Process k9-dienst -ErrorAction SilentlyContinue))"
# K9's own logs: both lie in ProgramData\K9\logs (an older agent wrote into the user folder).
# Of every log the warnings and errors since the sample started - until 21.11.2026 only the
# newest file was looked at, and that was always the agent's: the service log, which says when
# what was frozen, was missing in every result.
foreach ($log in @(Get-ChildItem "$env:LOCALAPPDATA\K9\logs", 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
    Stand (Ascii "Protokoll $($log.Name) ($($log.Length) Bytes), Warnungen und Fehler (letzte 40):")
    try {
        $zeilen = @(Get-Content -LiteralPath $log.FullName -ErrorAction Stop | Where-Object { $_ -match ' (WARN|ERROR) ' } | Select-Object -Last 40)
        foreach ($z in $zeilen) { $t = Ascii $z; Stand ("  " + $t.Substring(0, [Math]::Min(260, $t.Length))) }
    } catch { Stand (Ascii "  nicht lesbar: $($_.Exception.Message)") }
}
Schluss 'FERTIG'
