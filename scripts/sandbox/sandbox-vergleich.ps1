<#
  Vergleichstest mit ECHTER Schadsoftware - NUR IN DER WINDOWS-SANDBOX und NUR mit Zustimmung
  des Nutzers fuer genau diesen Tag (Datei C:\Testlabor\vergleich\ZUSTIMMUNG.txt mit dem heutigen
  Datum, siehe docs\SANDBOX-TESTPLAN.md, Abschnitt "Vergleichstest").

  Ablauf (alles in der Sandbox, nichts davon erreicht den PC):
    A  Schluessel pruefen; K9 wie auf dem PC einrichten (Dienst, abuse.ch-Schluessel, ClamAV,
       Erkennungsdaten); 7-Zip (offizielles MSI) installieren
    B  MalwareBazaar: die neuesten Proben (verschluesselte ZIP-Archive, Passwort "infected") laden;
       optional die Ergebnisse von Trend Micro bei VirusTotal je Pruefsumme (nur Abfrage)
    C  NETZWERK AUS (Netzwerkadapter der Sandbox abschalten) - erst danach wird entpackt
    D  jede Probe einzeln nach Downloads entpacken, 25 s warten: hat K9 sie in Echtzeit erkannt?
       Hat Windows Defender (in der Sandbox aktiv, wird NICHT veraendert) sie entfernt?
    E  danach ein Scan des Probenordners (k9 scan)
    F  Ergebnisse als Text nach C:\Ergebnis (keine Proben, keine Archive, keine Schluessel)
  Proben werden NIE gestartet (nur Dateipruefung), ausser mit -Starten (eigene Zustimmung noetig,
  Zeile "starten" in ZUSTIMMUNG.txt).

  -Schwerpunkt (schliesst -Starten ein; zusaetzlich die Zeile "ransomware" in ZUSTIMMUNG.txt):
  nur Datendiebe und Ransomware. Vor jedem Start legt das Skript Koeder an - Schein-Browserprofile,
  Schein-Wallets (Zufallsinhalt, keine echten Zugangsdaten) und 160 Schein-Dokumente -, damit die
  Erkennung von Datendieben und Ransomware ueberhaupt ansprechen kann. 120 s Beobachtung je Probe,
  Ransomware zuletzt. Sandbox: k9-vergleich-schwerpunkt.wsb.
  -NurRansomware: der Schwerpunkt-Lauf nur mit Ransomware (k9-vergleich-ransomware.wsb).

  Schluessel (Entscheidung des Nutzers): C:\Testlabor\vergleich\abusech-key.txt (Pflicht, am besten ein
  eigener Wegwerf-Schluessel nur fuer diesen Test) und optional virustotal-key.txt.

  Aufruf in der Sandbox (Administrator-PowerShell):
    powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-vergleich.ps1 -Anzahl 30
#>
param([ValidateRange(1, 100)][int]$Anzahl = 30, [switch]$Starten, [switch]$Schwerpunkt, [switch]$NurRansomware)
$ErrorActionPreference = 'Continue'
if ($NurRansomware) { $Schwerpunkt = $true } # the focus run with ransomware samples only
if ($Schwerpunkt) { $Starten = $true }
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$cfg = 'C:\Testlabor\vergleich'
$heute = Get-Date -Format 'dd.MM.yyyy'
$zustimmung = Join-Path $cfg 'ZUSTIMMUNG.txt'
$z = if (Test-Path $zustimmung) { Get-Content $zustimmung -Raw } else { '' }
if ($z -notmatch [regex]::Escape($heute)) {
    Write-Host "Keine Zustimmung fuer heute ($heute) in $zustimmung - Abbruch."
    exit 1
}
if ($Starten -and $z -notmatch '(?im)^\s*starten\s*$') {
    Write-Host 'Proben starten ist nicht freigegeben (Zeile "starten" fehlt in ZUSTIMMUNG.txt) - Abbruch.'
    exit 1
}
if ($Schwerpunkt -and $z -notmatch '(?im)^\s*ransomware\s*$') {
    Write-Host 'Der Lauf mit Datendieben und Ransomware ist nicht freigegeben (Zeile "ransomware" fehlt in ZUSTIMMUNG.txt) - Abbruch.'
    exit 1
}
# A started sample could write into a folder that leads to the PC: with -Starten only in the
# sandbox without a writable folder (k9-vergleich-starten.wsb); results stay on its desktop.
if ($Starten) {
    if (Test-Path 'C:\Ergebnis') { Write-Host 'Mit -Starten nur in k9-vergleich-starten.wsb (ohne Ergebnisordner zum PC) - Abbruch.'; exit 1 }
    $probe = 'C:\Testlabor\schreibtest.txt'
    try { Set-Content $probe 'x' -ErrorAction Stop; Remove-Item $probe; Write-Host 'Testordner ist beschreibbar - Abbruch.'; exit 1 } catch {}
}
$keyFile = Join-Path $cfg 'abusech-key.txt'
if (-not (Test-Path $keyFile)) { Write-Host "Schluessel fehlt: $keyFile"; exit 1 }
$abuseKey = (Get-Content $keyFile -Raw).Trim()
$vtFile = Join-Path $cfg 'virustotal-key.txt'
$vtKey = if (Test-Path $vtFile) { (Get-Content $vtFile -Raw).Trim() } else { '' }

$out = if ($Schwerpunkt) { 'C:\K9-Testergebnis' } elseif ($Starten) { Join-Path $env:USERPROFILE 'Desktop\Ergebnis' } else { 'C:\Ergebnis' }
New-Item -ItemType Directory -Force $out | Out-Null
$prog = 'C:\Testlabor\programm'
$k9 = 'C:\Program Files\K9\k9.exe'
$zips = 'C:\Proben-Archive'
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $zips, $dl | Out-Null
Start-Transcript -Path (Join-Path $out 'vergleich-protokoll.txt') | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step([string]$t) { Write-Host "`n=== $t ($(Get-Date -Format HH:mm:ss))" }
function Run([string]$exe) { & $exe @args 2>&1 | Out-String | Write-Host }
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

# Decoys for -Schwerpunkt: what an info stealer looks for and what ransomware encrypts.
# Random or invented content only - no real credentials, no real documents.
$koederOrdner = @("$env:USERPROFILE\Documents\Rechnungen", "$env:USERPROFILE\Documents\Steuer 2025", "$env:USERPROFILE\Desktop\Projekt Haus", "$env:USERPROFILE\Pictures\Urlaub 2026")
$koederText = ('Rechnung Nr. 2026-1147 an Max Mustermann, Musterstrasse 1, 12345 Musterstadt. Betrag 119,00 EUR. ' * 120)
function KoederHeil {
    @($koederOrdner | ForEach-Object { Get-ChildItem -LiteralPath $_ -File -ErrorAction SilentlyContinue } |
        Where-Object {
            # Unchanged: old name and old beginning (encryption in place keeps name and size).
            if ($_.Name -notmatch '^Datei\d{3}\.(docx|xlsx|pdf|jpg|txt)$') { return $false }
            try { $fs = [IO.File]::Open($_.FullName, 'Open', 'Read', 'ReadWrite'); $b = New-Object byte[] 12; [void]$fs.Read($b, 0, 12); $fs.Close(); [Text.Encoding]::ASCII.GetString($b) -eq 'Rechnung Nr.' } catch { $false }
        }).Count
}
function Koeder {
    $rnd = New-Object Random
    $speicher = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Web Data",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles\k9test.default-release\logins.json",
        "$env:APPDATA\Mozilla\Firefox\Profiles\k9test.default-release\key4.db",
        "$env:APPDATA\Mozilla\Firefox\Profiles\k9test.default-release\cookies.sqlite",
        "$env:APPDATA\discord\Local Storage\leveldb\000003.log",
        "$env:APPDATA\Telegram Desktop\tdata\key_datas",
        "$env:APPDATA\Exodus\exodus.wallet\seed.seco",
        "$env:APPDATA\Electrum\wallets\default_wallet",
        "${env:ProgramFiles(x86)}\Steam\config\loginusers.vdf"
    )
    foreach ($p in $speicher) {
        if (Test-Path -LiteralPath $p) { continue }
        New-Item -ItemType Directory -Force (Split-Path $p -Parent) | Out-Null
        $b = New-Object byte[] 8192; $rnd.NextBytes($b)
        try { [IO.File]::WriteAllBytes($p, $b) } catch {}
    }
    $ini = "$env:APPDATA\Mozilla\Firefox\profiles.ini"
    if (-not (Test-Path $ini)) { Set-Content $ini "[Profile0]`r`nName=default-release`r`nIsRelative=1`r`nPath=Profiles/k9test.default-release`r`nDefault=1" -Encoding ASCII }
    # Documents: restore the complete set when a sample changed, renamed or deleted some.
    if ((KoederHeil) -lt 160) {
        foreach ($dir in $koederOrdner) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force $dir | Out-Null
            $i = 0
            foreach ($ext in 'docx', 'xlsx', 'pdf', 'jpg', 'txt') {
                1..8 | ForEach-Object { $i++; Set-Content -LiteralPath (Join-Path $dir ('Datei{0:000}.{1}' -f $i, $ext)) $koederText -Encoding ASCII }
            }
        }
    }
}

Step 'A0 Schluessel pruefen (bevor irgendetwas installiert wird)'
try {
    $probe = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_recent'; selector = '100' } -TimeoutSec 120
} catch { $probe = $null; Write-Host "  MalwareBazaar: $($_.Exception.Message)" }
if (-not $probe -or $probe.query_status -ne 'ok') {
    Write-Host "MalwareBazaar nimmt den Schluessel in abusech-key.txt nicht an (Antwort: $($probe.query_status)). Ist es wirklich der Schluessel von auth.abuse.ch? Abbruch - nichts wurde geladen."
    Stop-Transcript | Out-Null
    exit 1
}
Write-Host '  abuse.ch-Schluessel in Ordnung.'

Step 'A K9 wie auf dem PC einrichten: Dienst, abuse.ch-Schluessel, ClamAV, Erkennungsdaten; dazu 7-Zip'
if ($Schwerpunkt) {
    # The service then writes every access to stored logins with its verdict into its log:
    # afterwards it is clear whether a sample touched the decoys at all - also when K9 allowed
    # the access or stayed silent.
    [Environment]::SetEnvironmentVariable('K9_LOG', 'debug', 'Machine')
    $env:K9_LOG = 'debug'
}
Run "$prog\k9.exe" dienst installieren
# K9 in the sandbox gets the same sources as on the PC: the abuse.ch key (hash lists) and ClamAV.
$OutputEncoding = [Text.Encoding]::ASCII # no byte order mark in front of the key
$abuseKey | & $k9 geheimnis abusech-key --aus-eingabe 2>&1 | Out-String | Write-Host
$clam = Join-Path $env:TEMP 'clamav.msi'
for ($try = 1; $try -le 3 -and -not (Test-Path 'C:\Program Files\ClamAV\clamd.exe'); $try++) {
    try {
        Write-Host "  ClamAV wird geladen (etwa 200 MB, Versuch $try; dabei bewegt sich hier bis zu 5 Minuten nichts) ..."
        Titel 'ClamAV wird geladen'
        Invoke-WebRequest -UseBasicParsing 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.msi' -OutFile $clam -TimeoutSec 300
        Laeuft 'ClamAV wird installiert' 600 'msiexec.exe' "/i `"$clam`" /qn /norestart"
    } catch { Write-Host "  ClamAV, Versuch ${try}: $($_.Exception.Message)"; Warten 10 'Pause vor dem naechsten Versuch' }
}
Write-Host "  ClamAV installiert: $(Test-Path 'C:\Program Files\ClamAV\clamd.exe')"
if ($Starten) {
    # Like on the test PC: freeze the program of a critical finding, check every PowerShell script.
    Run $k9 funktion anhalten an
    Run $k9 powershell-protokoll an
}
Run $k9 quellen aktualisieren
Rad 'Warte auf den K9-Agenten' { [bool](Get-Process k9-agent -ErrorAction SilentlyContinue) } 300
# The service loads the sources in the background: wait until the hash lists and ClamAV are there
# (at most 25 minutes; the ClamAV signatures are about 300 MB).
$ready = $false
for ($i = 0; $i -lt 75 -and -not $ready; $i++) {
    Warten 20 "K9 laedt die Erkennungsdaten (Pruefung $($i + 1) von hoechstens 75)"
    $q = (& $k9 quellen | Out-String)
    # "429" (too many requests for the large list today) does not get better by waiting.
    if ($q -match 'MalwareBazaar[^\r\n]*429' -and $q -match 'ClamAV-Signaturen[^\r\n]*Stand') {
        Write-Host '  HINWEIS: abuse.ch lehnt die grosse Hashliste heute ab (429, zu viele Abrufe) - K9 laeuft in diesem Test OHNE Hashlisten.'
        break
    }
    $ready = ($q -notmatch 'MalwareBazaar[^\r\n]*FEHLER') -and ($q -notmatch 'ClamAV-Signaturen[^\r\n]*FEHLER') -and ($q -match 'MalwareBazaar[^\r\n]*Stand') -and ($q -match 'ClamAV-Signaturen[^\r\n]*Stand')
    if ($i -eq 30 -and -not $ready) { Run $k9 quellen aktualisieren }
}
Run $k9 quellen
if (-not $ready) { Write-Host 'HINWEIS: Nicht alle Erkennungsdaten sind geladen (siehe oben) - das Ergebnis unterschaetzt K9 dann.' }
$msi = Join-Path $env:TEMP '7z-x64.msi'
Invoke-WebRequest -UseBasicParsing 'https://www.7-zip.org/a/7z2409-x64.msi' -OutFile $msi -TimeoutSec 120
Laeuft '7-Zip wird installiert' 300 'msiexec.exe' "/i `"$msi`" /qn"
$7z = 'C:\Program Files\7-Zip\7z.exe'
if (-not (Test-Path $7z)) { Write-Host '7-Zip fehlt - Abbruch.'; Stop-Transcript | Out-Null; exit 1 }

Step "B Die neuesten $Anzahl Proben von MalwareBazaar laden"
$types = 'exe', 'dll', 'msi', 'ps1', 'js', 'vbs', 'hta', 'bat', 'docm', 'xlsm', 'doc', 'xls', 'lnk', 'jar'
if ($Starten) { $types = 'exe', 'ps1', 'js', 'vbs', 'hta', 'bat' } # what can be started here without Office or Java
if ($Schwerpunkt) { $types = @('exe') }
$recent = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_recent'; selector = '100' } -TimeoutSec 120
# Half new (hours old), half older (1 to 4 weeks): signatures need time to catch up.
# At most 2 per family; samples without a family name are not one family.
$half = [Math]::Max(1, [int]($Anzahl / 2))
$fresh = @($recent.data | Where-Object { $types -contains $_.file_type })
$named = @($fresh | Where-Object { $_.signature } | Group-Object signature | ForEach-Object { $_.Group | Select-Object -First 2 })
$unnamed = @($fresh | Where-Object { -not $_.signature })
$pickNew = @(@($named) + @($unnamed) | Select-Object -First $half)
$pickNew | ForEach-Object { $_ | Add-Member -NotePropertyName gruppe -NotePropertyValue 'neu' -Force }
$now = (Get-Date).ToUniversalTime()
$pickOld = @()
foreach ($fam in 'AgentTesla', 'Formbook', 'RemcosRAT', 'AsyncRAT', 'LummaStealer', 'XWorm', 'SnakeKeylogger', 'Vidar', 'RedLineStealer', 'GuLoader', 'DCRat', 'NanoCore', 'njrat', 'QuasarRAT', 'Amadey') {
    if ($pickOld.Count -ge ($Anzahl - $pickNew.Count)) { break }
    try {
        $sig = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_siginfo'; signature = $fam; limit = '1000' } -TimeoutSec 120
    } catch { Write-Host "  ${fam}: $($_.Exception.Message)"; continue }
    $old = @($sig.data | Where-Object {
            $types -contains $_.file_type -and $_.first_seen -and
            (($now - [datetime]::ParseExact($_.first_seen, 'yyyy-MM-dd HH:mm:ss', $null)).TotalDays -ge 7) -and
            (($now - [datetime]::ParseExact($_.first_seen, 'yyyy-MM-dd HH:mm:ss', $null)).TotalDays -le 30)
        } | Select-Object -First 2)
    $old | ForEach-Object { $_ | Add-Member -NotePropertyName gruppe -NotePropertyValue 'aelter' -Force }
    Write-Host "  ${fam}: $(@($sig.data).Count) Proben, davon 7-30 Tage alt und ausgewaehlt: $($old.Count)"
    $pickOld += $old
    Start-Sleep 2
}
$pick = @($pickNew) + @($pickOld | Select-Object -First ($Anzahl - $pickNew.Count))
if ($Schwerpunkt) {
    # Info stealers first (about 60 %), ransomware last: at most 2 per family, exe only,
    # not older than 60 days (ransomware: 365 days - there are far fewer samples).
    function Alter($p) { ($now - [datetime]::ParseExact($p.first_seen, 'yyyy-MM-dd HH:mm:ss', $null)).TotalDays }
    $quote = if ($NurRansomware) { 0 } else { [Math]::Max(1, [int]($Anzahl * 0.6)) }
    $diebe = @()
    foreach ($fam in 'LummaStealer', 'Vidar', 'Stealc', 'RedLineStealer', 'RhadamanthysStealer', 'AgentTesla', 'SnakeKeylogger', 'Formbook', 'MassLogger', 'PureLogsStealer', 'ACRStealer', 'MeduzaStealer') {
        if ($diebe.Count -ge $quote) { break }
        try {
            $sig = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_siginfo'; signature = $fam; limit = '1000' } -TimeoutSec 120
        } catch { Write-Host "  ${fam}: $($_.Exception.Message)"; continue }
        $take = @($sig.data | Where-Object { $_.file_type -eq 'exe' -and $_.first_seen -and (Alter $_) -le 60 } | Select-Object -First 2)
        $take | ForEach-Object { $_ | Add-Member -NotePropertyName gruppe -NotePropertyValue 'datendieb' -Force }
        Write-Host "  Datendieb ${fam}: $(@($sig.data).Count) Proben, ausgewaehlt: $($take.Count)"
        $diebe += $take
        Start-Sleep 2
    }
    $diebe = @($diebe | Select-Object -First $quote)
    $rest = $Anzahl - $diebe.Count
    $ransom = @()
    $known = @($diebe | ForEach-Object { $_.sha256_hash })
    # By family name (the tag "ransomware" also returns stealers and adware): one sample per
    # family, the newest first; families that had recent samples on 19.11.2026 come first.
    foreach ($fam in 'LockBit', 'MedusaLocker', 'BlackMatter', 'INC', 'Makop', 'Chaos', 'Conti', 'Stop', 'BlackBasta', 'Babuk', 'WannaCry', 'Mallox', 'Maze', 'Trigona', 'Medusa', 'Hive', 'Xorist', 'Phobos', 'Akira', 'GlobeImposter') {
        if ($ransom.Count -ge $rest) { break }
        $sig = $null
        foreach ($versuch in 1..3) {
            try {
                $sig = Invoke-RestMethod -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_siginfo'; signature = $fam; limit = '100' } -TimeoutSec 120
                break
            } catch { Write-Host "  Ransomware ${fam}, Versuch ${versuch}: $($_.Exception.Message)"; Start-Sleep 5 }
        }
        if (-not $sig) { continue }
        $take = @($sig.data | Where-Object { $_.file_type -eq 'exe' -and $_.first_seen -and $known -notcontains $_.sha256_hash } | Sort-Object first_seen -Descending | Select-Object -First 1)
        Write-Host "  Ransomware ${fam}: $(@($sig.data).Count) Proben, ausgewaehlt: $($take.Count)$(if ($take.Count) { " (erstmals gesehen $($take[0].first_seen))" })"
        $ransom += $take
        Start-Sleep 2
    }
    $ransom = @($ransom | Select-Object -First $rest)
    if (-not $ransom.Count) { Write-Host '  HINWEIS: Keine Ransomware-Proben erhalten - dieser Lauf prueft nur Datendiebe.' -ForegroundColor Yellow }
    $ransom | ForEach-Object { $_ | Add-Member -NotePropertyName gruppe -NotePropertyValue 'ransomware' -Force }
    $pick = @($diebe) + @($ransom)
    $pickNew = @(); $pickOld = $pick
}
Write-Host "  ausgewaehlt: $($pick.Count) ($($pickNew.Count) neue, $($pick.Count - $pickNew.Count) aeltere)"
$rows = @()
$nr = 0
foreach ($p in $pick) {
    $nr++
    Write-Host "  Probe $nr von $($pick.Count) wird geladen ($($p.file_type) $($p.signature))"
    Titel "Probe $nr von $($pick.Count) wird geladen"
    $zip = Join-Path $zips "$($p.sha256_hash).zip"
    try {
        Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'https://mb-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $abuseKey } -Body @{ query = 'get_file'; sha256_hash = $p.sha256_hash } -OutFile $zip -TimeoutSec 120
    } catch { Write-Host "  nicht geladen: $($p.sha256_hash)"; continue }
    $trend = ''
    if ($vtKey) {
        try {
            $vt = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$($p.sha256_hash)" -Headers @{ 'x-apikey' = $vtKey } -TimeoutSec 60
            $r = $vt.data.attributes.last_analysis_results
            $trend = "$($r.TrendMicro.category)/$($r.'TrendMicro-HouseCall'.category)"
        } catch { $trend = 'unbekannt' }
        Warten 16 "Probe $nr von $($pick.Count) geladen - Pause fuer VirusTotal" # free key: at most 4 requests per minute
    }
    $age = [Math]::Round(($now - [datetime]::ParseExact($p.first_seen, 'yyyy-MM-dd HH:mm:ss', $null)).TotalDays, 1)
    $rows += [pscustomobject]@{ gruppe = $p.gruppe; alter_tage = $age; dateien = ''; sha256 = $p.sha256_hash; typ = $p.file_type; familie = $p.signature; erstmals = $p.first_seen; trendmicro_vt = $trend; k9_echtzeit = ''; k9_hashliste = ''; k9_yara = ''; k9_clamav = ''; k9_regeln = ''; defender = ''; k9_scan = ''; gestartet = ''; k9_verhalten = ''; k9_datendieb = ''; k9_ransomware = ''; koeder = ''; koeder_zugriffe = '' }
}

Step 'C Netzwerk aus - erst jetzt wird entpackt'
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
if ($Starten) {
    # Started samples must not get the network back: three locks instead of one. The adapter is
    # disabled, its device is removed, and the firewall of the sandbox blocks every connection.
    & netsh advfirewall set allprofiles state on | Out-Null
    & netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | ForEach-Object { & pnputil /remove-device $_.InstanceId 2>&1 | Out-Null }
}
# Is the network off? Asked by really trying to connect (three addresses, 1.5 s each) - without
# Windows services: on 19.11.2026 a sample disabled the service Get-NetAdapter and
# Test-Connection need, the check itself crashed and the run stopped although the network was off.
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
function NetzAus { -not (Erreichbar) }
Start-Sleep 5
$online = Erreichbar
Write-Host "  Netzwerk erreichbar: $online"
if ($online) { Write-Host 'Netzwerk ist noch an - Abbruch, nichts wurde entpackt.'; Stop-Transcript | Out-Null; exit 1 }

Step 'D Jede Probe einzeln nach Downloads entpacken (Echtzeitschutz)'
$nr = 0
foreach ($r in $rows) {
    $nr++
    $wo = "Probe $nr von $($rows.Count) ($($r.typ) $($r.familie))"
    $zip = Join-Path $zips "$($r.sha256).zip"
    $before = (& $k9 erkennungen --alle | Out-String)
    $names = & $7z l -slt -pinfected $zip | Select-String '^Path = ' | Select-Object -Skip 1 | ForEach-Object { ($_ -replace '^Path = ', '').Trim() }
    & $7z e -pinfected -y "-o$dl" $zip | Out-Null
    Warten 40 "$wo entpackt - K9 prueft die Datei" # ClamAV in real time needs 15-20 seconds the first time
    $after = (& $k9 erkennungen --alle | Out-String)
    $new = ($after -split "`n") | Where-Object { $before -notmatch [regex]::Escape($_.Trim()) -and $_.Trim() }
    $r.dateien = (@($names | ForEach-Object { Split-Path $_ -Leaf }) -join '|')
    $hit = @($new | Where-Object { $line = $_; @($names | Where-Object { $line -match [regex]::Escape((Split-Path $_ -Leaf)) }).Count -gt 0 })
    # Every rule that fired, by detection path: hash list (the sample is already known),
    # YARA and ClamAV (found by its content).
    $rules = @($hit | ForEach-Object { ($_ -split '\|')[1].Trim() } | Select-Object -Unique)
    $r.k9_regeln = $rules -join '; '
    $r.k9_echtzeit = if ($rules.Count) { 'ja' } else { 'nein' }
    $r.k9_hashliste = if ($rules | Where-Object { $_ -like 'HASH:*' }) { 'ja' } else { 'nein' }
    $r.k9_yara = if ($rules | Where-Object { $_ -like 'YARA:*' }) { 'ja' } else { 'nein' }
    $r.k9_clamav = if ($rules | Where-Object { $_ -like 'CLAMAV:*' }) { 'ja' } else { 'nein' }
    $gone = @($names | Where-Object { -not (Test-Path (Join-Path $dl (Split-Path $_ -Leaf))) }).Count
    $r.defender = if ($gone -gt 0) { "entfernt ($gone)" } else { 'nein' }
    if ($Starten) {
        $f = @($names | ForEach-Object { Join-Path $dl (Split-Path $_ -Leaf) } | Where-Object { Test-Path $_ } | Select-Object -First 1)[0]
        if ($f) {
            # As after a real download: Windows marks the file as coming from the internet.
            try { Set-Content -Path $f -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -ErrorAction Stop } catch {}
            # Samples are often named by their checksum only: give the file its type.
            if ([IO.Path]::GetExtension($f) -ne ".$($r.typ)") { $g = "$f.$($r.typ)"; try { Rename-Item $f $g -ErrorAction Stop; $f = $g } catch {} }
            if (-not (NetzAus)) {
                Write-Host 'DAS NETZWERK IST WIEDER AN - es wird nichts mehr gestartet. Bitte die Sandbox SOFORT schliessen.' -ForegroundColor Red
                $r.gestartet = 'nein (Netzwerk war wieder an)'
                break
            }
            if ($Schwerpunkt) { Titel "$wo - Koeder werden angelegt"; Koeder; Warten 20 "$wo - Koeder angelegt" } # complete decoys; let K9 finish checking them
            $b2 = (& $k9 erkennungen --alle | Out-String)
            try {
                switch ($r.typ) {
                    'exe' { Start-Process $f -ErrorAction Stop }
                    'bat' { Start-Process cmd.exe -ArgumentList "/c `"$f`"" -WindowStyle Minimized -ErrorAction Stop }
                    'ps1' { Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$f`"" -WindowStyle Minimized -ErrorAction Stop }
                    'hta' { Start-Process mshta.exe -ArgumentList "`"$f`"" -ErrorAction Stop }
                    default { Start-Process wscript.exe -ArgumentList "`"$f`"" -ErrorAction Stop }
                }
                $r.gestartet = 'ja'
            } catch { $r.gestartet = "nein ($($_.Exception.Message))" }
            Warten $(if ($Schwerpunkt) { 120 } else { 60 }) "$wo LAEUFT - K9 beobachtet"
            $a2 = (& $k9 erkennungen --alle | Out-String)
            $new2 = @(($a2 -split "`n") | Where-Object { $b2 -notmatch [regex]::Escape($_.Trim()) -and $_.Trim() })
            # Everything K9 reported after the start that is not a file signature: behaviour.
            $beh = @($new2 | ForEach-Object { ($_ -split '\|')[1].Trim() } | Where-Object { $_ -and $_ -notlike 'HASH:*' -and $_ -notlike 'YARA:*' -and $_ -notlike 'CLAMAV:*' } | Select-Object -Unique)
            $r.k9_verhalten = $beh -join '; '
            if ($Schwerpunkt) {
                $r.k9_datendieb = if ($beh | Where-Object { $_ -like 'INFOSTEALER*' -or $_ -like 'BROWSER:*' }) { 'ja' } else { 'nein' }
                $r.k9_ransomware = if ($beh | Where-Object { $_ -like 'RANSOMWARE*' }) { 'ja' } else { 'nein' }
                $r.koeder = "$(KoederHeil) von 160 Dokumenten unveraendert"
                # Did the sample open the decoy stores? Lines of the service log that name its file.
                $zugriffe = @(Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName -ErrorAction SilentlyContinue } |
                    Where-Object { $_ -match 'Zugangsdaten-Zugriff:' -and $_ -match [regex]::Escape((Split-Path $f -Leaf)) })
                $gemeldet = @($zugriffe | Where-Object { $_ -match 'Report\(' }).Count
                $r.koeder_zugriffe = "$($zugriffe.Count) Zugriffe auf Koeder-Speicher, davon $gemeldet mit Meldung, $($zugriffe.Count - $gemeldet) ohne"
            }
            # End what the sample left running in the user's folders (frozen processes too).
            Get-Process | Where-Object { $_.Path -and ($_.Path -like "$env:USERPROFILE\*" -or $_.Path -like "$env:TEMP\*" -or $_.Path -like 'C:\ProgramData\*') -and $_.Path -notlike '*\K9\*' } | Stop-Process -Force -ErrorAction SilentlyContinue
            Get-Process wscript, cscript, mshta -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            if (-not (NetzAus)) {
                Write-Host 'DAS NETZWERK IST WIEDER AN - Abbruch. Bitte die Sandbox SOFORT schliessen.' -ForegroundColor Red
                break
            }
        } else { $r.gestartet = 'nein (Datei fehlt)' }
    }
    Write-Host "  $($r.sha256.Substring(0,12)) $($r.typ) $($r.familie): K9 $($r.k9_echtzeit) [$($r.k9_regeln)], Defender $($r.defender), Trend Micro (VT) $($r.trendmicro_vt)$(if ($Starten) { " | gestartet: $($r.gestartet) | Verhalten: [$($r.k9_verhalten)]" })$(if ($Schwerpunkt) { " | $($r.koeder)" })"
}

Step 'E Scan des Downloads-Ordners'
Write-Host '  Der Scan dauert bis zu einigen Minuten; dabei bewegt sich hier nichts ...'
Titel 'Scan des Downloads-Ordners'
$scan = & $k9 scan $dl 2>&1 | Out-String
Write-Host $scan
$all = (& $k9 erkennungen --alle | Out-String)
# After the scan with all engines: every rule per sample (real time stops at the first engine
# that reports; the scan asks hash lists, YARA and ClamAV independently).
$lines = $all -split "`n"
foreach ($r in $rows) {
    $leafs = @($r.dateien -split '\|' | Where-Object { $_ })
    $mine = @($lines | Where-Object { $line = $_; @($leafs | Where-Object { $line -match [regex]::Escape($_) }).Count -gt 0 })
    # Only what recognises the FILE counts here (hash list, YARA, ClamAV) - not the
    # findings after the start (origin warning, behaviour), which name the same file.
    $rules = @($mine | ForEach-Object { ($_ -split '\|')[1].Trim() } | Where-Object { $_ -match '^(HASH|YARA|CLAMAV):' } | Select-Object -Unique)
    if ($rules.Count) { $r.k9_regeln = $rules -join '; ' }
    $r.k9_hashliste = if ($rules | Where-Object { $_ -like 'HASH:*' }) { 'ja' } else { 'nein' }
    $r.k9_yara = if ($rules | Where-Object { $_ -like 'YARA:*' }) { 'ja' } else { 'nein' }
    $r.k9_clamav = if ($rules | Where-Object { $_ -like 'CLAMAV:*' }) { 'ja' } else { 'nein' }
    $r.k9_scan = if ($rules.Count -or $r.k9_echtzeit -eq 'ja') { 'ja' } else { 'nein' }
}

Step 'F Ergebnisse'
Titel 'FERTIG - Ergebnisse stehen im Fenster'
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $out 'vergleich.csv')
$n = $rows.Count
$sum = @("Proben: $n (MalwareBazaar; Typen: $($types -join ', '))")
foreach ($g in @(@('alle', $rows), @('neu (Stunden alt)', @($rows | Where-Object gruppe -eq 'neu')), @('aelter (7-30 Tage)', @($rows | Where-Object gruppe -eq 'aelter')), @('Datendiebe', @($rows | Where-Object gruppe -eq 'datendieb')), @('Ransomware', @($rows | Where-Object gruppe -eq 'ransomware')))) {
    $set = @($g[1])
    if (-not $set.Count) { continue }
    $sum += @(
        "",
        "--- $($g[0]): $($set.Count) Proben",
        "K9 Echtzeit erkannt: $(@($set | Where-Object k9_echtzeit -eq 'ja').Count)",
        "K9 gesamt (Echtzeit oder Scan): $(@($set | Where-Object k9_scan -eq 'ja').Count)",
        "  ueber die Hashliste (Probe war schon bekannt): $(@($set | Where-Object k9_hashliste -eq 'ja').Count)",
        "  ueber YARA (am Inhalt erkannt): $(@($set | Where-Object k9_yara -eq 'ja').Count)",
        "  ueber ClamAV (am Inhalt erkannt): $(@($set | Where-Object k9_clamav -eq 'ja').Count)",
        "  am Inhalt erkannt (YARA oder ClamAV): $(@($set | Where-Object { $_.k9_yara -eq 'ja' -or $_.k9_clamav -eq 'ja' }).Count)",
        "  nur ueber die Hashliste erkannt: $(@($set | Where-Object { $_.k9_hashliste -eq 'ja' -and $_.k9_yara -ne 'ja' -and $_.k9_clamav -ne 'ja' }).Count)",
        "Windows Defender (Sandbox) entfernt: $(@($set | Where-Object defender -like 'entfernt*').Count)",
        "Nicht geprueft (Lauf vorher abgebrochen): $(@($set | Where-Object { -not $_.k9_echtzeit }).Count)",
        "Trend Micro laut VirusTotal erkannt: $(@($set | Where-Object { $_.trendmicro_vt -match 'malicious' }).Count) (nur die Engine bei VirusTotal, nicht das ganze Produkt)"
    )
}
$sum += @("", "Proben gestartet: $([bool]$Starten)")
if ($Starten) {
    $run = @($rows | Where-Object gestartet -eq 'ja')
    $sum += @(
        "--- nach dem Start: $($run.Count) Proben wirklich gestartet (Netzwerk aus)",
        "K9 hat Verhalten gemeldet bei: $(@($run | Where-Object { $_.k9_verhalten }).Count)",
        "  davon bei Proben, die als Datei NICHT erkannt wurden: $(@($run | Where-Object { $_.k9_verhalten -and $_.k9_scan -ne 'ja' }).Count)",
        "Weder als Datei noch am Verhalten erkannt: $(@($run | Where-Object { -not $_.k9_verhalten -and $_.k9_scan -ne 'ja' }).Count)",
        "Gemeldete Verhaltensregeln (Anzahl Proben):"
    )
    $sum += @($run | ForEach-Object { $_.k9_verhalten -split '; ' } | Where-Object { $_ } | ForEach-Object { ($_ -split ':')[0] } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "  $($_.Name): $($_.Count)" })
    if ($Schwerpunkt) {
        $d = @($run | Where-Object gruppe -eq 'datendieb')
        $e = @($run | Where-Object gruppe -eq 'ransomware')
        $sum += @(
            "",
            "--- SCHWERPUNKT (Koeder: Schein-Browserprofile, Schein-Wallets, 160 Schein-Dokumente; 120 s je Probe)",
            "Datendiebe gestartet: $($d.Count)",
            "  K9 meldet Zugriff auf Zugangsdaten (INFOSTEALER/BROWSER): $(@($d | Where-Object k9_datendieb -eq 'ja').Count)",
            "  K9 meldet irgendein Verhalten: $(@($d | Where-Object { $_.k9_verhalten }).Count)",
            "  Proben, die die Koeder-Speicher ueberhaupt geoeffnet haben (laut Dienst-Protokoll): $(@($d | Where-Object { $_.koeder_zugriffe -and $_.koeder_zugriffe -notlike '0 Zugriffe*' }).Count)",
            "  davon OHNE Meldung von K9 (uebersehen oder erlaubt): $(@($d | Where-Object { $_.koeder_zugriffe -and $_.koeder_zugriffe -notlike '0 Zugriffe*' -and $_.k9_datendieb -ne 'ja' }).Count)",
            "Ransomware gestartet: $($e.Count)",
            "  K9 meldet Ransomware-Verhalten (RANSOMWARE): $(@($e | Where-Object k9_ransomware -eq 'ja').Count)",
            "  K9 meldet irgendein Verhalten: $(@($e | Where-Object { $_.k9_verhalten }).Count)",
            "  Proben, die Dokumente wirklich veraendert haben: $(@($e | Where-Object { $_.koeder -and $_.koeder -notlike '160 von*' }).Count)",
            "  davon OHNE Ransomware-Meldung von K9: $(@($e | Where-Object { $_.koeder -and $_.koeder -notlike '160 von*' -and $_.k9_ransomware -ne 'ja' }).Count)"
        )
    }
    $sum += @("", "Je Probe (Typ, Familie, als Datei erkannt, Verhalten):")
    $sum += @($rows | ForEach-Object { "  $($_.typ) $($_.familie) | Datei: $($_.k9_scan) | gestartet: $($_.gestartet) | $($_.k9_verhalten)$(if ($Schwerpunkt) { " | $($_.koeder) | $($_.koeder_zugriffe)" })" })
}
$sum | Set-Content -Encoding UTF8 (Join-Path $out 'vergleich-zusammenfassung.txt')
$sum | Write-Host
& $k9 erkennungen --alle *> (Join-Path $out 'vergleich-erkennungen.txt')
Stop-Transcript | Out-Null
if ($Starten) { Write-Host "`nBitte jetzt ein Bildschirmfoto dieses Fensters machen (auf dem PC: Windows-Taste + Umschalt + S) - es gibt hier absichtlich keinen Ordner zurueck zum PC." -ForegroundColor Yellow }
Write-Host "`nTest gestartet um $($script:radBeginn.ToString('HH:mm:ss')) Uhr, beendet um $(Get-Date -Format HH:mm:ss) Uhr."
Write-Host "`nFertig. Ergebnisse (nur Text) in $out. Die Sandbox jetzt schliessen - alle Proben werden dabei verworfen."
