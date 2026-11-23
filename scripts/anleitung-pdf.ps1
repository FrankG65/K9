# Erzeugt docs\Anleitung-K9.pdf aus docs\ANLEITUNG.md
#   1. Abschnitt "Aktueller Stand der Erkennungsdaten" aus "k9 quellen --json" füllen
#   2. k9-doc (kleines Rust-Hilfsprogramm) wandelt Markdown in druckfertiges HTML
#   3. Microsoft Edge (headless) druckt das HTML als PDF
# Aufruf:  powershell -ExecutionPolicy Bypass -File scripts\anleitung-pdf.ps1
# Wird automatisch aufgerufen vom Git-Hook (.githooks\pre-commit) und vom Agent
# nach jeder erfolgreichen Quellen-Aktualisierung.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:Path += ";$env:USERPROFILE\.cargo\bin;$env:ProgramFiles\Git\cmd"

$md = Join-Path $root "docs\ANLEITUNG.md"
$pdf = Join-Path $root "docs\Anleitung-K9.pdf"
$outDir = Join-Path $root "target\anleitung"
$html = Join-Path $outDir "Anleitung.html"
$mdFilled = Join-Path $outDir "ANLEITUNG.gefuellt.md"
New-Item -ItemType Directory -Force $outDir | Out-Null

# k9-doc bauen: immer, wenn cargo da ist (schnell, nur bei Aenderungen), sonst nur wenn es fehlt.
# Die Versionsnummer liest k9-doc ohnehin bei jedem Lauf aus Cargo.toml.
$vsdoc = Join-Path $root "target\debug\k9-doc.exe"
if ((Get-Command cargo -ErrorAction SilentlyContinue) -or -not (Test-Path $vsdoc)) {
    cmd /c "cargo build -q -p k9-doc"
    if ($LASTEXITCODE -ne 0) { throw "k9-doc konnte nicht gebaut werden" }
}

# --- Erkennungsdaten einsetzen -------------------------------------------------
$de = [Globalization.CultureInfo]::GetCultureInfo("de-DE")
function N($v) { ([int64]$v).ToString("N0", $de) }
$k9 = @("target\release\k9.exe", "target\debug\k9.exe") | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
$section = "*Keine Daten: k9.exe wurde noch nicht gebaut.*"
if ($k9) {
    $json = cmd /c "`"$k9`" quellen --json" 2>$null | Out-String
    try {
        $s = $json | ConvertFrom-Json
        $lines = @(
            "Momentaufnahme vom **$($s.stand)** (Quellen aktiv und aktuell: **$($s.quellen_ok) von $($s.quellen_aktiv)**).",
            "",
            "| Erkennungsdaten | Anzahl | davon |",
            "|---|---:|---|",
            "| Schadsoftware-Hashes | $(N $s.schadsoftware_hashes) | MalwareBazaar $(N $s.malwarebazaar_hashes), ThreatFox $(N $s.threatfox_hashes) |",
            "| Schad-/Phishing-Adressen | $(N $s.schad_adressen) | URLhaus $(N $s.urlhaus_adressen), OpenPhish $(N $s.openphish_adressen), ThreatFox $(N $s.threatfox_adressen) |",
            "| ThreatFox-IOCs gesamt | $(N $s.threatfox_iocs) | Hashes, Adressen, Domains |",
            "| YARA-Regeln | $(N $s.yara_regeln) | YARA Forge |",
            "| ClamAV-Signaturen | $(N $s.clamav_signaturen) | main, daily, bytecode |",
            "| CISA-KEV-Einträge | $(N $s.kev_eintraege) | aktiv ausgenutzte Schwachstellen |",
            "",
            "| Quelle | Einträge | zuletzt aktualisiert | Zustand |",
            "|---|---:|---|---|"
        )
        foreach ($q in $s.quellen) {
            $state = if (-not $q.aktiv) { "deaktiviert" } elseif ($q.ok) { "OK" } elseif ($q.fehler) { "Fehler" } else { "noch nicht geladen" }
            $when = if ($q.aktualisiert) { $q.aktualisiert } else { "–" }
            $lines += "| $($q.name) | $(N $q.eintraege) | $when | $state |"
        }
        $section = $lines -join "`n"
    } catch {
        $section = "*Erkennungsdaten konnten nicht gelesen werden.*"
    }
}
$text = [IO.File]::ReadAllText($md, [Text.Encoding]::UTF8)
$text = [regex]::Replace($text, '<!-- ERKENNUNGSDATEN:[^>]*-->', [Text.RegularExpressions.MatchEvaluator] { param($m) $section })
# Projektstatistik (docs\STATISTIK.md, ohne die eigene Ueberschrift)
$statMd = Join-Path $root "docs\STATISTIK.md"
$stat = if (Test-Path $statMd) { ([IO.File]::ReadAllText($statMd, [Text.Encoding]::UTF8) -replace '^# [^\r\n]*\r?\n', '') } else { "*Noch keine Statistik erzeugt.*" }
$text = [regex]::Replace($text, '<!-- STATISTIK:[^>]*-->', [Text.RegularExpressions.MatchEvaluator] { param($m) $stat })
[IO.File]::WriteAllText($mdFilled, $text, (New-Object Text.UTF8Encoding($false)))

# --- HTML und PDF -----------------------------------------------------------------
$commit = $null
try { $commit = (git rev-parse --short HEAD 2>$null) } catch { }
$stand = "Stand: " + (Get-Date -Format "dd.MM.yyyy HH:mm") + $(if ($commit) { " · Programmstand $commit" } else { "" })
cmd /c "`"$vsdoc`" `"$mdFilled`" `"$html`" `"$stand`""
if ($LASTEXITCODE -ne 0) { throw "HTML konnte nicht erzeugt werden" }

$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw "Microsoft Edge nicht gefunden" }

# Eigenes Profil, damit ein offenes Edge-Fenster nicht stört.
# Nicht in TEMP (dort prueft die Ransomware-Erkennung; das Edge-Profil schreibt komprimierte Dateien).
$profileDir = Join-Path $outDir "edge-profil"
$uri = ([Uri]$html).AbsoluteUri
$tmpPdf = Join-Path $outDir "Anleitung.pdf"
Remove-Item $tmpPdf -ErrorAction SilentlyContinue
# Edge meldet Erfolg auf stderr – das ist kein Fehler.
$ErrorActionPreference = "Continue"
& $edge --headless=new --disable-gpu --no-first-run --user-data-dir="$profileDir" --no-pdf-header-footer --generate-pdf-document-outline --print-to-pdf="$tmpPdf" $uri 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
for ($i = 0; $i -lt 60 -and -not (Test-Path $tmpPdf); $i++) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $tmpPdf)) { throw "Edge hat kein PDF erzeugt" }
Copy-Item $tmpPdf $pdf -Force

$bytes = [IO.File]::ReadAllText($pdf, [Text.Encoding]::GetEncoding(28591))
$pages = ([regex]::Matches($bytes, '/Type\s*/Page[^s]')).Count
Write-Host "PDF erzeugt: $pdf ($pages Seiten)"
