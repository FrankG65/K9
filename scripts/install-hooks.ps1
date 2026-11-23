# Aktiviert die Git-Hooks des Projekts (Ordner .githooks), u. a. die automatische
# Aktualisierung der PDF-Anleitung bei jedem Commit.
# Aufruf (einmalig je Klon):  powershell -ExecutionPolicy Bypass -File scripts\install-hooks.ps1
$root = Split-Path -Parent $PSScriptRoot
$env:Path += ";$env:ProgramFiles\Git\cmd"
git -C $root config core.hooksPath .githooks
Write-Host "Git-Hooks aktiv: $(git -C $root config core.hooksPath)"
