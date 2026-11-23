<#
  Laeuft AUF DEM PC: startet fuer jede Ransomware-Familie eine frische Windows-Sandbox mit
  sandbox-ransomware-einzeln.ps1, sichert laufend den Stand und raeumt danach auf.
  Nur mit Zustimmung des Nutzers fuer den Tag (testlabor\sandbox\vergleich\ZUSTIMMUNG.txt: Datum,
  "starten", "ransomware"). Siehe docs\SANDBOX-TESTPLAN.md.

  Sicherheit des Ergebnisordners (der einzige Ordner, in den die Sandbox schreiben darf):
    - eigener, leerer Ordner testlabor\ransomware-uebergabe, vor jeder Sandbox geleert
    - herauskopiert wird NUR stand.txt, und nur wenn sie klein ist (< 200 KB) und ausschliesslich
      druckbare ASCII-Zeichen enthaelt; die Kopien liegen in testlabor\ransomware-ergebnis
    - alles andere in dem Ordner wird nach jeder Sandbox UNGEOEFFNET geloescht
  Zwischenspeicher (USB-Stick, nur fuer diesen Zweck): MalwareBazaar begrenzt die Abrufe je Tag.
  Die erste Sandbox uebergibt das noch verschluesselte Archiv der Probe, dieses Skript legt es
  ungeoeffnet auf den Stick (nur echte, verschluesselte ZIP-Archive bis 60 MB); alle weiteren
  Sandboxen lesen es von dort (nur lesbar eingebunden). Auf dem PC wird nie etwas ausgepackt.
  Leeren: ransomware-reihe.ps1 -ZwischenspeicherLeeren
  Dieses Skript beendet keine Prozesse: Die Sandbox faehrt sich selbst herunter (Skript am Ende,
  sonst die Notbremse nach 16 Minuten).

  Aufruf (PowerShell im Projektordner):
    powershell -ExecutionPolicy Bypass -File scripts\sandbox\ransomware-reihe.ps1 -Familien LockBit,Makop -Anhalten aus,an
#>
param(
    [string[]]$Familien = @('LockBit', 'MedusaLocker', 'BlackMatter', 'INC', 'Makop', 'Chaos', 'Conti', 'Stop', 'BlackBasta', 'Babuk'),
    [ValidateSet('an', 'aus')][string[]]$Anhalten = @('aus', 'an'),
    [ValidateRange(1, 8)][int]$Minuten = 3,
    # Switch "neue-programme" on inside the sandbox (since 0.39.0).
    [switch]$NeueProgramme,
    # Cache for the still encrypted sample archives: a folder on a removable drive named "K9"
    # (a USB stick only for this purpose). '' = no cache, every sandbox downloads itself.
    [string]$Zwischenspeicher = 'E:\K9-Proben',
    # Only empty the cache and end.
    [switch]$ZwischenspeicherLeeren
)
$ErrorActionPreference = 'Stop'
$projekt = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$labor = Join-Path $projekt 'testlabor'
$sandbox = Join-Path $labor 'sandbox'
$uebergabe = Join-Path $labor 'ransomware-uebergabe'
$ergebnis = Join-Path $labor 'ransomware-ergebnis'
# The cache must be a folder on a removable drive with the volume name "K9".
function LagerPruefen([string]$ordner) {
    if (-not $ordner) { return $false }
    $lw = Split-Path $ordner -Qualifier
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$lw'" -ErrorAction SilentlyContinue
    if (-not $d -or $d.DriveType -ne 2 -or $d.VolumeName -ne 'K9') { Write-Host "Zwischenspeicher ${ordner}: kein Wechseldatentraeger mit dem Namen K9 - es wird ohne Zwischenspeicher gearbeitet."; return $false }
    New-Item -ItemType Directory -Force $ordner | Out-Null
    $true
}
if ($ZwischenspeicherLeeren) {
    if (LagerPruefen $Zwischenspeicher) {
        Get-ChildItem -LiteralPath $Zwischenspeicher -Force | Remove-Item -Recurse -Force
        Write-Host "Zwischenspeicher geleert: $(@(Get-ChildItem -LiteralPath $Zwischenspeicher -Force).Count) Dateien uebrig."
    }
    exit 0
}
$lager = if (LagerPruefen $Zwischenspeicher) { $Zwischenspeicher } else { '' }
$heute = Get-Date -Format 'dd.MM.yyyy'
$z = Get-Content (Join-Path $sandbox 'vergleich\ZUSTIMMUNG.txt') -Raw
if ($z -notmatch [regex]::Escape($heute) -or $z -notmatch '(?im)^\s*starten\s*$' -or $z -notmatch '(?im)^\s*ransomware\s*$') { throw "Keine Zustimmung fuer heute ($heute)." }
Copy-Item (Join-Path $PSScriptRoot 'sandbox-ransomware-einzeln.ps1') $sandbox -Force
New-Item -ItemType Directory -Force $uebergabe, $ergebnis | Out-Null

# Takes an encrypted sample archive handed over by the sandbox into the cache - unopened.
# Only a real ZIP archive (signature PK 03 04) whose first entry is encrypted (bit 0 of the
# flags), at most 60 MB, with the expected name.
$script:uebernahmeFehler = 0
function ArchivUebernehmen([string]$fam) {
    if (-not $lager) { return }
    $zip = Join-Path $uebergabe "probe-$fam.zip"
    $txt = Join-Path $uebergabe "probe-$fam.txt"
    if (-not (Test-Path -LiteralPath $zip)) { return }
    # The sandbox writes the archive first and the note with the checksum after it. Decide only
    # when both are there; this function is called again every two seconds.
    if (-not (Test-Path -LiteralPath $txt)) { return }
    try {
        $i = Get-Item -LiteralPath $zip -ErrorAction Stop
        $ok = $i.Length -gt 100 -and $i.Length -le 60MB -and -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)
        if ($ok) {
            # Share everything: on 21.11.2026 the archive could not be opened for five tries in a
            # row ("used by another process") - the sandbox side still holds the file, and with
            # the share mode "read only" Windows refuses the open as long as anyone may write.
            $fs = [IO.File]::Open($zip, 'Open', 'Read', 'ReadWrite, Delete'); $b = New-Object byte[] 8; [void]$fs.Read($b, 0, 8); $fs.Close()
            $ok = $b[0] -eq 0x50 -and $b[1] -eq 0x4B -and $b[2] -eq 3 -and $b[3] -eq 4 -and ($b[6] -band 1) -eq 1
        }
        $info = ''
        if ($ok -and (Test-Path -LiteralPath $txt)) {
            $t = [IO.File]::ReadAllBytes($txt)
            if ($t.Length -le 300) { $info = -join ($t | Where-Object { $_ -ge 32 -and $_ -le 126 } | ForEach-Object { [char]$_ }) }
        }
        if ($ok -and $info -match '^[0-9a-f]{64} ') {
            # Copied through a shared handle (not moved): the source may still be held open.
            $ein = [IO.File]::Open($zip, 'Open', 'Read', 'ReadWrite, Delete')
            try { $aus = [IO.File]::Create((Join-Path $lager "$fam.zip")); try { $ein.CopyTo($aus) } finally { $aus.Close() } } finally { $ein.Close() }
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            Set-Content -LiteralPath (Join-Path $lager "$fam.txt") $info -Encoding ASCII
            Write-Host "  Probe $fam im Zwischenspeicher abgelegt ($([int]($i.Length / 1KB)) KB, verschluesseltes Archiv)"
        } else {
            Write-Host "  Uebergebenes Archiv $fam nicht uebernommen (kein verschluesseltes ZIP oder Angaben fehlen)"
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $txt -Force -ErrorAction SilentlyContinue
    } catch {
        # The sandbox still has the file open (seen on 21.11.2026: the first try failed, the note
        # was deleted anyway and the valid archive was then thrown away). Nothing is removed
        # here - the next round tries again; what is left is emptied after the run.
        # Run of 21.11.2026, 15:18: the archive was again not taken and nothing was printed.
        # Since then the reason is shown: every other error at once, a locked file from the
        # fifth failed try on (once), so that a lasting lock no longer stays invisible.
        $script:uebernahmeFehler++
        if ($_.Exception -isnot [System.IO.IOException]) { Write-Host "  Zwischenspeicher: $($_.Exception.GetType().Name): $($_.Exception.Message)" }
        elseif ($script:uebernahmeFehler -eq 5) { Write-Host "  Zwischenspeicher: Archiv seit 5 Versuchen nicht lesbar - $($_.Exception.GetType().Name): $($_.Exception.Message)" }
    }
}

function SandboxLaeuft { [bool](Get-Process -Name 'WindowsSandbox*', 'vmmemWindowsSandbox' -ErrorAction SilentlyContinue) }
function Leeren { Get-ChildItem -LiteralPath $uebergabe -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
# Only a small file of printable ASCII is taken over (never anything a sample may have written).
function StandLesen {
    $f = Join-Path $uebergabe 'stand.txt'
    try {
        $i = Get-Item -LiteralPath $f -ErrorAction Stop
        if ($i.Length -eq 0 -or $i.Length -gt 200KB -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $null }
        $b = [IO.File]::ReadAllBytes($f)
        foreach ($x in $b) { if (-not ($x -eq 10 -or $x -eq 13 -or ($x -ge 32 -and $x -le 126))) { return $null } }
        [Text.Encoding]::ASCII.GetString($b)
    } catch { $null }
}

foreach ($fam in $Familien) {
    if ($fam -notmatch '^[A-Za-z0-9]+$') { throw "Ungueltiger Familienname: $fam" }
    foreach ($modus in $Anhalten) {
        if (SandboxLaeuft) { throw 'Es laeuft noch eine Sandbox - bitte zuerst schliessen.' }
        Leeren
        $name = "$fam-$modus"
        $ziel = Join-Path $ergebnis "$name.txt"
        $wsb = Join-Path $labor 'ransomware-lauf.wsb'
        @"
<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Enable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$sandbox</HostFolder>
      <SandboxFolder>C:\Testlabor</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$uebergabe</HostFolder>
      <SandboxFolder>C:\Ergebnis</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
$(if ($lager) { "    <MappedFolder>`r`n      <HostFolder>$lager</HostFolder>`r`n      <SandboxFolder>C:\Proben</SandboxFolder>`r`n      <ReadOnly>true</ReadOnly>`r`n    </MappedFolder>" })
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c start "K9 Ransomware-Test $name" powershell.exe -NoExit -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-ransomware-einzeln.ps1 -Familie $fam -Anhalten $modus -Minuten $Minuten$(if ($NeueProgramme) { ' -NeueProgramme' })</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $wsb -Encoding ASCII
        Write-Host "$(Get-Date -Format HH:mm:ss) Sandbox fuer $name startet"
        Start-Process -FilePath $wsb
        $beginn = Get-Date
        $letzter = ''
        $gesehen = $false
        while ($true) {
            Start-Sleep 2
            ArchivUebernehmen $fam
            $t = StandLesen
            # Keep the longest valid version: a later, encrypted or shortened file does not replace it.
            if ($t -and $t.Length -gt $letzter.Length) { $letzter = $t; [IO.File]::WriteAllText($ziel, $t, [Text.Encoding]::ASCII) }
            $laeuft = SandboxLaeuft
            if ($laeuft) { $gesehen = $true }
            $min = ((Get-Date) - $beginn).TotalMinutes
            if ($gesehen -and -not $laeuft) { break }
            if (-not $gesehen -and $min -gt 3) { Write-Host '  Sandbox ist nicht gestartet.'; break }
            if ($min -gt 25) { Write-Host '  Sandbox laeuft nach 25 Minuten noch - bitte von Hand schliessen. Reihe wird beendet.'; Leeren; exit 2 }
        }
        Leeren
        $letzte = @($letzter -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
        Write-Host "$(Get-Date -Format HH:mm:ss) $name beendet nach $([int]((Get-Date) - $beginn).TotalMinutes) min; letzter Stand: $letzte"
        Start-Sleep 10
    }
}
Remove-Item -LiteralPath (Join-Path $labor 'ransomware-lauf.wsb') -Force -ErrorAction SilentlyContinue
Write-Host "Fertig. Ergebnisse (nur Text): $ergebnis"
