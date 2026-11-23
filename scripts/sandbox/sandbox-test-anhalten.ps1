<#
  Kurzlauf "Anhalten und Fortsetzen" IN DER WINDOWS-SANDBOX (nach sandbox-test-ausbau2.ps1,
  Anhalten eingeschaltet, Testprogramm mod-tool2.exe vorhanden). Agent und Dienst laufen.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

  Erwartung: Kette Kritisch -> Testprogramm angehalten; "k9 entscheiden <Nr> einmalig"
  -> Testprogramm laeuft weiter (keine angehaltenen Threads mehr).
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$out = 'C:\Ergebnis'
$k9 = 'C:\Program Files\K9\k9.exe'
Start-Transcript -Path (Join-Path $out 'protokoll-anhalten.txt') | Out-Null
function Suspended([int]$id) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $p) { return 'beendet' }
    $s = @($p.Threads | Where-Object { $_.WaitReason -eq 'Suspended' }).Count
    "$s von $($p.Threads.Count) Threads angehalten"
}
Write-Host "Agent laeuft: $([bool](Get-Process k9-agent -ErrorAction SilentlyContinue))"
$tool = Join-Path $env:USERPROFILE 'Downloads\mod-tool2.exe'
$p = Start-Process -FilePath $tool -PassThru
Start-Sleep 20
Write-Host "Testprogramm (PID $($p.Id)): $(Suspended $p.Id)"
$liste = & $k9 erkennungen 2>&1 | Out-String
# Die neueste kritische Kette (hoechste Nummer)
$nr = ($liste -split "`n" | Where-Object { $_ -match 'KETTE:ANGRIFF' -and $_ -match 'Kritisch' } |
    ForEach-Object { if ($_ -match '^\s*#(\d+)') { [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
Write-Host "Kette offen: Nr. $nr"
# Weiterlaufen lassen ist eine Abschwaechung: der Dienst fragt im Sandbox-Fenster nach (bis 120 s).
Write-Host 'Bitte jetzt im Sandbox-Fenster die Rueckfrage mit "Ja" bestaetigen.'
if ($nr) { & $k9 entscheiden $nr einmalig 2>&1 | Out-String | Write-Host }
Start-Sleep 5
Write-Host "Testprogramm (PID $($p.Id)) nach der Entscheidung: $(Suspended $p.Id)"
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
schtasks.exe /delete /tn VS-Test-Aufgabe2 /f | Out-Null
Get-ChildItem 'C:\ProgramData\K9\logs' -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ('dienst2-' + $_.BaseName + '.log')) }
Stop-Transcript | Out-Null
