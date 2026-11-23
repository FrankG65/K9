<#
  Kurzprobe IN DER WINDOWS-SANDBOX (nach sandbox-test-infostealer.ps1, K9 installiert):
  Wird ein Zugriff mit kleingeschriebenem Pfad erkannt? Nur die Schein-Dateien des Infostealer-Tests.
  Laeuft nur im Sandbox-Konto UND wenn der Projektordner nicht existiert (also nie auf dem PC).

    P1 cmd liest die Chrome-Schein-Datei mit kleingeschriebenem Pfad und laeuft noch 5 s weiter
    P2 cmd liest die Steam-Schein-Datei mit normalem Pfad und endet sofort
  Ergebnis: Zeilen "Zugangsdaten: ..." im Dienst-Protokoll (C:\Ergebnis\probe-dienst.log).
#>
$ErrorActionPreference = 'Continue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\K9-Quelltext')) {
    Write-Host 'Nur in der Windows-Sandbox ausfuehren.'
    exit 1
}
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
$steam = Join-Path ${env:ProgramFiles(x86)} 'Steam\config\loginusers.vdf'
Write-Host "P1 $(Get-Date -Format HH:mm:ss)"
cmd.exe /c "type `"$($chrome.ToLower())`" > nul & timeout /t 5 > nul"
Start-Sleep 15
Write-Host "P2 $(Get-Date -Format HH:mm:ss)"
cmd.exe /c "type `"$steam`" > nul"
Start-Sleep 15
Get-ChildItem 'C:\ProgramData\K9\logs' -File | Sort-Object LastWriteTime | Select-Object -Last 1 |
    ForEach-Object { Copy-Item $_.FullName 'C:\Ergebnis\probe-dienst.log' }
Write-Host 'Fertig.'
