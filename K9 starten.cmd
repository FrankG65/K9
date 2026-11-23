@echo off
rem Startet den K9-Agent und oeffnet das Dashboard im Browser.
rem Laeuft der Agent schon (z. B. per Autostart), wird nur das Dashboard
rem geoeffnet - es startet nie ein zweiter Agent.
rem Fenster offen lassen - Schliessen oder Strg+C beendet den Agent.
chcp 65001 >nul
rem Mit eingerichtetem Dienst laeuft der Agent aus C:\Program Files\K9.
if exist "%ProgramFiles%\K9\k9-agent.exe" (
    cd /d "%ProgramFiles%\K9"
) else (
    cd /d "%~dp0target\release"
)
if not exist k9-agent.exe (
    echo k9-agent.exe fehlt - bitte zuerst bauen: cargo build --release
    pause
    exit /b 1
)
k9-agent.exe --browser
rem Exitcode 3 = Agent lief bereits, Dashboard wurde geoeffnet
if errorlevel 3 if not errorlevel 4 (
    timeout /t 4 >nul
    exit /b 0
)
pause
