# Bilder von K9

Quellen sind die SVG-Dateien. Alle PNG- und ICO-Dateien erzeugt das Werkzeug `tools\k9-bilder`
(im Projektordner, nicht während eines Spiels):

```
cargo run --release --manifest-path tools/k9-bilder/Cargo.toml -- pictures
```

Bis 32 Pixel wird die vereinfachte Pfote ohne Schriftzug verwendet, ab 40 Pixel die Pfote mit „K9“.
Schrift der Buchstaben: Archivo Black (SIL Open Font License 1.1), in Pfade umgewandelt.

| Datei | Verwendung |
|---|---|
| `k9-pfote.svg` | Quelle des Programmsymbols ab 40 Pixel |
| `k9-pfote-klein.svg` | Quelle bis 32 Pixel (ohne Schriftzug) |
| `k9-tray-normal.svg`, `-warnung.svg`, `-kritisch.svg`, `-gestoppt.svg` | Quellen der Symbole im Infobereich |
| `favicon.svg` | Symbol im Browser-Tab des Dashboards (`/favicon.svg`) |
| `k9-logo.svg`, `k9-logo-hell.svg` | Logo (hell: für dunklen Hintergrund) |
| `k9-16.png` … `k9-1024.png` | Programmsymbol als PNG in allen Größen |
| `k9.ico` | Symbol von `k9.exe`, `k9-agent.exe`, `k9-dienst.exe` (eingebettet) und der Verknüpfung „K9-Dashboard“, Meldefenster und Bestätigungsfenster |
| `k9-tray-normal.ico` | Infobereich: alles ruhig |
| `k9-tray-warnung.ico` | Infobereich: offene Meldung (Mittel/Hoch), gelber Punkt |
| `k9-tray-kritisch.ico` | Infobereich: offene kritische Meldung, roter Punkt |
| `k9-tray-gestoppt.ico` | Infobereich: Windows-Dienst nicht erreichbar (grau) |
| `favicon.ico` | Browser-Tab des Dashboards (`/favicon.ico`) |
| `k9-logo.png` | Titelseite der PDF-Anleitung |
| `k9-logo-hell.png` | Logo für dunklen Hintergrund |
