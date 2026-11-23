# K9 – Anleitung

Diese Anleitung enthält alle Schritte, Einstellungen, PowerShell-Befehle und Hinweise.
Sie wird bei jeder Änderung am Programm mit aktualisiert (Änderungsverlauf im Anhang).

# Teil 1 – Kurzanleitung

## Wichtige Abläufe

**a) Nach jedem Neustart: Remote Control für Claude starten**

Eine **normale** PowerShell öffnen (nicht „als Administrator“ – die startet in `C:\WINDOWS\system32`
und gehört nicht zum Projekt):

```
cd "C:\K9-Quelltext"
$env:Path += ";$env:USERPROFILE\.local\bin"
claude remote-control
```

Das Fenster offen lassen, solange Claude arbeiten soll.

Einmalig und dauerhaft (danach reicht `claude remote-control` ohne die `$env:Path`-Zeile; die
PowerShell danach neu öffnen):

```
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path","User") + ";$env:USERPROFILE\.local\bin", "User")
```

**b) Neue Version installieren** (normale PowerShell, Windows fragt nach Administratorrechten → „Ja“):

```
& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren
```

**c) Treiber prüfen** (nur lesen, ändert nichts):

```
& "C:\Program Files\K9\k9.exe" treiber
```

**d) Verwaiste Treiber-Reste entfernen** (PowerShell **als Administrator**, in dieser Reihenfolge;
Einzelheiten im Kapitel „Treiberprüfung“). `-Satz` wählt die Treiber: `Verwaist` (GIGABYTE,
Thrustmaster, inpoutx64, Colasoft), `Asus` (erst wenn keine ASUS-Software mehr installiert ist) oder
ohne Angabe Creative/Corel:

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase Pruefen
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase 1
```

Dann über Start → Ein/Aus **„Neu starten“** (nicht „Herunterfahren“), danach:

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase 2
```

Falls danach etwas fehlt: `... -Satz Verwaist -Phase Wiederherstellen` und neu starten.

**e) Zustand und Dashboard**

```
& "C:\Program Files\K9\k9.exe" status
& "C:\Program Files\K9\k9.exe" dienst status
& "C:\Program Files\K9\k9.exe" dashboard
```

**f) Dashboard wieder öffnen** (z. B. nach dem Schließen des Browsers)

1. **Verknüpfung „K9-Dashboard“** auf dem Desktop oder im Startmenü anklicken. Sie wird von
   `k9 dienst installieren`/`aktualisieren` angelegt bzw. erneuert und von `dienst deinstallieren`
   wieder entfernt. Sie startet `k9.exe dashboard` minimiert, es erscheint kein Konsolenfenster
   im Vordergrund.
2. Oder in einer **normalen** PowerShell (keine Administratorrechte nötig):

   ```
   & "C:\Program Files\K9\k9.exe" dashboard
   ```

   Das öffnet das Dashboard im Browser. Der Agent muss laufen – das tut er normalerweise immer, der
   Dienst startet ihn automatisch.
3. Oder Doppelklick auf `C:\K9-Quelltext\K9 starten.cmd`: Läuft der Agent schon, öffnet
   sich nur das Dashboard; ein zweiter Agent wird nie gestartet.
4. Ist das Dashboard offen, kannst du es im Browser als **Lesezeichen** speichern – das funktioniert
   dauerhaft.

Die Adresse `http://127.0.0.1:47110` allein reicht nicht: Das Dashboard ist nur auf diesem PC erreichbar
und verlangt einen Zugangsschlüssel. Den hängt `k9 dashboard` automatisch an. Der Schlüssel liegt
geschützt in der Windows-Anmeldeinformationsverwaltung und ändert sich auch nach einem Neustart nicht.

**g) Funktionen ein- und ausschalten** (normale PowerShell, keine Administratorrechte nötig)

```
cd "C:\Program Files\K9"
.\k9.exe funktion status
.\k9.exe funktion anhalten an
.\k9.exe funktion ransomware-anhalten an
.\k9.exe funktion neue-programme an
.\k9.exe funktion virustotal an
.\k9.exe funktion firewall an
.\k9.exe funktion schattenkopien an
```

`k9 funktion` ändert in `config.toml` nur die eine Zeile (Kommentare bleiben, ein fehlender
Abschnitt wird einmal angelegt); zweimal ausführen schadet nicht. Namen: `anhalten`,
`ransomware-anhalten`, `neue-programme`, `virustotal`, `sigma`, `lolbas`, `yara-erweitert`, `schad-domains`, `spamhaus-drop`,
`firewall`, `schattenkopien`, `angriffsketten`, `download-herkunft`, `skriptpruefung`, `datendiebe`,
`anmeldungen`, `sicherheitscheck`, `programm-updates`, `wochenbericht`, `heimnetz`, `neue-luecken`,
`speicher-scan`.

- **Einschalten** wirkt sofort: Der Dienst übernimmt es innerhalb von 30 Sekunden, ohne Neustart.
  Ausnahme `skriptpruefung`, `datendiebe`, `ransomware-anhalten` und `neue-programme`: Die wirken erst nach dem nächsten Start des Dienstes
  (PC neu starten oder `k9 dienst aktualisieren`) – das sagt der Befehl auch.
- **Ausschalten** (`… aus`) schwächt den Schutz: Die Funktion bleibt an, bis du im Meldefenster
  „Sicherheitseinstellung wurde abgeschwächt“ **„Änderung übernehmen“** wählst und im
  Bestätigungsfenster mit „Ja“ zustimmst. Warst du das nicht, „Gesehen“ wählen und vollständig
  scannen.
- Für VirusTotal brauchst du einmal den Schlüssel: `.\k9.exe geheimnis virustotal-key` (Eingabe
  bleibt unsichtbar). Einen gespeicherten Schlüssel ersetzen oder löschen musst du bestätigen.
- Ob Windows Speicher für Schattenkopien hat, zeigt (PowerShell **als Administrator**, nur lesen):
  `vssadmin list shadowstorage`.
- Weitere Laufwerke für Schattenkopien (normale PowerShell), z. B. C: und F::
  `.\k9.exe funktion schattenkopien laufwerke C: F:`

**h) K9 vorübergehend pausieren und wieder aktivieren** (normale PowerShell)

Pausieren (1 bis 240 Minuten, ohne Angabe 60). Du bestätigst mit „j“ und danach im kleinen Fenster
„K9-Agent pausieren?“ mit „Ja“:

```
& "C:\Program Files\K9\k9.exe" agent-beenden --minuten 60
```

Pausiert ist der Agent: Prüfung neuer Dateien, Meldefenster, Dashboard, Symbol im Infobereich,
geplante Scans. Der Windows-Dienst prüft weiter (Programmstarts, DNS, PowerShell-Skripte,
Datendiebe); was er in der Pause findet, zeigt der Agent danach. Nach Ablauf startet der Dienst den
Agent von selbst wieder – ohne Alarm.

Pause **vorzeitig beenden** und K9 wieder aktivieren – keine Bestätigung nötig (es verstärkt den
Schutz). Der Befehl beendet die Pause beim Dienst und startet den Agent unsichtbar wie bei der
Anmeldung; ein zweiter Agent startet nie:

```
& "C:\Program Files\K9\k9.exe" pause-beenden
```

Ausgabe: „Pause beendet, Agent laeuft.“ (bzw. „Keine Pause aktiv, Agent laeuft bereits.“).
Mit einer älteren Version ohne diesen Befehl geht es so (der Dienst beendet die Pause dann nach
wenigen Sekunden selbst):

```
& "$env:SystemRoot\System32\conhost.exe" --headless "C:\Program Files\K9\k9-agent.exe"
```

Prüfen, ob der Agent wieder läuft (Zeile „Agent : laeuft“), und das Dashboard öffnen:

```
& "C:\Program Files\K9\k9.exe" status
& "C:\Program Files\K9\k9.exe" dashboard
```

Die Verknüpfung „K9-Dashboard“ öffnet nur das Dashboard – sie startet den Agent **nicht** und
beendet die Pause nicht. Fürs Spielen musst du nicht pausieren: Der Spielmodus schaltet von selbst
auf leichte Prüfungen; sofort erscheinen dann nur Ransomware-Alarme und kritische Meldungen zu
Datendieben, Angriffsketten, Browser-Fernsteuerung und Manipulation.

**i) Firewall-Sperre kurz abschalten** (z. B. wenn ein Programm keine Verbindung bekommt)

Die K9-Regeln „K9 – Botnetz-Server gesperrt …“ stellt der Dienst sofort wieder her, wenn sie jemand
löscht oder ändert – auch wenn du das selbst in der Firewall-Konsole tust. Absichtlich abschalten
geht nur über K9 (PowerShell **als Administrator**, danach im Fenster „Firewall-Sperre vorübergehend
entfernen?“ mit „Ja“ bestätigen):

```
& "C:\Program Files\K9\k9.exe" firewall entfernen
```

Die Regeln bleiben dann weg bis zur nächsten regulären Erneuerung (täglich, neue ThreatFox-Daten
oder Neustart des Dienstes). Dauerhaft aus (normale PowerShell, mit Bestätigung):

```
& "C:\Program Files\K9\k9.exe" funktion firewall aus
```

## Schnellhilfe – häufige Befehle

> **Wichtig:** Das Schließen des Browser-Fensters beendet den Agent **nicht** – der Schutz läuft
> weiter. Das Dashboard kannst du jederzeit wieder öffnen.

Alle Befehle in PowerShell. Zuerst immer in den Programmordner wechseln:

```
cd "C:\Program Files\K9"
```

Der Programmordner ist `C:\Program Files\K9` (im deutschen Explorer heißt er
„C:\Programme\K9“ – das ist derselbe Ordner), sobald der Windows-Dienst eingerichtet ist
(dorthin kopiert `k9 dienst installieren`/`aktualisieren` die Programme). Ohne Dienst liegen
die Programme im Build-Ordner: `cd "C:\K9-Quelltext\target\release"`.

| Ich möchte … | Befehl |
|---|---|
| das Dashboard wieder öffnen (z. B. nach dem Schließen des Browsers) | `.\k9.exe dashboard` |
| sehen, ob der Agent läuft (und Quellen, Zeitpläne, Warnungen) | `.\k9.exe status` |
| den Agent beenden (fragt nach „j“ zur Bestätigung) | `.\k9.exe agent-beenden` |
| den Windows-Dienst einrichten (einmalig, UAC mit „Ja“ bestätigen) | `.\k9.exe dienst installieren` |
| sehen, ob der Windows-Dienst läuft | `.\k9.exe dienst status` |
| nach einem neuen Build die Programme aktualisieren (UAC) | `& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren` |
| den Agent bei der Windows-Anmeldung automatisch starten | `.\k9.exe autostart-agent an` |
| den automatischen Start wieder ausschalten | `.\k9.exe autostart-agent aus` |
| prüfen, ob der automatische Start eingeschaltet ist | `.\k9.exe autostart-agent status` |
| offene Funde in der Konsole sehen | `.\k9.exe erkennungen` |
| einen Ordner sofort prüfen | `.\k9.exe scan "C:\Ordner"` |
| den ganzen PC prüfen | Dashboard, Kasten „Status“ → „Vollständiger Scan (schonend)“ oder „(schnell)“ |

Komplettes Beispiel, Dashboard wieder öffnen:

```
cd "C:\Program Files\K9"
.\k9.exe dashboard
```

**Doppelklick auf „K9 starten.cmd“** ist immer sicher: Läuft der Agent schon (z. B. durch
den Autostart), öffnet sich nur das Dashboard – es startet nie ein zweiter Agent.

# Teil 2 – Bedienung

## Überblick

K9 ist ein **Begleit-Scanner**: Er läuft zusätzlich zu deinem Virenschutz
(Trend Micro Maximum Security) und ändert dort nichts.

- **Nichts passiert automatisch beim ersten Fund.** Jede neue Erkennung wird gemeldet,
  du entscheidest: Quarantäne, Löschen/Deaktivieren, Freigabe (bei Software: „Hinweis gesehen“ oder „Ignorieren“).
- **Deine Entscheidung wird gemerkt.** Derselbe Fund meldet sich danach nicht mehr.
  Entscheidungen kannst du jederzeit ansehen und widerrufen.
- **Gaming hat Vorrang.** Während ein Spiel läuft, gibt es keine geplanten Scans und keine Fenster;
  Meldungen kommen nach dem Spiel.

| Prüfung | Was wird geprüft |
|---|---|
| Dateien | YARA-Regeln, ClamAV, Hashlisten (MalwareBazaar, ThreatFox), Schad-/Phishing-Adressen in .url/.html/.eml/.svg |
| Verwundbare Software | installierte Programme gegen aktiv ausgenutzte Lücken (CISA KEV + NVD) |
| Phishing-Adressen | Browserverlauf (Chrome, Edge, Brave, Vivaldi, Opera, Firefox) und hosts-Datei |
| Autostarts | Run-Einträge, Autostart-Ordner, geplante Aufgaben, Dienste, versteckte WMI-Autostarts |
| Konten und Anmeldungen | neue Benutzerkonten, neue Administratoren, Remotedesktop-Anmeldungen, viele falsche Passwörter, gelöschtes Sicherheitsprotokoll |
| Echtzeitschutz | neue Dateien, Programmstarts, neue Autostarts, Verbindungen, Ransomware-Verhalten, USB-Sticks (Teil 3, „Echtzeitschutz“) |

Programme (nach dem Bauen in `C:\K9-Quelltext\target\release`):

- `k9-agent.exe` – Hintergrund-Agent mit Dashboard und Meldefenster
- `k9.exe` – Befehle für die Eingabeaufforderung/PowerShell

## Meldungen: Meldefenster, Dashboard, E-Mail, Handy

**Symbol im Infobereich (unten rechts neben der Uhr):** Die orange Pfote zeigt den Zustand auf einen
Blick – ohne Punkt: alles ruhig; gelber Punkt: offene Meldung (Mittel/Hoch); roter Punkt: offene
kritische Meldung; grau: der Windows-Dienst ist nicht erreichbar. Linksklick öffnet das Dashboard,
Rechtsklick zeigt „Dashboard öffnen“. Der Zustand wird alle 30 Sekunden aktualisiert. Ist die Pfote
unter „Ausgeblendete Symbole“ (Pfeil), kannst du sie in die Taskleiste ziehen.

**Überschrift des Dashboards:** das K9-Symbol (orange Pfote mit dem Schriftzug „K9“) und daneben
die Versionsnummer (z. B. 0.2.2), klein und unten bündig mit der Pfote. Fährst du mit der Maus über Symbol oder Nummer (oder springst mit
der Tab-Taste hin), erscheint darunter ein Feld mit der Bauzeit und – wenn die Version genau einem
gespeicherten Stand entspricht – dem Commit. Dieselbe Nummer zeigen `k9 --version`, `k9 status`, `k9 dienst status` und das
Dienst-Protokoll beim Start. Sie steigt mit jeder Version, die du installierst; im
Änderungsverlauf steht bei jeder Zeile die Version.

**Ton:** Öffnet sich ein Meldefenster oder das Bestätigungsfenster, spielt Windows den Ton „Warnung“
(die Testmeldung: „Hinweis“) aus deinem Windows-Soundschema – Lautstärke und Klang stellst du dort ein.

Standard sind **Meldefenster** und **Dashboard**. Einstellung in `config.toml`:

```
[meldungen]
kanaele = ["fenster", "dashboard"]
spaeter_minuten = 60
```

| Kanal | Bedeutung |
|---|---|
| `fenster` | eigenes Fenster mit Schaltflächen (Quarantäne, Löschen, Freigabe, Später). Funktioniert auch, wenn Windows-Benachrichtigungen aus sind. |
| `popup` | Windows-Benachrichtigung – nur, wenn diese in Windows eingeschaltet sind (Einstellungen → System → Benachrichtigungen). |
| `dashboard` | offene Funde im Browser-Dashboard |
| `email` | E-Mail über SMTP mit TLS (Teil 5, „Schlüssel und Passwörter“) |
| `handy` | Push-Nachricht über ntfy (Teil 5, „Schlüssel und Passwörter“) |

„Später“ oder Schließen des Fensters entscheidet nichts – du wirst nach `spaeter_minuten`
erneut gefragt. Während eines Spiels erscheint kein Fenster.

**Dashboard öffnen:** Verknüpfung „K9-Dashboard“ auf dem Desktop oder im Startmenü, in einer
normalen PowerShell `& "C:\Program Files\K9\k9.exe" dashboard` oder Doppelklick auf `C:\K9-Quelltext\K9 starten.cmd`. Der Agent muss laufen (der Dienst
startet ihn automatisch). `http://127.0.0.1:47110` allein im Browser reicht nicht, weil das Dashboard
einen Zugangsschlüssel verlangt; `k9 dashboard` hängt ihn an. Der Schlüssel liegt dauerhaft in der
Windows-Anmeldeinformationsverwaltung – ein Lesezeichen der geöffneten Seite funktioniert deshalb auch
nach einem Neustart. Einzelheiten: „Wichtige Abläufe“, Punkt f (Teil 1).

Meldekanal testen:

```
.\k9.exe test-meldung fenster
.\k9.exe test-meldung email
.\k9.exe test-meldung handy
```

## Scannen: Schnellscan und vollständiger Scan

Im Dashboard stehen im Kasten **„Status“** (dem dritten von oben) drei Schaltflächen zum Scannen
(seit Version 0.27.0). Alle drei **melden nur** – nichts wird automatisch verschoben oder gelöscht.

| Schaltfläche | Was geprüft wird | Tempo | Wenn ein Spiel läuft |
|---|---|---|---|
| **Schnellscan (Standardordner)** | Downloads, Desktop, Dokumente und Temp-Ordner (`[scan] standard_pfade`), dazu installierte Programme, Adressen und Autostarts | wenige Prüfstränge (`max_threads`, Standard 2) | läuft sofort, auch während eines Spiels |
| **Vollständiger Scan (schonend)** | alle eingebauten Laufwerke und eingesteckten USB-Datenträger, dazu Programme, Adressen und Autostarts | wenige Prüfstränge (`max_threads`) – du kannst dabei weiterarbeiten, es dauert am längsten | pausiert, bis das Spiel beendet ist |
| **Vollständiger Scan (schnell)** | dasselbe | ein Drittel der Prozessorkerne als Prüfstränge, mindestens 4 und höchstens 16 (auf dem Test-PC mit 48 Prozessorkernen: 16; bis Version 0.41.0: 8) – für die Nacht oder wenn du nicht am PC sitzt; der PC reagiert in dieser Zeit träger | pausiert, bis das Spiel beendet ist |

**Gemessen am 22.11.2026 auf dem Test-PC** (48 Prozessorkerne; 9,4 GB in 36.667 Dateien aus dem
Windows-Systemordner, nur lesend, alle Prüfungen außer ClamAV; die Daten lagen dabei schon im
Arbeitsspeicher, die Festplatte hat also nicht gebremst):

| Prüfstränge | Dauer | Durchsatz | genutzte Kerne |
|---|---|---|---|
| 8 (bisher) | 34 bis 37 s | rund 270 MB/s | 7,6 |
| **16 (jetzt)** | **19 s** | **rund 500 MB/s** | 14,7 |
| 24 | 16 s | rund 590 MB/s | 18,2 |
| 32 | 16 s | rund 580 MB/s | 18,6 |

Mit 16 Prüfsträngen ist der schnelle Scan knapp doppelt so schnell wie bisher. Darüber bringt es
kaum noch etwas, und mit 16 bleiben zwei Drittel des Prozessors für dich frei. Auf einer Festplatte,
deren Daten noch nicht im Arbeitsspeicher liegen, kann das Lesen bremsen – dann ist der Gewinn
kleiner. Der schonende Scan und alle anderen Prüfungen bleiben bei den wenigen Prüfsträngen aus
`[scan] max_threads` (höchstens 8).

**Wie sich das beim Arbeiten anfühlt:** Während der Messung (drei Minuten, zuletzt mit 24 und 32
Prüfsträngen) wurde am Test-PC weitergearbeitet, ohne dass etwas zu bemerken war. Bei 48 Kernen
bleibt genug Reserve. Der Hinweis „der PC reagiert in dieser Zeit träger“ gilt deshalb vor allem
für PCs mit weniger Kernen. Beim Spielen pausiert der Scan ohnehin.

- **Fortschritt:** Solange ein Scan läuft, zeigt die Zeile „Scan läuft“ die Art des Scans, wie viele
  Dateien er schon erreicht hat und in welchem Ordner er gerade ist. Die Zeile aktualisiert sich
  alle 2 Sekunden von selbst, ohne dass die Seite neu lädt – du kannst währenddessen im Dashboard
  weiterarbeiten. Ist der Scan fertig, lädt die Seite einmal neu; das Ergebnis steht dann in der
  Zeile „Letzter Scan“.
- **„Scan abbrechen“:** Während eines Scans steht an der Stelle der drei Schaltflächen nur noch
  diese eine. Der Scan endet nach der Datei, die gerade geprüft wird; was bis dahin gefunden wurde,
  bleibt als Meldung erhalten. Abbrechen lässt sich jeder Scan, auch ein geplanter.
- **Welche Laufwerke:** eingebaute Festplatten und SSDs sowie eingesteckte USB-Sticks und
  Speicherkarten. Netzlaufwerke und CD/DVD-Laufwerke gehören nicht dazu. Es gelten deine Ausnahmen
  (`[scan] ausnahmen`) und die Größengrenze (`max_dateigroesse_mb`), siehe Teil 5, „Konfiguration“.
- **Wie lange es dauert,** hängt von der Datenmenge ab und ist noch nicht gemessen;
  ein vollständiger Scan großer Laufwerke kann Stunden dauern. Dein Virenschutz prüft in der Regel
  jede Datei mit, die K9 dabei öffnet – auch das kostet Zeit.
- **„Schnell“ heißt 8 Prüfstränge.** Mehr lässt der Scanner derzeit nicht zu, auch wenn dein PC
  mehr Prozessorkerne hat. Die Windows-Prioritätsstufen „Hoch“ und „Echtzeit“ nutzt K9 bewusst
  nicht: Damit könnten Maus, Ton und andere Schutzprogramme ins Stocken geraten.
- Wo eine Meldung rät, „einen vollständigen Scan zu starten“, ist eine der beiden Schaltflächen
  „Vollständiger Scan“ gemeint. Einen einzelnen Ordner prüfst du weiter in der Konsole mit
  `.\k9.exe scan "D:\Ordner"`.

## Entscheidungen, Quarantäne, Widerruf

- **Quarantäne:** Die Datei wird verschleiert in `C:\ProgramData\K9\quarantaene`
  abgelegt (nicht ausführbar, nur der Dienst hat Zugriff). Wiederherstellen jederzeit möglich.
  K9 öffnet die Datei dafür nur ein einziges Mal: Kopieren, Prüfsumme vergleichen und Entfernen
  laufen über denselben Zugriff, so kann sich kein anderes Programm (z. B. die Prüfung von Trend
  Micro nach dem Lesen) dazwischendrängen. Hat ein anderes Programm die Datei gerade offen, wartet
  K9 bis zu 5 Sekunden. Klappt es nicht, bleibt alles, wie es war: das Original bleibt liegen, keine
  Kopie in der Quarantäne, der Fund bleibt offen. Jeder Versuch steht im Dienst-Protokoll.
- **Löschen:** endgültig.
- **Freigabe/Ignorieren:** wird nie mehr gemeldet. Bei Programmstarts gilt die Freigabe nur für
  **genau diese Befehlszeile** (zusammen mit Regel und startendem Programm) – nie für PowerShell oder
  cmd allgemein.
- **Nur diesmal erlauben** (bei Programmstarts): schließt den Fund, merkt sich nichts. Tritt dasselbe
  wieder auf, wirst du erneut gefragt. Läuft das Programm nicht mehr, heißt der Knopf
  **„Gesehen (Prozess beendet, nichts wird gemerkt)“**.
- **Prozess beenden** wird nur angeboten, solange genau dieser Prozess noch läuft: Programmpfad **und**
  Startzeit müssen zum Fund passen. Windows vergibt Prozess-IDs schnell neu – gehört die ID inzwischen
  zu einem anderen Prozess (auch zu einer zweiten Kopie desselben Programms), wird nichts beendet und
  das Dashboard zeigt „Prozess läuft nicht mehr“.
- **Freigabe bei „Schutz vor Datendieben“** heißt „Freigabe (dieses Programm für Daten von …)“: Sie gilt
  nur für genau diese Programmdatei (Pfad und Signatur bzw. Prüfsumme) und genau diese Daten.
- **Datei nicht mehr vorhanden:** Ist die gemeldete Datei inzwischen verschwunden (z. B. eine
  Temp-Datei), zeigt das Dashboard „Datei nicht mehr vorhanden“ und bietet statt Quarantäne/Löschen
  **„Gesehen (Datei nicht mehr vorhanden, nichts wird gemerkt)“** an. Nichts wird automatisch erledigt.
- **Windows-Systemdateien** (alles unter `C:\Windows`, z. B. powershell.exe, cmd.exe): „Quarantäne“ und
  „Löschen“ werden dafür nie angeboten und sind im Programmkern gesperrt. Möglich sind „Prozess beenden“,
  „Nur diesmal erlauben“ und „Freigabe (genau diese Befehlszeile)“.

**Zeile „Betrifft: …“** (Dashboard und Meldefenster, seit Version 0.23.0): Unter dem Namen der
Bedrohung steht in klaren Worten, worum es geht – denn der Name allein („ClamAV:
PUA.Win.Packer.Exesplitter-8“) verrät nicht, welches Programm gemeint ist:

| Art der Meldung | Was in der Zeile steht | Beispiel |
|---|---|---|
| Datei, während K9 ein Programm aktualisiert | Dateiname und das Programm, zu dessen Update sie gehört | „Installationsdatei AusweisApp-2.6.3-AMD64.msi zum Update von AusweisApp“ |
| Datei aus einem winget-Paket | Dateiname und Paketname | „Datei AusweisApp-2.6.3-AMD64.msi, aus dem winget-Paket Governikus.AusweisApp.2.6.3“ |
| andere Datei | Dateiname | „Datei rechnung.js“ |
| Programm | Programmname, Hersteller laut gültiger Signatur (oder „ohne gültige Signatur“), zugehöriges Update | „Programm installer.exe, signiert von Opera Norway AS, gestartet beim Update von Opera Stable“ |
| Autostart, Firewall-Regel … während eines Updates | das Programm, bei dessen Update der Eintrag entstand | „entstanden beim Update von Opera Stable“ |

Der Hersteller erscheint nur, wenn K9 die Signatur für diese Meldung geprüft hat. Kann K9 das
Programm nicht sicher bestimmen, bleibt die Zeile weg – K9 rät nicht.

**Warum die Nummern in „Offene Erkennungen“ nicht fortlaufend sind:** Jede Meldung behält ihre
Nummer für immer. In der Liste fehlen die Nummern, die du schon entschieden hast. Tritt dieselbe
Sache später noch einmal auf (gleiche Regel, gleiches Programm, gleiche Befehlszeile oder Datei),
legt K9 keine neue Meldung an, sondern öffnet die alte wieder – deshalb können sehr alte Nummern
neben ganz neuen stehen. Seit Version 0.47.2 steht das auch im Dashboard unter der Überschrift, und
in der Spalte „Erkannt“ zeigt „erneut: …“, wann eine alte Meldung zuletzt wieder aufgetreten ist.
Die Liste ist nach Nummer geordnet, leise Meldungen stehen am Ende.

**Mehrere Meldungen auf einmal bearbeiten** (Dashboard, „Offene Erkennungen“): In der Spalte
„Auswahl“ ganz rechts die Meldungen ankreuzen – oder bei einer Meldung auf **„gleiche“** klicken,
dann sind alle offenen Meldungen derselben Art mit derselben Datei bzw. demselben Programm
angekreuzt; „Alle auswählen“ kreuzt alle an. Unten erscheint eine Leiste mit „N Meldungen
ausgewählt“ und **nur den Aktionen, die für jede ausgewählte Meldung möglich sind**, mit der Anzahl
dahinter, z. B. „Gesehen (Prozess beendet, nichts wird gemerkt) (3)“ oder „Freigabe (3)“. Heißt eine
Aktion bei den Meldungen unterschiedlich, steht dort ein neutraler Name (z. B. „Freigabe“). Ist
für die Auswahl keine Aktion gemeinsam möglich, sagt die Leiste das; „Auswahl aufheben“ setzt
alles zurück. Es gelten dieselben Regeln wie beim einzelnen Klick: Quarantäne/Löschen nie für
Windows-Systemdateien, jede Meldung wird einzeln ausgeführt und protokolliert, eine Freigabe
braucht die Bestätigung – **ein** Bestätigungsfenster für die ganze Auswahl, das alle Meldungen
auflistet. Danach zeigt das Dashboard „N erledigt“ bzw. „N erledigt, M fehlgeschlagen – #12: …“
mit dem Grund. Höchstens 200 Meldungen auf einmal; geänderte Sicherheitseinstellungen werden
immer einzeln entschieden.

- **Deaktivieren (Autostart):** Ein Run-Eintrag wird wie im Task-Manager (Registerkarte
  „Autostart“) abgeschaltet: Der Eintrag bleibt stehen, Windows startet das Programm aber nicht mehr.
  Im Task-Manager steht er danach als „Deaktiviert“. Einträge für alle Benutzer (HKLM) schaltet der
  Windows-Dienst mit seinen eigenen Rechten. RunOnce-Einträge (einmalige Starts) werden gesichert und
  entfernt. Eine Startordner-Datei kommt in die Quarantäne, geplante Aufgaben werden deaktiviert,
  Dienste nur mit Administratorrechten. „Wieder einschalten“ unter „Deaktivierte Autostarts“ macht es
  rückgängig. Klappt etwas nicht, nennt die Meldung den Windows-Fehler (z. B. „Zugriff verweigert
  (Windows-Fehler 5)“).
- **Software:** Es wird nie automatisch aktualisiert. Der Fund zeigt die Lösung, z. B.
  `winget upgrade --id Programm.Id -e`.
- **Widerruf:** Dashboard → „Gespeicherte Entscheidungen“ → „Widerrufen“, oder
  `.\k9.exe entscheidungen widerrufen <Nr>`. Beim nächsten Fund wird wieder gefragt.
- Vor jeder Aktion wird geprüft, ob die Datei noch dieselbe ist (Prüfsumme). Eine
  inzwischen veränderte Datei wird nicht angefasst.

## Sprache: Deutsch oder Englisch (seit Version 0.49.0)

K9 gibt es auf Deutsch und auf Englisch. Voreingestellt ist `auto`: K9 nimmt die
Anzeigesprache von Windows. Ist Windows auf Deutsch eingestellt, bleibt alles deutsch, bei
jeder anderen Sprache zeigt K9 Englisch.

**Am einfachsten im Dashboard:** Ganz oben rechts steht „Sprache: **Deutsch** English“. Die
fett gedruckte Sprache gilt gerade, die andere ist eine Schaltfläche. Ein Klick auf „English“
stellt sofort um: Dashboard, Meldefenster und das Symbol im Infobereich sind ab diesem
Augenblick englisch. Oben rechts steht dann „Language: Deutsch **English**“, und ein Klick auf
„Deutsch“ stellt genauso wieder zurück. Ein Neustart ist dafür nicht nötig. K9 trägt die Wahl
in die `config.toml` ein, sie gilt also auch nach dem nächsten Start.

Oder mit einem Befehl (normale PowerShell, kein Administrator nötig):

```
cd "C:\Program Files\K9"
.\k9.exe sprache en
```

| Befehl | Wirkung |
|---|---|
| `.\k9.exe sprache` | zeigt die Sprache, die gerade gilt, und was eingestellt ist |
| `.\k9.exe sprache en` | Englisch |
| `.\k9.exe sprache de` | Deutsch |
| `.\k9.exe sprache auto` | wie Windows (Voreinstellung) |

Der Befehl schreibt die Zeile `sprache = "en"` ganz oben in die `config.toml` (vor dem ersten
Abschnitt in eckigen Klammern) und ändert sonst nichts. **Der Schalter im Dashboard wirkt
sofort. Nach dem Befehl übernimmt der Dienst die Sprache innerhalb von 30 Sekunden, der Agent
bei seinem nächsten Start – am einfachsten startest du den PC neu.** Wer Englisch fest haben
will, stellt am besten `en` ein statt `auto`: Der Dienst läuft unter dem Systemkonto von
Windows, und dessen Anzeigesprache kann von deiner abweichen.

**Was auf Englisch erscheint (Stand Version 0.50.0):**

- das ganze Dashboard: alle Bereiche, Überschriften, Tabellen, Schaltflächen, Hinweise und die
  Rückmeldungen nach einem Klick,
- das Meldefenster mit allen Schaltflächen und Erklärungen,
- die Entscheidungen („Allow“, „Quarantine“, „Delete/disable“, „End process“, „Seen“ …),
- **die Meldungen selbst** (seit 0.50.0): Name der Bedrohung, Fundort, Kategorie, der Hinweis
  mit der Empfehlung und die Zeile „Betrifft“ – für alle Erkennungen von Agent und Dienst,
- die Bestätigungsfenster des Dienstes („Confirm release?“, „Restore from quarantine?“ …),
- die Benachrichtigungen per Windows-Popup, E-Mail und Handy,
- der Sicherheits-Check mit allen Punkten und Empfehlungen und der Wochenbericht,
- die Texte zum Aktualisieren und Deinstallieren von Programmen,
- das Symbol im Infobereich (Text am Mauszeiger und das Menü).

**Was deutsch bleibt:**

- die Ausgabe der `k9`-Befehle in der PowerShell und die Namen der Befehle
  (zum Beispiel `k9 dienst aktualisieren`),
- die Zeilen im Bereich „Protokoll“ und in den Protokolldateien,
- Fehlertexte, wenn eine Aktion scheitert (hinter „Error:“ steht dann ein deutscher Satz),
- einzelne Fachangaben in den Einzelheiten einer Meldung, zum Beispiel die Treffersicherheit
  („hoch“, „mittel“, „niedrig“) und der Status in „Letzte Erkennungen“ („offen“),
- die Kommentare in der `config.toml` und diese Anleitung.

Gut zu wissen:

- **Deine Entscheidungen gelten in beiden Sprachen.** Eine Freigabe, die du auf Deutsch
  gegeben hast, gilt auch, wenn K9 dieselbe Sache später auf Englisch meldet – K9 erkennt
  eine Meldung an ihrem Fingerabdruck, nicht an ihrem Text.
- **Sicherheits-Check, „Letzte Aktionen“ und Erkennungsquellen** stehen nach dem Umschalten
  sofort in der neuen Sprache: Beim Klick auf „English“ bzw. „Deutsch“ prüft K9 den
  Sicherheits-Check gleich neu (das dauert ein paar Sekunden, der drehende Kreis zeigt es an).
  Was K9 früher gespeichert hat („Letzte Aktionen“, der Stand der Quellen), übersetzt es beim
  Anzeigen. Nur die Rückmeldungen von winget selbst (etwa „Erfolgreich installiert“) kommen
  in der Sprache von Windows.
- Meldungen, die schon in der Liste stehen, behalten ihre Sprache – auch in „Letzte
  Erkennungen“ und im „Protokoll“. Neue Meldungen kommen in der eingestellten Sprache.
- Die Schaltflächen „Ja“ und „Nein“ im Bestätigungsfenster beschriftet Windows selbst – sie
  erscheinen in der Sprache von Windows, nicht in der von K9.
- Namen von Regeln aus fremden Quellen (ClamAV, YARA, Sigma) sind schon immer englisch und
  bleiben, wie die Quelle sie liefert.

# Teil 3 – Funktionen

Alle Funktionen auf einen Blick. **Schalter** ist der Eintrag in `config.toml` bzw. der Name für
`k9 funktion <name> an|aus`; **Standard** ist der Zustand nach der Installation. Deinen aktuellen Stand
zeigt `.\k9.exe funktion status`. Abschalten einer Schutzfunktion wirkt erst nach deiner Bestätigung.

| Funktion | Was sie tut | Schalter | Standard |
|---|---|---|---|
| Echtzeitschutz (Dateien) | prüft neue Dateien in Downloads, Desktop, Dokumente, TEMP, Autostart | `echtzeit.aktiv` | an |
| Programmstarts | verdächtige Befehlszeilen, Programme aus Benutzerordnern | `echtzeit.prozesse` | an |
| Autostarts | neue Run-Einträge, Aufgaben, Dienste, Browser-Hilfsprogramme, versteckte WMI-Autostarts | `echtzeit.autostart` | an |
| Konten und Anmeldungen | neues Konto, neuer Administrator, Remotedesktop, viele falsche Passwörter | `anmeldungen` (`echtzeit.anmeldungen`) | an |
| Sicherheits-Check | Ampel im Dashboard: Virenschutz, Firewall, Updates, Secure Boot, Benutzerkontensteuerung, Remotedesktop, Speicherintegrität, Datensicherung | `sicherheitscheck` | an |
| Veraltete Programme | Programme mit neuerer Version (winget), nur Anzeige mit Befehl | `programm-updates` | an |
| Wochenbericht | jede Woche eine Zusammenfassung als Meldefenster | `wochenbericht` | an |
| Neue Geräte im Heimnetz | unbekanntes Gerät im eigenen Netz melden | `heimnetz` | an |
| Neue Sicherheitslücken | neue Lücken (Hoch/Kritisch) installierter Programme, einmal am Tag | `neue-luecken` | an |
| Speicher-Scan im Leerlauf | Schadcode, der nur im Arbeitsspeicher steht; nie bei Spiel oder Anti-Cheat | `speicher-scan` (`echtzeit.speicher_scan`) | aus |
| Netzwerk und DNS | Verbindungen und DNS-Abfragen zu Schad- und Phishing-Adressen | `echtzeit.netzwerk` | an |
| Ransomware-Erkennung | Köderdateien und viele verschlüsselte Dateien in kurzer Zeit | `echtzeit.ransomware` | an |
| USB/Speicherkarten | Prüfung beim Einstecken | `echtzeit.usb` | an |
| ClamAV in Echtzeit | riskante neue Dateien zusätzlich mit ClamAV | `echtzeit.clamav` | an |
| Schutz vor Datendieben | fremde Programme an gespeicherten Passwörtern/Cookies | `datendiebe` (`echtzeit.infostealer`) | an |
| PowerShell-Skriptprüfung | Skripte vor dem Ausführen | `skriptpruefung` (`echtzeit.powershell_skripte`) | an |
| Programme und Skripte aus dem Internet | unsignierte Programme und alle Skripte (.js, .vbs, .hta, .ps1, .bat) mit Internet-Herkunft beim Start | `download-herkunft` | an |
| Angriffsketten | Schritte eines unsignierten Programms aus dem Internet (seit 0.34.0 auch: neu im Benutzerordner, vom USB-Stick) als eine Meldung | `angriffsketten` | an |
| Browser-Erweiterungen | neue Erweiterungen, neue Rechte, Schad-Erweiterungen | `quellen.erweiterungen_aktiv` | an |
| Treiberprüfung | verwundbare und veraltete Treiber | `quellen.treiber_aktiv` | an |
| Ähnliche Domains | Nachahmer-Domains bekannter Marken | `phishing.aehnliche_domains` | an |
| Eingehende Firewall-Regeln | neue Regeln, die Verbindungen von überall hereinlassen (ohne Programm, Programm im Benutzerordner oder unsigniert) | immer an (Dienst) | an |
| Manipulationsalarm | Dienst gestoppt, Dateien verändert, Einstellungen abgeschwächt | immer an | an |
| Spielmodus | während eines Spiels nur leichte Prüfungen, keine Fenster | `gaming.aktiv` | an |
| Arbeitsordner | Verhaltensmeldungen aus Claude-Projekten und Builds nur leise im Dashboard | `arbeitsordner.aktiv`, `k9 arbeitsordner` | an |
| Kritische Programme anhalten | Programm eines kritischen Funds einfrieren, bis du entscheidest; bekannte Schadsoftware wird schon beim Start eingefroren | `anhalten` | aus |
| Ransomware-Verdächtige anhalten | verdächtige Programme bei Ransomware-Verdacht einfrieren, bis du entscheidest (im Test: 382 bis 383 von 400 Dateien gerettet statt 0) | `ransomware-anhalten` | aus |
| Neue Programme aus dem Internet anhalten (seit 0.39.0) | ein unsigniertes Programm aus dem Internet beim ersten Start einfrieren, bis du es freigibst | `neue-programme` | aus |
| VirusTotal | Prüfsumme neuer Programme aus dem Internet abfragen | `virustotal` | aus |
| Sigma-Regeln | jeden Programmstart zusätzlich mit den offenen Sigma-Regeln (SigmaHQ) prüfen, Stufen hoch und kritisch | `sigma` | aus |
| YARA: erweitertes Paket (seit 0.43.0) | rund doppelt so viele YARA-Regeln für die Dateiprüfung | `yara-erweitert` | aus |
| LOLBAS-Regeln (seit 0.40.0) | zusätzlich die Sigma-Regeln der Stufe „mittel“ zu missbrauchten Windows-Programmen; Treffer nur leise im Dashboard | `lolbas` | aus |
| Große Liste Schad-Domains | DNS-Abfragen zusätzlich gegen rund 390.000 Domains prüfen (HaGeZi) | `schad-domains` | aus |
| Gekaperte Netze | Verbindungen zusätzlich gegen Spamhaus DROP prüfen | `spamhaus-drop` | aus |
| Firewall-Sperre | bekannte Botnetz-Steuerserver sperren | `firewall` | aus |
| Schattenkopien | Kopie im Leerlauf, Laufwerke wählbar | `schattenkopien` | aus |
| Vollständige PowerShell-Protokollierung | Windows-Richtlinie: alle Skripte prüfen | `k9 powershell-protokoll an` | aus |

## Echtzeitschutz

Der Echtzeitschutz läuft im Agent mit deinen normalen Benutzerrechten (kein Treiber). Er startet
automatisch mit dem Agent. Der optionale Windows-Dienst (Abschnitt „Windows-Dienst“ weiter unten)
ergänzt ihn um die Teile, die Administratorrechte brauchen. Auch hier gilt: **Nichts wird ohne deine
Entscheidung verschoben, gelöscht, deaktiviert oder beendet.**

| Bereich | Was passiert | Admin nötig? |
|---|---|---|
| Neue/geänderte Dateien | Downloads, Desktop, Dokumente, TEMP und Autostart-Ordner werden überwacht; nach dem Start prüft der Agent einmal die dort in den letzten 24 Stunden geänderten Dateien. Neue Dateien werden geprüft, sobald sie fertig geschrieben sind (Hashlisten, Muster inkl. EICAR-Testdatei, YARA, Schad-Adressen). | nein |
| Riskante Dateien mit ClamAV | Neue Programme, Skripte, Makro-Dokumente, Archive (ZIP, 7z, RAR, ISO …), PDFs und Installer werden zusätzlich mit den ClamAV-Signaturen geprüft – auch Dateien in Archiven. ClamAV startet nur bei Bedarf (ca. 11 s Ladezeit, Meldung nach ca. 15–20 s), nie während eines Spiels, und beendet sich nach 10 Minuten ohne Arbeit wieder. | nein |
| Programmstarts | Jeder neue Prozess wird geprüft: Office/Browser startet PowerShell/cmd/wscript/mshta/rundll32, PowerShell mit verschlüsselten (`-EncodedCommand`, auch abgekürzt) oder Download-Befehlen, mshta/rundll32 mit Skriptcode in der Befehlszeile, Löschen von Schattenkopien (kritisch), gestartete Programme aus Benutzerordnern mit Hashlisten/YARA. Ohne Dienst können sehr kurze Prozesse (unter 1 Sekunde) durchrutschen; mit Dienst wird jeder Start erfasst. | nein |
| Autostarts | Neue Einträge in Run/RunOnce und im Autostart-Ordner werden gemeldet (alle 30 s), Aufgaben und Dienste alle 10 Minuten geprüft; neue Aufgaben/Dienste, die cmd, PowerShell, mshta, rundll32 u. a. starten, werden immer gemeldet. Bekannte Einträge merkt sich der Agent dauerhaft, so fallen auch Einträge auf, die angelegt wurden, während er nicht lief. Option „Deaktivieren“. Ein Programm gilt als „aus einem für Benutzer beschreibbaren Ordner“, wenn es im Benutzerprofil, in TEMP oder unter „Öffentlich“ liegt – unter `C:\ProgramData` nur, wenn die Ordnerrechte es normalen Benutzern wirklich erlauben (z. B. nicht „Package Cache“, das nur Administratoren ändern dürfen). Ist die Signatur gerade nicht prüfbar (Datei von einem Installationsprogramm gesperrt), wird nach 3 Sekunden noch einmal geprüft; bleibt es so, kommt eine Meldung „Signatur nicht prüfbar“ mit Schwere Niedrig statt „unsigniert“. Ist der Eintrag später verschwunden (z. B. RunOnce nach dem Neustart), erledigt der Dienst die Meldung innerhalb von 10 Minuten selbst („Erledigt: Autostart-Eintrag entfernt“). | nein |
| Versteckte WMI-Autostarts | Der Dienst prüft kurz nach dem Start und dann alle 10 Minuten (nie während eines Spiels), ob über WMI ein Befehl oder Skript an einen Auslöser gebunden ist („dauerhafte WMI-Ereignisabonnements“). Das ist ein beliebtes Versteck von Schadsoftware: Es gibt dann keinen Run-Eintrag, keine Datei im Autostart-Ordner und keine geplante Aufgabe. Windows selbst nutzt das so gut wie nie. Die Meldung (Hoch) nennt den Befehl, den Auslöser und den PowerShell-Befehl zum Entfernen. K9 entfernt nichts. Mit „Gesehen“ wird genau dieser Eintrag nicht mehr gemeldet. | ja (Dienst) |
| Zugangsdaten (Schutz vor Datendieben) | Öffnet ein fremdes Programm gespeicherte Zugangsdaten – Passwörter und Cookies von Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Thunderbird, die Anmeldung von Steam und Discord, Telegram-Sitzungen, Krypto-Wallets –, kommt eine Meldung. Erlaubt sind nur das zugehörige Programm (gültig vom Hersteller signiert und aus seinem Programmordner), die Windows-Suche, Windows-Sicherung, Defender, Trend Micro und K9 selbst. Kritisch: unsigniertes Programm aus einem Benutzerordner oder Zugriff auf mehrere Speicher innerhalb einer Minute (typisch für Datendiebe). Hoch: Skript- und Windows-Werkzeuge (PowerShell, cmd, esentutl …) oder unsignierte Programme. Mittel: signierte Programme anderer Hersteller (z. B. Passwortmanager-Import). Ebenso gemeldet: ein Browser, der von einem anderen Programm mit Fernsteuerung (Remote-Debugging) gestartet wird – unsichtbar mit deinem echten Profil kritisch. Nichts wird beendet; die Meldung erklärt, was zu tun ist (Passwörter ändern, überall abmelden). Kritische Meldungen erscheinen wie der Ransomware-Alarm auch während eines Spiels. Das lesende Programm bestimmt der Dienst nur aus Angaben des Windows-Kernels (nie aus der Befehlszeile, die ein Schadprogramm fälschen kann), auch wenn es sich sofort wieder beendet hat; kennt er das Programm im ersten Moment nicht, wartet er zwei Sekunden auf die Angaben zum Programmstart, bevor er urteilt (seit Version 0.25.1 – sehr kurzlebige Hilfsprogramme, etwa des Browsers selbst, werden so richtig zugeordnet statt als „unbekannt“ gemeldet); ist die Zuordnung auch dann nicht sicher möglich, lautet die Meldung „Programm nicht sicher zuzuordnen“ (Mittel, bei mehreren Speichern Hoch); kennt der Dienst wenigstens den Namen aus dem Startereignis, steht er dabei („laut Startereignis „msedge.exe“ – Name ungeprüft“) – als Hinweis für dich, nie als Grund für eine Erlaubnis. Groß-/Kleinschreibung des Pfads spielt keine Rolle. Zeigt der Windows-Explorer einen Ordner nur an (Maus über dem Ordner, Ordnerbaum, Suche), bleibt das still – gemeldet wird er erst, wenn er eine Datei aus einem Speicher wirklich öffnet. Nicht erkannt: Schadcode, der sich in den Browser selbst einschleust, und Lesen direkt von der Festplatte oder aus Schattenkopien. Schalter: `infostealer` | ja (Dienst) |
| Browser-Erweiterungen | Alle 10 Minuten (nicht während eines Spiels) liest der Agent die Erweiterungen von Chrome, Edge, Brave, Vivaldi, Opera und Firefox. Gemeldet werden: neue Erweiterungen (Info bis Hoch, je nach Rechten und Herkunft), Aktualisierungen mit **neuen Rechten** (z. B. plötzlich „alle Webseiten“ oder „debugger“ – bis Kritisch), Erweiterungen auf der Liste bekannter Schad-Erweiterungen (Kritisch), per Richtlinie oder Registry erzwungene Installationen (Hoch; mit fremder Update-Adresse Kritisch) und Browser-Verknüpfungen mit `--load-extension` oder Fernsteuerung (Hoch). Beim ersten Lauf werden vorhandene Erweiterungen nur bewertet und gemerkt – gemeldet wird dann nur Ernstes. Entfernt wird nie etwas; die Meldung sagt, wie es im Browser geht. Übersicht aller Erweiterungen: Dashboard, Kasten „Browser-Erweiterungen“ (dort auch ein Hinweis, wenn der Entwicklermodus an ist). | nein |
| Browser-Hilfsprogramme | Neu registrierte Hilfsprogramme von Browser-Erweiterungen („Native Messaging“ bei Chrome, Edge, Brave, Vivaldi, Opera, Firefox) werden gemeldet wie neue Autostarts. Über sie kann eine Schad-Erweiterung Programme starten. „Deaktivieren“ schaltet die Registrierung ab, sie lässt sich jederzeit wieder einschalten. | nein (HKLM-Einträge: über den Dienst) |
| Netzwerk | Alle 2 Sekunden (während eines Spiels alle 5): offene Verbindungen gegen bekannte Schad-IP-Adressen (ThreatFox, URLhaus), mit dem verursachenden Programm. Alle 60 Sekunden: der DNS-Zwischenspeicher von Windows. Alle 15 Minuten: zuletzt besuchte Browser-Adressen. | nein |
| DNS-Abfragen | Abgleich jeder DNS-Abfrage mit Schad-Domains (ThreatFox, URLhaus; Schwere Hoch) und Phishing-Domains (Liste „phishing-filter“; Schwere Mittel – auch alle Unterdomains, aber nie eine ganze gemeinsam genutzte Endung wie `github.io`), inkl. des fragenden Programms. Dazu die Prüfung auf **ähnliche Domains** bekannter Marken (Teil 3, „Phishing: ähnliche Domains“). Nur mit dem Windows-Dienst (Windows erlaubt das ohne Administratorrechte nicht). Hinweis: Die Phishing-Testseite von AMTSO liegt auf einer echten, harmlosen Domain und wird von einer DNS-Prüfung deshalb grundsätzlich nicht erkannt. | **ja** (Dienst) |
| PowerShell-Skripte | PowerShell übergibt jedes Skript vor dem Ausführen im Klartext an Windows – auch verschleierte oder verschlüsselte. Der Dienst prüft es auf typische Angriffe: Abschalten der Windows-Schadsoftware-Prüfung (AMSI, Kritisch), Löschen von Schattenkopien (Kritisch), Zugriff auf gespeicherte Zugangsdaten, Herunterladen und direkt im Speicher ausführen, verstecktes Programm in den Speicher laden, Abschwächen des Virenschutzes (je Hoch); eine heruntergeladene Datei starten (Mittel – das machen auch normale Installationsskripte). Gespeichert werden nur Regel, Prüfsumme und ein kurzer Ausschnitt mit **maskierten Zeichenketten** – nie das Skript selbst (es könnte Passwörter enthalten). Die Freigabe gilt für genau dieses Skript. Ohne die Windows-Richtlinie „Script Block Logging“ meldet PowerShell nur Skripte, die es selbst für verdächtig hält; alle Skripte prüft der Dienst erst nach `k9 powershell-protokoll an` (siehe unten). Schalter: `powershell_skripte` | ja (Dienst) |
| Programme aus dem Internet | Windows vermerkt bei heruntergeladenen Dateien die Herkunft (Internet-Zone und meist die Download-Adresse). Startet ein **unsigniertes** Programm mit diesem Vermerk, meldet der Dienst das mit Schwere Mittel und der Download-Adresse (ohne Zusätze nach „?“, die Zugangsschlüssel enthalten können) – der häufigste Weg für gefälschte Cheats, Mods und Cracks. Signierte Programme und selbst erstellte Dateien bleiben still. Die Freigabe gilt für genau diese Programmdatei. Schalter: `download_herkunft` | ja (Dienst) |
| Skripte aus dem Internet | Dasselbe für Skriptdateien: Wird eine Datei `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.hta`, `.ps1`, `.bat` oder `.cmd` mit Internet-Herkunft über den Windows-Skripthost (`wscript`, `cscript`), `mshta`, PowerShell oder `cmd` gestartet, meldet der Dienst das mit Schwere **Hoch** – auch wenn die Datei in keiner Liste steht. Einzelheiten im Abschnitt „Programme und Skripte aus dem Internet“. Schalter: `download_herkunft` | ja (Dienst) |
| Angriffsketten | Startet ein unsigniertes Programm aus dem Internet, verfolgt der Dienst 30 Minuten lang dieses Programm und alle Programme, die es startet. Seit Version 0.34.0 gilt dasselbe für unsignierte Programme **ohne** die Kennzeichnung „aus dem Internet“, wenn ihre Datei höchstens 24 Stunden alt ist und in einem Benutzerordner liegt (`C:\Users\…`, z. B. aus einem Archiv entpackt) oder wenn sie von einem Wechseldatenträger (USB-Stick) gestartet werden – nicht aber in deinen Arbeitsordnern. Für diese Programme gibt es keine eigene Meldung beim Start; gemeldet wird erst die Kette. Einzelne Schritte sind oft harmlos, zusammen nicht: **Kritisch**, wenn danach gespeicherte Zugangsdaten geöffnet, eine Schad- oder Phishing-Adresse abgefragt ein PowerShell-Skript mit kritischem Inhalt ausgeführt Wiederherstellungsdaten gelöscht werden sollen (seit Version 0.36.0) oder K9 selbst angegriffen wird (Schadsoftware schaltet oft zuerst den Schutz ab): der K9-Agent wird von außen beendet (seit Version 0.32.0), Windows soll den K9-Dienst stoppen oder der Dienst wird gewaltsam beendet (seit Version 0.33.0); **Hoch**, wenn ein verdächtiges Skript läuft oder ein Autostart eingerichtet wird (geplante Aufgabe, Run-Eintrag). Ein Skript-Programm allein (typisch für Installationsprogramme) ergibt keine Meldung. Die Meldung zeigt alle Schritte der Reihe nach und erscheint bei Kritisch auch während eines Spiels. Schalter: `angriffsketten` | ja (Dienst) |
| Manipulationsalarm (Selbstschutz) | Schadsoftware schaltet Schutzprogramme oft zuerst ab. Gemeldet werden – auch während eines Spiels –: Agent unerwartet beendet (als Hinweis mit Schwere Hoch), und als kritische Meldung: Dienst läuft seit 2 Minuten nicht mehr (meldet der Agent; nicht beim Herunterfahren und nicht bei `k9 dienst aktualisieren`), Programmdateien in `C:\Program Files\K9` verändert (verglichen mit dem Stand der letzten `k9 dienst aktualisieren` – nur diese schreibt einen neuen Ausgangsstand, ein Neustart des Dienstes nie; geprüft bei jedem Dienststart und alle 10 Minuten), Dienst startet nicht mehr automatisch, Überwachung des Dienstes (Ereignisverfolgung) von außen gestoppt. Hinweis mit Schwere Hoch (seit Version 0.33.0): „Ein Programm wollte den K9-Dienst beenden“ – der Dienst lehnt jeden Stopp ab, der nicht von `k9 dienst stoppen` oder `k9 dienst aktualisieren` kommt, und läuft weiter. Mittel: der Dienst wurde neu gestartet, ohne dass Windows startete oder aktualisiert wurde (z. B. gestoppt und wieder gestartet, Absturz). Geprüft wird alle 10 Minuten; repariert wird nichts automatisch, die Meldung sagt, was zu tun ist. | ja (Dienst) |
| Ransomware | Versteckte Köderdateien in Dokumente, Desktop und Bilder – je zwei: `~vs-koeder-nicht-loeschen.docx` (steht im Ordner ganz hinten) und seit Version 0.37.0 `!vs-koeder-nicht-loeschen.docx` (steht ganz vorne, wird von Verschlüsselern, die einen Ordner von vorne abarbeiten, zuerst getroffen); Alarm, wenn sie verändert werden oder viele Dateien in kurzer Zeit verschlüsselt werden (ab 12). Seit Version 0.37.0 reichen schon **2** Dateien, wenn gerade ein neues unsigniertes Programm läuft (aus dem Internet, höchstens 24 Stunden alt in einem Benutzerordner oder vom USB-Stick) – angehalten wird dann nur dieses Programm. Von Natur aus komprimierte Dateien zählen nicht: Archive, Bilder, Videos, Git-Daten und der Zwischenspeicher von Browsern (Cache, Schriften, Erweiterungspakete). | nein |
| USB/Speicherkarten | Wechseldatenträger werden beim Einstecken geprüft (während eines Spiels erst danach). | nein |

**Edge-Aufräumen nach einem Update:** Nach jedem Edge-Update trägt der Edge-Installer einmalig
`HKLM\…\RunOnce → msedge_cleanup_{GUID}` ein; er löscht bei der nächsten Anmeldung die alte Version.
Dieser Eintrag wird **nicht gemeldet**, nur im Agent-Protokoll vermerkt – aber nur, wenn alles passt:
Name `msedge_cleanup_{GUID}`, Programm genau `setup.exe` im Ordner `Microsoft\Edge\Application\<Version>\Installer`
unter „Programme“, gültige Signatur von genau „Microsoft Corporation“ und nur die bekannten
Aufräum-Optionen. Jede Abweichung (anderer Ordner, unsigniert, andere Optionen) bleibt eine Meldung.

**Ransomware-Alarm:** Er erscheint mit höchster Priorität sofort als Meldefenster – auch während
eines Spiels (abschaltbar mit `ransomware_meldung_trotz_spiel = false`). Wahlweise:
„Prozess beenden“, „Datei in Quarantäne“ oder „Freigabe (weiterlaufen lassen)“.

**Wie schnell der Alarm kommt (seit Version 0.22.0):** K9 prüft jede geänderte Datei in den
überwachten Ordnern eine Viertelsekunde nach dem Schreiben darauf, ob ihr Inhalt wie verschlüsselt
aussieht, und schlägt Alarm, sobald das bei **12 Dateien innerhalb von 20 Sekunden** der Fall ist
(vorher: 25 Dateien, Prüfung nach 1,5 Sekunden). Gezählt werden nur Dateien, die gerade eben neu
geschrieben wurden. Geht der Angriff weiter, zählt K9 sofort wieder mit; eine zweite Meldung kommt
nur, wenn dabei etwas angehalten wurde.

**Wer erkennt – Dienst und Agent (seit Version 0.24.0):** Die Erkennung läuft jetzt im **Dienst**
und zusätzlich wie bisher im Agenten.

| | Dienst | Agent |
|---|---|---|
| Läuft als | System – Schadsoftware mit deinen Benutzerrechten kann ihn nicht beenden | du – kann von Schadsoftware beendet werden |
| Überwacht | Dokumente, Desktop, Bilder und Downloads **aller** Benutzer | Downloads, Desktop, Dokumente, Temp und Autostart des angemeldeten Benutzers, dazu die Köderdateien |
| Weiß, welches Programm es war | ja: Er sieht jedes Öffnen einer Datei samt Programm und nennt genau das Programm, das die verschlüsselten Dateien geöffnet hat | nein: Er verdächtigt alle kürzlich aus Benutzerordnern gestarteten Programme |
| Hält an (wenn eingeschaltet) | genau dieses Programm | alle Verdächtigen |

Meldet der Dienst, bleibt der Agent für denselben Angriff still – du bekommst eine Meldung mit dem
Namen des Programms („Betrifft: Programm …“). Der Agent springt nur ein, wenn vom Dienst binnen
zweieinhalb Sekunden nichts kommt. Lässt sich das Programm nicht bestimmen, meldet der Dienst nach
anderthalb Sekunden trotzdem und sucht bis zu 20 Sekunden weiter; findet er es, hält er es an und
meldet erneut.

Der Anlass war der Test vom 20.11.2026: Die Ransomware Conti verschlüsselte alles, ohne dass eine
einzige Meldung kam. Im Nachtest mit dem harmlosen Testprogramm und **beendetem Agenten** hielt der
Dienst das Programm allein an (366 von 400 Dateien blieben erhalten, Testbericht 7.20).

**Gegen Conti hat das nicht gereicht (Test vom 21.11.2026, Testbericht 7.24):** Mit K9 0.30.0
blieben wieder 0 von 160 Dateien erhalten. Der Lauf zeigt, warum: 36 Sekunden nach dem Start lief
der K9-Agent nicht mehr, fünf Sekunden später auch der K9-Dienst nicht mehr – erst dann wurde
verschlüsselt, in wenigen Sekunden. Conti schaltet also zuerst den Schutz ab. In der Sandbox hat
jedes Programm Administratorrechte; ob Conti den Dienst auf deinem PC ebenso beenden könnte, ist
nicht getestet.

**Abwehr seit Version 0.32.0:** Der Dienst bemerkt das Ende des Agenten jetzt sofort. Läuft in dem
Moment ein unsigniertes Programm aus dem Internet (oder etwas, das es gestartet hat), wertet er das
als kritischen Schritt einer Angriffskette: Du bekommst eine kritische Meldung „Angriffskette: …
K9-Agent von außen beendet“, und mit dem Schalter „Kritische Programme anhalten“ (`anhalten`) wird
das Programm eingefroren, bis du entscheidest. Im Conti-Test lagen zwischen dem Ende des Agenten und
dem Ende des Dienstes fünf Sekunden – in dieser Zeit greift die Abwehr.

Was du dazu wissen musst:

- Sie greift nur bei Programmen ohne gültige Signatur und nur in den ersten 30 Minuten nach ihrem
  Start. Bis Version 0.33.0 musste Windows das Programm außerdem als „aus dem Internet“
  kennzeichnen. Diese Kennzeichnung fehlt aber oft: bei Programmen, die aus einem Archiv entpackt,
  von einem USB-Stick kopiert oder von einem anderen Programm geschrieben wurden. **Seit Version
  0.34.0** zählen deshalb auch:
  - unsignierte Programme in einem Benutzerordner (`C:\Users\…`: Downloads, Desktop, Dokumente,
    Temp, AppData), deren Datei **höchstens 24 Stunden alt** ist – die Meldung nennt sie
    „(neu im Benutzerordner)“,
  - unsignierte Programme, die von einem **Wechseldatenträger** (USB-Stick) gestartet werden, egal
    wie alt – die Meldung nennt sie „vom Wechseldatenträger“.

  Ausgenommen sind Programme in deinen Arbeitsordnern (eigene Builds). Programme auf anderen
  Laufwerken (z. B. Spiele auf `D:`) und ältere Programme zählen nicht – so bleibt ein Spiel
  unberührt, auch wenn es nicht signiert ist.
- **Geprüft** mit dem harmlosen Testprogramm ohne Internet-Kennzeichnung (21.11.2026, Testbericht
  7.28): Agent beendet – 400 von 400 Dateien heil; Dienst gewaltsam beendet – 400 von 400 heil. Der
  Fall „USB-Stick“ ist nur durch Programmtests geprüft.
- Für dich heißt das: Stürzt der Agent ab (oder beendest du ihn im Task-Manager), während ein
  frisch entpacktes unsigniertes Programm läuft, wird dieses Programm angehalten und du bekommst
  eine kritische Meldung. Kennst du das Programm, lässt du es mit „Freigabe“ weiterlaufen.
- Kein Alarm, wenn das Ende des Agenten gewollt war: bei `k9 dienst aktualisieren`, bei einer Pause,
  die du im Bestätigungsfenster erlaubt hast, oder wenn sich niemand mehr angemeldet hat.
- Stürzt der Agent ab oder beendest du ihn im Task-Manager, während so ein Programm läuft, wird
  dieses Programm ebenfalls angehalten. Mit „Freigabe“ läuft es weiter, verloren geht nichts.
- **Geprüft mit dem harmlosen Testprogramm** (21.11.2026, Testbericht 7.25): Mit Version 0.32.0
  gingen noch 12 von 400 Dateien verloren, weil Windows den Start des Programms 0,2 Sekunden zu spät
  meldete. Seit Version 0.32.1 zählt auch ein spät gemeldeter Start; im zweiten Lauf blieben alle
  400 Dateien heil, das Programm war 0,56 Sekunden nach dem Ende des Agenten angehalten.
- **Der Dienst selbst ist seit Version 0.33.0 besser geschützt** – siehe den nächsten Abschnitt
  „Schutz des Dienstes gegen das Beenden“.
- **Geprüft mit Conti** (21.11.2026, Testbericht 7.26, Version 0.32.1): Conti beendete den Agenten
  wieder nach 36 Sekunden, wurde sofort angehalten und kam nicht mehr dazu, den Dienst zu beenden.
  Alle 160 Test-Dokumente blieben heil (mit Version 0.30.0 waren es 0 von 160). Das ist ein Lauf mit
  einer Probe, kein Beweis für jede Ransomware.
- Beendet eine Schadsoftware den Dienst vor dem Agenten oder im selben Augenblick, hilft diese
  Abwehr allein nicht – dafür gibt es seit Version 0.33.0 den Schutz des Dienstes.

**Schutz des Dienstes gegen das Beenden (seit Version 0.33.0):** Der Agent war bisher das einzige,
dessen Ende K9 als Angriff wertete. Ein Schädling, der zuerst den Dienst beendet, wäre
durchgekommen. Jetzt gilt:

| Was passiert | Was K9 tut |
|---|---|
| Windows soll den Dienst stoppen (`sc stop`, `net stop`, Diensteverwaltung, der „Neustart-Manager“ von Windows, den Ransomware gern benutzt) | Der Dienst **lehnt ab** und läuft weiter. Du bekommst den Hinweis „Ein Programm wollte den K9-Dienst beenden“ (höchstens einmal je Minute). Läuft dabei ein unsigniertes Programm aus dem Internet, kommt die kritische Meldung „Angriffskette: … Versuch, den K9-Dienst zu beenden“, und mit dem Schalter `anhalten` wird das Programm eingefroren. |
| Der Dienst wird gewaltsam beendet (z. B. `taskkill /F` mit Administratorrechten) | Windows startet ihn nach **1 Sekunde** neu (vorher 10 Sekunden); seit Version 0.34.0 auch beim zweiten Mal nach 1 Sekunde (vorher 60) und ab dem dritten Mal am selben Tag nach 5 Sekunden (vorher 5 Minuten). Beim Start merkt der Dienst, dass er nicht ordentlich beendet wurde, sieht nach, welche unsignierten Programme aus dem Internet seit höchstens 30 Minuten laufen, und meldet jedes als kritische „Angriffskette: … K9-Dienst gewaltsam beendet“ – mit dem Schalter `anhalten` eingefroren. Zusätzlich kommt wie bisher „Der K9-Dienst wurde neu gestartet“. |
| Du selbst willst den Dienst stoppen | Nimm `k9 dienst stoppen` (oder `k9 dienst aktualisieren`, `k9 dienst deinstallieren`). Diese Befehle kündigen den Stopp beim Dienst an; nur dann gehorcht er. Sie brauchen wie bisher Administratorrechte (UAC-Abfrage). |
| Windows fährt herunter oder startet neu | Der Dienst beendet sich wie immer, ohne Meldung. |

```powershell
& "C:\Program Files\K9\k9.exe" dienst stoppen
& "C:\Program Files\K9\k9.exe" dienst starten
```

Was du dazu wissen musst:

- **In der Diensteverwaltung von Windows (`services.msc`) lässt sich der K9-Dienst nicht mehr
  stoppen** – der Dienst läuft einfach weiter, und du bekommst den Hinweis oben. `sc stop` meldet
  dabei keinen Fehler, obwohl nichts gestoppt wurde. Das ist Absicht. Starten kannst du ihn dort weiterhin.
- Stürzt der Dienst ab, während ein unsigniertes Programm aus dem Internet läuft, wird dieses
  Programm nach dem Neustart ebenfalls angehalten. Mit „Freigabe“ läuft es weiter, verloren geht
  nichts.
- Nach einem Stromausfall oder Absturz von Windows passiert das nicht: K9 merkt sich, zu welchem
  Start von Windows sein letzter Lauf gehörte, und wertet nur ein Ende bei weiterlaufendem Windows
  als Angriff.
- **Geprüft** mit dem harmlosen Testprogramm in der Sandbox (21.11.2026, Testbericht 7.27): Stopp
  über Windows abgelehnt und Programm angehalten, 400 von 400 Dateien heil; Dienst gewaltsam beendet,
  nach 1 Sekunde wieder da und Programm angehalten, 400 von 400 Dateien heil. Dafür waren drei Läufe
  nötig – die ersten beiden haben je einen Fehler aufgedeckt, der behoben ist. Mit echter
  Ransomware ist dieser Schutz noch nicht geprüft.
- **Grenzen:** Das ist ein Schutz ohne eigenen Treiber. Ein Programm mit Administratorrechten, das
  K9 gezielt kennt, kann den Dienst weiterhin ausschalten (z. B. deaktivieren und dann beenden –
  dafür gibt es den Alarm „Der K9-Dienst startet nicht mehr automatisch“ – oder die Ankündigung
  nachahmen). In der einen Sekunde bis zum Neustart ist K9 blind. Und angehalten werden nur
  unsignierte Programme, die aus dem Internet stammen, neu in einem Benutzerordner liegen oder von
  einem USB-Stick gestartet wurden (siehe oben) – ein signiertes oder schon länger vorhandenes
  Programm nicht.

**Löschen der Wiederherstellungsdaten (verbessert in Version 0.36.0):** Viele Ransomware löscht
zuerst die Schattenkopien (`vssadmin delete shadows` und ähnliche Befehle) und verschlüsselt erst
danach. K9 meldet das als „Wiederherstellung wird gelöscht“ und friert – mit dem Schalter
`ransomware-anhalten` – das Programm ein, das den Befehl ausgelöst hat. Im Test vom 21.11.2026
(Testbericht 7.29) lief Babuk trotz dieser Meldung weiter: Es startet den Befehl über ein
kurzlebiges `cmd.exe`, das schon beendet war, als K9 nach dem Auslöser suchte. Seit 0.36.0 findet K9
den Auslöser über seine eigenen Aufzeichnungen der Programmstarts, auch wenn Zwischenschritte
beendet sind. Stammt das Programm aus dem Internet (oder ist es neu im Benutzerordner), kommt
zusätzlich die kritische Meldung „Angriffskette: … Wiederherstellungsdaten sollen gelöscht werden“.
Geprüft mit dem harmlosen Testprogramm (400 von 400 Dateien heil) und mit Babuk selbst: 160 von 160
Dokumenten heil, mit Version 0.35.2 waren es 120 (Testbericht 7.30; ein Lauf, eine Probe).

**Was die Tests mit echter Ransomware am 21.11.2026 gezeigt haben** (je eine Probe, 160
Test-Dokumente, Testbericht 7.26, 7.29 bis 7.31, 7.33 und 7.35):

| Familie | Vor dem 21.11. | Mit Version 0.36.0 | Gestoppt durch |
|---|---|---|---|
| Conti | 0 von 160 heil | **160 von 160** | Abwehr gegen das Abschalten von K9 (seit 0.32.1) |
| Babuk | 106 bis 120 | **160 von 160** | Löschversuch der Wiederherstellungsdaten (seit 0.36.0) |
| LockBit | 104 bis 105 | **160 von 160** | Löschversuch der Wiederherstellungsdaten (seit 0.36.0) |
| BlackMatter | 150 | **160 von 160** (0.38.0) | als Datei erkannt (YARA) und beim Start angehalten |
| MedusaLocker | 138 | **159 von 160** (0.38.0) | zweite Köderdatei am Ordneranfang (seit 0.37.0) |
| BlackBasta | 128 | **128, 128 und einmal 35**; mit 0.37.1 zweimal 128 | Ransomware-Schutz – zu spät für die ersten Dokumente |
| BlackBasta mit dem Schalter `neue-programme` | – | **160 von 160**, zweimal (0.39.0) | beim Start angehalten, bevor es eine Datei anfasst |

BlackBasta verschlüsselt schon in der ersten Sekunde, bevor es irgendetwas anderes tut. Dagegen
hilft keine der neuen Abwehren; K9 hält es erst an, wenn die ersten Dutzend Dateien verloren sind,
und in einem von drei Läufen waren es deutlich mehr. Schattenkopien und eine Sicherung auf einem
getrennten Datenträger bleiben deshalb unverzichtbar. Auf deinem PC kommt hinzu, was die Sandbox mit
Absicht nicht hat: Die Hashlisten kennen diese Proben und melden die Datei schon vor dem Start.

**Früher Stopp bei neuen unsignierten Programmen (seit Version 0.37.0):** BlackBasta verschlüsselt
schon in der ersten Sekunde nach dem Start. Bis K9 zwölf verschlüsselte Dateien gezählt hatte,
waren im Test 32 von 160 Dokumenten verloren, einmal 125. Deshalb zählt der Agent jetzt zusätzlich
mit einer zweiten, viel niedrigeren Schwelle: Sehen **2** Dateien innerhalb von 20 Sekunden
verschlüsselt aus und läuft gerade ein unsigniertes Programm, das aus dem Internet stammt, höchstens
24 Stunden alt in einem Benutzerordner liegt oder von einem USB-Stick gestartet wurde, wird genau
dieses Programm angehalten (mit `ransomware-anhalten`) und gemeldet: „Ransomware-Verdacht – Dateien
wurden verschlüsselt/überschrieben, während ein neues unsigniertes Programm läuft“. Läuft kein
solches Programm, passiert bei 2 Dateien nichts; dann gilt wie bisher die Schwelle 12. Außerdem
prüft K9 eine geänderte Datei jetzt nach 0,1 statt 0,25 Sekunden (im Dienst nach 0,08 statt 0,15).

**Was das gemessen bringt** (harmloses Testprogramm, 40 Dateien je Sekunde, Testbericht 7.32): Die
niedrigere Schwelle allein brachte nichts, erst die kürzere Wartezeit – statt 11 bis 12 gehen 7 bis
8 von 400 Dateien verloren. Das ist eine kleine Verbesserung, kein Durchbruch.

**Gemessen mit BlackBasta selbst (22.11.2026, Testbericht 7.33):** Version 0.37.0 war **schlechter**
als die Version davor – 31 und 43 statt 128 von 160 Dokumenten heil. BlackBasta traf die neue
Köderdatei zuerst, und K9 wartete auf die gerade gesperrte Datei, statt weiterzuprüfen. Version
0.37.1 behebt das (zweimal wieder 128 von 160). Unterm Strich bringen die zweite Köderdatei und der
frühe Stopp gegen BlackBasta **keinen messbaren Gewinn**: Es verschlüsselt den ersten Ordner, bevor
K9 die erste Änderung prüfen kann. Bitte 0.37.0 nicht verwenden.

- Der Preis: Ein frisch geladenes unsigniertes Programm, das selbst gepackte Dateien über
  bestehende Dokumente schreibt (z. B. ein Konverter), kann angehalten werden. Mit „Freigabe“ läuft
  es weiter; es geht nichts verloren.
- Spiele, Anti-Cheat, Windows-Teile, Programme von Microsoft und Trend Micro, K9 selbst und alles in
  deinen Arbeitsordnern werden wie bisher nie angehalten.
- Die zweite Köderdatei `!vs-koeder-nicht-loeschen.docx` ist versteckt wie die erste. Bitte beide
  nicht löschen oder ändern – sonst kommt der Ransomware-Alarm.

**Neue Programme aus dem Internet beim Start anhalten (seit Version 0.39.0, Schalter
`neue-programme`, Standard: aus):** Gegen Ransomware, die schon in der ersten Sekunde verschlüsselt,
hilft nur, was vor der ersten Datei greift. Mit diesem Schalter hält der Agent jedes Programm an,
das **unsigniert** ist und von Windows als **„aus dem Internet“** gekennzeichnet wurde – beim Start,
bevor es etwas tun kann. Du bekommst die Meldung „Neues unsigniertes Programm aus dem Internet
angehalten: …“ (Schwere Hoch) mit den Schaltflächen des Meldefensters:

- „Freigabe (genau diese Programmdatei)“ – das Programm läuft sofort weiter, und K9 merkt sich die
  Datei: Künftig startet genau diese Datei ohne Rückfrage. Wird die Datei verändert, fragt K9 wieder.
- „Prozess beenden“ – wenn du das Programm nicht kennst; danach die Datei in Quarantäne.

Einschalten:

```powershell
& "C:\Program Files\K9\k9.exe" funktion neue-programme an
```

Der Schalter wirkt nach dem nächsten Start des Agenten (abmelden und anmelden, PC neu starten oder
`k9 dienst aktualisieren`).

Was du dazu wissen musst:

- **Gemessen** (22.11.2026, Testbericht 7.36): BlackBasta, das ohne den Schalter 32 von 160
  Dokumenten verschlüsselt, kam mit dem Schalter in zwei Läufen nicht dazu, eine Datei anzufassen
  (160 von 160). Das harmlose Testprogramm verlor 0 bis 1 von 400 Dateien statt 6 bis 9.
- **Der Preis:** bei jedem neuen unsignierten Programm aus dem Internet ein Klick mehr – auch bei
  harmlosen (kleine Werkzeuge, Mods, Installationsprogramme ohne Signatur). Signierte Programme und
  alles in deinen Arbeitsordnern sind nicht betroffen.
- **Nicht während eines Spiels:** Im Spielmodus hält K9 so nichts an (der Agent sieht dann nur alle
  drei Sekunden nach).
- **Zwei Meldungen:** Kurz danach kommt wie bisher auch „Unsigniertes Programm aus dem Internet
  gestartet“ vom Dienst. Die erste hält an, die zweite informiert.
- **Grenzen:** Ein Programm, das mit Administratorrechten startet, kann der Agent nicht anhalten.
  Programme ohne die Kennzeichnung „aus dem Internet“ (aus einem Archiv entpackt, vom USB-Stick)
  hält dieser Schalter nicht an. Zwischen Start und Anhalten liegen wenige Hundertstelsekunden bis
  etwa eine Zehntelsekunde.
- Solange der Schalter an ist, sieht der Agent 16-mal je Sekunde nach neuen Programmen (sonst
  viermal). **Was das kostet, war zuerst falsch geschätzt:** Hier stand „rund 2 % eines Kerns“.
  Gemessen am 22.11.2026 auf dem Test-PC waren es bis Version 0.44.1 **19 bis 23 %** eines Kerns
  außerhalb von Spielen, weil jeder Blick die ganze Prozessliste von Windows abfragte (knapp
  14 Millisekunden bei 400 Prozessen). Seit Version 0.44.2 fragt der Agent nur noch die
  Prozessnummern ab – das kostet unter einer Hundertstel-Millisekunde – und holt die ganze Liste
  erst, wenn wirklich ein Programm dazugekommen ist. Im Spiel sieht er nur alle drei Sekunden nach.
  **Nachgemessen mit 0.44.2** (22.11.2026, fünf Minuten ohne Spiel, alle Schalter an): im Mittel
  **1,2 % eines Kerns**, einzelne Minuten zwischen 0,7 und 2,6 % (Testbericht 7.42). Startest du
  viele Programme kurz hintereinander, ist es in dieser Zeit mehr.

**Eine „Freigabe“ gibt ein angehaltenes Programm ganz frei (seit Version 0.38.0):** Hält K9 ein
Programm an, tun das oft mehrere Meldungen zugleich – Agent und Dienst, Ransomware-Verdacht,
Angriffskette, „Wiederherstellung wird gelöscht“. Windows zählt jedes Anhalten mit. Bis Version
0.37.1 nahm eine „Freigabe“ nur **eines** davon zurück: Das Programm blieb eingefroren, bis du alle
Meldungen dazu entschieden hattest, und nichts wies dich darauf hin. Jetzt gilt: Gibst du bei
**einer** Meldung frei („Freigabe“ oder „Nur diesmal erlauben“), läuft das Programm sofort wieder,
egal wie oft es angehalten wurde. Die übrigen Meldungen zu diesem Programm bleiben in der Liste
stehen, bis du sie entscheidest; sie halten das Programm nicht mehr fest. Willst du es nicht
weiterlaufen lassen, nimm bei einer der Meldungen „Prozess beenden“.

K9 zeigt immer nur **ein** Meldefenster zugleich. Wartet ein angehaltenes Programm auf dich und das
Fenster zeigt gerade eine andere Meldung, wähle dort „Später“ – die Meldung zum angehaltenen
Programm steht seit Version 0.44.1 als nächste in der Reihe. Im Dashboard siehst du jederzeit alle
offenen Meldungen auf einmal.

Jede Freigabe musst du in einem kleinen Fenster des Dienstes mit „Ja“ bestätigen – auch dann, wenn
du sie mit `k9 entscheiden <Nr> freigabe` gibst. So kann sich Schadsoftware nicht selbst freigeben.
Deshalb lässt sich die Freigabe nicht unbeaufsichtigt testen (Testbericht 7.39). Mit Klick geprüft
am 22.11.2026 (Testbericht 7.41): Das angehaltene Testprogramm lief sofort nach „Ja“ weiter, und
beim zweiten Start wurde dieselbe Datei nicht mehr angehalten.

**Betroffene Dateien (seit Version 0.27.1):** Die Meldung zeigt im Dashboard und im Meldefenster
bis zu fünf der betroffenen Dateien als Beispiel („Betroffene Dateien (Beispiele)“); dieselben stehen
im Protokoll. Daran erkennst du meist sofort, ob es deine Dokumente trifft oder nur Hilfsdateien
eines Programms.

**Kein Alarm bei Spielen:** Schreibt ein Spiel oder ein Anti-Cheat-Programm viele gepackte Dateien
(Spielstände), erkennt der Dienst das Programm und schlägt keinen Alarm.

**Kein Alarm beim Entpacken und Herunterladen (seit Version 0.26.0):** Ransomware verändert Dateien,
die **schon da waren**. Wer ein Archiv entpackt, etwas herunterlädt oder Dateien exportiert, legt
**neue** Dateien an. K9 zählt deshalb nur noch:

| Was passiert | Zählt für den Ransomware-Alarm? |
|---|---|
| Eine vorhandene Datei (älter als 8 Sekunden) hat plötzlich verschlüsselt aussehenden Inhalt – an Ort und Stelle überschrieben oder dabei umbenannt | **ja** |
| Eine neue Datei mit gepacktem Inhalt entsteht, nichts wird gelöscht | nein |
| Neue Dateien mit verschlüsselt aussehendem Inhalt entstehen, **und** in denselben 20 Sekunden werden mindestens 5 Dateien gelöscht (Ransomware, die Kopien schreibt und die Originale löscht) | **ja** |

Das ist wichtig, weil viele freie Programme (zum Beispiel 7-Zip) keine Signatur tragen und deshalb
unter die frühe Schwelle von 5 Dateien fallen – ohne diese Regel hätte K9 sie beim Entpacken
gepackter Daten einfrieren können. Im Test legte ein unsigniertes Programm 300 neue gepackte
Dateien an: kein Alarm, nichts angehalten (Testbericht 7.22).

**Wie viele Dateien gehen verloren? (seit Version 0.25.0)** K9 erkennt Ransomware an ihrem Schaden,
deshalb gehen die ersten Dateien immer verloren – außer K9 kennt das Programm schon. Drei Stufen:

| Fall | Was K9 tut | Verlust im Test (400 Dateien, 40 je Sekunde) |
|---|---|---|
| Das Programm ist **bekannte Schadsoftware** (Treffer in den Hashlisten, den eingebauten Mustern oder einer eindeutigen YARA-/ClamAV-Familie) | Es wird **beim Start** eingefroren, bevor es etwas tun kann – der Agent sieht viermal je Sekunde nach neuen Programmen (während eines Spiels alle drei Sekunden). Schalter: `anhalten` („Kritische Programme anhalten“) | **0** |
| **Unbekanntes Programm** ohne gültige Signatur oder aus einem Benutzerordner | Der Dienst hält es an, sobald **5** Dateien, die es geöffnet hat, verschlüsselt aussehen. Schalter: `ransomware-anhalten` | 17 bis 18 |
| Signiertes, installiertes Programm | allgemeine Schwelle von **12** Dateien, damit Pack- und Sicherungsprogramme nicht bei jeder Kleinigkeit angehalten werden. Schalter: `ransomware-anhalten` | rund 35 |

Bloße Verdachtsregeln (YARA „Indicator“/„Suspicious“, ClamAV „PUA“) frieren beim Start **nichts**
ein – sie treffen auch harmlose Installationsprogramme. Spiele, Anti-Cheat, Windows-Bestandteile,
Programme von Microsoft und Trend Micro und K9 selbst werden nie eingefroren.

Echte Ransomware brauchte im Test vom 20.11.2026 zwischen 5 und 74 Sekunden vom Start bis zur ersten
verschlüsselten Datei – beim Anhalten am Start bleibt also genug Zeit. Die verlorenen Dateien der
beiden anderen Fälle lassen sich meist aus den **Schattenkopien** zurückholen (Abschnitt
„Eingriffe“, Punkt „Schattenkopien“), solange die Ransomware sie nicht löschen konnte; genau diesen Löschversuch
erkennt K9 und hält das Programm dabei an.

**Vollständiger Schutz vor dem ersten Schreibzugriff** ist nur mit einem Schutzprogramm möglich, das
im Windows-Kern mitläuft: In Trend Micro heißt die Funktion **„Ordnerschild“**. Sie ist bei dir
eingeschaltet (geprüft am 20.11.2026) und verbietet unbekannten Programmen das Schreiben in die
geschützten Ordner. K9 ändert daran nichts.

**„Ransomware-Verdächtige anhalten“** (Schalter `ransomware-anhalten`, Standard: **aus**):

```
cd "C:\Program Files\K9"
.\k9.exe funktion ransomware-anhalten an
```

Ausschalten: `.\k9.exe funktion ransomware-anhalten aus` (wirkt erst nach deiner Bestätigung im
Fenster). Die Änderung gilt nach einem Neustart des Dienstes oder des PCs.

Ist der Schalter an, friert K9 bei einem Ransomware-Alarm die verdächtigen Programme ein
(*angehalten*, **nie beendet**) – das sind Programme, die in den letzten 15 Minuten aus einem
Benutzerordner oder ohne gültige Signatur gestartet wurden. Erst deine Entscheidung im Meldefenster
beendet sie („Prozess beenden“) oder lässt sie weiterlaufen („Freigabe“). Zusätzlich friert der
Dienst das Programm ein, das die Windows-Wiederherstellung löschen will (`vssadmin delete shadows`
und ähnliche Befehle) – das tut Ransomware meist, bevor oder während sie verschlüsselt.

**Nie eingefroren werden:** Spiele und Anti-Cheat-Programme, Bestandteile von Windows, Programme
mit Signatur von Microsoft oder Trend Micro, K9 selbst und Programme aus deinen Arbeitsordnern
(dort schreiben Builds viele gepackte Dateien). Liegen alle betroffenen Dateien in Arbeitsordnern,
wird gar nichts eingefroren.

**Was es bringt – gemessen am 19.11.2026** in der Sandbox mit einem harmlosen Testprogramm, das
400 Schein-Dokumente mit 40 Dateien pro Sekunde überschreibt (Testbericht, Abschnitt 7.18):

| Einstellung | Dateien gerettet | Was passiert ist |
|---|---|---|
| Anhalten **aus** | 0 von 400 | Alarm nach rund einer Sekunde, das Programm lief zu Ende |
| Anhalten **an** | 365 bis 377 von 400 | Programm nach 23 bis 35 Dateien eingefroren (unter einer Sekunde) |

**Das Risiko:** Trifft der Verdacht ein harmloses Programm – zum Beispiel ein Packprogramm oder ein
Sicherungsprogramm, das gerade viele Dateien verschlüsselt speichert –, bleibt es eingefroren, bis
du im Meldefenster „Freigabe“ wählst. Verloren geht dabei nichts; das Programm läuft danach weiter.

**Mit echter Ransomware gemessen am 20.11.2026** (Testbericht, Abschnitt 7.19 – je eine Probe, 160
kleine Schein-Dokumente, drei Minuten Beobachtung):

| Ransomware | Dateien heil, Anhalten aus | Dateien heil, Anhalten an |
|---|---|---|
| LockBit | 0 von 160 | 104 |
| MedusaLocker | 0 | 138 |
| BlackMatter | 0 | 150 |
| BlackBasta | 0 | 128 |
| Babuk | 0 | 106 |
| Conti | 0 | 0 (kein Alarm – Conti beendet K9 vor dem Verschlüsseln, auch am 21.11. mit 0.30.0) |

**Grenzen:** Bei Ransomware, die K9 noch nicht kennt, sind die ersten Dateien verloren (im Test oben
10 bis 56 von 160 – K9 erkennt sie am Schaden, nicht vorher). Der Schalter hilft nur, wenn K9 die Ransomware überhaupt bemerkt und selbst noch läuft – Conti
hat im Test K9 abgeschaltet, bevor es verschlüsselte (Testbericht 7.24). K9 ersetzt deshalb keine Datensicherung: Eine Kopie deiner wichtigen
Dateien auf einem Laufwerk, das nicht ständig angeschlossen ist, bleibt der einzige sichere Schutz.

**Gaming:** Während eines Spiels bleibt der Echtzeitschutz aktiv, prüft aber nur gegen die
Hashlisten (sehr schnell). Die gründlichere YARA-Prüfung wird für diese Dateien nach dem Spiel
nachgeholt. ClamAV läuft während eines Spiels nicht: Ein schon gestartetes ClamAV wird beendet,
riskante neue Dateien warten und werden nach dem Spiel geprüft.

Gemessener Verbrauch des Agents (dieser PC, 48 logische Prozessoren, alle Signaturen geladen):

| Situation | CPU (alle Kerne) | Arbeitsspeicher |
|---|---|---|
| Leerlauf | 0,08 % (entspricht ca. 4 % eines Kerns) | 28 MB aktiv, 181 MB reserviert |
| 520 neue Dateien in 30 s | 1,6 s CPU-Zeit, im Mittel 0,11 % | 30 MB aktiv |
| Während eines Spiels, ruhig | 0,01 % | 31 MB aktiv |
| Während eines Spiels, 200 neue Dateien | 0,2 s CPU-Zeit, im Mittel 0,02 % | – |
| ClamAV-Echtzeitprüfung aktiv (clamd) | Start: ca. 10 s CPU-Zeit einmalig, danach im Leerlauf 0 % | ca. 0,9–1 GB, nur solange clamd läuft (endet nach 10 Minuten ohne Arbeit) |

Einstellungen in `config.toml` (Abschnitt `[echtzeit]`):

```
[echtzeit]
aktiv = true
# leer = Downloads, Desktop, Dokumente, TEMP, Autostart-Ordner
ordner = []
# zusätzlich überwachte Ordner (ohne Köderdateien), z. B. ['D:\Downloads2']
zusatz_ordner = []
max_dateigroesse_mb = 64
prozesse = true
autostart = true
netzwerk = true
netzwerk_intervall_sekunden = 60
ransomware = true
ransomware_meldung_trotz_spiel = true
ransomware_prozess_anhalten = false
usb = true
# riskante neue Dateien auch mit ClamAV prüfen (aus: false)
clamav = true
# ClamAV nach so vielen Minuten ohne Arbeit beenden (gibt RAM frei)
clamav_leerlauf_minuten = 10
# fremde Zugriffe auf gespeicherte Zugangsdaten melden (Dienst)
infostealer = true
powershell_skripte = true           # PowerShell-Skripte vor dem Ausführen prüfen (Dienst)
# unsignierte Programme aus dem Internet beim Start melden (Dienst)
download_herkunft = true
# Schritte eines Programms aus dem Internet zu einer Meldung zusammenfassen (Dienst)
angriffsketten = true
```

**Alle PowerShell-Skripte prüfen (optional):** Standardmäßig sieht der Dienst nur die Skripte, die
PowerShell selbst als verdächtig einstuft. Für alle Skripte schaltest du die Windows-Richtlinie
„Script Block Logging“ ein – PowerShell **als Administrator** öffnen:

```
cd "C:\Program Files\K9"
.\k9.exe powershell-protokoll an
```

Ausschalten mit `.\k9.exe powershell-protokoll aus`, Stand anzeigen mit
`.\k9.exe powershell-protokoll status`. Hinweis: Windows schreibt die Skripte dann zusätzlich in
sein eigenes Ereignisprotokoll (Microsoft-Windows-PowerShell/Operational) – dort können auch Passwörter
aus Skripten landen. K9 selbst speichert keine Skripte.

Wenn du den Arbeitsspeicher von ClamAV gar nicht möchtest: `clamav = false` setzen und den Agent neu
starten. Dann prüft ClamAV weiterhin bei geplanten und manuellen Scans.

### Agent automatisch bei der Anmeldung starten

```
cd "C:\Program Files\K9"
.\k9.exe autostart-agent an
```

Der Agent startet dann bei jeder Windows-Anmeldung **unsichtbar** (ohne Konsolenfenster, über
`conhost --headless`, ohne Administratorrechte; Eintrag `HKCU\...\Run\K9-Agent`).
Das Dashboard erreichst du weiter mit `.\k9.exe dashboard`.

| Befehl | Bedeutung |
|---|---|
| `.\k9.exe autostart-agent an` | Agent bei der Anmeldung starten |
| `.\k9.exe autostart-agent aus` | Autostart wieder entfernen |
| `.\k9.exe autostart-agent status` | anzeigen, ob der Autostart eingeschaltet ist |
| `.\k9.exe agent-beenden` | laufenden (auch unsichtbaren) Agent beenden, z. B. vor einem neuen Build (fragt nach „j“) |

## Eingriffe – alle standardmäßig aus

Diese Funktionen greifen ein oder ändern Windows. Sie sind **aus**, bis du sie einschaltest – am
einfachsten mit `k9 funktion <name> an` (siehe „Wichtige Abläufe“, Punkt g); der Dienst übernimmt
das innerhalb von 30 Sekunden. Spiele, Anti-Cheat und Windows werden nie angefasst.

```
[echtzeit]
# Programm einer kritischen Meldung anhalten, bis du entscheidest
kritische_prozesse_anhalten = false

[quellen]
# Prüfsumme neuer Programme aus dem Internet bei VirusTotal abfragen
virustotal_aktiv = false

[schutz]
# im Leerlauf eine Schattenkopie anlegen (Rückweg nach Ransomware)
schattenkopien = false
schattenkopien_stunden = 24
# weitere Laufwerke: k9 funktion schattenkopien laufwerke C: F:
schattenkopien_laufwerke = ["C:"]
# bekannte Botnetz-Steuerserver in der Windows-Firewall sperren
firewall_sperre = false
```

- **Anhalten:** Nur bei **kritischen** Meldungen zu einem Programm (Angriffskette, Datendieb,
  kritisches PowerShell-Skript). Das Programm wird eingefroren, **nie beendet** und nie von selbst
  fortgesetzt; im Meldefenster entscheidest du: „Prozess beenden“ oder „Freigabe“/„Nur diesmal
  erlauben“ (läuft weiter). Nie angehalten werden: Spiele (Spiele-Ordner und -Programme aus
  `[gaming]`), Anti-Cheat (z. B. Easy Anti-Cheat, BattlEye, Vanguard, FACEIT), Programme unter
  `C:\Windows`, Programme mit Signatur von Microsoft oder Trend Micro, K9 selbst.
  Achtung: Trifft es ein harmloses Programm, bleibt es bis zu deiner Entscheidung eingefroren.
- **VirusTotal:** Startet ein unsigniertes Programm aus dem Internet zum ersten Mal, fragt der Dienst
  die **Prüfsumme** bei VirusTotal ab – die Datei wird nie hochgeladen. Ab 3 erkennenden
  Virenscannern Meldung „Hoch“, bei 1–2 „Mittel“. Höchstens 4 Abfragen pro Minute und 500 pro Tag,
  Ergebnisse 7 Tage gemerkt, nie während eines Spiels. Datenschutz: Die Prüfsumme geht an VirusTotal
  (gehört zu Google). Den kostenlosen Schlüssel (nur private Nutzung) bekommst du nach einer
  Anmeldung auf virustotal.com; hinterlegen (PowerShell):

```
cd "C:\Program Files\K9"
.\k9.exe geheimnis virustotal-key
```

  Echte Schlüssel gibst du immer so ein (die Eingabe bleibt unsichtbar). Nicht mit
  `--aus-eingabe` oder in einem Skript übergeben: Ist die vollständige PowerShell-Protokollierung an
  (`k9 powershell-protokoll an`), landet ein so übergebener Schlüssel im Klartext im
  Windows-Ereignisprotokoll.
- **Schattenkopien:** Im Leerlauf (mindestens 15 Minuten ohne Eingabe, nie während eines Spiels)
  höchstens alle `schattenkopien_stunden` eine Kopie jedes Laufwerks aus `schattenkopien_laufwerke`
  (Standard C:; vor jedem Laufwerk wird erneut geprüft, ob du noch nichts tust und kein Spiel läuft).
  Eine Schattenkopie ändert keine Dateien; nur beim Anlegen hält Windows Schreibzugriffe wenige
  Sekunden an. Ein Laufwerk hinzufügen gilt sofort, eines entfernen erst nach deiner Bestätigung.
  Ältere Dateien mit `schattenkopien_laufwerk = "C:"` gelten weiter, solange die Liste fehlt. Windows löscht die ältesten Kopien
  selbst, wenn sein Speicher dafür voll ist; K9 löscht nie eine Kopie und ändert den
  Speicher nicht. Ist kein Speicher eingerichtet (Computerschutz aus), kommt ein Hinweis – einschalten
  kannst nur du (Systemsteuerung → System → Computerschutz); der Hinweis erscheint je Laufwerk nur
  einmal, solange er offen ist. Stand: `.\k9.exe dienst status`
  (Zeile „Schattenkopien“) und im Dashboard beim Dienst.
- **Firewall-Sperre:** Nur Adressen mit hoher Sicherheit: abuse.ch Feodo Tracker (empfohlene Liste)
  und ThreatFox-Einträge der Art „Botnetz-Steuerserver“ mit Sicherheit 100, jeweils höchstens 30 Tage
  alt, nur öffentliche IPv4-Adressen (nie Heimnetz, Router, Loopback, Multicast oder Provider-NAT).
  Gesperrt wird genau Adresse **und** Port (ausgehend, TCP), höchstens 1000 Adressen, täglich neu
  (nie während eines Spiels). Je Port gibt es eine Regel „K9 – Botnetz-Server gesperrt
  (Port N)“ in der Gruppe **„K9“** (zu sehen unter „Windows Defender Firewall mit erweiterter
  Sicherheit“ → Ausgehende Regeln); die Beschreibung nennt Quelle (abuse.ch Feodo Tracker/ThreatFox),
  Stand, Anzahl der Adressen und „Entfernen: k9 firewall entfernen“. Entfernt werden immer nur diese
  eigenen Regeln (und die einer älteren Version, „Virenscanner C2-Sperre“) – nie eine andere Regel, auch
  nicht eine fremde in derselben Gruppe.

  **Geteilte CDN-Netze werden nie gesperrt:** Adressen von Cloudflare, Amazon CloudFront, Fastly und
  den Google-Front-Ends bedienen tausende fremde Webseiten – eine Sperre würde normales Surfen stören.
  Die Listen dieser Anbieter lädt der Dienst bei jeder Aktualisierung der Sperre neu; klappt das nicht,
  nimmt er die letzte Kopie oder die eingebaute Liste. Übersprungene Adressen stehen im
  Dienst-Protokoll („… Adressen in geteilten CDN-Netzen uebersprungen“).

  **Höchstens 1000 Adressen, die neuesten zuerst:** Gibt es mehr Kandidaten, werden die zuletzt
  gemeldeten gesperrt; ältere fallen weg. Die Sperre erneuert sich täglich, nach neuen
  ThreatFox-Daten und bei jedem Dienststart (nie während eines Spiels).

  **Ohne Lücke:** Bei jeder Erneuerung vergleicht der Dienst die vorhandenen Regeln mit der neuen
  Liste und ändert nur, was anders ist – direkt über die Schnittstelle der Windows-Firewall, das
  dauert Sekunden. Stimmen die Regeln schon (z. B. nach einem Neustart des PCs), wird gar nichts
  geändert. Geänderte Regeln bekommen ihre neuen Adressen an Ort und Stelle, neue Regeln kommen
  dazu, und erst danach werden nicht mehr benötigte entfernt. Das Dienst-Protokoll nennt jedes Mal
  „Firewall-Sperre: Regeln … unverändert, … aktualisiert, … neu, … entfernt in … ms“.
  *Warum:* Bis Version 0.2.1 löschte der Dienst bei jeder Erneuerung zuerst alle K9-Regeln und legte
  sie dann mit je einem eigenen PowerShell-Aufruf neu an. Das dauerte etwa 5 Minuten, auch nach
  jedem Neustart des PCs, und so lange war die Sperre lückenhaft. Ist die Firewall-Schnittstelle
  einmal nicht erreichbar, nimmt der Dienst ersatzweise PowerShell, aber in derselben Reihenfolge.

  **Risiko:** Eine gelistete Adresse kann zu einem gemieteten Cloud-Server gehören, der später neu
  vergeben wird; ein harmloser Dienst auf genau dieser Adresse und diesem Port wäre dann gesperrt.

  Vorschau, ohne etwas zu ändern (normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" firewall vorschau
```

  **Schutz der eigenen Regeln:** Löscht, deaktiviert oder ändert ein Programm (oder jemand in der
  Firewall-Konsole) K9-Regeln, stellt der Dienst sie innerhalb von etwa 2 Sekunden wieder her – er
  merkt jede Änderung am Regelspeicher sofort, zusätzlich prüft er alle 10 Minuten. Das passiert auch
  während eines Spiels, still; die Meldung wartet bis danach. Gemeldet wird „K9-Sperrregeln entfernt
  (N Regeln) – wiederhergestellt“ (Schweregrad Hoch) mit dem Programm, das es getan hat, Benutzer und
  Zeit aus dem Firewall-Protokoll. Passiert es immer wieder, bleibt es **eine** Meldung, die mitzählt
  („Vorfälle“). Knöpfe: „Freigabe (dieses Programm darf K9-Regeln ändern)“ – meldet dieses Programm
  nicht mehr, **wiederhergestellt wird trotzdem immer** – und „Gesehen“.

  **Schneller Rückweg**, wenn etwas keine Verbindung mehr bekommt:

  1. Sofort alle K9-Regeln entfernen (PowerShell **als Administrator**, im Fenster „Firewall-Sperre
     vorübergehend entfernen?“ mit „Ja“ bestätigen). Der Dienst entfernt sie selbst und stellt sie
     **nicht** wieder her bis zur nächsten regulären Erneuerung (täglich, neue ThreatFox-Daten oder
     Neustart des Dienstes). Regeln von Hand in der Firewall-Konsole zu löschen hilft nicht – die
     stellt der Dienst sofort wieder her:

```
& "C:\Program Files\K9\k9.exe" firewall entfernen
```

  2. Dauerhaft ausschalten (normale PowerShell). Das schwächt den Schutz: im Meldefenster
     „Änderung übernehmen“ wählen und im Bestätigungsfenster „Ja“; danach entfernt der Dienst die
     Regeln innerhalb von 30 Sekunden selbst:

```
& "C:\Program Files\K9\k9.exe" funktion firewall aus
```

## Eingehende Firewall-Regeln

Programme können sich in der Windows-Firewall selbst Türen nach innen öffnen. Der Dienst bemerkt jede
neue oder geänderte **eingehende** Regel sofort und meldet sie, wenn sie Verbindungen **von jeder
Adresse** zulässt und eines davon zutrifft:

- **kein Programm angegeben** – dann darf *jedes* Programm an diesem Port Verbindungen annehmen
  (Schweregrad Hoch, wenn die Regel auch im öffentlichen Netz gilt, sonst Mittel),
- das Programm liegt in einem Ordner, in den jedes Programm schreiben kann (Benutzerordner,
  AppData, Temp, ProgramData) – Mittel,
- das Programm ist nicht gültig digital signiert – Mittel.

Nur ins Dienst-Protokoll kommen: die Regeln, die Windows für das eigene Netz der Windows-Sandbox
anlegt („HNS Container Networking – DNS …“, an eine einzige Netzwerkschnittstelle gebunden), Regeln für gültig signierte Programme (z. B. in „Programme“ oder in
einer Spielebibliothek), Teile von Windows, Store-Apps, Regeln nur für das eigene Netz und Regeln für
Programme, die es nicht mehr gibt. K9s eigene Regeln werden nie gemeldet.

Beim **allerersten Start** merkt sich der Dienst alle vorhandenen Regeln als Ausgangsstand – gemeldet
wird nur, was danach neu dazukommt. Wird dieselbe Regel immer wieder angelegt (wie die 3151-mal
vorhandene „allow 9009“), gibt es **eine** Meldung mit der Anzahl. Die Meldung nennt Port, Protokoll,
Profile, das Programm und – wenn es noch im Firewall-Protokoll steht – **welches Programm die Regel
angelegt hat** (mit Signatur).

Deine Wahl im Meldefenster oder Dashboard:

- **„Regel entfernen“** (bei Kopien „Regel entfernen (alle N gleichen)“): entfernt genau diese Regel
  und ihre gleichen Kopien – nichts anderes, nie K9s eigene. Mit Bestätigungsfenster. Wird die Regel
  danach wieder angelegt, meldet K9 das erneut; dann das genannte Programm prüfen.
- **„Freigabe (diese Regel nicht mehr melden)“**: merkt sich genau diese Regel.
- **„Gesehen“**: schließt die Meldung, die Regel bleibt.

Nichts wird automatisch entfernt. Während eines Spiels wartet die Meldung bis danach.

Welche der vorhandenen Regeln gemeldet würden, wenn sie neu wären (ändert nichts, normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" firewall eingang
```

## Programme und Skripte aus dem Internet

Windows merkt sich bei jeder Datei, die aus dem Internet kommt, die Herkunft: Browser, Mail-Programme
und der Explorer (beim Entpacken eines geladenen ZIP-Archivs) hängen der Datei einen unsichtbaren
Vermerk an („Internet-Zone“, meist mit der Download-Adresse). K9 nutzt diesen Vermerk in dem Moment,
in dem die Datei **gestartet** wird – unabhängig davon, ob sie in einer Liste bekannter Schadsoftware
steht:

| Was gestartet wird | Meldung | Schwere |
|---|---|---|
| Programm (`.exe` …) aus dem Internet **ohne gültige Signatur** eines Herstellers | „Unsigniertes Programm aus dem Internet gestartet: …“ | Mittel |
| Skript (`.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.hta`, `.ps1`, `.bat`, `.cmd`) aus dem Internet, gestartet über `wscript`, `cscript`, `mshta`, PowerShell oder `cmd` | „Skript aus dem Internet gestartet: … (über wscript.exe)“ | Hoch |
| Signiertes Programm aus dem Internet, selbst erstellte Dateien, Skripte ohne Internet-Vermerk | keine Meldung | – |

**Warum Skripte „Hoch“ sind:** Ein Doppelklick auf eine `.js`- oder `.vbs`-Datei führt sie sofort aus.
Angreifer verschicken sie als „Rechnung“, „Lieferschein“ oder „Bewerbung“, oft in einem ZIP-Archiv.
Skripte ändern sich ständig, deshalb stehen neue Varianten selten schon in einer Liste. Im
Vergleichstest vom 19.11.2026 liefen drei von fünf Skript-Proben, ohne dass K9 nach dem Start etwas
meldete – diese Meldung schließt die Lücke.

**Was die Meldung zeigt:** das Skript, das Programm, das es ausführt, die Download-Adresse (ohne
Zusätze nach „?“, die Zugangsschlüssel enthalten können) und was das Skript gestartet hat. Passiert
danach mehr (Autostart, Zugriff auf Zugangsdaten, Verbindung zu einer Schad-Adresse), fasst K9 das zu
einer **Angriffskette** zusammen.

**Deine Wahl:**

- **„Prozess beenden“** – beendet das laufende Skript (das Windows-Programm selbst wird nie gelöscht).
  Danach die Skriptdatei löschen und einen vollständigen Scan starten.
- **„Freigabe (genau dieses Skript)“** – für ein Skript, das du kennst (z. B. ein eigenes
  Installationsskript). Gilt nur für genau diesen Inhalt; eine geänderte Datei wird wieder gemeldet.
- **„Nur diesmal erlauben“** – schließt die Meldung, ohne etwas zu merken.

Jedes Skript wird einmal gemeldet, nicht bei jedem Start. In Arbeitsordnern (Claude-Projekte) kommt die
Meldung nur leise ins Dashboard. Ausschalten (beide Meldungen, wirkt nach deiner Bestätigung):
`k9 funktion download-herkunft aus`.

Es spielt keine Rolle, wie das Skript aufgerufen wird: mit vollem Pfad (so startet es ein Doppelklick)
oder nur mit dem Dateinamen aus einem Ordner heraus (`wscript rechnung.js`) – K9 liest dann den
Arbeitsordner des gestarteten Programms aus und findet die Datei darüber.

**Grenzen:** Ohne Internet-Vermerk gibt es keine Meldung – z. B. bei Dateien von einem USB-Stick oder
wenn ein Packprogramm den Vermerk beim Entpacken nicht weitergibt (7-Zip tut das nur, wenn man es
einstellt; der Windows-Explorer tut es immer). Solche Skripte prüft K9 weiter über Hashlisten,
YARA, ClamAV und – bei PowerShell – über die Skriptprüfung.

## Große Listen für das Netzwerk (standardmäßig aus)

Zwei zusätzliche, frei verfügbare Listen erweitern die Prüfung von DNS-Abfragen und Verbindungen
(seit Version 0.29.0). Beide sind **aus**, bis du sie einschaltest (normale PowerShell):

```
cd "C:\Program Files\K9"
.\k9.exe funktion schad-domains an
.\k9.exe funktion spamhaus-drop an
.\k9.exe quellen aktualisieren
```

| | Schad-Domains (HaGeZi) | Gekaperte Netze (Spamhaus DROP) |
|---|---|---|
| Schalter | `schad-domains` | `spamhaus-drop` |
| Inhalt | rund 390.000 Domains von Schadsoftware-, Phishing- und Betrugsseiten („Threat Intelligence Feeds“, mittlere Liste) | 1.751 Netze, die gekapert sind oder von Kriminellen betrieben werden |
| Wo es wirkt | bei jeder DNS-Abfrage (Dienst), auch für Unterdomains | bei jeder Verbindung (Agent, alle 2 Sekunden) |
| Meldung | „Dieser PC hat die als schädlich gelistete Domain … aufgelöst (HaGeZi TIF)“ | „Verbindung zu bekannter Schad-Adresse … (Spamhaus DROP)“ |
| Schwere | **Mittel** – eine große Sammelliste ist ungenauer als die bisherigen Listen | **Hoch** |
| Speicher und Tempo | 3 MB; eine Abfrage kostet weniger als eine Millionstel Sekunde | wenige Kilobyte |
| Lizenz | GPL-3.0; wird beim Aktualisieren geladen, nicht mit K9 ausgeliefert | kostenlos, Quelle: The Spamhaus Project |

Die bisherigen, genaueren Listen (ThreatFox, URLhaus, Phishing-Filter) gewinnen, wenn eine Domain
auf mehreren steht. Ausschalten: `.\k9.exe funktion schad-domains aus` bzw. `… spamhaus-drop aus`
(wirkt erst nach deiner Bestätigung).

**Was zu erwarten ist:** Eine Sammelliste dieser Größe trifft gelegentlich auch Seiten, die nur
zweifelhaft sind (Werbenetze mit Betrugsanzeigen, frisch registrierte Domains). Hast du die Seite
selbst aufgerufen und nichts eingegeben oder geladen, genügt „Gesehen“. Wie viele solcher
Meldungen auf deinem PC kommen, ist noch nicht gemessen – deshalb sind die Listen zunächst aus.
Von HaGeZi gibt es auch eine volle Liste mit rund 2,3 Millionen Domains; K9 nutzt bewusst die
mittlere.

## Sigma-Regeln (standardmäßig aus)

**Was das ist:** „Sigma“ ist eine offene Sammlung von Erkennungsregeln (SigmaHQ), die
Sicherheitsfachleute weltweit pflegen. Die Regeln beschreiben typische Angriffs-Befehle, zum
Beispiel missbrauchte Windows-Werkzeuge. K9 prüft damit **jeden Programmstart** – zusätzlich zu den
eigenen Regeln. Das hilft bei Schadsoftware, die in keiner Liste steht und nur am Verhalten auffällt.

Einschalten (normale PowerShell; der Dienst lädt das Regelpaket beim nächsten Abgleich, spätestens
nach 30 Minuten):

```
cd "C:\Program Files\K9"
.\k9.exe funktion sigma an
.\k9.exe quellen aktualisieren sigma
```

Ausschalten: `.\k9.exe funktion sigma aus` (wirkt erst nach deiner Bestätigung im Fenster).

| Frage | Antwort |
|---|---|
| Welche Regeln? | Seit Version 0.44.0 zusätzlich das Zusatzpaket „Emerging Threats“ desselben Sigma-Release (Regeln zu aktuellen Angriffswellen und ausgenutzten Sicherheitslücken): 158 weitere Regeln der Stufen hoch und kritisch für Programmstarts, zusammen 712 (Stand r2026-07-01). Kein eigener Schalter – es gehört zu `sigma` und kommt mit der nächsten Aktualisierung der Quelle. Dazu wie bisher: Das Paket „core“ von SigmaHQ: nur die Stufen **hoch** und **kritisch**. Davon betreffen 558 den Start von Programmen unter Windows; 554 kann K9 auswerten (Stand r2026-07-01). **55 dieser 554 Regeln können bei K9 nie auslösen** (gezählt am 21.11.2026, seit Version 0.35.1 zeigt `k9 quellen` die Zahl an): Sie verlangen auf jedem Weg eine Angabe, die K9 nicht hat – etwa den ursprünglichen Dateinamen (Regeln „Renamed … Execution“), den Datei-Fingerabdruck Imphash oder den Benutzer. Wirksam sind also 499 Regeln. |
| Was sieht K9 von einem Start? | das Programm, seine Befehlszeile und das startende Programm. Verlangt eine Regel etwas anderes (z. B. den ursprünglichen Dateinamen oder den Benutzer), kann K9 diesen Teil nicht beantworten – eine solche Regel löst dann **nie** aus, statt zu raten. Wie viele der 554 Regeln dadurch stumm bleiben, ist noch nicht gezählt. |
| Wie sieht die Meldung aus? | „Sigma-Regel „Titel der Regel“ (Autor: …)“ mit Programm und Befehlszeile. Den Autor zu nennen, verlangt die Lizenz der Regeln. Knöpfe wie bei anderen Programmstarts. Meist ist das gemeldete Programm schon beendet, dann stehen dort **„Gesehen (Prozess beendet, nichts wird gemerkt)“** und „Freigabe (genau diese Befehlszeile)“. Läuft es noch, heißen sie „Prozess beenden“, „Nur diesmal erlauben“ und „Freigabe (genau diese Befehlszeile)“. |
| Welche Schwere? | Sigma „kritisch“ wird in K9 **Hoch**, Sigma „hoch“ wird **Mittel**. Nie „Kritisch“: Die Regeln sind allgemeine Faustregeln, und ein Treffer soll kein Programm einfrieren. |
| Fehlalarme? | Möglich – die Regeln sind für Firmennetze geschrieben. In deinen Arbeitsordnern (Claude-Projekte) kommen Sigma-Meldungen nur leise ins Dashboard. Meldet K9s eigene Regel denselben Start schon, gibt es keine zweite Meldung von Sigma. |
| Was bringt es? | Gemessen am 22.11.2026 (Testbericht 7.37): Von 20 typischen Angreifer-Befehlszeilen meldet K9 mit seinen eigenen Regeln 9, mit den Sigma-Regeln zusammen 18. Neun Befehle werden **nur** dank Sigma gemeldet (z. B. regsvr32 mit Netzadresse, Ereignisprotokoll leeren, SAM sichern, Speicherabbild über comsvcs.dll). Von fünf harmlosen Befehlen meldete Sigma „core“ keinen. |
| Was kostet es? | Gemessen auf diesem PC: rund 0,25 Millisekunden je Programmstart (optimierte Fassung, 554 Regeln). Beim Spielen ist das nicht spürbar; Programme starten dort selten. |
| Woher kommt das Paket? | vom offiziellen Release bei GitHub, einmal am Tag, mit Prüfsumme. Ein beschädigtes Paket ersetzt das alte nicht. |

**Grenzen:** Die Prüfung läuft nur im Windows-Dienst. Mit echter Schadsoftware in der Sandbox ist
sie noch nicht getestet – eingeschaltet lassen und ein paar Tage beobachten ist der empfohlene Weg.
Die zweite geplante Quelle „LOLBAS“ ist noch nicht eingebunden.

## Dateien aus einer Schattenkopie zurückholen (seit Version 0.44.0)

**Wozu:** K9 legt im Leerlauf Schattenkopien deiner Laufwerke an (Schalter `schattenkopien`). Eine
Schattenkopie ist ein eingefrorener Stand des Laufwerks von einem bestimmten Zeitpunkt. Hat
Ransomware Dateien verschlüsselt, bevor K9 sie anhalten konnte – im Test mit BlackBasta ohne den
Schalter `neue-programme` waren es 32 von 160 Dokumenten –, liegen die unversehrten Fassungen noch
in der letzten Schattenkopie davor. Mit `k9 wiederherstellen` holst du sie heraus.

**Was der Befehl tut – und was nicht:** Er liest einen Ordner aus der Schattenkopie und kopiert
alle Dateien, die es heute **nicht mehr gibt** oder die heute **anders** sind (Größe oder
Änderungszeit), in einen **neuen** Ordner. Dein Ordner wird dabei nicht verändert, nichts wird
überschrieben, nichts gelöscht. Du vergleichst danach selbst und kopierst zurück, was du brauchst.

**So gehst du vor.** Schattenkopien lassen sich nur mit Administratorrechten lesen: Rechtsklick auf
das Startmenü, „Terminal (Administrator)“ öffnen.

1. Ansehen, welche Schattenkopien es gibt:

```powershell
& "C:\Program Files\K9\k9.exe" wiederherstellen liste
```

2. Dateien eines Ordners zurückholen – aus der neuesten Schattenkopie:

```powershell
& "C:\Program Files\K9\k9.exe" wiederherstellen "C:\Users\anna\Documents"
```

3. Oder aus der neuesten Schattenkopie **vor** einem bestimmten Zeitpunkt (z. B. vor dem Angriff)
   und in einen Ordner deiner Wahl:

```powershell
& "C:\Program Files\K9\k9.exe" wiederherstellen "C:\Users\anna\Documents" --stand "2026-11-21 22:30" --ziel "D:\Zurueck"
```

Ohne `--ziel` legt K9 auf dem Desktop den Ordner „K9-Wiederherstellung <Datum Zeit>“ an. Mit
`--alles` werden auch die unveränderten Dateien kopiert.

Am Ende steht, wie viele Dateien in der Schattenkopie heute fehlen, wie viele verändert sind und
wie viele kopiert wurden.

**Wichtig nach einem Angriff:** erst das Schadprogramm loswerden („Prozess beenden“, Datei in
Quarantäne, vollständiger Scan), dann zurückholen. Und zügig – Windows löscht die ältesten
Schattenkopien von selbst, wenn der Speicher dafür voll ist.

**Grenzen:**

- Es gibt nur zurück, was beim Anlegen der Schattenkopie schon da war. Alles Jüngere fehlt.
- Viele Ransomware löscht die Schattenkopien zuerst. K9 meldet das und hält das Programm an
  („Löschen der Wiederherstellungsdaten“), aber darauf verlassen darf man sich nicht: Eine
  Sicherung auf einem getrennten Datenträger ersetzt dieser Befehl nicht.
- Der Zielordner muss leer oder neu sein und darf nicht im Ordner liegen, den du zurückholst.
- Dateien, die heute nur umbenannt wurden (Ransomware hängt oft eine Endung an), zählen als
  „fehlt heute“ und werden zurückgeholt; die verschlüsselte Fassung bleibt in deinem Ordner liegen.
- **Stand der Prüfung:** Auf dem Test-PC ausprobiert am 22.11.2026 (Testbericht 7.40): Die Liste
  zeigte 19 Schattenkopien; aus der Kopie vom 21.11., 22:24 Uhr, kamen die fünf seitdem geänderten
  Dateien des Doku-Ordners zurück, Byte für Byte gleich dem Stand jenes Abends. Mit einem echten
  Ransomware-Schaden wurde der Befehl nicht getestet.

## YARA-Regeln: Fehlalarme und das erweiterte Paket (seit Version 0.43.0)

**Worum es geht:** YARA-Regeln beschreiben Muster im Inhalt von Dateien. K9 lädt sie von YARA Forge,
standardmäßig das Paket „core“ (rund 5.000 Regeln). Es gibt auch das Paket „extended“ mit rund
10.800 Regeln. Mehr Regeln finden mehr, schlagen aber auch öfter bei sauberen Dateien an.

**Gemessen am 22.11.2026 auf dem Test-PC** (Testbericht 7.38): 269.136 saubere Dateien, 61 GB, aus dem
Windows-Systemordner und `C:\Program Files`, nur lesend.

| Paket | Regeln | Treffer auf sauberen Dateien | davon laut bis 0.42.0 | davon laut ab 0.43.0 |
|---|---|---|---|---|
| „core“ (Standard) | 5.078 | 14 Dateien (7 Regeln) | 14 | **1** |
| „extended“ | 10.848 | 25 Dateien (11 Regeln) | 25 | **2** |

Fast die Hälfte der Treffer lag in den Signaturdateien von Trend Micro: Ein Virenscanner trägt die
Muster von Schadsoftware in sich, und andere Scanner erkennen sie dort wieder. Der Rest betraf
signierte Dateien von NVIDIA, Adobe, Microsoft Visual Studio, Papyrus und Raspberry Pi Imager.

**Was K9 seit 0.43.0 damit macht:** Ein YARA-Treffer kommt **nur leise ins Dashboard** (ohne Fenster
und Ton, mit der Begründung in der Meldung), wenn die Datei nicht aus dem Internet stammt und

- zu einem Schutzprogramm gehört (Ordner von Trend Micro, Windows Defender oder ClamAV unter
  `C:\Program Files`), oder
- eine gültige Signatur eines Herstellers trägt **und** in einem Ordner liegt, in den nur ein
  Administrator schreiben kann (`C:\Program Files`, `C:\Windows`), oder
- eine gültige Signatur trägt und seit über 7 Tagen unverändert auf dem PC liegt, oder
- unsigniert im Windows-Ordner liegt und seit über 7 Tagen unverändert ist (z. B. ein Skript eines
  Treiberpakets).

Alles andere meldet K9 wie bisher laut – jede Datei mit Internet-Kennzeichnung, jede unsignierte
Datei außerhalb von Windows, jede frische Datei in einem Benutzerordner. Bekannte Schadsoftware aus
den Hashlisten und ClamAV-Treffer sind von dieser Regel nicht betroffen.

**Gültig signierte Dateien (seit Version 0.50.2):** Trifft eine YARA-Regel eine Datei mit gültiger
digitaler Signatur, meldet K9 sie **höchstens als „Mittel“** und hängt an den Namen
„(Datei gültig digital signiert – vermutlich Fehlalarm, bitte prüfen)“. Eine solche Datei wird beim
Start **nicht mehr angehalten** – angehalten werden nur noch Treffer ab „Hoch“. Anlass war Meldung 446
vom 23.11.2026: Die Regel „CAPE_Hijackloaderstub“ hielt das Startprogramm von GitHub Desktop an, das
gültig von „GitHub, Inc.“ signiert ist. Regeln für Lade- und Packprogramme passen leider auch auf
harmlose Startprogramme und Installer. Gemeldet wird trotzdem weiter, denn Schadsoftware ist
manchmal mit einem gestohlenen Zertifikat signiert. Bei den Hashlisten gilt dasselbe schon länger
(dort „Niedrig“ mit dem Hinweis „vermutlich Fehleintrag“).

**Das erweiterte Paket einschalten** (Standard: aus):

```powershell
& "C:\Program Files\K9\k9.exe" funktion yara-erweitert an
& "C:\Program Files\K9\k9.exe" quellen aktualisieren yara_forge
```

Zurück zum Paket „core“: `k9 funktion yara-erweitert aus` (mit Bestätigung im Meldefenster) und
noch einmal `k9 quellen aktualisieren yara_forge`. Die Regeln mit einer Bewertung unter 60
(`yara_min_score`) lässt K9 bei beiden Paketen weg.

**Kosten:** Die Prüfung derselben 61 GB dauerte mit „core“ 143 Sekunden, mit „extended“ 191 –
ein Drittel länger. Beim Echtzeitschutz fällt das nicht auf, ein vollständiger Scan dauert
entsprechend länger.

**Grenzen:** Die Messung zeigt, welche Regeln auf **deinen** heutigen Dateien anschlagen. Ein neues
harmloses Programm kann morgen eine andere Regel treffen. Die zwei verbliebenen lauten Treffer sind
unsignierte Skriptdateien in `C:\Program Files` (PDF24, Visual Studio) – dafür gibt es weiterhin
die „Freigabe“. Die leise Regel verlässt sich auf die Signatur: Schadsoftware mit einer gestohlenen
gültigen Signatur, die sich nach `C:\Program Files` kopiert, würde bei einem YARA-Treffer nur leise
gemeldet. Ob „extended“ auch mehr echte Schadsoftware findet, ist nicht gemessen.

### Arbeitsdateien von Schutzprogrammen (seit Version 0.45.0)

**Der Anlass:** Trend Micro legt im Ordner `Temp` eine gepackte Arbeitsdatei an und hält sie
geöffnet, solange sein Fensterprogramm läuft. ClamAV schlägt darauf mit dem Muster
`PUA.Win.Exploit.CVE_2012_1461-1` an – das Muster erkennt eine bestimmte Bauart gepackter Archive,
keinen Schadcode. Jedes Mal, wenn Trend Micro den Inhalt änderte, kam die Meldung neu (Nr. 285 am
20.11., Nr. 387 am 22.11.2026), denn eine „Freigabe“ gilt immer nur für genau einen Inhalt.

**Was K9 jetzt bei jeder Dateimeldung tut:** Es fragt Windows, welche Programme die Datei gerade
geöffnet halten, und schreibt das in die Meldung („Beim Fund geöffnet von: …“ mit Programm, Pfad
und Signatur). Das hilft dir bei jeder Dateimeldung zu erkennen, wem die Datei gehört.

**Wann die Meldung nur leise ins Dashboard kommt** (ohne Fenster und Ton, mit Begründung) – nur wenn
**alles** davon zutrifft:

- Es ist ein Muster-Treffer von ClamAV oder YARA mit Schwere „Mittel“ oder darunter. Bekannte
  Schadsoftware aus den Hashlisten und alles mit Schwere „Hoch“ oder „Kritisch“ bleibt immer laut.
- Die Datei stammt nicht aus dem Internet und ist kein Programm und kein Skript (geprüft an der
  Endung und an den ersten Bytes).
- **Jedes** Programm, das die Datei offen hält, ist das gültig signierte Programm eines
  installierten Schutzprogramms (Trend Micro, Windows Defender oder ClamAV in `C:\Program Files`).
- Dasselbe Programm hält die Datei **zwei Sekunden später immer noch** offen. Das unterscheidet eine
  Arbeitsdatei von einer Datei, die ein Virenscanner nur kurz zum Prüfen öffnet – der lässt nach
  Millisekunden wieder los.

Geprüft am 22.11.2026 an der echten Datei: K9 nennt `uiWinMgr.exe` (Trend Micro, Inc.) als Halter
und ordnet die Meldung leise ein; die Prüfung dauert dann rund 2,2 Sekunden. Bei einer Datei, die
niemand offen hält, dauert sie 16 Millisekunden und die Meldung bleibt laut (Testbericht 7.43).

**Grenzen:** Die Regel vertraut der Signatur und dem Ordner des Schutzprogramms. Könnte ein Angreifer
ein echtes Schutzprogramm dazu bringen, seine Datei dauerhaft offen zu halten, käme ein
ClamAV- oder YARA-Treffer mittlerer Schwere darauf nur leise – im Dashboard steht er trotzdem. Im
Alltag beobachtet ist die leise Meldung noch nicht: Sie zeigt sich erst, wenn Trend Micro die Datei
das nächste Mal ändert.

## LOLBAS-Regeln (seit Version 0.40.0, standardmäßig aus)

**Was das ist:** „LOLBAS“ ist eine öffentliche Liste von derzeit 246 Programmen, die zu Windows
gehören und von Angreifern missbraucht werden – etwa `certutil`, um etwas aus dem Internet zu laden,
oder `rundll32`, um fremden Code auszuführen. Solche Programme sind signiert und unverdächtig; ein
Angreifer braucht dafür keine eigene Schadsoftware.

**Warum K9 nicht einfach die Liste nimmt:** Ein Programmname allein sagt nichts. `certutil` und
`msiexec` laufen auf jedem PC täglich. Entscheidend ist, **wie** ein Programm aufgerufen wird, und
das beschreiben die Sigma-Regeln, auf die LOLBAS verweist. Für 201 der 246 Programme gibt es solche
Regeln. Das Paket, das der Schalter `sigma` lädt, enthält aber nur die Stufen „hoch“ und
„kritisch“ – und damit Regeln zu nur 49 dieser Programme. Die meisten LOLBAS-Regeln haben die Stufe
„mittel“.

**Was der Schalter tut:** Mit `lolbas` lädt K9 zusätzlich genau die Regeln der Stufe „mittel“, auf
die LOLBAS verweist (derzeit 81), und prüft damit jeden Programmstart – nur dann, wenn weder die
eigenen Regeln von K9 noch die Sigma-Regeln aus `sigma` angeschlagen haben.

```powershell
& "C:\Program Files\K9\k9.exe" funktion lolbas an
& "C:\Program Files\K9\k9.exe" quellen aktualisieren lolbas
```

Der Dienst übernimmt den Schalter innerhalb von 30 Sekunden und lädt die Regeln beim nächsten
Aktualisieren der Quellen (der zweite Befehl holt sie sofort).

| Frage | Antwort |
|---|---|
| Wie sieht die Meldung aus? | „LOLBAS-Regel „Titel der Regel“ (Sigma, Autor: …)“ mit Programm und Befehlszeile, Schwere **Mittel**. |
| Warum sehe ich kein Meldefenster? | Absicht. Regeln der Stufe „mittel“ schlagen öfter bei harmlosen Dingen an – schon das Öffnen eines Eintrags der Systemsteuerung (`rundll32.exe shell32.dll,Control_RunDLL`) löst eine davon aus. Deshalb kommen LOLBAS-Treffer in der **Probephase nur leise ins Dashboard**, ohne Fenster und Ton. Nach einigen Tagen werten wir aus, welche Regeln stören. |
| Hält K9 dabei etwas an? | Nein. Angehalten wird nur bei kritischen Meldungen. |
| Was kostet es? | Gemessen: rund 0,02 Millisekunden je Programmstart (81 Regeln). |
| Brauche ich dafür `sigma`? | Nein, die beiden Schalter sind unabhängig. Zusammen decken sie mehr ab. |
| Woher kommen die Daten? | Die Liste von lolbas-project.github.io, die Regeln aus dem offiziellen Sigma-Release bei GitHub (mit Prüfsumme), einmal am Tag. |

**Was der erste Test gezeigt hat** (22.11.2026, Testbericht 7.37, 20 Angriffs-Befehlszeilen und
5 harmlose in der Sandbox): Die LOLBAS-Regeln haben **keinen** Befehl zusätzlich erkannt – alles,
was sie gefunden hätten, hatten die eigenen Regeln von K9 oder Sigma „core“ schon gemeldet – und
sie haben den einzigen Fehlalarm ausgelöst. Der Schalter ist also bisher eher eine Ergänzung auf
Verdacht als ein belegter Gewinn. Wenn die leisen Meldungen im Alltag nur stören, schalte ihn
wieder aus: `k9 funktion lolbas aus`.

**Grenzen:** 4 der 81 Regeln können mit den Angaben von K9 nie auslösen. Zu 45 der 246 Programme
gibt es gar keine Sigma-Regel. Mit echten Angriffen ist die Wirkung nicht geprüft – bekannt ist
bisher nur, dass die Regeln geladen und ausgewertet werden und was sie kosten.

## Wie gut erkennt K9? (Vergleichstest mit echter Schadsoftware)

Vom 18. bis 20.11.2026 wurde K9 in der Windows-Sandbox mit echten, aktuellen Schadprogrammen von
MalwareBazaar geprüft (Einzelheiten: Testbericht, Abschnitte 7.12, 7.13, 7.15, 7.17 und 7.19). Kurz gefasst:

| Frage | Ergebnis |
|---|---|
| Erkennt K9 gemeldete Schadsoftware als Datei? | Ja: 26 von 30 im ersten Lauf, 20 von 20 im zweiten. Fast immer über die **Hashliste** – die vier Verpassten waren erst Minuten alt und noch nicht gelistet. |
| Erkennt K9 Schadsoftware, die in keiner Liste steht, am Inhalt? | Teilweise: 11 von 30 bzw. 8 von 20 über YARA/ClamAV. Gut bei ausführbaren Fernsteuerungs-Trojanern, **kaum bei Skripten**. |
| Wie schneidet die Dateiprüfung von Trend Micro ab? | 16 von 30 bzw. 12 von 20 (nur die Engine bei VirusTotal – dein installiertes Trend Micro hat zusätzlich Verhaltensschutz). |
| Meldet K9 etwas, wenn die Schadsoftware läuft? | Bei 14 von 19 gestarteten Proben: 5-mal echtes Verhalten (Autostart, Steuer-Adresse, Angriffskette, PowerShell), 9-mal die Warnung „unsigniertes Programm aus dem Internet“. 5 liefen ohne Meldung – darunter drei Skripte (seit 0.19.0 gemeldet) und ein gültig signiertes Fernwartungsprogramm. |
| Erkennt K9 Datendiebe am Verhalten? | Im dritten Lauf (19.11., 11 Datendiebe, Sandbox mit Schein-Browserprofilen als Köder, ohne Hashlisten): eine Probe griff nachweislich nach den Ködern und wurde gemeldet (zwei Speicher, Angriffskette). Bei den anderen zehn kam nur die Herkunftswarnung – ob sie ohne Netzwerk überhaupt etwas stehlen wollten, ließ sich nicht feststellen. |
| Erkennt K9 Ransomware am Verhalten? | Meistens: Im Test vom 20.11. (zehn Familien, je eine Probe) haben sechs Proben wirklich verschlüsselt; bei fünf davon schlug K9 Alarm (LockBit, MedusaLocker, BlackMatter, BlackBasta, Babuk). **Conti wurde nicht aufgehalten** – auch am 21.11. mit K9 0.30.0 nicht: Es beendet erst den K9-Agenten, dann den K9-Dienst und verschlüsselt danach (Testbericht 7.24, in der Sandbox mit Administratorrechten). |
| Rettet K9 dann die Dateien? | Nur mit dem Schalter „Ransomware-Verdächtige anhalten“ (Standard: aus). Ohne ihn waren bei allen sechs Proben alle 160 Schein-Dokumente verschlüsselt. Mit ihm blieben bei den fünf erkannten Proben 104 bis 150 von 160 erhalten (65 bis 94 %). |
| Was wurde nicht geprüft? | Vier Ransomware-Proben verschlüsselten in der Sandbox nichts. Datendiebe mit Verbindung zu ihrem Steuerserver – die Sandbox hat absichtlich kein Netzwerk. |

**Was das für dich heißt:** K9 ist eine sinnvolle zweite Meinung neben Trend Micro, vor allem durch die
laufend aktualisierten Hashlisten und die Meldungen beim Start. Die Hashliste von MalwareBazaar wird
einmal am Tag vollständig geladen und seit Version 0.20.0 **jede Stunde** um die neuesten Einträge
ergänzt (Abschnitt „Erkennungsquellen“). Schadsoftware, die jünger ist als der letzte Abruf, steht
noch nicht darin – im Test waren das die vier Verpassten. Es ist kein Ersatz: Ganz neue Schadsoftware,
die noch niemand gemeldet hat und die sich unauffällig verhält, kann auch K9 übersehen. Am meisten
schützt weiterhin, Anhänge und Downloads aus unbekannter Quelle nicht zu starten.

## Wie oft prüft K9?

| Was | Wann |
|---|---|
| Start eines Programms oder Skripts aus dem Internet | sofort (Dienst) |
| Neue/geänderte Dateien in Downloads, Desktop, Dokumente, TEMP, Autostart-Ordner | sofort (etwa 1,5 Sekunden, nachdem die Datei fertig geschrieben ist) |
| Ransomware-Verdacht (viele Dateien plötzlich mit verschlüsseltem Inhalt) | sofort (Dienst und Agent: Prüfung eine Viertelsekunde nach dem Schreiben, Alarm ab 12 Dateien) |
| Programmstarts, PowerShell-Skripte, Zugriff auf gespeicherte Zugangsdaten, DNS-Abfragen | sofort (Dienst, Windows-Ereignisse) |
| Ransomware-Köderdateien verändert | sofort |
| Neue eingehende Firewall-Regeln | sofort, zusätzlich alle 10 Minuten |
| Konten und Anmeldungen | sofort (etwa 1 Sekunde), zusätzlich jede Minute |
| USB-Sticks/Speicherkarten | beim Einstecken |
| Manipulation an K9 (Agent beendet) | alle 5 Sekunden; Programmdateien und Einstellungen alle 10 Minuten |
| Neue Autostarts (Run-Schlüssel, Autostart-Ordner) | sofort, zusätzlich alle 30 Sekunden (Browser-Hilfsprogramme nur alle 30 Sekunden) |
| Verbindungen zu Schad-Adressen | alle 2 Sekunden (während eines Spiels alle 5); DNS-Zwischenspeicher alle 60 Sekunden (`netzwerk_intervall_sekunden`) |
| Neue Treiber | jede Minute; alle Treiber gegen die Sperrlisten alle 6 Stunden |
| Geplante Aufgaben, Dienste, versteckte WMI-Autostarts | alle 10 Minuten (nicht während eines Spiels) |
| Browser-Erweiterungen | regelmäßig im Hintergrund (nicht während eines Spiels) |
| Neue Geräte im Heimnetz | alle 15 Sekunden die Geräteliste von Windows (sendet nichts), alle 5 Minuten alle Adressen (nicht während eines Spiels) |
| Sicherheits-Check | alle 6 Stunden; veraltete Programme (winget) einmal am Tag |
| Neue Sicherheitslücken (CVE) installierter Programme | einmal am Tag (nicht während eines Spiels) |
| Speicher-Scan (nur wenn eingeschaltet) | im Leerlauf ab 10 Minuten ohne Eingabe, jedes Programm höchstens alle 6 Stunden; nie bei Spiel oder Anti-Cheat |
| Neueste Schadsoftware-Hashes (MalwareBazaar, Einträge der letzten 48 Stunden) | jede Stunde (nicht während eines Spiels) |
| Übrige Erkennungsdaten (vollständige Hashliste, YARA, ClamAV, Adresslisten …) | alle 24 Stunden, je Quelle einstellbar (nicht während eines Spiels) |
| Geplanter Scan der Standardordner, Software- und Adressprüfung | nach deinem Zeitplan; Standard: nach 20 Minuten Leerlauf, höchstens einmal in 24 Stunden |
| Vollständiger Scan aller Laufwerke | nur von Hand: Dashboard, Kasten „Status“ (Teil 2, „Scannen: Schnellscan und vollständiger Scan“) |
| Ausfall einer Erkennungsquelle oder von ClamAV | alle 30 Minuten (Dienst, nicht während eines Spiels) |
| Wochenbericht | einmal pro Woche |

„Sofort“ heißt: Windows meldet das Ereignis an K9, es gibt keine Wartezeit durch einen Prüftakt.
Während eines Spiels laufen nur die leichten Sofort-Prüfungen weiter; Fenster kommen erst danach
(außer Ransomware und kritischer Datendiebstahl).

## Arbeitsordner (leise Meldungen)

Auf manchen PCs arbeiten Entwicklungswerkzeuge wie Claude Code. Sie bauen Programme, starten PowerShell mit
verschlüsselten Befehlen oder einen Browser für Webseiten-Abrufe. Für K9 sieht das aus wie ein
Angriff. Damit du deswegen keine Meldefenster bekommst, gibt es **Arbeitsordner** und
**Arbeitsprogramme**:

- **Arbeitsordner** (Standard: `%TEMP%\claude`, dort legen alle Claude-Projekte ihre Arbeitsdateien
  ab): Liegen alle Spuren einer Verhaltensmeldung dort, kommt sie **leise**.
- **Arbeitsprogramme** (Standard: `%USERPROFILE%\.local\bin\claude.exe`): Wurde das gemeldete
  Programm von einem Arbeitsprogramm gestartet (auch über Zwischenschritte wie `cmd.exe` oder
  `bash.exe`), kommt die Meldung leise. Das gilt nur, wenn das Arbeitsprogramm **gültig digital
  signiert** ist. Eine gefälschte `claude.exe` zählt also nicht.

**Leise** heißt: Die Meldung steht im Dashboard unter „Offene Erkennungen“ ganz unten mit dem Hinweis
„Leise (nur im Dashboard, kein Meldefenster)“ und dem Grund. Es öffnet sich kein Meldefenster, es
geht keine E-Mail und keine Handy-Nachricht raus, und das Symbol im Infobereich bekommt keinen Punkt.
Entscheiden kannst du wie immer, auch mehrere auf einmal. Viele Ransomware-Verdachte im selben
Arbeitsordner ergeben **eine** Meldung statt Hunderte.

**Eine Regel für ein Arbeitsprogramm freigeben (seit Version 0.48.0).** Manche leisen Meldungen
kommen immer wieder: Jeder PowerShell-Befehl eines Claude-Projekts löst zum Beispiel dieselben
zwei, drei Regeln aus, und du schließt sie jedes Mal von Hand. Bei einer leisen Meldung mit dem
Grund „gestartet von deinem Arbeitsprogramm claude.exe …“ gibt es deshalb eine weitere Schaltfläche:

> **„Freigabe (diese Regel für alles, was dein Arbeitsprogramm claude.exe startet)“**

- **Wirkung:** Alle offenen Meldungen dieser Regel aus demselben Arbeitsprogramm sind damit
  erledigt. Schlägt die Regel später wieder bei etwas an, das dieses Arbeitsprogramm gestartet hat,
  legt K9 keine offene Meldung mehr an. Der Vorgang bleibt unter „Letzte Erkennungen“ sichtbar
  (Status „automatisch“).
- **Gilt nur**, wenn das Arbeitsprogramm gültig signiert ist und am selben Ort liegt wie bei der
  Freigabe. Derselbe Befehl aus einer anderen Quelle wird normal gemeldet.
- **Gilt nie** für Meldungen mit Schwere „Kritisch“, für Schadsoftware-Treffer und für alles, was
  nicht leise ist.
- **Bestätigung und Widerruf** wie bei jeder Freigabe: Der Dienst fragt in seinem Fenster nach, und
  unter „Gespeicherte Entscheidungen“ steht der Eintrag „Regel … für alles, was dein
  Arbeitsprogramm claude.exe startet“, den du dort widerrufen kannst.
- **Der Preis:** Für die freigegebene Regel vertraust du allem, was dieses Arbeitsprogramm startet.
  Würde ein Claude-Projekt etwas Schädliches ausführen, fiele es bei genau dieser Regel nicht mehr
  auf; alle anderen Regeln und Schutzschichten bleiben wie sie sind. „Diese Regel“ meint die Regel
  hinter der Meldung, bei „powershell.exe mit verdächtigen Argumenten“ also alle verdächtigen
  PowerShell-Befehlszeilen, nicht nur die eine angezeigte.

Leise werden nur diese Verhaltensmeldungen (unter „Kritisch“): verdächtige Befehlszeilen und
Programmketten, Browser-Fernsteuerung, PowerShell-Skripte, unsignierte Programme und Skripte aus dem Internet,
Zugriffe auf gespeicherte Zugangsdaten. Dazu kommt der Ransomware-Verdacht „viele Dateien
verschlüsselt“, wenn alle betroffenen Dateien in einem Arbeitsordner liegen. **Immer normal**
gemeldet werden: bekannte Schadsoftware (Hashlisten, YARA, ClamAV), Köderdateien, Angriffsketten,
Selbstschutz, Autostarts, Treiber, Firewall-Regeln und jede andere kritische Meldung.

Anzeigen, welche Arbeitsordner gelten (normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" arbeitsordner status
```

Einen Ordner hinzufügen, z. B. alle Projekte unter `D:\Projekte` (normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" arbeitsordner hinzufuegen "D:\Projekte"
```

Ein neuer Arbeitsordner schwächt den Schutz. Er wirkt deshalb erst, wenn du im Meldefenster
„Änderung übernehmen“ wählst und im Bestätigungsfenster „Ja“. Danach gilt er nach spätestens
30 Sekunden, ohne Neustart. Bis dahin zeigt `arbeitsordner status` „(wartet auf deine Bestätigung)“.
Entfernen wirkt sofort:

```
& "C:\Program Files\K9\k9.exe" arbeitsordner entfernen "D:\Projekte"
```

**Leise beim Update:** Dasselbe gilt, solange K9 selbst ein Programm aus der Liste der veralteten
Programme aktualisiert, installiert oder deinstalliert, und zwei Minuten danach. Leise mit dem Vermerk
„beim Update von …“ kommen dann nur eindeutige Nebenwirkungen des Installationsprogramms: Hilfsdateien
im Temp-Ordner, die nur eine Verdachts-Regel treffen (YARA „Indicator“/„Suspicious“, ClamAV „PUA“),
neue Autostart-Einträge der Stufe Info (einmalige Einträge, Update-Prüfer) und – seit Version 0.22.1 –
das Installationsprogramm eines Browsers, das beim Update dessen eigene Daten liest (Beispiel: Der
Opera-Installer läuft aus dem Temp-Ordner und liest das Opera-Profil). Das gilt nur, wenn alles
zusammenpasst: K9 aktualisiert gerade genau diesen Browser, das Programm ist gültig signiert, liegt im
Temp-Ordner und liest nur diesen einen Speicher. Liest es die Daten eines **anderen** Browsers oder
mehrere Speicher, kommt die Meldung normal. Bekannte Schadsoftware, kritische Meldungen,
Firewall-Regeln, Anmeldungen und neue Geräte bleiben immer laut.

Ganz abschalten: in `config.toml` unter `[arbeitsordner]` `aktiv = false` setzen. Dann kommt
jede Meldung wieder normal.

## Konten und Anmeldungen

Wer sich Zugang zu deinem PC verschafft, legt oft ein eigenes Konto an, macht sich zum
Administrator oder meldet sich per Remotedesktop an. Windows benachrichtigt den Dienst
**sofort**, wenn ein solcher Eintrag ins Sicherheitsprotokoll geschrieben wird; die Meldung kommt
innerhalb etwa einer Sekunde (während eines Spiels wartet das Fenster wie immer bis danach). Als
Reserve liest der Dienst zusätzlich jede Minute nach (während eines Spiels alle 5 Minuten). Windows schreibt diese Einträge von selbst, K9 ändert keine Windows-Einstellung.

| Meldung | Schwere |
|---|---|
| Neues Benutzerkonto angelegt | Hoch |
| Konto zur Gruppe Administratoren oder Remotedesktopbenutzer hinzugefügt | Hoch |
| Benutzerkonto aktiviert (eingebautes Administrator- oder Gastkonto: Hoch); nicht, wenn es zum Anlegen desselben Kontos gehört | Mittel |
| Anmeldung per Remotedesktop (aus dem Internet: Hoch, aus deinem Netz: Mittel) | Hoch/Mittel |
| 10 oder mehr fehlgeschlagene Anmeldungen in 10 Minuten (höchstens einmal in 30 Minuten) | Hoch, wenn eine Adresse aus dem Internet dabei ist, sonst Mittel |
| Das Sicherheitsprotokoll wurde gelöscht (so verwischen Angreifer Spuren) | Hoch |

Jede Meldung nennt Konto, Uhrzeit und, wenn bekannt, wer es war bzw. die Adresse. Bei
fehlgeschlagenen Anmeldungen stehen seit Version 0.27.1 Konto, Herkunft und das Programm, das die
Anmeldung versucht hat, schon in der Überschrift, zum Beispiel „12 fehlgeschlagene Anmeldungen in
10 Minuten – Konto anna; von diesem PC, keine Netzwerkadresse; Programm msedge.exe“. Kamen die
Versuche von einem Programm auf dem PC, ist das kein Angriff von außen; der Hinweis sagt das dazu. Hast du es
selbst getan (z. B. ein neues Konto für die Familie): „Gesehen“. Sonst sagt die Meldung, was zu
tun ist. Beim **allerersten Start** merkt sich der Dienst nur den aktuellen Stand des Protokolls,
gemeldet wird erst, was danach passiert.

Ausschalten (wirkt erst nach deiner Bestätigung), normale PowerShell:

```
& "C:\Program Files\K9\k9.exe" funktion anmeldungen aus
```

## Sicherheits-Check (Dashboard)

Im Dashboard steht oben der Kasten **„Sicherheits-Check“**. Er zeigt mit einer Ampel, ob der
Grundschutz deines PCs stimmt: grün „in Ordnung“, gelb „prüfen“, rot „handeln“, grau „unbekannt“.
Zu jedem gelben oder roten Punkt steht daneben, was du tun kannst. **K9 ändert keine dieser
Einstellungen.** Der Agent prüft etwa 2 Minuten nach dem Start und dann alle 6 Stunden, nie während
eines Spiels. Unter der Tabelle steht, von wann der Stand ist („Stand: …“).

**Rückmeldung beim Klicken (seit Version 0.48.1):** Klickst du im Dashboard auf eine Schaltfläche,
dreht sich auf ihr sofort ein kleiner Kreis, bis das Ergebnis da ist. So siehst du, dass K9
arbeitet, auch wenn es einen Moment dauert.

**Du hast gerade etwas umgestellt?** Dann zeigt das Dashboard bis zur nächsten Prüfung noch den
alten Zustand. Klick im Bereich „Sicherheits-Check“ unter der Tabelle auf **„Jetzt neu prüfen“**
(seit Version 0.47.1) – K9 liest die Einstellungen sofort neu und ändert dabei nichts. Dasselbe
leistet der Befehl `& "C:\Program Files\K9\k9.exe" sicherheitscheck`. Die Liste der veralteten
Programme wird dabei nicht neu abgefragt; das geschieht weiter einmal am Tag.

| Punkt | Grün, wenn … |
|---|---|
| Virenschutz | ein Virenschutz (z. B. Trend Micro) an ist und aktuelle Virendefinitionen hat; Einträge längst deinstallierter Programme (Programmdatei fehlt) zählen nicht |
| Firewall | die Windows-Firewall im privaten und im öffentlichen Netz an ist (oder eine andere Firewall) |
| Windows-Updates | das letzte Windows-Update höchstens 35 Tage her ist (rot ab 60 Tagen) |
| Secure Boot | Secure Boot im BIOS/UEFI an ist |
| Benutzerkontensteuerung | sie an ist und bei Änderungen nachfragt |
| Remotedesktop | Remotedesktop aus ist (gelb, wenn an: andere könnten sich anmelden) |
| Speicherintegrität | die Speicherintegrität (Kernisolierung) an ist |
| Lokale Sicherheitsautorität | der „Schutz durch lokale Sicherheitsautorität“ an ist (seit Version 0.48.0). Er verhindert, dass Schadsoftware sich in den Teil von Windows einklinkt, der deine Anmeldedaten verwaltet. Einschalten: Windows-Sicherheit → Gerätesicherheit → Kernisolierung; kostet keine Leistung |
| Datensicherung | die neueste Datei in deinem Sicherungsordner höchstens 14 Tage alt ist (rot ab 30 Tagen) |
| Programm-Updates | alle über winget bekannten Programme aktuell sind |

**Datensicherung:** Trag den Ordner deiner Sicherung in `config.toml` ein (Pfad der Datei zeigt
`.\k9.exe konfiguration`), z. B. für eine externe Platte E: unter `[sicherheitscheck]`:

```
sicherung_ordner = ['E:\Sicherung']
```

Du kannst auch ein ganzes Laufwerk eintragen, z. B. `sicherung_ordner = ['J:\']`. Die Platte darf
danach abgesteckt sein. K9 merkt sich, wann es die neueste Sicherung zuletzt gesehen hat.

**K9 sichert nicht selbst.** Es sieht nur nach, wie alt die neueste **Datei** im eingetragenen
Ordner ist (bis drei Unterordner tief). Zum Sichern brauchst du ein eigenes Programm, z. B. den
Dateiversionsverlauf von Windows oder Veeam Agent Free. Was im Dashboard beim Punkt
„Datensicherung“ stehen kann:

| Anzeige | Bedeutung |
|---|---|
| grau: „kein Sicherungsordner eingetragen“ | `sicherung_ordner` ist leer |
| gelb: „Sicherungsordner ist da, enthält aber noch keine Datei – noch keine Sicherung“ | die Platte ist angesteckt, aber es wurde noch nie gesichert (seit Version 0.46.1) |
| gelb: „Sicherungsordner nicht gefunden (Platte abgesteckt?) und noch nie gesehen“ | die Platte ist abgesteckt, und K9 hat dort noch nie eine Sicherung gesehen |
| grün / gelb / rot: „letzte Sicherung vor … Tagen“ | grün bis 14 Tage, gelb darüber, rot ab 30 Tagen |

**Wohin mit der Sicherung?** Am besten auf eine externe Platte, die nur zum Sichern angesteckt ist.
Ransomware verschlüsselt alles, was gerade erreichbar ist – auch eine zweite interne Platte, eine
dauerhaft angesteckte USB-Platte und ein verbundenes Netzlaufwerk. Die Schattenkopien, aus denen
`k9 wiederherstellen` Dateien zurückholt, ersetzen die Sicherung nicht: Sie liegen auf derselben
Platte, und Ransomware löscht sie oft zuerst.

**Veraltete Programme:** Einmal am Tag fragt der Agent `winget`, welche Programme eine neuere
Version haben. Von selbst installiert oder entfernt K9 nichts. Die Liste steht im Kasten unter
„… Programme mit neuerer Version anzeigen“:

- hinter jedem Programm **„Aktualisieren“** (`winget upgrade --id … -e`) und **„Deinstallieren“**
  (`winget uninstall --id … -e`),
- in der Spalte **„Auswahl“** je ein Kästchen zum Ankreuzen, darüber **„Ausgewählte aktualisieren“**
  und **„Ausgewählte deinstallieren“** für alle angekreuzten Programme,
- darüber außerdem **„Alle aktualisieren“** und **„Alle deinstallieren“** für die ganze Liste.

Trend Micro und K9 selbst werden nie deinstalliert (dort steht „(nicht über K9)“, beim
Sammel-Deinstallieren werden sie übersprungen). Nach jedem Klick öffnet sich **ein**
K9-Bestätigungsfenster („Programm aktualisieren?“ bzw. „3 Programme deinstallieren?“ mit der Liste
der Programme); erst nach **„Ja“** arbeitet winget die Programme **nacheinander** im Hintergrund ab,
„Nein“ bricht ab. Während dessen steht hinter dem Programm, das gerade dran ist, ein **drehender
Kreis** mit „Aktualisieren läuft …“ bzw. „Deinstallieren läuft …“, hinter den übrigen
„… wartet …“ (direkt nach dem Klick: „wartet auf dein „Ja“ im Bestätigungsfenster …“); die Seite lädt
sich dann alle 3 Sekunden selbst neu und die Liste bleibt offen. Installationsprogramme können
eigene Fenster zeigen oder nach Administratorrechten fragen (Windows-Abfrage „Ja“).

**Programme, die Administratorrechte brauchen (seit Version 0.46.0):** Manche Programme lassen sich
nur mit Administratorrechten aktualisieren (zum Beispiel „Claude“; winget meldet dann den Fehler
0x80073D28). K9 selbst läuft ohne diese Rechte. Scheitert „Aktualisieren“ deshalb, startet K9
winget sofort ein zweites Mal über die Abfrage der Windows-Benutzerkontensteuerung:

- Windows zeigt sein eigenes Fenster. Mit einem Administratorkonto wählst du dort „Ja“; mit einem
  Konto ohne Administratorrechte fragt Windows dort nach dem Kennwort eines Administrators.
- **K9 sieht dieses Kennwort nie** und speichert nichts davon – die Abfrage gehört zu Windows.
- Danach öffnet sich ein Fenster von winget, in dem du den Fortschritt siehst. Es schließt sich am
  Ende von selbst.
- Wählst du „Nein“ oder wartest zu lange, passiert nichts; unter dem Programm steht dann rot, dass
  die Abfrage nicht bestätigt wurde, und wie es von Hand geht (`winget upgrade --id … -e` im
  „Terminal (Administrator)“).

Grenzen: „Abbrechen“ im Dashboard wirkt auf diesen zweiten Lauf nicht – ein Programm ohne
Administratorrechte kann keines mit diesen Rechten beenden; schließe dafür das Fenster von winget.
Gibst du in der Abfrage das Kennwort eines **anderen** Kontos ein, läuft winget unter diesem Konto
und findet dort unter Umständen andere Programme vor. Ausprobiert am 22.11.2026 mit „Claude“
(4.29.0.0 auf 6.28899.6): Die Aktualisierung lief nach dem „Ja“ in der Windows-Abfrage ohne
Probleme durch. Der Fall „Konto ohne Administratorrechte mit Kennwortabfrage“ ist nicht ausprobiert.

Solange etwas
wartet oder läuft, steht im Bereich „Sicherheits-Check“ ein Hinweis, was gerade zu tun ist; er
verschwindet von selbst, sobald alles erledigt ist (seit Version 0.45.1). Das Ergebnis
steht im Bereich „Sicherheits-Check“ unter **„Letzte Aktionen“**, direkt unter der Liste der
Programme (bis Version 0.45.0 hieß die Zeile „Zuletzt“); ein erfolgreich aktualisiertes oder entferntes Programm
verschwindet aus der Liste. Kann winget ein Update auf deinem PC gar nicht installieren („nicht möglich“,
z. B. weil das Programm nur über sein eigenes Update oder die Herstellerseite aktualisiert werden kann),
verschwindet es ebenfalls, bis es eine noch neuere Version gibt. Schlägt eine Aktion aus einem anderen
Grund fehl, bleibt das Programm in der Liste und der Grund steht rot unter seinem Namen.

**Wenn es hängt:** Neben „Aktualisieren läuft …“ bzw. „Deinstallieren läuft …“ steht **„Abbrechen“**;
das beendet winget für dieses Programm sofort, die übrigen laufen weiter. Von selbst beendet K9 einen
Lauf, wenn der Download länger als 4 Minuten keinen Fortschritt macht (der Windows-Download-Dienst
bleibt manchmal kurz vor dem Ende stehen) oder wenn winget nach 30 Minuten kein Ergebnis hat. Danach
gilt dasselbe wie bei jedem Fehler:

**Wenn „Aktualisieren“ fehlschlägt** (z. B. „Not found (404)“: der Hersteller hat die Datei verschoben
und der winget-Katalog kennt die neue Adresse noch nicht): K9 erneuert den winget-Katalog und versucht
es sofort ein zweites Mal. Klappt auch das nicht, steht unter dem Programm der Link **„Selbst laden von
der offiziellen Seite (aus dem winget-Katalog)“**. Diese Adresse stammt aus dem von Microsoft geprüften
Katalog und ist immer eine https-Adresse des Herstellers. K9 lädt selbst **nie** ein Installationsprogramm
von einer anderen Seite: Nur bei winget wird die geladene Datei gegen die Prüfsumme im Katalog geprüft.
Meist ist der Katalog nach ein bis zwei Tagen berichtigt, dann klappt „Aktualisieren“ wieder. Der Hinweis
unter dem Programm nennt das Datum, seit dem der Fehler besteht.

**„Suchen und Laden“:** Unter dem Programm steht nach dem Fehler auch der Knopf **„Suchen und Laden“**.
Nach „Ja“ im Bestätigungsfenster sucht K9 das Installationsprogramm (`.exe`, `.msi`, `.msix`) in
dieser Reihenfolge, immer nur über https:

1. direkte Links auf der offiziellen Seite – nur Dateien auf der Seite des Herstellers selbst (keine
   Spiegelserver oder Download-Portale), 64 Bit, keine portable, ARM- oder 32-Bit-Version,
2. dasselbe auf bis zu 5 Unterseiten des Herstellers, deren Adresse „download“ enthält,
3. die Adresse aus dem winget-Katalog, auch ein ZIP-Archiv mit dem Installationsprogramm darin. Das
   hilft, wenn winget die Datei nur ablehnt, weil die Prüfsumme im Katalog veraltet ist („Der Hash-Wert
   des Installers stimmt nicht überein“).

Die Datei kommt nach „Downloads“ und bleibt nur, wenn sie gültig signiert ist und vom **selben Hersteller**
stammt wie die installierte Version; sonst löscht K9 sie sofort wieder. **Gestartet wird dabei
nichts.** Danach erscheint „Installieren“ (nächster Absatz). Findet K9 nichts Passendes (viele
Seiten bieten den Download nur über Zwischenseiten an), steht der Grund unter dem Programm – dann
selbst über den Link laden.

**Selbst geladene Datei installieren:** Lädst du das Installationsprogramm über den Link selbst nach
„Downloads“, erscheint unter dem Programm der Knopf **„Installieren“** (Seite neu laden, spätestens nach
15 Sekunden). K9 bietet ihn nur an, wenn alles davon stimmt:

- die Datei ist eine `.exe` oder `.msi` der letzten 14 Tage direkt im Ordner „Downloads“,
- ihr Dateiname oder Produktname enthält den Namen des Programms,
- sie ist **gültig digital signiert**, und zwar vom **selben Hersteller** wie die installierte Version,
- K9 hat keine offene Meldung zu der Datei (Hashlisten, YARA und ClamAV prüfen „Downloads“ ohnehin).

Nach dem Klick zeigt das Bestätigungsfenster Datei, Hersteller und SHA-256; nach „Ja“ prüft K9 die
Datei noch einmal (unverändert?) und startet dann das Installationsprogramm mit seinen normalen
Fenstern. Danach fragt K9 winget erneut; ist das Programm aktuell, verschwindet es aus der Liste.
**„Still installieren“** steht daneben, wenn K9 die Art des Installationsprogramms am Inhalt der Datei
erkennt (Windows Installer/MSI, Inno Setup, NSIS, WiX-Paket). Dann läuft die Installation **ohne Fenster
und ohne Fragen** mit den Standardeinstellungen des Herstellers (Zielordner, Verknüpfungen, Lizenz) –
so installiert auch winget. Das Bestätigungsfenster nennt Art und Schalter. Die Windows-Abfrage nach
Administratorrechten kann trotzdem kommen. Ob das Programm danach von selbst startet, bestimmt der
Hersteller; meist startet es im stillen Modus nicht. Willst du etwas auswählen (anderer Ordner,
Zusatzfunktionen), nimm „Installieren“.

**Abweichender Herstellername:** Firmen ändern manchmal ihren Namen. Stimmen die ersten beiden Wörter
des Herstellernamens überein (z. B. „WESTERN DIGITAL CORPORATION“ und „Western Digital Technologies,
Inc.“), bleibt die geladene Datei erhalten, und statt „Installieren“ steht dort rot markiert
**„Trotzdem installieren“** mit beiden Namen. Das Bestätigungsfenster nennt beide Namen noch einmal;
bestätige nur, wenn du das für dieselbe Firma hältst. „Still installieren“ gibt es in diesem Fall
nicht. Bei einem ganz anderen Hersteller lehnt K9 die Datei wie bisher ab.

Den Hersteller der installierten Version liest K9 aus den Programmdateien (auch in Unterordnern) und
bei Store-/MSIX-Apps aus dem App-Manifest. Sind die Programmdateien gar nicht signiert (z. B.
OpenOffice), kann K9 nichts vergleichen: Dann gibt es keinen Knopf, und du startest die Datei von Hand.
Ein `.msix`-Paket öffnet bei „Installieren“ das Windows-Fenster „App-Installer“; „Still installieren“
gibt es dafür nicht. Alle auf einmal aktualisieren geht auch so (normale PowerShell):

```
winget upgrade --all
```

Den Check sofort ausführen (normale PowerShell; `--programme` fragt zusätzlich winget, das dauert
etwa eine Minute):

```
& "C:\Program Files\K9\k9.exe" sicherheitscheck --programme
```

**Reste alter Virenschutzprogramme:** Windows merkt sich manchmal deinstallierte Programme weiter
als „eingeschaltet“ (bei dir z. B. Kaspersky Total Security). K9 zählt sie nicht mit. Entfernen
kannst du die Einträge in einer **Administrator-PowerShell** (ändert weder Trend Micro noch Windows
Defender, nur die veralteten Einträge im Sicherheitscenter):

```
$liste = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
$liste | Where-Object displayName -like 'Kaspersky*' | Remove-CimInstance
$liste = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct
$liste | Where-Object displayName -like 'Kaspersky*' | Remove-CimInstance
```

Prüfen, was danach noch eingetragen ist (normale PowerShell):

```
$liste = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
$liste | Select-Object displayName, pathToSignedProductExe
```

## Speicher-Scan im Leerlauf (standardmäßig aus)

Manche Schadsoftware steht nie als Datei auf der Platte: Sie wird in ein laufendes Programm
eingeschleust oder erst im Arbeitsspeicher entpackt. Der Speicher-Scan liest deshalb im Leerlauf den
Arbeitsspeicher verdächtiger Programme und prüft ihn mit den YARA-Regeln.

**Warum er aus ist – Anti-Cheat:** Anti-Cheat-Systeme (Easy Anti-Cheat, BattlEye, Vanguard, FACEIT …)
werten fremde Zugriffe auf den Speicher eines Spiels oder des Anti-Cheats als Angriff. Im schlimmsten
Fall wird das Spielkonto gesperrt. K9 ist deshalb so gebaut, dass es einem Anti-Cheat nicht begegnen
kann:

- **Nie, solange ein Spiel oder ein Anti-Cheat-Programm läuft** – dann wird der ganze Durchlauf
  ausgelassen, nicht nur diese Programme. Kommt ein Spiel während des Durchlaufs dazu oder bewegst
  du die Maus, bricht er sofort ab.
- **Gar nicht** auf einem PC, auf dem ein Anti-Cheat ständig geladen ist (Riot Vanguard, FACEIT,
  ESEA). Bei dir ist keines davon installiert; BattlEye und Easy Anti-Cheat laufen nur zusammen mit
  dem Spiel.
- Geprüft werden nur Programme aus Ordnern, in die jedes Programm schreiben kann (Benutzerordner),
  oder Programme ohne gültige Signatur. **Nie:** Windows, Store-Apps, Programme von Microsoft und
  Trend Micro, K9 und ClamAV, Spiele, Anti-Cheat.
- **Nur lesen**, mit deinen normalen Benutzerrechten: Es wird nichts angehalten, nichts verändert
  und kein Code eingeschleust. Gelesen wird nur ausführbarer Speicher, der zu keiner Datei gehört
  (dort sitzt eingeschleuster Code), höchstens 48 MB je Programm.
- Es zählen nur YARA-Regeln mit hoher Treffsicherheit (Score ab 75).

Ein **Restrisiko** bleibt: Startet ein Spiel genau in der Sekunde, in der K9 ein anderes Programm
liest, sieht ein Anti-Cheat höchstens, dass K9 ein fremdes Programm gelesen hat – nicht das Spiel.
Wenn dir das zu heikel ist, lass den Schalter aus.

Vorschau, ohne dass Arbeitsspeicher gelesen wird (normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" speicher-scan
```

Einschalten bzw. ausschalten (Ausschalten wirkt nach deiner Bestätigung):

```
& "C:\Program Files\K9\k9.exe" funktion speicher-scan an
& "C:\Program Files\K9\k9.exe" funktion speicher-scan aus
```

Danach läuft er von selbst, sobald du 10 Minuten nichts eingegeben hast
(`speicher_scan_leerlauf_minuten`), jedes Programm höchstens alle 6 Stunden. Ein Treffer kommt als
Meldung „Schadcode im Arbeitsspeicher: …“ mit den Knöpfen wie bei anderen Programm-Meldungen; nichts
wird von selbst beendet. Im Protokoll des Agents steht, wie viele Programme geprüft wurden oder warum
der Scan ausgelassen wurde.

## Neue Sicherheitslücken (CVE)

Die Prüfung „Verwundbare Software“ meldet Lücken, die bereits **aktiv ausgenutzt** werden. Zusätzlich
fragt der Agent einmal am Tag (nie während eines Spiels) die US-Datenbank NVD nach allen **neu
veröffentlichten** Lücken mit Schweregrad Hoch oder Kritisch – das sind einige Hundert pro Woche – und
vergleicht Hersteller, Produkt und Version aus der Angabe des Herstellers mit deinen installierten
Programmen. Es wird nur gelesen; nichts wird installiert.

| Ergebnis | Meldung |
|---|---|
| Deine Version liegt im genannten Bereich oder ist genau genannt | „Neue Sicherheitslücke: …“ – Kritisch: Schwere Hoch, Hoch: Schwere Mittel |
| Dein Programm ist genannt, aber ohne brauchbare Versionsangabe | eine Stufe niedriger, mit „bitte prüfen“ |
| Dein Programm ist genannt, deine Version aber nicht – sie ist älter als eine genannte derselben Versionslinie | „Mögliche neue Sicherheitslücke“ nur **leise** im Dashboard (ältere, nicht mehr gepflegte Versionen sind oft ebenfalls betroffen, sicher ist das nicht) |
| Deine Version ist neuer als alle genannten | keine Meldung |

Die Meldung nennt die CVE-Nummern, den Schweregrad, ab welcher Version die Lücke behoben ist (wenn
bekannt) und den Befehl zum Aktualisieren.

**Wie dringend ist es? (EPSS, seit Version 0.30.0)** Hinter jeder CVE steht eine Schätzung von
FIRST.org, wie wahrscheinlich die Lücke in den nächsten 30 Tagen wirklich ausgenutzt wird, zum
Beispiel „Ausnutzung in 30 Tagen: 12,3 % wahrscheinlich (höher als 97 % aller Lücken)“. Die
wahrscheinlichste Lücke steht oben. Ab 10 % beginnt der Hinweis mit „Dringend“, unter 1 % steht
dort „unwahrscheinlich“. Die Schätzung hilft dir beim Einordnen – an der Schwere der Meldung ändert
K9 deswegen nichts. K9 fragt nur die CVE ab, die deine installierten Programme betreffen; antwortet
FIRST.org nicht, kommt die Meldung ohne Schätzung. Liegt die Schätzung für **alle** Lücken einer
Meldung unter 1 %, kommt sie seit Version 0.31.0 nur leise ins Dashboard (ohne Meldefenster). Knöpfe: „Aktualisieren-Hinweis gesehen“ oder „Ignorieren“.
Aktualisieren kannst du am einfachsten in der Liste der veralteten Programme im Sicherheits-Check.
Windows selbst wird hier nicht geprüft (dafür ist Windows Update da), und Programme, die Windows nicht
als installiert führt, kann K9 nicht zuordnen.

Ansehen, was die Prüfung für die letzten Tage ergibt (meldet nichts, normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" luecken --tage 7
```

## Wochenbericht

Einmal in der Woche (der erste etwa einen Tag nach der Installation) kommt ein Meldefenster
„Wochenbericht“ mit der Zusammenfassung der letzten 7 Tage: neue Meldungen nach Schwere, wie viele
leise aus Arbeitsordnern kamen, was noch offen ist, deine Entscheidungen, die gelben und roten Punkte
des Sicherheits-Checks und die Zahl der veralteten Programme. Schließen mit „Gesehen“. Während eines
Spiels wartet er bis danach. Ausschalten: `k9 funktion wochenbericht aus` (wirkt nach deiner
Bestätigung).

## Neue Geräte im Heimnetz

Der Agent fragt alle 5 Minuten (nie während eines Spiels) alle Adressen deines eigenen Netzes nach
ihrer Hardware-Adresse (ARP, das macht jeder PC ständig). Dazwischen liest er alle 15 Sekunden die
Geräteliste, die Windows ohnehin führt; das sendet nichts. Ein Gerät, das mit deinem PC spricht, fällt
so nach Sekunden auf, jedes andere nach spätestens 5 Minuten. Wirklich „im selben Moment“ erfährt nur
der Router von einem neuen Gerät. Nur das eigene Netz mit dem Internetzugang,
höchstens 254 Adressen; virtuelle Netze (WSL, Hyper-V) nicht. Beim **ersten** Mal merkt er sich alle
Geräte, die da sind. Taucht danach ein unbekanntes Gerät auf, kommt **eine** Meldung (Niedrig) mit
Adresse und Hardware-Adresse. Kennst du es (neues Handy, Gäste, Fernseher): „Gesehen“, dann wird
genau dieses Gerät nicht mehr gemeldet. Handys und Tablets nutzen oft eine zufällige Hardware-Adresse;
die Meldung sagt das dazu.

Bekannte Geräte anzeigen (normale PowerShell):

```
& "C:\Program Files\K9\k9.exe" heimnetz
```

## Phishing: ähnliche Domains

```
[phishing]
aehnliche_domains = true          # Nachahmer-Domains bekannter Marken melden
eigene_marken = []                # z. B. ["meinebank.de", "meinverein.de"]
```

Der Dienst prüft jede DNS-Abfrage darauf, ob sie eine bekannte Marke nachahmt (Steam, Epic
Games, Discord, Battle.net/Blizzard, Riot, Rockstar, PlayStation, Ubisoft, NVIDIA, Microsoft,
Outlook, Facebook, Instagram, WhatsApp, Telegram, Netflix, Sparkasse, PayPal, Amazon, Google,
Office, Live, Apple, iCloud, Xbox, eBay). Gemeldet wird mit Schwere **Mittel**:

- **Tippfehler-Domain** – nur bei längeren Namen, z. B. `steamcomunity.com`, `dicsord.com`;
- **verwechselbare Zeichen** – kyrillische oder griechische Buchstaben (Punycode `xn--…`),
  `0` statt `o`, `1` oder `i` statt `l`, `rn` statt `m`, z. B. `paypa1.com`;
- **Markenname mit Lockwort** – z. B. `paypal-login.example`, `discord-nitro.example`;
- **Marken-Domain vor einer fremden Domain** – z. B. `paypal.com.konto-check.example`.

Die offiziellen Domains (auch die Download- und Bilder-Server wie `steamstatic.com`,
`discordapp.net`, `epicgamescdn.com`) werden nie gemeldet, ebenso der Markenname unter einer
anderen Endung (`amazon.de`). Verglichen wird nur der eigentliche Name vor der Endung; was als
Endung zählt, bestimmt die Public Suffix List (so gilt bei `nutzer.github.io` „nutzer“ als Name).
Kurze Marken (PayPal, Amazon, Google, Office, Live …) werden nicht auf Tippfehler geprüft, das
würde normale Wörter treffen. Geprüft gegen die 1 Million beliebtesten Domains (Tranco-Liste):
53 Treffer, fast alle echte Nachahmer-Domains. Gehört eine gemeldete Adresse wirklich dir oder dem
Anbieter: „Freigabe“ wählen oder sie als eigene Marke eintragen. Der Dienst liest `[phishing]` beim
Start: Änderungen wirken nach dem nächsten Neustart des PCs.

## ClamAV

```
winget install Cisco.ClamAV
cd "C:\Program Files\K9"
.\k9.exe quellen aktualisieren clamav
```

Die Installation fragt nach Administratorrechten. K9 nutzt eigene
Konfigurationsdateien und einen eigenen Signaturordner (`quellen\clamav`), die ClamAV-Installation
bleibt unverändert. `clamd` läuft nur während eines Scans (ca. 1 GB RAM) und nur lokal (127.0.0.1).
Dateien über 40 MB und Prüfungen über 15 Sekunden je Datei überspringt ClamAV
(Hashes und YARA prüfen diese Dateien trotzdem).

**Unerwünschte Programme (PUA):** Mit `clamav_pua = true` (Standard) meldet ClamAV auch
potenziell unerwünschte Programme, z. B. Adware, Werbe-Installer, Cracks, Keygens und
Hacktools. Mit Packern verkleinerte Programme gelten nicht als Fund (sehr viele harmlose Spiele
und Werkzeuge sind gepackt). Werkzeuge (`PUA.….Tool.…`) haben die Schwere **Niedrig**, alle anderen
PUA **Mittel**. **Wichtig für Spieler:** Spiel-Trainer, Cheat-Engine, Mod-Manager und ähnliche
Werkzeuge können als PUA auftauchen. Wenn du das Programm kennst und behalten willst, wähle in der
Meldung „Freigabe“ – die Entscheidung wird gemerkt. Ganz abschalten: in `config.toml` unter
`[quellen]` `clamav_pua = false` setzen und den Agent neu starten (Teil 5, „Starten“).

## Treiberprüfung (verwundbare und veraltete Treiber)

Treiber laufen im Windows-Kern. Ein verwundbarer Treiber kann einem Schadprogramm vollen Zugriff auf
den PC geben („Bring Your Own Vulnerable Driver“). Viele alte Treiber vertragen außerdem die
Speicherintegrität/Virtualisierung (VBS/HVCI) nicht. Das kann der Grund sein, warum Windows mit
eingeschaltetem SVM bzw. VT-x nicht startet. Auf diesem PC startet Windows seit dem Aufräumen am
14.11.2026 mit SVM einwandfrei; SVM bleibt an (VBS an, Speicherintegrität aus – MSI Afterburner und die
Spiele laufen). Meldet sich das Anti-Cheat eines Spiels, SVM im BIOS wieder ausschalten.

**Liste anzeigen** (nur lesen, ändert nichts, ohne Administratorrechte):

```
cd "C:\Program Files\K9"
.\k9.exe treiber
```

Die Ausgabe hat zwei Teile:

1. **Bekannte verwundbare/bösartige Treiber**: Treffer in der Microsoft-Sperrliste oder in LOLDrivers.
   Abgeglichen wird über den Datei-Hash bzw. Authenticode-Hash (sicher). „Name und Version“ ist ein
   schwächerer Treffer (Herausgeber nicht geprüft); für Microsoft-eigene Treiber gibt es ihn nicht.
   Zu jedem Treffer stehen Version, Hersteller, das vermutlich zugehörige Programm, Starttyp, ob
   geladen, CVE-Nummern und eine Empfehlung.
2. **Treiber anderer Hersteller** mit dem Hinweis **HVCI ja/nein**. „nein“ heißt, der Treiber
   verletzt Regeln der Speicherintegrität (Abschnitt gleichzeitig schreib- und ausführbar,
   Ausrichtung nicht 4 KB, Importtabelle in ausführbarem Code). Das ist keine Bedrohung, sondern ein
   Hinweis, was vor dem Einschalten der Virtualisierung aktualisiert oder entfernt werden sollte.
3. **Für die Speicherintegrität vermutlich untauglich** (seit Version 0.47.0): dieselben Treiber
   noch einmal kurz, mit der Angabe, ob sie gerade benutzt werden. Seit 0.47.0 sieht K9 dafür auch
   in den **Treibervorrat von Windows** (`System32\DriverStore\FileRepository`): Dort liegen
   Treiberpakete, die installiert sind, deren Treiber aber gerade kein Gerät benutzt – sie stehen
   dann als „nur im Treibervorrat“ in der Liste.

**Speicherintegrität einschalten – so gehst du vor** (K9 ändert daran nichts selbst):

1. Windows-Sicherheit → „Gerätesicherheit“ → „Details zur Kernisolierung“ → „Speicher-Integrität“
   einschalten. Findet Windows unverträgliche Treiber, schaltet es nicht um und nennt sie unter
   „Inkompatible Treiber“. **Diese Liste ist maßgeblich** – die Einschätzung von K9 ist eine
   Faustregel und nennt meist mehr Treiber, als Windows tatsächlich stören.
2. Zu jedem genannten Treiber klären, ob ihn noch ein Gerät braucht. `.\k9.exe treiber` zeigt
   Hersteller, Version und ob er geladen ist.
3. Unbenutzte Treiber entfernen (über „Apps & Features“ das zugehörige Programm deinstallieren),
   dann die Speicher-Integrität erneut einschalten und neu starten.

Beispiel vom 23.11.2026 auf dem Test-PC: Windows nannte zwei Treiber einer alten Webcam von 2012,
die längst durch ein neueres Modell ersetzt war, und einen Treiber, den ein Headset nur während
einer Firmware-Aktualisierung braucht. K9 hatte den Headset-Treiber bis Version 0.46.1 nicht
gezeigt, weil er nur im Treibervorrat lag. Die Speicherintegrität kann ein paar Prozent Bilder pro
Sekunde kosten; gemessen ist das nicht.

Alle Treiber auflisten (auch Microsoft): `.\k9.exe treiber --alle`. Als JSON: `.\k9.exe treiber --json`.

**Mit Windows-Dienst** prüft der Dienst alle Treiber alle 6 Stunden und nach jedem Listen-Update
(nie während eines Spiels). Jede Minute schaut er, ob ein neuer Treiber installiert oder geladen
wurde – als „neu“ gilt nur ein Treiber, den er noch nie gesehen hat (er merkt sich alle dauerhaft).
Eine gültig signierte neue Version eines schon bekannten Treibers (z. B. Grafiktreiber-Update) ist
keine Meldung, sondern nur ein Eintrag „Treiber aktualisiert“ im Ereignisprotokoll.
Treffer und neue Treiber erscheinen als Meldung:

| Schaltfläche | Bedeutung |
|---|---|
| Treiber deaktivieren | setzt den Starttyp auf „Deaktiviert“ (nach dem Bestätigungsfenster). Wirkt beim nächsten Neustart; das zugehörige Programm oder Gerät funktioniert dann evtl. nicht mehr. Wieder einschalten: Dashboard „Deaktivierte Autostarts“ → „Wieder einschalten“. **Nur für spät startende Treiber** – Boot- und Systemtreiber werden nie abgeschaltet (Gefahr, dass Windows nicht mehr startet). |
| Gesehen | Hinweis zur Kenntnis genommen |
| Ignorieren | diesen Treiber nicht mehr melden |

Treiberdateien werden **nie gelöscht**. Empfohlener Weg: vorher einen Wiederherstellungspunkt anlegen,
dann das zugehörige Programm aktualisieren (Hersteller-Website) oder über „Apps & Features“
deinstallieren und anschließend `.\k9.exe treiber` erneut ausführen.

**Nach dem Deinstallieren** erledigen sich die Meldungen von selbst: Sind Treiberdatei und
Diensteintrag weg, setzt der Dienst die Meldung auf „automatisch erledigt“ und schreibt
„Erledigt: Treiber … wurde entfernt“ ins Ereignisprotokoll – du musst nichts anklicken. Das prüft er alle 10 Minuten (auch während eines Spiels, es sind nur Datei- und Registry-Abfragen) und sofort, wenn ein Treiber verschwindet; nach einem Neustart kann es bis zu 10 Minuten dauern. Bei noch
vorhandenen Treibern aktualisiert er bei jeder Prüfung die angezeigten Angaben (z. B. Hersteller). Die Empfehlung passt zu den Schaltflächen: „hier deaktivieren“ steht nur da, wo es die Schaltfläche gibt; ein schon deaktivierter Treiber wird als solcher genannt.
In Dashboard und Meldefenster stehen nur ausgefüllte Angaben; die zweite Zeile zeigt die Quelle,
z. B. „Treiber · LOLDrivers (Hash)“.

Abschalten der Prüfung: in `config.toml` unter `[quellen]` `treiber_aktiv = false`.

### Verwaiste Treiber-Reste entfernen

Beim Deinstallieren bleiben oft Treiber zurück. **Nicht von Hand löschen:** Fehlt eine Datei, während
noch ein Dienst- oder Filtereintrag besteht, kann ein Gerät (z. B. CD/DVD-Laufwerk) ausfallen. Dafür gibt es das Skript
`treiber-aufraeumen.ps1`. Es arbeitet in zwei Schritten, sichert alles und löscht nichts
endgültig. `k9 dienst aktualisieren` kopiert es nach `C:\Program Files\K9`; nur dort
aufrufen (ein Skript im Projektordner könnte jedes Programm mit deinen Rechten verändern).

Mit `-Satz` wählst du, welche Treiber bearbeitet werden:

| Satz | Treiber | Hinweis |
|---|---|---|
| `CreativeCorel` (Standard, ohne `-Satz`) | `CtiIo64.sys` (Creative), `PxHlpa64.sys` (Corel, Filter der CD/DVD-Laufwerke) | bereits erledigt |
| `Verwaist` | `gdrv.sys` (liegt in `C:\Windows`), `gdrv3.sys` (GIGABYTE), `TmHid.sys` (Thrustmaster), `inpoutx64.sys`; nur noch Datei: `Capsax64Drv.sys` (Colasoft) | |
| `Asus` | `AsIO2.sys`, `AsIO3.sys`, `GLCKIO2.sys`, `IOMap64.sys` und die zurückgebliebenen ASUS-Dienste `asComSvc` und `AsusCertService` (nur der Dienst wird abgeschaltet und ausgetragen, der Programmordner bleibt) | erst nach „VGA“ und dem offiziellen „Armoury Crate Uninstall Tool“ von asus.com |

Ist bei einem Treiber kein Dienst mehr eingetragen, die Datei aber noch da (z. B. `IOMap64.sys`),
verschiebt das Skript nur die Datei in die Sicherung – und nur, wenn kein Dienst sie mehr nennt, sie
gültig vom erwarteten Hersteller signiert ist und sich seit Phase 1 nicht verändert hat.

Für jeden Treiber zeigt „Pruefen“: Dienst, Starttyp, ob geladen, Verweise und ob das zugehörige
Programm noch installiert ist (auch versteckte Einträge). **Übersprungen** wird ein Treiber, solange
sein Programm noch installiert ist oder ein laufendes Programm ihn geladen hat. Jeder Satz hat einen
eigenen Sicherungsordner (`treiberbackup\verwaist`, `treiberbackup\asus`), damit sich die Läufe nicht
in die Quere kommen. Die Befehle unten zeigen `-Satz Verwaist`; für die ASUS-Treiber ersetzt du
`Verwaist` durch `Asus`.

Zur Sicherheit bricht das Skript ab, wenn ein Treiber noch von etwas anderem gebraucht wird
(andere Gerätefilter, Dienst-Abhängigkeiten), wenn kein Wiederherstellungspunkt möglich ist
(Computerschutz aus) oder wenn der Sicherungsordner nicht geschützt ist. Die Sicherung liegt in
`C:\ProgramData\K9\treiberbackup` (nur Administratoren und System); beim Zurückspielen
werden alle Prüfsummen kontrolliert.

PowerShell **als Administrator** öffnen (Rechtsklick auf Start → „Terminal (Administrator)“):

**Zuerst prüfen** (nur lesen, ändert nichts, zeigt genau, was Phase 1 ändern würde):

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase Pruefen
```

**Phase 1** – Wiederherstellungspunkt (vorhanden aus den letzten 24 Stunden oder neu angelegt;
sonst Abbruch), Sicherung der Registry-Einträge und Prüfsummen, Treiber deaktivieren (bei Corel
zusätzlich `PxHlpa64` genau aus der Filterliste der CD/DVD-Klasse entfernen):

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase 1
```

Danach **„Neu starten“** wählen – nicht „Herunterfahren“: Mit dem Windows-Schnellstart bleiben die Treiber sonst geladen (Phase 2 erkennt das und bricht ab).

**Phase 2** – prüft, ob die Treiber nicht mehr laufen, ob Ton (bei Creative/Corel auch CD/DVD)
funktioniert, nennt Geräte mit Fehler und fragt dich zur Sicherheit. Erst dann werden die Dienste ausgetragen und die Dateien in den
geschützten Sicherungsordner verschoben:

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase 2
```

**Zurück** (falls nach Phase 1 oder 2 etwas fehlt) – spielt die Sicherung wieder ein, danach neu starten:

```
cd "C:\Program Files\K9"
powershell -ep Bypass -File .\treiber-aufraeumen.ps1 -Satz Verwaist -Phase Wiederherstellen
```

## Erkennungsquellen

```
[quellen]
ordner = ""                       # leer = %LOCALAPPDATA%\K9\quellen
aktualisieren_stunden = 24
intervall_stunden = { urlhaus = 6 }
yara_aktiv = true
yara_paket = "core"               # oder "extended"
yara_min_score = 60
clamav_aktiv = true
clamav_programmordner = "C:\\Program Files\\ClamAV"
clamav_port = 3310
# ClamAV meldet auch unerwünschte Programme (PUA), siehe „ClamAV“ in Teil 3
clamav_pua = true
abusech_aktiv = true
openphish_aktiv = true
phishing_filter_aktiv = true      # zweite Phishing-Liste (malware-filter), Domains
cve_aktiv = true
browserverlauf_pruefen = true
treiber_aktiv = true
erweiterungen_aktiv = true
# Sigma-Regeln (SigmaHQ) für Programmstarts laden und prüfen (Dienst), siehe Teil 3
sigma_aktiv = false
# große Liste von Schad-Domains (HaGeZi, mittlere Liste) für die DNS-Prüfung
hagezi_tif_aktiv = false
# gekaperte und kriminelle Netze (Spamhaus DROP) für die Prüfung der Verbindungen
spamhaus_drop_aktiv = false
```

Mit `k9 quellen` siehst du zu jeder Quelle Stand, Einträge und **Lizenz** (Namensnennung).

**Beobachtet K9, ob es neue Quellen gibt?** Nur in engen Grenzen, und es nutzt nie von selbst eine
neue Quelle. Seit Version 0.44.0 gilt: Bietet SigmaHQ oder YARA Forge in einem neuen Release ein
Paket an, das K9 noch nicht kennt, bekommst du einmal den Hinweis „Neues Paket bei …“ (Schwere
Niedrig). K9 lädt das Paket nicht – eine neue Quelle soll erst jemand auf Nutzen, Fehlalarme und
Lizenz prüfen. Neue Anbieter oder neue Listen bei abuse.ch, HaGeZi und den anderen Quellen bemerkt
K9 nicht; dafür bleibt nur, die Quellenliste von Zeit zu Zeit durchzusehen.

**Wenn eine Quelle oder ClamAV ausfällt (seit Version 0.31.0):** Ohne aktuelle Quellen findet K9
nichts Neues. Der Dienst prüft deshalb alle 30 Minuten (nicht während eines Spiels) und meldet:

| Störung | Meldung ab | Schwere |
|---|---|---|
| Eine Quelle lässt sich nicht aktualisieren | 3 Fehlversuche hintereinander, oder der Stand ist 3 Tage alt und der letzte Abruf scheiterte | Hoch bei Hashlisten, YARA und ClamAV-Signaturen, sonst Mittel |
| ClamAV startet nicht (z. B. weil eine Programmdatei fehlt) | 2 Fehlstarts hintereinander | Hoch, mit dem Befehl zum Neuinstallieren |
| Schattenkopien eines Laufwerks lassen sich nicht anlegen (seit Version 0.35.0) | 2 gescheiterte Versuche hintereinander (je Laufwerk; geprüft, wenn eine Kopie fällig ist) | Mittel |
| Die Firewall-Sperre lässt sich nicht erneuern (seit Version 0.35.0) | 2 gescheiterte Erneuerungen hintereinander | Mittel |
| winget lässt sich nicht starten (seit Version 0.35.0) | sofort, bei der Software-Prüfung des Agenten | Niedrig – veraltete Programme werden weiter gemeldet, nur ohne fertigen Befehl zum Aktualisieren |

Jede Störung wird **einmal** gemeldet. Ist sie behoben, schließt K9 die Meldung von selbst („Erledigt:
… wird wieder aktualisiert“ im Ereignisprotokoll). „Zu viele Abrufe“ bei einem Anbieter ist keine
Störung – der vorhandene Stand bleibt gültig. War der PC einige Tage aus, gibt es ebenfalls keine
Meldung; erst ein gescheiterter Abruf zählt.

**Stündliches Nachladen der neuesten Schadsoftware (MalwareBazaar):** Neue Schadsoftware wird bei
MalwareBazaar oft schon Minuten nach dem ersten Auftauchen gemeldet. Damit K9 sie nicht erst am
nächsten Tag kennt, arbeitet diese eine Quelle in zwei Schritten:

| Schritt | Was geladen wird | Wie oft | Größe |
|---|---|---|---|
| Vollständige Liste | alle bekannten Schadsoftware-Hashes (über eine Million) | einmal in 24 Stunden | rund 30 MB |
| Neueste Einträge | nur die Hashes der letzten 48 Stunden (rund 1.000) | jede Stunde | unter 100 KB |

Die neuesten Einträge fügt K9 in die vollständige Liste ein; nichts geht verloren, nichts steht
doppelt darin. Geladen wird vom Dienst im Hintergrund, **nie während eines Spiels** (danach wird
nachgeholt). Der Dienst sieht alle 30 Minuten nach, ob etwas fällig ist – zwischen zwei Abrufen
liegen also 60 bis 90 Minuten. Im Dashboard steht im Kasten „Erkennungsdaten“ der Stand mit Uhrzeit,
z. B. „2026-11-19 (neueste Proben 14:30)“.

Für alle anderen Quellen gilt `aktualisieren_stunden`. Möchtest du auch MalwareBazaar nur einmal am
Tag laden, trage das Intervall ein:

```
[quellen]
intervall_stunden = { malwarebazaar = 24 }
```

Kann die vollständige Liste einmal nicht geladen werden (z. B. weil abuse.ch „zu viele Abrufe“
meldet), fügt K9 die neuesten Einträge trotzdem ein und versucht die vollständige Liste in der
nächsten Stunde wieder. Der bisherige Stand bleibt immer aktiv.

**Grenze:** Eine Hashliste kennt nur, was schon jemand gemeldet hat. Schadsoftware, die in der
letzten Stunde neu aufgetaucht ist, kann fehlen – dafür gibt es die Prüfung am Inhalt (YARA, ClamAV)
und die Meldungen beim Start (Abschnitt „Programme und Skripte aus dem Internet“).

## Aktueller Stand der Erkennungsdaten

<!-- ERKENNUNGSDATEN: wird beim Erzeugen der PDF automatisch aus "k9 quellen --json" gefüllt -->

Die gleichen Zahlen zeigen das Dashboard (Kasten „Erkennungsdaten“ ganz oben) und
`.\k9.exe quellen`. Nach einer erfolgreichen Aktualisierung der Quellen erzeugt der Agent
diese PDF automatisch neu (höchstens alle 12 Stunden, nie während eines Spiels).

# Teil 4 – Befehlsreferenz

## Alle k9-Befehle

Alle Befehle im Programmordner `C:\Program Files\K9` ausführen (ohne eingerichteten Dienst im
Build-Ordner `C:\K9-Quelltext\target\release`).

| Befehl | Bedeutung |
|---|---|
| `.\k9.exe scan` | Standardpfade scannen |
| `.\k9.exe scan "C:\Ordner"` | bestimmten Ordner scannen |
| `.\k9.exe pruefen software` | installierte Programme auf aktiv ausgenutzte Lücken prüfen |
| `.\k9.exe pruefen urls` | Browserverlauf und hosts-Datei prüfen |
| `.\k9.exe pruefen autostart` | Autostarts prüfen |
| `.\k9.exe pruefen alles` | alle Prüfungen inkl. Standardpfade |
| `.\k9.exe erkennungen` | offene Funde anzeigen (`--alle` für alle) |
| `.\k9.exe entscheiden 5 quarantaene` | Fund Nr. 5 in Quarantäne |
| `.\k9.exe entscheiden 5 loeschen` | Fund Nr. 5 löschen |
| `.\k9.exe entscheiden 5 freigabe` | Fund Nr. 5 freigeben (auch `ignorieren`) |
| `.\k9.exe entscheiden 5 gesehen` | Software-/Adress-Hinweis als gesehen markieren |
| `.\k9.exe entscheiden 5 deaktivieren` | Autostart abschalten |
| `.\k9.exe entscheidungen` | gemerkte Entscheidungen anzeigen |
| `.\k9.exe entscheidungen widerrufen 3` | Entscheidung Nr. 3 widerrufen |
| `.\k9.exe quarantaene` | Quarantäne anzeigen |
| `.\k9.exe quarantaene wiederherstellen 2` | Datei zurückholen (wird beim nächsten Fund wieder gemeldet) |
| `.\k9.exe quarantaene wiederherstellen 2 --freigeben` | zurückholen und dauerhaft freigeben |
| `.\k9.exe autostart` | deaktivierte Autostarts anzeigen |
| `.\k9.exe autostart reaktivieren 1` | Autostart wieder einschalten |
| `.\k9.exe quellen` | Stand aller Erkennungsquellen mit Übersicht (Anzahl Hashes, Adressen, Regeln, Signaturen) |
| `.\k9.exe quellen --json` | dieselbe Übersicht als JSON (für Skripte) |
| `.\k9.exe quellen aktualisieren` | alle Quellen jetzt laden (`… aktualisieren clamav` für eine) |
| `.\k9.exe cache-leeren` | nächster Scan prüft wieder alle Dateien |
| `.\k9.exe autostart-agent an` / `aus` / `status` | Agent bei der Windows-Anmeldung unsichtbar starten (Teil 3, „Echtzeitschutz“) |
| `.\k9.exe agent-beenden --minuten 60` | K9 pausieren: Agent beenden (Bestätigung „j“, dann Bestätigungsfenster „K9-Agent pausieren?“ → „Ja“); 1–240 Minuten, Standard 60; danach startet der Dienst den Agent von selbst; der Dienst prüft in der Pause weiter |
| `.\k9.exe pause-beenden` | Pause vorzeitig beenden: Pause beim Dienst aufheben und Agent unsichtbar starten (keine Bestätigung nötig); Ausgabe „Pause beendet, Agent laeuft.“ |
| `.\k9.exe treiber` | Treiber prüfen: verwundbare/bösartige Treiber, Eignung für Speicherintegrität (nur lesen; `--alle`, `--json`) |
| `.\k9.exe dienst installieren` | Windows-Dienst einrichten (UAC); aus dem Build-Ordner aufrufen |
| `& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren` | neue Version installieren: Programme nach `C:\Program Files\K9` übernehmen (UAC) |
| `.\k9.exe dienst status` | Zustand des Windows-Dienstes |
| `.\k9.exe dienst starten` / `stoppen` | Dienst starten/anhalten (UAC) |
| `.\k9.exe dienst deinstallieren` | Dienst vollständig entfernen (UAC) |
| `.\k9.exe entscheiden 5 beenden` | Prozess eines Echtzeit-Funds beenden (nur auf deinen Wunsch) |
| `.\k9.exe entscheiden 5 einmalig` | Fund nur diesmal erlauben (nichts wird gemerkt) |
| `.\k9.exe status` | Überblick: Agent, Gaming, Quellen, Zeitpläne, Warnungen |
| `.\k9.exe dashboard` | Dashboard im Browser öffnen |
| `.\k9.exe test-meldung fenster` | Beispiel-Meldefenster |
| `.\k9.exe geheimnis abusech-key` | Schlüssel speichern (Teil 5, „Schlüssel und Passwörter“) |
| `.\k9.exe konfiguration` | Pfad der config.toml |
| `.\k9.exe funktion status` | alle schaltbaren Funktionen mit Stand (auch: wartet auf Bestätigung), PowerShell-Protokollierung, VirusTotal-Schlüssel |
| `.\k9.exe wiederherstellen liste` / `wiederherstellen "<Ordner>" [--stand "JJJJ-MM-TT HH:MM"] [--ziel "<Ordner>"] [--alles]` | Schattenkopien anzeigen bzw. fehlende und veränderte Dateien eines Ordners aus einer Schattenkopie in einen neuen Ordner kopieren (nur in „Terminal (Administrator)“) |
| `.\k9.exe funktion <name> an` / `aus` | Funktion ein-/ausschalten (`anhalten`, `ransomware-anhalten`, `neue-programme`, `virustotal`, `sigma`, `lolbas`, `yara-erweitert`, `schad-domains`, `spamhaus-drop`, `firewall`, `schattenkopien`, `angriffsketten`, `download-herkunft`, `skriptpruefung`, `datendiebe`, `anmeldungen`, `sicherheitscheck`, `programm-updates`, `wochenbericht`, `heimnetz`, `neue-luecken`, `speicher-scan`); an sofort, aus erst nach deiner Bestätigung |
| `.\k9.exe sprache` · `sprache de` · `sprache en` · `sprache auto` | Sprache von Dashboard, Meldefenster und Symbol im Infobereich anzeigen bzw. festlegen (wirkt nach dem nächsten Start von Agent und Dienst; sofort geht es mit dem Schalter „Sprache:“ oben rechts im Dashboard) |
| `.\k9.exe funktion schattenkopien laufwerke C: F:` | Laufwerke der Schattenkopien festlegen (hinzufügen sofort, entfernen erst nach deiner Bestätigung) |
| `.\k9.exe firewall status` / `vorschau` / `eingang` / `entfernen` | Firewall-Sperre bekannter Botnetz-Steuerserver anzeigen / zeigen, was gesperrt würde und welche Regeln dafür geändert, neu angelegt oder entfernt würden (ändert nichts) / eingehende Regeln zeigen, die gemeldet würden (ändert nichts) / Regeln entfernen (entfernen nur als Administrator) |
| `.\k9.exe sicherheitscheck` (`--programme`) | Sicherheits-Check jetzt ausführen und anzeigen (mit `--programme` auch veraltete Programme über winget); ändert nichts |
| `.\k9.exe heimnetz` | bekannte Geräte im Heimnetz anzeigen |
| `.\k9.exe speicher-scan` | Vorschau des Speicher-Scans: dürfte er gerade laufen, welche Programme würde er prüfen (liest keinen Arbeitsspeicher) |
| `.\k9.exe luecken` (`--tage 7`) | neue Sicherheitslücken (Hoch/Kritisch) der letzten Tage für installierte Programme anzeigen (1–14 Tage, Standard 3); meldet und ändert nichts |
| `.\k9.exe arbeitsordner` / `hinzufuegen "D:\Projekte"` / `entfernen "D:\Projekte"` | Arbeitsordner anzeigen / hinzufügen (wirkt nach deiner Bestätigung) / entfernen (sofort); Verhaltensmeldungen von dort kommen nur leise ins Dashboard (Teil 3, „Arbeitsordner“) |
| `.\k9.exe powershell-protokoll status` / `an` / `aus` | Vollständige PowerShell-Skriptprotokollierung anzeigen / einschalten / ausschalten (an/aus nur als Administrator) |
| `.\k9.exe --help` | Hilfe |

Die Konsolenausgabe schreibt Umlaute als ae/oe/ue/ss, damit sie in jeder Konsole
lesbar ist. Dateipfade werden unverändert angezeigt.

# Teil 5 – Installation, Update, Fehlerbehebung

## Voraussetzungen

- Windows 11, Rust (stable), Visual Studio Build Tools (C++), Git – bereits eingerichtet.
- Optional: ClamAV (`winget install Cisco.ClamAV`).
- Optional, aber empfohlen: kostenloser abuse.ch-Auth-Key und NVD-API-Key (Teil 5, „Schlüssel und Passwörter“).

## Bauen (Programme erzeugen)

PowerShell öffnen und eingeben:

```
cd "C:\K9-Quelltext"
cargo build --release
```

> **Mit Windows-Dienst:** Der Agent läuft aus `C:\Program Files\K9` – der Build-Ordner
> ist frei, du musst den Agent zum Bauen nicht beenden. Die neue Version kommt danach mit
> `& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren` (UAC) zum Einsatz.
>
> **Ohne Dienst:** Vorher das Agent-Fenster schließen (bzw. `.\k9.exe agent-beenden`). Solange
> der Agent aus dem Build-Ordner läuft, ist `k9-agent.exe` gesperrt („Zugriff verweigert“).

**Wenn das Bauen ohne jede Ausgabe endet oder „Zugriff verweigert“ meldet:** Dann hat sehr
wahrscheinlich der **Ordnerschutzschild von Trend Micro** ein Bauwerkzeug gesperrt (so geschehen am
22.11.2026). Trend Micro zeigt dazu ein Fenster „Dieses Programm blockieren?“; bleibt es rund
20 Sekunden unbeantwortet, wird das Programm gesperrt – `cargo` endet dann ohne ein einziges Wort.
Betroffen waren nacheinander `cargo.exe` (Zieldatei `.package-cache`, cargos eigene leere
Sperrdatei), `clippy-driver.exe` und `rustc.exe`, alle unter
`C:\Users\<Name>\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin`. Abhilfe: im Fenster
„Diesem Programm vertrauen“ wählen, oder – wenn es schon gesperrt ist – in Trend Micro unter
„Protokolle“ die Anzeige „Ordnerschutzschild“ wählen, den Eintrag anklicken und „Entsperren“.
`powershell.exe` solltest du dort **nicht** entsperren: Damit dürfte jedes PowerShell-Skript an
diesem Schutz vorbei. K9 ändert an Trend Micro nichts; das entscheidest du.

Tests (optional):

```
cargo test
powershell -ExecutionPolicy Bypass -File scripts\e2e-test.ps1
```

## Starten

- **Doppelklick** auf `C:\K9-Quelltext\K9 starten.cmd`.
  Der Agent startet, das Dashboard öffnet sich im Browser.
  Läuft der Agent bereits (z. B. durch den Autostart), öffnet der Doppelklick nur das Dashboard –
  es läuft nie ein zweiter Agent; das Fenster schließt sich nach ein paar Sekunden von selbst.
- Wurde der Agent per Doppelklick gestartet, muss das Konsolenfenster offen bleiben.
  **Schließen oder Strg+C beendet den Agent.** Das Schließen des Browsers beendet ihn nicht.
- Dashboard später erneut öffnen:

```
cd "C:\Program Files\K9"
.\k9.exe dashboard
```

In PowerShell steht vor dem Programmnamen immer `.\` (in der Eingabeaufforderung `cmd` nicht).

Autostart bei der Anmeldung: Teil 3 („Agent automatisch bei der Anmeldung starten“);
Windows-Dienst: Teil 5 („Windows-Dienst“).

## Windows-Dienst (mit Administratorrechten)

Der Dienst „K9 Schutzdienst“ läuft als Windows-Dienst (Konto LocalSystem) und
übernimmt nur, was der Agent ohne Administratorrechte nicht kann:

| Aufgabe | Was passiert |
|---|---|
| Jeder Programmstart | Über die Windows-Ereignisablaufverfolgung (ETW, Kernel-Prozessereignisse) sieht der Dienst **jeden** Start samt Befehlszeile, auch Prozesse, die nach wenigen Millisekunden enden. Geprüft wird mit denselben Regeln wie im Agent; der Agent lässt diese Prüfung dann weg (keine doppelten Meldungen). |
| DNS-Abfragen | Jede DNS-Abfrage wird mit den Schad-Domains (ThreatFox, URLhaus) verglichen. Der Fund nennt das fragende Programm mit Prozess-ID und Befehlszeile; „Ignorieren“ gilt dann nur für diese Domain bei diesem Programm. Fragt der Windows-DNS-Dienst (svchost.exe), steht das dabei. |
| Agent-Wache (Selbstschutz) | Läuft der Agent nicht mehr, ohne dass du ihn mit `k9 agent-beenden` beendet hast, startet der Dienst ihn neu und meldet einen **Hinweis** („Agent wurde unerwartet beendet“) – erst nach 30 Sekunden und nur, wenn Windows nicht gerade neu startet, herunterfährt oder du dich abmeldest. Bist du schon länger als 3 Minuten angemeldet oder kommt der Start von `k9 dienst aktualisieren` (auch aus einer Administrator-PowerShell), startet der Dienst den Agent nach etwa 10 Sekunden; nur direkt nach der Anmeldung wartet er bis zu 3 Minuten, weil der Agent dann über den Autostart ohnehin startet. Ein zweiter Agent startet nie. Hat ein unbekanntes Programm die Pause angefordert, kommt ebenfalls ein Hinweis. |
| Aktionen mit Adminrechten | Wählst du bei einem Fund des Dienstes z. B. „Prozess beenden“ und der Agent darf das nicht, führt der Dienst genau diese Aktion aus – nur für Funde, die er selbst gemeldet hat, und nur die Aktionen, die im Meldefenster angeboten wurden. |

Auch der Dienst ändert **nie** etwas ohne deine Entscheidung. Seine Funde erscheinen wie alle
anderen im Meldefenster und im Dashboard. Er scannt keine Dateien, sondern wertet nur Ereignisse aus.
Auf das Spielen wirkt er sich deshalb nicht aus. Er läuft mit niedriger Priorität.

**Einrichten** (einmalig; Windows fragt nach Administratorrechten → mit „Ja“ bestätigen):

```
cd "C:\K9-Quelltext\target\release"
.\k9.exe dienst installieren
```

Dabei werden `k9-dienst.exe`, `k9-agent.exe` und `k9.exe` nach `C:\Program Files\K9`
kopiert (dort kann sie kein normales Programm verändern), dein Autostart bei der Anmeldung auf den
Agent dort umgestellt und der Dienst mit Start „Automatisch (verzögert)“ und Neustart nach Absturz
angelegt und gestartet. Danach startet der Agent aus `C:\Program Files\K9` neu.

**Sicherheit:** Der Dienst startet und vertraut nur Programmen in `C:\Program Files\K9`.
Den Agent startet er immer mit deinem normalen Benutzerkonto (nie mit Systemrechten). Der Ordner
`C:\K9-Quelltext` ist nur noch der Entwicklungs- und Build-Ordner.

**Nach einem neuen Build** (UAC mit „Ja“ bestätigen):

```
& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren
```

Ist Trend Micro aktiv, kann es die neue Datei in `C:\Program Files\K9`
prüfen oder sperren; dann `C:\Program Files\K9\k9-dienst.exe` als vertrauenswürdig eintragen.

| Befehl | Bedeutung |
|---|---|
| `.\k9.exe dienst installieren` | Dienst einrichten (UAC); aus dem Build-Ordner aufrufen |
| `.\k9.exe dienst aktualisieren` | neue Version aus dem Build-Ordner nach `C:\Program Files\K9` übernehmen (UAC) |
| `.\k9.exe dienst status` | Zustand: läuft?, Prozessstarts/DNS/Agent-Wache aktiv? (ohne Admin) |
| `.\k9.exe dienst stoppen` | Dienst bis zum nächsten Windows-Start anhalten (UAC). Seit Version 0.33.0 der einzige Weg zum Stoppen: `sc stop` und die Diensteverwaltung von Windows lehnt der Dienst ab |
| `.\k9.exe dienst starten` | Dienst wieder starten (UAC) |
| `.\k9.exe dienst deinstallieren` | Dienst, Einstellungen und `C:\Program Files\K9` entfernen (UAC); der Agent arbeitet wie vorher weiter |

Im Dashboard steht unter „Status“ die Zeile **Windows-Dienst** mit dem aktuellen Zustand.

**Dashboard-Schaltflächen:** Entscheidungen, Widerrufe, Wiederherstellen und Wieder-Einschalten
werden im Hintergrund gesendet. Die Seite springt nicht nach oben, die Tabelle wird an Ort und
Stelle aktualisiert, und die Bestätigung erscheint kurz unten am Bildschirm.

**Agent absichtlich beenden, wenn der Dienst läuft:** `.\k9.exe agent-beenden` fragt nach einer
Bestätigung („j“) und meldet dem Dienst eine Pause. Dann gibt es keinen Selbstschutz-Alarm, und der
Dienst startet den Agent nach 60 Minuten wieder. Eine andere Dauer (1–240 Minuten):

```
cd "C:\Program Files\K9"
.\k9.exe agent-beenden --minuten 120
```

Früher wieder starten: `.\k9.exe pause-beenden` (Teil 1, „Wichtige Abläufe“, Punkt h). Wird der Agent auf anderem Weg
beendet (Task-Manager, Absturz, Schadsoftware), meldet der Dienst das als Hinweis und startet ihn neu.
Strg+C im sichtbaren Agent-Fenster zählt als absichtliches Beenden (60 Minuten Pause).

## Umstellung von „Virenscanner“ auf K9

Bis zum 15.11.2026 hieß das Programm „Virenscanner“ (Befehl `vscan`). Die Umstellung macht ein
einziges Update (PowerShell **als Administrator**):

```
& "C:\K9-Quelltext\target\release\k9.exe" dienst aktualisieren
```

Dabei passiert der Reihe nach:

1. Der alte Dienst und der alte Agent werden beendet.
2. Einstellungen, Daten und Anmeldeinformationen werden **kopiert** (nicht verschoben) – Funde,
   Entscheidungen (mit gültiger Unterschrift), Quarantäne, Schlüssel, bestätigte Einstellungen.
3. Der neue Dienst „K9 Schutzdienst“ startet und prüft sich selbst. Erst wenn alles stimmt
   („Selbsttest von K9: in Ordnung“), werden der alte Dienst, die alten Programme, der alte Autostart
   und die alten Verknüpfungen entfernt.
4. Klappt etwas nicht, wird K9 wieder entfernt und die alte Installation läuft unverändert weiter.

Die alten Daten bleiben als Sicherung (`C:\ProgramData\Virenscanner.alt`,
`%APPDATA%\Virenscanner.alt`, `%LOCALAPPDATA%\Virenscanner.alt`). Wenn alles läuft, entfernst du
sie (PowerShell als Administrator, fragt nach).

```
cd "C:\Program Files\K9"
.\k9.exe alte-installation entfernen
```

Die Protokolle des alten Agents bleiben in der Sicherung. Unverändert bleiben nur die Köderdateien der Ransomware-Erkennung (`~vs-koeder-nicht-loeschen.docx`):
Sie werden mit ihrem bisherigen Inhalt verglichen, ein neuer Name würde Fehlalarme auslösen.


## Trend Micro – nötige Ausnahmen

Trend Micro kann neue, unsignierte Programme und Dateien mit Schadsoftware-Mustern
(YARA-Regeln, Signaturen) blockieren oder löschen. Bitte in Trend Micro eintragen
(Einstellungen → **Ausnahmeliste**):

| Art | Eintrag | Grund |
|---|---|---|
| Ordner | `D:\Projekte` | Programmcode und gebaute Programme (unverändert) |
| Ordner | `%LOCALAPPDATA%\K9\quellen` | YARA-Regeln, Signaturen und Listen enthalten Schadsoftware-Muster |
| Programm (vertrauenswürdig) | `C:\K9-Quelltext\target\release\k9-agent.exe` | Verhaltensüberwachung: der Agent liest viele Dateien |
| Programm (vertrauenswürdig) | `C:\K9-Quelltext\target\release\k9.exe` | Verhaltensüberwachung: Scans und Prüfungen |
| Ordner | `C:\K9-Quelltext\target\debug` | eingetragen am 19.11.2026: Hilfs- und Testprogramme, die beim Bauen entstehen |

**Beim Bauen (nur für die Entwicklung):** Die Verhaltensüberwachung von Trend Micro hält frisch
gebaute Hilfs- und Testprogramme in `target\debug` kurz an („Zugriff verweigert“). Dann erscheinen
zwei Fenster: erst die Meldung, dass das Programm beendet wurde (mit „OK“ bestätigen), kurz danach die
Frage „Datei starten?“ (mit „Ja“ bestätigen). Die Namen dieser Programme ändern sich bei jedem Bauen,
deshalb lässt sich keine dauerhafte Ausnahme je Programm eintragen; die Ordner-Ausnahme oben hilft nur
teilweise. Für den normalen Betrieb von K9 spielt das keine Rolle.

Die Ordner-Ausnahme gilt nur für die Dateiprüfung. Die Verhaltensüberwachung prüft
laufende Programme separat – deshalb zusätzlich die beiden Programme eintragen. Sperrt Trend Micro
die installierte Version, zusätzlich `C:\Program Files\K9\k9-dienst.exe` als vertrauenswürdig
eintragen. *Erledigt am 17.11.2026:* Die alten Einträge mit „Virenscanner“, `vscan.exe`,
`vs-agent.exe` und `vs-dienst.exe` hast du gelöscht – die Ausnahmeliste enthält nur noch die
K9-Einträge oben. Damit ist die Umstellung von „Virenscanner“ auf K9 vollständig abgeschlossen.
Falls `k9-agent.exe` schon gesperrt wurde: unter „Sicherheitsbericht/Quarantäne“
wiederherstellen und „nicht mehr warnen“ wählen.

K9 selbst ändert **nie** Einstellungen von Trend Micro oder Windows Defender.

## Schlüssel und Passwörter

Schlüssel werden **nie** in `config.toml` gespeichert, sondern in der
Windows-Anmeldeinformationsverwaltung (Eintrag „K9“). Die Eingabe ist unsichtbar:
Schlüssel einfügen (Rechtsklick oder Strg+V) und Enter drücken.

```
cd "C:\Program Files\K9"
```

| Schlüssel | Woher | Befehl |
|---|---|---|
| abuse.ch Auth-Key (MalwareBazaar, URLhaus, ThreatFox) | kostenlos: https://auth.abuse.ch/ | `.\k9.exe geheimnis abusech-key` |
| NVD-API-Key (schnellere Software-Prüfung) | kostenlos: https://nvd.nist.gov/developers/request-an-api-key | `.\k9.exe geheimnis nvd-key` |
| SMTP-Passwort (E-Mail-Meldungen) | dein E-Mail-Anbieter | `.\k9.exe geheimnis smtp-passwort` |
| ntfy-Token (Handy, optional) | ntfy-Server | `.\k9.exe geheimnis ntfy-token` |

Danach Quellen laden: `.\k9.exe quellen aktualisieren`.
Schlüssel entfernen: `.\k9.exe geheimnis abusech-key --loeschen`.

**Mit Windows-Dienst:** Der abuse.ch-Key und der NVD-Key gehören dem Dienst, denn nur er aktualisiert
die Erkennungsdaten. `k9 geheimnis abusech-key` (aus `C:\Program Files\K9`) gibt den
Schlüssel direkt an den Dienst. Der speichert ihn verschlüsselt, sodass nur er ihn lesen kann
(`C:\ProgramData\K9\geheim`). Eine lesbare Kopie in der Anmeldeinformationsverwaltung
gibt es für den abuse.ch-Key dann nicht mehr. Den NVD-Key behält zusätzlich dein Benutzerkonto, weil
die Software-Prüfung des Agents ihn braucht. Bei `k9 dienst aktualisieren` übernimmt der Dienst
vorhandene Schlüssel automatisch.

E-Mail einrichten (`config.toml`):

```
[meldungen]
kanaele = ["fenster", "dashboard", "email"]

[email]
smtp_server = "smtp.example.de"
smtp_port = 465
verschluesselung = "tls"      # "starttls" bei Port 587
benutzer = "ich@example.de"
absender = "ich@example.de"
empfaenger = ["ich@example.de"]
```

Handy (App „ntfy“ installieren und Thema abonnieren):

```
[handy]
server = "https://ntfy.sh"
thema = "ein-langes-zufaelliges-thema"
```

## Konfiguration (config.toml)

Datei: `%APPDATA%\K9\config.toml` (Pfad anzeigen: `.\k9.exe konfiguration`).
Sie wird beim ersten Start mit Kommentaren angelegt. Nach Änderungen den Agent neu starten.
Daten (Datenbank, Quarantäne, Protokolle, Quellen): `%LOCALAPPDATA%\K9`.

### Sprache

```
# "de", "en" oder "auto" (auto = Anzeigesprache von Windows)
sprache = "auto"
```

Die Zeile steht ganz oben, vor dem ersten Abschnitt in eckigen Klammern. Einfacher geht es mit
`.\k9.exe sprache en` (siehe Teil 2, „Sprache: Deutsch oder Englisch“).

### Scan

```
[scan]
standard_pfade = [
    "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop",
    "%USERPROFILE%\\Documents", "%TEMP%",
]
ausnahmen = []
max_dateigroesse_mb = 128
max_threads = 2
cache = true
```

### Zeitpläne (mehrere möglich)

```
[[zeitplan]]
name = "Leerlauf-Scan"
art = "leerlauf"          # nach N Minuten ohne Tastatur/Maus
minuten = 20
min_abstand_stunden = 24

[[zeitplan]]
art = "taeglich"
uhrzeit = "12:30"

[[zeitplan]]
art = "woechentlich"
tage = ["Sa", "So"]
uhrzeit = "10:00"
pruefungen = ["dateien", "software", "urls", "autostart"]

[[zeitplan]]
art = "einmalig"
zeitpunkt = "2026-12-24 18:00"
```

Weitere Arten: `sofort` (nur von Hand), `staendig` (Platzhalter für Echtzeitschutz).
`pruefungen` leer = alle Prüfungen. Fällige Scans warten, bis kein Spiel mehr läuft.

### Arbeitsordner

```
[arbeitsordner]
aktiv = true
# Teil eines Pfades: ganzer Ordnername
ordner = ["%TEMP%\\claude"]
# nur mit gültiger Signatur
programme = ["%USERPROFILE%\\.local\\bin\\claude.exe"]
```

Hinzufügen am besten mit `k9 arbeitsordner hinzufuegen` (Teil 3, „Arbeitsordner“).

### Sicherheits-Check, Wochenbericht, Heimnetz

```
[sicherheitscheck]
aktiv = true                 # Ampel im Dashboard, alle 6 Stunden
programm_updates = true      # veraltete Programme über winget, einmal am Tag
sicherung_ordner = []        # z. B. ['E:\Sicherung']
wochenbericht = true
heimnetz = true
# neue Sicherheitslücken (Hoch/Kritisch) installierter Programme, einmal am Tag
neue_luecken = true
```

### Gaming-Modus

```
[gaming]
aktiv = true
vollbild_erkennen = true
spiele_prozesse = []                  # z. B. ["eldenring.exe"]
spiele_ordner = ["\\steamapps\\common\\", "\\Epic Games\\", "\\GOG Games\\", ...]
keine_spiele = ["crosshairx.exe", "wallpaper32.exe", "wallpaper64.exe", ...]   # seit 0.44.3
kritische_sofort_extern = true        # kritische Funde trotzdem per E-Mail/Handy
pruefintervall_sekunden = 15
```

**Hilfsprogramme sind keine Spiele (seit Version 0.44.3):** K9 hält jedes Programm aus einem
Spieleordner für ein Spiel. Manche Programme liegen dort, ohne Spiele zu sein, und laufen stundenlang
im Hintergrund: Fadenkreuz-Overlays wie CrosshairX, Hintergrundbild-Programme wie Wallpaper Engine,
Aufnahmeprogramme. Solange so ein Programm lief, blieb K9 im Spielmodus – am 22.11.2026 über
Stunden, obwohl kein Spiel lief. Im Spielmodus warten Aktualisierungen und Prüfungen, es erscheinen
keine Meldefenster, und der Schalter `neue-programme` hält nichts an: Der Schutz ist dann schwächer.

Die Liste `keine_spiele` nennt solche Programme. Läuft nur eines davon, ist K9 **nicht** im
Spielmodus; läuft daneben ein echtes Spiel, gilt der Spielmodus wie immer. Voreingestellt sind
`crosshairx.exe`, `wallpaper32.exe`, `wallpaper64.exe`, `webwallpaper32.exe`, `losslessscaling.exe`,
`soundpad.exe` und `obs64.exe`. Weitere trägst du in `config.toml` im Abschnitt `[gaming]` ein
(Dateiname in Kleinbuchstaben). Ob K9 gerade im Spielmodus ist und weshalb, steht im Dashboard und
im Protokoll des Agenten („Gaming-Modus aktiv: Spiel aus Spieleordner: …“).

Diese Programme werden weiterhin nie angehalten – das hängt am Spieleordner, nicht an dieser Liste.

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| `cargo build` meldet „Zugriff verweigert“ | Agent-Fenster schließen, dann neu bauen. |
| Agent startet direkt nach dem Bauen nicht („Zugriff verweigert“) | Neue Programme werden beim ersten Start geprüft – kurz warten und erneut starten; in Trend Micro als vertrauenswürdig eintragen (Teil 5, „Trend Micro“). |
| Dashboard zeigt „Ungültige Herkunft“ | Seite über `.\k9.exe dashboard` neu öffnen (behoben seit 13.11.2026). |
| Keine Windows-Popups | Windows-Benachrichtigungen sind aus → Kanal `fenster` nutzen (Standard) oder Benachrichtigungen einschalten. |
| `k9 status` warnt „Datei fehlt – vermutlich von einem anderen Virenschutz gelöscht“ | Ordner `%LOCALAPPDATA%\K9\quellen` in Trend Micro als Ausnahme eintragen, dann `.\k9.exe quellen aktualisieren`. |
| abuse.ch: „Zugriff verweigert … Auth-Key“ | Key neu hinterlegen: `.\k9.exe geheimnis abusech-key`, dann `.\k9.exe quellen aktualisieren` (mit Dienst: aus `C:\Program Files\K9` aufrufen, der Schlüssel geht an den Dienst). |
| „Dienst: Schlüssel nur über k9“ | `k9.exe` aus dem Build-Ordner wird vom Dienst nicht akzeptiert – den Befehl in `C:\Program Files\K9` ausführen. |
| Quellen-Aktualisierung „startet“ nur, Ergebnis fehlt | Mit Dienst läuft sie im Hintergrund: nach einigen Minuten Dashboard „Erkennungsquellen“ neu laden oder `C:\ProgramData\K9\logs\dienst.log.<Datum>` ansehen. |
| Software-Prüfung sehr langsam | NVD-API-Key hinterlegen (Teil 5, „Schlüssel und Passwörter“). Danach kommen die Daten aus dem Cache. |
| ClamAV „nicht installiert“ | `winget install Cisco.ClamAV`, dann `.\k9.exe quellen aktualisieren clamav`. |
| Fund ist ein Fehlalarm | Im Meldefenster/Dashboard „Freigabe“ bzw. „Ignorieren“ wählen. |
| Umlaute als „?“ in der Konsole | Ausgaben werden als ae/oe/ue geschrieben (seit 13.11.2026). |
| `cargo build` scheitert, Agent läuft unsichtbar (Autostart) | `.\k9.exe agent-beenden`, dann bauen. |
| Ein harmloses Programm ist „eingefroren“ | Nur möglich, wenn „Kritische Programme anhalten“ (`anhalten`) oder „Ransomware-Verdächtige anhalten“ (`ransomware-anhalten`) eingeschaltet ist: im Meldefenster/Dashboard „Freigabe (weiterlaufen lassen)“ bzw. „Freigabe“ wählen – das Programm läuft dann weiter, verloren geht nichts. |
| Meldung „chrome.exe startet cmd.exe“ für ein Browser-Hilfsprogramm (z. B. Trend Micro Toolbar) | Seit 14.11.2026 automatisch erkannt. Ein Start ist in Ordnung, wenn das Hilfsprogramm im Browser für genau diese Erweiterung registriert und digital signiert ist. Nur sonst kommt eine Meldung. Wiederholte Starts mit wechselnden Pipe-Namen zählen als derselbe Fund. |
| Meldung „powershell.exe mit verdächtigen Argumenten (invoke-expression)“, während Claude auf dem PC arbeitet | Claude führt Befehle über PowerShell mit `Invoke-Expression` aus – die Erkennung ist richtig, der Anlass harmlos. „Nur diesmal erlauben“ wählen. Eine automatische Ausnahme gibt es bewusst nicht, weil Schadsoftware sie nachahmen könnte. |
| Keine DNS-Prüfung | Ohne Administratorrechte nicht möglich → Windows-Dienst einrichten (`.\k9.exe dienst installieren`). Verbindungen und Browserverlauf werden auch ohne Dienst geprüft. |
| `k9 dienst installieren` meldet „Abgebrochen“ | Die UAC-Abfrage wurde abgelehnt oder nicht angezeigt. Befehl in einer eigenen PowerShell auf dem PC ausführen und mit „Ja“ bestätigen. |
| Hinweis „Der K9-Agent wurde unerwartet beendet“ | Der Agent wurde ohne `k9 agent-beenden` beendet (Task-Manager, Absturz …). Beim Neustart oder Herunterfahren von Windows kommt dieser Hinweis nicht mehr. Der Dienst hat ihn neu gestartet. Warst du es nicht, einen vollständigen Scan starten. „Gesehen“ schließt den Hinweis. |
| `k9 agent-beenden`: „Dienst nicht erreichbar“ | Der Dienst läuft, antwortet aber nicht. Mit `.\k9.exe dienst status` prüfen, notfalls `.\k9.exe dienst stoppen`. |
| Dashboard: Entscheidung „nicht vom Dienst unterschrieben – gilt nicht“ | Sie wurde ohne den Dienst gespeichert (z. B. mit `k9.exe` aus dem Build-Ordner oder während der Dienst gestoppt war) oder nachträglich verändert. Widerrufen und beim nächsten Fund neu entscheiden. |
| Meldung „Sicherheitseinstellung wurde abgeschwächt“, obwohl du `config.toml` selbst geändert hast | „Änderung übernehmen“ wählen, dann den Agent neu starten (Doppelklick auf „K9 starten.cmd“ genügt nicht, wenn er schon läuft: zuerst `.\k9.exe agent-beenden`). |
| Nach „Freigabe“ erscheint ein zweites Fenster „K9 – … bestätigen?“ | Absichtlich (Schutz gegen Fernsteuerung). Mit „Ja“ bestätigen, wenn du die Entscheidung gerade selbst getroffen hast. |
| Fehler „Nicht bestätigt – es wurde nichts geändert“ | Im Bestätigungsfenster wurde „Nein“ gewählt oder 2 Minuten nicht geantwortet. Entscheidung einfach wiederholen. |
| Entscheidung im Dashboard: „Dienst nicht erreichbar“ | Der Dienst läuft nicht: `.\k9.exe dienst starten`. Funde gehen dabei nicht verloren, der Agent speichert sie zwischen. |
| „Original … kann nicht geöffnet werden (in Benutzung?)“ bei Quarantäne oder Löschen | Ein anderes Programm hält die Datei länger als 5 Sekunden offen. Nichts wurde verändert, der Fund bleibt offen. Das Programm schließen (oder Windows neu starten) und den Knopf erneut wählen. Die Zeile „Quarantäne fehlgeschlagen …“ in `C:\ProgramData\K9\logs\dienst.log.<Datum>` nennt Fund, Datei und Anzahl der Versuche. |
| Quarantäne-Datei lässt sich nicht öffnen | Absichtlich: Nur der Dienst hat Zugriff. Wiederherstellen über das Dashboard oder `.\k9.exe quarantaene wiederherstellen <Nr.>`. |
| ClamAV braucht viel Arbeitsspeicher | Nur solange es läuft (nach 10 Minuten ohne Arbeit beendet). Ganz aus: in `config.toml` unter `[echtzeit]` `clamav = false`. |

# Anhang

## A. Technik: Schutz vor Manipulation

### Bestätigungsfenster (Härtung Stufe 3)

Mit Dienst gehören alle Funde, Entscheidungen, die Quarantäne-Liste und das Ereignisprotokoll dem
Dienst (`C:\ProgramData\K9\geschuetzt.db`). Agent, Dashboard und k9 lesen sie nur und
schicken alles Neue an den Dienst.

Entscheidungen, die den Schutz **abschwächen**, musst du zusätzlich in einem kleinen Fenster des
Dienstes bestätigen: „Freigabe“, „Nur diesmal erlauben“, „Gesehen“/„Ignorieren“, Wiederherstellen
aus der Quarantäne, einen Autostart wieder einschalten, eine geänderte Einstellung übernehmen und
den Agent pausieren. Das Fenster heißt „K9 – … bestätigen?“, zeigt Bedrohung, Fundort,
Regel und Aktion und hat nur „Ja“ und „Nein“ („Nein“ ist vorausgewählt). Kein anderes Programm kann
darin klicken, auch nicht über das Dashboard. Ohne Antwort nach 2 Minuten gilt „Nein“, und es wird
nichts geändert.

Quarantäne, Löschen, Prozess beenden und Deaktivieren brauchen keine Bestätigung, sie verstärken
den Schutz.

Ist der Dienst nicht erreichbar, speichert der Agent neue Funde zwischen und liefert sie nach. Fehlt
dabei etwas, meldet der Dienst „Zwischengespeicherte Funde sind verschwunden“.

### Schutz vor Manipulation (mit Dienst)

Ein Schadprogramm, das mit deinen normalen Rechten läuft, soll K9 nicht abschalten
oder sich selbst freigeben können:

| Was | Schutz |
|---|---|
| Gespeicherte Entscheidungen (Freigabe, Quarantäne …) | Jede Entscheidung, die du im Meldefenster, im Dashboard oder mit `k9 entscheiden` triffst, unterschreibt der Dienst digital. Den Schlüssel kann nur der Dienst lesen (`C:\ProgramData\K9\geheim`). Eine Entscheidung ohne gültige Unterschrift wird ignoriert, und der Fund wird wieder gemeldet. Im Dashboard steht dann „nicht vom Dienst unterschrieben – gilt nicht“. |
| Quarantäne | liegt in `C:\ProgramData\K9\quarantaene`. Normale Programme haben dort keinen Zugriff. In die Quarantäne verschieben und Wiederherstellen erledigt der Dienst. |
| Sicherheitseinstellungen in `config.toml` | Schaltet jemand eine Schutzfunktion aus (Echtzeitschutz, Teilprüfungen, Erkennungslisten, PowerShell-Skriptprüfung, Angriffsketten, Anhalten, VirusTotal, Firewall-Sperre, Schattenkopien …), schaltet den Spielmodus ein, trägt neue Scan-Ausnahmen, Spiele oder Spiele-Ordner ein, ändert die überwachten Ordner oder entfernt einen Meldekanal, gilt das **erst nach deiner Bestätigung** – auch für den Dienst, schon beim Start. Du bekommst ein Meldefenster „Sicherheitseinstellung wurde abgeschwächt“ mit „Änderung übernehmen“ (danach Bestätigungsfenster) oder „Gesehen“. Bis dahin gelten die bisherigen Werte. Schärfere Werte gelten sofort und werden der neue bestätigte Stand – sie später wieder abzuschalten, braucht also ebenfalls deine Bestätigung. Der Dienst prüft `config.toml` alle 30 Sekunden; Anhalten, VirusTotal, Firewall-Sperre, Schattenkopien, Angriffsketten und Herkunftsprüfung folgen ohne Neustart, die übrigen Prüfungen des Dienstes beim nächsten Start, die des Agents beim nächsten Start des Agents. Den bestätigten Stand hält der Dienst in `C:\ProgramData\K9\einstellungen-bestaetigt.json`; er gilt nur, wenn die Datei dem System gehört, kein normales Konto sie ändern kann und kein Verknüpfungspunkt im Weg liegt. |
| Schlüssel des Dienstes (VirusTotal, abuse.ch, NVD) | Den ersten Schlüssel speicherst du ohne Rückfrage; einen gespeicherten ersetzen oder löschen musst du im Bestätigungsfenster bestätigen. |
| Vollständige PowerShell-Protokollierung | Wird die Richtlinie ausgeschaltet (das geht nur mit Administratorrechten), meldet der Dienst „Die vollständige PowerShell-Protokollierung wurde ausgeschaltet“ (Mittel). Warst du das mit `k9 powershell-protokoll aus`, einfach „Gesehen“. |

Beim ersten Start nach `k9 dienst aktualisieren` übernimmt der Dienst deine bisherigen
Entscheidungen und Quarantäne-Dateien einmalig. Die aktuellen Einstellungen gelten dann als bestätigt.

### Erkennungsdaten beim Dienst (Härtung Stufe 2)

Die Erkennungsdaten (YARA-Regeln, Hashlisten, ClamAV-Signaturen, Phishing- und CVE-Listen) liegen
mit Dienst in `C:\ProgramData\K9\quellen`. Programme mit deinen Rechten können sie lesen,
aber nicht verändern. Aktualisiert werden sie nur vom Dienst: automatisch alle 30 Minuten, soweit
fällig, nie während eines Spiels. Sofort aktualisieren:

```
cd "C:\Program Files\K9"
.\k9.exe quellen aktualisieren
```

Der Befehl startet die Aktualisierung im Dienst und kehrt sofort zurück. Das Ergebnis steht im
Dashboard unter „Erkennungsquellen“ und im Dienst-Protokoll. Die Zahlen in dieser PDF erneuert der
Agent danach von selbst. Beim ersten Start nach `k9 dienst aktualisieren` übernimmt der Dienst
die vorhandenen Daten einmalig.

**Sicherheit:** Der Dienst arbeitet in deinen Ordnern nur mit deinen Rechten, Systemrechte nutzt
er nur für seine eigenen Ordner. Programme startet er nur aus `C:\Program Files`. Die vollständige
Prüfliste steht in `docs\SICHERHEIT.md`.

**Wenn der Dienst gestoppt ist** (`.\k9.exe dienst stoppen`): Der Agent prüft Programmstarts wieder
selbst (sehr kurze Prozesse können durchrutschen). DNS-Prüfung und Agent-Wache fehlen.
Quarantäne, neue Entscheidungen und Quellen-Updates funktionieren erst wieder mit laufendem Dienst.
Das Dashboard zeigt „gestoppt – eingeschränkter Schutz“. Wieder starten: `.\k9.exe dienst starten`.

Der Dienst schreibt sein Protokoll nach `C:\ProgramData\K9\logs\dienst.log.<Datum>`
(lesbar für dich, nicht veränderbar).

## B. Sicherheit

Die Schutzmaßnahmen gegen Manipulation stehen ausführlich in `docs\SICHERHEIT.md`. Kurz:

- Programme laufen nur aus `C:\Program Files\K9` (nur Administratoren können dort schreiben).
  Alte Pfade (`Program Files\Virenscanner`, die Sicherungen `*.alt`) gelten nach der Umstellung
  nirgends mehr als vertrauenswürdig.
- Entscheidungen sind vom Dienst unterschrieben; Abschwächungen brauchen das Bestätigungsfenster.
- Einzige bewusste Ausnahme beim Namen: die Köderdateien `~vs-koeder-nicht-loeschen.docx`.


## C. Test mit der harmlosen Testsignatur

K9 kennt eine eigene, harmlose Testsignatur (kein EICAR – das würde Trend Micro melden):

```
$sig = "K9-" + "TESTSIGNATUR-" + "HARMLOS-2026"
New-Item -ItemType Directory -Force "$env:TEMP\vs-probe" | Out-Null
Set-Content "$env:TEMP\vs-probe\probe.txt" "Hallo $sig"
cd "C:\Program Files\K9"
.\k9.exe scan "$env:TEMP\vs-probe"
```

Bei laufendem Agent erscheint nach wenigen Sekunden das Meldefenster. Danach aufräumen:

```
Remove-Item -Recurse "$env:TEMP\vs-probe"
```

**Speicher-Scan testen** (nur wenn er eingeschaltet ist): Das Testprogramm hält die Testsignatur
20 Minuten lang nur im Arbeitsspeicher. Es muss aus dem Build-Ordner laufen, denn das installierte
K9 prüft sich nie selbst:

```
& "C:\K9-Quelltext\target\release\k9.exe" test-speicher --minuten 20
```

Danach Maus und Tastatur 10 Minuten nicht anfassen. Es erscheint die Meldung „Schadcode im
Arbeitsspeicher: K9-Testsignatur im Arbeitsspeicher (harmlos)“ (Schwere Niedrig); schließen mit
„Nur diesmal erlauben“ bzw. – wenn das Testprogramm schon beendet ist – „Gesehen (Prozess beendet,
nichts wird gemerkt)“.

### Externer Test mit EICAR (Zusammenfassung)

Am 13.11.2026 wurde K9 mit den offiziellen EICAR-Testdateien geprüft. EICAR ist ein
international genormter, **harmloser** Prüftext, auf den alle Virenscanner reagieren. Der Test lief
im Ordner `C:\K9-Quelltext\testlabor` (bei Trend Micro ausgenommen, nicht im Git). Der
ausführliche Bericht steht in `docs\TESTBERICHT.md`.

| Prüfung | Ergebnis |
|---|---|
| Manueller Scan: `eicar.com`, `eicar.com.txt`, `eicar_com.zip`, `eicarcom2.zip` (ZIP in ZIP) | 4 von 4 erkannt (ClamAV), 0,6 s |
| Echtzeit: neue `eicar.com` | erkannt nach ca. 2 s (eingebaute EICAR-Erkennung) |
| Echtzeit: neue ZIP und ZIP in ZIP | erkannt nach ca. 18 s (ClamAV startet bei Bedarf) |
| Echtzeit: harmlose PDF zur Kontrolle | keine Meldung (richtig) |
| Echtzeit: Verknüpfung (.url) mit aktuellem Phishing-Link | erkannt nach ca. 1 s (OpenPhish) |
| Nichts automatisch verändert | ja – alle Dateien blieben bis zur Entscheidung unverändert |
| Windows-Dienst: sehr kurzer Prozess, DNS-Abfrage, hart beendeter Agent | erkannt bzw. nach 10 s neu gestartet mit Hinweis |
| Windows Sandbox für weitere Tests | am 13.11. noch nicht möglich (Virtualisierung im BIOS aus); seit dem 14.11.2026 eingeschaltet, alle späteren Sandbox-Tests liefen dort |

**Ehrliche Einordnung:** Die eingebaute EICAR-Erkennung behebt nur den Testfall. Die eigentliche
Lücke war, dass der Echtzeitschutz die 3,6 Millionen ClamAV-Signaturen nicht nutzte. Deshalb prüft
er riskante neue Dateien jetzt auch mit ClamAV (siehe „Echtzeitschutz“ in Teil 3).

Selbst nachtesten (EICAR-Dateien nur in einem bei Trend Micro ausgenommenen Ordner anlegen, sonst
löscht Trend Micro sie sofort):

```
cd "C:\Program Files\K9"
.\k9.exe scan "C:\K9-Quelltext\testlabor"
```

## D. Projektstatistik

<!-- STATISTIK: wird beim Erzeugen der PDF aus docs/STATISTIK.md eingesetzt -->

## E. Änderungsverlauf

| Datum | Änderung |
|---|---|
| 23.11.2026 | **Version 0.50.2:** YARA-Treffer auf gültig digital signierte Dateien werden höchstens als „Mittel“ gemeldet (mit dem Hinweis „vermutlich Fehlalarm, bitte prüfen“) und beim Start nicht mehr angehalten. Anlass: Meldung 446 – die Regel „CAPE_Hijackloaderstub“ hielt das von GitHub, Inc. signierte Startprogramm von GitHub Desktop an. Gemeldet werden solche Treffer weiterhin. Außerdem fragt ein Test von K9 keinen Wallet-Pfad mehr beim Dateisystem ab (er hatte die leisen Meldungen „liest Krypto-Wallet“ 429 bis 450 ausgelöst). Teil 3, „YARA-Regeln“, ergänzt. |
| 23.11.2026 | **Version 0.50.1:** Englisches Dashboard vervollständigt: Die Punkte des Sicherheits-Checks, „Letzte Aktionen“, die Namen, Lizenzen und der Stand der Erkennungsquellen, der Status in „Letzte Erkennungen“, die Stufe im „Protokoll“ und der Grund des Spielmodus erscheinen jetzt auch auf Englisch (vorher waren nur die Überschriften übersetzt). Beim Umschalten prüft K9 den Sicherheits-Check sofort neu. Fehler behoben: Der Sprachschalter funktionierte nicht, wenn die `config.toml` mit einem Byte-Order-Mark gespeichert war (so speichern der Windows-Editor und PowerShell 5). Der Gesamttest prüft jetzt auch die englische Seite. |
| 23.11.2026 | **Version 0.50.0:** Englische Fassung, zweiter Teil: Jetzt erscheinen auch die Meldungen selbst auf Englisch (Name der Bedrohung, Fundort, Kategorie, Hinweis mit Empfehlung, „Betrifft“) – für alle Erkennungen von Agent und Dienst –, dazu die Bestätigungsfenster des Dienstes, die Benachrichtigungen per Windows-Popup, E-Mail und Handy und der Wochenbericht. Der Dienst übernimmt eine geänderte Sprache innerhalb von 30 Sekunden ohne Neustart. Gespeicherte Entscheidungen gelten in beiden Sprachen (der Fingerabdruck einer Meldung hängt nicht von der Sprache ab). Deutsch bleiben die Ausgabe der `k9`-Befehle, das Protokoll und Fehlertexte. Für deutsche Nutzer ändert sich nichts. |
| 23.11.2026 | **Version 0.49.0:** K9 gibt es jetzt auch auf Englisch. Neue Einstellung `sprache` (`auto`, `de`, `en`; Voreinstellung `auto` = Anzeigesprache von Windows) und Sprachschalter oben rechts im Dashboard („Sprache: Deutsch English“, wirkt sofort) und neuer Befehl `.\k9.exe sprache en` (ebenso `de` und `auto`). Auf Englisch erscheinen das ganze Dashboard, das Meldefenster, die Entscheidungen, der Sicherheits-Check, die Texte zum Aktualisieren von Programmen und das Symbol im Infobereich. Vorerst deutsch bleiben der Text der Meldungen selbst, die Ausgabe der `k9`-Befehle, das Protokoll und die Anleitung. Neuer Abschnitt „Sprache: Deutsch oder Englisch“ in Teil 2. Für deutsche Nutzer ändert sich nichts. |
| 23.11.2026 | **Version 0.48.1:** Dashboard: Jeder Klick auf eine Schaltfläche zeigt jetzt sofort, dass K9 arbeitet – auf der angeklickten Schaltfläche dreht sich ein kleiner Kreis, und die Schaltflächen des Formulars lassen sich nicht ein zweites Mal anklicken, bis die Seite das Ergebnis zeigt. Anlass: Nach „Jetzt neu prüfen“ war ein, zwei Sekunden lang nicht zu erkennen, ob der Klick angekommen ist. |
| 23.11.2026 | **Version 0.48.0:** (1) **Neue Entscheidung „Freigabe (diese Regel für alles, was dein Arbeitsprogramm claude.exe startet)“** bei leisen Meldungen, die ein Arbeitsprogramm ausgelöst hat. Anlass: Die Meldungen Nr. 58 und 89 und jedes Mal neue Sigma-Meldungen kamen bei jedem PowerShell-Befehl eines Claude-Projekts wieder. Nach der Freigabe legt K9 für diese Regel und dieses Arbeitsprogramm keine offene Meldung mehr an; nie bei Schwere „Kritisch“, mit Bestätigung durch den Dienst, widerrufbar. Neuer Absatz im Kapitel „Arbeitsordner (leise Meldungen)“. (2) **Sicherheits-Check:** neuer Punkt „Lokale Sicherheitsautorität“ (liest einen Wert aus der Registrierung, öffnet nie ein Fenster). |
| 23.11.2026 | **Version 0.47.2:** (1) **Fehlalarm beim Schutz vor Datendieben behoben:** Ein Skript, das nur Ordnergrößen zusammenzählte, löste drei kritische Meldungen „liest Zugangsdaten mehrerer Programme“ aus. Zwei Ursachen: Ein Ordner `js\cookies` im Programmcode einer Browser-Erweiterung galt als Cookie-Speicher, und schon das Öffnen eines Ordners zum Auflisten zählte als Zugriff. Jetzt gilt: Der Programmcode von Erweiterungen zählt nie, eine Speicherdatei muss genau so heißen (z. B. `…\Network\Cookies`), und wer nur einen Ordner auflistet, liest nichts – das Öffnen der Dateien darin wird weiter gemeldet. (2) **Dashboard, „Offene Erkennungen“:** Unter der Überschrift steht jetzt, warum die Nummern nicht fortlaufend sind; in der Spalte „Erkannt“ zeigt „erneut: …“ das letzte Auftreten einer wieder geöffneten Meldung. |
| 23.11.2026 | **Version 0.47.1:** Neue Schaltfläche „Jetzt neu prüfen“ im Bereich „Sicherheits-Check“ des Dashboards. Anlass: Nach dem Einschalten der Speicher-Integrität zeigte das Dashboard den Punkt weiter gelb, weil K9 nur alle 6 Stunden prüft und der letzte Stand von vorher war. Unter der Tabelle steht jetzt auch, dass K9 alle 6 Stunden prüft. |
| 23.11.2026 | **Version 0.47.0:** `k9 treiber` sieht jetzt auch in den Treibervorrat von Windows und zeigt Treiberpakete, die installiert, aber nicht in Benutzung sind („nur im Treibervorrat“). Anlass: Windows verweigerte das Einschalten der Speicher-Integrität unter anderem wegen eines Headset-Treibers, den K9 nicht gezeigt hatte. Neu am Ende der Ausgabe: die kurze Liste „Für die Speicherintegrität vermutlich untauglich“ mit der Angabe, ob der Treiber gerade benutzt wird. Neuer Absatz „Speicherintegrität einschalten – so gehst du vor“. |
| 22.11.2026 | **Version 0.46.1:** Punkt „Datensicherung“ im Sicherheits-Check berichtigt. Bisher zählten auch Ordner mit: Auf einer frisch eingerichteten, leeren Sicherungsplatte legt Windows von selbst den Ordner „System Volume Information“ an – K9 hätte das als „letzte Sicherung vor 0 Tagen“ gezeigt, obwohl nichts gesichert ist. Jetzt zählen nur Dateien, die Windows-eigenen Ordner bleiben außen vor. Neu ist die Anzeige „Sicherungsordner ist da, enthält aber noch keine Datei – noch keine Sicherung“. Abschnitt „Datensicherung“ erweitert (K9 sichert nicht selbst, Tabelle der Anzeigen, wohin mit der Sicherung). Das Aktualisieren mit Administratorrechten aus 0.46.0 ist jetzt mit „Claude“ erprobt. |
| 22.11.2026 | **Version 0.46.0:** Programme, die sich nur mit Administratorrechten aktualisieren lassen (z. B. „Claude“, winget-Fehler 0x80073D28), aktualisiert K9 jetzt trotzdem: Nach dem ersten, gescheiterten Versuch startet es winget über die Abfrage der Windows-Benutzerkontensteuerung. Windows zeigt dafür sein eigenes Fenster („Ja“ bzw. Kennwort eines Administrators); K9 sieht kein Kennwort. Bisher stand dort nur, wie es von Hand im „Terminal (Administrator)“ geht – das steht jetzt nur noch da, wenn die Abfrage abgelehnt wird oder scheitert. Neuer Absatz „Programme, die Administratorrechte brauchen“. Außerdem im Kapitel „Bauen“: was zu tun ist, wenn der Ordnerschutzschild von Trend Micro die Bauwerkzeuge sperrt (das Bauen endete am 22.11. deshalb ohne jede Ausgabe). |
| 22.11.2026 | **Version 0.45.1:** Dashboard, Programme aktualisieren oder deinstallieren: Der Hinweis „… bitte im Bestätigungsfenster „Ja“ wählen …“ blieb stehen, auch nachdem alles erledigt war – er kam mit jedem Neuladen der Seite wieder. Jetzt steht er nur noch, solange etwas wartet oder läuft, und verschwindet von selbst. Er verwies außerdem auf einen Bereich „Zuletzt“, den es so nicht gibt: Gemeint war eine kleine Zeile im Bereich „Sicherheits-Check“. Sie heißt jetzt „Letzte Aktionen“, und der Hinweis nennt Bereich und Stelle genau. Allgemein gilt jetzt: Ein Hinweis oben im Dashboard erscheint einmal und kommt beim Neuladen der Seite nicht wieder. |
| 22.11.2026 | **Version 0.45.0:** Arbeitsdateien von Schutzprogrammen lösen kein Meldefenster mehr aus. Anlass: Die Meldungen 285 und 387 betrafen dieselbe Arbeitsdatei von Trend Micro im Ordner `Temp`; nach jeder Änderung des Inhalts meldete ClamAV sie neu. K9 fragt jetzt bei jeder Dateimeldung Windows, welches Programm die Datei geöffnet hält, und zeigt das im Dashboard („Beim Fund geöffnet von: …“). Hält ausschließlich ein gültig signiertes Schutzprogramm die Datei auch zwei Sekunden später noch offen, kommt ein Muster-Treffer von ClamAV oder YARA bis Schwere „Mittel“ nur leise ins Dashboard. Hashlisten-Treffer, Programme, Skripte und Dateien aus dem Internet bleiben immer laut. Neuer Abschnitt „Arbeitsdateien von Schutzprogrammen“, Testbericht 7.43. Außerdem behoben: Öffneten mehrere Teile von K9 eine ganz neue Datenbank im selben Augenblick (allererster Start), konnte einer davon mit einem Fehler abbrechen – im Test etwa bei jedem fünften Versuch. Bestehende Datenbanken waren nicht betroffen. |
| 22.11.2026 | **Version 0.44.3:** Hilfsprogramme in einem Spieleordner zählen nicht mehr als Spiel. Anlass: K9 blieb am 22.11. stundenlang im Spielmodus, weil das Fadenkreuz-Programm CrosshairX aus dem Steam-Ordner lief – im Spielmodus warten Prüfungen und Aktualisierungen, und der Schalter `neue-programme` hält nichts an. Neue Liste `keine_spiele` im Abschnitt `[gaming]` (voreingestellt: CrosshairX, Wallpaper Engine, Lossless Scaling, Soundpad, OBS). Läuft nur eines dieser Programme, ist K9 nicht im Spielmodus; mit einem echten Spiel daneben wie bisher. Neuer Absatz „Hilfsprogramme sind keine Spiele“. Außerdem nachgemessen: Der Agent braucht mit 0.44.2 außerhalb von Spielen im Mittel 1,2 % eines Prozessorkerns (vorher 19 bis 23 %); Zahl beim Schalter `neue-programme` und im Testbericht 7.42 eingetragen. |
| 22.11.2026 | **Version 0.44.2:** Der Agent verbraucht deutlich weniger Rechenzeit. Anlass: die erste Messung der Belastung (Testbericht 7.42). **Im Spiel** (40 Minuten, 12:30 bis 13:10 Uhr) lag K9 bei 0,8 % (Agent) plus 0,6 % (Dienst) eines Prozessorkerns – das Spielen bleibt unberührt. **Außerhalb des Spiels** brauchte der Agent mit dem Schalter `neue-programme` aber dauerhaft 19 bis 23 % eines Kerns, zehnmal so viel wie in der Anleitung geschätzt: Er fragte 16-mal je Sekunde die ganze Prozessliste ab (knapp 14 ms je Abfrage). Jetzt fragt er nur die Prozessnummern ab und holt die Liste erst, wenn ein Programm dazugekommen ist. Die Angabe in der Anleitung ist berichtigt. |
| 22.11.2026 | **Version 0.44.1:** Eine Meldung, die ein Programm angehalten hat, kommt jetzt an die Spitze der Warteschlange der Meldefenster (bisher galt das nur für den Ransomware-Alarm). Anlass: Im Freigabe-Test in der Sandbox wartete die Meldung zum angehaltenen Programm unbemerkt hinter einem offenen Meldefenster mit einem anderen Hinweis. K9 zeigt weiterhin immer nur ein Meldefenster zugleich – steht dort etwas anderes, führt „Später“ zur nächsten Meldung. Danach bestanden: Freigabe per Klick lässt das angehaltene Programm sofort weiterlaufen, beim zweiten Start wird dieselbe Datei nicht mehr angehalten (Testbericht 7.41). |
| 22.11.2026 | **Version 0.44.0:** Neuer Befehl `k9 wiederherstellen`: holt nach einem Ransomware-Angriff Dateien aus einer Schattenkopie zurück. `k9 wiederherstellen liste` zeigt die Schattenkopien; `k9 wiederherstellen "<Ordner>"` kopiert alle Dateien, die heute fehlen oder verändert sind, in einen neuen Ordner auf dem Desktop (oder `--ziel`), wahlweise aus dem Stand vor einem Zeitpunkt (`--stand`). Dein Ordner bleibt unverändert, nichts wird überschrieben oder gelöscht. Braucht „Terminal (Administrator)“. Durch Programmtests belegt und am selben Tag auf dem Test-PC mit einer echten Schattenkopie ausprobiert (Testbericht 7.40: fünf Dateien, Byte für Byte der Stand vom Vorabend). Neues Kapitel „Dateien aus einer Schattenkopie zurückholen“. **Außerdem:** Der Schalter `sigma` lädt jetzt auch das Zusatzpaket „Emerging Threats“ (158 weitere Regeln zu aktuellen Angriffswellen, zusammen 712); und K9 gibt einen Hinweis, wenn SigmaHQ oder YARA Forge ein Paket anbieten, das es noch nicht kennt (es lädt und nutzt es nicht von selbst). |
| 22.11.2026 | **Version 0.43.0:** Weniger Fehlalarme der YARA-Regeln und neuer Schalter `k9 funktion yara-erweitert an` für das Paket „extended“ (10.848 statt 5.078 Regeln, Standard: aus). Gemessen auf 269.136 sauberen Dateien deines PCs: „core“ schlug bei 14 an, „extended“ bei 25 – fast die Hälfte in den Signaturdateien von Trend Micro. Neu: Treffer in Dateien eines Schutzprogramms, in signierten Dateien an Orten, in die nur ein Administrator schreiben kann, und in signierten Dateien, die seit über 7 Tagen unverändert sind, kommen nur noch leise ins Dashboard; Dateien aus dem Internet immer laut. Danach laut: 1 („core“) bzw. 2 („extended“). Außerdem schreibt der Agent alle 10 Minuten eine Zeile „Belastung durch den Agenten“ ins Protokoll, getrennt nach Spielzeit und sonstiger Zeit. Neues Kapitel „YARA-Regeln: Fehlalarme und das erweiterte Paket“. |
| 22.11.2026 | **Version 0.42.0:** Der vollständige Scan (schnell) nutzt jetzt ein Drittel der Prozessorkerne als Prüfstränge, mindestens 4 und höchstens 16 – auf dem Test-PC mit 48 Prozessorkernen 16 statt bisher 8. Gemessen: 9,4 GB in 19 statt 35 Sekunden, knapp doppelt so schnell; mit 24 oder 32 Prüfsträngen kaum noch schneller. Der schonende Scan und alle anderen Prüfungen sind unverändert. Messwerte im Abschnitt „Scannen“. |
| 22.11.2026 | **Version 0.41.0:** Neue eigene Regel „Schutz von Windows wird per Befehl abgeschaltet“ (Schwere Hoch, in Arbeitsordnern leise): meldet, wenn die Windows-Firewall (`netsh advfirewall … state off`) oder der Defender (`Set-MpPreference -Disable…`, `Add-MpPreference -Exclusion…`, Dienste WinDefend/MpsSvc beenden oder deaktivieren) per Befehl abgeschwächt wird. Anlass: neuer Sandbox-Test mit 20 Angriffs-Befehlszeilen (Testbericht 7.37) – vorher 16, jetzt 18 von 20 gemeldet; 9 davon nur dank der Sigma-Regeln. Die LOLBAS-Regeln brachten in diesem Test keinen zusätzlichen Treffer und einen Fehlalarm; das steht jetzt im Kapitel „LOLBAS-Regeln“. Neues Testskript `sandbox-test-regeln.ps1`. |
| 22.11.2026 | **Version 0.40.0:** Neue Quelle **LOLBAS** (Schalter `k9 funktion lolbas an`, Standard: aus). Die Liste der von Angreifern missbrauchten Windows-Programme dient zur Auswahl: K9 lädt die Sigma-Regeln der Stufe „mittel“, auf die sie verweist (81 Regeln zu 201 von 246 Programmen), und prüft damit jeden Programmstart, bei dem sonst nichts angeschlagen hat. Treffer sind „Mittel“ und kommen in der Probephase **nur leise ins Dashboard** – diese Regeln schlagen auch bei Harmlosem an. Kosten gemessen: 0,02 Millisekunden je Programmstart. Jetzt 15 Quellen. Neues Kapitel „LOLBAS-Regeln“. |
| 22.11.2026 | **Version 0.39.0:** Neuer Schalter `k9 funktion neue-programme an` (Standard: aus): Ein unsigniertes Programm, das Windows als „aus dem Internet“ kennzeichnet, wird beim ersten Start angehalten, bis du es freigibst – gegen Ransomware, die schon in der ersten Sekunde verschlüsselt (BlackBasta blieb bisher bei 128 von 160 Dokumenten). Neue Meldung „Neues unsigniertes Programm aus dem Internet angehalten“; „Freigabe (genau diese Programmdatei)“ lässt es weiterlaufen und merkt sich die Datei. Nicht während eines Spiels, nicht für signierte Programme und Arbeitsordner. Gemessen (Testbericht 7.36): BlackBasta zweimal 160 von 160 Dokumenten heil mit dem Schalter, ohne ihn 128. Neuer Abschnitt „Neue Programme aus dem Internet beim Start anhalten“. |
| 22.11.2026 | **Version 0.38.0:** Eine „Freigabe“ gibt ein angehaltenes Programm jetzt ganz frei. Bisher hielt jede Meldung das Programm für sich fest (bei BlackBasta im Test fünf Meldungen); nach einer einzelnen Freigabe blieb es eingefroren, ohne dass K9 das anzeigte. Mit dir am 22.11. so entschieden: Eine Freigabe genügt, die übrigen Meldungen bleiben in der Liste. Außerdem kann das harmlose Testprogramm jetzt eine Köderdatei sperren und verändern (Durchgang R18), damit ein Fehler wie in 0.37.0 künftig ohne echte Ransomware auffällt (Testbericht 7.34: 392 von 400 Dateien heil, so schnell wie ohne Köderdatei). Eigene Programme von K9 werden bei einem Ransomware-Alarm nicht mehr als Verdächtige genannt. Mit echter Ransomware nachgemessen (Testbericht 7.35): MedusaLocker 159 von 160 Dokumenten heil (am 20.11. 138; gestoppt durch die neue Köderdatei), BlackMatter 160 von 160 (am 20.11. 150). Neuer Abschnitt „Eine Freigabe gibt ein angehaltenes Programm ganz frei“. |
| 22.11.2026 | **Version 0.37.1:** Fehlerbehebung zu 0.37.0, die gegen BlackBasta **schlechter** war als die Version davor (Testbericht 7.33: 31 und 43 von 160 Dokumenten heil statt 128). Ursache: Traf die Ransomware zuerst eine Köderdatei und hielt sie gerade offen, wartete die Dateiüberwachung des Agenten bis zu einer Sekunde auf diese eine Datei und prüfte so lange nichts anderes. Jetzt wartet die Überwachung nie mehr auf eine Köderdatei (ein Blick, später noch einmal), und bei jedem Ransomware-Alarm wird ein neues unsigniertes Programm als Allererstes angehalten – vor dem Warten auf den Dienst und vor der Prüfung der Signaturen aller übrigen Programme. Mit BlackBasta nachgemessen: zweimal 128 von 160 – der Stand von 0.36.0, nicht besser. |
| 21.11.2026 | **Version 0.37.0:** Zwei Maßnahmen gegen Ransomware, die sofort verschlüsselt (Anlass: BlackBasta, Testbericht 7.31 – 128, 128 und einmal 35 von 160 Dokumenten heil). **Neu 1:** eine zweite versteckte Köderdatei `!vs-koeder-nicht-loeschen.docx` in Dokumente, Desktop und Bilder, die im Ordner ganz vorne steht. **Neu 2:** Läuft ein neues unsigniertes Programm (aus dem Internet, höchstens 24 Stunden alt in einem Benutzerordner oder vom USB-Stick), hält der Agent es schon nach 2 statt 12 verschlüsselt aussehenden Dateien an – ohne erst auf den Dienst zu warten. Dasselbe Programm wird vom Agenten nicht mehr mehrfach angehalten. **Neu 3:** Eine geänderte Datei wird nach 0,1 statt 0,25 Sekunden geprüft (Dienst: 0,08 statt 0,15). Gemessen mit dem harmlosen Testprogramm bei 40 Dateien je Sekunde (Testbericht 7.32): Die Schwelle allein brachte nichts (389 statt 388 von 400 heil), mit der kürzeren Wartezeit 392 bis 393. Mit BlackBasta selbst noch nicht gemessen – der Abruf der Probe wurde am Abend abgelehnt. Neuer Abschnitt „Früher Stopp bei neuen unsignierten Programmen“. |
| 21.11.2026 | **Version 0.36.0:** Anlass: LockBit, BlackBasta und Babuk gegen 0.35.2 (Testbericht 7.29) – 105, 128 und 120 von 160 Dokumenten heil, also **keine Verbesserung** gegenüber dem Vortag; diese Familien verschlüsseln sofort. Bei Babuk meldete K9 den Löschversuch der Wiederherstellungsdaten sechs Sekunden vor der ersten verschlüsselten Datei, fror das auslösende Programm aber nicht ein, weil das kurzlebige `cmd.exe` dazwischen schon beendet war. **Neu:** K9 findet den Auslöser jetzt über seine eigenen Aufzeichnungen der Programmstarts, und „Wiederherstellungsdaten sollen gelöscht werden“ ist ein kritischer Schritt der Angriffskette. Mit dem harmlosen Testprogramm bestätigt (Durchgang R15: 400 von 400 Dateien heil) und am selben Abend mit echter Ransomware: Babuk 160 von 160 Dokumenten heil (vorher 120, Testbericht 7.30), LockBit 160 von 160 (vorher 105, Testbericht 7.31). BlackBasta bleibt bei 128 von 160 und fiel in einem von drei Läufen auf 35 – es verschlüsselt, bevor es die Wiederherstellungsdaten löscht. Neue Abschnitte „Löschen der Wiederherstellungsdaten“ und „Was die Tests mit echter Ransomware am 21.11.2026 gezeigt haben“. |
| 21.11.2026 | **Version 0.35.2:** Liste „Programme mit neuerer Version“: Scheitert „Aktualisieren“, weil das Paket nur mit Administratorrechten installiert werden kann (Fehler 0x80073d28, am 21.11. bei „Claude“), zeigt K9 statt des englischen Satzes von winget einen deutschen Hinweis mit dem fertigen Befehl für „Terminal (Administrator)“ und spart sich den zweiten, aussichtslosen Versuch. K9 selbst holt sich dafür weiterhin keine Administratorrechte. |
| 21.11.2026 | **Version 0.35.1:** Sigma: K9 zählt jetzt, wie viele der geladenen Regeln mit seinen Angaben nie auslösen können, und zeigt die Zahl in `k9 quellen` und im Dienst-Protokoll. Beim aktuellen Paket sind es 55 von 554 (z. B. „Renamed Whoami Execution“, „Hacktool Execution - Imphash“); wirksam sind 499. An der Erkennung ändert sich nichts. Außerdem im Testbericht 7.26 klargestellt: „Conti als Datei nicht erkannt“ lag am Testaufbau (in der Sandbox sind absichtlich keine Hashlisten geladen); auf dem PC steht der Fingerabdruck der Probe in der MalwareBazaar-Liste. |
| 21.11.2026 | **Version 0.35.0:** Drei weitere Meldungen, wenn etwas ausfällt, worauf K9 sich stützt: Schattenkopien eines Laufwerks lassen sich zweimal hintereinander nicht anlegen (Mittel), die Firewall-Sperre lässt sich zweimal hintereinander nicht erneuern (Mittel), winget lässt sich nicht starten (Niedrig). Wie bei den Quellen und ClamAV: jede Störung einmal, und K9 schließt die Meldung selbst, sobald es wieder klappt. Diese drei Fälle sind nur durch Programmtests der Zählung geprüft, nicht mit einem echten Ausfall. |
| 21.11.2026 | **Version 0.34.1:** Fehlalarm „Programm nicht sicher zuzuordnen (PID …) liest … (Passwörter, Cookies)“ behoben. Vier solche Meldungen vom 20. und 21.11. betrafen jeweils die Datei `Local State` genau **eines** Browsers (Chrome, Edge, Brave, Edge). Ursache: Der Dienst kannte nur Programme, deren Start er selbst miterlebt hat. Ein Browser, der schon lief, als der Dienst (neu) startete – etwa nach `k9 dienst aktualisieren` –, war ihm unbekannt; schrieb dieser Browser beim Schließen seine eigene Datei und war sofort weg, konnte K9 ihn nicht mehr benennen. Jetzt übernimmt der Dienst beim Start alle laufenden Programme (Protokollzeile „Schutz vor Datendieben: … laufende Programme übernommen“). Die Erklärung passt zu allen vier Meldungen, bewiesen ist sie für die alten Meldungen nicht – taucht die Meldung wieder auf, bitte nicht wegklicken, sondern melden. |
| 21.11.2026 | **Version 0.34.0:** Angriffsketten beginnen jetzt auch bei unsignierten Programmen **ohne** die Kennzeichnung „aus dem Internet“ – bisher blieb die Abwehr gegen das Abschalten von K9 (0.32/0.33) wirkungslos, wenn ein Schädling aus einem Archiv entpackt oder von einem USB-Stick gestartet wurde. Neu als Anfang einer Kette: ein unsigniertes Programm in einem Benutzerordner (`C:\Users\…`), dessen Datei höchstens 24 Stunden alt ist („neu im Benutzerordner“), und ein unsigniertes Programm von einem Wechseldatenträger („vom Wechseldatenträger“). Ausgenommen: deine Arbeitsordner. Beim Start gibt es dafür keine eigene Meldung; erst wenn ein kritischer oder hoher Schritt dazukommt (Zugangsdaten geöffnet, Schad-Adresse, K9 angegriffen, Autostart …), erscheint die Meldung „Angriffskette“ und – mit `anhalten` – wird das Programm eingefroren. Spiele und andere Programme außerhalb der Benutzerordner oder älter als 24 Stunden sind nicht betroffen. **Außerdem:** Wird der Dienst ein zweites Mal gewaltsam beendet, startet Windows ihn wieder nach 1 Sekunde (vorher 60 Sekunden), ab dem dritten Mal nach 5 Sekunden (vorher 5 Minuten) – im Sandbox-Lauf gingen in der Lücke von 60 Sekunden 22 von 400 Dateien verloren (Testbericht 7.28). |
| 21.11.2026 | **Version 0.33.0:** Schutz des Dienstes gegen das Beenden (bisher die größte Lücke: K9 wertete nur das Ende des Agenten als Angriff). **Neu 1:** Der Dienst lehnt jeden Stopp über Windows ab (`sc stop`, `net stop`, Diensteverwaltung, Neustart-Manager), der nicht von `k9 dienst stoppen`, `k9 dienst aktualisieren` oder `k9 dienst deinstallieren` angekündigt wurde, und meldet den Hinweis „Ein Programm wollte den K9-Dienst beenden“. Läuft dabei ein unsigniertes Programm aus dem Internet, ist das der neue kritische Schritt „Versuch, den K9-Dienst zu beenden“ der Angriffskette; mit `anhalten` wird das Programm eingefroren. **Neu 2:** Wird der Dienst gewaltsam beendet, startet Windows ihn nach 1 Sekunde neu (vorher 10). Der Dienst erkennt beim Start, dass er nicht ordentlich beendet wurde, und meldet jedes unsignierte Programm aus dem Internet, das seit höchstens 30 Minuten läuft, als kritische Angriffskette „K9-Dienst gewaltsam beendet“ (mit `anhalten` eingefroren). **Geändert:** In der Diensteverwaltung von Windows lässt sich der K9-Dienst nicht mehr stoppen – nimm `k9 dienst stoppen`. Herunterfahren und Neustart von Windows sind nicht betroffen. Neuer Abschnitt „Schutz des Dienstes gegen das Beenden“. In der Sandbox mit dem harmlosen Testprogramm bestätigt (Testbericht 7.27, dritter Lauf: in allen drei Durchgängen 400 von 400 Dateien heil). |
| 21.11.2026 | **Version 0.32.1:** Fehlerbehebung zur Abwehr aus 0.32.0. Im ersten Probelauf in der Sandbox (Testbericht 7.25) griff der neue Schritt „K9-Agent von außen beendet“ nicht: Windows meldete dem Dienst den Start des Testprogramms erst 0,2 Sekunden **nach** dem Ende des Agenten, obwohl das Programm schon 2 Sekunden lief. K9 kannte das Programm in dem Moment noch nicht und sah keinen Zusammenhang; 12 von 400 Dateien gingen verloren, bevor der Ransomware-Schutz anhielt. Jetzt merkt sich der Dienst, wann der Agent beendet wurde. Wird danach der Start eines unsignierten Programms aus dem Internet bekannt, das **vor** diesem Zeitpunkt begonnen hat, zählt der Schritt nachträglich und das Programm wird sofort angehalten. Bestätigt mit dem harmlosen Testprogramm (400 von 400 Dateien heil) und mit Conti (160 von 160 Dokumenten heil, Testbericht 7.26). |
| 21.11.2026 | **Version 0.32.0:** Abwehr gegen Schadsoftware, die zuerst K9 abschaltet (Anlass: Conti im Test vom 21.11., Testbericht 7.24). Der Dienst bemerkt das Ende des K9-Agenten jetzt **sofort** (vorher nach bis zu 10 Sekunden). Wird der Agent von außen beendet, während ein unsigniertes Programm aus dem Internet oder etwas, das es gestartet hat, noch läuft, ist das ein neuer kritischer Schritt der Angriffskette („K9-Agent von außen beendet“): kritische Meldung, und mit „Kritische Programme anhalten“ wird das Programm eingefroren, bis du entscheidest. Kein Alarm bei einem Update, bei einer von dir im Bestätigungsfenster erlaubten Pause oder wenn niemand mehr angemeldet ist. Noch **nicht** mit echter Ransomware geprüft. Außerdem berichtigt: Im Abschnitt „Sigma-Regeln“ standen die Schaltflächen nur für ein noch laufendes Programm; ist es schon beendet, heißt die Schaltfläche „Gesehen (Prozess beendet, nichts wird gemerkt)“ |
| 21.11.2026 | **Version 0.31.2:** Dritter Sigma-Fehlalarm behoben: „Execution Of Non-Existing File“ (44 Meldungen zwischen 10:18 und 10:36 Uhr, die ersten für `git.exe` bei Bau-Läufen). Bei sehr kurzlebigen Programmen kennt K9 nur den Dateinamen, nicht den Ordner; die Regel hielt den fehlenden Ordner für verdächtig. Jetzt gilt: Kennt K9 von einem Programm oder seinem Starter nur den Namen, bleiben alle Bedingungen zum Ordner unentschieden und lösen nichts aus – Regeln, die nur den Programmnamen und die Befehlszeile brauchen, arbeiten weiter. Mit dem echten Regelpaket gegen die auf dem PC gesehenen Starts geprüft |
| 21.11.2026 | **Version 0.31.1:** Zwei Fehlalarme der Sigma-Regeln behoben, die gleich nach dem Einschalten auffielen. (1) „System File Execution Location Anomaly“ für `conhost.exe`: Windows schreibt den Pfad dieses Programms als `\??\C:\WINDOWS\system32\conhost.exe`; K9 liest diese Schreibweise jetzt wie den normalen Pfad – vorher löste jedes Konsolenfenster die Regel aus. (2) Sigma-Treffer für Programme, die über mehrere kurzlebige Zwischenschritte von einem Arbeitsprogramm gestartet wurden (z. B. `claude.exe` → bash → bash → grep), kommen jetzt wie vorgesehen nur leise: Der Dienst merkt sich zu jedem Programmstart, wer ihn gestartet hat, und verfolgt die Kette selbst, auch wenn die Zwischenschritte schon beendet sind |
| 21.11.2026 | **Version 0.31.0:** K9 meldet jetzt, wenn etwas ausfällt, worauf es sich stützt. (1) **Erkennungsquelle:** nach 3 Fehlversuchen hintereinander oder wenn der Stand 3 Tage alt ist und der letzte Abruf scheiterte – Meldung „Erkennungsquelle fällt aus: …“ (Hashlisten, YARA und ClamAV-Signaturen: Hoch, sonst Mittel). (2) **ClamAV startet nicht:** nach 2 Fehlstarts – Meldung mit dem Befehl zum Neuinstallieren (Hoch). Jede Störung wird einmal gemeldet; ist sie behoben, schließt der Dienst die Meldung selbst („Erledigt: …“). „Zu viele Abrufe“ zählt nicht als Störung. Geprüft wird alle 30 Minuten, nicht während eines Spiels. Außerdem: Meldungen zu neuen Sicherheitslücken kommen **nur leise ins Dashboard**, wenn die EPSS-Schätzung für alle genannten Lücken unter 1 % liegt. **Fehler behoben (0.28.0 bis 0.30.0):** Eine mit `k9 funktion … an` eingeschaltete Quelle (Sigma, Schad-Domains, Spamhaus DROP) wurde erst nach einem Neustart des Dienstes geladen, obwohl der Befehl „wirkt sofort“ meldete – eingeschaltet, aber ohne Daten und damit wirkungslos; der Dienst lädt jetzt mit den aktuellen Einstellungen. Noch nicht enthalten: Meldung bei fehlendem winget und bei gescheiterter Schattenkopie oder Firewall-Sperre. **Test:** Conti in der Sandbox mit K9 0.30.0 – 0 von 160 Dateien erhalten; Conti beendet erst den Agenten, dann den Dienst und verschlüsselt danach (Testbericht 7.24, Abschnitte „Ransomware-Alarm“ und „Wie gut erkennt K9?“ berichtigt) |
| 21.11.2026 | **Version 0.30.0:** Meldungen zu **neuen Sicherheitslücken** zeigen zu jeder CVE die EPSS-Schätzung von FIRST.org: wie wahrscheinlich die Lücke in den nächsten 30 Tagen ausgenutzt wird („Ausnutzung in 30 Tagen: 12,3 % wahrscheinlich (höher als 97 % aller Lücken)“). Die wahrscheinlichste Lücke steht oben; ab 10 % sagt der Hinweis „Dringend“, unter 1 % „unwahrscheinlich“. Schwere und Art der Meldung ändern sich dadurch nicht. Abgefragt werden nur die CVE, die installierte Programme betreffen; ohne Antwort kommt die Meldung wie bisher. Auch `k9 luecken` zeigt die Schätzung |
| 21.11.2026 | **Version 0.29.0:** Zwei neue Listen für das Netzwerk, beide standardmäßig aus. `k9 funktion schad-domains an`: große Liste von Schad-, Phishing- und Betrugs-Domains (HaGeZi Threat Intelligence Feeds, mittlere Liste, rund 390.000 Einträge) für die DNS-Prüfung, Meldung mit Schwere Mittel, 3 MB Speicher. `k9 funktion spamhaus-drop an`: Spamhaus DROP (1.751 gekaperte oder kriminelle Netze) für die Prüfung der Verbindungen, Meldung mit Schwere Hoch. Die genaueren bisherigen Listen haben Vorrang. Anleitung: neuer Abschnitt „Große Listen für das Netzwerk“; Quellenliste ergänzt. Wie viele Meldungen die Sammelliste im Alltag bringt, ist noch nicht gemessen |
| 21.11.2026 | **Version 0.28.0:** Neue Erkennungsquelle **Sigma-Regeln** (SigmaHQ), standardmäßig aus, Schalter `k9 funktion sigma an`: Der Dienst prüft jeden Programmstart zusätzlich mit den Regeln der Stufen hoch und kritisch (554 von 558 Regeln für Windows-Programmstarts auswertbar). Meldung „Sigma-Regel „…“ (Autor: …)“ mit Schwere Hoch (Sigma kritisch) bzw. Mittel (Sigma hoch), nie Kritisch; leise in Arbeitsordnern; keine zweite Meldung, wenn K9s eigene Regel schon meldet. Regeln, die Angaben verlangen, die K9 nicht hat, lösen nie aus. Gemessen: rund 0,25 ms je Programmstart. Das Paket kommt mit Prüfsumme vom offiziellen Release; Lizenz Detection Rule License 1.1 (Autor wird in jeder Meldung genannt). Anleitung: neuer Abschnitt „Sigma-Regeln“; Quellenliste ergänzt. Noch nicht mit echter Schadsoftware getestet |
| 21.11.2026 | **Version 0.27.1:** Fehlalarme behoben, die am 20.11. abends auffielen. (1) ClamAV legt seine Zwischendateien (entpackte Archive, Teile von PDFs) nicht mehr im Temp-Ordner ab, sondern in einem eigenen K9-Ordner, den der Echtzeitschutz nicht überwacht – vorher prüfte K9 diese Stücke selbst und meldete sie (sechs YARA-Treffer auf `clamav-….tmp`, ein Ransomware-Verdacht auf `pdf-tmp…`). (2) Ein Ransomware-Verdacht zeigt jetzt im Dashboard und im Meldefenster bis zu fünf **betroffene Dateien**, und sie stehen im Protokoll – so war belegbar, dass der Verdacht vom 20.11., 20:21 Uhr von Hilfsdateien eines unsichtbar gestarteten Edge stammte. (3) Die Meldung „fehlgeschlagene Anmeldungen“ nennt **Konto, Herkunft und Programm**; kamen die Versuche von einem Programm auf dem PC, sagt der Hinweis das, statt von Passwort-Raten zu sprechen |
| 20.11.2026 | **Version 0.27.0:** Neu im Dashboard, Kasten „Status“: drei Schaltflächen zum Scannen – „Schnellscan (Standardordner)“ (die bisherige Schaltfläche „Standardpfade jetzt scannen“, nur klarer benannt), „Vollständiger Scan (schonend)“ und „Vollständiger Scan (schnell)“ für **alle eingebauten Laufwerke und eingesteckten USB-Datenträger** (schonend: `max_threads`, schnell: 8 Prüfstränge), darunter eine Erklärung. Die Zeile „Scan läuft“ zeigt Art, Zahl der erreichten Dateien und den aktuellen Ordner und aktualisiert sich alle 2 Sekunden, ohne dass die Seite neu lädt; „Scan abbrechen“ beendet jeden laufenden Scan, bereits Gefundenes bleibt erhalten. Beide vollständigen Scans pausieren, solange ein Spiel läuft (der Schnellscan von Hand läuft wie bisher sofort). Abbrechen, Spielpause und Fortschritt greifen jetzt auch, während ein Scan bereits bekannte, unveränderte Dateien nur überspringt. „Letzter Scan“ nennt die Art des Scans. Anleitung: neuer Abschnitt „Scannen: Schnellscan und vollständiger Scan“. Außerdem: Der Dienst schreibt auf der Protokollstufe „debug“ jeden Zugriff auf gespeicherte Zugangsdaten samt Urteil mit (nur für die Sandbox-Tests mit Ködern; im normalen Betrieb unverändert), das Vergleichsskript wertet das aus |
| 20.11.2026 | **Version 0.26.1:** Projektstatistik (Anhang D) auf den Stand gebracht: Meilensteine und Entwicklungsschritte reichten nur bis zum 15.11., jetzt bis zum 20.11. (Umstellung auf K9, Versionen 0.2 bis 0.26); neue Tabelle „Tests mit echter Schadsoftware und Ransomware“ mit den Abschnitten 7.12 bis 7.23 des Testberichts; der Umfang zählt jetzt auch `k9-res` und `k9-testsim`; neue Zeile bei den Messungen zum Ransomware-Testprogramm |
| 20.11.2026 | **Version 0.26.1:** Anleitung vollständig auf Fehler durchgesehen und berichtigt: Die Tabelle „Fehlerbehebung“ war ab „Keine DNS-Prüfung“ zerrissen (13 Zeilen standen als Rohtext da); „auf den alle K9 reagieren“ heißt wieder „alle Virenscanner“; Verbindungen zu Schad-Adressen werden alle 2 Sekunden geprüft (nicht alle 60); „Agent unerwartet beendet“ ist ein Hinweis mit Schwere Hoch (nicht Kritisch); `ransomware-anhalten` steht in der Liste der Schalter und bei den Schaltern, die erst nach einem Neustart des Dienstes wirken; der Befehl dazu und die Befehlsreferenz nennen den Programmordner `C:\Program Files\K9` statt des Build-Ordners; `dienst aktualisieren` steht in der Befehlsreferenz; die Zahl der geretteten Dateien in der Funktionsübersicht entspricht dem letzten Test (382 bis 383 von 400); veraltete Verweise („Abschnitt 7“, Abschnitt „Schattenkopien“), das Testdatum (18. bis 20.11.), der Hinweis zum vorzeitigen Beenden der Pause (`pause-beenden`), die Zeile zum eingefrorenen Programm und eine doppelte Tabellenzeile sind berichtigt |
| 20.11.2026 | **Version 0.26.1:** PDF-Anleitung: Der Befehl zum dauerhaften Eintragen des Pfades (Teil 1) steht wieder als ein einziger Befehl da; er ist für eine Zeile zu lang und bricht im Kasten an einem Leerzeichen um – in normaler Schriftgröße |
| 20.11.2026 | **Version 0.26.1:** PDF-Anleitung: Die Schrift in den Befehlskästen ist wieder überall normal groß. Zu lange Befehle sind jetzt als zwei kurze, vollständige Befehle mit einer Hilfsvariablen geschrieben (jede Zeile ein ganzer Befehl, keine eingerückten Fortsetzungszeilen); der Aufruf des Treiber-Aufräumskripts wechselt zuerst mit `cd` in den Programmordner und ist dadurch kurz. In Einstellungsbeispielen steht ein langer Kommentar in einer eigenen Zeile über der Einstellung. Ein Test verhindert künftig Zeilen über 92 Zeichen. Der Änderungsverlauf ist jetzt durchgehend sortiert, das jüngste Datum steht ganz oben (die allerersten Einträge vom 13. und 15.11. standen bisher in umgekehrter Reihenfolge davor) |
| 20.11.2026 | **Version 0.26.1:** Der Agent sieht jetzt viermal je Sekunde nach neu gestarteten Programmen (vorher einmal; während eines Spiels weiter alle drei Sekunden). Bekannte Schadsoftware wird damit innerhalb einer Viertelsekunde nach dem Start eingefroren statt nach bis zu einer Sekunde; im Test verlor ein bekanntes Programm, das sofort loslegt, 8 von 400 Dateien (Testbericht 7.23) |
| 20.11.2026 | **Version 0.26.0:** Weniger Fehlalarme beim Ransomware-Schutz: K9 zählt nur noch Dateien, die schon vorher da waren (älter als 8 Sekunden) und plötzlich verschlüsselt aussehen; neu angelegte gepackte Dateien – Entpacken, Download, Export – zählen nicht, außer es werden gleichzeitig mindestens 5 Dateien gelöscht (Ransomware, die Kopien schreibt und Originale löscht). Anlass: Unsignierte Programme wie 7-Zip wären sonst beim Entpacken gepackter Daten eingefroren worden. Im Sandbox-Test: harmloses Anlegen von 300 gepackten Dateien ohne Alarm, Ransomware nach beiden Arten weiter erkannt (383 von 400 Dateien erhalten). Anleitung: neuer Absatz „Kein Alarm beim Entpacken und Herunterladen“; Testbericht 7.22 |
| 20.11.2026 | **Version 0.25.1:** Schutz vor Datendieben: Öffnet ein Programm gespeicherte Zugangsdaten und der Dienst kennt es im ersten Moment nicht, wartet er zwei Sekunden auf die Angaben zum Programmstart, bevor er „Programm nicht sicher zuzuordnen“ meldet. Anlass: die Meldung zu Edge-Daten alle sechs Stunden durch ein sehr kurzlebiges Programm, bei der auch der Name fehlte |
| 20.11.2026 | **Version 0.25.0:** Weniger Verlust bei Ransomware: (1) Bekannte Schadsoftware (Hashlisten, eingebaute Muster, eindeutige YARA-/ClamAV-Familien – keine Verdachtsregeln) wird mit eingeschaltetem `anhalten` schon **beim Start** eingefroren; im Test blieben 400 von 400 Dateien erhalten. (2) Der Dienst hält ein unbekanntes Programm (unsigniert oder aus einem Benutzerordner) schon nach 5 statt 12 verschlüsselten Dateien an; im Test 382 bis 383 statt 365 von 400. Signierte, installierte Programme behalten die Schwelle 12. Anleitung: neuer Absatz „Wie viele Dateien gehen verloren?“ mit Hinweis auf das Trend-Micro-Ordnerschild; Testbericht 7.21. Außerdem behoben: Beim allerersten Start mit einer neuen Datenbank konnte eine Dashboard-Abfrage einmalig mit „database is locked“ scheitern |
| 20.11.2026 | **Version 0.24.0:** Die Ransomware-Erkennung läuft jetzt zusätzlich im Dienst (als System, von Schadsoftware mit Benutzerrechten nicht zu beenden): Er überwacht Dokumente, Desktop, Bilder und Downloads aller Benutzer, bestimmt aus den Dateiöffnungen genau das Programm, das die verschlüsselten Dateien geöffnet hat, meldet es beim Namen und hält – mit eingeschaltetem `ransomware-anhalten` – nur dieses eine Programm an. Der Agent bleibt als zweite Sicherung und meldet nicht doppelt. Kein Alarm mehr, wenn ein Spiel viele gepackte Dateien schreibt. Anlass: Conti blieb im Test unerkannt. Gemessen mit dem harmlosen Testprogramm, auch mit beendetem Agenten: 365 bis 366 von 400 Dateien erhalten (Testbericht 7.20). Anleitung: neuer Absatz „Wer erkennt – Dienst und Agent“ |
| 20.11.2026 | **Version 0.23.0:** Test mit zehn echten Ransomware-Familien in der Sandbox, je mit und ohne „Ransomware-Verdächtige anhalten“: Fünf von sechs Proben, die wirklich verschlüsselten, wurden erkannt; mit dem Schalter blieben dort 104 bis 150 von 160 Dateien erhalten, ohne ihn keine. Conti wurde übersehen (Ursache noch offen, vermutlich wird der Agent beendet). Einzelheiten im Testbericht, Abschnitt 7.19; die Tabellen in „Ransomware-Alarm“ und „Wie gut erkennt K9?“ sind ergänzt |
| 20.11.2026 | **Version 0.23.0:** PDF-Anleitung: Jeder Befehl in einem Befehlskasten steht jetzt in genau einer Zeile – die Schrift eines Kastens wird so weit verkleinert, bis seine längste Zeile passt (vorher wurden lange Befehle umbrochen und beim Kopieren in zwei Zeilen zerlegt, sodass sie in PowerShell nicht mehr funktionierten). Stehen mehrere Befehle in einem Kasten, endet jede Zeile außer der letzten mit einem Strichpunkt: Manche PDF-Programme lassen beim Kopieren die Zeilenwechsel weg, die Befehle kleben dann hintereinander – mit dem Strichpunkt führt PowerShell sie trotzdem nacheinander aus. Außerdem ist jede Zeile eines Kastens in der PDF ein eigener Absatz, damit PDF-Programme beim Kopieren den Zeilenwechsel mitgeben. Ein Kasten lässt sich damit als Ganzes markieren, kopieren und einfügen |
| 19.11.2026 | **Version 0.23.0:** Dashboard und Meldefenster zeigen bei jeder Meldung eine neue Zeile „Betrifft: …“ in klaren Worten: bei Dateien den Dateinamen und – wenn K9 gerade ein Programm aktualisiert – „Installationsdatei AusweisApp-2.6.3-AMD64.msi zum Update von AusweisApp“ (sonst das winget-Paket, aus dem sie stammt); bei Programmen den Programmnamen, den Hersteller laut Signatur oder „ohne gültige Signatur“ und das zugehörige Update. Anlass: Bei „ClamAV: PUA.Win.Packer…“ war nicht zu sehen, dass es um die AusweisApp ging |
| 19.11.2026 | **Version 0.22.1:** Fehlalarm behoben: Beim Update von Opera über K9 meldete K9 den Opera-Installer als „installer.exe liest Opera (Passwörter, Cookies)“. Liest das gültig signierte Installationsprogramm aus dem Temp-Ordner die Daten genau des Browsers, den K9 gerade aktualisiert, kommt die Meldung jetzt nur leise ins Dashboard („beim Update von …“). Der Gesamttest räumt außerdem einen verspätet gestarteten Test-Agenten auf |
| 19.11.2026 | **Version 0.22.0:** Ransomware-Alarm schneller: Prüfung eine Viertelsekunde nach dem Schreiben (vorher 1,5 Sekunden), Alarm ab 12 statt 25 verschlüsselten Dateien; es zählen nur gerade eben geschriebene Dateien (ein Fehlalarm durch alte Dateien hatte im Test den echten Alarm unterdrückt), und nach einem Alarm zählt K9 sofort weiter. Neuer Schalter `k9 funktion ransomware-anhalten an` (Standard aus): friert verdächtige Programme bei Ransomware-Verdacht ein, auch ganz frisch gestartete und das Programm, das die Windows-Wiederherstellung löschen will; nie Spiele, Anti-Cheat, Windows-Bestandteile, Microsoft/Trend Micro, K9 selbst und Programme aus Arbeitsordnern. Gemessen mit einem harmlosen Testprogramm in der Sandbox: 365 bis 377 von 400 Dateien gerettet statt 0 (Testbericht 7.18). Außerdem: Bei „Programm nicht sicher zuzuordnen“ nennt K9 jetzt den Programmnamen aus dem Startereignis, wenn es ihn kennt (Anlass: eine Meldung zu Edge-Daten alle sechs Stunden); Abhängigkeit wasmtime auf 48.0.9 aktualisiert (acht neue Sicherheitshinweise). Anleitung: Abschnitt „Ransomware-Alarm“ neu gefasst; Trend Micro: Hinweis zum Bauen |
| 19.11.2026 | **Version 0.21.1:** Erste echte Ransomware in der Sandbox geprüft (LockBit, eine Probe je Sandbox, neuer Testaufbau): K9 erkennt das Verhalten eindeutig (Ransomware-Alarm, Angriffskette, Löschen der Wiederherstellung), aber nicht früher als der Schaden – 160 kleine Schein-Dokumente waren in unter fünf Sekunden verschlüsselt. Der Manipulationsschutz hielt. Der Vergleich mit „Ransomware-Verdächtige anhalten“ und neun weitere Familien stehen noch aus (Tageslimit bei MalwareBazaar). Testbericht, Abschnitt 7.17 |
| 19.11.2026 | **Version 0.21.1:** Erster Ransomware-Lauf in der Sandbox abgebrochen und ohne Aussage (Fehler des Testskripts: falscher Alarm der Netzwerk-Prüfung, unpassende Probenauswahl); beides behoben, Einzelheiten im Testbericht, Abschnitt 7.16. Ransomware in Aktion ist weiter ungeprüft |
| 19.11.2026 | **Version 0.21.1:** Vergleichstest „Schwerpunkt Datendiebe“ ausgeführt (11 echte Datendiebe mit Ködern, ohne Hashlisten): 4 von 11 als Datei am Inhalt erkannt, nach dem Start bei allen die Herkunftswarnung, bei einer Probe (AgentTesla) der Zugriff auf Zugangsdaten samt Angriffskette. Ransomware lief nicht (Serverfehler bei MalwareBazaar) und ist weiter ungeprüft. Einzelheiten und Grenzen im Testbericht, Abschnitt 7.15. Sandbox-Skripte: drehendes Rad, Startzeit, Schutz vor Anhalten durch Mausklick, eigener Ransomware-Lauf |
| 19.11.2026 | **Version 0.21.1:** Schutz vor Datendieben: Der Windows-Explorer wird nicht mehr gemeldet, wenn er einen Ordner mit Wallet- oder Zugangsdaten nur anzeigt (Maus über dem Ordner, Ordnerbaum, Suche) – dabei wird nichts gelesen. Öffnet er eine Datei daraus, kommt die Meldung weiterhin. Anlass: Meldung „explorer.exe liest Krypto-Wallet“ vom 19.11. für einen Ordner auf Laufwerk F: |
| 19.11.2026 | **Version 0.21.0:** „Skript aus dem Internet gestartet“ greift jetzt auch, wenn das Skript nur mit dem Dateinamen statt mit dem vollen Pfad aufgerufen wird (z. B. `wscript rechnung.js` aus dem Ordner „Downloads“): K9 liest dafür den Arbeitsordner des gestarteten Programms aus |
| 19.11.2026 | **Version 0.20.1:** Fehler behoben: Nach der Installation von 0.20.0 wollte K9 die vollständige MalwareBazaar-Liste sofort neu laden, obwohl sie erst wenige Stunden alt war; abuse.ch lehnte das mit „zu viele Abrufe (429)“ ab, und das stündliche Nachladen blieb aus. Jetzt zählt das Alter der vorhandenen Liste, und wenn die vollständige Liste einmal nicht geladen werden kann, werden die neuesten Einträge trotzdem eingefügt |
| 19.11.2026 | **Version 0.20.0:** Sandbox-Test „Skript aus dem Internet gestartet“ bestanden (8 von 8): Skripte mit Internet-Vermerk über `wscript`, `cscript`, `mshta`, PowerShell und `cmd` werden gemeldet, jedes nur einmal, Skripte ohne Vermerk nicht. Einzelheiten im Testbericht, Abschnitt 7.14 |
| 19.11.2026 | **Version 0.20.0:** Neu: K9 lädt **jede Stunde** die neuesten Schadsoftware-Hashes von MalwareBazaar nach (Einträge der letzten 48 Stunden, unter 100 KB) und fügt sie in die vollständige Liste ein; die ganze Liste wird weiter einmal am Tag geladen. Schadsoftware von heute ist damit meist innerhalb einer Stunde bekannt statt erst am nächsten Tag. Nie während eines Spiels; abstellbar mit `intervall_stunden = { malwarebazaar = 24 }`. Die Zahlen in der PDF-Anleitung werden höchstens alle 12 Stunden neu geschrieben. Anleitung: neuer Absatz „Stündliches Nachladen“ im Abschnitt „Erkennungsquellen“ |
| 19.11.2026 | **Version 0.19.0:** Neu: Meldung „Skript aus dem Internet gestartet“ (Schwere Hoch), wenn eine Skriptdatei mit Internet-Herkunft (.js, .jse, .vbs, .vbe, .wsf, .hta, .ps1, .bat, .cmd) über `wscript`, `cscript`, `mshta`, PowerShell oder `cmd` gestartet wird – die Lücke aus dem Vergleichstest. Freigabe gilt für genau dieses Skript; Schalter `download-herkunft`. Anleitung: neue Abschnitte „Programme und Skripte aus dem Internet“ und „Wie gut erkennt K9?“ |
| 19.11.2026 | **Version 0.18.3:** Vergleichstest mit gestarteten Proben ausgeführt: 20 von 20 als Datei erkannt (8 am Inhalt), nach dem Start bei 5 von 19 echtes Verhalten gemeldet, bei 9 die Warnung „unsigniertes Programm aus dem Internet gestartet“, bei 5 nichts. Einzelheiten und Grenzen im Testbericht, Abschnitt 7.13 |
| 19.11.2026 | **Version 0.18.3:** Vergleichstest mit gestarteten Proben vorbereitet (`k9-vergleich-starten.wsb`, startet von selbst): 20 startbare Proben, K9 eingestellt wie auf dem PC (Anhalten an, PowerShell-Protokollierung an), Netzwerk dreifach gesperrt (Adapter aus, Gerät entfernt, Firewall der Sandbox sperrt alles) und nach jeder Probe geprüft, kein Ordner zurück zum PC – das Ergebnis wird vom Bildschirm fotografiert |
| 19.11.2026 | **Version 0.18.3:** Vergleichstest mit echter Schadsoftware in der Sandbox ausgeführt (nur prüfen): 30 Proben, K9 erkannte 26, davon 11 am Inhalt (YARA); die Trend-Micro-Engine bei VirusTotal 16. Einzelheiten und Grenzen im Testbericht, Abschnitt 7.12 |
| 19.11.2026 | **Version 0.18.3:** Vergleichstest-Skript: je zur Hälfte neue (Stunden alte) und ältere Proben (7 bis 30 Tage, aus 15 verbreiteten Familien), Proben ohne Familiennamen zählen nicht mehr als eine Familie, Auswertung getrennt nach „neu“ und „älter“ und nach dem abschließenden Scan mit allen Erkennungswegen. Erster Lauf am 18.11. mit 8 Proben: 8 von 8 über die Hashliste, 0 am Inhalt |
| 18.11.2026 | **Version 0.18.3:** Eingehende Firewall-Regeln: Die Regeln, die Windows beim Start der Windows-Sandbox für deren eigenes Netz anlegt („HNS Container Networking – DNS …“, an genau eine Netzwerkschnittstelle gebunden, nur Port 53/67/68), werden nicht mehr gemeldet, nur protokolliert. „Regel entfernen“ scheiterte bei Regeln, deren Kennung Leerzeichen oder Klammern enthält („ungültige Regel-Kennung“); das geht jetzt |
| 18.11.2026 | **Version 0.18.2:** `k9 geheimnis <name> --aus-eingabe` nimmt einen Wert auch dann an, wenn PowerShell beim Weiterreichen ein unsichtbares Zeichen davorsetzt (im ersten Vergleichstest wurde der abuse.ch-Schlüssel deshalb als „ungültiges Format“ abgelehnt). Vergleichstest-Skript: wartet, bis Hashlisten und ClamAV-Signaturen geladen sind, und nimmt die neuesten 100 statt nur die Proben der letzten Stunde als Auswahl |
| 18.11.2026 | **Version 0.18.1:** Vergleichstest-Skript: prüft zuerst den abuse.ch-Schlüssel, richtet K9 in der Sandbox wie auf dem PC ein (abuse.ch-Hashlisten, ClamAV) und wertet je Erkennungsweg getrennt aus (Hashliste, YARA, ClamAV) |
| 18.11.2026 | **Version 0.18.1:** Vergleichstest: `k9-vergleich.wsb` startet das Testskript in der Sandbox von selbst in einem sichtbaren Fenster (Ablauf im Sandbox-Testplan) |
| 18.11.2026 | **Version 0.18.1:** Testhilfe für den Speicher-Scan: `k9 test-speicher` (aus dem Build-Ordner) hält die harmlose Testsignatur nur im Arbeitsspeicher; Beschreibung in Anhang C |
| 18.11.2026 | **Version 0.18.0:** Neu, standardmäßig **aus**: Speicher-Scan im Leerlauf (`k9 funktion speicher-scan an`). Sucht Schadcode, der nur im Arbeitsspeicher steht. Läuft nie, solange ein Spiel oder ein Anti-Cheat-Programm läuft, und gar nicht auf einem PC mit ständig geladenem Anti-Cheat (Riot Vanguard, FACEIT); prüft nur Programme aus Benutzerordnern oder ohne gültige Signatur, nur lesend. Vorschau ohne Speicherzugriff: `k9 speicher-scan` |
| 18.11.2026 | **Version 0.17.0:** Neu: neue Sicherheitslücken (CVE) mit Schweregrad Hoch oder Kritisch für installierte Programme, auch wenn sie noch nicht aktiv ausgenutzt werden. Der Agent fragt einmal am Tag die NVD nach den neu veröffentlichten Lücken und vergleicht Hersteller, Produkt und Version mit deinen Programmen; Befehl `k9 luecken`, Schalter `neue-luecken` |
| 18.11.2026 | **Version 0.16.1:** Geladene Installationsprogramme: Weicht der Herstellername nur leicht ab (dieselbe Firma unter geändertem Namen, z. B. WD Security: „WESTERN DIGITAL CORPORATION“ statt „Western Digital Technologies, Inc.“), löscht K9 die Datei nicht mehr, sondern bietet „Trotzdem installieren“ an – mit deutlichem Hinweis und beiden Namen im Bestätigungsfenster. Ein ganz anderer Hersteller wird weiter abgelehnt |
| 18.11.2026 | **Version 0.16.0:** „Suchen und Laden“ und „Installieren“ für mehr Programme: K9 findet den Hersteller der installierten Version jetzt auch, wenn die Programme in Unterordnern liegen (z. B. LibreOffice) und bei Store-/MSIX-Apps (z. B. TradingView, aus dem App-Manifest). „Suchen und Laden“ sieht zusätzlich auf bis zu 5 Download-Unterseiten des Herstellers nach und nutzt die Adresse aus dem winget-Katalog, auch ZIP-Archive mit dem Installationsprogramm darin (z. B. WD Security) – für Fälle, in denen winget die Datei nur wegen einer veralteten Prüfsumme ablehnt. Neu erlaubt: `.msix`-Pakete |
| 18.11.2026 | **Version 0.15.0:** Schneller: Konten und Anmeldungen jetzt wirklich sofort (0.14.2 hat das Signal von Windows nicht bekommen, die Meldung kam erst mit der Minuten-Prüfung nach 20 bis 55 Sekunden; jetzt ruft Windows den Dienst bei jedem Ereignis direkt). Neue Autostarts (Run-Schlüssel, Autostart-Ordner) sofort statt alle 30 Sekunden. Verbindungen zu Schad-Adressen alle 2 Sekunden statt alle 60 (im Spiel alle 5). Neue Geräte im Heimnetz: alle 15 Sekunden ein Blick in die Geräteliste von Windows (sendet nichts), alle 5 Minuten statt jede Stunde alle Adressen. Schutz vor Datendieben: Hilfsdateien der Browser (`Local State….tmp`, `-wal`, `-shm`, `-journal`) lösen keine Meldung „Programm nicht sicher zuzuordnen“ mehr aus |
| 18.11.2026 | **Version 0.14.2:** Konten und Anmeldungen: Meldung jetzt sofort (innerhalb etwa einer Sekunde) statt nach bis zu einer Minute – Windows benachrichtigt den Dienst, sobald ein überwachtes Ereignis ins Sicherheitsprotokoll geschrieben wird; die Prüfung jede Minute bleibt als Reserve. Neuer Abschnitt „Wie oft prüft K9?“ |
| 18.11.2026 | **Version 0.14.1:** Konten und Anmeldungen: Beim Anlegen eines Kontos kommt nur noch eine Meldung („Neues Benutzerkonto“); die Aktivierung, die Windows dabei sofort mitschreibt, wird nicht mehr zusätzlich gemeldet. Am echten PC mit einem Testkonto geprüft (18.11.) |
| 18.11.2026 | **Version 0.14.0:** Solange K9 selbst ein Programm aktualisiert, installiert oder deinstalliert (und zwei Minuten danach), kommen eindeutige Nebenwirkungen des Installationsprogramms leise mit dem Vermerk „beim Update von …“: Hilfsdateien im Temp-Ordner, die nur eine Verdachts-Regel treffen (YARA „Indicator“/„Suspicious“, ClamAV „PUA“), und neue Autostart-Einträge der Stufe Info. Bekannte Schadsoftware, kritische Meldungen, Firewall-Regeln, Anmeldungen und neue Geräte bleiben laut (Anlass: 15 solche Meldungen bei rund 60 Updates am 18.11.). Außerdem: E-Mail-Baustein (lettre) auf 0.11.24 aktualisiert, sechs am 17.11. veröffentlichte Sicherheitslücken im E-Mail-Versand geschlossen (betrifft nur den Kanal `email`) |
| 18.11.2026 | **Version 0.13.1:** Liste der veralteten Programme: Ein hängender winget-Lauf blockiert die Warteschlange nicht mehr (am 18.11. blieb der TeamSpeak-Download bei 112 von 113 MB stehen). K9 beendet winget, wenn der Download über 4 Minuten keinen Fortschritt macht oder nach 30 Minuten ohne Ergebnis, und versucht es einmal neu. Neuer Knopf „Abbrechen“ neben „… läuft …“ |
| 18.11.2026 | **Version 0.13.0:** Liste der veralteten Programme: neuer Knopf „Still installieren“ neben „Installieren“ für eine geprüfte geladene Datei – Installation ohne Fenster und ohne Fragen mit den Standardeinstellungen des Herstellers. K9 erkennt die Art des Installationsprogramms am Inhalt (MSI, Inno Setup, NSIS, WiX-Paket); bei unbekannter Art gibt es nur „Installieren“ |
| 18.11.2026 | **Version 0.12.0:** Liste der veralteten Programme: neuer Knopf „Suchen und Laden“ nach einem fehlgeschlagenen „Aktualisieren“. K9 sucht auf der offiziellen Seite aus dem winget-Katalog das Installationsprogramm (nur https, nur Dateien auf der Seite des Herstellers selbst, 64 Bit, keine portable Version), lädt es nach „Downloads“ und behält es nur, wenn es gültig signiert ist und vom selben Hersteller stammt wie die installierte Version; gestartet wird erst mit „Installieren“ nach deiner Bestätigung |
| 18.11.2026 | **Version 0.11.0:** Liste der veralteten Programme: Nach einem fehlgeschlagenen „Aktualisieren“ steht unter dem Programm ein kurzer Hinweis mit Datum („Seit 18.11.2026: Die Download-Adresse im winget-Katalog stimmt nicht …“, Link zur offiziellen Seite, „oder in 1–2 Tagen erneut „Aktualisieren““); er bleibt über die tägliche Prüfung erhalten. Neu: Knopf „Installieren“ für eine selbst geladene Datei in „Downloads“ – nur wenn sie gültig signiert ist, vom selben Hersteller stammt wie die installierte Version, zum Programm passt und K9 keine Meldung dazu hat; Bestätigungsfenster mit Datei, Hersteller und SHA-256, erneute Prüfung direkt vor dem Start |
| 18.11.2026 | **Version 0.10.3:** Liste der veralteten Programme: Schlägt „Aktualisieren“ fehl (z. B. „Not found (404)“, die Download-Adresse im winget-Katalog stimmt nicht mehr), erneuert K9 den winget-Katalog und versucht es von selbst ein zweites Mal. Klappt auch das nicht, steht unter dem Programm der Link zur offiziellen Seite aus dem winget-Katalog (nur https) zum Selbstladen. K9 lädt nie selbst Installationsprogramme von anderen Seiten |
| 18.11.2026 | **Version 0.10.2:** Liste der veralteten Programme: Kann winget ein Update auf deinem PC gar nicht installieren (Meldung „neuere Paketversion verfügbar, die jedoch nicht auf Ihr System zutrifft“, z. B. Bonjour), verschwindet das Programm aus der Liste und bleibt weg, bis es eine noch neuere Version gibt; unter „Zuletzt“ steht „nicht möglich“. Schlägt ein Update aus anderem Grund fehl, steht der Grund rot unter dem Programmnamen. Umlaute in den winget-Meldungen werden richtig angezeigt |
| 18.11.2026 | **Version 0.10.1:** Liste der veralteten Programme: Das drehende Rad erscheint sofort nach dem Klick („wartet auf dein „Ja“ im Bestätigungsfenster …“, dann „… läuft …“, bei den übrigen „… wartet …“); vorher blieb die Seite nach dem Klick stehen, weil sie vor dem „Ja“ geladen wurde. Die Liste bleibt offen, sobald du darin etwas gestartet hast; die Seite lädt sich während der Arbeit alle 3 Sekunden neu und bleibt an derselben Stelle. Der Knopf zum Öffnen der Liste ist größer |
| 18.11.2026 | **Version 0.10.0:** Liste der veralteten Programme: drehender Kreis „… läuft …“ bzw. „… wartet …“ hinter jedem Programm, das gerade bearbeitet wird (Seite lädt sich dann alle 5 Sekunden neu); Kästchen „Auswahl“ mit „Ausgewählte aktualisieren/deinstallieren“; „Alle aktualisieren/deinstallieren“; ein Bestätigungsfenster für alle gewählten Programme, Bearbeitung nacheinander |
| 18.11.2026 | **Version 0.9.0:** Dashboard, Liste der veralteten Programme: hinter jedem Programm „Aktualisieren“ und „Deinstallieren“ (winget, nur nach „Ja“ im Bestätigungsfenster, eins nach dem anderen, Ergebnis unter „Zuletzt“); Trend Micro und K9 lassen sich dort nicht deinstallieren |
| 18.11.2026 | **Version 0.8.1:** Sicherheits-Check: Einträge im Windows-Sicherheitscenter, deren Programmdatei fehlt (z. B. ein deinstalliertes Kaspersky), zählen nicht mehr als „Virenschutz an“ bzw. „Firewall an“. Vergleichstest: Proben starten nur in einer Sandbox ohne beschreibbaren Ordner zum PC (`k9-vergleich-starten.wsb`); Kapitel „Kaspersky-Reste entfernen“ |
| 17.11.2026 | **Version 0.8.0:** Vorbereitet, noch nicht ausgeführt: Vergleichstest mit echter Schadsoftware in der Windows-Sandbox (`scripts\sandbox\sandbox-vergleich.ps1`, `k9-vergleich.wsb`; Proben werden nur in der Sandbox geladen, Netzwerk aus vor dem Entpacken, nur Text-Ergebnisse, nur mit Zustimmung für den jeweiligen Tag; Ablauf im Sandbox-Testplan) |
| 17.11.2026 | **Version 0.8.0:** Neu: Sicherheits-Check im Dashboard (Ampel für Virenschutz, Firewall, Windows-Updates, Secure Boot, Benutzerkontensteuerung, Remotedesktop, Speicherintegrität, Datensicherung, Programm-Updates; nur lesen) und `k9 sicherheitscheck`; veraltete Programme über winget einmal am Tag mit Befehlen zum Aktualisieren (K9 installiert nichts); Wochenbericht als Meldefenster; neue Geräte im Heimnetz (stündlich, nie im Spiel) und `k9 heimnetz`; Abschnitt `[sicherheitscheck]`, Funktionen `sicherheitscheck`, `programm-updates`, `wochenbericht`, `heimnetz` |
| 17.11.2026 | **Version 0.7.0:** Neu: Konten und Anmeldungen überwachen (Dienst, Windows-Sicherheitsprotokoll, nur lesen): neues Benutzerkonto, neuer Administrator oder Remotedesktopbenutzer, aktiviertes Konto, Remotedesktop-Anmeldung, viele fehlgeschlagene Anmeldungen, gelöschtes Sicherheitsprotokoll; Schalter `anmeldungen`. Neu: versteckte Autostarts über WMI (dauerhafte Ereignisabonnements mit Befehl oder Skript) alle 10 Minuten, nie während eines Spiels; die Meldung nennt den Befehl zum Entfernen, K9 entfernt nichts |
| 17.11.2026 | **Version 0.6.0:** Neu: Arbeitsordner und Arbeitsprogramme (`k9 arbeitsordner`, Abschnitt `[arbeitsordner]`). Verhaltensmeldungen aus Claude-Projekten und Builds kommen nur noch leise ins Dashboard (kein Meldefenster, keine E-Mail, kein Punkt am Symbol); viele Ransomware-Verdachte im selben Arbeitsordner ergeben eine Meldung. Bekannte Schadsoftware, Köderdateien und kritische Meldungen bleiben laut. Ransomware-Erkennung: Browser-Zwischenspeicher (Cache, Schriften, Erweiterungspakete) gilt als von Natur aus komprimiert; das beendet die 94 Fehlalarme vom 17.11. durch ein anderes Claude-Projekt |
| 17.11.2026 | **Version 0.5.1:** Anleitung: Die alten Trend-Micro-Ausnahmen („Virenscanner“-Pfade, `vscan.exe`, `vs-agent.exe`, `vs-dienst.exe`) sind gelöscht; die Liste zeigt nur noch die K9-Ausnahmen, die Umstellung auf K9 ist abgeschlossen |
| 17.11.2026 | **Version 0.5.1:** „Deaktivieren“ bei Autostart-Meldungen für alle Benutzer (HKLM\…\Run, z. B. „Opera Browser Assistant“) scheiterte mit „nicht beschreibbar“: Der Dienst arbeitete dort mit deinen normalen Benutzerrechten, die den Schlüssel nur lesen dürfen. Jetzt schaltet er solche Einträge mit seinen eigenen Rechten ab, und zwar wie der Task-Manager (Eintrag bleibt, wird nicht mehr gestartet, „Wieder einschalten“ möglich). Fehlermeldungen beim Schreiben in die Registrierung nennen den Windows-Fehler. Die alte Installation „Virenscanner“ wurde am 17.11.2026 entfernt; offen sind nur noch die alten Trend-Micro-Ausnahmen |
| 16.11.2026 | **Version 0.5.0:** Mehrere Meldungen auf einmal bearbeiten: neue Spalte „Auswahl“ in „Offene Erkennungen“ (ankreuzen, „gleiche“, „Alle auswählen“), Leiste mit den Aktionen, die für alle ausgewählten Meldungen möglich sind; ein Bestätigungsfenster für die Auswahl, jede Meldung wird einzeln ausgeführt, Ergebnis je Meldung |
| 16.11.2026 | **Version 0.4.3:** Quarantäne im Dashboard: die Beschriftung von „Wiederherstellen“ und „Wiederherstellen + Freigeben“ steht linksbündig statt mittig. Die Titelseite der Anleitung zeigte noch „Version 0.4.2“ (das Hilfsprogramm für die PDF war veraltet); jetzt liest es die Versionsnummer bei jedem Erzeugen aus dem Projekt |
| 16.11.2026 | **Version 0.4.2:** Das Dashboard nutzt die Fensterbreite: bis 1800 Pixel die volle Breite (vorher fest 1150 Pixel in der Mitte), darüber bleibt es 1800 Pixel breit und mittig, damit die Zeilen lesbar bleiben; die Ränder wachsen mit. Titelseite dieser Anleitung: neben der Pfote stehen jetzt Version und Datum (statt „K9“), unten bündig mit dem Symbol; beides wird bei jedem Erzeugen der PDF automatisch eingesetzt |
| 16.11.2026 | **Version 0.4.1:** Dashboard übersichtlicher: Spalten „#“ und „Aktion“ breiter, Datum und Uhrzeit überall untereinander und ohne Umbruch (Zeiten aus dem Firewall-Protokoll in Ortszeit), Knöpfe brechen nicht mehr mitten im Wort um („Löschen/Deaktivieren“ höchstens nach dem „/“), „Widerrufen“ und die Spalte „Stufe“ im Protokoll ohne Umbruch, in der Quarantäne „Wiederherstellen“ und „Wiederherstellen + Freigeben“ untereinander |
| 16.11.2026 | **Version 0.4.0:** K9 stellt seine Sperrregeln sofort wieder her (etwa 2 Sekunden), wenn sie jemand löscht, abschaltet oder ändert, und meldet, welches Programm es war (eine Meldung pro Programm, die mitzählt; Knöpfe „Freigabe (dieses Programm darf K9-Regeln ändern)“ und „Gesehen“). `k9 firewall entfernen` läuft jetzt über den Dienst (mit Bestätigungsfenster) und pausiert die Sperre bis zur nächsten regulären Erneuerung; neuer Ablauf i) in der Kurzanleitung |
| 16.11.2026 | **Version 0.3.0:** Neue Wache für eingehende Firewall-Regeln: neue Regeln, die Verbindungen von überall zulassen (ohne Programm, Programm im Benutzerordner oder unsigniert), werden sofort gemeldet – gleiche Regeln als eine Meldung mit Anzahl, mit dem Programm, das sie angelegt hat; Knöpfe „Regel entfernen“, „Freigabe (diese Regel nicht mehr melden)“, „Gesehen“; beim ersten Start nur Ausgangsstand; neu `k9 firewall eingang` |
| 16.11.2026 | **Version 0.2.2:** Firewall-Sperre ohne Lücke: Der Dienst gleicht die Regeln über die Schnittstelle der Windows-Firewall ab (Sekunden statt etwa 5 Minuten), ändert nur Abweichungen, legt Neues an, bevor er Überflüssiges entfernt, und lässt passende Regeln beim Dienststart unberührt; `k9 firewall vorschau` zeigt die geplanten Änderungen. Dashboard-Überschrift: Versionsnummer halb so groß, unten bündig mit der Pfote |
| 16.11.2026 | **Version 0.2.1:** Überschrift des Dashboards: größeres K9-Symbol mit dem Schriftzug „K9“ in der Pfote, Versionsnummer kleiner daneben; das Feld mit Bauzeit und Commit erscheint jetzt zuverlässig beim Darüberfahren mit der Maus (auch über der Pfote) und bei der Tab-Taste (der Browser-Tooltip von 0.2.0 erschien über dem Symbol nicht) |
| 16.11.2026 | **Version 0.2.0:** Die Überschrift des Dashboards zeigt statt „K9“ die Pfote und die Versionsnummer (Maus darüber: Bauzeit und Commit); ab jetzt steigt die Versionsnummer mit jeder installierten Version. `k9 --help` zeigt die Beschreibung von `funktion` wieder an der richtigen Stelle |
| 16.11.2026 | **Version 0.1.0 (letzte mit dieser Nummer):** Quarantäne und Löschen öffnen die Datei nur noch einmal (Kopieren, Prüfen und Entfernen über denselben Zugriff), sodass die Prüfung eines anderen Virenscanners nach dem Lesen sie nicht mehr blockiert; ist die Datei gerade von einem anderen Programm geöffnet, wartet K9 bis zu 5 Sekunden. Erfolg und Fehlschlag stehen im Dienst-Protokoll. Das Bestätigungsfenster nennt jetzt genau den gewählten Knopf (z. B. „„Gesehen (Datei nicht mehr vorhanden, nichts wird gemerkt)“ bestätigen?“ statt „Nur diesmal erlauben bestätigen?“) |
| 15.11.2026 | Das Aufräumen von Microsoft Edge nach einem Update (einmaliger RunOnce-Eintrag `msedge_cleanup_{…}` mit dem gültig von Microsoft signierten Edge-Installer und nur den bekannten Aufräum-Optionen) wird nicht mehr gemeldet, nur protokolliert; jede Abweichung bleibt eine Meldung |
| 15.11.2026 | Firewall-Sperre: Adressen in geteilten CDN-Netzen (Cloudflare, Amazon CloudFront, Fastly, Google-Front-Ends) werden nie gesperrt; bei mehr als 1000 Kandidaten die neuesten zuerst; neu `k9 firewall vorschau`; schneller Rückweg in der Anleitung |
| 15.11.2026 | Meldefenster und Bestätigungsfenster spielen wieder den Windows-Warnton (Testmeldung: Hinweiston); er war mit dem eigenen K9-Symbol weggefallen |
| 15.11.2026 | Neu: `k9 pause-beenden` beendet eine Pause sofort und startet den Agent; Anleitung: K9 vorübergehend pausieren und wieder aktivieren („Wichtige Abläufe“, Punkt h), Hinweis zu Meldungen während eines Spiels |
| 15.11.2026 | Umstellung auf K9: ein eingeschalteter Autostart des Agents bei der Anmeldung wird übernommen (vorher ging er verloren – nachholen mit `k9 autostart-agent an`) |
| 15.11.2026 | **Neuer Name: K9** (vorher „Virenscanner“). Befehl `k9` (vorher `vscan`), Programme `k9.exe`, `k9-agent.exe`, `k9-dienst.exe`, Dienst „K9 Schutzdienst“, Ordner `C:\Program Files\K9`, `C:\ProgramData\K9`, `%APPDATA%\K9`, `%LOCALAPPDATA%\K9`, Verknüpfung „K9-Dashboard“, Firewall-Gruppe „K9“. `k9 dienst aktualisieren` übernimmt die alte Installation (Funde, Entscheidungen, Quarantäne, Schlüssel, Einstellungen) und entfernt sie erst nach erfolgreichem Selbsttest; die alten Daten bleiben als Sicherung `…\Virenscanner.alt`, bis du `k9 alte-installation entfernen` ausführst. Unverändert bleiben nur die Köderdateien (`~vs-koeder-nicht-loeschen.docx`) |
| 15.11.2026 | Ransomware-Erkennung: Git-Dateien (komprimierte Objekte, Pakete) gelten nach ihrem Inhalt als „von Natur aus komprimiert“ – keine Fehlalarme mehr beim Arbeiten mit Git; verschlüsselte Daten werden weiter erkannt, auch in einem Ordner „objects“ |
| 15.11.2026 | VirusTotal-Schlüssel nur noch beim Dienst (keine Kopie in der Anmeldeinformationsverwaltung); eine Aktualisierung ersetzt nie einen gespeicherten Dienst-Schlüssel, ändern nur mit `k9 geheimnis …` und Bestätigung |
| 15.11.2026 | Firewall-Sperre erneuert sich sofort, wenn neue ThreatFox-Daten da sind (nicht erst nach 24 Stunden); Sandbox-Lauf 19 bestanden (Testbericht 7.9) |
| 15.11.2026 | Firewall-Sperre: Regeln heißen jetzt „K9 – Botnetz-Server gesperrt (Port N)“, Gruppe „K9“, Beschreibung mit Quelle, Stand, Anzahl und Entfernen-Befehl; Regeln mit dem alten Namen „Virenscanner C2-Sperre“ werden ersetzt; `k9 firewall status` listet die Regeln |
| 15.11.2026 | Schattenkopien für mehrere Laufwerke (`schattenkopien_laufwerke`, Befehl `k9 funktion schattenkopien laufwerke C: F:`); Statuszeile je Laufwerk |
| 15.11.2026 | Fehler behoben: „Änderung übernehmen“ für eine abgeschwächte Sicherheitseinstellung scheiterte seit Härtung Stufe 3 nach dem Bestätigungsfenster mit „Bestätigen kann nur der Windows-Dienst“ (Meldefenster, Dashboard und `k9 entscheiden`); jetzt übernimmt der Dienst die Werte und schließt den Fund |
| 15.11.2026 | Neu: `k9 funktion <name> an/aus` und `k9 funktion status` (ändert nur die eine Zeile in `config.toml`); Anhalten, VirusTotal, Firewall-Sperre, Schattenkopien, Angriffsketten und Herkunftsprüfung folgen `config.toml` ohne Neustart (innerhalb von 30 Sekunden) |
| 15.11.2026 | Manipulationsschutz erweitert: alle Schutzschalter, Spiele-Listen und der Spielmodus brauchen zum Abschwächen deine Bestätigung, auch beim Dienst selbst (vorher nur die Echtzeit-Schalter des Agents); schärfere Werte werden sofort der bestätigte Stand; „Verdächtige Prozesse anhalten“ einschalten braucht keine Bestätigung mehr, ausschalten schon; Ersetzen/Löschen eines Dienst-Schlüssels braucht die Bestätigung; Meldung, wenn die vollständige PowerShell-Protokollierung ausgeschaltet wird |
| 15.11.2026 | PowerShell-Skriptprüfung: Herunterladen und nur eine Datei starten ist jetzt Mittel (vorher Hoch); Herunterladen und im Speicher ausführen bleibt Hoch. Der eigene Testlauf (`scripts\e2e-test.ps1`) erzeugt keine Meldung mehr |
| 15.11.2026 | `k9 dienst aktualisieren` aus einer Administrator-PowerShell: der Dienst startet den Agent jetzt nach etwa 10 Sekunden (vorher erst nach 3 Minuten; aus einer normalen PowerShell startet `k9` ihn wie bisher selbst) |
| 15.11.2026 | Hinweis „Schattenkopien: kein Speicher“ nur noch einmal je Laufwerk (nicht bei jedem Dienststart neu); Agent-Wache startet einen beendeten Agent nach etwa 10 Sekunden neu (vorher bis zu 3 Minuten), außer direkt nach Anmeldung oder Aktualisierung; Sandbox-Lauf 17 bestanden (Testbericht 7.7) |
| 15.11.2026 | Neues Kapitel 15 „Projektstatistik“ (Zeitraum, Dauer der Entwicklungsschritte, Umfang, Erkennungsdaten, Messungen, Sandbox-Läufe, Funde nur als Anzahlen), bei jedem Commit neu erzeugt; Hinweis, echte Schlüssel nur über die unsichtbare Eingabe einzugeben |
| 15.11.2026 | `k9 geheimnis <name> --aus-eingabe` liest den Wert aus der Standardeingabe (für Skripte); fehlgeschlagene VirusTotal-Abfragen zählen nicht gegen die Tagesgrenze |
| 15.11.2026 | Neu, alle standardmäßig aus: kritische Programme anhalten bis zur Entscheidung (`kritische_prozesse_anhalten`), VirusTotal-Abfrage nur der Prüfsumme (`virustotal_aktiv`, `k9 geheimnis virustotal-key`), Schattenkopien im Leerlauf (`[schutz] schattenkopien`), Firewall-Sperre bekannter Botnetz-Steuerserver (`firewall_sperre`, `k9 firewall status/entfernen`) |
| 15.11.2026 | PowerShell-Skriptprüfung empfängt bei eingeschalteter Richtlinie jetzt alle Skripte (vorher nur die von PowerShell als verdächtig eingestuften) |
| 15.11.2026 | `k9 powershell-protokoll an` legt den Richtlinien-Schlüssel jetzt selbst an (vorher Fehler „nicht beschreibbar“, wenn er noch nicht existierte) |
| 15.11.2026 | Neu: erweiterter Manipulationsalarm (Dienst gestoppt, Programmdateien verändert, Startart geändert, Überwachung gestoppt); Ausgangsstand der Programmdateien schreibt nur `k9 dienst aktualisieren`, Meldung bei einem Neustart des Dienstes außerhalb von Windows-Start und Aktualisierung |
| 15.11.2026 | Neu: Angriffsketten – Programm aus dem Internet und seine Kindprozesse (Skript, Autostart, Zugangsdaten, Schad-Adresse) als eine Meldung (Schalter `angriffsketten`) |
| 15.11.2026 | Neu: Meldung, wenn ein unsigniertes Programm aus dem Internet startet (Herkunftsvermerk, Schalter `download_herkunft`) |
| 15.11.2026 | Neu: Prüfung von PowerShell-Skripten vor dem Ausführen (Dienst, Schalter `powershell_skripte`), Befehl `k9 powershell-protokoll an/aus/status`; Firefox-eigene Suchmaschinen (…@search.mozilla.org) werden nicht mehr gemeldet |
| 15.11.2026 | Anleitung neu gegliedert: Titelseite, anklickbares Inhaltsverzeichnis mit PDF-Lesezeichen, Teil 1 Kurzanleitung, Teil 2 Bedienung, Teil 3 Funktionen (mit Übersichtstabelle), Teil 4 Befehlsreferenz, Teil 5 Installation/Update/Fehlerbehebung, Anhang; Seitenzahlen in der Fußzeile |
| 15.11.2026 | Programmsymbol „Pfote“ (orange) für `k9.exe`, `k9-agent.exe`, `k9-dienst.exe`, Verknüpfung, Meldefenster und Bestätigungsfenster; neues Symbol im Infobereich mit Zustand (ruhig, Meldung, kritisch, Dienst gestoppt); Symbol im Browser-Tab des Dashboards |
| 14.11.2026 | „Prozess beenden“ prüft Programmpfad und Startzeit (keine Verwechslung bei neu vergebenen Prozess-IDs), sonst „Prozess läuft nicht mehr“; „Gesehen“ für beendete Prozesse und verschwundene Dateien; Freigabe-Knopf bei Datendieb-Funden sagt, was gemerkt wird; leere Zeile „Befehlszeile“ ausgeblendet; Tabellenspalten im Dashboard schreiben nicht mehr ineinander; Firefox-eigene Erweiterungen (u. a. „Web Compatibility Interventions“) werden nicht mehr gemeldet; leerer Registry-Eintrag für eine Chrome-Erweiterung nur noch als Info; Agent-Protokoll „Meldefenster angezeigt“; der End-zu-End-Test liest nie mehr echte Benutzerordner (Profile, TEMP) |
| 14.11.2026 | Schutz vor Datendieben: erkennt jetzt auch sehr kurz laufende Programme und Pfade in beliebiger Groß-/Kleinschreibung; Zuordnung nur über Kernel-Angaben, bei Unsicherheit Meldung „Programm nicht sicher zuzuordnen“; Statistik im Dienst-Protokoll mit Dateiöffnungen je Sekunde und CPU-Zeit (Sandbox-Läufe 7–12) |
| 14.11.2026 | Ähnliche Domains: weitere offizielle Hersteller-Domains nie gemeldet (u. a. telegra.ph, t.me, rgpub.io, Netflix-, NVIDIA- und Microsoft-Anmeldedomains); Entwürfe für die Veröffentlichung: `docs/RELEASE-PLAN.md`, `docs/RELEASE-CHECKLISTE.md`, `README.en.md` |
| 14.11.2026 | Neu: ClamAV meldet unerwünschte Programme (PUA, ohne Packer; Werkzeuge „Niedrig“), Schalter `clamav_pua`; zweite Phishing-Liste „phishing-filter“ (Quelle `phishing_filter`, Schwere Mittel, nie ganze öffentliche Endungen dank Public Suffix List); Meldung ähnlicher Domains bekannter Marken (Abschnitt `[phishing]`, eigene Marken möglich); `k9 quellen` zeigt die Lizenz jeder Quelle |
| 14.11.2026 | Neu: Prüfung der Browser-Erweiterungen (neue Erweiterungen, Rechte-Erweiterungen bei Updates, Liste bekannter Schad-Erweiterungen „MalExt Sentry“, erzwungene Installationen per Richtlinie/Registry, Verknüpfungen mit `--load-extension`); Dashboard-Kasten „Browser-Erweiterungen“; neue Quelle `malext`, Schalter `erweiterungen_aktiv`; Programmstart-Regel für `--load-extension` aus Benutzerordnern |
| 14.11.2026 | Neu: Schutz vor Datendieben (Infostealer) – der Dienst meldet fremde Zugriffe auf gespeicherte Zugangsdaten (Browser, Steam, Discord, Telegram, Wallets) und ferngesteuerte Browser; Schalter `infostealer` |
| 14.11.2026 | Prozess-Funde zeigen „gestartet von: unbekannt“, wenn der startende Prozess nicht mehr ermittelbar ist |
| 14.11.2026 | Verknüpfung „K9-Dashboard“ auf dem Desktop und im Startmenü (von `dienst installieren`/`aktualisieren` angelegt, von `dienst deinstallieren` entfernt) |
| 14.11.2026 | Neuer Abschnitt „Dashboard wieder öffnen“ in den wichtigen Abläufen (Befehl, Startdatei, Lesezeichen, Zugangsschlüssel) |
| 14.11.2026 | Dienst-Protokoll vermerkt Beginn und Ende des Spielmodus („Spielmodus vom Agent: …“) |
| 14.11.2026 | `k9 dienst aktualisieren` zeigt auch den eingetragenen Datenordner des Dienstes (`C:\ProgramData\K9`) |
| 14.11.2026 | SVM bleibt dauerhaft an (VBS an, Speicherintegrität aus); Hinweis zum Trend-Micro-AMSI-Ereignis im Testbericht korrigiert (nicht VBS-bedingt) |
| 14.11.2026 | Härtung: Der Dienst nutzt als eigenen Datenordner nur noch `C:\ProgramData\K9` (unabhängig davon, ob `dienst aktualisieren` mit Adminrechten lief); der Spielmodus kommt über die Dienst-Pipe statt über eine Datei im Benutzerordner (damit wirkt die Update-Pause beim Spielen jetzt zuverlässig) |
| 14.11.2026 | Neue Aufgaben/Dienste, die ein Skript-Programm starten, heißen in der Meldung „startet ein Skript-Programm“ (Schwere Mittel); End-zu-End-Test hält fehlgeschlagene Prüfungen in `target\e2e-fehler.log` fest |
| 14.11.2026 | Sehr kurze Prozesse (`mshta`, `rundll32` mit Skriptcode) und neue Aufgaben mit `cmd.exe` ohne Pfad werden erkannt |
| 14.11.2026 | Signierte Aktualisierung eines bekannten Treibers (Windows Update, Grafiktreiber) ist keine Meldung mehr, nur ein Ereigniseintrag |
| 14.11.2026 | Nach dem Sandbox-Online-Test: Programmstarts mit `-EncodedCommand` (jede Abkürzung), `mshta`/`rundll32` mit Skriptcode und das Löschen von Schattenkopien werden erkannt; der Agent prüft nach dem Start die Dateien der letzten 24 Stunden, merkt sich Autostarts dauerhaft und meldet neue Aufgaben/Dienste, die Skript-Programme starten |
| 14.11.2026 | Funde des Dienstes bleiben bis zur Zustellung an den Agent gespeichert (gehen bei einem Neustart nicht verloren, keine doppelten Meldungen) |
| 14.11.2026 | Programme enthalten die C-Laufzeit selbst (kein Visual-C++-Paket nötig); Agent-Wache findet den Benutzer auch in Remotedesktop-/Sandbox-Sitzungen (nur derselbe Benutzer); erster Sandbox-Testlauf bestanden (Testbericht 7.2) |
| 14.11.2026 | Treiberprüfung: „Neuer Treiber“ nur noch für wirklich nie gesehene Treiber (dauerhaft gemerkt; kein Fehlalarm mehr, wenn ein Programm wie MSI Afterburner seinen Treiber erst nach der Anmeldung lädt); Autostart-Meldungen in HKLM werden auch ohne angemeldeten Benutzer erledigt |
| 14.11.2026 | Autostarts: echte Ordnerrechte unter `C:\ProgramData` statt Pauschalregel, „Signatur nicht prüfbar“ getrennt von „unsigniert“ (mit zweitem Versuch), Meldungen zu entfernten Autostart-Einträgen erledigen sich selbst |
| 14.11.2026 | Hinweis „Agent unerwartet beendet“ nicht mehr beim Neustart/Herunterfahren von Windows (30 s Wartezeit); Treiber-Meldungen werden alle 10 Minuten auf entfernte Treiber geprüft; Empfehlungstext passend zu den Schaltflächen (bereits deaktivierte Treiber) |
| 14.11.2026 | `treiber-aufraeumen.ps1` mit `-Satz` (`Verwaist`: GIGABYTE gdrv/gdrv3, Thrustmaster TmHid, inpoutx64, Colasoft; `Asus`: AsIO2/AsIO3/GLCKIO2/IOMap64 und die ASUS-Dienste asComSvc/AsusCertService; Treiber ohne Dienst: nur die Datei wird gesichert, nach Prüfung von Signatur und Prüfsumme): überspringt Treiber, deren Programm noch installiert ist oder die gerade geladen sind; eigener Sicherungsordner je Satz |
| 14.11.2026 | Treiber-Meldungen: erledigen sich nach dem Deinstallieren automatisch, Angaben werden bei jeder Prüfung aktualisiert; Dashboard/Meldefenster zeigen nur ausgefüllte Felder und die Quelle („Treiber · LOLDrivers (Hash)“), keine doppelt maskierten Zeichen mehr |
| 14.11.2026 | `k9 treiber`: Treiber mit Mustertexten aus dem Treiber-Entwicklungskit (z. B. gdrv.sys) werden über die digitale Signatur dem Hersteller zugeordnet; leere Versionsangaben werden ausgeblendet |
| 14.11.2026 | Neuer Abschnitt „Wichtige Abläufe“ am Anfang (Remote Control nach Neustart, Update, Treiberprüfung, Aufräum-Skript, Status) |
| 14.11.2026 | Skript `treiber-aufraeumen.ps1` (in `C:\Program Files\K9`) zum sicheren Entfernen verwaister Treiber (Creative CtiIo64, Corel PxHlpa64) in zwei Schritten: geschützte Sicherung mit Prüfsummen, Abbruch bei weiteren Verweisen oder ohne Wiederherstellungspunkt |
| 14.11.2026 | Treiberprüfung: `k9 treiber`, Quellen LOLDrivers und Microsoft-Sperrliste, Speicherintegritäts-Hinweis, Dienst prüft regelmäßig und meldet neue Treiber, „Treiber deaktivieren“ mit Bestätigung (nie Boot-/Systemtreiber) |
| 14.11.2026 | Härtung Stufe 3: Funde, Entscheidungen, Quarantäne-Liste und Protokoll in der Datenbank des Dienstes (`geschuetzt.db`), Agent liest nur; abschwächende Entscheidungen brauchen ein nicht fernsteuerbares Bestätigungsfenster; Zwischenpuffer mit Lückenerkennung |
| 14.11.2026 | `k9 quellen` meldet keinen fehlenden abuse.ch-Key mehr, wenn der Schlüssel beim Dienst liegt |
| 14.11.2026 | Härtung Stufe 2: Erkennungsdaten geschützt in `C:\ProgramData\K9\quellen`, Aktualisierung nur durch den Dienst (nie während eines Spiels), API-Schlüssel verschlüsselt beim Dienst; Sicherheitsprüfung aller Dienst-Eingaben (`docs\SICHERHEIT.md`): Dienst arbeitet in Benutzerordnern nur mit Benutzerrechten, Protokoll in `C:\ProgramData\K9\logs`, ClamAV nur aus `C:\Program Files` |
| 14.11.2026 | Browser-Hilfsprogramme (Native Messaging): registrierte und signierte Starts lösen keinen Fehlalarm mehr aus; neue Registrierungen werden gemeldet und können deaktiviert werden |
| 14.11.2026 | Härtung Stufe 1: Entscheidungen vom Dienst unterschrieben, Quarantäne geschützt in `C:\ProgramData\K9`, abschwächende Änderungen in `config.toml` erst nach Bestätigung |
| 13.11.2026 | Programme nach `C:\Program Files\K9` (`k9 dienst aktualisieren`), Dienst vertraut nur Programmen dort; kurze Prozesse mit Befehlszeile aus Kernel-Ereignissen; DNS-Funde nennen das fragende Programm; Dashboard springt nach einem Klick nicht mehr nach oben |
| 13.11.2026 | Externer Test (EICAR): eingebaute EICAR-Erkennung; riskante neue Dateien werden in Echtzeit auch mit ClamAV geprüft (`clamav`, `clamav_leerlauf_minuten`); `zusatz_ordner`; Testbericht in Kapitel 12 |
| 13.11.2026 | Schnellhilfe am Anfang; Agent läuft nur einmal (zweiter Start öffnet nur das Dashboard); Köderdatei-Alarm nur noch für die echten Köderdateien, Lesen löst nie Alarm aus; Dashboard: breitere Fundort-Spalte, lange Befehlszeilen mit „mehr anzeigen“, Schaltflächen untereinander |
| 13.11.2026 | Windows-Dienst (`k9 dienst …`): jeder Programmstart und jede DNS-Abfrage über ETW, Agent-Wache mit Selbstschutz-Hinweis, Aktionen mit Adminrechten nur für eigene Funde; `k9 agent-beenden` fragt nach Bestätigung (`--minuten`); Dashboard zeigt den Dienst-Status |
| 13.11.2026 | Programmstart-Funde: „Nur diesmal erlauben“, Freigabe nur für genau diese Befehlszeile, Windows-Systemdateien nie in Quarantäne/Löschen; ältere zu breite Prozess-Freigaben werden entfernt |
| 13.11.2026 | Schritt 3: Echtzeitschutz (Ordner, Programmstarts, Autostarts, Netzwerk, Ransomware mit Köderdateien, USB), Aktion „Prozess beenden“, `k9 autostart-agent`, `k9 agent-beenden`; leichte Prüfung während Spielen |
| 13.11.2026 | Erkennungsdaten-Übersicht: Dashboard-Kasten, `k9 quellen` (+ `--json`), Abschnitt in dieser PDF; echte ClamAV-Signaturanzahl; PDF wird nach jeder Quellen-Aktualisierung neu erzeugt |
| 13.11.2026 | Konsolenausgabe ohne Umlaute (ae/oe/ue/ss), Konsole auf UTF-8; diese PDF-Anleitung |
| 13.11.2026 | ClamAV-Grenzen (40 MB, 15 s je Datei) für schnellere Scans; signierte Dateien in Hashlisten als „vermutlich Fehleintrag“ markiert |
| 13.11.2026 | abuse.ch auf neue Download-Adressen (API v2) umgestellt; Schlüssel wird in Meldungen maskiert |
| 13.11.2026 | Schritt 2: YARA Forge, ClamAV, abuse.ch, OpenPhish, CISA KEV/NVD; Prüfungen Software, Phishing-Adressen, Autostarts; Scan-Cache |
| 13.11.2026 | Eigenes Meldefenster (Kanal `fenster`) mit Quarantäne/Löschen/Freigabe/Später |
| 13.11.2026 | Dashboard-Schaltflächen repariert („Ungültige Herkunft“) |
| 13.11.2026 | Startdatei „K9 starten.cmd“; ehrliche Meldung bei ausgeschalteten Windows-Benachrichtigungen |
| 13.11.2026 | Schritt 1: Agent, `k9`, Dashboard, Entscheidungen merken, Quarantäne, Gaming-Modus, Testsignatur |

