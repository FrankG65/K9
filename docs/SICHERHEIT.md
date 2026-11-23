# K9 – Sicherheitsprüfung des Windows-Dienstes

Stand: 14.11.2026 (Härtung Stufe 3)

Der Dienst „K9-Dienst“ läuft als **LocalSystem**. Alles, was ein Programm mit normalen
Benutzerrechten verändern kann, gilt für ihn als **nicht vertrauenswürdig**. Ein Schadprogramm mit
deinen Rechten darf über den Dienst nie mehr erreichen als ohne ihn.

## Grundregeln

1. **Ausführen und Laden nur aus geschützten Ordnern.** Programme startet der Dienst nur aus
   `C:\Program Files\…` bzw. `C:\Windows\System32`. DLLs lädt er nur aus System32 und seinem
   Programmordner (`SetDefaultDllDirectories`, aktuelles Verzeichnis entfernt).
2. **In Benutzerordnern nur mit Benutzerrechten.** Jede Anfrage über die Pipe läuft mit den Rechten
   des Aufrufers (`ImpersonateNamedPipeClient`). Hintergrundarbeiten in deinen Ordnern laufen mit
   deinem Anmelde-Token (`WTSQueryUserToken`). Systemrechte gibt es nur für die eigenen geschützten
   Ordner (`as_system`). Eine Umleitung (Junction, Symlink, Hardlink) in deinem Ordner kann den
   Dienst deshalb nicht in Systemordner lenken. Ohne Benutzer-Token bricht ein Zugriff auf
   Benutzerpfade ab (`ensure_user_context`).
3. **Eigene Daten nur in `C:\ProgramData\K9`** (Besitzer SYSTEM, Benutzer nur Lesen bzw.
   gar kein Zugriff): Protokoll, temporäre Dateien, Schlüssel, Quarantäne, Erkennungsdaten,
   bestätigte Einstellungen.
4. **Werte aus der Datenbank sind nur Hinweise.** Für Aktionen mit Systemrechten nutzt der Dienst
   ausschließlich die Werte, die er selbst gemeldet und im Speicher behalten hat.

## Prüftabelle

| Eingabe (von Benutzerprogrammen änderbar) | Verwendung im Dienst | Risiko vorher | Maßnahme |
|---|---|---|---|
| `config.toml` → `clamav_programmordner` | Pfad von `freshclam.exe` | **Code mit Systemrechten** (eigenes Programm eintragen) | Dienst startet freshclam nur unter `%ProgramFiles%` (`is_under_program_files`) |
| `config.toml` → `quellen.ordner` | Ordner der Erkennungsdaten | Dienst schreibt in beliebigen Ordner | Dienst nutzt immer `C:\ProgramData\K9\quellen`, die Einstellung wird ignoriert |
| `config.toml` → `yara_paket` | Teil der Download-Adresse | Fremde Adresse | Nur feste Werte (`core`/`extended`/`full`), Adressen sind fest im Programm |
| `config.toml` (ganze Datei) | Einstellungen, Sicherheitsprüfung | Dienst legte die Datei als SYSTEM an; Fehlermeldungen mit Dateiinhalt | Nur lesen, mit Benutzerrechten; nie anlegen oder schreiben; fehlerhaft → Standardwerte |
| `config.toml` → Schutzschalter und Listen | Abschalten von Prüfungen, Ausnahmen, Spiele-Listen | Schadprogramm mit Benutzerrechten schaltet den Schutz ab | Eine Regeltabelle (`schutz::SCHALTER`/`LISTEN`, Unit-Test: jeder Schalter eingeordnet) für Dienst, Agent und k9; Abschwächung gilt erst nach Bestätigung im Bestätigungsfenster, auch beim Dienststart; Verschärfung wird sofort bestätigter Stand; bestätigter Stand nur aus einer Datei, die SYSTEM/Administratoren gehört, ohne Änderungsrechte für andere und ohne Verknüpfungspunkt |
| Dienst-Schlüssel (VirusTotal, abuse.ch, NVD) | API-Schlüssel | Ungültiger Schlüssel schaltet Abfragen still ab | Erster Schlüssel ohne Rückfrage, Ersetzen/Löschen nur nach Bestätigung |
| `%LOCALAPPDATA%\K9\logs` | Dienst-Protokoll | **Datei schreiben in beliebigen Ordner** (Junction auf `C:\Windows\System32`) | Protokoll nach `C:\ProgramData\K9\logs` |
| `%TEMP%` (des Benutzers) | Temporäre Dateien bei Downloads | wie oben | Dienst-TEMP = `C:\ProgramData\K9\temp` (nur SYSTEM/Admins) |
| Datenbank `k9.db` (Benutzerordner) | Funde, Entscheidungen, Quarantäne-Liste | Schreiben als SYSTEM über Umleitung; gefälschte Pfade | Zugriff nur mit Benutzerrechten; `trusted_schema=OFF`; Entscheidungen nur mit Dienst-Unterschrift gültig. Stufe 3 verlegt die Datenbank ganz in den Dienst |
| Quarantäne-Liste → `stored_file` | Wiederherstellen liest diese Datei mit Systemrechten | **Beliebige Datei lesen** (z. B. Registry-Hives) | Nur normale Datei *im* geschützten Quarantäne-Ordner, ohne Umleitung, Pfad aufgelöst (`safe_inside`) |
| Quarantäne-Liste → `original_path` / Ziel | Wiederherstellen schreibt dorthin | **Beliebige Datei schreiben** (z. B. DLL in System32) | Schreiben nur mit Benutzerrechten |
| Fund → Dateipfad | In Quarantäne verschieben, Löschen | **Beliebige Datei löschen/lesen** | Lesen und Löschen nur mit Benutzerrechten; nur das Schreiben in die geschützte Quarantäne mit Systemrechten |
| Fund → Prozess-ID / Programm | „Prozess beenden“ | **Beliebigen Prozess beenden** (z. B. Trend Micro) | Funde des Agents: mit Benutzerrechten. Funde des Dienstes: mit Systemrechten, aber nur mit PID und Programmpfad aus dem Speicher des Dienstes, Programmpfad wird vorher geprüft |
| Fund → Autostart-Details | Deaktivieren/Reaktivieren (Dienste, Run-Schlüssel) | Fremde Dienste abschalten | Nur mit Benutzerrechten (HKLM/Dienste sind dann nicht änderbar) |
| Quarantäne-Migration (alter Benutzerordner) | Kopieren und Löschen | Umleitung → Systemdateien lesen/löschen | Lesen und Löschen mit Benutzerrechten, nur `*.vsq`-Dateien im alten Ordner |
| Erkennungsdaten-Migration | Kopieren in den geschützten Ordner | Umleitung → Systemdateien in lesbaren Ordner kopieren | Lesen mit Benutzerrechten, Umleitungen werden übersprungen, Zwischenordner, erst nach vollständiger Kopie aktiv |
| Spielmodus (Agent) | Aktualisierung/Treiberprüfung verschieben | Updates unterdrücken | Kommt über die Pipe (`Spielmodus`), nur vom installierten Agent angenommen; nach 5 Minuten ohne neue Meldung ungültig. Keine Datei im Benutzerordner mehr. Folge höchstens: spätere Aktualisierung |
| `HKLM\SOFTWARE\K9` → `Datenordner` | Eigener Datenordner des Dienstes | Dienst arbeitet in einem Benutzerordner (je nach Aufruf von `dienst aktualisieren` mit/ohne Adminrechte) | Der Dienst nimmt nur `C:\ProgramData\K9` an (Pfad aufgelöst, keine Verbindungspunkte/Links); sonst Warnung und trotzdem der geschützte Ordner. Der Installer trägt immer diesen Ordner ein. Der Benutzerordner wird nur für die einmalige Übernahme gelesen, mit Benutzerrechten |
| Manipulationsalarm | Schutz wird abgeschaltet oder ausgetauscht | Fehlalarme bei eigenen Aktualisierungen und beim Herunterfahren; Angreifer stoppt den Dienst, tauscht eine Datei und startet ihn neu | Ausgangsstand (Prüfsummen) in der geschützten Datenbank, geschrieben **nur** von `k9 dienst aktualisieren` mit Administratorrechten, nie von einem Dienststart; Vergleich bei jedem Start und alle 10 Minuten; ein Neustart außerhalb von Windows-Start und Aktualisierung wird gemeldet (Mittel); „Dienst läuft nicht“ erst nach 2 Minuten und nicht beim Herunterfahren; nur melden, nie reparieren. **Grenze:** Ein Angreifer mit Administratorrechten kann den Aktualisierungsweg selbst benutzen (eigene Dateien „aktualisieren“) oder die geschützte Datenbank ändern; ohne Code-Signatur der Programme lässt sich das nicht vollständig verhindern. Bei der ersten Installation gilt der beim ersten Dienststart vorgefundene Stand. |
| Angriffsketten (Dienst) | Eine kritische Meldung statt vieler einzelner | Fehlalarme bei Installationsprogrammen; Verwechslung durch neu vergebene Prozess-IDs | Kette nur ab unsigniertem Programm aus dem Internet; Mitglieder über Prozess-ID **und** Startzeit; nur 30 Minuten; Skript-Programm allein meldet nichts; nur Buchführung im Speicher, keine Eingriffe |
| Anhalten kritischer Programme (aus) | Schaden stoppen, bevor du entscheidest | Harmloses Programm eingefroren; Spiel oder Anti-Cheat angehalten (Kontosperre); neu vergebene Prozess-ID | Nur Kritisch-Funde vom Typ Prozess; Prozess-ID, Startzeit und Pfad geprüft; nie Spiele, Anti-Cheat, Windows-Ordner, Microsoft-/Trend-Micro-Signatur, K9; nur anhalten, nie beenden, nie automatisch fortsetzen; Fortsetzen über den Dienst nur für denselben Prozess |
| VirusTotal (aus) | Zweitmeinung zu neuen Programmen | Datenschutz (Prüfsumme an Google); Schlüssel | Nur SHA-256, nie die Datei; Schlüssel nur im geschützten Speicher des Dienstes, nur im Kopf der HTTPS-Anfrage; 4/min, 500/Tag; 7 Tage Zwischenspeicher. Echte Schlüssel nur über die unsichtbare Eingabe von `k9 geheimnis`; `--aus-eingabe` nur für Tests – bei vollständiger PowerShell-Protokollierung stünde ein per Befehl/Skript übergebener Schlüssel im Klartext im Ereignisprotokoll |
| Schattenkopien (aus) | Rückweg nach Ransomware | Plattenplatz; Konflikt mit der Regel „Schattenkopien löschen“ | Nur anlegen, nie löschen, Speichergröße nie ändern (Windows rotiert selbst); nur im Leerlauf, nie im Spiel |
| Firewall-Sperre (aus) | Verbindungen zu Botnetz-Steuerservern verhindern | Sperre harmloser geteilter Server; Sperre im Heimnetz; zu viele Regeln | Nur Feodo-Empfehlung und ThreatFox „botnet_cc“ mit Sicherheit 100, ≤ 30 Tage; nur öffentliche IPv4; genau Adresse und Port; höchstens 1000; nur Regeln mit eigenem Namen, jederzeit entfernbar; nie im Spiel aktualisiert |
| Herkunftsvermerk (Zone.Identifier) beim Programmstart | Meldung „unsigniertes Programm aus dem Internet“ | manipulierter Vermerk; Zugangsschlüssel in Download-Adressen | Nur den kleinen Datenstrom lesen (höchstens 64 KB), nie ändern; Adresse ohne Teil nach „?“/„#“; Signatur per WinVerifyTrust; jede Programmdatei nur einmal geprüft |
| ETW Microsoft-Windows-PowerShell (Ereignis 4104, Skriptblöcke) | Meldung „verdächtiges Skript“ | Skripte enthalten Passwörter; Fehlalarme bei Admin-Skripten; Täuschung des Programms über die Befehlszeile | Skript nur im Speicher geprüft, gespeichert nur Regel, SHA-256 und gekürzter Ausschnitt mit maskierten Zeichenketten und Kodierungen; Teile höchstens 1 MB; Programm nur aus Kernel-Angaben; Freigabe nur für genau dieses Skript; die Windows-Richtlinie setzt nur der Nutzer selbst (`k9 powershell-protokoll`) |
| ETW Kernel-File (Dateizugriffe auf Zugangsdaten) | Meldung „Datendieb“ | Fehlalarme gegen echte Programme; Flut; Umgehung durch Groß-/Kleinschreibung oder gefälschte Befehlszeile; wiederverwendete Prozess-IDs | Alle Dateiöffnungen ohne Kernel-Filter (der verglich in der Sandbox mit Beachtung der Schreibweise), Auswahl im Dienst ohne Rücksicht auf Groß-/Kleinschreibung; Programm nur aus Kernel-Angaben (Kernel-Process-Bildpfad, laufender Prozess mit passender Startzeit), Lebensläufe je Prozess-ID mit Start/Ende, sonst „Programm nicht sicher zuzuordnen“; Nur Text (Pfad, PID); Eigentümer nur mit gültiger Hersteller-Signatur **und** Herstellerordner; Windows-Bestandteile nur namentlich mit Microsoft-Signatur und festem Ordner (nie pauschal „von Microsoft signiert“: PowerShell, cmd, esentutl usw. bleiben meldepflichtig); höchstens eine Meldung je Programm und Speicher in 10 Minuten; Freigabe nur für genau Programm + Speicher + Signatur bzw. Prüfsumme |
| Browser-Einstellungen, Erweiterungs-Manifeste, Richtlinien, Verknüpfungen | Inventar und Bewertung der Erweiterungen | Manipulierte JSON-Dateien | Nur lesen (Agent, Benutzerrechte), nie schreiben; JSON nur als Daten; Erweiterungen werden nie entfernt oder abgeschaltet |
| MalExt-Liste (Download) | Schad-Erweiterungen erkennen | Manipulierte Liste | Nur HTTPS, feste Adresse; nur gültige IDs; unter 100 Einträgen verworfen; Aktualisierung nur durch den Dienst in den geschützten Ordner |
| Phishing-Liste „phishing-filter“ (Download) | Phishing-Domains erkennen | Manipulierte Liste, Eintrag für eine ganze Endung (Fehlalarm-Flut) | Nur HTTPS, feste Adresse; nur gültige Hostnamen; öffentliche Endungen (Public Suffix List, mitgeliefert) werden verworfen, auch beim Laden; unter 1.000 Einträgen verworfen; Schwere nur Mittel; Aktualisierung nur durch den Dienst |
| Prüfung auf ähnliche Domains | Nachahmer-Domains melden | Fehlalarme, Rechenlast bei vielen DNS-Abfragen | Nur Namen vor der Endung; offizielle Domains als Liste; Tippfehler nur bei langen Namen; gegen 1 Mio. Tranco-Domains getestet; jeder Name wird nur einmal geprüft (Zwischenspeicher bis 20.000 Namen; Dienst mit niedriger Priorität) |
| Pipe-Nachrichten | Alle Befehle | Fremde Befehle | ACL (SYSTEM, Admins, der eingerichtete Benutzer), Version, Größen, feste Aktionsliste; Aufrufer muss Agent/k9 aus `C:\Program Files\K9` sein; Ausführung mit Rechten des Aufrufers |
| Pipe → `GeheimnisSetzen` | API-Schlüssel speichern | Schlüssel überschreiben | Nur von `k9.exe` aus `C:\Program Files`, nur zwei bekannte Namen, Größe begrenzt |
| API-Schlüssel | Downloads abuse.ch/NVD | Diebstahl aus der Anmeldeinformationsverwaltung | Dienst-Kopie mit DPAPI (SYSTEM) in `…\geheim`; die abuse.ch-Kopie beim Benutzer wird entfernt. Der NVD-Schlüssel bleibt zusätzlich beim Benutzer (die Software-Prüfung des Agents braucht ihn, geringer Wert) |
| Downloads (YARA Forge, abuse.ch, OpenPhish, CISA, NVD, ClamAV) | Erkennungsdaten | Manipulierte Daten | Nur HTTPS mit festen Adressen; YARA Forge mit Prüfsumme; ClamAV prüft Signaturen selbst (freshclam); Verarbeitung speichersicher (Rust, yara-x) |
| ETW-Ereignisse (Prozessnamen, Befehlszeilen, DNS-Namen) | Prüfregeln, Fundtexte | – | Nur Text, wird nie ausgeführt |
| Umgebungsvariablen | Ordnerpfade | – | Werden beim Start aus `HKLM\SOFTWARE\K9` (nur Admins schreibbar) gesetzt; `SystemRoot` stammt vom Dienststeuerungs-Manager |
| `HKLM\SOFTWARE\K9` → Agentpfad | Agent starten | Fremdes Programm | Nur Admins schreibbar; zusätzlich muss der Pfad in `C:\Program Files\K9` liegen; Start immer mit dem Token des Benutzers (nie SYSTEM) |
| Agent-Neustart | `conhost.exe` | – | Aus `%SystemRoot%\System32`, Token des Benutzers |

## Stufe 3: Datenbank beim Dienst, Bestätigungsfenster

| Thema | Umsetzung |
|---|---|
| Funde, Entscheidungen, Quarantäne-Liste, Ereignisse, deaktivierte Autostarts | liegen in `C:\ProgramData\K9\geschuetzt.db` (Besitzer SYSTEM, Benutzer nur Lesen). Agent und k9 hängen sie schreibgeschützt an; ihre alten Kopien werden in `alt_*` umbenannt und nicht mehr benutzt |
| Neue Funde | gehen über die Pipe an den Dienst; der Dienst prüft Entscheidungen und speichert. Ein Programm mit deinen Rechten kann einen Fund dort nicht löschen oder als erledigt markieren |
| Dienst nicht erreichbar | Funde werden im Benutzerordner mit fortlaufender Nummer zwischengespeichert und später nachgeliefert. Fehlen Nummern, meldet der Dienst „Zwischengespeicherte Funde sind verschwunden“ |
| Entscheidungen | führt der Dienst aus (Quarantäne, Löschen, Beenden mit deinen Rechten), er merkt und unterschreibt sie |
| Abschwächende Entscheidungen (Freigabe, Nur diesmal, Gesehen/Ignorieren, Wiederherstellen, Autostart wieder einschalten, Einstellung übernehmen, Agent pausieren) | brauchen ein **Bestätigungsfenster**, das der Dienst mit deinem *erhöhten* Token in deiner Sitzung startet (`k9.exe bestaetigen` aus `C:\Program Files\K9`). Programme mit normalen Rechten können es nicht bedienen (Windows UIPI). Das Fenster zeigt nur festen Text aus der Datenbank des Dienstes (Bedrohung, Fundort, Regel, Aktion) und „Ja“/„Nein“ (vorausgewählt: Nein), keine Links, keine Hilfe, keine Datei-Dialoge. Ohne Antwort nach 2 Minuten gilt „Nein“ |
| HKCU im Dienst | Unter Impersonation öffnet der Dienst den Registry-Zweig des Benutzers (`RegOpenCurrentUser`), nicht den von SYSTEM |

## Bleibende Grenzen

- **Aufruferprüfung über den Programmpfad:** Ein Programm mit deinen Rechten könnte sich in den
  laufenden Agent einklinken (gleicher Benutzer). Ohne Treiber gibt es dagegen keinen vollständigen
  Schutz. Abschwächende Entscheidungen brauchen aber das Bestätigungsfenster, und alles andere läuft
  mit deinen eigenen Rechten.
- **Bestätigungsfenster ohne Administratorkonto:** Ist der Benutzer kein Administrator, gibt es kein
  erhöhtes Token, und das Fenster läuft mit normalen Rechten (dann ohne UIPI-Schutz). Auf diesem PC
  ist der Benutzer Administrator.
- **Lokale Zwischenpuffer** (Meldefenster-Warteschlange, Scan-Cache, Zeitplan-Stand) bleiben im
  Benutzerordner. Ein Programm kann dort höchstens ein Meldefenster verzögern; der Fund bleibt beim
  Dienst offen und erscheint im Dashboard.

## Tests

- Gefälschte bzw. nachträglich geänderte Freigabe wird ignoriert (`self_made_allowance_without_signature_is_ignored`).
- Nur Programme in `C:\Program Files\K9` gelten als vertrauenswürdig (`only_programs_in_program_files_are_trusted`).
- Agent kann die Dienst-Datenbank nur lesen, Übernahme alter Daten, Umbenennung der alten Kopien
  (`service_database_is_read_only_for_the_agent_and_takes_over_old_data`).
- Lücken in der Nummernfolge zwischengespeicherter Funde werden erkannt (`sequence_gaps_are_detected`).
- Text im Bestätigungsfenster kann die Befehlszeile nicht verlassen (`text_cannot_break_out_of_the_command_line`).
- Unit-Tests und portable Agents lesen nie `C:\ProgramData\K9` und sprechen nie mit dem
  installierten Dienst. Testdateien liegen nie in `%TEMP%`.
