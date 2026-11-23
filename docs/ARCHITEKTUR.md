# Architektur

Stand: Version 0.50.1 (23.11.2026). Die Modultabellen stammen aus den einzeiligen Beschreibungen
am Anfang jeder Quelldatei.

## Überblick

K9 besteht aus drei Programmen, die installiert werden, und vier Hilfs-Crates.

```
crates/
  k9-core/     Bibliothek – die gesamte Erkennungs- und Entscheidungslogik
  k9-dienst/   Windows-Dienst „K9-Dienst“ (LocalSystem)
  k9-agent/    Agent im Benutzerkonto (Dashboard, Meldefenster, Zeitpläne)
  k9-cli/      Kommandozeile „k9“
  k9-doc/      Hilfsprogramm: wandelt die Anleitung (Markdown) in druckfertiges HTML für die PDF
  k9-res/      Build-Helfer: bettet das Programmsymbol als Windows-Ressource ein
  k9-testsim/  Testwerkzeug, wird nie installiert: verhält sich an Schein-Dateien wie Ransomware
scripts/       End-zu-End-Test, PDF-Erzeugung, Tests in der Windows-Sandbox
```

Sprache: **Rust** (Speichersicherheit, keine Laufzeitumgebung, sehr geringer Ressourcenbedarf).
Die C-Laufzeit ist statisch eingebunden. Die Abhängigkeiten sind verbreitete, gepflegte Crates
(`windows`, `tokio`, `axum`, `rusqlite` mit eingebautem SQLite, `yara-x`, `sha2`, `serde`/`toml`,
`lettre` und `reqwest` mit rustls, `keyring`, `tracing`, `chrono`). `cargo audit` gehört zur
Prüfkette vor jedem Commit.

### Wer macht was

| Programm | Läuft als | Aufgabe |
|---|---|---|
| `k9-dienst.exe` | LocalSystem | Sieht, was ein normaler Benutzer nicht sieht: jeden Programmstart, jede DNS-Abfrage und jeden Zugriff auf gespeicherte Zugangsdaten über die Ereignisverfolgung von Windows (ETW). Führt die geschützte Datenbank der Erkennungen und Entscheidungen, unterschreibt Entscheidungen, zeigt das Bestätigungsfenster für alles, was den Schutz schwächt, und wacht über den Agent und die eigenen Dateien. |
| `k9-agent.exe` | angemeldeter Benutzer | Echtzeitprüfung neuer Dateien, Zeitpläne, Spielerkennung, Meldefenster, Symbol im Infobereich, Dashboard unter `127.0.0.1`. Nimmt die Funde des Dienstes entgegen und reicht die Entscheidungen des Nutzers weiter. |
| `k9.exe` | angemeldeter Benutzer (fragt nur zum Einrichten, Aktualisieren und Entfernen des Dienstes nach Administratorrechten) | Scans, Entscheidungen, Quellen, Funktionsschalter, Zurückholen von Dateien aus Schattenkopien. |

Die Aufteilung folgt einer Regel: **Ein Programm mit den Rechten des Benutzers darf über den
Dienst nie mehr erreichen als ohne ihn.** Der Dienst behandelt alles, was ein normaler Benutzer
ändern kann, als nicht vertrauenswürdig (siehe [SICHERHEIT.md](SICHERHEIT.md)).

### Wo die Daten liegen

| Ort | Inhalt | Wer schreiben darf |
|---|---|---|
| `C:\Program Files\K9` | die drei Programme | Administratoren |
| `C:\ProgramData\K9` | geschützte Datenbank (Erkennungen, Entscheidungen, Quarantäne-Liste), Quarantäne, Erkennungsdaten, Protokoll des Dienstes, Ausgangsstand der Programmdateien | der Dienst |
| `%APPDATA%\K9\config.toml` | Konfiguration | der Benutzer; Änderungen, die den Schutz schwächen, gelten erst nach Bestätigung |
| `%LOCALAPPDATA%\K9` | eigene Buchführung des Agents, Protokoll des Agents, Bericht des Sicherheits-Checks | der Benutzer |
| Windows-Anmeldeinformationsverwaltung | Schlüssel und Passwörter (Dashboard-Schlüssel, abuse.ch, NVD, SMTP, ntfy) | der Benutzer |

## Datenfluss

```
 Dateiprüfungen (Agent, k9)         Verhalten (Dienst, über ETW)
 Zeitplan / k9 scan / Dashboard     Programmstarts, DNS, Zugangsdaten,
 neue Dateien, USB-Datenträger      Skripte, Ransomware, Treiber, Konten
            │                                   │
            ▼                                   ▼
   Scanner liest jede Datei einmal     Regeln, Ketten, Sigma (auf Wunsch)
   → Engines: Hashlisten, Muster,               │
     YARA-X, ClamAV, Adresslisten               │
            └───────────────┬───────────────────┘
                            ▼
      Fund { Art, Pfad, Fingerabdruck, Regel-ID, Name, Schwere, Details }
                            ▼
        leise? (Arbeitsordner / Arbeitsprogramm, bekannte Nebenwirkung eines Updates)
                            ▼
        gemerkte Entscheidung für (Fingerabdruck, Regel-ID), vom Dienst unterschrieben?
           ├─ Freigabe      → still ignoriert (als „automatisch“ vermerkt)
           ├─ Quarantäne    → still erneut angewendet + Protokolleintrag
           ├─ Löschen       → still erneut angewendet + Protokolleintrag
           └─ keine         → als offen gespeichert
                                 │  (schon offen? → keine zweite Meldung)
                                 ▼
                    Läuft ein Spiel?
                      ├─ ja   → in die Warteschlange; Zustellung nach dem Spiel
                      │         (kritische Alarme kommen durch)
                      └─ nein → Meldefenster, Dashboard, auf Wunsch E-Mail / Handy
                                 ▼
             der Nutzer entscheidet (Meldefenster, Dashboard oder `k9 entscheiden`)
                                 ▼
          Entscheidungen, die den Schutz schwächen: Bestätigungsfenster des Dienstes
                                 ▼
          Aktion wird ausgeführt (nur wenn die Datei noch dieselbe SHA-256 hat)
          und gemerkt → derselbe Fund meldet sich nie wieder
```

**Fingerabdrücke.** Eine Datei wird durch ihre SHA-256 und die Regel-ID bestimmt, ein Prozessfund
durch Regel, Elternprogramm und Befehlszeile, Software durch Name, Version und die Liste der CVE,
ein Autostart durch Eintrag und Ziel. Eine Entscheidung gilt deshalb für genau einen Fall. Die
eine Ausnahme ist gewollt und wird vom Nutzer gewählt: Eine Regel lässt sich für alles freigeben,
was ein signiertes Arbeitsprogramm startet (siehe Anleitung, Kapitel „Arbeitsordner“).

**Widerruf.** Eine widerrufene Entscheidung wird gelöscht; beim nächsten Fund wird wieder gefragt.
Das Wiederherstellen aus der Quarantäne entfernt die Quarantäne-Entscheidung (sonst würde die Datei
beim nächsten Scan still wieder verschoben).

**Agent und Dienst** sprechen über zwei benannte Pipes: Eine bringt die Funde des Dienstes zum
Agent, die andere die Anfragen von Agent und `k9` zum Dienst. Der Agent hängt die Datenbank des
Dienstes schreibgeschützt an. Die Aufrufer der Anfrage-Pipe werden geprüft: Angenommen werden nur
die eigenen Programme aus dem Installationsordner.

## Module in `k9-core`

### Grundlagen

| Modul | Aufgabe |
|---|---|
| `app` | gemeinsamer Start für Agent und k9: Pfade, Konfiguration, Datenbank, Engines |
| `paths` | Lage der Konfigurations- und Datenordner |
| `config` | Konfiguration (`config.toml`), kommentierte Standarddatei |
| `funktion` | `k9 funktion`: einzelne Funktionen ein- und ausschalten, ohne die Datei zu beschädigen |
| `model` | Datenmodell der Erkennungen, Aktionen und Arten |
| `store` | SQLite: Erkennungen, Entscheidungen, Quarantäne-Liste, Protokoll, Warteschlangen |
| `pipeline` | Fund → gemerkte Entscheidung → still anwenden oder als offen speichern; Entscheidung anwenden |
| `schutz` | Schutz sicherheitsrelevanter Zustände vor Programmen mit Benutzerrechten (unterschriebene Entscheidungen, bestätigte Einstellungen) |
| `dienst` | gemeinsame Teile für Dienst, Agent und k9 (Pipe-Protokoll) |
| `secrets` | Geheimnisse in der Windows-Anmeldeinformationsverwaltung |
| `term` | Konsolenausgabe ohne Umlaute |
| `sprache` | Sprache aller Texte (Deutsch oder Englisch, Einstellung `sprache`), Makros `t!`/`tf!`/`tw!`; Fingerabdrücke von Meldungen bleiben sprachunabhängig |
| `winreg` | kleine Registrierungs-Hilfsfunktionen |
| `priority` | niedrige Priorität, damit Prüfungen nie mit Spielen konkurrieren |
| `gaming` | Spielerkennung und Leerlaufzeit |
| `schedule` | Zeitpläne: sofort, ständig, täglich, wöchentlich, einmalig, Leerlauf |
| `umzug` | Umstellung vom alten Namen („Virenscanner“) auf K9 |

### Dateiprüfung

| Modul | Aufgabe |
|---|---|
| `scanner` | liest jede Datei einmal in Blöcken, bildet die SHA-256, füttert alle Engines |
| `engine` | Engine-Schnittstelle, Hashlisten- und Bytemuster-Engine, eigene Testsignatur |
| `yara` | YARA-Engine (yara-x, reines Rust), Regeln aus YARA Forge |
| `clamav` | das offizielle ClamAV für Windows (clamd + freshclam), nur lokal |
| `sources` | Erkennungsquellen: Signaturen, Regeln und Listen laden, prüfen und speichern |
| `sperrlisten` | zwei große, wählbare Sperrlisten für die Netzwerkprüfung |
| `quarantine` | verschleierte Quarantäne mit Prüfsummenkontrolle, Wiederherstellen, Löschen |
| `herkunft` | Herkunft geladener Dateien („Mark of the Web“) |
| `virustotal` | wählbare Abfrage der SHA-256 eines Programms (nichts wird hochgeladen) |

### Verhalten

| Modul | Aufgabe |
|---|---|
| `realtime` | Bausteine des Echtzeitschutzes im Benutzermodus: Ordnerüberwachung, Prozess-, Netzwerk- und DNS-Abfragen, Ransomware-Heuristik, Anhalten und Beenden von Prozessen |
| `ransom` | Ransomware-Erkennung im Dienst: Wer hat die Dateien geschrieben, die plötzlich verschlüsselt aussehen |
| `anhalten` | ein verdächtiges Programm anhalten, bis der Nutzer entscheidet (wählbar) |
| `ketten` | Angriffsketten: Einzelne Schritte sind oft harmlos, zusammen nicht |
| `skripte` | PowerShell-Skriptblöcke, geprüft vor dem Ausführen |
| `sigma` | Sigma-Regeln (SigmaHQ) für Programmstarts, wählbar |
| `infostealer` | welche Dateien Zugangsdaten enthalten und wer sie öffnen darf |
| `speicher` | Speicher-Scan im Leerlauf, wählbar |
| `arbeitsordner` | Arbeitsordner und Arbeitsprogramme: Verhaltensmeldungen von dort kommen leise |
| `sofort` | Wecksignale von Windows statt regelmäßigem Nachsehen |

### Bestand und Systemzustand

| Modul | Aufgabe |
|---|---|
| `autostart` | Run-Einträge, Autostart-Ordner, geplante Aufgaben, Dienste; Signaturprüfung; Deaktivieren und Reaktivieren |
| `wmi_autostart` | versteckte Autostarts über WMI |
| `nativehost` | Hilfsprogramme von Browser-Erweiterungen („Native Messaging“) |
| `erweiterungen` | Browser-Erweiterungen: Bestand, Richtlinien, bekannte Schad-Erweiterungen |
| `treiber` | Kerneltreiber: Bestand, verwundbare und bösartige Treiber, Eignung für die Speicherintegrität |
| `software` | installierte Programme gegen aktiv ausgenutzte Lücken; veraltete Programme (winget) |
| `luecken` | neue Sicherheitslücken (CVE) installierter Programme, mit EPSS |
| `nachladen` | Installationsprogramm von der offiziellen Seite laden, wenn winget es nicht kann, mit Prüfung auf denselben Hersteller |
| `anmeldungen` | Konten und Anmeldungen aus dem Sicherheitsprotokoll |
| `eingang` | Wache über eingehende Firewall-Regeln |
| `firewall` | bekannte Botnetz-Steuerserver in der Windows-Firewall sperren (wählbar) |
| `heimnetz` | neue Geräte im Heimnetz |
| `urls` | Schad- und Phishing-Adressen: Dateien, Browserverlauf (aus einer Kopie), hosts-Datei |
| `phishing` | Nachahmer-Domains bekannter Marken |
| `sicherheit` | der Sicherheits-Check: Ampel für den Grundschutz des PCs |
| `basis` | Ausgangsstand der installierten Programmdateien für den Manipulationsalarm |
| `wiederherstellung` | Dateien nach einem Ransomware-Angriff aus einer Schattenkopie zurückholen |

### Meldungen

| Modul | Aufgabe |
|---|---|
| `notify` | Kanäle: Meldefenster, Popup, Dashboard, E-Mail, Handy (ntfy); Warteschlange während eines Spiels |
| `window` | das eigene Meldefenster (nativer TaskDialog) |
| `wochenbericht` | Zusammenfassung einmal pro Woche |
| `verknuepfung` | Verknüpfungen zum Dashboard |

## Module in `k9-dienst`

| Modul | Aufgabe |
|---|---|
| `main` | Einstieg des Dienstes; lehnt Stopp-Befehle ab, die `k9` nicht angekündigt hat |
| `etw` | ETW-Sitzung: Programmstarts, DNS-Abfragen, PowerShell-Skriptblöcke, Zugriffe auf Zugangsdaten |
| `server` | die beiden benannten Pipes: Funde zum Agent, Anfragen von Agent und `k9` |
| `bestaetigung` | Bestätigungsfenster für Entscheidungen, die den Schutz schwächen |
| `einstellungen` | wacht über die Sicherheitseinstellungen in `config.toml`; Abschwächungen warten auf Bestätigung |
| `selbstschutz` | Manipulationsalarm: Programmdateien verändert, Dienst gestoppt, Ereignisverfolgung von außen beendet |
| `wache` | hält den Agent in der Sitzung des Benutzers am Laufen |
| `ransom_wache` | Ransomware-Erkennung über den Dokumentordnern |
| `treiber_wache` | Treiberprüfung alle 6 Stunden und wenn ein Treiber dazukommt |
| `konten_wache` | Konten und Anmeldungen |
| `eingang_wache` | eingehende Firewall-Regeln |
| `wmi_wache` | versteckte WMI-Autostarts |
| `aufraeumen` | schließt Meldungen, deren Ursache verschwunden ist |
| `quellen` | Erkennungsdaten im geschützten Ordner |
| `sperre` | Firewall-Sperre (wählbar) |
| `schattenkopie` | Schattenkopien als Rückweg nach Ransomware (wählbar) |
| `vt` | VirusTotal-Abfragen (wählbar) |
| `stoerungen` | meldet, wenn etwas ausfällt, worauf K9 sich stützt: eine Quelle, ClamAV, eine geplante Arbeit |

## Module in `k9-agent`

| Modul | Aufgabe |
|---|---|
| `main` | Einstieg des Agents |
| `scheduler` | Schleife: Spielerkennung, fällige Zeitpläne, wartende Meldungen |
| `realtime` | Echtzeitschutz in der Sitzung des Benutzers (neue Dateien, Programme, Autostarts, Netzwerk, USB-Datenträger) |
| `dienst_client` | Verbindung zum Dienst: nimmt dessen Funde entgegen |
| `dashboard` | lokales Dashboard im Browser (nur `127.0.0.1`) |
| `pflege` | Hintergrundarbeiten, solange kein Spiel läuft: Sicherheits-Check, Heimnetz, Wochenbericht, neue Sicherheitslücken |
| `tray` | Symbol im Infobereich |

## Quarantäne

Die Datei wird blockweise gelesen, mit einem zufälligen 32-Byte-Schlüssel (je Datei, in der
Datenbank gespeichert) XOR-verschleiert und als `*.vsq` im Quarantäneordner abgelegt. Erst wenn die
Kopie vollständig ist und ihre Prüfsumme dem Fund entspricht, wird das Original entfernt. Die
gespeicherte Datei ist weder ausführbar noch für andere Scanner als aktive Schadsoftware sichtbar.
Eine geschützte Zugriffsliste des Originals wird gespeichert und beim Wiederherstellen wieder
gesetzt; die Prüfsumme wird beim Wiederherstellen erneut kontrolliert.

## Spielmodus

- **Erkennung:** Direct3D-Vollbild, Vollbild-Anwendungen und Präsentationsmodus
  (`SHQueryUserNotificationState`), dazu laufende Programme aus Spieleordnern (Steam, Epic, GOG, EA,
  Ubisoft, Battle.net, Riot, Xbox) oder mit eingetragenen Namen. Hilfsprogramme, die in
  Spieleordnern liegen, aber keine Spiele sind (Overlays, Hintergrundbild-Programme), schließt eine
  Liste aus.
- **Wirkung:** Geplante Prüfungen und Aktualisierungen warten; ein laufender geplanter Scan
  pausiert zwischen zwei Dateien; Meldungen werden gesammelt und danach zugestellt. Nur kritische
  Alarme öffnen ein Fenster.
- **Grundlast:** Agent und Dienst laufen unter normaler Priorität mit niedriger I/O- und
  Speicherpriorität und im Effizienzmodus von Windows. Gemessen auf dem Test-PC: rund 1,4 % eines
  Prozessorkerns für beide zusammen während eines Spiels (Testbericht 7.42).

## Das Dashboard

Bindet nur an `127.0.0.1`. Jede Anfrage trägt einen zufälligen 256-Bit-Schlüssel (zeitkonstanter
Vergleich); der Host-Header muss `127.0.0.1` oder `localhost` sein (Schutz gegen DNS-Rebinding);
Änderungen nur per POST, fremde Herkunft wird abgewiesen; strenge Content-Security-Policy,
`X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`; alle Ausgaben
sind HTML-maskiert.

## Was K9 bewusst nicht hat

- **Keinen eigenen Kerneltreiber.** Alles arbeitet im Benutzermodus und über ETW. Der Preis: Ein
  Programm mit Administratorrechten kann mehr, als K9 verhindern kann. Die Anleitung nennt diese
  Grenze bei jeder Funktion, die sie betrifft.
- **Keinen automatischen Eingriff beim ersten Fund.** Das Anhalten eines Programms ist das
  Stärkste, was K9 von sich aus tut; es ist wählbar und mit einem Klick rückgängig.
- **Keine Änderungen an anderen Schutzprogrammen.**
- **Kein Hochladen.** Auch die wählbare VirusTotal-Abfrage sendet nur eine Prüfsumme.
