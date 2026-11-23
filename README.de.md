# K9 – Begleit-Scanner für Windows-PCs, auf denen auch gespielt wird

*English version: [README.md](README.md)*

K9 läuft **neben** deinem vorhandenen Virenschutz und meldet, was ihm auffällt: Schadsoftware,
Ransomware-Verhalten, Datendiebe, Phishing-Adressen, verdächtige Programmstarts, neue Autostarts,
verwundbare Programme und Treiber. Es ändert keine Einstellungen anderer Sicherheitsprodukte, legt
dort keine Ausnahmen an und schaltet nichts ab. K9 ist in Rust geschrieben und braucht nach dem
Bauen keine weiteren Laufzeitpakete.

Entwickelt und getestet wurde K9 auf einem Windows-11-PC neben Trend Micro Maximum Security.
K9 gibt es auf Deutsch und Englisch: Es richtet sich nach der Sprache von Windows, umschalten
lässt es sich oben rechts im Dashboard („Sprache: Deutsch English“) oder mit `k9 sprache de`.
Die Ausgabe der `k9`-Befehle, das Protokoll und die Anleitung sind deutsch.

## Grundsätze

- **Nichts passiert automatisch.** Jede neue Erkennung wird gemeldet und wartet auf deine
  Entscheidung: Quarantäne, Löschen/Deaktivieren oder Freigabe. Programme werden nie von selbst
  aktualisiert, Dateien nie von selbst gelöscht.
- **Entscheidungen werden gemerkt.** Derselbe Fund meldet sich danach nicht mehr. Jede
  Entscheidung kannst du ansehen und widerrufen.
- **Spielen hat Vorrang.** Agent und Dienst laufen mit niedriger Priorität. Während eines Spiels
  warten geplante Prüfungen und Aktualisierungen, und es erscheinen keine Fenster – nur kritische
  Alarme (Ransomware, Datendiebstahl) kommen durch.
- **Alles bleibt auf dem PC.** K9 lädt Erkennungsdaten herunter, sendet aber nichts hoch. Das
  Dashboard ist nur unter `127.0.0.1` erreichbar und verlangt einen zufälligen Zugangsschlüssel.
- **Schutz vor Manipulation.** Abschwächende Entscheidungen und Einstellungen brauchen eine
  Bestätigung in einem eigenen Fenster des Dienstes; Entscheidungen sind vom Dienst unterschrieben.

## Was K9 prüft

| Bereich | Wie |
|---|---|
| Dateien | YARA-Regeln (YARA Forge), ClamAV, Hashlisten (MalwareBazaar, ThreatFox), Schad- und Phishing-Adressen in `.url`/`.html`/`.eml`/`.svg` |
| Echtzeit: neue Dateien | Downloads, Desktop, Dokumente, TEMP, Autostart-Ordner, USB-Datenträger beim Einstecken |
| Programmstarts | jeder Start über die Ereignisverfolgung von Windows (ETW): verdächtige Befehlszeilen und Programmketten, PowerShell-Skripte vor dem Ausführen, unsignierte Programme und Skripte aus dem Internet, Angriffsketten; auf Wunsch zusätzlich Sigma- und LOLBAS-Regeln |
| Ransomware | Köderdateien und Erkennung vieler verschlüsselter Dateien in kurzer Zeit; auf Wunsch wird das verdächtige Programm angehalten, bis du entscheidest |
| Datendiebe | fremde Programme, die gespeicherte Passwörter und Cookies von Browsern, Steam, Discord, Telegram oder Wallets öffnen |
| Autostarts | Run-Einträge, Autostart-Ordner, geplante Aufgaben, Dienste, Hilfsprogramme von Browser-Erweiterungen, versteckte WMI-Autostarts |
| Browser-Erweiterungen | neue Erweiterungen, neue Rechte nach einem Update, bekannte Schad-Erweiterungen |
| Netzwerk und DNS | Verbindungen und DNS-Abfragen zu Schad- und Phishing-Adressen, Nachahmer-Domains bekannter Marken, neue eingehende Firewall-Regeln |
| Konten und Anmeldungen | neue Benutzerkonten und Administratoren, Remotedesktop-Anmeldungen, viele falsche Passwörter |
| Treiber | verwundbare und bösartige Kerneltreiber (Microsoft-Sperrliste, LOLDrivers), Eignung für die Speicherintegrität |
| Verwundbare Software | installierte Programme gegen aktiv ausgenutzte Lücken (CISA KEV, NVD, EPSS) |
| Sicherheits-Check | Ampel im Dashboard: Virenschutz, Firewall, Windows-Updates, Secure Boot, Benutzerkontensteuerung, Remotedesktop, Speicherintegrität, lokale Sicherheitsautorität, Datensicherung, veraltete Programme |

Jede Funktion mit Schalter und Voreinstellung steht in der Anleitung, Teil 3. Eingriffe wie das
Anhalten verdächtiger Programme, die Firewall-Sperre oder Schattenkopien sind nach der Installation
aus und werden von dir eingeschaltet.

## Bestandteile

| Programm | Aufgabe |
|---|---|
| `k9-dienst.exe` | Windows-Dienst (LocalSystem): Programmstarts, DNS und Dateizugriffe über ETW, Treiberprüfung, Wache über den Agent, geschützte Datenbank der Entscheidungen |
| `k9-agent.exe` | Agent im Benutzerkonto: Echtzeitprüfung von Dateien, Zeitpläne, Spielerkennung, Meldefenster, Dashboard im Browser |
| `k9.exe` | Befehle für die PowerShell: scannen, entscheiden, Quellen, Funktionen schalten, installieren und aktualisieren |

## Voraussetzungen

Windows 10 oder 11 (64 Bit). Zum Bauen: Rust (stable, `x86_64-pc-windows-msvc`), Visual Studio
Build Tools (C++) und Git. Optional: ClamAV (`winget install Cisco.ClamAV`), ein kostenloser
abuse.ch-Schlüssel (MalwareBazaar, URLhaus, ThreatFox) und ein NVD-Schlüssel.

## Bauen und einrichten

```powershell
cd "C:\K9-Quelltext"
cargo build --release
& ".\target\release\k9.exe" dienst installieren
& "C:\Program Files\K9\k9.exe" quellen aktualisieren
& "C:\Program Files\K9\k9.exe" dashboard
```

`dienst installieren` fragt nach Administratorrechten, kopiert die Programme nach
`C:\Program Files\K9` und richtet Dienst und Agent ein. Eine neue Version kommt mit
`& ".\target\release\k9.exe" dienst aktualisieren`, entfernt wird K9 mit
`& "C:\Program Files\K9\k9.exe" dienst deinstallieren`.

Die Programme sind nicht signiert. Ein Virenschutz kann deshalb frisch gebaute Programme oder die
geladenen Signaturdateien beanstanden (sie enthalten die Muster von Schadsoftware). Ausnahmen
trägst du dort selbst ein; K9 tut das nie für dich. Welche Ausnahmen neben Trend Micro nötig
waren, steht in der Anleitung, Teil 5.

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/ANLEITUNG.md](docs/ANLEITUNG.md) | Kurzanleitung, Bedienung, alle Funktionen, Befehlsreferenz, Installation, Fehlerbehebung, Änderungsverlauf |
| [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md) | Aufbau der Programme und Datenflüsse |
| [docs/SICHERHEIT.md](docs/SICHERHEIT.md) | Schutz vor Manipulation, Annahmen, Grenzen |
| [docs/QUELLEN.md](docs/QUELLEN.md) | alle Erkennungsquellen mit Adresse, Lizenz und Namensnennung |
| [docs/TESTBERICHT.md](docs/TESTBERICHT.md) | alle Tests mit Aufbau, Ergebnis und Grenzen, auch die missglückten |
| [docs/SANDBOX-TESTPLAN.md](docs/SANDBOX-TESTPLAN.md) | Tests in der Windows-Sandbox |
| [docs/STATISTIK.md](docs/STATISTIK.md) | Test-PC, aufgewendete Zeit, KI-Nutzung und Kosten, Umfang, Testläufe |

Auf Englisch gibt es die Startseite und unter [docs/en](docs/en) Architektur, Sicherheit, Quellen und
Statistik. Die Anleitung ist deutsch.

## Prüfen

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
powershell -ExecutionPolicy Bypass -File scripts\e2e-test.ps1
```

Die automatischen Tests (`cargo test`, `e2e-test.ps1`) benutzen weder EICAR noch echte
Schadsoftware, sondern eine eigene, harmlose Testsignatur. Riskante Verhaltenstests und die Vergleichstests mit echter Schadsoftware
laufen ausschließlich in der Windows-Sandbox (`scripts\sandbox`); die Skripte verweigern den Start
außerhalb der Sandbox. In den `.wsb`-Dateien und Skripten stehen Beispielpfade
(`C:\K9-Quelltext`, `C:\Users\anna`), die du an deinen PC anpasst.

## Grenzen

- K9 ist ein privates Projekt und **kein Ersatz für einen Virenschutz**. Es ergänzt ihn.
- K9 wird frei veröffentlicht. Eine Vermarktung ist nicht geplant; es gibt keine fertigen
  Installationspakete, keine Unterstützung und keine Gewähr (siehe Lizenz).
- Getestet ist es auf einem einzigen PC. Was gemessen wurde und was nicht, steht im Testbericht.
- K9 arbeitet ohne eigenen Kerneltreiber. Ein Programm mit Administratorrechten kann mehr, als K9
  verhindern kann; die Anleitung nennt diese Grenzen bei jeder Funktion.
- Verhaltensregeln lösen Fehlalarme aus. Deshalb entscheidet immer der Mensch.

## Erkennungsquellen und Lizenzen

Die Erkennungsdaten lädt das Programm auf deinem PC und gibt sie nicht weiter. Jede Quelle mit
Lizenz und Namensnennung steht in [docs/QUELLEN.md](docs/QUELLEN.md) und in `k9 quellen`. Die
Public Suffix List (MPL-2.0) liegt unverändert bei.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
