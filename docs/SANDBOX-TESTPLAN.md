# Sandbox-Testplan (Entwurf – noch nicht ausgeführt)

Ziel: Funktionen von K9 prüfen, die auf dem echten PC zu riskant wären (echte
Angriffstechniken, Dienst-Installation, Selbstschutz), ohne den PC zu verändern. Alles läuft in der
Windows-Sandbox und wird beim Schließen verworfen.

## Voraussetzungen

1. SVM im BIOS an und Windows startet damit normal (eigener Schritt, siehe Koordination).
2. Funktion „Windows-Sandbox“ einschalten (PowerShell **als Administrator**, danach Neustart):

   ```
   Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
   ```

3. Ordner auf dem PC vorbereiten (normale PowerShell). Der Testordner liegt in `testlabor` (nicht im
   Git) und enthält **nur** unsere drei Programme und harmlose Testdateien – keine Skripte mit echten
   Angriffs-Inhalten. Der Ergebnisordner liegt bewusst **nicht** im Projektordner, denn der ist in
   Trend Micro ausgenommen; in „Dokumente“ prüfen Trend Micro und unser Echtzeitschutz alles, was ankommt:

   ```
   New-Item -ItemType Directory -Force "C:\K9-Quelltext\testlabor\sandbox\programm"
   New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\Virenscanner-Sandbox-Ergebnis"
   Copy-Item "C:\K9-Quelltext\target\release\k9.exe","C:\K9-Quelltext\target\release\k9-agent.exe","C:\K9-Quelltext\target\release\k9-dienst.exe" "C:\K9-Quelltext\testlabor\sandbox\programm\"
   ```

## Sandbox-Konfiguration

`scripts\sandbox\k9-test.wsb` (Standard, **ohne Netzwerk**) und
`scripts\sandbox\k9-test-online.wsb` (nur Netzwerk an):

| Einstellung | Wert | Grund |
|---|---|---|
| Netzwerk | aus (online-Variante: an) | nur Tests mit offiziellen Downloads brauchen es |
| Grafikbeschleunigung (vGPU) | aus | kleinere Angriffsfläche |
| Zwischenablage, Mikrofon, Kamera, Drucker | aus | kein Weg zurück zum PC außer dem Ergebnisordner |
| Protected Client | an | zusätzliche Isolation der Sandbox-Sitzung |
| `C:\K9-Quelltext\testlabor\sandbox` → `C:\Testlabor` | **nur lesen** | unsere drei Programme und harmlose Testdateien |
| `C:\Users\anna\Documents\Virenscanner-Sandbox-Ergebnis` → `C:\Ergebnis` | schreiben | **nur Textberichte** (TXT/JSON/LOG) |

Der beschreibbare Ordner ist nötig, damit Ergebnisse herauskommen. Er liegt außerhalb der
Trend-Micro-Ausnahme, damit nichts, was die Sandbox dort ablegt, am Virenschutz des PCs vorbeikommt.
Auf dem PC werden daraus nur `.txt`-, `.json`- und `.log`-Dateien gelesen; jede andere Datei dort wird
gemeldet und nicht geöffnet.

## Tests in der Sandbox

K9 läuft in der Sandbox als eigene Installation (`C:\Testlabor\programm\k9.exe dienst
installieren` – der Sandbox-Benutzer ist Administrator); der PC ist nicht beteiligt.

| # | Test | Quelle | Netzwerk | Erwartung |
|---|---|---|---|---|
| 1 | Dienst-Installation, ETW-Prozessstarts, DNS-Abfragen, Agent-Wache | eigenes Programm | nein | `k9 dienst status`: alles aktiv |
| 2 | Echtzeit-Dateiprüfung mit der eigenen verschleierten Testsignatur | eigenes Programm | nein | Fund „Testsignatur“ |
| 3 | EICAR-Testdatei (Download) | eicar.org (offizielle Seite) | ja | Fund „EICAR“, nichts automatisch verschoben |
| 4 | AMTSO Security Features Check (Testdatei-Downloads, PUA, Phishing-Testseite) | amtso.org | ja | Funde für Download/Phishing-Adresse |
| 5 | Persistenz: Run-Schlüssel (T1547.001), geplante Aufgabe (T1053.005) | Atomic Red Team (github.com/redcanaryco/atomic-red-team) | ja (Download) | Autostart-Funde; nach Entfernen „Erledigt: Autostart-Eintrag entfernt“ |
| 6 | Verdächtige Programmstarts: PowerShell mit kodiertem Befehl (T1059.001), mshta (T1218.005), rundll32 (T1218.011), Office→cmd-Kette (simuliert) | Atomic Red Team | ja (Download) | Programmstart-Funde mit Befehlszeile |
| 7 | Schattenkopien löschen (T1490, `vssadmin delete shadows`) | Atomic Red Team | ja (Download) | Ransomware-Hinweis |
| 8 | Ransomware-Verhalten: Köderdateien umbenennen/verschlüsseln | eigenes Testskript (harmlos, nur Köderordner) | nein | kritischer Fund, Prozess-Aktionen angeboten |
| 9 | Selbstschutz: Agent per `taskkill` beenden; abschwächende `config.toml`-Änderung | Bordmittel | nein | Hinweis „Agent unerwartet beendet“ (nach 30 s); Bestätigungsfenster |
| 10 | Neuer Treiberdienst (nur Registry-Eintrag, keine Treiberdatei laden) | Bordmittel (`sc.exe create … type= kernel`) | nein | Meldung „Neuer Treiber“ innerhalb 1 Minute |

Atomic Red Team, EICAR und die AMTSO-Testdateien werden **nur in der Sandbox** (online-Variante) direkt
von den offiziellen Seiten geladen (github.com/redcanaryco/atomic-red-team, eicar.org, amtso.org) und
nie auf dem PC bereitgelegt.

Nicht vorgesehen: echte Schadsoftware-Proben, verwundbare Treiber laden, Tests auf dem PC selbst.

## Erster Lauf (offline): Tests 1, 2, 8, 9, 10

Skript `scripts\sandbox\sandbox-test-offline.ps1` (wird nach `testlabor\sandbox` kopiert, läuft nur im
Sandbox-Konto `WDAGUtilityAccount`, Dauer etwa 12 Minuten):

1. Auf dem PC: Doppelklick auf `C:\K9-Quelltext\scripts\sandbox\k9-test.wsb`.
2. In der Sandbox: Start → „PowerShell“ → Rechtsklick → „Als Administrator ausführen“, dann:

   ```
   powershell -ExecutionPolicy Bypass -File C:\Testlabor\sandbox-test-offline.ps1
   ```

3. Warten, bis „Fertig. Ergebnisse in C:\Ergebnis“ erscheint; Sandbox-Fenster schließen.

Das Skript installiert den Dienst in der Sandbox, legt eine Datei mit der eigenen Testsignatur in
„Downloads“, überschreibt 30 eigene Testdateien mit Zufallsdaten, beendet den Agent hart und trägt einen
Treiberdienst ein, der nie gestartet wird. Danach legt es `protokoll.txt`, `erkennungen.txt`,
`status.txt`, `dienst.txt` und die Dienst-Protokolle in `C:\Ergebnis` ab.

## Zweiter Lauf (online): Tests 3–7 und Warteschlange

Skript `scripts\sandbox\sandbox-test-online.ps1` in der Sandbox `k9-test-online.wsb` (Netzwerk an),
gestartet über die Sandbox-Befehlszeile (`wsb exec`). Schutz: läuft nur im Sandbox-Konto **und** wenn
`C:\K9-Quelltext` nicht existiert. Das Skript enthält keine Testsignatur und keinen EICAR-Inhalt, nur
Adressen und Namen. Dauer etwa 35 Minuten.

| Schritt | Quelle | Erwartung von K9 |
|---|---|---|
| A Installation, Quellen laden | eigene Programme | 5 von 9 Quellen (ohne abuse.ch-Schlüssel, ohne ClamAV) |
| B EICAR-Testdatei und -Zip | amtso.eicar.org, secure.eicar.org | Fund „EICAR“ (Defender in der Sandbox reagiert evtl. zuerst) |
| C AMTSO-PUA-Testdatei, Phishing-Testseite | amtso.eicar.org, amtso.org | **kein** Fund erwartet (keine PUA-Regel; Seite steht nicht auf OpenPhish) – bekannte Lücken |
| D1 T1547.001 „Reg Key Run“ | Atomic Red Team (YAML, fester Commit) | Autostart-Meldung; nach dem Aufräumen „Erledigt: Autostart-Eintrag entfernt“ |
| D2 T1053.005 „Scheduled Task Startup Script“ | dto. | Meldung zu den Aufgaben (Prüfung alle 10 Minuten) |
| D3 T1059.001 „PowerShell Command Execution“ (`-e`) | dto. | Programmstart-Fund mit Befehlszeile |
| D4 T1218.005 „Mshta executes VBScript“ | dto. (+ `src\powershell.ps1`) | Programmstart-Fund |
| D5 T1218.011 „Rundll32 execute VBscript command“ | dto. | Programmstart-Fund |
| D6 T1490 „Delete Volume Shadow Copies“ | dto. | Programmstart-/Ransomware-Hinweis |
| E Fund ohne Agent, Dienst-Neustart | eigene harmlose Treiberdatei | Fund wird nach dem Neustart **genau einmal** zugestellt |

Atomic Red Team: nur die sechs YAML-Dateien und eine `src`-Datei werden über raw.githubusercontent.com
(redcanaryco, Commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`) geladen – kein Zip, keine Binärdateien,
kein Zusatzmodul; ein kleiner Leser im Skript führt genau die genannten Tests aus und räumt danach auf.

## Dritter Lauf: Schutz vor Datendieben (offline)

Skript `scripts\sandbox\sandbox-test-infostealer.ps1` (Dauer etwa 15 Minuten, davon 10 Minuten Ruhe für
die Statistik im Dienst-Protokoll). Nur Schein-Dateien mit Zufallsinhalt; sie werden angelegt, bevor der
K9 installiert ist.

| Test | Erwartung |
|---|---|
| T1 Kopie von `k9.exe` als `Downloads\unbekannt.exe` liest die Chrome-Schein-Datei | Kritisch (unsigniert, Benutzerordner) |
| T2 PowerShell liest Chrome-, dann Steam-Schein-Datei | Hoch, dann Kritisch (mehrere Speicher) |
| T3 cmd liest die Chrome-Datei mit kleingeschriebenem Pfad | Hoch |
| T3b certutil liest die Chrome-Datei als `gOOGLE\Chrome\uSeR dAtA` | Hoch |
| T3c esentutl kopiert die Steam-Datei als `sTeAm\config\loginusers.vdf` | Hoch |
| T4 Edge unsichtbar mit `--remote-debugging-port` | Kritisch „Browser ferngesteuert“ |
| T5 Edge normal | keine Meldung |
| Statistik | Zeile „Schutz vor Datendieben: … Dateiöffnungen in 10 min (… je Sekunde), davon … geprüft; CPU-Zeit des Dienstes …“ |

Zusatzprobe `scripts\sandbox\sandbox-probe-gross-klein.ps1` (nach dem Lauf): cmd liest einmal mit kleingeschriebenem und einmal mit normalem Pfad.

## Vierter Lauf: Browser-Erweiterungen (offline)

Skript `scripts\sandbox\sandbox-test-erweiterungen.ps1`. Nur selbst angelegte Test-Einträge, die nichts tun.

| Test | Erwartung |
|---|---|
| Edge im Grundzustand | keine Meldung (erster Lauf = Grundzustand) |
| Ungepackte Test-Erweiterung im Edge-Profil mit „alle Webseiten + cookies“ | Hoch („außerhalb des Stores“) |
| Richtlinie `ExtensionInstallForcelist` mit fremder Update-Adresse | Kritisch |
| Registry-Eintrag `Software\Microsoft\Edge\Extensions\<id>` mit lokalem Pfad | Hoch |
| Verknüpfung auf dem Desktop: `msedge.exe --load-extension=...` | Hoch |
| Edge mit `--load-extension` aus dem Benutzerordner gestartet | Hoch (Programmstart) |

## Fünfter Lauf: Ausbau Phase 1 (offline, frische Sandbox, ca. 25 Minuten)

Skript `scripts\sandbox\sandbox-test-ausbau1.ps1`. Nur harmlose, selbst erzeugte Test-Schritte.

| Test | Erwartung |
|---|---|
| P1 Skriptblock mit dem AMSI-Klassennamen (ohne Richtlinie) | Kritisch „Skript schaltet AMSI ab“ |
| P2 `k9 powershell-protokoll an`, Download-und-Ausführen-Skript gegen eine nicht erreichbare Adresse | Hoch „lädt Code aus dem Internet und führt ihn aus“ |
| P3 selbst übersetztes Testprogramm mit Herkunftsvermerk „Internet“ startet | Mittel „unsigniertes Programm aus dem Internet“, Adresse ohne `?token` |
| P4 dasselbe Programm legt eine Aufgabe an, PowerShell liest die Chrome-Schein-Datei | Angriffskette Hoch, dann Kritisch |
| U `k9 dienst aktualisieren` mit veränderten Programmdateien | **kein** Selbstschutz-Alarm (der Dienst übernimmt beim Neustart die neuen Prüfsummen); bei S2 nennt die Meldung nur k9.exe |
| S1 `logman stop` der ETW-Sitzung | Kritisch „Überwachung von außen gestoppt“ |
| S2 Startart „manuell“, k9.exe verändert, 11 Minuten warten | Kritisch „startet nicht mehr automatisch“ und „Programmdateien verändert“ |
| S3 Dienst gestoppt, 2,5 Minuten warten | Kritisch „Dienst läuft nicht mehr“ (vom Agent), nach dem Start Mittel „Dienst wurde neu gestartet“ |
| S4 Dienst stoppen, k9.exe austauschen, sofort starten | Kritisch „Programmdateien verändert“ beim Start (Ausgangsstand stammt aus U), Mittel „neu gestartet“ |

## Sechster Lauf: PowerShell-Skriptprüfung mit Richtlinie (kurz, nach dem fünften)

Skript `scripts\sandbox\sandbox-test-skripte.ps1`: Aktualisierung, Richtlinie an, je ein neuer
PowerShell-Prozess mit Download-und-Ausführen (Hoch), AMSI-Klassenname (Kritisch) und harmlosem
Skript (keine Meldung), Richtlinie aus und Prüfung der Registry-Werte.

## Siebter Lauf: Ausbau Phase 2 (offline, frische Sandbox, ca. 25 Minuten)

Skript `scripts\sandbox\sandbox-test-ausbau2.ps1`. Schaltet in der Sandbox „Anhalten“ und
„Schattenkopien“ ein (VirusTotal und Firewall-Sperre brauchen Internet bzw. einen Schlüssel und
werden mit lokaler Test-Liste bzw. Dummy-Schlüssel offline geprüft).

| Test | Erwartung |
|---|---|
| E1 Testprogramm aus dem Internet startet eine Kette bis zu den Zugangsdaten | Angriffskette Kritisch, Testprogramm angehalten (Threads „Suspended“) |
| E2 PowerShell liest Chrome- und Steam-Datei | Kritisch, aber nicht angehalten (Microsoft-signiert) |
| E3 `k9 entscheiden <Nr> einmalig` | Testprogramm läuft weiter |
| H1 Schattenkopien im Leerlauf | Kopie angelegt oder Hinweis „kein Speicher“; Zeile in `k9 dienst status` |
| G2 Firewall-Sperre mit lokaler Test-Liste (öffentlich + Port, privat, Loopback, zu alt) | Regel nur für die öffentliche Adresse mit Port |
| G3 `k9 firewall entfernen` | keine eigenen Regeln mehr, Gesamtzahl wie vorher |
| F1 VirusTotal offline mit Dummy-Schlüssel | nur Log „fehlgeschlagen“, kein Fund, kein Absturz |
| H2 Schattenkopien | Anzahl nie durch K9 verringert |
| R1–R3 Rückfragen Phase 1 | Skriptblock Hoch; eigene Aktualisierung ohne Alarm; Austausch + Neustart: Alarm nur für k9.exe |

E3 einzeln wiederholen: `scripts\sandbox\sandbox-test-anhalten.ps1` (startet das Testprogramm,
zeigt die angehaltenen Threads, wählt die neueste kritische Kette und fragt nach „Ja“ im
Sandbox-Fenster, danach `k9 entscheiden <Nr> einmalig`).

## Achter Lauf: Schalter und Manipulationsschutz (offline, frische Sandbox, ca. 15 Minuten)

Skript `scripts\sandbox\sandbox-test-schalter.ps1`. Ein „Schadprogramm“ mit normalen Rechten
schaltet Schutzfunktionen direkt in `config.toml` ab; der Dienst muss den Schutz behalten. Zwei Klicks
im Bestätigungsfenster („Ja“ bei S5, „Nein“ bei S6).

| Test | Erwartung |
|---|---|
| S1 `k9 funktion anhalten/virustotal an` (zweimal) | `config.toml` gültig, `[quellen]` einmal; „VirusTotal-Abfrage: aktiv“ ohne Neustart; beide im bestätigten Stand |
| S2 beide in `config.toml` auf `false` gesetzt | Alarm im Dienst-Log, Fund EINSTELLUNG:SICHERHEIT (Hoch), VirusTotal bleibt aktiv, Status „wartet auf deine Bestätigung“ |
| S3 Testprogramm-Kette bis zu den Zugangsdaten | Kritisch und angehalten (Anhalten gilt weiter) |
| S4 Dienst neu starten | Start-Log „Nicht bestätigte Sicherheitseinstellungen gelten nicht“, VirusTotal weiter aktiv |
| S5 `k9 entscheiden <Nr> freigabe` + „Ja“ | „VirusTotal-Abfrage: aus“, Status „aus“ |
| S6 Dienst-Schlüssel zweimal speichern, beim zweiten „Nein“ | erster ohne Rückfrage, Ersetzen abgelehnt |

Nicht in der Sandbox (zu lang): Meldung beim Ausschalten der PowerShell-Protokollierung (Prüfung alle
10 Minuten) – durch Unit-Tests abgedeckt.

## Neunter Lauf: Schattenkopien auf mehreren Laufwerken und Namen der Firewall-Regeln (offline, frische Sandbox, ca. 10 Minuten)

Skript `scripts\sandbox\sandbox-test-laufwerke.ps1`, keine Klicks. Die Sandbox hat nur C:.

| Test | Erwartung |
|---|---|
| L1 `k9 funktion schattenkopien an`, `laufwerke C:` (zweimal) | „aktiv (C:, alle 24 h)“, `config.toml` gültig, `[schutz]` einmal |
| L2 `laufwerke C: Z:` | abgelehnt („gibt es auf diesem PC nicht“), Datei unverändert |
| L3 ungültige Angabe | abgelehnt, Datei unverändert |
| L4 Liste in `config.toml` geleert | Alarm „Laufwerk für Schattenkopien entfernt: C:“, C: wird weiter gesichert |
| L5 `k9 dienst status` | Zeile „Schattenkopien: C: …“ |
| W1 Firewall-Sperre mit lokaler Test-Liste, dazu eine Regel der alten Version und zwei fremde Regeln | Regel „K9 – Botnetz-Server gesperrt (Port 4444)“ in Gruppe „K9“ mit Beschreibung; alte Regel ersetzt; fremde Regeln bleiben |
| W2 `k9 firewall entfernen` | nur eigene Regeln entfernt |

## Zehnter Lauf: Umstellung „Virenscanner“ → K9 (offline, frische Sandbox, ca. 20 Minuten)

Skript `scripts\sandbox\sandbox-test-umzug.ps1`, keine Klicks. Vorher die alte Version (21b0cdc)
nach `testlabor\sandboxlt` und die neue nach `testlabor\sandbox\programm` legen.

| Test | Erwartung |
|---|---|
| U1 alte Version mit Daten (Fund in Quarantäne, Entscheidung, Dummy-Schlüssel, Firewall-Regel, Anhalten an, Laufwerk C:) | Daten vorhanden |
| U2 `k9 dienst aktualisieren` | „Selbsttest von K9: in Ordnung“, alter Dienst entfernt, Sicherung `*.alt` |
| U3 Daten | gleiche Zahl Entscheidungen, alle gültig unterschrieben, Quarantäne unter `C:\ProgramData\K9`, Schlüssel beim Dienst (nicht in der Anmeldeinformationsverwaltung), Einstellungen und Laufwerke übernommen |
| U4 keine alten Namen | kein Dienst, Registry-Schlüssel, Autostart, Firewall-Eintrag, Verknüpfung oder Programmordner „Virenscanner“; Symbol in allen Programmen und in der Verknüpfung; Sicherung des geheimen Ordners bleibt gesperrt |
| U5 kein Fehlalarm | Dienststart „Update“, kein Selbstschutz-Fund |
| U6 echte Manipulation | `k9.exe` verändert + Dienstneustart → Kritisch |
| U7 zweite Aktualisierung | keine zweite Übernahme |
| U8 `k9 alte-installation entfernen --ja` | Sicherungen weg |

## Elfter Lauf: Skript aus dem Internet gestartet (offline, frische Sandbox, ca. 4 Minuten)

Prüft die Meldung `DOWNLOAD:SKRIPT-GESTARTET` (ab Version 0.19.0) mit **harmlosen** Skripten, die nur
ein paar Sekunden warten. Keine Schadsoftware, kein Netzwerk. Den Internet-Vermerk
(`Zone.Identifier`, Zone 3, mit einer erfundenen Download-Adresse) hängt das Skript selbst an.

Start: Doppelklick auf `scripts\sandbox\k9-test-skriptherkunft.wsb` – der Test läuft von selbst
(Skript `sandbox-test-skriptherkunft.ps1`) und zeigt am Ende „GESAMT: BESTANDEN“ oder die Fehler.
Ergebnisse: `Dokumente\Virenscanner-Sandbox-Ergebnis\skriptherkunft` (`ergebnis.txt`, Protokolle).

| Test | Erwartung |
|---|---|
| T1 `rechnung.js` mit Vermerk über `wscript` | Meldung, Schwere Hoch |
| T2 `liste.js` mit Vermerk über `cscript` | Meldung |
| T3 `formular.hta` mit Vermerk über `mshta` | Meldung |
| T4 `einrichten.ps1` mit Vermerk über `powershell -File` | Meldung |
| T5 `start.bat` mit Vermerk über `cmd /c` | Meldung |
| T6 `rechnung.js` noch einmal | keine zweite Meldung (einmal je Skript) |
| T7 `eigenes.js` ohne Vermerk | keine Meldung |
| T8 Download-Adresse in der Meldung | ohne den Teil nach „?“ (kein „geheim“) |
| T9 `kurz.js` und `kurz.bat` mit Vermerk, nur mit dem Dateinamen aus „Downloads“ gestartet (ab 0.21.0) | Meldung |

## Vergleichstest mit echter Schadsoftware (vorbereitet, noch NICHT ausgeführt)

**Nur mit ausdrücklicher Zustimmung des Nutzers für genau den Tag des Laufs.** Skript
`scripts\sandbox\sandbox-vergleich.ps1`, Sandbox `scripts\sandbox\k9-vergleich.wsb` (mit Netzwerk).

Was passiert, alles in der Sandbox:

1. K9 installieren, Erkennungsdaten laden, 7-Zip (offizielles MSI von 7-zip.org) installieren.
2. Die neuesten Proben von MalwareBazaar laden (verschlüsselte ZIP-Archive, Passwort „infected“),
   höchstens 2 je Familie, Standard 30 Stück, nur gängige Typen (exe, dll, msi, ps1, js, vbs, hta,
   bat, Office mit Makros, lnk, jar). Mit VirusTotal-Schlüssel zusätzlich das Ergebnis der
   Trend-Micro-Engine je Prüfsumme (nur Abfrage, 4 pro Minute).
3. **Netzwerk aus** (Netzwerkadapter der Sandbox). Ist es danach noch erreichbar, bricht das Skript
   ab, ohne etwas zu entpacken.
4. Jede Probe einzeln nach „Downloads“ entpacken, 25 Sekunden warten: Hat K9 sie in Echtzeit erkannt?
   Hat Windows Defender (in der Sandbox aktiv, wird nicht verändert) sie entfernt?
5. Scan des Ordners mit `k9 scan`.
6. Ergebnisse nur als Text nach `C:\Ergebnis`: `vergleich.csv` (je Probe), `vergleich-zusammenfassung.txt`,
   `vergleich-erkennungen.txt`, Protokoll. Proben, Archive und Schlüssel bleiben in der Sandbox und
   sind beim Schließen weg.

Proben werden **nie gestartet**, außer mit `-Starten` und einer eigenen Zeile `starten` in der
Zustimmungsdatei (dann prüft der Test auch Programmstart, Verhalten und Ketten). Gestartet wird nur in
`scripts\sandbox\k9-vergleich-starten.wsb`: Dort gibt es keinen beschreibbaren Ordner zum PC (eine
laufende Probe könnte sonst Dateien in den Ergebnisordner legen). Die Ergebnisse stehen dann nur auf
dem Desktop der Sandbox und werden dort angesehen; das Skript bricht ab, wenn ein Ordner zum PC
beschreibbar ist.

Vorbereitung auf dem PC (normale PowerShell), nur wenn der Nutzer zustimmt:

```
New-Item -ItemType Directory -Force "C:\K9-Quelltext\testlabor\sandbox\vergleich"
Copy-Item "C:\K9-Quelltext\scripts\sandbox\sandbox-vergleich.ps1" "C:\K9-Quelltext\testlabor\sandbox\"
Set-Content "C:\K9-Quelltext\testlabor\sandbox\vergleich\ZUSTIMMUNG.txt" "Zustimmung $(Get-Date -Format dd.MM.yyyy)"
Set-Content "C:\K9-Quelltext\testlabor\sandbox\vergleich\abusech-key.txt" "<eigener Wegwerf-Schluessel>"
```

Start (normale PowerShell): `Start-Process "C:\K9-Quelltext\scripts\sandbox\k9-vergleich.wsb"`. Die Sandbox
startet das Skript von selbst in einem sichtbaren Fenster (30 Proben, nur prüfen). Fragt die Sandbox
nach Administratorrechten für die Installation von K9: „Ja“. Am Ende die Sandbox schließen.

**Lauf mit gestarteten Proben:** Zustimmungsdatei mit dem Datum des Tages **und** einer eigenen Zeile
`starten`, dann `Start-Process "C:\K9-Quelltext\scripts\sandbox\k9-vergleich-starten.wsb"`. 20 Proben
(exe, ps1, js, vbs, hta, bat), jede wird nach der Dateiprüfung gestartet und 60 Sekunden beobachtet.
Das Netzwerk der Sandbox ist dann dreifach gesperrt (Adapter aus, Gerät entfernt, Firewall sperrt
alles) und wird vor und nach jeder Probe geprüft; ist es wieder an, bricht das Skript ab und die
Sandbox ist sofort zu schließen. Es gibt keinen Ordner zurück zum PC: Das Ergebnis steht am Ende im
Fenster und wird vom PC aus fotografiert (Windows-Taste + Umschalt + S).

Offen (Entscheidung des Nutzers): welcher abuse.ch-Schlüssel in die Sandbox darf (am besten ein eigener
Wegwerf-Schlüssel nur für diesen Test), ob der VirusTotal-Schlüssel mitgenutzt wird, ob Proben
gestartet werden dürfen. Danach den Ordner `testlabor\sandbox\vergleich` wieder löschen.

### Schwerpunkt: Datendiebe und Ransomware in Aktion (vorbereitet am 19.11.2026)

Die Läufe vom 18./19.11. konnten die Erkennung von Datendieben und Ransomware nicht prüfen: Die
Sandbox war leer – nichts zu stehlen, nichts zu verschlüsseln. Der Schwerpunkt-Lauf ändert das:

- **Köder:** Vor jedem Start legt das Skript Schein-Browserprofile (Chrome, Edge, Brave, Firefox),
  Schein-Dateien von Discord, Telegram, Steam und zwei Wallets (alles Zufallsinhalt, keine echten
  Zugangsdaten) sowie 160 Schein-Dokumente in „Dokumente“, „Desktop“ und „Bilder“ an. Nach jeder
  Probe zählt es, wie viele Dokumente unverändert sind, und stellt den Satz wieder her.
- **Auswahl:** 20 Proben, nur `.exe`: etwa 12 Datendiebe (LummaStealer, Vidar, Stealc, RedLine,
  AgentTesla … – höchstens 2 je Familie, höchstens 60 Tage alt), danach etwa 8 Ransomware-Proben
  (Tag „ransomware“ bei MalwareBazaar, höchstens 1 Jahr alt). Ransomware kommt zuletzt, weil sie die
  Sandbox unbrauchbar machen kann.
- **Beobachtung:** 120 Sekunden je Probe, K9 eingestellt wie auf dem PC (Anhalten an).
- **Auswertung:** je Probe, ob K9 den Zugriff auf Zugangsdaten (`INFOSTEALER`, `BROWSER`) oder
  Ransomware-Verhalten (`RANSOMWARE`) gemeldet hat, und ob Dokumente verändert wurden – auch der
  Fall „Dokumente verändert, aber keine Meldung“ wird gezählt.
- **Sicherheit:** wie beim Lauf mit gestarteten Proben (Netzwerk dreifach gesperrt und je Probe
  geprüft, Testordner nur lesbar, kein Ordner zurück zum PC). Ergebnis per Bildschirmfoto.
- **Zustimmung:** `testlabor\sandbox\vergleich\ZUSTIMMUNG.txt` mit dem Datum des Tages und den
  beiden Zeilen `starten` und `ransomware`.
- **Start:** Doppelklick auf `scripts\sandbox\k9-vergleich-schwerpunkt.wsb` (Dauer etwa 90 Minuten).
- **Nur Ransomware:** `scripts\sandbox\k9-vergleich-ransomware.wsb` startet denselben Lauf mit
  10 Ransomware-Proben und ohne Datendiebe (etwa 60 Minuten). Nötig, weil MalwareBazaar die Abfrage
  nach Ransomware am 19.11. mit einem Serverfehler (502) beantwortete und das Stichwort „ransomware“
  im zweiten Versuch überwiegend andere Schadsoftware lieferte. Das Skript wählt jetzt nach den Namen
  bekannter Ransomware-Familien aus, je Familie die neueste Probe (LockBit, MedusaLocker, BlackMatter,
  INC, Makop, Chaos, Conti, Stop, BlackBasta, Babuk …), mit drei Versuchen je Abfrage.
- **Netzwerk-Prüfung:** Vor und nach jeder Probe versucht das Skript, drei Adressen im Internet
  direkt zu erreichen. Gelingt eine Verbindung, bricht es ab. Die Prüfung braucht keinen
  Windows-Dienst mehr – eine Probe hatte am 19.11. den dafür nötigen Dienst abgeschaltet und so einen
  falschen Abbruch ausgelöst (Testbericht 7.16).
- **Hashlisten:** Lehnt abuse.ch die große Hashliste ab („429, zu viele Abrufe“ – nach mehreren
  Läufen am selben Tag), wartet das Skript nicht mehr 25 Minuten darauf, sondern läuft ohne
  Hashlisten weiter und sagt das im Fenster. K9 muss die Proben dann am Inhalt und Verhalten erkennen.
- **Grenzen:** Ohne Netzwerk können Datendiebe nichts verschicken und manche Ransomware wartet auf
  ihren Steuerserver; Proben, die eine Sandbox erkennen, tun absichtlich nichts.

### Wie schnell ist K9 bei Ransomware? Harmloser Simulator (offline, ca. 10 Minuten)

Start: Doppelklick auf `scripts\sandbox\k9-test-ransomware-sim.wsb` – der Test läuft von selbst, die
Sandbox schließt sich danach. Keine Schadsoftware, kein Netzwerk, keine Zustimmungsdatei nötig.
Das Testprogramm `k9-testsim.exe` (wird nicht installiert) überschreibt nur Dateien in einem Ordner,
der die Markerdatei `K9-TESTORDNER.txt` enthält; ohne sie verweigert es den Start.

| Durchgang | Erwartung |
|---|---|
| R1 Ransomware-Anhalten aus | Alarm, alle 400 Dateien überschrieben |
| R2 Ransomware-Anhalten an | Alarm, Testprogramm eingefroren, über 375 von 400 Dateien unverändert (bis 0.24.0: über 350) |
| R3 Anhalten an, mit `vssadmin delete shadows` (für eine Kennung, die es nicht gibt) | wie R2, zusätzlich „Wiederherstellung wird gelöscht“ |
| R4 Wiederholung von R2 | wie R2 – auch direkt nach früheren Alarmen |
| R5 Anhalten an, K9-Agent unmittelbar vorher beendet (ab 0.24.0) | wie R2 – der Dienst erkennt und hält allein an |
| R6 bekanntes Programm (K9-Testsignatur angehängt), wartet 8 Sekunden (ab 0.25.0) | beim Start eingefroren, alle 400 Dateien unverändert |
| R7 harmlos: 300 neue gepackte Dateien anlegen, wie beim Entpacken (ab 0.26.0) | **kein** Alarm, Testprogramm läuft zu Ende |
| R8 verschlüsselte Kopie schreiben und Original löschen (ab 0.26.0) | wie R2 |
| R9 bekanntes Programm, das sofort überschreibt (ab 0.26.1) | beim Start eingefroren, über 385 von 400 Dateien unverändert |

Ergebnisse: `Dokumente\Virenscanner-Sandbox-Ergebnis\ransomware-sim` (`ergebnis.txt` mit dem Verlauf
je halbe Sekunde, Protokolle von Agent und Dienst). Erste Messung: Testbericht, Abschnitt 7.18.

### Ransomware: eine Probe je Sandbox (vorbereitet am 19.11.2026)

Zwei Läufe am 19.11. haben gezeigt, dass mehrere Ransomware-Proben in einer Sandbox nicht
funktionieren: LockBit verschlüsselte alle Schein-Dokumente, MedusaLocker beendete das Testfenster und
räumte den Desktop ab – die Zusammenfassung war verloren. Der neue Aufbau:

- **Auf dem PC** läuft `scripts\sandbox\ransomware-reihe.ps1`. Es öffnet für jede Familie und jede
  Variante eine **frische Sandbox**, wartet, bis sie sich selbst beendet, und startet die nächste.
- **In der Sandbox** läuft `sandbox-ransomware-einzeln.ps1` mit genau einer Probe: K9 einrichten,
  Netzwerk dreifach sperren, Köder anlegen, Probe starten und 3 Minuten lang alle 5 Sekunden den Stand
  aufschreiben (wie viele der 160 Schein-Dokumente unverändert sind, was K9 gemeldet hat). Danach
  fährt die Sandbox herunter; eine Notbremse tut das nach 16 Minuten in jedem Fall.
- **Zwei Varianten je Probe:** Ransomware-Anhalten **aus** (Standard, so steht es heute auf dem PC)
  und **an** (`ransomware_prozess_anhalten = true`). So zeigt der Test, was das Anhalten bringt.
- **Ergebnisordner zum PC** (Abweichung von der bisherigen Regel, nur mit Zustimmung des Nutzers): Die
  Sandbox darf in genau einen leeren Ordner schreiben (`testlabor\ransomware-uebergabe`). Das Skript
  auf dem PC kopiert daraus nur `stand.txt`, und nur wenn sie klein ist und ausschließlich
  druckbaren Text enthält; es behält die längste gültige Fassung (eine später verschlüsselte Datei
  ersetzt sie nicht). Alles andere in dem Ordner wird nach jeder Sandbox ungeöffnet gelöscht.
  Ergebnisse: `testlabor\ransomware-ergebnis\<Familie>-<aus|an>.txt`.
- **Zwischenspeicher auf einem USB-Stick** (seit 20.11.2026, mit Zustimmung des Nutzers): MalwareBazaar
  gibt nur eine begrenzte Zahl von Proben je Tag heraus (am 20.11. war nach 20 Abrufen Schluss). Die
  erste Sandbox übergibt deshalb das noch **verschlüsselte, passwortgeschützte Archiv** der Probe; das
  Skript auf dem PC legt es ungeöffnet in `E:\K9-Proben` ab (nur echte verschlüsselte ZIP-Archive bis
  60 MB, noch bevor die Probe in der Sandbox gestartet wird). Alle weiteren Sandboxen lesen die Probe
  von dort (nur lesbar eingebunden) und brauchen keinen Abruf mehr. Auf dem PC wird nie etwas
  ausgepackt; auf den eingebauten Laufwerken liegt keine Probe. Der Stick muss ein
  Wechseldatenträger mit dem Namen „K9“ sein, sonst arbeitet das Skript ohne Zwischenspeicher.
  Leeren nach dem Testtag:
  `powershell -ExecutionPolicy Bypass -File scripts\sandbox\ransomware-reihe.ps1 -ZwischenspeicherLeeren`
- **Zustimmung:** wie beim Schwerpunkt-Lauf (Datum, `starten`, `ransomware`).
- **Dauer:** etwa 8 Minuten je Sandbox; 10 Familien in beiden Varianten rund 2,5 Stunden. Während
  der Reihe öffnen und schließen sich die Sandbox-Fenster von selbst.

## Woran du siehst, dass ein Lauf noch arbeitet

Die Skripte `sandbox-vergleich.ps1` und `sandbox-test-skriptherkunft.ps1` zeigen in jeder Wartezeit ein
**drehendes Rad** (`| / - \`) mit dem aktuellen Schritt, der Restzeit und der Uhrzeit, zum Beispiel
`/ Probe 7 von 20 (exe Vidar) LAEUFT - K9 beobachtet - noch hoechstens 1:12 min (12:41:03)`.
Zusätzlich steht im **Fenstertitel**, seit wie vielen Minuten der Test läuft und was gerade geschieht.
Ganz oben im Fenster und im Fenstertitel steht die **Startzeit** des Tests, am Ende zusätzlich die
Endzeit. Dreht sich das Rad und läuft die Uhrzeit weiter, arbeitet der Test.

**Wichtig – nicht in das Fenster klicken:** Ein Mausklick in ein PowerShell-Fenster markiert Text und
hält das Skript an, bis die Markierung aufgehoben wird; im Fenstertitel steht dann vorne
„Auswählen“. So stand der Schwerpunkt-Lauf am 19.11. eine Stunde still. Abhilfe: **Esc** drücken.
Die Skripte schalten dieses Anhalten jetzt beim Start selbst ab. Nur bei zwei Schritten bewegt
sich kurz nichts (Laden von ClamAV, Scan am Ende); das steht dann ausdrücklich davor.

## Ergebnisse zurück zum PC

In der Sandbox am Ende (PowerShell):

```
C:\Testlabor\programm\k9.exe status > C:\Ergebnis\status.txt
C:\Testlabor\programm\k9.exe erkennungen --alle > C:\Ergebnis\erkennungen.txt
Copy-Item "C:\ProgramData\K9\logs\*" C:\Ergebnis\
```

Auf dem PC werden diese Dateien nur gelesen (von Claude ausgewertet), nie ausgeführt. Vorher wird der
Ordner aufgelistet: Liegt dort etwas anderes als `.txt`, `.json` oder `.log`, wird das gemeldet und nicht geöffnet.

## Aufräumen danach

1. Sandbox-Fenster schließen – alles darin ist weg.
2. Ergebnisse nach der Auswertung löschen:

   ```
   Remove-Item -Recurse -Force "$env:USERPROFILE\Documents\Virenscanner-Sandbox-Ergebnis", "C:\K9-Quelltext\testlabor\sandbox"
   ```

3. Optional die Funktion wieder ausschalten (Administrator, danach Neustart):

   ```
   Disable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
   ```

4. SVM bleibt an (Entscheidung des Nutzers, 14.11.2026: VBS an, Speicherintegrität aus, Spiele laufen).
   Nur falls ein Anti-Cheat sich meldet: SVM im BIOS wieder aus.
