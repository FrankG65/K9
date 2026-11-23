# K9 – Testbericht (externer Test)

Stand: 13.11.2026 · PC: Windows 11 Pro, 48 logische Prozessoren · Trend Micro Maximum Security installiert

## 1. Ziel und Rahmen

K9 sollte mit Material von außen geprüft werden, nicht nur mit der eigenen
Testsignatur. Verwendet wurden die offiziellen **EICAR-Testdateien**. Das ist der internationale
Standard (EICAR/AMTSO), auf den jeder K9 reagieren soll. Der Prüftext ist harmlos und
enthält keinen ausführbaren Schadcode.

Regeln für den Test:

- Testdateien nur in `C:\K9-Quelltext\testlabor`. Der Ordner ist bei Trend Micro ausgenommen und
  steht in `.gitignore`.
- Keine Änderungen an Trend Micro oder Windows Defender.
- Keine Installation von Angriffssimulatoren (Atomic Red Team, Ransomware-Simulatoren). Dafür gibt es
  keine Zustimmung.
- Nichts wird automatisch verändert. Jeder Fund wartet auf deine Entscheidung.

Testdateien: `eicar.com`, `eicar.com.txt` (gleicher Inhalt), `eicar_com.zip` (gepackt) und
`eicarcom2.zip` (ZIP in einer ZIP). Für den Echtzeittest kamen später neue Dateien mit Zeitstempel im
Namen dazu, außerdem eine harmlose PDF als Kontrolle.

## 2. Ergebnisse

### 2.1 Manueller Scan (`k9 scan testlabor`)

| Datei | Erkannt | Engine |
|---|---|---|
| eicar.com | ja | ClamAV (Eicar-Test-Signature) |
| eicar.com.txt | ja | ClamAV |
| eicar_com.zip | ja | ClamAV (Archiv entpackt) |
| eicarcom2.zip (ZIP in ZIP) | ja | ClamAV (verschachteltes Archiv) |

Ergebnis: 4 von 4 erkannt, Scan-Dauer 0,6 s. Alle Funde wurden gemeldet (Meldefenster, Dashboard).
Keine Datei wurde verändert.

### 2.2 Echtzeitschutz (vorher)

Vor den Änderungen nutzte der Echtzeitschutz nur Hashlisten, Muster, YARA und Schad-Adressen.
ClamAV kam nur bei Scans zum Einsatz. Eine neu abgelegte EICAR-Datei wäre deshalb **in Echtzeit
nicht erkannt** worden. Das ist die wichtigste Erkenntnis des Tests.

### 2.3 Behebung

1. **Eingebaute EICAR-Erkennung** (Regel `EICAR-TEST`, Schweregrad mittel). Ehrlich gesagt behebt das
   nur den Testfall: Externe Prüfseiten funktionieren jetzt auch in Echtzeit.
2. **Die eigentliche Lücke:** Der Echtzeitschutz prüft riskante neue Dateien jetzt zusätzlich mit den
   rund 3,6 Millionen ClamAV-Signaturen. Gemeint sind Programme, Skripte, Makro-Dokumente, Archive,
   PDFs, Installer und alles mit Windows-Programmkopf („MZ“). ClamAV (clamd) startet nur bei Bedarf.
   Während eines Spiels läuft es nicht (Dateien warten bis nach dem Spiel). Nach 10 Minuten ohne
   Arbeit beendet es sich wieder. Einstellbar mit `clamav` und `clamav_leerlauf_minuten` unter
   `[echtzeit]`.

### 2.4 Echtzeitschutz (nachher)

Der Testordner war dafür vorübergehend über `zusatz_ordner` überwacht. Der Eintrag ist wieder entfernt.

| Neue Datei | Erkannt nach | Engine |
|---|---|---|
| eicar_204959.com | ca. 2 s | eingebaute EICAR-Erkennung |
| eicar_204959.zip | ca. 18 s | ClamAV (Start bei Bedarf: 11 s) |
| eicar2_204959.zip (ZIP in ZIP) | ca. 18 s | ClamAV |
| harmlos_204959.pdf (Kontrolle) | keine Meldung | – (richtig) |
| phishing-test.url (aktueller Link aus OpenPhish) | ca. 1 s | Adressprüfung (OpenPhish) |

### 2.5 Verbrauch der ClamAV-Echtzeitprüfung

| Messung | Wert |
|---|---|
| Ladezeit clamd (alle Signaturen) | 11 s |
| CPU-Zeit beim Laden | ca. 10 s (einmalig, niedrige Priorität) |
| Arbeitsspeicher clamd, solange er läuft | ca. 0,9–1 GB (vom Windows-Speicher nach und nach ausgelagert, gemessen 480–990 MB aktiv) |
| CPU im Leerlauf, clamd geladen | 0 % |
| Nach 10 Minuten ohne Arbeit | clamd wird beendet, Speicher wieder frei (siehe 2.6) |
| Agent selbst | 31 MB aktiv, 182 MB reserviert (unverändert) |
| Während eines Spiels | clamd läuft nicht |

### 2.6 Beenden nach Leerlauf

Letzte ClamAV-Prüfung um 20:50:17. Um 21:00:18 meldete der Agent „clamd nach Leerlauf beendet“.
Der Prozess `clamd.exe` war danach nicht mehr vorhanden, und der Arbeitsspeicher war wieder frei.
Das entspricht genau der eingestellten Leerlaufzeit von 10 Minuten.

## 3. Weitere Prüfungen

| Prüfung | Ergebnis |
|---|---|
| Windows Sandbox (für gefährlichere Tests in einer Wegwerf-Umgebung) | **noch nicht nutzbar**: Windows 11 Pro ist geeignet, und das Feature `Containers-DisposableClientVM` ist vorhanden (Zustand: deaktiviert). Die Virtualisierung ist aber im BIOS/UEFI ausgeschaltet (kein Hypervisor aktiv). Zum Einschalten: Virtualisierung (Intel VT-x bzw. AMD SVM) im BIOS aktivieren, dann „Windows-Features aktivieren oder deaktivieren“ → „Windows-Sandbox“. Das ändert Systemeinstellungen und wurde deshalb nicht gemacht. |
| AMTSO „Security Features Check“ (Testseiten im Browser) | nicht automatisch ausgeführt, weil dafür dein Browser nötig ist und Trend Micro ebenfalls reagiert. Die Download-Tests landen im überwachten Ordner „Downloads“. Dort greifen jetzt EICAR-Erkennung und ClamAV. |
| Kurze Prozessstarts, DNS-Abfragen, Selbstschutz | siehe Abschnitt 4 (Windows-Dienst) |

## 4. Windows-Dienst (Live-Test)

Der Dienst wurde am 13.11.2026 eingerichtet und nach `C:\Program Files\K9` aktualisiert
(deutscher Explorer: „C:\Programme\K9“). Er läuft als LocalSystem, der Agent mit dem
normalen Benutzerkonto.

| Prüfung | Ergebnis |
|---|---|
| Sehr kurzer Prozess: `certutil.exe -? -urlcache` (harmlos, endet nach wenigen Millisekunden) | **1. Version: nicht erkannt.** Die Befehlszeile war nicht mehr lesbar, als der Dienst nachsah. **Behoben:** Prozessstarts kommen jetzt vom Kernel-Systemanbieter, dessen Ereignis die Befehlszeile mitliefert. **2. Version: erkannt** (ca. 2 s, Regel PROZESSARGUMENTE:certutil.exe). |
| DNS-Abfrage einer Schad-Domain aus URLhaus (nur aufgelöst, keine Verbindung) | erkannt. 1. Version ohne fragendes Programm (Testprogramm schon beendet). **Behoben:** Jetzt „abgefragt von powershell.exe (PID …)“ samt Befehlszeile, eigener Fingerabdruck je Domain und Programm. |
| Selbstschutz: Agent hart beendet (`taskkill /F`, wie im Task-Manager) | um 21:34:44 beendet; um 21:34:54 meldete der Dienst „Agent wurde unerwartet beendet“ und startete den Agent neu |
| Agent nach Neustart durch den Dienst | läuft als `PC\anna` (nicht als SYSTEM) aus `C:\Program Files\K9` |
| Absichtliches Beenden mit `k9 agent-beenden --minuten 15` | kein Alarm; Pause im Dienstprotokoll mit dem aufrufenden Programm vermerkt |
| Dienst vertraut nur Programmen in `C:\Program Files\K9` | Unit-Test; Agent-Wache bleibt aus, wenn der Agentpfad woanders liegt |

Verbrauch des Dienstes (48 logische Prozessoren):

| Situation | CPU (alle Kerne) | Arbeitsspeicher |
|---|---|---|
| Leerlauf (20 s gemessen) | 0,006 % | 28 MB aktiv, 17 MB privat |
| 200 kurze Prozesse in ca. 15 s | im Mittel 0,16 %, Spitze 1,7 % (eine Sekunde) | 28 MB |

Der Dienst scannt keine Dateien. Beim Spielen fallen nur wenige Prozessstarts an, deshalb ist kein
Einfluss zu erwarten.

## 5. Härtung (Stufe 1 und 2)

| Prüfung | Ergebnis |
|---|---|
| Übernahme beim Update (Stufe 1, live am 14.11.2026) | 12 Entscheidungen unterschrieben und gültig, 9 Quarantäne-Dateien nach `C:\ProgramData\K9\quarantaene` verschoben, Zugriff für normale Programme verweigert, Einstellungen als bestätigt gespeichert |
| Selbst eingetragene oder nachträglich geänderte Freigabe | wird ignoriert (Unit-Test) |
| Abschwächende Änderung in config.toml | gilt erst nach Bestätigung, schärfere Werte ohne Rückfrage (Unit-Test) |
| Browser-Hilfsprogramm von Trend Micro (Native Messaging) | live als registriert und signiert erkannt, kein Fehlalarm mehr |
| Sicherheitsprüfung aller Eingaben des Dienstes | siehe `docs\SICHERHEIT.md`; behoben u. a.: ClamAV-Pfad aus config.toml, Protokoll/Datenbank/TEMP im Benutzerordner (Umleitungs-Angriff), Wiederherstellen/Quarantäne/Löschen/Prozess beenden mit Systemrechten |
| Testtrennung | Unit-Tests und Ende-zu-Ende-Test berühren weder `C:\ProgramData\K9` noch den installierten Dienst noch `%TEMP%`. Vorher hatten zwei Testläufe in `%TEMP%` die Funde #25/#26 ausgelöst. Kontrolle danach: keine echten Daten verändert. |

## 6. Härtung Stufe 3

| Prüfung | Ergebnis |
|---|---|
| Agent schreibt direkt in die Dienst-Datenbank (Fund als erledigt markieren, neuen Fund eintragen) | abgelehnt (Unit-Test) |
| Übernahme vorhandener Funde, Entscheidungen, Ereignisse; zweite Übernahme | alles übernommen, nichts doppelt (Unit-Test) |
| Fehlende Nummern zwischengespeicherter Funde | erkannt (Unit-Test) |
| Bestätigungsfenster: Text aus Funddaten kann die Befehlszeile nicht verlassen | geprüft (Unit-Test) |
| Live auf dem PC | nach `k9 dienst aktualisieren` (siehe Anleitung) |

## 7. Treiberprüfung (14.11.2026, nur lesend)

583 Treiberdateien, geprüft gegen LOLDrivers und die Microsoft-Sperrliste (8.782 Einträge):

| Ergebnis | Treiber |
|---|---|
| Auf den Listen (Datei-Hash) | AsIO2.sys, AsIO3.sys, GLCKIO2.sys (ASUS, Systemstart, geladen); inpoutx64.sys (geladen); C:\Windows\gdrv.sys (Gigabyte, nicht geladen) |
| Nicht HVCI-tauglich und geladen | Acronis True Image 24.8 (fltsrv, snapman, file_tracker, volume_tracker, tib_mounter, virtual_file), RTCore64 (MSI Afterburner 4.6.6), PxHlpa64 (Corel), CtiIo64 (Creative), ekaprot6 (Ekahau), inpoutx64, npusbio_x64, TmBusEn (Thrustmaster) |
| Fehlalarm behoben | Zwei Microsoft-Treiber (appid.sys, monitor.sys) passten zunächst auf Name/Version-Regeln; Name/Version-Regeln gelten jetzt nicht mehr für Microsoft-signierte Treiber. |

Tests mit erfundenen Listeneinträgen: Seiten-Hashes werden ignoriert, Name/Version nur innerhalb des
Bereichs, Authenticode-Hash ändert sich nicht durch das Prüfsummenfeld, Windows-Treiber sind
HVCI-tauglich, Dateiname allein ist nie ein Treffer.

### 7.1 Nach dem Aufräumen und Start mit Virtualisierung (14.11.2026, nur lesend)

- Aufräum-Skript (Sätze `Verwaist` und `Asus`): alle 9 Dienste und Dateien entfernt, Sicherungen mit
  Prüfsummen. `k9 treiber`: **0** verwundbare Treiber. Gerätefehler danach nur bei zwei Netzwerkkarten,
  die schon seit August im Geräte-Manager deaktiviert sind (nicht durch das Aufräumen).
- Start mit eingeschaltetem SVM: Hypervisor läuft, virtualisierungsbasierte Sicherheit (VBS) läuft,
  der sichere Kernel startet (`IsSecureKernelRunning` 1; beim ersten Versuch vor dem Aufräumen: Fehler
  `0xc0000001`). Speicherintegrität (HVCI) ist **nicht** eingeschaltet; deshalb lädt RTCore64 (MSI
  Afterburner) weiterhin.
- CodeIntegrity-Protokoll: keine blockierten Kernel-Treiber.
- **Beobachtung (nichts geändert):** Windows lehnt die Trend-Micro-AMSI-Komponente
  `C:\Windows\System32\TmAMSI\TmAMSIProvider64.dll` nur in geschützten Windows-Prozessen ab
  (`svchost.exe`, `SecurityHealthService.exe`; Ereignisse 3033/3089 „did not meet the Windows signing
  level requirements“). Das passiert schon **vor** dem ersten Start mit SVM (175 Ereignisse vor 15:14),
  hat also nichts mit VBS zu tun: Diese Prozesse laden nur von Microsoft signierte Bibliotheken. In
  normalen Prozessen (geprüft: PowerShell) ist der Trend-AMSI-Anbieter geladen, die Skriptprüfung von
  Trend Micro arbeitet dort also.
- Fehlalarm behoben: „Neuer Treiber RTCore64.sys“ nach dem Neustart – Afterburner lädt den Treiber
  erst nach der Anmeldung. Der Dienst merkt sich jetzt alle je gesehenen Treiber dauerhaft.

### 7.2 Erster Testlauf in der Windows-Sandbox (14.11.2026, offline)

Ausgeführt mit `scripts\sandbox\sandbox-test-offline.ps1` über die Sandbox-Befehlszeile (`wsb exec`),
ohne Netzwerk; nichts auf dem PC verändert. Ergebnisse (nur Textdateien) in
`Dokumente\Virenscanner-Sandbox-Ergebnis`.

| Test | Erwartet | Ergebnis |
|---|---|---|
| 1 Dienst installieren | Dienst läuft, Prozessstarts und DNS aktiv | bestanden |
| 2 Datei mit eigener Testsignatur in „Downloads“ | Fund | bestanden (#1, 2 s nach dem Anlegen) |
| 3 30 Dateien mit Zufallsdaten überschrieben | Ransomware-Alarm, kritisch | bestanden (#2, nach 4 s) |
| 4 Agent hart beendet | Neustart, Hinweis nach 30 s | bestanden (Neustart nach 4 s, Hinweis #3 nach 30 s) |
| 5 Neuer Treiberdienst (nur eingetragen) | Meldung „Neuer Treiber“ | bestanden (#4, 46 s nach dem Eintragen) |

Nichts wurde automatisch verschoben oder gelöscht; alle Funde warteten auf eine Entscheidung.

Dabei gefunden und behoben:

- Die Programme brauchten das Visual-C++-Paket (`VCRUNTIME140.dll`), das in einer frischen Sandbox fehlt.
  Sie enthalten die Laufzeit jetzt selbst und laufen auf jedem Windows.
- Die Agent-Wache suchte den Benutzer nur in der Konsolensitzung. In der Sandbox (wie bei Remotedesktop)
  wurde der Agent deshalb nicht gestartet. Jetzt zählt auch eine aktive Sitzung desselben Benutzers;
  Sitzungen anderer Benutzer nie.
- Funde des Dienstes warteten nur im Arbeitsspeicher, bis der Agent verbunden war; ein Neustart des
  Dienstes vorher verlor sie (im zweiten Lauf beobachtet). Sie werden jetzt in der Datenbank des Dienstes
  aufbewahrt, bis der Agent sie erhalten hat – ohne doppelte Einträge.

### 7.3 Zweiter Testlauf in der Windows-Sandbox (14.11.2026, mit Netzwerk)

Skript `scripts\sandbox\sandbox-test-online.ps1`, Quellen nur offiziell (eicar.org, amtso.org,
Atomic Red Team von github.com/redcanaryco, Commit `a0e3f9bc`). Auf dem PC keine Reaktion.

| Schritt | Erwartet | Ergebnis |
|---|---|---|
| A Installation, Quellen | 5 von 9 Quellen | bestanden (YARA Forge, OpenPhish, CISA KEV, LOLDrivers, Microsoft-Sperrliste) |
| B EICAR-Datei und -Zip | Fund | **nicht erkannt** – die Dateien kamen an, bevor der Agent lief |
| C AMTSO PUA, Phishing-Seite | kein Fund (bekannte Lücken) | kein Fund |
| D1 Run-Schlüssel | Autostart-Meldung | **nicht gemeldet** – angelegt 14 s vor dem Agent-Start |
| D2 Geplante Aufgaben | Meldung | **nicht gemeldet** – neue Aufgaben mit cmd.exe galten als unauffällig |
| D3 `powershell -e <Base64>` | Programmstart-Fund | **nicht erkannt** – nur `-enc` war bekannt |
| D4 `mshta vbscript:` | Programmstart-Fund | **nicht erkannt** – nur mit Office/Browser als Elternprozess |
| D5 `rundll32 vbscript:` | Programmstart-Fund | **nicht erkannt** – wie D4 |
| D6 `vssadmin delete shadows` | Ransomware-Hinweis | **nicht erkannt** – keine Regel |
| E Fund ohne Agent, Dienst-Neustart | genau einmal zugestellt | bestanden („1 wartende Funde übernommen“, Fund genau einmal) |

Behoben (alle mit Tests):

- Programmstarts: `-EncodedCommand` in jeder Abkürzung (`-e`, `-en`, `-enc`, `-ec`, …) mit Base64;
  `mshta`/`rundll32` mit `vbscript:`, `javascript:` oder `RunHTMLApplication` – unabhängig vom
  Elternprozess; Löschen von Schattenkopien/Sicherungskatalog und Abschalten der Wiederherstellung
  (`vssadmin`, `wmic`, `wbadmin`, `bcdedit`, PowerShell) als kritischer Ransomware-Hinweis.
- Agent: prüft nach dem Start einmal die Dateien der überwachten Ordner, die in den letzten 24 Stunden
  geändert wurden (höchstens 2000, nie während eines Spiels; bekannte Dateien überspringt der Cache).
- Agent: merkt sich bekannte Autostarts dauerhaft – Einträge, die angelegt wurden, während er nicht lief,
  werden gemeldet. Neue geplante Aufgaben und Dienste, die cmd, PowerShell, mshta, rundll32 u. a. starten,
  werden wie neue Run-Einträge gemeldet.
- Dienst: Treiber, die während des Dienst-Starts hinzukommen, gelten jetzt als neu (gespeicherte Liste
  statt Momentaufnahme).

### 7.4 Wiederholung des Online-Laufs mit den Korrekturen (14.11.2026)

| Schritt | Ergebnis |
|---|---|
| B EICAR-Datei und -Zip (Agent läuft) | bestanden – in Echtzeit nach 2 s gemeldet |
| D1 Run-Schlüssel | bestanden – gemeldet; nach dem Entfernen vom Dienst selbst erledigt |
| D2 Geplante Aufgaben | **nicht gemeldet** – Aktion `cmd.exe /c …` ohne Pfad, das Ziel blieb leer |
| D3 `powershell -e <Base64>` | bestanden (Hoch) |
| D4/D5 `mshta`/`rundll32` mit Skriptcode | **nicht erkannt** – sehr kurze Prozesse heißen nach ihrer Befehlszeile („mshta“ ohne „.exe“) |
| D6 Schattenkopien löschen | bestanden (Kritisch) |
| E1 Datei kommt an, während kein Agent läuft | bestanden – Nachprüfung nach dem Start findet sie |
| E2 Treiberdienst in der Startphase des Dienstes | bestanden – als neu gemeldet |
| E3 Hinweis „Agent beendet“ über den Dienst-Neustart | bestanden – genau einmal zugestellt |

Beide Lücken (D2, D4/D5) sind behoben: Programmnamen ohne Endung gelten als `.exe`, und bei Aufgaben
zählt auch das erste Wort des Befehls.

Gezielte Nachprüfung in derselben Sandbox mit der korrigierten Version: `mshta` und `rundll32` mit
Skriptcode werden erkannt (Hoch); eine neue geplante Aufgabe mit `cmd.exe /c …` wird bei der nächsten
vollständigen Runde (alle 10 Minuten) gemeldet – jetzt als „startet ein Skript-Programm“, Schwere Mittel.
(Dieselben Aufgaben wie im Lauf davor galten zu Recht als schon bekannt; geprüft wurde mit einem neuen
Aufgabennamen.) End-zu-End-Test 10-mal hintereinander: 44 von 44 bestanden; die einmalige Abweichung
davor trat nicht wieder auf, fehlgeschlagene Prüfungen werden jetzt in `target\e2e-fehler.log` festgehalten.

**Positives Ergebnis:** Während des Laufs hat der Tester in einem Meldefenster der Sandbox versehentlich
„Freigabe“ angeklickt. Das Bestätigungsfenster des Dienstes hat das abgefangen („Nicht bestätigt“), der
Fund blieb offen. Geprüft: Im Meldefenster ist „Später“ die Standard-Schaltfläche (Enter, Esc und das X
bedeuten „Später“), im Bestätigungsfenster ist „Nein“ vorausgewählt, ohne Antwort gilt nach 120 Sekunden
„Nein“. Eine Tastatureingabe kann also nie eine Freigabe oder andere Abschwächung auslösen.

### 7.5 Schutz vor Datendieben und Browser-Erweiterungen in der Sandbox (14.11.2026, offline)

| Lauf | Build | Ergebnis |
|---|---|---|
| 7 Datendiebe | febf7bb | T1–T3 **nicht gemeldet**, T4/T5 bestanden. Ursache: Die Dateiereignisse kommen verzögert an; die kurz laufenden Leser waren schon beendet, der Dienst hat sie verworfen. |
| 8 Erweiterungen | Zwischenstand | E1–E5 bestanden (Richtlinie Kritisch, Registry Hoch, Verknüpfung Hoch, `--load-extension` Hoch, keine weiteren Meldungen) |
| 9 Datendiebe | Zuordnung über Prozess-Lebensläufe | T2/T4/T5 bestanden; T1 nur Hoch (nur der Programmname war bekannt), T3 (Kleinschreibung) nicht gemeldet. Zusatzprobe: kleingeschrieben nein, normal ja – der Kernel-Filter beachtete die Schreibweise. |
| 10 | Zwischenstand, zählt nicht | nur zum Vergleich |
| 11 Datendiebe | k9-dienst 4404661d | **alle bestanden:** T1 Kritisch (voller Pfad aus dem Kernel), T2 Hoch → Kritisch, T3/T3b/T3c (klein, `uSeR dAtA`, `sTeAm`) Hoch, T4 Kritisch, T5 keine Meldung |
| 12 Erweiterungen | k9-dienst 4404661d | **alle bestanden** (E1–E4 erneut erkannt, keine neuen Meldungen) |

Änderungen dazu: Der Dienst merkt sich je Prozess-ID, welches Programm wann lief (Start- und
Ende-Ereignisse; Windows vergibt IDs schnell neu). Das Programm kommt nur aus Kernel-Angaben – nie aus
der Befehlszeile, die ein Schadprogramm fälschen kann; ist es nicht sicher bestimmbar, kommt
„Programm nicht sicher zuzuordnen“. Der Kernel-Filter ist entfernt, alle Dateiöffnungen kommen im
Dienst an und werden dort ohne Rücksicht auf Groß-/Kleinschreibung ausgewählt.

Gemessen in Lauf 11 (Sandbox, 10 Minuten mit Tests, Edge-Starts und Leerlauf): 37.976 Dateiöffnungen
(62 je Sekunde), davon 1.288 geprüft; CPU-Zeit des ganzen Dienstes 1,2 s, also 0,21 % eines Kerns.
Mit Kernel-Filter waren es im gleichen Ablauf 2.159 Ereignisse.

**Messung auf dem PC** (14.11.2026, k9-dienst 4404661d, nur Protokollzeilen gelesen; CPU-Zeit des ganzen
Dienstes, ein Kern = 1/48 der CPU):

| 10-Minuten-Fenster (Berlin) | Lage | Dateiöffnungen je Sekunde | davon geprüft | CPU (ein Kern) |
|---|---|---|---|---|
| 22:42–22:52 | nach der Installation (Start, Treiberprüfung) | 505 | 42 % | 1,70 % |
| 22:52–23:02 | ab 22:56 Beispielspiel | 576 | 37 % | 0,82 % |
| 23:02–23:12 | im Spiel | 412 | 52 % | 0,57 % |
| 23:12–23:22 | im Spiel | 397 | 51 % | 0,60 % |

Während des Spiels keine Meldungen, keine Fehler, Spielmodus aktiv (keine ClamAV-Starts, keine
Aktualisierungen). Die Last ist nicht spürbar; eine weitere Entlastung ist nicht nötig.

**Nebenwirkung des End-zu-End-Tests (behoben):** Der Test-Agent aus `target\release` las für den
Dashboard-Kasten „Browser-Erweiterungen“ die echten Browserordner (Fehlalarme #47–#49), und clamd legte
beim Test Temp-Dateien mit der Testsignatur in das echte TEMP (#38/#39). Jetzt zeigen LOCALAPPDATA,
APPDATA, USERPROFILE, TEMP und TMP im Test auf leere Testordner, und im Testmodus liefert der Programmkern
grundsätzlich keine echten Benutzerordner (Unit-Test). Nach dem nächsten Testlauf: keine neuen Funde in
der echten Datenbank.

### 7.6 Ausbau Phase 1 in der Sandbox (15.11.2026, offline)

| Lauf | Build | Ergebnis |
|---|---|---|
| 13 | bd8e9bb | Selbstschutz S1–S4 bestanden (Überwachung gestoppt, Startart, Dateien, Dienst gestoppt, Austausch mit sofortigem Neustart). Nicht aussagekräftig: drei Fehler im Testskript (C#-Pfad, Aktualisierungspfad); echter Fehler: `powershell-protokoll an` legte den Richtlinien-Schlüssel nicht an. |
| 14 | 65df7ca | **Bestanden:** Skriptblock mit FromBase64String + VirtualAlloc ohne Richtlinie (Hoch); unsigniertes Programm aus dem Internet (Mittel); Angriffskette Hoch (Aufgabe) → Kritisch (Zugangsdaten); eigene Aktualisierung ohne Alarm, danach nennt der Dateialarm nur k9.exe; S1–S4 wie in Lauf 13; Richtlinie an/aus sauber. Fehler: mit Richtlinie kamen keine Skripte an – der Dienst empfing PowerShell nur bis Stufe „Information“, alle Skripte kommen aber als „ausführlich“. |
| 15/16 | 01f7cf7 | Mit Stufe „ausführlich“ und Filter nur auf Ereignis 4104: Download-und-Ausführen (Hoch) und AMSI-Klassenname (Kritisch) mit Richtlinie erkannt, harmloses Skript ohne Meldung, Richtlinie danach vollständig entfernt. |

Nebenbefund: Die Testskripte selbst enthalten die Prüfwörter und werden bei eingeschalteter
Richtlinie bzw. als verdächtig protokolliert ebenfalls gemeldet – erwartet.

### 7.7 Ausbau Phase 2 in der Sandbox (15.11.2026, offline, Lauf 17)

Build 30615be, Skripte `sandbox-test-ausbau2.ps1` und `sandbox-test-anhalten.ps1`.

| Test | Ergebnis |
|---|---|
| E1 Kette bis zu den Zugangsdaten | **Bestanden:** Angriffskette Kritisch, Testprogramm angehalten (12 von 12 Threads) |
| E2 PowerShell liest Chrome-/Steam-Datei | **Bestanden:** Kritisch, nicht angehalten (Microsoft-signiert) |
| E3 „Nur diesmal erlauben“ | **Bestanden** nach Bestätigung der Rückfrage („Ja“): Entscheidung gespeichert, 0 von 12 Threads angehalten. Erster Versuch scheiterte am Testablauf: der Agent war nach dem Dienstneustart beendet, und die Agent-Wache startete ihn erst nach 3 Minuten – die Rückfrage kam zu spät. |
| H1 Schattenkopien | **Bestanden:** Hinweis „kein Speicher“ (in der Sandbox ist der Computerschutz aus) und Zeile in `k9 dienst status`. Nebenbefund: der Hinweis kam bei jedem Dienststart neu. |
| H2 nichts gelöscht | **Bestanden:** Anzahl der Schattenkopien nie verringert |
| G2/G3 Firewall-Sperre | **Bestanden:** Regel nur für die öffentliche Adresse mit Port; nach `k9 firewall entfernen` keine eigenen Regeln, Gesamtzahl wie vorher |
| F1 VirusTotal offline | **Bestanden:** nur Log „fehlgeschlagen“, kein Fund, kein Absturz |
| R1–R3 Phase 1 | **Bestanden** |

Korrigiert danach: Der Hinweis „kein Speicher“ hat je Laufwerk einen festen Fingerabdruck (eine
Meldung, solange sie offen ist). Die Agent-Wache startet einen fehlenden Agent nach etwa 10 Sekunden,
wenn du länger als 3 Minuten angemeldet bist; direkt nach der Anmeldung und nach einer Aktualisierung
wartet sie wie bisher bis zu 3 Minuten (Unit-Test `start_now`).

Nachtrag bei der Installation auf dem PC (15.11.2026): Aus einer Administrator-PowerShell startet
`k9 dienst aktualisieren` den Agent nicht selbst (das macht nur die normale PowerShell nach der
Rückfrage), also blieb es bei der Wache mit ihren 3 Minuten. Jetzt startet die Wache nach einer
Aktualisierung immer nach etwa 10 Sekunden.

### 7.8 Schalter und Manipulationsschutz in der Sandbox (15.11.2026, offline, Lauf 18)

Build 212ebee (Skript `sandbox-test-schalter.ps1`), Nachtest mit f7c5e2a in derselben Sandbox
(`sandbox-test-schalter-bestaetigen.ps1`).

| Test | Ergebnis |
|---|---|
| S1 `k9 funktion anhalten/virustotal an` (zweimal) | **Bestanden:** `config.toml` gültig, `[quellen]` einmal, VirusTotal ohne Neustart aktiv, beide im bestätigten Stand |
| S2 „Schadprogramm“ setzt beide in `config.toml` auf `false` | **Bestanden:** Alarm im Dienst-Log, Fund EINSTELLUNG:SICHERHEIT (Hoch), VirusTotal blieb aktiv, Status „wartet auf deine Bestätigung“. (Das Skript meldete fälschlich FEHLER: sein Suchmuster traf den Alarmtext selbst.) |
| S3 Testprogramm-Kette bis zu den Zugangsdaten | **Bestanden:** angehalten (12 von 12 Threads), obwohl `config.toml` „false“ sagte |
| S4 Dienst neu gestartet | **Bestanden:** Start-Log „Nicht bestätigte Sicherheitseinstellungen gelten nicht“, VirusTotal weiter aktiv |
| S5 Änderung übernehmen | **Fehler gefunden:** Nach „Ja“ im Bestätigungsfenster lehnte der Dienst mit „Bestätigen kann nur der Windows-Dienst“ ab – seit Härtung Stufe 3 ließ sich eine abgeschwächte Einstellung nie übernehmen (Schutz blieb an). Behoben in f7c5e2a. |
| S6 Dienst-Schlüssel ersetzen | **Bestanden:** erster ohne Rückfrage, Ersetzen nach „Nein“ abgelehnt, nur einmal gespeichert |
| B0 Aktualisierung auf f7c5e2a | **Bestanden:** Abschwächung gilt weiter nicht, Fund offen, bestätigter Stand „an“ |
| B1 Bestätigungsfenster „Nein“ | **Bestanden:** nichts geändert (Status „wartet“, Fund offen, bestätigter Stand unverändert) |
| B2 Bestätigungsfenster „Ja“ | **Bestanden:** „VirusTotal-Abfrage: aus“ ohne Neustart, Status „aus“, Fund entschieden, bestätigter Stand „aus“ |

### 7.9 Mehrere Laufwerke und Namen der Firewall-Regeln (15.11.2026, offline, Lauf 19)

Build 21b0cdc, Skript `sandbox-test-laufwerke.ps1`, keine Klicks. Alle Prüfungen bestanden:
`k9 funktion schattenkopien laufwerke` schreibt die Liste einmal und gültig; ein nicht vorhandenes
Laufwerk (Z:) und ungültige Angaben werden abgelehnt, ohne die Datei zu ändern; leert ein
„Schadprogramm“ die Liste, meldet der Dienst „Laufwerk für Schattenkopien entfernt: C:“ und sichert C:
weiter; die Statuszeile lautet „C: …“. Firewall: Regel „K9 – Botnetz-Server gesperrt
(Port 4444)“ in Gruppe „K9“ mit Beschreibung (Quelle, Stand, Anzahl, Entfernen-Befehl); die
Regel der alten Version wurde ersetzt; eine fremde Regel in derselben Gruppe und eine mit ähnlichem
Namen blieben erhalten, auch bei `k9 firewall entfernen` (Gesamtzahl 412 → 411, nur die eigene weg).

### 7.10 Umstellung „Virenscanner“ → K9 (15.11.2026, offline, Lauf 20)

Alte Version 21b0cdc mit echten Daten (Fund in Quarantäne, unterschriebene Entscheidung,
Dummy-Schlüssel, Firewall-Regel, Anhalten an, Laufwerk C:), dann `k9 dienst aktualisieren`
(Skript `sandbox-test-umzug.ps1`, keine Klicks).

Erster Lauf (Build 6e2accf): fast alles bestanden, aber `config.toml` wurde nicht übernommen –
k9.exe legt beim Start Standardwerte an, und die Übernahme übersprang vorhandene Zielordner. Der
Dienst hielt die bestätigten Werte (Anhalten, Firewall-Sperre) trotzdem an und meldete
„Sicherheitseinstellung wurde abgeschwächt“ – Schutz gehalten, aber Fehlalarm. Behoben in 8e36b67.

Wiederholung (Build 8e36b67): **alle 50 Prüfungen bestanden** – Selbsttest in Ordnung, gleiche
Zahl Funde und Entscheidungen, alle gültig unterschrieben, Quarantäne unter `C:\ProgramData\K9`,
VirusTotal-Schlüssel nur beim Dienst, `config.toml` übernommen, kein Dienst/Registry-Schlüssel/
Autostart/Firewall-Eintrag/Verknüpfung/Programmordner mit „Virenscanner“ mehr, Symbol in allen
Programmen und in der Verknüpfung, Symbol im Infobereich, Sicherung des geheimen Ordners für Benutzer
gesperrt, Dienststart „Update“ ohne Fehlalarm, echte Manipulation weiter Kritisch, keine zweite
Übernahme, `k9 alte-installation entfernen` löscht die Sicherungen.

### 7.11 K9-Update, Pause beenden, Ton (15.11.2026, offline, Lauf 21)

Installierte Version 8e36b67 (wie auf dem PC, Autostart und Anhalten an), dann Update auf b69887c
(Skript `sandbox-test-update-k9.ps1`, ein Klick). **Alle 13 Prüfungen bestanden:** keine zweite
Übernahme, Dienststart „Update“, kein Fehlalarm, Autostart und Schalter bleiben; Testmeldung mit
Protokollzeile „Ton: SystemAsterisk“; `k9 agent-beenden --minuten 30` (Bestätigung „Ja“) beendet den
Agent, `k9 pause-beenden` meldet „Pause beendet, Agent laeuft.“ (Dienst-Protokoll „Agent-Pause
vorzeitig beendet“), ein zweiter Aufruf „Keine Pause aktiv“; danach startet der Dienst einen hart
beendeten Agent wieder (Wache aktiv).

### 7.12 Vergleichstest mit echter Schadsoftware (18./19.11.2026, Sandbox, nur prüfen)

Skript `scripts\sandbox\sandbox-vergleich.ps1`, Sandbox `k9-vergleich.wsb`. Proben von MalwareBazaar,
nur in der Sandbox geladen, Netzwerk vor dem Entpacken aus, **nichts gestartet**. K9 0.18.3 mit
abuse.ch-Hashlisten und YARA; Vergleich mit der Trend-Micro-Engine über VirusTotal (nur die
Dateiprüfung, nicht das ganze Produkt). Windows Defender hat in der Sandbox keine Probe entfernt.

| Lauf | Proben | K9 erkannt | über Hashliste | über YARA (Inhalt) | Trend Micro (VirusTotal) |
|---|---|---|---|---|---|
| 18.11., neu (2–6 Stunden alt) | 8 | 8 | 8 | 0 | 0 |
| 19.11., neu (Minuten bis 3 Stunden alt) | 15 | 11 | 10 | 8 | 8 |
| 19.11., älter (7–9 Tage, 8 Familien) | 15 | 15 | 15 | 3 | 8 |
| **19.11. zusammen** | **30** | **26 (87 %)** | 25 | 11 | 16 (53 %) |

- Die vier am 19.11. nicht erkannten Proben waren wenige Minuten alt (drei Skripte, eine exe) und
  standen noch nicht in der Hashliste, die K9 kurz vorher geladen hatte.
- **Heimvorteil:** Die Proben stammen aus derselben Quelle wie K9s Hashliste. Die Zahl „am Inhalt
  erkannt“ (YARA) ist die ehrlichere: 11 von 30, bei ausführbaren Fernsteuerungs-Trojanern gut (njRAT,
  Quasar, AsyncRAT, Remcos, Lumma), bei Skripten (js, vbs, ps1, hta) praktisch nichts.
- **ClamAV fehlte am 19.11.** (der Download des Installationspakets in der Sandbox brach ab); am 18.11.
  war es geladen und erkannte von 8 neuen Proben keine.
- Bei VirusTotal lieferte die Trend-Micro-Engine für vier Proben kein vollständiges Ergebnis (Fehler, Zeitüberschreitung oder leer);
  sie zählen dort als „nicht erkannt“.
- Nicht geprüft: die Verhaltenserkennung (Ransomware, Datendiebe, Angriffsketten) – dafür müssten Proben
  gestartet werden (`-Starten`, eigene Zustimmung, Sandbox ohne Ordner zum PC).

Ergebnisdateien: `Dokumente\Virenscanner-Sandbox-Ergebnis\vergleich-lauf2-8-proben` und
`vergleich-lauf3-30-proben`.

### 7.13 Vergleichstest mit gestarteten Proben (19.11.2026, Sandbox ohne Ordner zum PC)

Skript mit `-Starten`, Sandbox `k9-vergleich-starten.wsb`, Zustimmung des Nutzers mit der Zeile `starten`.
20 Proben (10 neue, 10 etwa eine Woche alte; exe, ps1, js, vbs, hta), K9 0.18.3 eingestellt wie auf dem
PC (Anhalten an, PowerShell-Protokollierung an), ClamAV geladen. Netzwerk dreifach gesperrt, nach
jeder Probe geprüft – es blieb aus. Ergebnis vom Bildschirm fotografiert (kein Ordner zum PC).

**Als Datei (vor dem Start):** 20 von 20 erkannt – alle über die Hashliste, 8 zusätzlich am Inhalt
(neu: 5 über YARA; älter: 3 über YARA/ClamAV). Trend-Micro-Engine bei VirusTotal: 12 von 20.

**Nach dem Start** (19 liefen wirklich; eine exe war für die Plattform ungültig), je 60 Sekunden:

| Was K9 meldete | Proben |
|---|---|
| echtes Verhalten: Autostart aus dem Benutzerordner (js AgentTesla), DNS-Abfrage einer bekannten Steuer-Adresse und Angriffskette (QuasarRAT), PowerShell mit verdächtigen Argumenten (hta), PowerShell-Skript lädt Code in den Speicher (ps1 AgentTesla), DNS-Abfrage einer Steuer-Adresse (js AsyncRAT) | 5 |
| nur „unsigniertes Programm aus dem Internet gestartet“ (kein Verhalten der Probe, aber eine Warnung beim Start) | 9 |
| nichts | 5 |

- Ohne Meldung nach dem Start blieben: ConnectWise (gültig signiertes Fernwartungsprogramm, das missbraucht
  wird), zwei js-Skripte, ein hta (leeres Fenster) und ein vbs (lief nicht: die Sandbox hat kein VBScript mehr).
- **Lücke:** Skripte aus dem Internet (js, vbs, hta über wscript/mshta) lösen beim Start keine
  Herkunftswarnung aus – die gibt es bisher nur für Programme (exe).
- **Grenzen des Tests:** kein Netzwerk (viele Proben tun ohne Steuerserver wenig), nur 60 Sekunden,
  eine leere Sandbox ohne Browserprofile und Dokumente – die Erkennung von Datendieben und Ransomware
  konnte deshalb nicht ansprechen und ist damit **nicht** geprüft. Keine Ransomware unter den Proben.

### 7.14 Skript aus dem Internet gestartet (19.11.2026, Sandbox offline, K9 0.20.0)

Elfter Lauf des Testplans (`k9-test-skriptherkunft.wsb`), nur harmlose Skripte mit von Hand
angehängtem Internet-Vermerk. **Bestanden, 8 von 8:**

| Test | Ergebnis |
|---|---|
| T1 `rechnung.js` über `wscript` | gemeldet (Hoch) |
| T2 `liste.js` über `cscript` | gemeldet (Hoch) |
| T3 `formular.hta` über `mshta` | gemeldet (Hoch) |
| T4 `einrichten.ps1` über `powershell -File` | gemeldet (Hoch) |
| T5 `start.bat` über `cmd /c` | gemeldet (Hoch) |
| T6 `rechnung.js` ein zweites Mal | keine zweite Meldung |
| T7 `eigenes.js` ohne Vermerk | keine Meldung |
| T8 Download-Adresse | ohne den Teil nach „?“ |

Damit ist die Lücke aus 7.13 (Skripte ohne Herkunftswarnung) geschlossen. Nicht geprüft: Skripte,
die mit relativem Pfad gestartet werden, und Archive, deren Packprogramm den Vermerk nicht weitergibt.

### 7.15 Schwerpunkt Datendiebe mit Koedern (19.11.2026, Sandbox ohne Ordner zum PC, K9 0.21.0)

Skript mit `-Schwerpunkt`, Sandbox `k9-vergleich-schwerpunkt.wsb`, Zustimmung des Nutzers mit den Zeilen
`starten` und `ransomware`. Dauer 12:38 bis 13:59 Uhr. Vor jedem Start Köder: Schein-Browserprofile,
Schein-Wallets, 160 Schein-Dokumente. Netzwerk dreifach gesperrt, je Probe geprüft – es blieb aus.

**Zwei Abweichungen vom Plan:**

- **Keine Ransomware:** MalwareBazaar beantwortete die Abfrage nach Ransomware-Proben mit „502 Bad
  Gateway“. Gelaufen sind nur 11 Datendiebe (LummaStealer 1, Vidar 2, Stealc 2, RedLineStealer 2,
  AgentTesla 2, SnakeKeylogger 2; eine zwölfte Probe ließ sich nicht laden). Ransomware in Aktion ist
  damit **weiter nicht geprüft**.
- **K9 ohne Hashlisten:** abuse.ch lehnte die große Liste ab („429, zu viele Abrufe“ nach mehreren
  Läufen am selben Tag). K9 musste die Proben am Inhalt und am Verhalten erkennen.

**Als Datei (ohne Hashliste):** 4 von 11 am Inhalt erkannt (YARA 3, ClamAV 3, teils beide).
Trend-Micro-Engine bei VirusTotal: 7 von 11. Die Zeile „K9 gesamt: 11“ in der Ausgabe dieses Laufs war
ein Zählfehler des Skripts (es zählte die Herkunftswarnung nach dem Start als Dateifund mit); er ist
behoben.

**Nach dem Start** (alle 11 liefen, je 120 Sekunden):

| Was K9 meldete | Proben |
|---|---|
| Zugriff auf Zugangsdaten (`INFOSTEALER:FIREFOX`, `INFOSTEALER:BRAVE`) und Angriffskette – eine AgentTesla-Probe | 1 |
| nur „unsigniertes Programm aus dem Internet gestartet“ | 10 |
| nichts | 0 |

Bei allen 11 blieben die 160 Köder-Dokumente unverändert (erwartet: Datendiebe verschlüsseln nicht).

**Einordnung:**

- Die eine Probe, die nachweislich an die Köder ging, wurde erkannt – mit zwei Speichern und als
  Angriffskette. Das ist der erste Nachweis der Datendieb-Erkennung an echter Schadsoftware.
- Für die übrigen zehn ist **nicht belegt**, ob sie die Köder überhaupt angefasst haben. LummaStealer,
  Vidar, Stealc und RedLine holen ihre Anweisungen üblicherweise erst vom Steuerserver; ohne Netzwerk
  tun sie vermutlich nichts. Der Test kann nicht unterscheiden zwischen „hat nichts gestohlen“ und
  „hat gestohlen, K9 hat es übersehen“. Dafür müsste K9 im Test zusätzlich jede Dateiöffnung der
  Köder mitschreiben – als nächster Schritt vorgesehen.
- Jede Probe löste mindestens die Herkunftswarnung beim Start aus.

### 7.16 Ransomware-Lauf, erster Versuch (19.11.2026, 14:06 bis 14:33 Uhr) - abgebrochen, ohne Aussage

Sandbox `k9-vergleich-ransomware.wsb`, 10 Proben, K9 0.21.1 ohne Hashlisten (abuse.ch 429).
Der Lauf brach nach der ersten Probe ab und zählt nicht. Zwei Fehler des Testskripts:

- **Falscher Alarm der Netzwerk-Prüfung:** Die erste Probe (RustyStealer) schaltete in der Sandbox
  einen Windows-Dienst ab, den `Get-NetAdapter` braucht. Die Prüfung stürzte ab („Cannot connect to
  CIM server“), das Skript wertete das als „Netzwerk wieder an“ und brach vorsichtshalber ab. Das
  Netzwerk war aus (Adapter entfernt, Firewall der Sandbox sperrte alles). Behoben: Die Prüfung
  versucht jetzt direkt, drei Adressen im Internet zu erreichen, und braucht keinen Windows-Dienst.
- **Falsche Auswahl:** Das Stichwort „ransomware“ lieferte bei MalwareBazaar überwiegend anderes
  (Datendiebe, Fernsteuerungs-Trojaner, Werbesoftware); echte Ransomware war nur eine der zehn
  Proben. Behoben: Auswahl über die Namen bekannter Ransomware-Familien, je Familie die neueste Probe
  (LockBit, MedusaLocker, BlackMatter, INC, Makop, Chaos, Conti, Stop, BlackBasta, Babuk …).

Verwertbar ist nur eine Beobachtung: Bei der einen gestarteten Probe, die K9 als Datei nicht kannte,
meldete K9 nach dem Start `KETTE:ANGRIFF`, `SKRIPT:AMSI-UMGEHUNG`, `SKRIPT:SCHUTZ-ABSCHALTEN` und die
Herkunftswarnung. **Ransomware in Aktion ist weiter nicht geprüft.**

### 7.17 Ransomware in Aktion: LockBit, eine Probe je Sandbox (19.11.2026)

Drei Läufe am selben Tag, K9 0.21.1 ohne Hashlisten, Netzwerk in der Sandbox dreifach gesperrt
(am Ende jeweils geprüft: nicht erreichbar), 160 Schein-Dokumente als Köder.

**Zweiter Sammellauf (14:46 Uhr, zehn Familien in einer Sandbox) – nach zwei Proben beendet:**
LockBit (Probe 1) lief vollständig; MedusaLocker (Probe 2) beendete das Testfenster und räumte den
Desktop der Sandbox ab, die Zusammenfassung ging verloren. K9 selbst lief weiter (Meldefenster noch
sichtbar). Folge: neuer Aufbau mit einer Probe je Sandbox und laufend gesichertem Stand.

**Einzellauf LockBit, Ransomware-Anhalten aus (15:50 bis 15:59 Uhr)** – Probe
`44f136cea982…` (erstmals gesehen 10.11.2026), Stand alle 5 Sekunden:

| Zeit nach dem Start | Schein-Dokumente unverändert | Neue K9-Meldungen |
|---|---|---|
| 5 s | 160 von 160 | `DOWNLOAD:UNSIGNIERT-GESTARTET` |
| 10 s | **0 von 160** | `RANSOMWARE:VERHALTEN`, `RANSOMWARE:WIEDERHERSTELLUNG`, `KETTE:ANGRIFF`, `INFOSTEALER:EDGE`, `AUTOSTART:UNSIGNIERT-BENUTZERORDNER` |
| 20 s | 0 von 160 | `EINSTELLUNG:SICHERHEIT` |
| 182 s (Ende) | 0 von 160 | – |

- **Als Datei** erkannte K9 die Probe ohne Hashliste **nicht** (kein YARA-Treffer; ClamAV war in
  diesem Lauf nicht installiert). Die Trend-Micro-Engine bei VirusTotal kennt sie.
- **Am Verhalten** erkannte K9 die Ransomware eindeutig – aber nicht früher als der Schaden: Alle 160
  kleinen Dateien waren innerhalb von weniger als fünf Sekunden verschlüsselt, im selben Fenster kam
  der Alarm. K9 hat hier **gemeldet, nicht verhindert**.
- `EINSTELLUNG:SICHERHEIT`: Die Probe veränderte die Einstellungsdatei von K9; der
  Manipulationsschutz wandte die Abschwächung nicht an und meldete sie.
- Die Probe lief bis zum Ende weiter (nichts wurde angehalten – so war die Variante eingestellt).

**Einzellauf LockBit, Ransomware-Anhalten an – nicht zustande gekommen:** MalwareBazaar gab die
Probe nicht mehr heraus („429 Too Many Requests“, auch nach vier Versuchen im Minutenabstand) –
vermutlich das Tageslimit für Probenabrufe nach den vielen Läufen des Tages. Der Vergleich
„Anhalten aus/an“ und die übrigen neun Familien stehen deshalb noch aus.

**Grenzen:** eine einzige Probe; 160 sehr kleine Dateien (rund 12 KB) sind in Sekunden verschlüsselt –
auf einem echten PC mit tausenden, größeren Dateien bleibt nach dem Alarm mehr zu retten, wie viel,
ist nicht gemessen. Die Messung hat ein Raster von 5 Sekunden.

### 7.18 Wie schnell ist K9 bei Ransomware? Messung mit harmlosem Testprogramm (19.11.2026)

Sandbox offline (`k9-test-ransomware-sim.wsb`), K9 0.22.0 (Entwicklungsstand), kein Schadprogramm:
`k9-testsim.exe` überschreibt 400 Schein-Dokumente (je rund 20 KB Text) in einem markierten
Testordner mit Zufallsdaten und hängt `.k9test` an, 40 Dateien pro Sekunde (10 Sekunden bis zum
Ende). Es liegt als unsigniertes Programm in „Downloads“. Gezählt wird alle halbe Sekunde.

**Erste Messung (16:35 Uhr) – deckte einen Fehler auf:** Im Durchgang „Anhalten an“ kam kein Alarm
und nichts wurde angehalten. Ursache laut Agent-Protokoll: Eine Sekunde vor dem Start hatte K9 einen
Alarm ohne Verdächtige ausgelöst – wegen der überschriebenen Dateien des Durchgangs davor, die nur
angefasst, nicht verändert worden waren. Nach einem Alarm blieb die Erkennung 20 Sekunden stumm; in
diese Pause fiel der Testangriff. Behoben: Es zählen nur Dateien, die in den letzten 15 Sekunden
geschrieben wurden, und nach einem Alarm wird sofort weitergezählt.

**Zweite Messung (16:50 bis 17:00 Uhr) mit der Korrektur:**

| Durchgang | Unverändert | Testprogramm | K9-Meldungen |
|---|---|---|---|
| R1 Anhalten aus | 0 von 400 | lief zu Ende | Ransomware-Alarm |
| R2 Anhalten an | **377 von 400** | angehalten nach 23 Dateien (unter 1 s) | Ransomware-Alarm |
| R3 Anhalten an, mit `vssadmin delete shadows` | **377 von 400** | angehalten nach 23 Dateien | Ransomware-Alarm, „Wiederherstellung wird gelöscht“ |
| R4 Anhalten an (Wiederholung von R2) | **365 von 400** | angehalten nach 35 Dateien | Ransomware-Alarm (zweimal) |

- Der Alarm kommt etwa 0,6 bis 1 Sekunde nach dem Start. Ohne Anhalten nützt er den Dateien nichts
  (R1); mit Anhalten bleiben 91 bis 94 % erhalten.
- R4: Beim ersten Alarm kannte K9 das eben gestartete Programm noch nicht (Alarm ohne Verdächtige);
  0,3 Sekunden später, nach den nächsten 12 Dateien, wurde es eingefroren. Genau dafür zählt K9 nach
  einem Alarm jetzt weiter. Warum die sofortige Abfrage der laufenden Programme das Programm beim
  ersten Mal nicht fand, ist noch offen.
- R3: Eingefroren hat zuerst die Dateierkennung des Agenten; der Dienst reagierte auf
  `vssadmin delete shadows` 1,3 Sekunden später (zweite Sicherung, nicht die schnellere).
- **Grenzen:** ein Testprogramm, keine echte Ransomware; feste Geschwindigkeit von 40 Dateien pro
  Sekunde (LockBit war im Test 7.17 schneller); nur Dateien in einem überwachten Ordner
  (Dokumente); je ein Lauf pro Einstellung.

### 7.19 Zehn Ransomware-Familien, je mit und ohne Anhalten (20.11.2026, 05:09 bis 08:00 Uhr)

Aufbau wie in 7.17: eine Probe je frischer Sandbox (`ransomware-reihe.ps1`), K9 0.23.0 ohne
Hashlisten und ohne ClamAV, 160 Schein-Dokumente, 3 Minuten Beobachtung, Stand alle 5 Sekunden.
Je Familie die neueste `.exe` bei MalwareBazaar; jede Probe zweimal: „Ransomware-Verdächtige
anhalten“ **aus** (Standard) und **an**. Alle 20 Sandboxen liefen bis zum Ende; das Netzwerk war
in jeder am Schluss nachweislich nicht erreichbar; im Übergabeordner lag jeweils nur `stand.txt`.

| Familie (Probe erstmals gesehen) | Als Datei erkannt | Unverändert, Anhalten aus | Unverändert, Anhalten an | Ransomware-Alarm |
|---|---|---|---|---|
| LockBit (10.11.) | nein | 0 von 160 | **104** | ja, dazu „Wiederherstellung wird gelöscht“ |
| MedusaLocker (30.10.) | nein | 0 | **138** | ja |
| BlackMatter (21.10.) | ja (YARA) | 0 | **150** | ja |
| BlackBasta (04.09.) | nein | 0 | **128** | ja, dazu „Wiederherstellung wird gelöscht“, Angriffskette |
| Babuk (29.08.) | nein | 0 | **106** | ja, dazu „Wiederherstellung wird gelöscht“ |
| **Conti** (24.09.) | nein | **0** | **0** | **nein – übersehen** |
| INC (20.10.) | nein | 160 | 160 | – (hat nichts verschlüsselt) |
| Makop (24.09.) | ja (YARA) | 160 | 160 | – (hat nichts verschlüsselt) |
| Chaos (24.09.) | ja (YARA) | 160 | 160 | – (hat nichts verschlüsselt) |
| Stop (21.09.) | nein | 160 | 160 | – (hat nichts verschlüsselt; Angriffskette und Autostart gemeldet) |

**Ergebnisse:**

- **Sechs Proben haben verschlüsselt.** Ohne Anhalten war bei allen sechs nach spätestens
  41 Sekunden jedes Schein-Dokument verändert.
- **Bei fünf davon schlug K9 Alarm**, meist innerhalb der ersten 5 bis 10 Sekunden. Mit
  eingeschaltetem Anhalten blieben dort 104 bis 150 von 160 Dateien erhalten (65 bis 94 %); nach dem
  Einfrieren ging in den restlichen Minuten nichts mehr verloren.
- **Conti wurde übersehen:** Alle 160 Dateien waren zwischen Sekunde 36 und 41 verändert, K9 meldete
  nur die Herkunftswarnung beim Start – keinen Ransomware-Alarm, und auch die sonst übliche Meldung
  über die veränderte K9-Einstellungsdatei fehlt. Dass gar keine Meldung mehr ankam, spricht dafür,
  dass der K9-Agent zu diesem Zeitpunkt nicht mehr arbeitete. Conti ist dafür bekannt, Programme zu
  beenden, die Dateien offen halten (über den Windows-„Restart Manager“), bevor es verschlüsselt –
  das würde den Agenten treffen. **Das ist eine Vermutung, kein Befund:** Ein Durchgang mit
  zusätzlichen Messwerten (laufen Agent und Dienst, Protokolle, Zustand der Dateien) kam am selben
  Tag nicht mehr zustande, weil MalwareBazaar die Probe nicht mehr herausgab (429).
- **Als Datei** erkannte K9 ohne Hashlisten 3 von 10 Proben am Inhalt (YARA).
- **Vier Proben verschlüsselten nichts** (vermutlich fehlendes Netzwerk oder erkannte Sandbox);
  sie sagen über die Erkennung nichts aus.

**Folgerungen:** „Ransomware-Verdächtige anhalten“ rettet bei erkannter Ransomware den größten Teil
der Dateien – ohne den Schalter nützt der Alarm den Dateien nichts. Die Erkennung sitzt aber im
Agenten, der mit Benutzerrechten läuft und von Schadsoftware beendet werden kann; eine Erkennung im
Dienst (läuft als System) wäre robuster und könnte genau das schreibende Programm benennen.

**Grenzen:** eine Probe je Familie, ein Lauf je Einstellung; 160 kleine Dateien (ein echter PC hat
tausende größere – dort bleibt anteilig mehr zu retten); Messraster 5 Sekunden; kein Netzwerk.

### 7.20 Ransomware-Erkennung im Dienst: Messung mit dem harmlosen Testprogramm (20.11.2026)

Sandbox offline (`k9-test-ransomware-sim.wsb`), K9 0.24.0, Testprogramm `k9-testsim.exe` wie in 7.18
(400 Schein-Dokumente, 40 Dateien pro Sekunde). Neu: die Erkennung im Dienst und ein fünfter
Durchgang, in dem der K9-Agent unmittelbar vor dem Testangriff beendet wird.

**Endstand (09:15 bis 09:26 Uhr):**

| Durchgang | Unverändert | Testprogramm | Wer hat angehalten |
|---|---|---|---|
| R1 Anhalten aus | 0 von 400 | lief zu Ende | – (Dienst meldet das Programm beim Namen) |
| R2 Anhalten an | **365** | angehalten nach rund 35 Dateien | Dienst, genau das Testprogramm |
| R3 Anhalten an, mit `vssadmin delete shadows` | **365** | angehalten | Dienst (Dateien), dazu „Wiederherstellung wird gelöscht“ |
| R4 Anhalten an, Wiederholung | **365** | angehalten | Dienst |
| R5 Anhalten an, **Agent vorher beendet** | **366** | angehalten | Dienst allein |

- In jedem Durchgang kam **eine** Meldung vom Dienst mit dem Namen des Programms; der Agent hielt
  seine eigene zurück („der Dienst hat bereits gemeldet“).
- R5 ist der Fall, der beim Test mit echter Ransomware vermutlich Conti durchließ (7.19): Ohne
  Agenten gab es bis Version 0.23.0 keine Erkennung. Jetzt bleibt das Ergebnis gleich.

**Fehler auf dem Weg dorthin** (beide vor dem Sichern gefunden und behoben):

1. Erste Fassung: Das Programm wurde erst gefunden, wenn seine Dateiöffnungen über die
   Ereignissitzung beim Dienst angekommen waren – bei beendetem Agenten nach 7 Sekunden (89 von 400
   Dateien erhalten). Behoben: Bei einem Verdacht lässt der Dienst die Puffer der Sitzung sofort
   ausliefern und sucht bis zu 20 Sekunden weiter.
2. Zweite Fassung: In zwei von vier Durchgängen wurde gar kein Programm gefunden (0 von 400). Die
   Regel „ein Programm zählt, wenn es ein Viertel der Dateien geöffnet hat“ scheiterte, weil die
   Öffnungen der neuesten Dateien immer noch unterwegs waren. Behoben: Es zählt, wer mindestens drei
   der Dateien geöffnet hat und mindestens halb so viele wie das Programm mit den meisten Öffnungen.

**Grenzen:** Testprogramm, keine echte Ransomware; ob Conti damit erkannt wird, ist noch nicht
geprüft (Nachlauf mit der echten Probe steht aus). Ein Angreifer mit Administratorrechten kann auch
den Dienst anhalten.

### 7.21 Weniger Verlust: Anhalten beim Start und frühere Schwelle (20.11.2026, K9 0.25.0)

Sandbox offline, Testprogramm wie in 7.20, sechs Durchgänge (14:02 bis 14:15 Uhr).

| Durchgang | 0.24.0 | 0.25.0 | Wer hat angehalten |
|---|---|---|---|
| R1 Anhalten aus | 0 von 400 | 0 | – |
| R2 unbekanntes Programm, Anhalten an | 365 | **383** | Dienst, nach 5 zugeordneten Dateien |
| R3 mit `vssadmin delete shadows` | 365 | **383** | Dienst |
| R4 Wiederholung | 365 | **383** | Dienst |
| R5 Agent vorher beendet | 366 | **382** | Dienst allein |
| R6 **bekanntes Programm** (K9-Testsignatur), wartet 8 s vor dem Überschreiben | – | **400** | Agent, beim Start (`anhalten`) |

- **Frühere Schwelle:** Für ein unsigniertes Programm aus „Downloads“ reichen 5 verschlüsselt
  aussehende Dateien, die es geöffnet hat. Der Verlust halbiert sich von rund 35 auf 17 bis 18 Dateien;
  der Rest ist die Zeit, bis die Dateiöffnungen über die Ereignissitzung beim Dienst ankommen.
- **Anhalten beim Start:** Das bekannte Programm wurde eingefroren, bevor es eine Datei anfasste.
  Der Agent prüft neue Programme einmal je Sekunde; ein Programm, das sofort loslegt, verliert in
  dieser Sekunde Dateien – echte Ransomware brauchte im Test 7.19 aber 5 bis 74 Sekunden.
- **Gefunden und behoben:** Je Angriff kamen zunächst zwei Meldungen des Dienstes im Abstand von
  0,1 Sekunden (das schon eingefrorene Programm wurde ein zweites Mal „angehalten“ und gemeldet).
  Der Dienst merkt sich jetzt, was er eingefroren hat.

**Grenzen:** Testprogramm statt echter Ransomware; „bekannt“ heißt hier die eingebaute Testsignatur,
nicht ein Treffer der Hashlisten; je ein Lauf.

### 7.22 Fehlalarm-Test: Entpacken gegen Verschlüsseln (20.11.2026, K9 0.26.0)

Sandbox offline, Testprogramm `k9-testsim.exe` (unsigniert, in „Downloads“), acht Durchgänge
(15:07 bis 15:23 Uhr). Neu sind R7 und R8.

| Durchgang | Unverändert | Testprogramm | K9 |
|---|---|---|---|
| R1 Anhalten aus | 0 von 400 | lief zu Ende | Ransomware-Alarm |
| R2 bis R4 Anhalten an | 383 | angehalten | Ransomware-Alarm (Dienst) |
| R5 Agent vorher beendet | 382 | angehalten | Ransomware-Alarm (Dienst allein) |
| R6 bekanntes Programm, wartet 8 s | 400 | beim Start angehalten | Testsignatur |
| **R7 harmlos:** 300 **neue** gepackte Dateien anlegen (wie Entpacken), nichts Vorhandenes anfassen | 400 | **lief zu Ende** | **keine Meldung** |
| **R8** verschlüsselte Kopie schreiben und Original löschen | 383 | angehalten | Ransomware-Alarm (Dienst) |

- R7 hätte mit dem Stand von 0.25.0 das Testprogramm nach 5 Dateien eingefroren (unsigniert, aus
  einem Benutzerordner, Dateien mit zufällig aussehendem Inhalt). Mit der neuen Regel bleibt es
  unbehelligt.
- R8 zeigt, dass die zweite Art von Ransomware (Kopie schreiben, Original löschen) über die
  gleichzeitigen Löschungen weiter erkannt wird – mit demselben Ergebnis wie das Überschreiben.

**Grenzen:** Geprüft ist nur das eigene Testprogramm, kein echtes Packprogramm. Ob echte Ransomware
mit der neuen Regel weiter erkannt wird, zeigt erst der nächste Lauf mit echten Proben: Die
Proben vom 20.11. haben die Schein-Dokumente an Ort und Stelle verändert, das spricht dafür. Ein
Programm, das beim Entpacken zugleich viele Dateien löscht, könnte weiterhin einen Alarm auslösen.

### 7.23 Bekanntes Programm, das sofort loslegt (20.11.2026, K9 0.26.1)

Derselbe Sandbox-Test mit einem neunten Durchgang (15:37 bis 15:54 Uhr); der Agent sieht jetzt
viermal je Sekunde nach neu gestarteten Programmen. R1 bis R8 wie in 7.22 (0 / 383 / 383 / 383 / 383 /
400 / 400 ohne Meldung / 382).

| Durchgang | Unverändert | Wer hat angehalten |
|---|---|---|
| R6 bekanntes Programm, wartet 8 s | 400 von 400 | Agent beim Start |
| **R9 bekanntes Programm, überschreibt sofort** (40 Dateien je Sekunde) | **392** | Agent beim Start, rund 0,2 Sekunden nach dem Start |

Ein Programm, das K9 kennt und das ohne jede Wartezeit loslegt, verliert bis zum Einfrieren 8
Dateien (vorher wäre es erst die Erkennung am Schaden gewesen: 17 bis 18). Echte Ransomware brauchte im
Test 7.19 mindestens 5 Sekunden bis zum ersten Schaden – dort bleibt nichts verloren.

### 7.24 Conti mit K9 0.30.0: K9 wird abgeschaltet, dann verschlüsselt (21.11.2026, 07:52 bis 08:01 Uhr)

Eine Probe in einer frischen Sandbox (`ransomware-reihe.ps1 -Familien Conti -Anhalten an`), Zustimmung
des Nutzers vom Tag und sein „starte“. K9 0.30.0 mit Agent und Dienst, „Ransomware-Verdächtige
anhalten“ an, ohne Hashlisten, 160 Schein-Dokumente, Netzwerk aus (am Ende nachweislich nicht
erreichbar). Dieselbe Probe wie am 20.11. (SHA-256 248cf7de…96209, erstmals gesehen 24.09.2026).

| Zeit nach dem Start | Schein-Dokumente heil | Agent | Dienst | K9-Meldung |
|---|---|---|---|---|
| 5 s | 160 von 160 | läuft | läuft | „unsigniertes Programm aus dem Internet gestartet“ |
| 10 bis 30 s | 160 | läuft | läuft | – |
| 36 s | 160 | **läuft nicht mehr** | läuft | – |
| 41 s | **0** | läuft nicht mehr | **läuft nicht mehr** | – |
| 46 s bis 3 min | 0 | – | – | – (die Probe hat sich beendet) |

**Ergebnis: 0 von 160 erhalten, kein Ransomware-Alarm.** Alle Dateien heißen danach `….qtox`
(Entropie 7,95), auch K9s Köderdateien und sogar das Protokoll des Dienstes.

**Was der Lauf belegt:** Conti beendet zuerst den K9-Agenten, wenige Sekunden später den
K9-Dienst und verschlüsselt erst dann – in weniger als fünf Sekunden. Die Vermutung aus 7.19 ist
damit bestätigt und reicht weiter: Auch die Erkennung im Dienst (seit 0.24.0) hilft nicht, wenn der
Dienst selbst beendet wird.

**Was er nicht belegt:** In der Windows-Sandbox läuft jedes Programm mit Administratorrechten. Auf
dem Test-PC startet ein normal geöffnetes Programm mit weniger Rechten; ob Conti den Dienst dort
beenden könnte, ist nicht getestet. Auf welchem Weg der Dienst beendet wurde (Bitte an Windows, ihn
zu stoppen, oder hartes Beenden), hat dieser Lauf nicht aufgezeichnet.

**Nebenbefund:** Das verschlüsselte Archiv der Probe wurde nicht auf den USB-Zwischenspeicher
übernommen („Datei wird von einem anderen Prozess verwendet“); der Stick blieb leer. Ursache war ein
Fehler im Testskript `ransomware-reihe.ps1`: Der erste Versuch traf das Archiv, während die Sandbox
es noch schrieb; dabei wurde die Begleitnotiz mit der Prüfsumme gelöscht, und der nächste Versuch
verwarf das gültige Archiv deshalb. Behoben am 21.11.2026 (bei gesperrter Datei wird nichts gelöscht
und zwei Sekunden später erneut versucht) – im nächsten Lauf zu bestätigen.

**Folge:** Seit Version 0.32.0 bemerkt der Dienst das Ende des Agenten sofort und wertet es als
kritischen Schritt der Angriffskette eines noch laufenden unsignierten Programms aus dem Internet;
mit „Kritische Programme anhalten“ wird dieses Programm eingefroren. Mit dem harmlosen Testprogramm
geprüft in 7.25 (erst mit Version 0.32.1 bestanden), mit Conti geprüft in 7.26 (160 von 160 heil).

### 7.25 Abwehr gegen das Abschalten von K9: Probeläufe mit dem harmlosen Testprogramm (21.11.2026)

**Aufbau (Durchgang R10 in `scripts/sandbox/sandbox-test-ransomware-sim.ps1`):** Windows-Sandbox
ohne Internet, „Kritische Programme anhalten“ an. Das harmlose Testprogramm `k9-testsim.exe` liegt
als `unbekannt2.exe` im Ordner Downloads und trägt die Kennzeichnung „aus dem Internet“ (ZoneId 3),
es ist nicht signiert. Es wartet nach dem Start 6 Sekunden und überschreibt dann 400 Testdateien.
Zwei Sekunden nach seinem Start beendet das Testskript den K9-Agenten von außen – das Muster von
Conti aus 7.24. Erwartet: Der Dienst hält das Programm an, bevor es eine Datei anfasst.

| Lauf | Zeit | Version | Dateien heil | Angehalten durch | Meldungen |
|---|---|---|---|---|---|
| 1 | 14:50 bis 14:57 Uhr | 0.32.0 | 388 von 400 | Ransomware-Schutz, nach 5 überschriebenen Dateien | Ransomware-Verdacht; Unsigniertes Programm aus dem Internet gestartet |
| 2 | 15:06 bis 15:13 Uhr | 0.32.1 | **400 von 400** | Angriffskette, Schritt „K9-Agent von außen beendet“ | Angriffskette; Unsigniertes Programm aus dem Internet gestartet |

**Lauf 1 – nicht bestanden.** Aus dem Protokoll des Dienstes (Zeiten der Sandbox, Sekunden nach
14:55 Uhr):

| Sekunde | Ereignis |
|---|---|
| 33,676 | „Selbstschutz: Agent (PID 3620) wurde von außen beendet“ – der Dienst sieht kein Programm aus dem Internet und erkennt keinen Zusammenhang |
| 33,900 | Erst jetzt meldet Windows dem Dienst den Start von `unbekannt2.exe` – 0,2 Sekunden zu spät, obwohl das Programm schon rund 2 Sekunden lief |
| 37,986 | Der Ransomware-Schutz hält das Programm an (5 von 5 Dateien); bis dahin sind 12 Dateien überschrieben |

Ursache: Windows liefert die Meldung über einen Programmstart mit Verzögerung. Die Abwehr aus 0.32.0
fragte nur die Programme ab, die der Dienst im Augenblick des Agent-Endes schon kannte.

**Behebung in 0.32.1:** Der Dienst merkt sich, wann der Agent von außen beendet wurde. Wird danach
der Start eines unsignierten Programms aus dem Internet bekannt, das vor diesem Zeitpunkt begonnen
hat, zählt der Schritt nachträglich.

**Lauf 2 – bestanden.** Sekunden nach 15:11 Uhr: 23,086 Agent von außen beendet; 23,640 Start von
`unbekannt2.exe` wird bekannt; 23,644 „Angriffskette (Kritisch) … K9-Agent von außen beendet“;
23,645 „Angehalten bis zur Entscheidung“. Zwischen dem Ende des Agenten und dem Anhalten lagen
0,56 Sekunden. Keine Datei wurde verändert.

**Grenzen:** Geprüft ist hier ein Programm, das 6 Sekunden wartet und den Dienst in Ruhe lässt
(Conti selbst: 7.26). Ein Programm, das Agent und Dienst im selben Augenblick beendet oder das
Windows nicht als „aus dem Internet“ kennzeichnet, wird so nicht aufgehalten.

### 7.26 Conti mit K9 0.32.1: angehalten, bevor der Dienst beendet wird (21.11.2026, 15:18 bis 15:27 Uhr)

**Aufbau:** wie 7.24 (dieselbe Probe, SHA-256 beginnt mit `248cf7de`, 160 Schein-Dokumente, Netzwerk
aus, „Kritische Programme anhalten“ an, 3 Minuten Beobachtung), diesmal mit K9 0.32.1.

| Zeit nach dem Start | 7.24 mit K9 0.30.0 | 7.26 mit K9 0.32.1 |
|---|---|---|
| +5 s | Meldung „Unsigniertes Programm aus dem Internet gestartet“ | dieselbe Meldung |
| +36 s | Agent beendet | Agent beendet |
| +41 s | Dienst beendet | Dienst läuft weiter, Probe ist eingefroren |
| +46 s | Verschlüsselung läuft | Agent läuft wieder (vom Dienst neu gestartet), Meldung „Angriffskette“ ist da |
| +76 s | – | Hinweis „Der K9-Agent wurde unerwartet beendet“ |
| Ende (+183 s) | **0 von 160** Dokumenten heil | **160 von 160** Dokumenten heil |

**Ergebnis:** Kein Dokument wurde verändert, auch die drei Köderdateien von K9 nicht. Der Dienst lief
bis zum Ende durch. Die Probe blieb als angehaltener Prozess stehen und wartete auf die
Entscheidung. Als Datei erkannte K9 die Probe vor dem Start weiterhin nicht.

**Zur Angabe „als Datei erkannt: nein“ (Nachtrag 21.11.2026, 19:05 Uhr):** Das liegt am Testaufbau,
nicht an K9. In der Sandbox werden mit Absicht nur die YARA-Regeln geladen, keine Hashlisten und
kein ClamAV – der Test soll zeigen, was K9 am Verhalten erkennt, wenn es die Datei nicht kennt. Auf
dem Test-PC ist die Hashliste von MalwareBazaar geladen (1.177.221 Einträge am 21.11.2026, 18:28 Uhr),
und der SHA-256-Wert dieser Probe steht darin (nachgeschlagen, ohne die Probe zu berühren). Dort
würde K9 die Datei also schon beim Ablegen oder vor dem Start als bekannte Schadsoftware melden.
Offen bleibt nur: Die YARA-Regeln allein erkennen diese Probe nicht.

**Einordnung:** Das ist **ein** Lauf mit **einer** Probe. Er zeigt, dass die Abwehr bei diesem Ablauf
von Conti rechtzeitig greift, weil Conti zwischen dem Ende des Agenten und dem Ende des Dienstes
rund fünf Sekunden braucht und K9 in unter einer Sekunde anhält. Eine Schadsoftware, die den Dienst
zuerst oder gleichzeitig beendet, die nicht als „aus dem Internet“ gekennzeichnet ist oder eine
gültige Signatur trägt, wird damit nicht aufgehalten.

**Offen:** Die Übergabe des Archivs an den Zwischenspeicher auf dem USB-Stick meldete erneut
„False“; der Stick blieb leer, die Probe wurde also wieder aus dem Internet geladen. Die Korrektur
vom Vormittag (7.24) hat das nicht behoben.

### 7.27 Schutz des Dienstes gegen das Beenden: drei Läufe mit dem harmlosen Testprogramm (21.11.2026, K9 0.33.0)

**Anlass:** In 7.26 wurde Conti nur gestoppt, weil es zuerst den Agenten beendet. Ein Schädling, der
zuerst den Dienst beendet, wäre durchgekommen.

**Aufbau:** wie 7.25 (Windows-Sandbox ohne Internet, „Kritische Programme anhalten“ an, harmloses
Testprogramm als unsigniertes Programm „aus dem Internet“, wartet 6 Sekunden und überschreibt dann
400 Testdateien). Drei Durchgänge, der Angriff jeweils 2 Sekunden nach dem Start:

- **R10** – der K9-Agent wird von außen beendet (wie 7.25),
- **R11** – `sc stop K9-Dienst`: Windows soll den Dienst stoppen,
- **R12** – der Prozess des Dienstes wird gewaltsam beendet.

| Lauf | Zeit | R10 Agent beendet | R11 Stopp über Windows | R12 Dienst gewaltsam beendet |
|---|---|---|---|---|
| 1 | 15:48 bis 15:58 Uhr | 400 von 400 | 400 von 400, **aber der Dienst endete trotzdem** | ungültig (Dienst lief nicht mehr): 377 von 400 |
| 2 | 16:02 bis 16:12 Uhr | 400 von 400 | 400 von 400, Dienst läuft weiter | **387 von 400** – Dienst nach 1 s wieder da, hält aber nicht an |
| 3 | 16:17 bis 16:27 Uhr | **400 von 400** | **400 von 400**, Dienst läuft weiter | **400 von 400** |

**Fehler aus Lauf 1:** Der Dienst lehnte den Stopp ab („Stopp des Dienstes ohne Ankündigung von k9
abgelehnt“), fror das Programm ein – und beendete sich im selben Augenblick doch („Dienst wird
beendet“). Ursache: Die verwendete Programmbibliothek für Windows-Dienste gibt nach dem ersten
Stopp-Befehl den Speicher der Befehlsbehandlung frei, weil sie annimmt, dass der Dienst dann endet.
Damit verschwand auch die Leitung, an der der Dienst auf sein Ende wartet. Behoben: Die
Befehlsbehandlung besitzt nichts mehr, was freigegeben werden könnte; das wird beim Start geprüft.
Das Testskript prüft seitdem vor jedem Durchgang, ob der Dienst läuft.

**Fehler aus Lauf 2:** Nach dem gewaltsamen Ende war der Dienst nach 1 Sekunde wieder da, stufte
seinen Start aber als „Start mit Windows“ ein, weil die Sandbox erst 8 Minuten lief (in den ersten
10 Minuten gilt jeder Start so) – und sah deshalb keinen Angriff. Das Programm überschrieb
13 Dateien, bis der Ransomware-Schutz anhielt. Behoben: Der Dienst merkt sich, zu welchem Start von
Windows sein letzter Lauf gehörte. Ist sein Kennzeichen noch gesetzt und Windows seitdem nicht neu
gestartet, wurde er gewaltsam beendet – egal wie lange Windows schon läuft.

**Lauf 3 – bestanden.** Aus dem Protokoll des Dienstes:

| Durchgang | Ablauf (Zeit der Sandbox) | Meldungen |
|---|---|---|
| R11 | 16:23:58,846 Stopp abgelehnt; 58,846 Angriffskette „Versuch, den K9-Dienst zu beenden“; 58,847 angehalten. Dienst danach: läuft | Angriffskette; „Ein Programm wollte den K9-Dienst beenden“; Unsigniertes Programm aus dem Internet gestartet |
| R12 | Dienst gewaltsam beendet; nach etwa 1 s neuer Dienst; 16:25:14,781 „der Dienst wurde gewaltsam beendet und neu gestartet – 1 laufendes Programm aus dem Internet“; 14,781 angehalten | Angriffskette „K9-Dienst gewaltsam beendet“; Unsigniertes Programm aus dem Internet gestartet |

**Beobachtung:** `sc stop` meldet Exitcode 0 und zeigt den Dienst als „RUNNING“ – Windows gibt die
Ablehnung nicht als Fehler an den Aufrufer weiter. Der Dienst läuft trotzdem weiter.

**Grenzen:** Nur das harmlose Testprogramm, das 6 Sekunden wartet. Nicht geprüft: ein Schädling, der
Agent und Dienst gleichzeitig beendet, der den Dienst erst deaktiviert und dann beendet, oder der
schon in der ersten Sekunde verschlüsselt; ebenso wenig echte Ransomware gegen 0.33.0.

### 7.28 Abwehr ohne die Kennzeichnung „aus dem Internet“: zwei Läufe mit dem harmlosen Testprogramm (21.11.2026, K9 0.34.0)

**Anlass:** Die Abwehr aus 7.25 bis 7.27 griff nur bei Programmen, die Windows als „aus dem
Internet“ kennzeichnet. Diese Kennzeichnung fehlt bei Programmen, die aus einem Archiv entpackt oder
von einem USB-Stick kopiert wurden. Seit 0.34.0 beginnt eine Angriffskette auch bei einem
unsignierten Programm, dessen Datei höchstens 24 Stunden alt ist und in einem Benutzerordner liegt,
und bei einem unsignierten Programm von einem Wechseldatenträger.

**Aufbau:** wie 7.27, mit zwei neuen Durchgängen, in denen das Testprogramm **keine**
Internet-Kennzeichnung trägt (frisch in den Ordner Downloads kopiert):

- **R13** – der K9-Agent wird 2 Sekunden nach dem Start beendet,
- **R14** – der K9-Dienst wird 2 Sekunden nach dem Start gewaltsam beendet (im selben Lauf zum
  zweiten Mal, nach R12).

| Lauf | Zeit | R10 | R11 | R12 | R13 ohne Kennzeichnung, Agent beendet | R14 ohne Kennzeichnung, Dienst gewaltsam beendet |
|---|---|---|---|---|---|---|
| 1 | 16:38 bis 16:51 Uhr | 400 | 400 | 400 | **400 von 400** | **378 von 400** – Dienst kam nicht rechtzeitig zurück |
| 2 | 16:54 bis 17:07 Uhr | 400 | 400 | 400 | **400 von 400** | **400 von 400** |

**Fehler aus Lauf 1:** Windows startete den Dienst nach dem ersten gewaltsamen Ende (R12) nach
1 Sekunde neu, nach dem zweiten (R14) aber erst nach 60 Sekunden – so war es für wiederholte
Abstürze eingestellt. In dieser Lücke überschrieb das Testprogramm 22 Dateien, bis der
Ransomware-Schutz des Agenten anhielt. Ein Angreifer hätte den Dienst also nur zweimal beenden
müssen. Behoben: auch der zweite Neustart nach 1 Sekunde, ab dem dritten am selben Tag nach
5 Sekunden.

**Lauf 2 – bestanden.** R13: Meldung „Angriffskette: unbekannt5.exe (neu im Benutzerordner) –
K9-Agent von außen beendet“, angehalten. R14: Dienst nach 1 Sekunde wieder da, „der Dienst wurde
gewaltsam beendet und neu gestartet – 1 laufendes verdächtiges Programm“, Angriffskette „K9-Dienst
gewaltsam beendet“, angehalten; dazu der Hinweis „Der K9-Dienst wurde neu gestartet“.

**Grenzen:** Der Fall „Wechseldatenträger“ ist nur durch Programmtests abgedeckt, nicht in der
Sandbox (dort gibt es keinen USB-Stick). Nicht geprüft ist, wie oft die neue Regel im Alltag bei
harmlosen Programmen greift – sie meldet erst, wenn zu einem neuen unsignierten Programm ein
kritischer oder hoher Schritt dazukommt. Echte Ransomware wurde gegen 0.34.0 nicht getestet.

### 7.29 LockBit, BlackBasta und Babuk gegen K9 0.35.2 – und was daraus folgte (21.11.2026)

**Frage:** Helfen die Neuerungen vom 21.11. (Abwehr gegen das Abschalten von K9, Schutz des
Dienstes, Ketten ohne Internet-Kennzeichnung) auch gegen die Familien, die im Test 7.19 Dateien
verschlüsselt haben?

**Aufbau:** wie 7.19 und 7.26 – je Familie eine frische Sandbox, dieselbe Probe wie am 20.11.,
160 Schein-Dokumente, Netzwerk aus, „Kritische Programme anhalten“ und „Ransomware-Verdächtige
anhalten“ an, 3 Minuten Beobachtung. Hashlisten und ClamAV sind in der Sandbox mit Absicht nicht
geladen (siehe Nachtrag in 7.26).

| Familie | Zeit | 20.11. (7.19) | 21.11. mit 0.35.2 | Erster Schaden | Wichtige Meldungen |
|---|---|---|---|---|---|
| LockBit | 19:28 bis 19:37 Uhr | 104 von 160 | **105 von 160** | nach 10 s | Ransomware-Verdacht, „Wiederherstellung wird gelöscht“ |
| BlackBasta | 19:37 bis 19:46 Uhr | 128 von 160 | **128 von 160** | nach 5 s | Ransomware-Verdacht, Angriffskette, „Wiederherstellung wird gelöscht“ |
| Babuk | 19:46 bis 19:55 Uhr | 106 von 160 | **120 von 160** | nach 36 s | „Wiederherstellung wird gelöscht“ nach 30 s, dann Ransomware-Verdacht, Angriffskette |

**Ergebnis: keine Verbesserung.** Diese drei Familien greifen K9 nicht zuerst an, sondern
verschlüsseln sofort. Gestoppt hat sie wie am 20.11. der Ransomware-Schutz, nachdem 32 bis 55
Dokumente verloren waren. Die Abweichungen zum Vortag (1 und 14 Dateien) sind bei je einem Lauf
nicht von Zufall zu unterscheiden. Agent und Dienst liefen in allen drei Läufen bis zum Ende.

**Beobachtung bei Babuk:** K9 meldete den Versuch, die Wiederherstellungsdaten zu löschen, sechs
Sekunden **vor** der ersten verschlüsselten Datei – das auslösende Programm lief trotzdem weiter.
Eigentlich friert K9 in diesem Fall das Programm ein, das den Löschbefehl gestartet hat. Vermutete
Ursache: Babuk startet den Befehl über ein kurzlebiges `cmd.exe`. Windows meldet einen Programmstart
ein bis zwei Sekunden verspätet; dann ist `cmd.exe` schon beendet, und K9 fand über die laufenden
Programme keinen Weg mehr zum eigentlichen Programm. Das Protokoll des Dienstes wird in diesem
Testaufbau nicht mitkopiert, die Ursache ist deshalb aus dem Ablauf geschlossen, nicht abgelesen.

**Behebung in 0.36.0:** Der Dienst geht den Weg nach oben jetzt über seine eigenen Aufzeichnungen
der Programmstarts (auch über beendete Zwischenschritte hinweg). Zusätzlich ist „Wiederherstellungs-
daten sollen gelöscht werden“ ein neuer kritischer Schritt der Angriffskette.

**Nachweis mit dem harmlosen Testprogramm (20:03 bis 20:16 Uhr, K9 0.36.0, Durchgang R15):** Das
Testprogramm (unsigniert, „aus dem Internet“) lässt über `cmd.exe` den harmlosen Löschbefehl für eine
nicht vorhandene Schattenkopie ausführen und überschreibt sechs Sekunden später 400 Dateien.
Ergebnis: **400 von 400 heil.** Protokoll (Zeit der Sandbox): 20:14:33,998 Start bekannt; 34,008 „Wiederherstellung wird
sabotiert – angehalten“; 34,010 Angriffskette „… Skript-Programm gestartet – cmd.exe,
Wiederherstellungsdaten sollen gelöscht werden – vssadmin.exe“. Die Durchgänge R10 bis R14 liefen im
selben Lauf erneut mit je 400 von 400.

**Was das nicht zeigt:** Es gibt keinen Vergleichslauf von R15 mit der alten Version. Der Lauf mit
Babuk selbst gegen 0.36.0 folgt in 7.30 (160 von 160 heil). Für LockBit und BlackBasta siehe 7.31 (LockBit wird gestoppt, BlackBasta nicht).

**USB-Zwischenspeicher:** Der Grund für den leeren Stick ist jetzt sichtbar („Archiv seit
5 Versuchen nicht lesbar – IOException: … wird bereits von einem anderen Prozess verwendet“). Das
Skript öffnet die Datei seitdem mit voller Freigabe und kopiert statt zu verschieben. Bestätigt im
Lauf 7.30.

### 7.30 Babuk gegen K9 0.36.0: beim Löschversuch angehalten (21.11.2026, 20:21 bis 20:29 Uhr)

**Aufbau:** wie 7.29, dieselbe Probe (SHA-256 beginnt mit `197fb4b7`), diesmal K9 0.36.0.

| Zeit nach dem Start | 7.29 mit K9 0.35.2 | 7.30 mit K9 0.36.0 |
|---|---|---|
| +5 s | „Unsigniertes Programm aus dem Internet gestartet“ | dieselbe Meldung |
| +23 bis +30 s | „Wiederherstellung wird gelöscht“ – Probe läuft weiter | „Wiederherstellung wird gelöscht“ **und** „Angriffskette“ – Probe eingefroren |
| +36 s | erste Dokumente verschlüsselt | – |
| Ende (+183 s) | **120 von 160** Dokumenten heil | **160 von 160** Dokumenten heil |

**Ergebnis:** Kein Dokument wurde verändert. Agent und Dienst liefen bis zum Ende, die Probe blieb
als angehaltener Prozess stehen. Damit ist die in 7.29 nur vermutete Ursache bestätigt: Mit der
Suche über die aufgezeichneten Programmstarts findet K9 den Auslöser und hält ihn rechtzeitig an.

**Einordnung:** ein Lauf, eine Probe. Die Abwehr wirkt bei Ransomware, die vor dem Verschlüsseln
die Wiederherstellungsdaten löscht. LockBit und BlackBasta gegen 0.36.0: siehe 7.31.

**USB-Zwischenspeicher – bestätigt:** „Archiv an den Zwischenspeicher übergeben: True“, auf dem Stick
lag danach das verschlüsselte Archiv (66 KB) mit seiner Begleitnotiz. Die Korrektur aus 7.29 wirkt.
Der Zwischenspeicher wurde nach dem Lauf um 20:31 Uhr geleert (0 Dateien übrig).

### 7.31 LockBit und BlackBasta gegen K9 0.36.0 (21.11.2026, 20:34 bis 21:10 Uhr)

**Aufbau:** wie 7.29, dieselben Proben, K9 0.36.0. BlackBasta lief dreimal.

| Familie | Lauf | 0.35.2 (7.29) | 0.36.0 | Angehalten durch |
|---|---|---|---|---|
| LockBit | 20:34 bis 20:42 Uhr | 105 von 160 | **160 von 160** | Angriffskette / „Wiederherstellung wird gelöscht“, rund 10 s nach dem Start, vor der ersten Verschlüsselung |
| BlackBasta | 1: 20:42 bis 20:51 Uhr | 128 von 160 | **35 von 160** | Ransomware-Schutz des Agenten |
| BlackBasta | 2: 20:53 bis 21:01 Uhr | | **128 von 160** | Ransomware-Schutz des Agenten, 0,3 s später zusätzlich der Dienst |
| BlackBasta | 3: 21:01 bis 21:10 Uhr | | **128 von 160** | wie Lauf 2 |

**LockBit:** vollständig gestoppt. LockBit löscht zuerst die Wiederherstellungsdaten und beginnt
danach zu verschlüsseln; mit 0.36.0 friert K9 es in dieser Lücke ein. Die Einschätzung aus 7.29
(„davon ist wenig zu erwarten“) war für LockBit falsch.

**BlackBasta:** unverändert. BlackBasta verschlüsselt in der ersten Sekunde nach dem Start, noch
bevor es die Wiederherstellungsdaten löscht. Aus dem Dienst-Protokoll von Lauf 2 (Zeit der Sandbox):
20:58:22,149 Agent hält die Probe an (Ransomware-Verdacht); 22,367 Angriffskette (Hoch); 22,442
„Wiederherstellung wird sabotiert – angehalten“; 22,445 Angriffskette (Kritisch). Der
Ransomware-Schutz ist hier also schneller als die neue Abwehr; bis dahin sind 32 Dokumente
verloren. In vier von fünf Läufen (20.11. und 21.11.) waren es genau 128 von 160.

**Der Ausreißer (Lauf 1, 35 von 160) ist nicht erklärt.** In diesem Lauf fehlte das Dienst-Protokoll
noch im Ergebnis (das Testskript las bis dahin nur die neueste Protokolldatei, und das war immer die
des Agenten; seit 20:52 Uhr sammelt es Warnungen und Fehler aus allen Protokollen). Der Agent hielt
die Probe auch in Lauf 1 an, nur waren da schon 125 Dokumente verschlüsselt. Zwei Wiederholungen
mit derselben Version ergaben wieder 128; ein Zusammenhang mit der Änderung in 0.36.0 ist damit
unwahrscheinlich, aber nicht ausgeschlossen. Es zeigt: Gegen Ransomware, die sofort verschlüsselt,
hängt der Schaden an Bruchteilen einer Sekunde und schwankt.

**Stand über alle getesteten Familien, die verschlüsseln (je eine Probe, K9 0.36.0 bzw. 0.32.1):**

| Familie | Dokumente heil | Gestoppt durch |
|---|---|---|
| Conti | 160 von 160 (7.26) | Abwehr gegen das Abschalten von K9 |
| Babuk | 160 von 160 (7.30) | Löschversuch der Wiederherstellung |
| LockBit | 160 von 160 (7.31) | Löschversuch der Wiederherstellung |
| BlackBasta | 128, 128, 35 von 160 (7.31) | Ransomware-Schutz, zu spät für die ersten Dokumente |
| MedusaLocker, BlackMatter | 138 und 150 von 160 (7.19, alte Version) | nicht erneut getestet |

**Offen:** ein schnellerer Ransomware-Schutz für Programme, die sofort verschlüsseln (BlackBasta);
MedusaLocker und BlackMatter gegen die neue Version. Der USB-Zwischenspeicher wurde nach dem
letzten Lauf geleert.

**Beobachtung am Rande:** Dieselbe Probe wird von mehreren Meldungen angehalten (Agent zweimal,
Dienst dreimal). Ob sie nach einer einzelnen „Freigabe“ sofort weiterläuft oder erst, wenn alle
Meldungen entschieden sind, ist nicht geprüft.

### 7.32 Früher Stopp für Programme, die sofort verschlüsseln: Messung mit dem harmlosen Testprogramm (21.11.2026, K9 0.37.0)

**Anlass:** BlackBasta (7.31) verschlüsselt in der ersten Sekunde. Zwei Maßnahmen in 0.37.0: eine
zweite Köderdatei, die im Ordner ganz vorne steht, und ein früher Stopp – läuft ein neues
unsigniertes Programm, hält der Agent es nach 2 statt 12 verschlüsselt aussehenden Dateien an.

**Aufbau:** Durchgänge R16 und R17 in `sandbox-test-ransomware-sim.ps1`: Das harmlose Testprogramm
(unsigniert; R16 „aus dem Internet“, R17 ohne Kennzeichnung, neu im Ordner Downloads) überschreibt
sofort nach dem Start 400 Testdateien, 40 je Sekunde. Vergleichswert aus früheren Läufen mit
demselben Tempo: 388 von 400 heil (7.25, Lauf 1).

| Lauf | Zeit | Stand | R16 | R17 | Zuerst angehalten durch |
|---|---|---|---|---|---|
| 1 | 21:23 bis 21:39 Uhr | Schwelle 2 statt 12, Wartezeit vor der Prüfung wie bisher (Agent 250 ms, Dienst 150 ms) | 389 von 400 | 388 von 400 | Dienst (5 bzw. 12 Dateien), 0,1 s vor dem Agenten |
| 2 | 21:52 bis 22:07 Uhr | zusätzlich Wartezeit verkürzt (Agent 100 ms, Dienst 80 ms) | **393 von 400** | **392 von 400** | Agent, 0,06 bzw. 0,24 s vor dem Dienst |

**Ergebnis:** Die niedrigere Schwelle allein brachte nichts (389 statt 388). Verloren gehen die
Dateien nicht beim Zählen, sondern in der Wartezeit zwischen der Änderung einer Datei und ihrer
Prüfung. Mit der verkürzten Wartezeit gehen bei 40 Dateien je Sekunde 7 bis 8 statt 11 bis 12
Dateien verloren – rund ein Drittel weniger. Die Durchgänge R10 bis R15 liefen in beiden Läufen
wieder mit je 400 von 400.

**Was fehlt:** die Messung mit BlackBasta selbst. Sie war für denselben Abend geplant; MalwareBazaar
lehnte den Abruf der Probe aber zweimal ab („429 Too Many Requests“, 21:39 und 21:43 Uhr). Der
USB-Zwischenspeicher war nach 7.31 geleert worden – sonst hätte die Probe dort gelegen. Ob die zweite
Köderdatei bei BlackBasta früher getroffen wird und wie viele Dokumente mit 0.37.0 heil bleiben, ist
deshalb offen. Das Testprogramm kann die Köderdatei nicht prüfen (es fasst nur Dateien seines
Testordners an).

**Einordnung:** Eine kleine Verbesserung, kein Durchbruch. Ein Programm, das sofort und schnell
verschlüsselt, kostet weiterhin die ersten Dateien; verlässlich hilft dagegen nur, was vor dem
Start greift (Hashlisten, YARA, ClamAV, Trend Micro) oder danach rettet (Schattenkopien, Sicherung).

### 7.33 BlackBasta gegen K9 0.37.0 und 0.37.1: eine Verschlechterung und ihre Behebung (22.11.2026, 02:50 bis 03:32 Uhr)

**Aufbau:** wie 7.31, dieselbe Probe. Ein erster Versuch um 00:45 Uhr scheiterte am Abruflimit von
MalwareBazaar („429“, vier Versuche); es lief keine Schadsoftware.

| Version | Lauf | Dokumente heil | Was K9 zuerst bemerkte |
|---|---|---|---|
| 0.36.0 (7.31) | drei Läufe | 35, 128, 128 | Ransomware-Verdacht (viele Dateien) |
| **0.37.0** | 02:50 bis 02:59 Uhr | **31 von 160** | Köderdatei verändert |
| **0.37.0** | 02:59 bis 03:07 Uhr | **43 von 160** | Köderdatei verändert |
| **0.37.1** | 03:14 bis 03:23 Uhr | **128 von 160** | Köderdatei verändert |
| **0.37.1** | 03:23 bis 03:32 Uhr | **128 von 160** | Köderdatei verändert |

**0.37.0 war gegen BlackBasta schlechter als die Version davor.** Die neue Köderdatei am
Ordneranfang wurde wie beabsichtigt als Erstes getroffen – und genau das bremste K9 aus: Die
Dateiüberwachung des Agenten las eine berührte Köderdatei sofort; war sie gesperrt (BlackBasta
verschlüsselte sie gerade), wartete sie bis zu fünfmal 0,2 Sekunden und prüfte in dieser Zeit keine
andere Datei. Bei einem Angriff, der in gut einer Sekunde durch ist, kostete das rund 90 weitere
Dokumente. Derselbe Mechanismus erklärt sehr wahrscheinlich den Ausreißer aus 7.31 (35 von 160 mit
0.36.0): Dort gab es nur die Köderdatei am Ordnerende, sie wurde in jenem Lauf offenbar früh
getroffen.

**Behebung in 0.37.1:** Die Überwachung wartet nie mehr auf eine Köderdatei (ein Blick; ist sie
gesperrt, 0,1 Sekunden später noch einer, währenddessen läuft alles andere weiter). Bei jedem
Ransomware-Alarm wird ein neues unsigniertes Programm als Allererstes angehalten – vor dem Warten
auf den Dienst und vor der Prüfung der Signaturen aller übrigen Programme.

**Ergebnis mit 0.37.1:** zweimal 128 von 160 – wieder der Stand von 0.36.0, nicht besser. Aus dem
Protokoll von Lauf 1 (Zeit der Sandbox): 03:19:55,165 Agent hält die Probe an (Köderdatei verändert);
55,313 der Dienst erfährt vom Start der Probe; 55,350 „Wiederherstellung wird sabotiert –
angehalten“. BlackBasta verschlüsselt zuerst den Ordner Desktop (32 Test-Dokumente und die beiden
Köderdateien) und ist damit fertig, bevor K9 die erste Änderung überhaupt prüfen kann.

**Was das zeigt:**

- Die zweite Köderdatei und der frühe Stopp haben gegen BlackBasta **keinen messbaren Nutzen**
  gebracht; der Gewinn aus 7.32 (harmloses Testprogramm, 392 statt 388 von 400) ist klein und kam
  von der kürzeren Wartezeit.
- Die erste Fassung hat geschadet. Gemerkt wurde das nur, weil mit echter Ransomware nachgemessen
  wurde – mit dem harmlosen Testprogramm war es nicht zu sehen, weil das keine Köderdatei anfasst.
- Gegen einen Verschlüsseler dieser Geschwindigkeit bleiben die ersten rund 30 Dokumente verloren.

**Offen:** ein harmloses Testprogramm, das auch eine Köderdatei sperrt und verändert (damit ein
solcher Fehler ohne echte Ransomware auffällt); MedusaLocker und BlackMatter gegen die neue Version.
Der USB-Zwischenspeicher wurde nach dem letzten Lauf geleert.

### 7.34 Gesperrte Köderdatei mit dem harmlosen Testprogramm nachgestellt (22.11.2026, 03:48 bis 04:05 Uhr, K9 0.38.0)

**Anlass:** Der Fehler aus 7.33 (K9 wartete auf die gesperrte Köderdatei) fiel nur mit echter
Ransomware auf. Das harmlose Testprogramm kann jetzt dasselbe: Mit `--koeder <Datei> --sperren-ms N`
öffnet es eine Köderdatei von K9 ohne Freigabe für andere, überschreibt sie und hält sie N
Millisekunden offen, während es schon die Testdateien überschreibt. Erlaubt ist dafür nur eine Datei,
die genau wie eine K9-Köderdatei heißt.

| Durchgang | Dateien heil (von 400) |
|---|---|
| R10 bis R15 (wie 7.29) | je 400 |
| R16 legt sofort los, „aus dem Internet“ | 394 |
| R17 legt sofort los, ohne Kennzeichnung | 394 |
| **R18 sperrt zuerst eine Köderdatei 0,8 s lang und legt sofort los** | **392** |

**Ergebnis:** Mit gesperrter Köderdatei hält K9 das Programm genauso schnell an wie ohne (392 gegen
394 – im Rahmen der Schwankung der Läufe davor, 392 bis 393). Das Warten auf die Köderdatei ist weg.

**Einschränkung:** Es gibt keinen Gegenlauf von R18 mit 0.37.0. Dass R18 den Fehler von damals
tatsächlich sichtbar gemacht hätte, ist also nicht gezeigt – nur, dass die aktuelle Version mit
diesem Muster kein Problem hat.

**Nebenbefund, behoben:** 20 Sekunden nach R18 meldete der Agent „Köderdatei wurde verändert“ und
nannte als Verdächtigen den K9-Dienst selbst (er war wenige Minuten zuvor in R14 neu gestartet
worden und zählte deshalb als „kürzlich gestartetes Programm“). Angehalten wurde er nicht – K9 hält
sich nie selbst an –, aber die Meldung war irreführend. Eigene Programme von K9 stehen jetzt nicht
mehr unter den Verdächtigen.

**Freigabe (ebenfalls 0.38.0):** Dass eine Freigabe ein mehrfach angehaltenes Programm ganz
freigibt, ist durch einen Programmtest belegt (Hilfsprozess dreimal angehalten, einmal freigegeben:
Zähler von 3 auf 0), nicht durch einen Klick im Dashboard.

### 7.35 MedusaLocker und BlackMatter gegen K9 0.38.0 (22.11.2026, 04:13 bis 04:30 Uhr)

**Aufbau:** wie 7.29, dieselben Proben wie am 20.11. (7.19), K9 0.38.0, „Kritische Programme
anhalten“ und „Ransomware-Verdächtige anhalten“ an.

| Familie | 20.11. (7.19) | 22.11. mit 0.38.0 | Angehalten durch |
|---|---|---|---|
| MedusaLocker | 138 von 160 | **159 von 160** | Köderdatei verändert – 15 Sekunden nach dem Start, nach dem ersten verschlüsselten Dokument |
| BlackMatter | 150 von 160 | **160 von 160** | „Bekannte Schadsoftware gestartet“ (YARA-Regel), 0,4 Sekunden nach dem Start |

**MedusaLocker:** Hier hat die zweite Köderdatei am Ordneranfang (seit 0.37.0) gewirkt: MedusaLocker
traf sie fast als Erstes, der Agent hielt die Probe sofort an. Ein Dokument war bis dahin
verschlüsselt, am 20.11. waren es 22. Eine Minute nach dem Anhalten startete eine Kopie der Probe
unter `AppData\Roaming\svhost.exe` (K9 meldete auch diesen Start); bis zum Ende der Beobachtung
verschlüsselte sie nichts weiter.

**BlackMatter:** Die YARA-Regeln erkennen diese Probe als Datei. K9 hielt sie beim Start an, bevor
sie etwas tun konnte. Am 20.11. gingen trotz derselben Erkennung zehn Dokumente verloren; seit
0.26.1 wird ein bekanntes Programm, das sofort loslegt, schneller angehalten (7.23).

**Stand über alle sechs Familien, die im Test verschlüsseln** (je eine Probe, 160 Dokumente,
aktuelle Version; in der Sandbox ohne Hashlisten und ClamAV):

| Familie | Am 20.11. | Jetzt | Gestoppt durch |
|---|---|---|---|
| Conti | 0 | 160 | Abwehr gegen das Abschalten von K9 (0.32.1) |
| Babuk | 106 | 160 | Löschversuch der Wiederherstellung (0.36.0) |
| LockBit | 104 | 160 | Löschversuch der Wiederherstellung (0.36.0) |
| BlackMatter | 150 | 160 | als Datei erkannt, beim Start angehalten |
| MedusaLocker | 138 | 159 | Köderdatei am Ordneranfang (0.37.0) |
| BlackBasta | 128 | 128 | Ransomware-Schutz – zu spät für den ersten Ordner |

**Einordnung:** je ein Lauf mit einer Probe (BlackBasta mehrere). Die Zahlen zeigen, dass die
Änderungen vom 21. und 22.11. bei fünf von sechs Familien wirken; sie sind kein Beweis für andere
Proben oder Familien. Der USB-Zwischenspeicher wurde nach dem Lauf geleert.

### 7.36 Schalter „neue-programme“: BlackBasta wird beim Start angehalten (22.11.2026, 04:59 bis 05:37 Uhr, K9 0.39.0)

**Anlass:** BlackBasta blieb als einzige Familie bei 128 von 160 Dokumenten (7.33); es
verschlüsselt, bevor K9 die erste Änderung prüfen kann. Der neue Schalter `neue-programme`
(Standard: aus) hält ein unsigniertes Programm, das Windows als „aus dem Internet“ kennzeichnet,
schon beim Start an, bis der Nutzer es freigibt.

**Harmloses Testprogramm (04:59 bis 05:19 Uhr):**

| Durchgang | Dateien heil (von 400) |
|---|---|
| R10 bis R15 | je 400 |
| R16 legt sofort los, 40 Dateien je Sekunde, Schalter aus | 394 |
| R17 dasselbe ohne Internet-Kennzeichnung, Schalter aus | 391 |
| R18 sperrt zuerst eine Köderdatei, Schalter aus | 394 |
| **R19 wie R16, Schalter an** | **399** |
| **R20 Schalter an, 200 Dateien je Sekunde** | **400** |

Mit dem Schalter meldet der Agent „Neues unsigniertes Programm aus dem Internet – angehalten bis zur
Freigabe“; der Dienst erfährt vom Start erst rund eine Sekunde später (04:16:35,359 gegen 36,357 Uhr
Weltzeit im Protokoll). In R19 ging eine Datei verloren, in R20 keine.

**BlackBasta, zweimal, Schalter an (05:19 bis 05:36 Uhr):**

| Lauf | Dokumente heil | Angehalten |
|---|---|---|
| 1 | **160 von 160** | beim Start; Meldungen „Neues unsigniertes Programm aus dem Internet angehalten“ und „Unsigniertes Programm aus dem Internet gestartet“ |
| 2 | **160 von 160** | ebenso |

BlackBasta kam in beiden Läufen nicht dazu, eine Datei anzufassen: kein Ransomware-Verdacht, kein
Löschversuch der Wiederherstellung, keine Angriffskette – die Probe stand von Anfang an.

**Stand über alle sechs Familien** (je eine Probe, 160 Dokumente): Conti 160, Babuk 160, LockBit 160,
BlackMatter 160, MedusaLocker 159, BlackBasta 128 ohne den Schalter und **160 mit dem Schalter**.

**Grenzen:**

- Der Schalter ist nach der Installation **aus**. Ohne ihn bleibt BlackBasta bei 128.
- Er hält nur Programme an, die als „aus dem Internet“ gekennzeichnet und unsigniert sind. Die
  Proben tragen diese Kennzeichnung, weil das Testskript sie so ablegt, wie ein Browser es tut. Eine
  Probe aus einem Archiv, das die Kennzeichnung nicht weitergibt, oder vom USB-Stick wird so nicht
  angehalten.
- Nicht im Spielmodus, und nicht bei Programmen mit Administratorrechten (der Agent kann sie nicht
  anhalten).
- Nicht geprüft: die Freigabe im Meldefenster nach dem Anhalten (nur der Programmtest aus 7.34) und
  die Wirkung im Alltag mit harmlosen unsignierten Programmen.

Der USB-Zwischenspeicher wurde nach dem letzten Lauf geleert.

### 7.37 Regeln für Programmstarts: 20 Angriffs-Befehlszeilen und 6 harmlose (22.11.2026, K9 0.40.0 und 0.41.0)

**Frage:** Wie viele typische Angreifer-Befehlszeilen meldet K9 – mit den eigenen Regeln, mit den
Sigma-Regeln (Schalter `sigma`, Paket „core“) und mit den LOLBAS-Regeln (Schalter `lolbas`, Sigma
Stufe „mittel“)? Und bleiben harmlose Befehle still?

**Aufbau** (`scripts/sandbox/sandbox-test-regeln.ps1`, `k9-test-regeln.wsb`): Windows-Sandbox ohne
Netzwerk, **keine Schadsoftware**. Gestartet werden Windows-eigene Programme mit Befehlszeilen, wie
Angreifer sie benutzen, aber ohne Wirkung: Adressen zeigen auf den eigenen Rechner (127.0.0.1,
Port 9), Ziele liegen in einem Testordner, gelöscht wird nur Nichtvorhandenes. Die Regelpakete
kommen vom PC, beide Schalter sind an. Gezählt wird je Befehl, welche Meldungen der Dienst danach
schreibt. Die LOLBAS-Regeln werden nur ausgewertet, wenn weder K9s eigene Regeln noch Sigma „core“
angeschlagen haben – sie können also nur zusätzliche Treffer liefern.

| Nr | Befehl | Lauf 1 (0.40.0, 06:02 Uhr) | Lauf 2 (0.41.0, 06:17 Uhr) |
|---|---|---|---|
| A01 | certutil lädt eine Datei aus dem Netz | K9 | K9 |
| A02 | bitsadmin lädt eine Datei aus dem Netz | K9, Sigma | K9, Sigma |
| A03 | mshta führt Skript aus der Befehlszeile aus | K9 | K9 |
| A04 | PowerShell mit verstecktem, kodiertem Befehl | K9 | K9 |
| A05 | PowerShell lädt Code aus dem Netz und führt ihn aus | K9 | K9 |
| A06 | regsvr32 lädt ein Skript aus dem Netz | Sigma | Sigma |
| A07 | geplante Aufgabe beim Anmelden für ein Programm in Public | Sigma | Sigma |
| A08 | Autostart-Eintrag (Run) für ein nicht vorhandenes Programm | – | – |
| A09 | Schattenkopien löschen | K9 | K9 |
| A10 | Ereignisprotokoll leeren | Sigma | Sigma |
| A11 | Systemdatei-Name am falschen Ort (svchost.exe in Public) | Sigma | Sigma |
| A12 | certutil dekodiert eine Datei | Sigma | Sigma |
| A13 | curl lädt eine .exe nach Public | Sigma | Sigma |
| A14 | Windows-Firewall per Befehl abschalten | **–** | **K9 (neu)** |
| A15 | Defender-Echtzeitschutz per Befehl abschalten | **–** | **K9 (neu)** |
| A16 | Speicherabbild über comsvcs.dll | Sigma | Sigma |
| A17 | Kontendatenbank SAM sichern | Sigma | Sigma |
| A18 | Erkundung: whoami /priv | Sigma | Sigma |
| A19 | Erkundung: Administratoren auflisten | – | – |
| A20 | cmd startet PowerShell mit Download-Befehl | K9 | K9 |

| Zusammenfassung | Lauf 1 | Lauf 2 |
|---|---|---|
| von irgendeiner Regel gemeldet | 16 von 20 | **18 von 20** |
| von den eigenen Regeln von K9 | 7 | 9 |
| nur dank Sigma „core“ | 9 | 9 |
| zusätzlich dank LOLBAS | 0 | 0 |
| harmlose Befehle gemeldet | 1 von 5 (LOLBAS) | 1 von 5 (LOLBAS) |

**Ergebnisse:**

- **Sigma „core“ lohnt sich:** 9 von 20 Befehlen werden nur dadurch gemeldet. Ohne den Schalter
  `sigma` wären es 7 (jetzt 9) von 20.
- **LOLBAS brachte in diesem Test nichts:** kein zusätzlicher Treffer, dafür der einzige
  Fehlalarm – das Öffnen eines Eintrags der Systemsteuerung (`rundll32.exe shell32.dll,Control_RunDLL`)
  löst „Potentially Suspicious Rundll32 Activity“ aus. Die Meldungen bleiben deshalb leise; ob der
  Schalter sich lohnt, muss die Beobachtung im Alltag zeigen.
- **Zwei Lücken geschlossen (0.41.0):** Das Abschalten der Windows-Firewall und des
  Defender-Echtzeitschutzes per Befehl meldete in Lauf 1 keine Regel. Neu ist die eigene Regel
  „Schutz von Windows wird per Befehl abgeschaltet“ (Schwere Hoch); in Lauf 2 sind beide gemeldet.
- **Weiter nicht gemeldet:** A08 – der Run-Eintrag zeigte auf ein Programm, das es nicht gibt (die
  Autostart-Prüfung von K9 bewertet die Datei, und ohne Datei gibt es nichts zu bewerten); A19 –
  das Auflisten der Administratoren ist ein alltäglicher Befehl, eine Regel dafür gäbe Fehlalarme.

**Grenzen:** Die 20 Befehle sind eine eigene Auswahl bekannter Muster, keine Stichprobe echter
Angriffe; die Quote 18 von 20 gilt nur für diese Auswahl. Ein harmloser Befehl (Editor öffnen)
startete wegen eines Fehlers im Testskript in beiden Läufen nicht – behoben für künftige Läufe.
Getestet ist die Meldung, nicht ein Anhalten: Diese Regeln halten nichts an.

### 7.38 YARA-Regeln auf sauberen Dateien: „core“ gegen „extended“ (22.11.2026, 08:30 bis 08:57 Uhr)

**Frage:** Wie viele Fehlalarme bringen die YARA-Regeln auf Dateien, die sicher sauber sind – und
wie viele mehr das Paket „extended“?

**Aufbau:** Messprogramm `yara_clean_files` (ignorierter Test in `k9-core`): liest die Regeln direkt
aus dem Archiv von YARA Forge (Stand 20261122, nichts wird entpackt), prüft `C:\Windows\System32`
(36.671 Dateien, 10,2 GB) und `C:\Program Files` (232.465 Dateien, 50,9 GB) mit 16 Prüfsträngen,
nur lesend; nichts wird gespeichert oder gemeldet. Mindestbewertung der Regeln 60 wie im Betrieb.

| Paket | Regeln | Dauer | Treffer | Regeln mit Treffer | laut mit Fassung 1 | laut mit Fassung 2 (0.43.0) |
|---|---|---|---|---|---|---|
| „core“ | 5.078 | 143 s | 14 Dateien | 7 | – | **1** |
| „extended“ | 10.848 | 191 s | 25 Dateien | 11 | 15 | **2** |

**Wo die Treffer lagen:** 12 von 25 in Signaturdateien von Trend Micro (`icrc$oth.*`, Regeln zu
Cobalt Strike, LockBit und „Xored Mozilla“); die übrigen in signierten Dateien von NVIDIA, Adobe,
Microsoft Visual Studio, Papyrus Autor und Raspberry Pi Imager, in zwei PowerShell-Skripten im
Windows-Ordner und in zwei unsignierten Skriptdateien (PDF24 `jspdf.js`, eine Datei von Visual
Studio).

**Fassung 1 der leisen Regel – zu streng:** Sie verlangte für jede Datei sieben Tage ohne Änderung.
Die Signaturdateien von Trend Micro werden täglich erneuert, ein installiertes Programm bei jeder
Aktualisierung – 15 von 25 Treffern blieben laut.

**Fassung 2 (0.43.0):** keine Wartezeit für Dateien eines Schutzprogramms unter `C:\Program Files`
und für signierte Dateien an Orten, in die nur ein Administrator schreiben kann; sieben Tage für
signierte Dateien anderswo und für unsignierte Dateien im Windows-Ordner; Dateien mit
Internet-Kennzeichnung nie leise. Damit bleiben 1 bzw. 2 Treffer laut – die beiden unsignierten
Skriptdateien.

**Grenzen:** Gemessen ist nur die Fehlalarm-Seite, und nur auf den Dateien dieses PCs an diesem Tag.
Ob „extended“ mehr echte Schadsoftware erkennt, wurde nicht gemessen. Die leise Regel vertraut
gültigen Signaturen an geschützten Orten.

### 7.39 Freigabe eines angehaltenen Programms: nicht ohne Klick prüfbar (22.11.2026, 09:16 bis 09:40 Uhr, K9 0.44.0)

**Frage:** Läuft ein Programm, das K9 angehalten hat, nach der „Freigabe“ wirklich weiter? Belegt
war das bisher nur durch einen Programmtest (7.34).

**Aufbau:** neuer Durchgang R21 im Sandbox-Test: Schalter `neue-programme` an, das harmlose
Testprogramm wird beim Start angehalten, dann sollte die Meldung mit `k9 entscheiden <Nr> freigabe`
entschieden werden.

**Ergebnis:** Das Anhalten klappte (400 von 400 Dateien heil, Programm steht, Meldung „Neues
unsigniertes Programm aus dem Internet angehalten“). Die Freigabe per Befehl endete mit
„Dienst: Nicht bestätigt – es wurde nichts geändert“. Das ist kein Fehler, sondern der Schutz, der
dafür sorgt, dass sich Schadsoftware nicht selbst freigeben kann: Jede Freigabe muss in einem
Fenster des Dienstes mit „Ja“ bestätigt werden, und in der unbeaufsichtigten Sandbox klickt niemand.
Der Durchgang wurde als „nicht bestanden“ gezählt, weil das Skript den Klick nicht vorgesehen hatte.

**Folge:** R21 läuft nicht mehr im automatischen Durchlauf mit. Es gibt dafür einen eigenen kurzen
Lauf (Datei `ransomware-sim-nur-freigabe.txt` neben dem Skript, etwa fünf Minuten), der an der
richtigen Stelle anhält und sagt, was zu klicken ist. Dieser Lauf ist in 7.41 beschrieben
(bestanden).

**Nebenbei bestätigt:** Die Durchgänge R10 bis R20 liefen im selben Lauf erneut wie in 7.36
(R10 bis R15 je 400 von 400; R16 bis R18 394, 394 und 392; R19 und R20 mit dem Schalter 400 und 399).

### 7.40 Wiederherstellung aus einer echten Schattenkopie (22.11.2026, 09:49 bis 09:51 Uhr, K9 0.44.0)

**Aufbau:** auf dem Test-PC, in einem Administrator-Terminal, vom Nutzer ausgeführt.

1. `k9 wiederherstellen liste` zeigte 19 Schattenkopien: 9 für C: (18.11. bis 22.11., 06:06 Uhr)
   und 10 für F: (15.11. bis 21.11., 22:24 Uhr).
2. `k9 wiederherstellen "C:\K9-Quelltext\docs" --stand "2026-11-21 23:00" --ziel
   "…\testlabor\wiederherstellung-test"` wählte die Kopie von F: vom 21.11., 22:24 Uhr, und meldete:
   0 Dateien fehlen heute, 5 sind heute verändert, 8 sind gleich; kopiert: 5 Dateien (2,5 MB).

**Prüfung:** Die fünf Dateien (`ANLEITUNG.md`, `Anleitung-K9.pdf`, `QUELLEN.md`, `STATISTIK.md`,
`TESTBERICHT.md`) trugen die Änderungszeiten vom 21.11. Vier davon sind in der Versionsverwaltung
gesichert; ihr SHA-256-Wert stimmt jeweils mit dem Stand des Commits vom 21.11., 22:08 Uhr, überein
und unterscheidet sich vom heutigen Stand. Der Doku-Ordner selbst blieb unverändert. Der Testordner
wurde danach gelöscht.

**Grenzen:** ein Ordner, fünf kleine Dateien, kein Schaden durch Ransomware. Nicht geprüft: große
Ordner, Dateien, die heute fehlen, und das Zusammenspiel mit einem echten Angriff.

### 7.41 Freigabe eines angehaltenen Programms per Klick (22.11.2026, K9 0.44.0 und 0.44.1)

**Aufbau:** eigener kurzer Lauf des Sandbox-Tests (Datei `ransomware-sim-nur-freigabe.txt`): Schalter
`neue-programme` an, das harmlose Testprogramm wird beim Start angehalten; der Tester gibt es im
Meldefenster frei und bestätigt im Fenster des Dienstes. Beweis für das Weiterlaufen: Das Programm
beginnt, seine Testdateien zu überschreiben.

| Lauf | Zeit | Version | Ergebnis |
|---|---|---|---|
| 1 | 09:50 bis 10:00 Uhr | 0.44.0 | **ohne Ergebnis** – angehalten (399 von 400 heil), aber keine Entscheidung angekommen |
| 2 | 10:06 bis 10:13 Uhr | 0.44.1 | **bestanden** |

**Lauf 1:** Der Tester sah die erwartete Meldung nicht. Ursache: K9 zeigt immer nur ein Meldefenster
zugleich. Das Testskript startet den Agenten neu; der Hinweis „Der K9-Agent wurde unerwartet
beendet“ stand deshalb schon als Fenster offen, und die Meldung zum angehaltenen Programm wartete
dahinter. Das war ein Fehler im Testaufbau – und zugleich eine Schwäche von K9: Ein angehaltenes
Programm wartet auf den Nutzer, seine Meldung reihte sich aber hinten ein. Behoben in 0.44.1
(Meldungen zu angehaltenen Programmen an die Spitze der Warteschlange); das Testskript erklärt
jetzt, dass zuerst ein anderes Fenster offen sein kann.

**Lauf 2** (Zeiten der Sandbox):

| Zeit | Ereignis |
|---|---|
| 10:11:29,870 | Testprogramm gestartet und angehalten („Neues unsigniertes Programm aus dem Internet – angehalten bis zur Freigabe“); 400 von 400 Dateien heil |
| 10:11:49,578 | Dienst: „Bestätigt: ‚Freigabe (genau diese Programmdatei)‘ bestätigen?“ – Klick des Nutzers auf „Ja“ |
| 10:11:49,601 | Dienst: Entscheidung „Freigabe (genau diese Programmdatei)“ für Erkennung 2 |
| 10:11:49,756 | Das Programm läuft und überschreibt Dateien; der Ransomware-Schutz hält es nach 4 Dateien wieder an (396 von 400 heil) – so soll es sein |
| danach | zweiter Start derselben Datei: **nicht** mehr beim Start angehalten (Freigabe gemerkt); der Ransomware-Schutz hält es nach 8 Dateien an |

**Ergebnis:** Die Freigabe per Klick lässt ein angehaltenes Programm sofort weiterlaufen, und K9
merkt sich die Datei. Dass es danach wegen seines Verhaltens erneut angehalten wird, zeigt, dass
eine Freigabe für „aus dem Internet“ den Ransomware-Schutz nicht aushebelt.

**Grenzen:** ein Lauf, ein Programm, das von genau einer Meldung angehalten war. Der Fall „mehrere
Meldungen halten dasselbe Programm an, eine Freigabe genügt“ ist weiter nur durch den Programmtest
aus 7.34 belegt.

### 7.42 Belastung durch K9 beim Spielen und außerhalb (22.11.2026, K9 0.44.1)

**Frage:** Die erste Bedingung des Projekts lautet, dass K9 das Spielen nicht beeinträchtigt. Seit
dem 21.11. sind viele Prüfungen dazugekommen. Gemessen war das bisher nicht.

**Aufbau:** Seit 0.43.0 schreibt der Agent alle 10 Minuten seine Rechenzeit ins Protokoll, getrennt
nach Zeit im Spielmodus und sonstiger Zeit; der Dienst tut das für sich schon länger. Der Tester spielte
am 22.11. von 12:30 bis 13:10 Uhr; K9 erkannte das Spiel um 12:23:50 Uhr („Gaming-Modus aktiv“).
Alle Schalter waren an (`anhalten`, `ransomware-anhalten`, `neue-programme`, `sigma`, `lolbas`).

| Zeitraum | Agent (Anteil eines Kerns) | Dienst (Anteil eines Kerns) |
|---|---|---|
| 09:39 bis 12:17 Uhr, kein Spiel | **19 bis 23 %** | 0,5 bis 1,7 % |
| 12:27 bis 13:07 Uhr, im Spiel (4 Messfenster) | **0,76 bis 0,83 %** | 0,57 bis 0,69 % |

**Ergebnis 1 – Spielen:** Im Spiel brauchen Agent und Dienst zusammen rund 1,4 % **eines** von
48 Prozessorkernen. Die Bedingung ist erfüllt und zum ersten Mal mit Zahlen belegt.

**Ergebnis 2 – außerhalb des Spiels war der Agent zu teuer:** 19 bis 23 % eines Kerns im Leerlauf.
Ursache: Mit dem Schalter `neue-programme` (seit 0.39.0) sieht der Agent alle 60 Millisekunden nach
neuen Programmen und fragte dafür jedes Mal die ganze Prozessliste von Windows ab. Nachgemessen:
13,7 Millisekunden Rechenzeit je Abfrage bei 402 Prozessen, 16-mal je Sekunde – das ergibt die
beobachteten 22 %. In der Anleitung stand eine ungeprüfte Schätzung von „rund 2 %“.

**Behebung in 0.44.2:** Der Agent fragt zuerst nur die Prozessnummern ab (gemessen: unter
0,01 Millisekunden je Abfrage) und holt die ganze Liste nur, wenn eine neue Nummer dabei ist.

**Nachmessung mit 0.44.2 (22.11.2026, 13:41 bis 13:46 Uhr, kein Spielmodus, 387 Prozesse, alle
Schalter an):** Rechenzeit des Agenten in fünf Fenstern zu je einer Minute, von außen gemessen:

| Fenster | 1 | 2 | 3 | 4 | 5 | Mittel |
|---|---|---|---|---|---|---|
| Anteil eines Kerns | 2,58 % | 0,65 % | 1,09 % | 0,96 % | 0,91 % | **1,24 %** |

Vorher waren es 19 bis 23 %. Zwei Messungen davor sind **nicht** verwertbar und deshalb hier nur
genannt: eine über drei Minuten (0,88 %) lief unbemerkt im Spielmodus, weil K9 das
Fadenkreuz-Programm CrosshairX aus dem Steam-Ordner für ein Spiel hielt (behoben in 0.44.3, Liste
`keine_spiele`); eine über fünf Minuten (3,52 %) lief gleichzeitig mit einem Bauvorgang, der Hunderte
Programme startete. In den ersten Minuten nach dem Ende des Spielmodus holt der Agent Aufgeschobenes
nach (Nachprüfung von 126 Dateien, Heimnetz, Signaturen laden, Anleitung neu erzeugen); in dieser
Zeit zeigte sein Protokoll 27,8 % eines Kerns über knapp vier Minuten, zum Teil wegen desselben
Bauvorgangs.

**Grenzen:** fünf Minuten an einem ruhigen PC. Wer viele Programme startet, verursacht mehr Arbeit,
weil der Agent jedes neue Programm ansieht. Ein Programm, das innerhalb von 60 Millisekunden endet und
dessen Nummer Windows in derselben Zeit neu vergibt, würde dem Agenten entgehen; der Dienst sieht
jeden Start über die Ereignisverfolgung trotzdem.

### 7.43 Arbeitsdatei eines Schutzprogramms: Wer hält die Datei offen? (22.11.2026, K9 0.45.0)

**Anlass:** Meldungen 285 (20.11.) und 387 (22.11.): ClamAV-Muster `PUA.Win.Exploit.CVE_2012_1461-1`
auf `C:\Users\anna\AppData\Local\Temp\<zufälliger Name>.tmp`. Von Hand geprüft:
Die Datei wird von genau einem Programm offen gehalten (`uiWinMgr.exe`, Trend Micro Client Main
Console, gültig signiert von Trend Micro, Inc.), und sie wurde am 20.11.2026 um 21:35:32 Uhr
angelegt – in derselben Sekunde, in der dieses Programm gestartet ist. Zwischen beiden Meldungen
hat Trend Micro den Inhalt geändert (gleiche Größe 336.621 Bytes, anderer Hashwert).

**Prüfung der neuen Regel** mit dem Lesetest `holders_live` (liest nur, meldet und speichert nichts):

| Datei | Halter laut K9 | Einordnung | Dauer |
|---|---|---|---|
| die Arbeitsdatei von Trend Micro | `uiWinMgr.exe` (`C:\Program Files\Trend Micro\Titanium\UIFramework\`, gültig signiert von Trend Micro, Inc.) | **leise** – „Arbeitsdatei eines Schutzprogramms – dauerhaft geöffnet von uiWinMgr.exe“ | 2.205 ms |
| `Cargo.toml` des Projekts (hält niemand offen) | niemand | laut | 16 ms |

Dazu 20 Fälle im Programmtest `work_file_of_a_security_program_is_quiet`: laut bleibt es unter
anderem, wenn der Halter nach zwei Sekunden losgelassen hat (Scanner, der nur prüft), wenn ein
zweites Programm die Datei hält, wenn der Halter unsigniert ist oder außerhalb von
`C:\Program Files` liegt, bei Hashlisten-Treffern, bei Schwere „Hoch“, bei Dateien aus dem Internet
und bei Programmen (Endung oder Kopf „MZ“).

**Grenzen:** Die echte Meldung ist mit 0.45.0 noch nicht aufgetreten – sie kommt erst, wenn Trend
Micro die Datei wieder ändert. Geprüft ist die Entscheidung, nicht der ganze Weg bis ins Dashboard.
Den Inhalt der Datei hat niemand angesehen: Trend Micro hält sie gesperrt.

## 8. Fazit

- Bei manuellen Scans erkennt K9 alle EICAR-Varianten, auch in verschachtelten Archiven.
- Der Echtzeitschutz hatte eine echte Lücke (kein ClamAV). Sie ist geschlossen, ohne dass das Spielen
  leidet: ClamAV läuft nur bei Bedarf und nie während eines Spiels.
- Phishing-Links in Dateien werden in Echtzeit erkannt.
- Der Windows-Dienst erkennt jetzt auch Prozesse, die nach Millisekunden enden, und DNS-Abfragen
  mit dem fragenden Programm. Ein hart beendeter Agent ist nach 10 Sekunden wieder da, und du
  bekommst einen Hinweis.
- Alle Funde warteten auf eine Entscheidung. Nichts wurde automatisch verändert.
- Tests in der Windows-Sandbox: erledigt (Abschnitte 7.2–7.4). Nach dem Aufräumen der Treiber startet
  Windows mit eingeschaltetem SVM einwandfrei; der Tester lässt SVM dauerhaft an (VBS an, Speicherintegrität
  aus), Spiele laufen ohne Probleme. Meldet sich ein Anti-Cheat, ist „SVM im BIOS aus“ der Ausweg.
