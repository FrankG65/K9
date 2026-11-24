# Projektstatistik

Stand: 24.11.2026 05:18. Diese Seite zeigt den Stand bei der Veröffentlichung. Zeiten und Commits stammen aus der Versionsgeschichte des Entwicklungs-PCs, die nicht mit veröffentlicht ist.

### Zeitraum

| Angabe | Wert |
|---|---|
| Projektstart | 13.11.2026 09:59 Uhr |
| Letzte Änderung | 24.11.2026 05:18 Uhr |
| Kalenderzeit | 259,3 h |
| Aktive Arbeitszeit (Schätzung) | 59,2 h in 53 Arbeitsblöcken |
| Commits | 242 |

Schätzung der aktiven Zeit: Commits und Meilensteine werden zu Arbeitsblöcken zusammengefasst; eine Pause von mehr als 60 Minuten beginnt einen neuen Block. Arbeit vor dem ersten Ereignis eines Blocks ist nicht enthalten.

### Test-PC

Alle Messungen und Tests dieser Anleitung und des Testberichts stammen von einem einzigen PC (Stand 23.11.2026, aus Windows ausgelesen).

| Bauteil | Angabe |
|---|---|
| Prozessor | AMD Ryzen Threadripper 3960X, 24 Kerne, 48 logische Prozessoren |
| Hauptplatine | Gigabyte TRX40 AORUS XTREME (BIOS F7f vom 24.09.2025) |
| Arbeitsspeicher | 64 GB |
| Grafikkarte | NVIDIA GeForce RTX 3090 (24 GB) |
| Datenträger | vier NVMe-SSDs mit je rund 2 TB (Samsung SSD 990, drei Seagate FireCuda), eine Festplatte mit 10 TB (WD) |
| Betriebssystem | Windows 11 Pro, Version 25H2, Build 26200.9974 |
| Virenschutz neben K9 | Trend Micro Maximum Security |
| Windows-Schutzfunktionen | Virtualisierung (SVM) an; Secure Boot aus; Speicherintegrität bis 23.11.2026 aus, seitdem an |

### KI-Nutzung: Tokens und Kosten

K9 wurde vollständig im Gespräch mit Claude (Claude Code) entwickelt. Die Tabelle zeigt, was die Sitzungsprotokolle auf dem Test-PC aufgezeichnet haben: 891 Anfragen aus 8 Sitzungen vom 16.11. bis 23.11.2026 (ausgezählt am 23.11.2026, 08:54 Uhr). Die Kosten sind auf **Claude Fable 5.2** umgerechnet, mit den Listenpreisen der Anthropic-API je Million Tokens (Stand der Preisliste: 03.11.2026). Ein Teil der Anfragen lief tatsächlich mit dem günstigeren Claude Opus 5.5.

| Art | Tokens | Preis je Million | Kosten |
|---|---:|---:|---:|
| Ausgabe (von Claude geschrieben, einschließlich Nachdenken) | 758.736 | 40,00 USD | 30,35 USD |
| Eingabe ohne Zwischenspeicher | 2.114 | 8,00 USD | 0,02 USD |
| Eingabe aus dem Zwischenspeicher gelesen | 370.633.730 | 0,20 USD | 74,13 USD |
| Eingabe in den Zwischenspeicher geschrieben (5 Minuten) | 1.144.655 | 10,00 USD | 11,45 USD |
| Eingabe in den Zwischenspeicher geschrieben (1 Stunde) | 3.868.328 | 16,00 USD | 61,89 USD |
| **Summe der aufgezeichneten Sitzungen** | | | **177,83 USD** |

**Hochrechnung auf das ganze Projekt (Schätzung):** Die aufgezeichneten Sitzungen decken 16,8 Stunden aktive Arbeit ab (gleiche Zählweise wie oben: eine Pause von mehr als 60 Minuten beginnt einen neuen Block). Das sind rund 10,60 USD je Stunde. Auf die 59,2 h aktive Arbeitszeit des ganzen Projekts gerechnet ergibt das rund **626 USD**.

**Was diese Zahl nicht ist:** keine Rechnung. Die ersten drei Tage (13. bis 15.11.), mehrere spätere Arbeitsblöcke und die Gespräche außerhalb dieser Sitzungen sind auf dem PC nicht aufgezeichnet; für sie ist der Stundensatz der aufgezeichneten Sitzungen angenommen. Abgerechnet wurde das Projekt nicht je Token nach dieser Preisliste.

### Meilensteine

| Zeit | Meilenstein |
|---|---|
| 13.11. 09:59 | Projektstart (erste Anfrage) |
| 13.11. 10:16 | Entscheidung: kein eigener Kernel-Treiber, Plan Schritte 1–3, Quarantäne nur auf Entscheidung |
| 13.11. 13:41 | PDF-Anleitung gewünscht |
| 14.11. 04:51 | SVM-Startproblem → Treiber-Bereinigung (ca. 06:52–11:34) |
| 14.11. 05:08 | Härtung »Alles (Stufe 1 bis 3)« |
| 14.11. 19:13 | SVM bleibt eingeschaltet |
| 14.11. 19:57 | Punkte 1–4 begonnen (Datendiebe, Erweiterungen, PUA/Phishing, Veröffentlichung) |
| 14.11. 22:21 | Veröffentlichung zurückgestellt |
| 14.11. 23:59 | Ausbau »Plan Schritt 1 bis 5« |
| 15.11. 06:19 | Sandbox-Lauf 13 |
| 15.11. 14:22 | Neuer Name: aus »Virenscanner« wird K9 |
| 16.11. 05:50 | Versionsnummern eingeführt (0.2.0) |
| 17.11. 21:56 | Arbeitsordner, Konten und Anmeldungen, Sicherheits-Check (0.6.0 bis 0.8.0) |
| 18.11. 19:24 | Vergleichstest mit echter Schadsoftware in der Sandbox vorbereitet |
| 19.11. 16:06 | Erste echte Ransomware in der Sandbox (LockBit) |
| 20.11. 05:09 | Zehn Ransomware-Familien in der Sandbox, je mit und ohne Anhalten (bis 08:00) |
| 20.11. 09:28 | Ransomware-Erkennung läuft im Dienst (0.24.0) |
| 20.11. 14:41 | Bekannte Schadsoftware wird beim Start angehalten (0.25.0) |
| 21.11. 07:52 | Conti in der Sandbox mit 0.30.0: K9 wird abgeschaltet, alle Dateien verschlüsselt (bis 08:01) |

### Entwicklungsschritte

| Schritt | Beginn | Kalenderzeit | aktive Zeit (Schätzung) |
|---|---|---|---|
| Schritt 1: Grundgerüst (Erkennung, Entscheidungen, Quarantäne, Gaming-Modus, Dashboard, Meldefenster) | 13.11. 09:59 | 1,2 h | 1,2 h |
| Schritt 2: echte Erkennungsquellen, PDF-Anleitung | 13.11. 11:13 | 3,6 h | 1,2 h |
| Schritt 3: Echtzeitschutz | 13.11. 14:51 | 5,3 h | 1,0 h |
| Windows-Dienst (ETW) | 13.11. 20:09 | 8,7 h | 1,5 h |
| SVM-Startproblem, Härtung Stufen 1–3 | 14.11. 04:51 | 1,4 h | 1,4 h |
| Treiberprüfung und Treiber-Bereinigung | 14.11. 06:16 | 8,6 h | 1,9 h |
| Sandbox-Läufe 1–6 und Korrekturen | 14.11. 14:50 | 5,1 h | 3,3 h |
| Punkte 1–4: Datendiebe, Browser-Erweiterungen, PUA/Phishing, Veröffentlichung | 14.11. 19:57 | 2,4 h | 1,2 h |
| Sandbox-Läufe 7–12, Sicherheitskorrekturen, Spiel-Messung | 14.11. 22:21 | 1,6 h | 0,6 h |
| Ausbau Phase 1 (PowerShell, Herkunft, Angriffsketten, Manipulationsalarm) | 14.11. 23:59 | 9,4 h | 1,7 h |
| Ausbau Phase 2 (Anhalten, VirusTotal, Firewall-Sperre, Schattenkopien) | 15.11. 09:25 | 5,0 h | 3,9 h |
| Umstellung auf K9, Sandbox-Läufe 20 und 21 | 15.11. 14:22 | 15,5 h | 1,7 h |
| Versionen 0.2 bis 0.5: Versionsanzeige, Wache für Firewall-Regeln, mehrere Meldungen auf einmal | 16.11. 05:50 | 40,1 h | 3,4 h |
| Versionen 0.6 bis 0.18: Arbeitsordner, Anmeldungen, Sicherheits-Check, Programm-Updates, neue Sicherheitslücken, Speicher-Scan | 17.11. 21:56 | 21,5 h | 7,7 h |
| Vergleichstests mit echter Schadsoftware, Skripte aus dem Internet, stündliche Hashliste (0.19 bis 0.21) | 18.11. 19:24 | 18,6 h | 3,8 h |
| Ransomware: Tests mit echten Proben, schnellerer Alarm, Erkennung im Dienst, Anhalten beim Start (0.22 bis 0.26) | 19.11. 14:02 | 32,6 h | 6,2 h |
| Scan-Schaltflächen im Dashboard: Schnellscan, vollständiger Scan aller Laufwerke, Abbrechen (0.27) | 20.11. 22:40 | 7,4 h | 0,0 h |
| Neue Quelle: Sigma-Regeln für Programmstarts (0.28) | 21.11. 06:01 | 0,4 h | 0,4 h |
| Neue Quellen: große Liste für Schad-Domains (HaGeZi) und Spamhaus DROP (0.29) | 21.11. 06:26 | 0,3 h | 0,3 h |
| EPSS-Schätzung in den Meldungen zu neuen Sicherheitslücken (0.30) | 21.11. 06:43 | 1,2 h | 0,1 h |
| Meldung bei Ausfall einer Quelle oder von ClamAV, EPSS unter 1 Prozent nur leise (0.31) | 21.11. 07:52 | 4,3 h | 0,6 h |
| Abwehr gegen das Abschalten von K9: Agent-Ende wird sofort erkannt und als Schritt einer Angriffskette gewertet (0.32) | 21.11. 12:09 | 3,1 h | 0,0 h |
| Abwehr in der Sandbox bestätigt: spät gemeldeter Programmstart zählt nachträglich, 400 von 400 Dateien heil (0.32.1) | 21.11. 15:13 | 0,2 h | 0,2 h |
| Conti mit 0.32.1 in der Sandbox: 160 von 160 Dokumenten heil (mit 0.30.0: 0 von 160) | 21.11. 15:27 | 1,0 h | 1,0 h |
| Schutz des Dienstes: lehnt fremde Stopp-Befehle ab, nach gewaltsamem Ende in 1 Sekunde zurück und hält Programme aus dem Internet an (0.33) | 21.11. 16:27 | 0,7 h | 0,7 h |
| Angriffsketten auch ohne Internet-Kennzeichnung: neue unsignierte Programme im Benutzerordner und vom USB-Stick (0.34) | 21.11. 17:07 | 3,2 h | 1,6 h |
| Auslöser eines Löschversuchs der Wiederherstellung wird auch über beendete Zwischenschritte gefunden und eingefroren (0.36) | 21.11. 20:16 | 0,9 h | 0,9 h |
| Echte Ransomware gegen 0.36.0: Conti, Babuk und LockBit je 160 von 160 Dokumenten heil; BlackBasta weiter 128 | 21.11. 21:10 | 1,0 h | 1,0 h |
| Früher Stopp für neue unsignierte Programme, zweite Köderdatei, kürzere Wartezeit vor der Prüfung (0.37) | 21.11. 22:07 | 5,4 h | 0,0 h |
| 0.37.0 war gegen BlackBasta schlechter (wartete auf die gesperrte Köderdatei); behoben und nachgemessen (0.37.1) | 22.11. 03:32 | 0,6 h | 0,6 h |
| Eine Freigabe gibt ein angehaltenes Programm ganz frei; Testprogramm stellt die gesperrte Köderdatei nach (0.38) | 22.11. 04:05 | 0,4 h | 0,4 h |
| Alle sechs verschlüsselnden Familien nachgemessen: fünf bei 159 bis 160 von 160 Dokumenten, BlackBasta bei 128 | 22.11. 04:30 | 1,1 h | 0,0 h |
| Schalter neue-programme: unsigniertes Programm aus dem Internet wird beim Start angehalten; BlackBasta 160 von 160 (0.39) | 22.11. 05:37 | 0,8 h | 0,8 h |
| LOLBAS-Regeln als Quelle; Regel-Test in der Sandbox: 18 von 20 Angriffs-Befehlszeilen gemeldet (0.40, 0.41) | 22.11. 06:26 | 2,5 h | 0,8 h |
| Schneller Scan mit 16 Prüfsträngen (0.42); YARA-Fehlalarme von 14 auf 1 gesenkt, Schalter für das erweiterte Paket (0.43) | 22.11. 08:57 | 0,7 h | 0,7 h |
| Befehl k9 wiederherstellen (Dateien aus Schattenkopien), Sigma-Zusatzpaket Emerging Threats, Hinweis auf neue Pakete (0.44) | 22.11. 09:40 | 3,8 h | 0,7 h |
| Belastung gemessen: im Spiel 1,4 % eines Kerns; Agent im Leerlauf von rund 20 % auf 1,2 % gesenkt (0.44.2) | 22.11. 13:30 | 0,3 h | 0,3 h |
| Hilfsprogramme in Spieleordnern (CrosshairX) halten K9 nicht mehr im Spielmodus (0.44.3) | 22.11. 13:50 | 0,5 h | 0,5 h |
| Dateimeldungen nennen das Programm, das die Datei offen hält; Arbeitsdateien von Schutzprogrammen nur noch leise (0.45.0) | 22.11. 14:22 | 5,0 h | 0,3 h |
| Programme mit Administratorrechten aktualisieren: Start von winget über die Windows-Abfrage (0.46.0) | 22.11. 19:19 | 0,3 h | 0,3 h |
| Datensicherung im Sicherheits-Check zählt nur noch Dateien; erste Sicherung mit Veeam eingerichtet (0.46.1) | 22.11. 19:39 | 9,4 h | 0,0 h |
| Erste Datensicherung des Test-PCs durchgelaufen, Rückholen einer Datei geprüft | 23.11. 05:03 | 0,8 h | 0,0 h |
| Treiberprüfung sieht auch in den Treibervorrat von Windows (0.47.0) | 23.11. 05:53 | 2,3 h | 2,3 h |
| Regel für ein Arbeitsprogramm freigeben; Sicherheits-Check prüft die lokale Sicherheitsautorität (0.48.0) | 23.11. 08:08 | 0,1 h | 0,1 h |
| Vorbereitung der Veröffentlichung begonnen (bereinigte Kopie ohne persönliche Angaben) | 23.11. 08:16 | 1,5 h | 1,5 h |
| K9 auch auf Englisch: Dashboard, Meldefenster und Symbol im Infobereich, Sprachschalter im Dashboard (0.49.0) | 23.11. 09:45 | 0,4 h | 0,4 h |
| Auch die Meldungen selbst erscheinen auf Englisch; Entscheidungen gelten in beiden Sprachen (0.50.0) | 23.11. 10:11 | 0,6 h | 0,6 h |
| Englisches Dashboard vervollständigt (Sicherheits-Check, Quellen, Letzte Aktionen); Gesamttest prüft die englische Seite (0.50.1) | 23.11. 10:45 | 0,6 h | 0,3 h |
| K9 auf GitHub veröffentlicht (bereinigte Kopie, Stand 0.50.1) | 23.11. 11:21 | 2,1 h | 0,3 h |
| YARA-Treffer auf gültig signierte Dateien nur noch Mittel, kein Anhalten (0.50.2) | 23.11. 13:25 | 16,1 h | 0,1 h |
| Zwei Fehlalarme behoben: Programmpfade mit / (OBS) bei Sigma, Edge-Sitzungsdateien beim Ransomware-Verdacht (0.50.3) | 24.11. 05:30 | -0,2 h | 0,0 h |

### Umfang des Programms

| Bereich | Zeilen (Rust) |
|---|---:|
| k9-core | 30.623 |
| k9-dienst | 5.463 |
| k9-agent | 4.715 |
| k9-cli | 2.365 |
| k9-doc | 433 |
| k9-res | 140 |
| k9-testsim | 212 |
| **gesamt** | **43.951** |

| Angabe | Wert |
|---|---:|
| Automatische Einzeltests | 389 |
| Prüfungen im End-zu-End-Test | 45 |
| PowerShell-Skripte (Zeilen) | 4.514 |
| Dokumentation (Markdown-Zeilen) | 6.271 |
| Seiten dieser Anleitung (vor dieser Änderung) | 111 |

Feste Regel-Kennungen je Bereich (dazu kommen die Regeln aus YARA, ClamAV, den Hash- und Adresslisten sowie die Prozess-Regeln):

| Bereich | Regeln |
|---|---:|
| AUTOSTART | 4 |
| BROWSER | 2 |
| DOWNLOAD | 5 |
| EINSTELLUNG | 1 |
| ERWEITERUNG | 3 |
| HOSTS | 2 |
| INFOSTEALER | 4 |
| KETTE | 1 |
| NETZ | 2 |
| PHISHING | 1 |
| RANSOMWARE | 2 |
| SCHATTENKOPIE | 1 |
| SELBSTSCHUTZ | 10 |
| SKRIPT | 8 |
| TREIBER | 2 |
| VIRUSTOTAL | 1 |

### Erkennungsdaten

| Angabe | Anzahl |
|---|---:|
| Erkennungsquellen aktiv / aktuell | 15 / 15 |
| YARA-Regeln | 10.848 |
| ClamAV-Signaturen | 3.642.950 |
| Schadsoftware-Hashes | 1.227.362 |
| Schad- und Phishing-Adressen | 212.016 |
| CISA-KEV-Einträge | 1.790 |

### Messungen (aus dem Testbericht)

| Messung | Ergebnis |
|---|---|
| Agent im Leerlauf | 0,08 % CPU (alle Kerne), 28 MB Arbeitsspeicher |
| Agent während eines Spiels | 0,01 % CPU |
| Dienst nach der Installation (10 min, mit Treiberprüfung) | 1,70 % eines Kerns, 505 Dateiöffnungen/s, 42 % davon geprüft |
| Dienst während Beispielspiel (3 × 10 min) | 0,57–0,82 % eines Kerns (bei 48 Kernen rund 0,01 % der CPU), 397–576 Dateiöffnungen/s, 37–52 % geprüft |
| Dienst in der Sandbox (10 min) | 0,21 % eines Kerns, 62 Dateiöffnungen/s, 3 % geprüft |
| Scan Downloads-Ordner (99 Dateien, 882 MB) | 4,6 s (rund 190 MB/s); zweiter Lauf 0,0 s |
| Autostarts, Browserverlauf, hosts | 12,3 s für 178 Autostart-Einträge |
| ClamAV-Echtzeitprüfung | einmalig ca. 10 s Ladezeit, ca. 1 GB RAM nur solange aktiv |
| Treiber | 568 geprüft, 0 auf einer Sperrliste (nach der Bereinigung von 9 Treibern/Diensten) |
| »Ähnliche Domains« gegen die 1 Mio. beliebtesten Domains | 53 Treffer, fast alle echte Nachahmer |
| Ransomware-Testprogramm (400 Dateien, 40 je Sekunde), Anhalten an | unbekanntes Programm: 382 bis 383 von 400 Dateien heil; bekanntes Programm: 400 von 400 (392, wenn es sofort loslegt); Anhalten aus: 0 |

### Sandbox-Testläufe

| Lauf | Datum | Thema | Ergebnis | gefundene Lücken |
|---|---|---|---|---|
| 1 | 14.11. | offline, Grundfunktionen | abgebrochen | Programme starteten ohne VC++-Laufzeit nicht → statische Laufzeit |
| 2 | 14.11. | offline | ohne Agent | Agent-Wache fand die Sandbox-Sitzung nicht → Suche über alle aktiven Sitzungen |
| 3 | 14.11. | offline | bestanden | – |
| 4 | 14.11. | online, Angriffstechniken | teilweise | verschlüsselte PowerShell-Befehle, sehr kurze Prozesse, Funde gingen bei Neustart verloren |
| 5 | 14.11. | online, Wiederholung | 9 bestanden | geplante Aufgabe mit cmd.exe ohne Pfad, mshta/rundll32 ohne .exe |
| 6 | 14.11. | gezielte Nachprüfung | bestanden | – |
| 7 | 14.11. | Schutz vor Datendieben | teilweise | kurz laufende Leser wurden verworfen |
| 8 | 14.11. | Browser-Erweiterungen | bestanden | – |
| 9 | 14.11. | Datendiebe, Korrektur | teilweise | Kernel-Filter beachtete Groß-/Kleinschreibung |
| 10 | 14.11. | Zwischenstand | zählt nicht | – |
| 11 | 14.11. | Datendiebe, Kernel-Zuordnung | bestanden | – |
| 12 | 14.11. | Browser-Erweiterungen | bestanden | – |
| 13 | 15.11. | Ausbau Phase 1 | teilweise | Fehler im Testskript; Richtlinien-Schlüssel wurde nicht angelegt |
| 14 | 15.11. | Ausbau Phase 1 | bestanden bis auf Skripte mit Richtlinie | PowerShell nur bis Stufe »Information« abonniert |
| 15 | 15.11. | PowerShell mit Richtlinie | teilweise | Anführungszeichen im Testskript |
| 16 | 15.11. | PowerShell mit Richtlinie | bestanden | – |
| 17 | 15.11. | Ausbau Phase 2 | bestanden | Agent kam nach Dienstneustart erst nach 3 Min. zurück; Hinweis »kein Speicher« bei jedem Dienststart neu |
| 18 | 15.11. | Schalter und Manipulationsschutz | bestanden (nach Nachtest) | »Änderung übernehmen« scheiterte seit Härtung Stufe 3; zwei Prüfmuster im Testskript zu weit |
| 19 | 15.11. | Schattenkopien mehrere Laufwerke, Namen der Firewall-Regeln | bestanden | – |
| 20 | 15.11. | Umstellung Virenscanner → K9 | bestanden (Wiederholung) | config.toml wurde nicht übernommen (k9.exe legt beim Start Standardwerte an) |
| 21 | 15.11. | K9-Update, Pause beenden, Ton | bestanden | – |

### Tests mit echter Schadsoftware und Ransomware (seit 18.11.)

Diese Tests sind nicht mehr als Läufe nummeriert; die Spalte »Testbericht« nennt den Abschnitt in `docs\TESTBERICHT.md`.

| Testbericht | Datum | Thema | Ergebnis |
|---|---|---|---|
| 7.12 | 18./19.11. | Vergleichstest, Proben nur geprüft | 26 von 30 als Datei erkannt, 11 davon am Inhalt (YARA) |
| 7.13 | 19.11. | Vergleichstest mit gestarteten Proben | 20 von 20 als Datei erkannt; bei 14 von 19 gestarteten Proben eine Meldung |
| 7.14 | 19.11. | Skript aus dem Internet gestartet | bestanden, 8 von 8 |
| 7.15 | 19.11. | Schwerpunkt Datendiebe mit Ködern (ohne Hashlisten) | 4 von 11 am Inhalt erkannt; eine Probe griff nach den Ködern und wurde gemeldet |
| 7.16 | 19.11. | Ransomware, erster Versuch | abgebrochen, zählt nicht (zwei Fehler im Testskript) |
| 7.17 | 19.11. | LockBit, eine Probe je Sandbox | Verhalten erkannt, aber nicht vor dem Schaden |
| 7.18 | 19.11. | Messung mit harmlosem Testprogramm | Anhalten aus: 0 von 400 Dateien heil; an: 365 bis 377 |
| 7.19 | 20.11. | Zehn Ransomware-Familien, je mit und ohne Anhalten | 6 verschlüsselten wirklich, 5 davon erkannt; mit Anhalten 104 bis 150 von 160 Dateien heil; Conti übersehen |
| 7.20 | 20.11. | Ransomware-Erkennung im Dienst | hält auch bei beendetem Agenten an (366 von 400 Dateien heil) |
| 7.21 | 20.11. | Anhalten beim Start, frühere Schwelle | bekanntes Programm 400 von 400, unbekanntes 383 von 400 |
| 7.22 | 20.11. | Entpacken gegen Verschlüsseln | kein Fehlalarm bei 300 neuen gepackten Dateien; Ransomware weiter erkannt |
| 7.23 | 20.11. | Bekanntes Programm, das sofort loslegt | 392 von 400 Dateien heil |
| 7.24 | 21.11. | Conti mit K9 0.30.0, Anhalten an | 0 von 160 heil: Conti beendet erst den Agenten, dann den Dienst und verschlüsselt danach |
| 7.25 | 21.11. | Harmloses Testprogramm, Agent wird von außen beendet (kein echter Schädling) | 0.32.0: 388 von 400 heil; 0.32.1: 400 von 400 heil |
| 7.26 | 21.11. | Conti mit K9 0.32.1, Anhalten an | 160 von 160 heil: nach dem Ende des Agenten sofort angehalten, Dienst läuft weiter |
| 7.27 | 21.11. | Harmloses Testprogramm, Dienst wird über Windows gestoppt bzw. gewaltsam beendet (kein echter Schädling) | 0.33.0, dritter Lauf: jeweils 400 von 400 heil |
| 7.28 | 21.11. | Harmloses Testprogramm ohne Internet-Kennzeichnung (kein echter Schädling) | 0.34.0, zweiter Lauf: alle fünf Durchgänge 400 von 400 heil |
| 7.29 | 21.11. | LockBit, BlackBasta, Babuk mit K9 0.35.2, Anhalten an | 105, 128 und 120 von 160 heil – keine Verbesserung gegenüber 7.19; Folge: 0.36.0 |
| 7.30 | 21.11. | Babuk mit K9 0.36.0, Anhalten an | 160 von 160 heil: beim Löschversuch der Wiederherstellung angehalten (vorher 120) |
| 7.31 | 21.11. | LockBit und BlackBasta (dreimal) mit K9 0.36.0, Anhalten an | LockBit 160 von 160 (vorher 105); BlackBasta 35, 128 und 128 von 160 – unverändert, mit einem Ausreißer |
| 7.32 | 21.11. | Harmloses Testprogramm, legt sofort los (kein echter Schädling), K9 0.37.0 | 392 bis 393 von 400 heil (vorher 388); BlackBasta selbst nicht messbar (Abruf abgelehnt) |
| 7.33 | 22.11. | BlackBasta mit K9 0.37.0 und 0.37.1, Anhalten an | 0.37.0: 31 und 43 von 160 (schlechter als vorher); 0.37.1: zweimal 128 von 160 |
| 7.34 | 22.11. | Harmloses Testprogramm sperrt eine Köderdatei (kein echter Schädling), K9 0.38.0 | 392 von 400 heil – so schnell angehalten wie ohne Köderdatei (394) |
| 7.35 | 22.11. | MedusaLocker und BlackMatter mit K9 0.38.0, Anhalten an | 159 und 160 von 160 heil (am 20.11.: 138 und 150) |
| 7.36 | 22.11. | BlackBasta mit K9 0.39.0 und dem Schalter neue-programme | zweimal 160 von 160 heil (ohne den Schalter 128) |
| 7.37 | 22.11. | 20 Angriffs-Befehlszeilen mit Windows-eigenen Programmen (kein Schädling), K9 0.41.0 | 18 von 20 gemeldet (9 eigene Regeln, 9 nur dank Sigma, LOLBAS 0); 1 von 5 harmlosen gemeldet (LOLBAS) |
| 7.38 | 22.11. | YARA-Regeln auf 269.136 sauberen Dateien (kein Schädling) | core 14, extended 25 Fehlalarme; mit der leisen Regel aus 0.43.0 laut: 1 bzw. 2 |
| 7.39 | 22.11. | Freigabe eines angehaltenen Programms (harmloses Testprogramm) | Anhalten ja; Freigabe ohne Klick nicht prüfbar (Bestätigungsfenster) – Lauf mit Klick steht aus |
| 7.40 | 22.11. | Wiederherstellung aus einer echten Schattenkopie (kein Schädling) | 5 geänderte Dateien zurückgeholt, Byte für Byte der Stand vom Vorabend |
| 7.41 | 22.11. | Freigabe per Klick in der Sandbox (harmloses Testprogramm) | erster Lauf ohne Ergebnis (Meldung hinter anderem Fenster), zweiter bestanden: läuft sofort weiter, zweiter Start ohne Anhalten |
| 7.42 | 22.11. | Belastung durch K9 (kein Schädling): 40 Minuten Spiel und Leerlauf | im Spiel 1,4 % eines Kerns (Agent + Dienst); außerhalb Agent 19 bis 23 % – behoben in 0.44.2, nachgemessen 1,2 % |
| 7.43 | 22.11. | Arbeitsdatei von Trend Micro (kein Schädling): Wer hält die Datei offen? | Halter richtig erkannt, Meldung wird leise; Datei ohne Halter bleibt laut |

### Funde auf dem Test-PC (nur Anzahlen)

Insgesamt **200** Erkennungen.

| Art | Anzahl |
|---|---:|
| Verdächtiger Prozess | 192 |
| Datei | 3 |
| Hinweis | 2 |
| Browser-Erweiterung | 2 |
| Autostart | 1 |

| Schwere | Anzahl |
|---|---:|
| Mittel | 167 |
| Hoch | 21 |
| Kritisch | 8 |
| Info | 3 |
| Niedrig | 1 |

| Status | Anzahl |
|---|---:|
| automatisch | 98 |
| entschieden | 96 |
| offen | 6 |

Erkannte und behobene Fehlalarme (seit 14.11. abends erfasst): 5 Ursachen, 18 Meldungen – Firefox-eigene Erweiterungen (5) und Suchmaschinen (6), Test-Agent des End-zu-End-Tests las echte Browserordner (3), Temp-Dateien von clamd beim Test (2), leere Chrome-Registry-Einträge (2, jetzt nur Info). Alle Ursachen sind behoben und durch Tests abgesichert.

