# Erkennungsquellen

Alle Quellen werden **lokal** genutzt: Es werden nur Listen/Regeln heruntergeladen,
es wird **nichts hochgeladen** (keine Dateien, keine Hashes, keine besuchten Adressen).
Downloads erfolgen ausschließlich über HTTPS. Ablage: mit Windows-Dienst
`C:\ProgramData\K9\quellen` (nur der Dienst schreibt), ohne Dienst
`%LOCALAPPDATA%\K9\quellen`. Fällige Quellen werden automatisch aktualisiert,
aber nie während eines Spiels; von Hand: `k9 quellen aktualisieren`.

> **Lizenzen:** Die Lizenzen unten sind der Stand der Recherche (November 2026).
> K9 verteilt selbst **keine** Signaturdaten – jede Installation lädt sie direkt
> beim Anbieter. Wer das Programm oder die Daten weitergibt, prüft bitte die aktuellen
> Nutzungsbedingungen jeder Quelle erneut. Zwei Quellen sind nur für die
> nicht-kommerzielle Nutzung frei (OpenPhish Community, die VirusTotal-Abfrage);
> K9 wird frei und ohne Vermarktung veröffentlicht.

| Quelle (Schlüssel) | Inhalt | Adresse | Intervall (Standard) | Prüfung der Daten | Lizenz / Bedingungen |
|---|---|---|---|---|---|
| YARA Forge (`yara_forge`) | YARA-Regeln, Paket „core“ (5.078 Regeln, Standard) oder „extended“ (10.848 Regeln, Schalter `yara-erweitert`; Stand 22.11.2026) | https://github.com/YARAHQ/yara-forge/releases (GitHub-API `releases/latest`) | 24 h | SHA-256-Prüfsumme aus dem GitHub-Release (`digest`), Regeln werden vor dem Austausch vollständig übersetzt | Sammlung: GPL-3.0. Jede Regel hat ihre eigene Lizenz im Metadatenfeld `license` (z. B. DRL 1.1, MIT, CC-BY-NC). Die Verteilung der Regel-Lizenzen wird bei jedem Download in `status.json` und im Dashboard gezeigt. |
| SigmaHQ Sigma-Regeln (`sigma`, nur mit `sigma_aktiv`) | Paket „core“: Regeln der Stufen hoch und kritisch (Status test/stable); K9 nutzt die Regeln für Windows-Programmstarts (554 von 558 auswertbar, Stand r2026-07-01). Seit 0.44.0 dazu das Zusatzpaket „Emerging Threats“ desselben Release, ebenfalls nur hoch und kritisch (158 weitere Regeln, zusammen 712) | https://github.com/SigmaHQ/sigma/releases (`sigma_core.zip`, `sigma_emerging_threats_addon.zip`) | 24 h | SHA-256 aus dem Release; das Paket wird vor dem Ersetzen vollständig gelesen | Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License): Nutzen, Ändern, Weitergeben erlaubt; **jede Meldung nennt den Autor der Regel** |
| LOLBAS mit den zugehörigen Sigma-Regeln (`lolbas`, nur mit `lolbas_aktiv`) | Die LOLBAS-Liste (246 Windows-Programme, die Angreifer missbrauchen, Stand 22.11.2026) dient nur zur Auswahl: Geladen werden die Sigma-Regeln für Windows-Programmstarts der Stufe „mittel“, auf die sie verweist – 81 Regeln zu 201 der 246 Programme (Stand r2026-07-01). Ein Programmname allein ist nie eine Meldung | https://lolbas-project.github.io/api/lolbas.json und https://github.com/SigmaHQ/sigma/releases (`sigma_all_rules.zip`) | 24 h | SHA-256 des Sigma-Pakets aus dem Release; gespeichert werden nur die ausgewählten Regeltexte; ohne auswertbare Regel bleibt der alte Stand | Liste: LOLBAS-Projekt, GPL-3.0 – nur gelesen, nicht mit K9 ausgeliefert; Regeln: Detection Rule License 1.1 – **jede Meldung nennt den Autor der Regel** |
| HaGeZi Threat Intelligence Feeds (`hagezi_tif`, nur mit `hagezi_tif_aktiv`) | Schad-, Phishing- und Betrugs-Domains, mittlere Liste (rund 390.000 Einträge, Stand 20.11.2026); lokal als 64-Bit-Schlüssel gespeichert (3 MB) | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt | 24 h (die Liste erscheint alle 8 bis 12 h neu) | mindestens 50.000 gültige Einträge, sonst bleibt der alte Stand; ganze gemeinsam genutzte Endungen werden nie übernommen | GPL-3.0 (https://github.com/hagezi/dns-blocklists); wird beim Aktualisieren geladen, nicht mit K9 ausgeliefert |
| Spamhaus DROP (`spamhaus_drop`, nur mit `spamhaus_drop_aktiv`) | IPv4-Netze, die gekapert sind oder von Kriminellen betrieben werden (1.751 Netze, Stand 21.11.2026) | https://www.spamhaus.org/drop/drop_v4.json | 24 h (Spamhaus bittet, nicht öfter als stündlich zu laden) | jede Zeile lesbar, kein Netz größer als /8, mindestens 100 Netze | kostenlos nutzbar (https://www.spamhaus.org/drop/terms/); Quelle: The Spamhaus Project – die Datei bleibt unverändert samt Copyright-Zeile gespeichert |
| abuse.ch MalwareBazaar (`malwarebazaar`) | SHA-256 bekannter Schadsoftware: vollständiger Export einmal am Tag, dazwischen jede Stunde der Export der letzten 48 Stunden (`sha256_recent.txt`, rund 1.000 Hashes), der in die vollständige Liste eingefügt wird | https://bazaar.abuse.ch/export/txt/sha256/full/ und https://bazaar.abuse.ch/export/txt/sha256/recent/ | 1 h (neueste), 24 h (vollständig) | Format- und Inhaltsprüfung (nur gültige 64-stellige Hashes) | abuse.ch-Nutzungsbedingungen; Daten laut abuse.ch frei nutzbar (CC0). **Kostenloser Auth-Key erforderlich** (https://auth.abuse.ch/). |
| abuse.ch URLhaus (`urlhaus`) | Aktive Schad-Adressen (Malware-Verteilung) | https://urlhaus.abuse.ch/downloads/text_online/ | 24 h (Empfehlung 6 h) | nicht leer, nur URLs | wie oben (CC0, Auth-Key) |
| abuse.ch Feodo Tracker (nur mit `firewall_sperre`) | Botnetz-Steuerserver, empfohlene Liste (Adresse, Port, zuletzt aktiv) | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json | täglich | nur öffentliche IPv4, Port > 0, zuletzt aktiv ≤ 30 Tage; Stand 15.11.2026: 1 Eintrag, zuletzt im März aktiv → derzeit leer | abuse.ch Nutzungsbedingungen (Feodo Tracker: frei nutzbar) |
| VirusTotal (nur mit `virustotal_aktiv`) | Ergebnis K9 zu einer Prüfsumme | https://www.virustotal.com/api/v3/files/<SHA-256> | bei Bedarf (4/min, 500/Tag) | nur Abfrage per Prüfsumme, kein Hochladen | kostenloser Schlüssel nur für private, nicht-kommerzielle Nutzung; die Prüfsumme wird an VirusTotal (Google) übertragen |
| abuse.ch ThreatFox (`threatfox`) | IOCs der letzten 48 h (SHA-256, URLs, Domains); lokal 180 Tage gesammelt | https://threatfox.abuse.ch/export/json/recent/ | 24 h | JSON-Format geprüft, nur die Typen sha256/url/domain | wie oben (CC0, Auth-Key) |
| OpenPhish Community (`openphish`) | Aktuelle Phishing-Adressen | https://openphish.com/feed.txt | 24 h (Feed ändert sich alle 12 h) | nicht leer, nur http(s)-Zeilen | OpenPhish Community Feed – laut Anbieter **nur für nicht-kommerzielle Nutzung**. |
| CISA KEV (`cisa_kev`) | Katalog aktiv ausgenutzter Schwachstellen | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 24 h | JSON-Format, Katalogversion | US-Regierungswerk, gemeinfrei (CC0) |
| NIST NVD CVE API 2.0 (kein Download-Paket) | Versionsbereiche zu den KEV-Kandidaten | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=… | bei Bedarf, Cache 30 Tage (`quellen\nvd`) | JSON-Format; Wiederholung bei Serverfehlern | gemeinfrei; NVD-Nutzungsbedingungen: Ratenbegrenzung 5 Abfragen/30 s ohne Key, 50 mit kostenlosem Key (https://nvd.nist.gov/developers/request-an-api-key). Hinweis laut NVD: „This product uses data from the NVD API but is not endorsed or certified by the NVD.“ |
| FIRST.org EPSS (kein Download-Paket) | Geschätzte Wahrscheinlichkeit, dass eine Lücke in den nächsten 30 Tagen ausgenutzt wird – nur für die CVE, die installierte Programme betreffen | https://api.first.org/data/v1/epss?cve=… | bei jeder Prüfung neuer Lücken (einmal am Tag) | Werte zwischen 0 und 1, sonst verworfen; ohne Antwort kommt die Meldung ohne Schätzung | kostenlos, ohne Anmeldung; Quelle: FIRST.org, Exploit Prediction Scoring System (https://www.first.org/epss) |
| LOLDrivers (`loldrivers`) | Bekannte verwundbare (588) und bösartige (125) Windows-Treiber: Datei-Hashes (SHA-1/SHA-256) und Authenticode-Hashes, CVE-Nummern | https://www.loldrivers.io/api/drivers.json | 24 h | JSON-Format, nur gültige Hashes; gespeichert wird ein verdichteter Index (`quellen\treiber\loldrivers.json`) | **Apache-2.0** (Projekt magicsword-io/LOLDrivers auf GitHub, geprüft 14.11.2026) |
| Microsoft-Sperrliste für Treiber (`ms_treiber`) | „Microsoft recommended driver block rules“: Authenticode-Hashes (SHA-1/SHA-256) und Datei-Name/Versions-Regeln | https://aka.ms/VulnerableDriverBlockList (ZIP, Datei `DriverPolicy_Enforced.xml`) | 24 h | ZIP/XML-Format, nur Authenticode-Hashes (Seiten-Hashes werden ignoriert); verdichteter Index `quellen\treiber\microsoft.json` | Von Microsoft im Download Center und auf Microsoft Learn veröffentlicht; es gilt der Microsoft-Nutzungsvertrag für die Website. Die Liste wird nur lokal ausgewertet und **nicht weitergegeben**. |
| MalExt Sentry (`malext`) | IDs bekannter schädlicher Browser-Erweiterungen (Chrome/Edge), rund 8.600 | https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv | 24 h | nur gültige Erweiterungs-IDs (32 Zeichen a–p); weniger als 100 Einträge → nicht übernommen; gespeichert als `quellen\erweiterungen\malext-ids.txt` | **Daten CC BY 4.0** (Namensnennung: toborrm9, „Malicious Extension Sentry“, https://github.com/toborrm9/malicious_extension_sentry), Code MIT; geprüft 14.11.2026, Projekt aktiv gepflegt (letzte Änderung am selben Tag) |
| malware-filter phishing-filter (`phishing_filter`) | Phishing-Domains aus OpenPhish, IPThreat und PhishTank, ohne beliebte Domains (Tranco, Umbrella, Cloudflare Radar – filtert der Anbieter selbst), rund 18.000 | https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt | 24 h (Liste ändert sich alle 12 h; z. B. `intervall_stunden = { phishing_filter = 12 }`) | nur gültige Hostnamen, keine IP-Adressen, **keine öffentlichen Endungen** laut Public Suffix List (z. B. `github.io`, `blogspot.com`); weniger als 1.000 Einträge → nicht übernommen; gespeichert als `quellen\phishing\phishing-filter-hosts.txt` | **Daten CC BY-SA 4.0** (Namensnennung: curben, „phishing-filter“, https://gitlab.com/malware-filter/phishing-filter; verändert wie in der Spalte davor beschrieben), Code CC0/MIT; nur lokal genutzt, nicht weitergegeben; geprüft 14.11.2026, Liste am selben Tag aktualisiert |
| ClamAV (`clamav`) | Signaturdatenbanken main/daily/bytecode | über `freshclam` von https://database.clamav.net | 24 h | `freshclam` prüft die digitalen Signaturen der Datenbanken selbst | ClamAV ist GPL-2.0; die Signaturdatenbanken stellt Cisco Talos bereit (Nutzung gemäß ClamAV-Bedingungen). ClamAV wird **nicht mitgeliefert**, sondern separat installiert (`winget install Cisco.ClamAV`). |

## Abweichende Intervalle

```toml
[quellen]
aktualisieren_stunden = 24
intervall_stunden = { urlhaus = 6, openphish = 12 }
```

MalwareBazaar ist die Ausnahme von `aktualisieren_stunden`: ohne eigenen Eintrag wird jede Stunde
nachgeladen. Mit `intervall_stunden = { malwarebazaar = 24 }` lädt K9 nur noch einmal am Tag.

## Schutz der Daten

* Neue Daten werden erst nach erfolgreicher Prüfung (Prüfsumme, Format, bei YARA:
  Übersetzung) eingespielt; bei einem Fehler bleibt der bisherige Stand aktiv.
* Für jede gespeicherte Datei steht die SHA-256 in `quellen\status.json`. Fehlt eine
  Datei oder wurde sie verändert (z. B. weil ein anderes Virenschutzprogramm die
  YARA-Regeln oder Signaturen gelöscht hat), meldet `k9 status`, `k9 quellen`
  und das Dashboard das deutlich – mit dem Hinweis, den Ordner beim anderen
  Virenschutz als Ausnahme einzutragen.
* Schlüssel (abuse.ch, NVD) liegen nur in der Windows-Anmeldeinformationsverwaltung.

## Mitgelieferte Daten

| Daten | Zweck | Lizenz |
|---|---|---|
| Public Suffix List (`crates/k9-core/data/public_suffix_list.dat`, unverändert, Stand 14.11.2026, https://publicsuffix.org/list/) | Bestimmt den eigentlichen Domain-Namen (z. B. `example.co.uk`, `nutzer.github.io`): Phishing-Listen-Einträge decken nie eine ganze öffentliche Endung ab; ähnliche Domains werden nur am Namen vor der Endung verglichen | Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/); die Datei liegt unverändert im Quellcode |
| Tranco-Liste der beliebtesten Domains (https://tranco-list.eu/) | Nur beim Entwickeln: Fehlalarm-Test der Prüfung auf ähnliche Domains (Test `fehlalarme_bei_beliebten_domains`); wird nicht mitgeliefert | MIT |

## Programmsymbol und Schrift

Das Symbol „Pfote“ (pictures\k9-pfote.svg und davon abgeleitete Dateien) wurde für K9 entworfen.
Die Buchstaben „K9“ darin sind in Pfade umgewandelt; sie stammen aus der Schrift **Archivo Black**
(Omnibus-Type), Lizenz **SIL Open Font License 1.1** – die Umwandlung in Pfade ist erlaubt, die
Schrift selbst wird nicht mitgeliefert und muss nicht installiert sein.

Die PNG- und ICO-Dateien erzeugt das Entwicklerwerkzeug `tools\k9-bilder` (nutzt die Bibliothek
resvg, MPL-2.0/Apache-2.0); es gehört nicht zur Installation.
