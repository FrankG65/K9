//! `k9` – command line of the K9.

mod dienst;

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use k9_core::app::{App, Check, ScanReport};
use k9_core::config::Channel;
use k9_core::model::Action;
use k9_core::notify::{self, Message};
use k9_core::scanner::NoControl;
use k9_core::sources::SourceId;
use k9_core::{gaming, pipeline, priority, say, say_err, sayw, secrets};

#[derive(Parser)]
#[command(name = "k9", version, about = "K9 - Begleit-Scanner fuer Windows (Kommandozeile)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ordner oder Dateien sofort scannen (ohne Pfad: Standardpfade aus der Konfiguration)
    Scan {
        pfade: Vec<PathBuf>,
    },
    /// Weitere Pruefungen: software | urls | autostart | alles (alles = inkl. Dateien der Standardpfade)
    Pruefen {
        #[arg(required = true)]
        was: Vec<String>,
    },
    /// Erkennungsquellen anzeigen oder aktualisieren
    Quellen {
        #[command(subcommand)]
        cmd: Option<SourcesCmd>,
        /// Uebersicht als JSON ausgeben (fuer Skripte und die PDF-Anleitung)
        #[arg(long)]
        json: bool,
    },
    /// Deaktivierte Autostarts anzeigen oder wieder einschalten
    Autostart {
        #[command(subcommand)]
        cmd: Option<AutostartCmd>,
    },
    /// Scan-Cache leeren (naechster Scan prueft wieder alle Dateien)
    CacheLeeren,
    /// Agent bei der Windows-Anmeldung unsichtbar starten: an | aus | status
    AutostartAgent { modus: String },
    /// Laufenden Agent beenden (auch den unsichtbar gestarteten); mit Dienst: Agent-Wache pausiert so lange
    AgentBeenden {
        /// Minuten, bis der Dienst den Agent wieder startet (1-240)
        #[arg(long, default_value_t = 60)]
        minuten: u32,
    },
    /// Pause vorzeitig beenden: Agent unsichtbar starten, Agent-Wache des Dienstes wieder an (keine Bestaetigung noetig)
    PauseBeenden,
    /// Treiber pruefen: Fremdtreiber, bekannte verwundbare/boesartige Treiber, Eignung fuer Speicherintegritaet (nur lesen)
    Treiber {
        /// Auch Microsoft-Treiber auflisten
        #[arg(long)]
        alle: bool,
        /// Ergebnis als JSON
        #[arg(long)]
        json: bool,
    },
    /// Bestaetigungsfenster des Dienstes (wird nur vom Windows-Dienst gestartet)
    #[command(hide = true)]
    Bestaetigen {
        #[arg(long)]
        titel: String,
        #[arg(long)]
        text: String,
    },
    /// Windows-Dienst (Prozess-/DNS-Ueberwachung, Agent-Wache): installieren | deinstallieren | status | starten | stoppen
    Dienst {
        aktion: String,
        #[arg(long, hide = true)]
        erhoeht: bool,
        #[arg(long, hide = true)]
        daten: Option<PathBuf>,
        #[arg(long, hide = true)]
        ergebnis: Option<PathBuf>,
    },
    /// Offene und letzte Erkennungen anzeigen
    Erkennungen {
        /// Auch bereits entschiedene/automatisch behandelte zeigen
        #[arg(long)]
        alle: bool,
    },
    /// Fuer eine offene Erkennung entscheiden: quarantaene | loeschen | freigabe/ignorieren | deaktivieren | gesehen
    Entscheiden {
        id: i64,
        aktion: Action,
        #[arg(long)]
        notiz: Option<String>,
    },
    /// Gespeicherte Entscheidungen anzeigen oder widerrufen
    Entscheidungen {
        #[command(subcommand)]
        cmd: Option<DecisionCmd>,
    },
    /// Quarantaene anzeigen oder Dateien wiederherstellen
    Quarantaene {
        #[command(subcommand)]
        cmd: Option<QuarantineCmd>,
    },
    /// Status: Pfade, Zaehler, Gaming-Modus, Zeitplaene, Agent
    Status,
    /// Testmeldung senden: fenster | popup | dashboard | email | handy
    TestMeldung { kanal: String },
    /// Dashboard-Adresse anzeigen und im Browser oeffnen (Agent muss laufen)
    Dashboard {
        /// Nur Adresse ausgeben, Browser nicht oeffnen
        #[arg(long)]
        nur_url: bool,
    },
    /// Geheimnis in der Windows-Anmeldeinformationsverwaltung speichern
    /// (smtp-passwort | ntfy-token | abusech-key | nvd-key | virustotal-key). Wert wird verdeckt abgefragt.
    Geheimnis {
        name: String,
        /// Geheimnis loeschen statt setzen
        #[arg(long)]
        loeschen: bool,
        /// Wert aus der Standardeingabe lesen (eine Zeile, z. B. fuer Testskripte)
        #[arg(long)]
        aus_eingabe: bool,
    },
    /// Pfad der Konfigurationsdatei ausgeben (legt sie bei Bedarf an)
    Konfiguration,
    /// Vollstaendige PowerShell-Skriptprotokollierung (Windows-Richtlinie "Script Block Logging"):
    /// an | aus | status. An/aus nur als Administrator.
    PowershellProtokoll {
        #[arg(default_value = "status")]
        aktion: String,
    },
    /// Firewall: status | vorschau | eingang | entfernen (Sperre bekannter Botnetz-Steuerserver; eingang = riskante eingehende Regeln anzeigen; entfernen als Administrator)
    Firewall {
        #[arg(default_value = "status")]
        aktion: String,
    },
    /// Sicherung der alten Installation (Virenscanner) nach der Umstellung auf K9: status | entfernen
    /// (entfernen als Administrator, fragt nach; --ja ohne Rueckfrage)
    AlteInstallation {
        #[arg(default_value = "status")]
        aktion: String,
        #[arg(long)]
        ja: bool,
    },
    /// Sprache der Oberflaeche / language of the user interface: de | en | auto (ohne Angabe: anzeigen)
    #[command(alias = "language")]
    Sprache { wert: Option<String> },
    /// Funktionen ein-/ausschalten: anhalten | virustotal | firewall | schattenkopien | angriffsketten |
    /// download-herkunft | skriptpruefung | datendiebe, jeweils an|aus; oder "status".
    /// An wirkt sofort, aus erst nach deiner Bestaetigung.
    /// Laufwerke der Schattenkopien: k9 funktion schattenkopien laufwerke C: F:
    Funktion {
        #[arg(default_value = "status")]
        name: String,
        wert: Vec<String>,
    },
    /// Dateien aus einer Schattenkopie zurueckholen (z. B. nach Ransomware): "liste" zeigt die
    /// Schattenkopien; mit einem Ordner werden fehlende und veraenderte Dateien in einen NEUEN
    /// Ordner kopiert. Nichts wird ueberschrieben oder geloescht. Braucht Administratorrechte.
    Wiederherstellen {
        /// "liste" oder der Ordner, dessen fruehere Dateien geholt werden sollen
        #[arg(default_value = "liste")]
        ordner: String,
        /// Stand: neueste Schattenkopie bis zu diesem Zeitpunkt, "JJJJ-MM-TT HH:MM" (Standard: die neueste)
        #[arg(long)]
        stand: Option<String>,
        /// Zielordner (Standard: Desktop\K9-Wiederherstellung <Zeit>)
        #[arg(long)]
        ziel: Option<String>,
        /// auch unveraenderte Dateien kopieren
        #[arg(long)]
        alles: bool,
    },
    /// Sicherheits-Check jetzt: Virenschutz, Firewall, Updates, Secure Boot, Benutzerkontensteuerung,
    /// Remotedesktop, Speicherintegritaet, Datensicherung (nur lesen). --programme: auch veraltete Programme (winget)
    Sicherheitscheck {
        #[arg(long)]
        programme: bool,
    },
    /// Bekannte Geraete im Heimnetz anzeigen (der Agent prueft stuendlich und meldet neue)
    Heimnetz,
    /// Speicher-Scan: zeigen, ob er gerade laufen duerfte und welche Programme er pruefen wuerde
    /// (liest keinen Arbeitsspeicher; einschalten mit: k9 funktion speicher-scan an)
    SpeicherScan,
    /// Test fuer den Speicher-Scan: haelt die harmlose K9-Testsignatur nur im Arbeitsspeicher und wartet.
    /// Aus dem Build-Ordner starten (das installierte K9 prueft sich nie selbst).
    TestSpeicher {
        #[arg(long, default_value_t = 20)]
        minuten: u64,
    },
    /// Neue Sicherheitsluecken (CVE, Hoch/Kritisch) der letzten Tage fuer installierte Programme anzeigen
    /// (nur lesen und anzeigen; der Agent prueft das einmal am Tag und meldet Treffer)
    Luecken {
        /// Wie viele Tage zurueck (1-14)
        #[arg(long, default_value_t = 3)]
        tage: i64,
    },
    /// Arbeitsordner (z. B. Claude-Projekte): Verhaltensmeldungen von dort nur leise im Dashboard.
    /// status | hinzufuegen <Ordner> | entfernen <Ordner>. Hinzufuegen wirkt erst nach deiner Bestaetigung.
    Arbeitsordner {
        #[arg(default_value = "status")]
        aktion: String,
        ordner: Option<String>,
    },
}

#[derive(Subcommand)]
enum SourcesCmd {
    /// Stand aller Quellen anzeigen (Standard)
    Liste,
    /// Quellen jetzt herunterladen/aktualisieren (optional nur eine: yara_forge, malwarebazaar,
    /// urlhaus, threatfox, openphish, phishing_filter, cisa_kev, clamav, loldrivers, ms_treiber, malext)
    Aktualisieren { quelle: Option<String> },
}

#[derive(Subcommand)]
enum AutostartCmd {
    /// Deaktivierte Autostarts anzeigen (Standard)
    Liste,
    /// Deaktivierten Autostart wieder einschalten
    Reaktivieren { id: i64 },
}

#[derive(Subcommand)]
enum DecisionCmd {
    /// Alle Entscheidungen anzeigen (Standard)
    Liste,
    /// Entscheidung widerrufen - die Erkennung wird beim naechsten Fund wieder gemeldet
    Widerrufen { id: i64 },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// Dateien in Quarantaene anzeigen (Standard)
    Liste,
    /// Datei wiederherstellen
    Wiederherstellen {
        id: i64,
        /// Anderes Ziel statt des Originalpfads
        #[arg(long)]
        ziel: Option<PathBuf>,
        /// Zusaetzlich dauerhaft freigeben (sonst wird beim naechsten Fund wieder gefragt)
        #[arg(long)]
        freigeben: bool,
    },
}

fn main() {
    k9_core::term::init_console();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("K9_LOG").unwrap_or_else(|_| "warn".into()))
        .with_target(false)
        .with_writer(|| k9_core::term::AsciiWriter(std::io::stderr()))
        .init();
    let cli = Cli::parse();
    if let Cmd::Bestaetigen { titel, text } = &cli.cmd {
        std::process::exit(confirmation_window(titel, text));
    }
    // The elevated helper of `k9 dienst` uses the data folder of the calling user.
    if let Cmd::Dienst { erhoeht: true, daten: Some(d), .. } = &cli.cmd {
        std::env::set_var(k9_core::paths::DATA_ENV, d);
    }
    if let Err(e) = run(cli) {
        say_err!("Fehler: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let app = App::open()?;
    match cli.cmd {
        Cmd::Scan { pfade } => scan(&app, pfade),
        Cmd::Pruefen { was } => {
            priority::below_normal();
            let mut checks = Vec::new();
            for w in &was {
                if w.eq_ignore_ascii_case("alles") {
                    checks = Check::ALL.to_vec();
                    break;
                }
                checks.push(Check::parse(w).with_context(|| format!("Unbekannte Prüfung '{w}' (software, urls, autostart, alles)"))?);
            }
            let roots = if checks.contains(&Check::Dateien) { existing(app.config.default_scan_paths()) } else { Vec::new() };
            say!("Prüfe: {}", checks.iter().map(|c| c.label()).collect::<Vec<_>>().join(", "));
            let rep = app.run_checks(&checks, &roots, &NoControl, &mut |m| say!("  … {m}"))?;
            print_report(&app, &rep);
            Ok(())
        }
        Cmd::Quellen { cmd, json: true } if cmd.is_none() => {
            let stats = app.sources()?.stats(&app.config.quellen);
            let mut out = std::io::stdout().lock();
            std::io::Write::write_all(&mut out, serde_json::to_string_pretty(&stats)?.as_bytes())?;
            std::io::Write::write_all(&mut out, b"
")?;
            Ok(())
        }
        Cmd::Quellen { cmd, .. } => sources(&app, cmd.unwrap_or(SourcesCmd::Liste)),
        Cmd::Autostart { cmd } => match cmd.unwrap_or(AutostartCmd::Liste) {
            AutostartCmd::Liste => {
                let list = app.store()?.list_disabled()?;
                if list.is_empty() {
                    say!("Keine deaktivierten Autostarts.");
                }
                for (id, label, at) in list {
                    say!("#{id:<5} {label} | deaktiviert {at}");
                }
                Ok(())
            }
            AutostartCmd::Reaktivieren { id } => {
                let label = k9_core::autostart::restore(&app.store()?, id)?;
                say!("Wieder eingeschaltet: {label}");
                say!("Hinweis: Die Deaktivieren-Entscheidung wurde zurückgesetzt – bei der nächsten Prüfung wird wieder gefragt.");
                Ok(())
            }
        },
        Cmd::AutostartAgent { modus } => agent_autostart(&modus),
        Cmd::Dienst { aktion, erhoeht, ergebnis, .. } => dienst::run(&app, &aktion, erhoeht, ergebnis),
        Cmd::PauseBeenden => end_pause(&app),
        Cmd::Bestaetigen { .. } => Ok(()),
        Cmd::Treiber { alle, json } => drivers_report(&app, alle, json),
        Cmd::AgentBeenden { minuten } => {
            let link = app.dashboard_link().context("Dashboard-Token nicht verfügbar")?;
            if !agent_reachable(link.port) {
                say!("Der Agent läuft nicht.");
                return Ok(());
            }
            if !(1..=240).contains(&minuten) {
                bail!("--minuten muss zwischen 1 und 240 liegen");
            }
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                // Deliberate stop by a person – a program cannot answer this prompt.
                say!("Den K9-Agent wirklich beenden? Der Echtzeitschutz ist dann aus. (j/n)");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_lowercase().as_str(), "j" | "ja" | "y") {
                    say!("Abgebrochen – der Agent läuft weiter.");
                    return Ok(());
                }
            }
            if k9_core::dienst::service_running() {
                // Routed via the service: it logs the caller and restarts the agent after the pause.
                match k9_core::dienst::request(&k9_core::dienst::Message::AgentStopp { v: k9_core::dienst::PROTOCOL, minuten }) {
                    Ok(k9_core::dienst::Message::Ergebnis { ok: true, .. }) => {
                        say!("Der Dienst startet den Agent in {minuten} Minuten wieder (früher: K9 starten.cmd).")
                    }
                    Ok(other) => bail!("Dienst hat die Pause abgelehnt: {other:?}"),
                    Err(e) => bail!("Dienst nicht erreichbar ({e:#}) – Agent wird nicht beendet, sonst gäbe es einen Selbstschutz-Alarm"),
                }
            }
            let mut s = std::net::TcpStream::connect(("127.0.0.1", link.port))?;
            let body = format!("t={}", link.token);
            let req = format!(
                "POST /beenden HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                link.port,
                body.len()
            );
            std::io::Write::write_all(&mut s, req.as_bytes())?;
            let mut resp = String::new();
            let _ = std::io::Read::read_to_string(&mut s, &mut resp);
            if resp.starts_with("HTTP/1.1 200") {
                say!("Agent wird beendet.");
            } else {
                bail!("Agent hat die Anfrage abgelehnt: {}", resp.lines().next().unwrap_or(""));
            }
            Ok(())
        }
        Cmd::CacheLeeren => {
            let n = app.store()?.cache_clear()?;
            say!("Scan-Cache geleert ({n} Einträge).");
            Ok(())
        }
        Cmd::Erkennungen { alle } => list_detections(&app, alle),
        Cmd::Entscheiden { id, aktion, notiz } => {
            let store = app.store()?;
            let r = pipeline::apply_decision(&store, &app.paths.quarantine_dir(), id, aktion, notiz.as_deref())?;
            say!("Entscheidung „{}“ für Erkennung {} gespeichert ({}).", r.action.label(), id, r.detection.threat_name);
            for p in &r.applied {
                say!("  angewendet: {p}");
            }
            for p in &r.missing {
                say!("  nicht mehr vorhanden: {p}");
            }
            Ok(())
        }
        Cmd::Entscheidungen { cmd } => decisions(&app, cmd.unwrap_or(DecisionCmd::Liste)),
        Cmd::Quarantaene { cmd } => quarantine(&app, cmd.unwrap_or(QuarantineCmd::Liste)),
        Cmd::Status => status(&app),
        Cmd::TestMeldung { kanal } => {
            let ch = Channel::parse(&kanal).with_context(|| format!("Unbekannter Kanal '{kanal}' (fenster, popup, dashboard, email, handy)"))?;
            notify::notifier_for(ch, &app.config, app.dashboard_link()).send(&Message::test(ch))?;
            match ch {
                Channel::Fenster => say!("Beispiel-Meldefenster wurde angezeigt – es wurde nichts verändert."),
                Channel::Dashboard => say!(
                    "Dashboard-Kanal braucht keinen Versand – offene Erkennungen erscheinen dort direkt. Adresse: {}",
                    app.dashboard_link().map(|l| l.home()).unwrap_or_default()
                ),
                _ => say!("Testmeldung über {} gesendet.", ch.label()),
            }
            Ok(())
        }
        Cmd::Dashboard { nur_url } => {
            let link = app.dashboard_link().context("Dashboard-Token nicht verfügbar")?;
            let url = link.home();
            say!("{url}");
            if !nur_url {
                if !agent_reachable(app.config.dashboard.port) {
                    say!("Hinweis: Der Agent läuft nicht – bitte zuerst 'k9-agent' starten.");
                }
                // `start` with an empty title argument; the URL contains only hex/ASCII.
                std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn()?;
            }
            Ok(())
        }
        Cmd::PowershellProtokoll { aktion } => powershell_protocol(&aktion),
        Cmd::Firewall { aktion } => firewall_command(&app, &aktion),
        Cmd::Funktion { name, wert } => funktion_command(&app, &name, &wert),
        Cmd::Sprache { wert } => language_command(&app, wert.as_deref()),
        Cmd::Wiederherstellen { ordner, stand, ziel, alles } => wiederherstellen_command(&ordner, stand.as_deref(), ziel.as_deref(), alles),
        Cmd::Arbeitsordner { aktion, ordner } => arbeitsordner_command(&app, &aktion, ordner.as_deref()),
        Cmd::Sicherheitscheck { programme } => sicherheitscheck_command(&app, programme),
        Cmd::Heimnetz => heimnetz_command(&app),
        Cmd::Luecken { tage } => luecken_command(tage),
        Cmd::TestSpeicher { minuten } => test_speicher_command(minuten),
        Cmd::SpeicherScan => speicher_command(&app),
        Cmd::AlteInstallation { aktion, ja } => match aktion.trim().to_lowercase().as_str() {
            "entfernen" => dienst::remove_backup(ja),
            "status" => {
                let b = k9_core::umzug::backups();
                if b.is_empty() {
                    say!("Keine Sicherung der alten Installation (Virenscanner).");
                }
                for d in b {
                    say!("Sicherung: {}", d.display());
                }
                Ok(())
            }
            other => bail!("Unbekannt: '{other}' (status, entfernen)"),
        },
        Cmd::Geheimnis { name, loeschen, aus_eingabe } => {
            if !secrets::USER_SECRETS.contains(&name.as_str()) {
                bail!("Unbekanntes Geheimnis '{name}' (erlaubt: {})", secrets::USER_SECRETS.join(", "));
            }
            // API keys for the source updates belong to the Windows service.
            let for_service = k9_core::schutz::SERVICE_SECRETS.contains(&name.as_str()) && k9_core::dienst::service_running();
            if loeschen && for_service {
                k9_core::dienst::request_set_secret(&name, None)?;
                let _ = secrets::delete(&name);
                say!("Geheimnis im Dienst gelöscht.");
                return Ok(());
            }
            if loeschen {
                let existed = secrets::delete(&name)?;
                say!("{}", if existed { "Geheimnis gelöscht." } else { "Kein Geheimnis gespeichert." });
                return Ok(());
            }
            let value = if aus_eingabe {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                // A pipe from PowerShell may put a byte order mark in front of the value.
                line.trim().trim_start_matches('\u{feff}').trim().to_string()
            } else {
                rpassword::prompt_password(k9_core::term::ascii(&format!("Wert für {name} (Eingabe bleibt unsichtbar, mit Enter bestätigen): ")))?
            };
            if value.is_empty() {
                bail!("Leerer Wert – nichts gespeichert");
            }
            if for_service {
                k9_core::dienst::request_set_secret(&name, Some(&value))?;
                // No readable copy for user programs (except the NVD key, the
                // software check of the agent needs it).
                if name == k9_core::sources::ABUSECH_KEY || name == k9_core::virustotal::VT_KEY {
                    let _ = secrets::delete(&name);
                } else {
                    secrets::set(&name, &value)?;
                }
                say!("Gespeichert im geschützten Speicher des Windows-Dienstes (nur der Dienst kann ihn lesen).");
                return Ok(());
            }
            secrets::set(&name, &value)?;
            say!("Gespeichert in der Windows-Anmeldeinformationsverwaltung (Dienst „K9“).");
            Ok(())
        }
        Cmd::Konfiguration => {
            say!("{}", app.paths.config_file().display());
            Ok(())
        }
    }
}

fn existing(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|p| p.exists()).collect()
}

fn scan(app: &App, pfade: Vec<PathBuf>) -> Result<()> {
    priority::below_normal();
    let roots = if pfade.is_empty() { existing(app.config.default_scan_paths()) } else { pfade };
    for r in &roots {
        if !r.exists() {
            bail!("Pfad existiert nicht: {}", r.display());
        }
    }
    say!("Scanne: {}", roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
    let rep = app.run_checks(&[Check::Dateien], &roots, &NoControl, &mut |m| say!("  … {m}"))?;
    print_report(app, &rep);
    Ok(())
}

fn print_report(app: &App, rep: &ScanReport) {
    let o = &rep.outcome;
    let s = &rep.stats;
    if s.files + s.cached > 0 {
        say!(
            "Fertig: {} Dateien geprüft ({:.1} MB), {} unverändert übersprungen (Cache), {} zu groß, {} nicht lesbar.",
            s.files,
            s.bytes as f64 / 1_048_576.0,
            s.cached,
            s.skipped,
            s.errors
        );
        say!("Dauer: {:.1} s, CPU-Zeit: {:.1} s", s.seconds, s.cpu_seconds);
    }
    for n in &rep.notes {
        say!("Hinweis: {n}");
    }
    say!(
        "Neue Erkennungen: {} | bereits offen: {} | freigegeben (ignoriert): {} | automatisch behandelt: {}",
        o.new.len(),
        o.already_pending,
        o.ignored,
        o.auto.len()
    );
    for d in &o.new {
        say!("  [NEU #{}] [{}] {} – {} ({})", d.id, d.kind.label(), d.threat_name, d.path, d.severity.label());
        if let Some(fix) = d.details.as_ref().and_then(|v| v["loesung"].as_str()) {
            say!("           Lösung: {fix}");
        }
    }
    for a in &o.auto {
        match &a.error {
            None => say!("  [AUTO] {} angewendet: {}", a.action.label(), a.detection.path),
            Some(e) => say!("  [AUTO-FEHLER] {}: {} – {e}", a.action.label(), a.detection.path),
        }
    }
    if rep.notified.queued > 0 {
        say!(
            "Gaming erkannt ({}): {} Meldung(en) werden nach dem Spiel zugestellt.",
            rep.gaming.reason.as_deref().unwrap_or("-"),
            rep.notified.queued
        );
    }
    if !rep.notified.sent.is_empty() {
        say!("Gemeldet über: {}", rep.notified.sent.iter().map(|c| c.label()).collect::<Vec<_>>().join(", "));
    }
    for (ch, e) in &rep.notified.failed {
        say!("Meldung über {} fehlgeschlagen: {e}", ch.label());
    }
    if !o.new.is_empty() && rep.notified.sent.contains(&Channel::Fenster) {
        if agent_reachable(app.config.dashboard.port) {
            say!("Das Meldefenster erscheint in wenigen Sekunden (über den Agent).");
        } else {
            say!("Das Meldefenster erscheint, sobald der Agent läuft ('K9 starten.cmd').");
        }
    }
    if !o.new.is_empty() {
        say!("Entscheiden: im Meldefenster, im Dashboard (k9 dashboard) oder mit 'k9 entscheiden <id> <aktion>'.");
    }
}

fn print_stats(s: &k9_core::sources::DataStats) {
    use k9_core::sources::fmt_num as n;
    say!("");
    say!("Erkennungsdaten (Stand {}):", s.stand);
    say!("  Quellen aktiv und aktuell : {} von {}", s.quellen_ok, s.quellen_aktiv);
    say!(
        "  Schadsoftware-Hashes      : {} (MalwareBazaar {}, ThreatFox {})",
        n(s.schadsoftware_hashes),
        n(s.malwarebazaar_hashes),
        n(s.threatfox_hashes)
    );
    say!(
        "  Schad-/Phishing-Adressen  : {} (URLhaus {}, OpenPhish {}, Phishing-Filter {}, ThreatFox {})",
        n(s.schad_adressen),
        n(s.urlhaus_adressen),
        n(s.openphish_adressen),
        n(s.phishing_filter_domains),
        n(s.threatfox_adressen)
    );
    say!("  ThreatFox-IOCs gesamt     : {}", n(s.threatfox_iocs));
    say!("  YARA-Regeln               : {}", n(s.yara_regeln));
    say!("  ClamAV-Signaturen         : {}", n(s.clamav_signaturen));
    say!("  CISA-KEV-Eintraege        : {}", n(s.kev_eintraege));
}

fn sources(app: &App, cmd: SourcesCmd) -> Result<()> {
    match cmd {
        SourcesCmd::Liste => {
            let src = app.sources()?;
            say!("Quellenordner: {}", src.dir.display());
            for id in SourceId::ALL {
                let st = src.get(id);
                let state = if !id.enabled(&app.config.quellen) {
                    "deaktiviert".to_string()
                } else if let Some(e) = &st.error {
                    format!("FEHLER: {e}")
                } else if let Some(u) = &st.last_update {
                    format!("Stand {} – {} Einträge – aktualisiert {u}", st.version.as_deref().unwrap_or("?"), st.entries)
                } else {
                    "noch nie geladen".into()
                };
                say!("- {}: {state}", id.label());
                say!("    Lizenz: {}", st.license.clone().unwrap_or_else(|| id.license().to_string()));
                if id.needs_abusech_key() && !has_abusech_key()? && id.enabled(&app.config.quellen) {
                    say!("    Auth-Key fehlt: kostenlos unter https://auth.abuse.ch/ registrieren, dann 'k9 geheimnis abusech-key'");
                }
                if id == SourceId::ClamAv && k9_core::clamav::installed(&app.config.quellen).is_none() {
                    say!("    ClamAV ist nicht installiert: winget install Cisco.ClamAV");
                }
            }
            for w in src.integrity_warnings() {
                say!("WARNUNG: {w}");
            }
            print_stats(&src.stats(&app.config.quellen));
        }
        SourcesCmd::Aktualisieren { quelle } => {
            let only = match quelle.as_deref() {
                Some(q) => Some(SourceId::parse(q).with_context(|| format!("Unbekannte Quelle '{q}'"))?),
                None => None,
            };
            if k9_core::schutz::protected_sources().is_some() {
                // Protected source data: only the Windows service updates it.
                say!("{}", k9_core::dienst::request_source_update(only.map(|o| o.key()))?);
                return Ok(());
            }
            priority::below_normal();
            say!("Aktualisiere Quellen (HTTPS, mit Prüfsummen wo verfügbar) …");
            for r in app.update_sources(only, false)? {
                match r {
                    Ok(m) => say!("  OK: {m}"),
                    Err(e) => say!("  FEHLER: {e}"),
                }
            }
            let n = app.store()?.cache_clear()?;
            if n > 0 {
                say!("Scan-Cache geleert ({n} Einträge) – neue Signaturen werden beim nächsten Scan auf alle Dateien angewendet.");
            }
        }
    }
    Ok(())
}

fn list_detections(app: &App, all: bool) -> Result<()> {
    let store = app.store()?;
    let list = if all { store.recent_detections(200)? } else { store.pending_detections()? };
    if list.is_empty() {
        say!("{}", if all { "Keine Erkennungen." } else { "Keine offenen Erkennungen." });
        return Ok(());
    }
    for d in list {
        say!(
            "#{:<5} {:<12} {:<9} [{}] {} | {} | {} | zuletzt {}{}{}",
            d.id,
            d.status.as_str(),
            d.severity.label(),
            d.kind.label(),
            d.threat_name,
            d.rule_id,
            d.path,
            d.last_seen,
            d.action.map(|a| format!(" | {}", a.label())).unwrap_or_default(),
            k9_core::arbeitsordner::reason_of(d.details.as_ref()).map(|w| format!(" | leise: {w}")).unwrap_or_default()
        );
    }
    Ok(())
}

fn decisions(app: &App, cmd: DecisionCmd) -> Result<()> {
    let store = app.store()?;
    match cmd {
        DecisionCmd::Liste => {
            let list = store.list_decisions()?;
            if list.is_empty() {
                say!("Keine gespeicherten Entscheidungen.");
            }
            for d in list {
                say!(
                    "#{:<5} {:<22} {} | {} | SHA-256 {} | {}{}",
                    d.id,
                    d.action.label(),
                    d.threat_name,
                    d.rule_id,
                    d.sha256,
                    d.decided_at,
                    d.note.map(|n| format!(" | {n}")).unwrap_or_default()
                );
            }
        }
        DecisionCmd::Widerrufen { id } => match store.revoke_decision(id)? {
            Some(d) => {
                store.log_event("info", &format!("Entscheidung widerrufen: {} ({})", d.threat_name, d.action.label()))?;
                say!("Entscheidung #{id} widerrufen – „{}“ wird beim nächsten Fund wieder gemeldet.", d.threat_name);
            }
            None => bail!("Entscheidung #{id} existiert nicht"),
        },
    }
    Ok(())
}

fn quarantine(app: &App, cmd: QuarantineCmd) -> Result<()> {
    let store = app.store()?;
    match cmd {
        QuarantineCmd::Liste => {
            let list = store.list_quarantine()?;
            if list.is_empty() {
                say!("Quarantäne ist leer.");
            }
            for q in list {
                say!("#{:<5} {} | {} | {} Bytes | seit {}", q.id, q.threat_name, q.original_path, q.size, q.quarantined_at);
            }
        }
        QuarantineCmd::Wiederherstellen { id, ziel, freigeben } => {
            let dest = pipeline::restore_from_quarantine(&store, id, ziel.as_deref(), freigeben)?;
            say!("Wiederhergestellt: {}", dest.display());
            if freigeben {
                say!("Dauerhaft freigegeben – wird nicht mehr gemeldet.");
            } else {
                say!("Hinweis: Beim nächsten Scan wird die Datei erneut gemeldet (Entscheidung zurückgesetzt).");
            }
        }
    }
    Ok(())
}

fn status(app: &App) -> Result<()> {
    let store = app.store()?;
    let c = store.counts()?;
    let g = gaming::detect(&app.config.gaming);
    let now = chrono::Local::now().naive_local();
    let mut out = std::io::stdout().lock();
    sayw!(out, "K9 {}", env!("CARGO_PKG_VERSION"))?;
    sayw!(out, "Konfiguration : {}", app.paths.config_file().display())?;
    sayw!(out, "Daten         : {}", app.paths.data_dir.display())?;
    sayw!(out, "Agent         : {}", if agent_reachable(app.config.dashboard.port) { "läuft" } else { "nicht gestartet" })?;
    sayw!(out, "Gaming-Modus  : {}",
        if !app.config.gaming.aktiv {
            "aus".to_string()
        } else if g.active {
            format!("SPIEL ERKANNT ({})", g.reason.unwrap_or_default())
        } else {
            "an – kein Spiel erkannt".into()
        }
    )?;
    sayw!(out, "Leerlauf      : {} s", gaming::idle_duration().as_secs())?;
    sayw!(out, "Meldekanäle   : {}", app.config.meldungen.kanaele.iter().map(|c| c.label()).collect::<Vec<_>>().join(", "))?;
    if let Some(hint) = notify::popup_hint(&app.config) {
        sayw!(out, "  ACHTUNG: {hint}")?;
    }
    if app.config.meldungen.kanaele.contains(&Channel::Fenster) {
        sayw!(out, "Meldefenster  : {} | wartend: {} (erscheinen über den Agent, nie während eines Spiels)",
            if k9_core::window::available() { "verfügbar" } else { "NICHT verfügbar" },
            store.window_queue_count()?
        )?;
    }
    sayw!(out, "Erkennungen   : {} offen, {} gesamt | Entscheidungen: {} | Quarantäne: {} | wartende Meldungen: {}",
        c.pending,
        c.detections_total,
        c.decisions,
        c.quarantined,
        store.queued_count()?
    )?;
    if let Ok(src) = app.sources() {
        let loaded = SourceId::ALL.iter().filter(|id| src.get(**id).last_update.is_some()).count();
        sayw!(out, "Quellen       : {loaded}/{} geladen (Details: k9 quellen)", SourceId::ALL.len())?;
        for w in src.integrity_warnings() {
            sayw!(out, "  WARNUNG: {w}")?;
        }
    }
    sayw!(out, "Zeitpläne:")?;
    if app.config.zeitplan.is_empty() {
        sayw!(out, "  (keine)")?;
    }
    for e in &app.config.zeitplan {
        let last = store.last_run(&e.key())?.unwrap_or_else(|| "nie".into());
        let next = e.kind.next_occurrence(now).map(|t| t.format("%Y-%m-%d %H:%M").to_string());
        sayw!(out, "  - {} | zuletzt: {last}{}",
            e.label(),
            next.map(|n| format!(" | nächster: {n}")).unwrap_or_default()
        )?;
    }
    Ok(())
}

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE: &str = "K9-Agent";

/// Starts the agent at logon via the per-user Run key, without a console
/// window (conhost --headless). No administrator rights needed.
fn agent_autostart(modus: &str) -> Result<()> {
    use k9_core::winreg::{self, HKCU};
    match modus.trim().to_lowercase().as_str() {
        "an" | "ein" => {
            let exe = std::env::current_exe()?.with_file_name("k9-agent.exe");
            if !exe.is_file() {
                bail!("{} nicht gefunden – bitte zuerst bauen", exe.display());
            }
            let conhost = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\conhost.exe");
            let cmd = format!("\"{}\" --headless \"{}\"", conhost.display(), exe.display());
            winreg::set_string(HKCU, RUN_KEY, RUN_VALUE, &cmd)?;
            say!("Autostart eingeschaltet: Der Agent startet bei der Anmeldung unsichtbar (ohne Fenster).");
            say!("Eintrag: HKCU\\{RUN_KEY} -> {RUN_VALUE}");
            say!("Beenden: k9 agent-beenden   |   Ausschalten: k9 autostart-agent aus");
        }
        "aus" => {
            match winreg::delete_value(HKCU, RUN_KEY, RUN_VALUE) {
                Ok(()) => say!("Autostart ausgeschaltet."),
                Err(_) => say!("Autostart war nicht eingeschaltet."),
            }
        }
        "status" => match winreg::read_string(HKCU, RUN_KEY, RUN_VALUE) {
            Some(c) => say!("Autostart ist eingeschaltet: {c}"),
            None => say!("Autostart ist ausgeschaltet."),
        },
        other => bail!("Unbekannt: '{other}' (an, aus, status)"),
    }
    Ok(())
}

/// With the Windows service the abuse.ch key lies in its protected store.
fn has_abusech_key() -> Result<bool> {
    if k9_core::schutz::protected_sources().is_some() {
        return Ok(k9_core::dienst::service_secret_names().is_ok_and(|n| n.iter().any(|k| k == k9_core::sources::ABUSECH_KEY)));
    }
    Ok(secrets::get(k9_core::sources::ABUSECH_KEY)?.is_some())
}

/// Read-only driver report (changes nothing).
fn drivers_report(app: &App, all: bool, json: bool) -> Result<()> {
    use k9_core::treiber;
    priority::below_normal();
    let mut index = app.sources().map(|s| treiber::DriverIndex::load(&s.dir)).unwrap_or_default();
    if index.is_empty() {
        // Lists not loaded yet (e.g. before the first update): fetch them for this run only.
        if !json {
            say!("Treiberlisten noch nicht vorhanden – lade sie nur für diesen Lauf (Microsoft, LOLDrivers) …");
        }
        index = treiber::fetch_lists();
    }
    let mut drivers = treiber::inventory();
    // Packages that are installed but not in use count for memory integrity as well.
    let store = treiber::store_inventory(&drivers);
    drivers.extend(store);
    treiber::analyze(&mut drivers, &index, true);
    drivers.retain(|d| d.datei.is_file());
    drivers.sort_by_key(|d| (d.treffer.is_empty(), d.microsoft(), d.datei.file_name().map(|f| f.to_string_lossy().to_lowercase())));
    if json {
        let mut out = std::io::stdout().lock();
        out.write_all(serde_json::to_string_pretty(&drivers)?.as_bytes())?;
        return Ok(());
    }
    let hits: Vec<_> = drivers.iter().filter(|d| !d.treffer.is_empty()).collect();
    say!("Treiberprüfung ({} Treiberdateien, Listen: {} Einträge)", drivers.len(), index.len());
    say!("");
    say!("== Bekannte verwundbare/bösartige Treiber: {} ==", hits.len());
    for d in &hits {
        let h = &d.treffer[0];
        say!("* {} – {} {} ({}, {})", d.datei.display(), h.eintrag.art, h.eintrag.name, h.eintrag.quelle, h.abgleich);
        let version = if d.info.version.is_empty() { String::new() } else { format!("Version {} · ", d.info.version) };
        let program = d.produkt_installiert.as_deref().unwrap_or(&d.info.produkt);
        say!("    {version}{} · Programm: {}", d.hersteller(), if program.is_empty() { "unbekannt" } else { program });
        say!("    Dienst {} · Start {} · geladen {}", if d.dienst.is_empty() { "-" } else { &d.dienst }, d.start_label(), if d.geladen { "ja" } else { "nein" });
        let cves: Vec<String> = d.treffer.iter().flat_map(|h| h.eintrag.cve.clone()).collect();
        if !cves.is_empty() {
            say!("    CVE: {}", cves.join(", "));
        }
        say!("    Empfehlung: {}", treiber::recommendation(d));
    }
    say!("");
    let third: Vec<_> = drivers.iter().filter(|d| all || !d.microsoft()).collect();
    say!("== {} ({}) ==", if all { "Alle Treiber" } else { "Treiber anderer Hersteller" }, third.len());
    say!("(HVCI = tauglich für Speicherintegrität/VBS; „nein“ heißt: kann mit eingeschalteter Virtualisierung Probleme machen)");
    for d in &third {
        let hvci = match &d.pe {
            Some(p) if p.hvci_probleme.is_empty() => "ja".to_string(),
            Some(p) => format!("nein ({})", p.hvci_probleme.join("; ")),
            None => "?".into(),
        };
        say!(
            "- {} | {} {} | {} | Start {} | geladen {} | signiert {} | HVCI {}{}",
            d.datei.display(),
            d.hersteller(),
            d.info.version,
            d.produkt_installiert.as_deref().unwrap_or(if d.info.produkt.is_empty() { "-" } else { &d.info.produkt }),
            if d.vorrat { "nur im Treibervorrat" } else { d.start_label() },
            if d.geladen { "ja" } else { "nein" },
            if d.signiert { "ja" } else { "nein/Katalog" },
            hvci,
            if d.treffer.is_empty() { "" } else { " | AUF SPERRLISTE" }
        );
    }
    say!("");
    // The short answer to "why can't I switch on memory integrity?".
    // Drivers that come with Windows are left out (as in the list above): the rule of thumb
    // also hits old storage drivers Windows ships itself, and those do not stop Windows.
    let unfit: Vec<_> = third.iter().filter(|d| d.pe.as_ref().is_some_and(|p| !p.hvci_probleme.is_empty())).collect();
    say!("== Für die Speicherintegrität vermutlich untauglich: {} ==", unfit.len());
    for d in &unfit {
        let state = if d.geladen {
            "GELADEN – wird gerade benutzt"
        } else if d.vorrat {
            "nicht in Benutzung, nur im Treibervorrat von Windows (Paket installiert)"
        } else if d.dienst.is_empty() {
            "nicht in Benutzung, Datei ohne Dienst"
        } else {
            "nicht geladen, Dienst vorhanden"
        };
        say!("- {} | {} | {}", d.datei.display(), d.hersteller(), state);
    }
    say!("Das ist eine Faustregel von K9. Maßgeblich ist die Liste von Windows: Windows-Sicherheit → Gerätesicherheit →");
    say!("Kernisolierung → Speicher-Integrität einschalten; Windows nennt dann die Treiber, die es wirklich stören.");
    say!("");
    say!("Es wurde nichts verändert. Deinstallieren über „Apps & Features“, vorher einen Wiederherstellungspunkt anlegen.");
    Ok(())
}

/// Minimal confirmation window: static text, "Ja"/"Nein", "Nein" preselected,
/// no links, no help, no file dialogs. Returns the button id (6 = Ja).
fn confirmation_window(title: &str, text: &str) -> i32 {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxIndirectW, MessageBoxW, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_USERICON, MB_YESNO, MSGBOXPARAMSW,
    };
    let body = format!(
        "{}\n\nNur bestätigen, wenn du das gerade selbst ausgelöst hast.",
        text.replace('|', "\n")
    );
    let t: Vec<u16> = format!("K9 – {title}").encode_utf16().chain(std::iter::once(0)).collect();
    let b: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: NUL-terminated strings; no owner window; icon = resource 1 of this program.
    unsafe {
        let base = MB_YESNO | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND;
        // Our own icon plays no sound by itself: the warning sound as before.
        k9_core::window::play_sound(false);
        if let Ok(module) = GetModuleHandleW(None) {
            let p = MSGBOXPARAMSW {
                cbSize: std::mem::size_of::<MSGBOXPARAMSW>() as u32,
                hInstance: module.into(),
                lpszText: PCWSTR(b.as_ptr()),
                lpszCaption: PCWSTR(t.as_ptr()),
                dwStyle: base | MB_USERICON,
                lpszIcon: PCWSTR(std::ptr::without_provenance(1)),
                ..Default::default()
            };
            return MessageBoxIndirectW(&p).0;
        }
        MessageBoxW(None, PCWSTR(b.as_ptr()), PCWSTR(t.as_ptr()), base | MB_ICONWARNING).0
    }
}

/// `k9 pause-beenden`: ends the pause in the service and starts the agent (hidden, like at logon).
fn end_pause(app: &App) -> Result<()> {
    use k9_core::dienst::{request, Message, PROTOCOL};
    let port = app.config.dashboard.port;
    let was_paused = if k9_core::dienst::service_running() {
        match request(&Message::PauseBeenden { v: PROTOCOL })? {
            Message::Ergebnis { ok: true, text, .. } => text == "beendet",
            Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
            other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
        }
    } else {
        false
    };
    let was_running = agent_reachable(port);
    if !was_running {
        dienst::start_installed_agent(app);
        let t = std::time::Instant::now();
        while !agent_reachable(port) && t.elapsed() < std::time::Duration::from_secs(20) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    let running = agent_reachable(port);
    say!("{}", pause_result(was_paused, was_running, running));
    if !running {
        bail!("Der Agent startet nicht – siehe Protokoll in %LOCALAPPDATA%\\K9\\logs");
    }
    Ok(())
}

/// Result line of `k9 pause-beenden`.
fn pause_result(was_paused: bool, was_running: bool, running: bool) -> &'static str {
    match (was_paused, was_running, running) {
        (_, _, false) => "Der Agent laeuft nicht.",
        (true, _, true) => "Pause beendet, Agent laeuft.",
        (false, true, true) => "Keine Pause aktiv, Agent laeuft bereits.",
        (false, false, true) => "Keine Pause aktiv – Agent gestartet, laeuft.",
    }
}

fn agent_reachable(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), std::time::Duration::from_millis(300)).is_ok()
}

/// Shows or removes the firewall rules of the C2 block (only rules with our own name).
/// `k9 funktion <name> <an|aus>` and `k9 funktion status`.
fn funktion_command(app: &App, name: &str, args: &[String]) -> Result<()> {
    use k9_core::funktion::{self, FUNKTIONEN};
    if name.trim().eq_ignore_ascii_case("status") {
        return funktion_status(app);
    }
    if name.trim().eq_ignore_ascii_case("schattenkopien") && args.first().is_some_and(|a| a.eq_ignore_ascii_case("laufwerke")) {
        return shadow_drives_command(app, &args[1..]);
    }
    if args.len() > 1 {
        bail!("Zu viele Angaben – z. B.: k9 funktion {} an", name.trim());
    }
    let wert = args.first().map(String::as_str);
    let names = || FUNKTIONEN.iter().map(|f| f.name).collect::<Vec<_>>().join(", ");
    let f = funktion::find(name).with_context(|| format!("Unbekannte Funktion '{name}' (erlaubt: {}, status)", names()))?;
    let on = match wert.map(|w| w.trim().to_lowercase()).as_deref() {
        Some("an" | "ein") => true,
        Some("aus") => false,
        _ => bail!("Bitte 'an' oder 'aus' angeben, z. B.: k9 funktion {} an", f.name),
    };
    let file = app.paths.config_file();
    let text = std::fs::read_to_string(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
    let in_file = f.value(&k9_core::config::Config::parse(&text).with_context(|| format!("Fehler in {}", file.display()))?);
    let label = f.label();
    if in_file == on {
        say!("{label}: in config.toml bereits {}.", if on { "eingeschaltet" } else { "ausgeschaltet" });
    } else {
        let new = k9_core::funktion::set_bool(&text, f, on)?;
        std::fs::write(&file, new).with_context(|| format!("{} kann nicht geschrieben werden", file.display()))?;
        say!("{label}: in config.toml {}.", if on { "eingeschaltet" } else { "ausgeschaltet" });
    }
    let service = k9_core::dienst::service_running();
    let guarded = k9_core::schutz::confirmed_settings().is_some();
    if !on && service && guarded && f.value(&app.config) {
        // app.config already holds the confirmed values: still on until confirmed.
        say!("Ausschalten schwaecht den Schutz: Bis du die Aenderung bestaetigst, bleibt die Funktion an.");
        say!("Der Dienst meldet sie innerhalb von 30 Sekunden (Meldefenster/Dashboard): dort \"Aenderung uebernehmen\" waehlen");
        say!("und im Bestaetigungsfenster (Administrator) zustimmen. Warst du das nicht: \"Gesehen\" waehlen und vollstaendig scannen.");
    }
    if !service {
        say!("Der Dienst laeuft nicht – die Funktion wirkt, sobald er laeuft.");
    } else if f.live {
        if on || !f.value(&app.config) {
            say!("Der Dienst uebernimmt das innerhalb von 30 Sekunden, ohne Neustart.");
        }
    } else {
        say!("Neustart noetig: Diese Funktion wirkt erst nach dem naechsten Start des Dienstes");
        say!("(PC neu starten oder \"k9 dienst aktualisieren\" als Administrator).");
    }
    if on && f.name == "virustotal" && !virustotal_key_stored() {
        say!("Noch kein Schluessel gespeichert: .\\k9.exe geheimnis virustotal-key (Eingabe bleibt unsichtbar).");
    }
    Ok(())
}

/// `k9 wiederherstellen …`: files out of a shadow copy into a new folder (see `wiederherstellung`).
fn wiederherstellen_command(ordner: &str, stand: Option<&str>, ziel: Option<&str>, alles: bool) -> Result<()> {
    use k9_core::wiederherstellung as w;
    if !k9_core::paths::is_elevated() {
        say!("Schattenkopien lassen sich nur mit Administratorrechten lesen.");
        say!("So geht es: Rechtsklick auf das Startmenue, \"Terminal (Administrator)\" oeffnen und dort denselben Befehl eingeben, z. B.:");
        say!("  & \"C:\\Program Files\\K9\\k9.exe\" wiederherstellen liste");
        bail!("keine Administratorrechte");
    }
    let copies = w::list()?;
    if ordner.eq_ignore_ascii_case("liste") {
        if copies.is_empty() {
            say!("Es gibt keine Schattenkopien. K9 legt sie im Leerlauf an (k9 funktion schattenkopien an).");
            return Ok(());
        }
        say!("Schattenkopien (je Laufwerk die neueste zuerst):");
        for k in &copies {
            say!("  {}  {}", k.laufwerk, k.zeit);
        }
        say!("Dateien zurueckholen: k9 wiederherstellen \"<Ordner>\" [--stand \"JJJJ-MM-TT HH:MM\"]");
        return Ok(());
    }
    if let Some(s) = stand {
        if chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").is_err() {
            bail!("--stand bitte als \"JJJJ-MM-TT HH:MM\" angeben, z. B. \"2026-11-21 22:30\"");
        }
    }
    let heute = std::path::absolute(ordner).with_context(|| format!("Ordner {ordner}"))?;
    let Some(kopie) = w::choose(&copies, &heute, stand) else {
        bail!("Keine passende Schattenkopie fuer {} gefunden (siehe: k9 wiederherstellen liste)", heute.display());
    };
    let quelle = w::shadow_path(kopie, &heute).context("Bitte den Ordner mit Laufwerk angeben, z. B. C:\\Users\\Name\\Documents")?;
    let ziel = match ziel {
        Some(z) => std::path::absolute(z)?,
        None => {
            let desktop = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default()).join("Desktop");
            desktop.join(format!("K9-Wiederherstellung {}", k9_core::now_string().replace(':', "-")))
        }
    };
    say!("Ordner        : {}", heute.display());
    say!("Schattenkopie : Laufwerk {} vom {}", kopie.laufwerk, kopie.zeit);
    say!("Ziel          : {}", ziel.display());
    let b = w::restore(&quelle, &heute, &ziel, alles)?;
    say!("In der Schattenkopie: {} Dateien fehlen heute, {} sind heute veraendert, {} sind gleich.", b.fehlend, b.geaendert, b.gleich);
    say!("Kopiert: {} Dateien ({:.1} MB) nach {}", b.kopiert, b.bytes as f64 / 1e6, ziel.display());
    if b.fehler_gesamt > 0 {
        say!("Nicht kopiert: {} Dateien, z. B.:", b.fehler_gesamt);
        for f in &b.fehler {
            say!("  {f}");
        }
    }
    say!("Dein Ordner wurde nicht veraendert. Vergleiche die Dateien und kopiere zurueck, was du brauchst.");
    Ok(())
}

/// `k9 sprache [de|en|auto]`: shows or sets the language of dashboard, alert windows and tray.
fn language_command(app: &App, value: Option<&str>) -> Result<()> {
    let name = |v: &str| match v {
        "de" => "Deutsch",
        "en" => "English",
        _ => k9_core::t!("auto (wie Windows)", "auto (like Windows)"),
    };
    let Some(value) = value else {
        say!("{}", k9_core::tf!("Sprache: {} – eingestellt ist: {}", "Language: {} – configured: {}", if k9_core::sprache::en() { "English" } else { "Deutsch" }, name(&app.config.sprache)));
        say!("{}", k9_core::t!("Aendern mit: k9 sprache de | en | auto", "Change with: k9 sprache de | en | auto"));
        return Ok(());
    };
    let value = value.to_lowercase();
    let file = app.paths.config_file();
    let text = std::fs::read_to_string(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
    let new = k9_core::funktion::set_language(&text, &value)?;
    if new != text {
        std::fs::write(&file, new).with_context(|| format!("{} kann nicht geschrieben werden", file.display()))?;
    }
    // The answer already comes in the new language.
    k9_core::sprache::set(k9_core::sprache::resolve(&value));
    say!("{}", k9_core::tf!("Sprache jetzt: {}.", "Language now: {}.", name(&value)));
    say!(
        "{}",
        k9_core::t!(
            "Agent und Dienst uebernehmen das bei ihrem naechsten Start – am einfachsten den PC neu starten.",
            "Agent and service pick this up at their next start – the easiest way is to restart the PC."
        )
    );
    say!(
        "{}",
        k9_core::t!(
            "Meldungen, die schon in der Liste stehen, behalten ihre Sprache.",
            "Findings that are already in the list keep their language."
        )
    );
    Ok(())
}

/// `k9 funktion schattenkopien laufwerke C: F:`: sets the list of drives.
fn shadow_drives_command(app: &App, args: &[String]) -> Result<()> {
    let list: Vec<String> = args.iter().map(|a| k9_core::funktion::drive_letter(a).with_context(|| format!("Ungueltiges Laufwerk '{a}' – z. B.: C: F:"))).collect::<Result<_>>()?;
    let list = k9_core::funktion::drives(&list);
    if list.is_empty() {
        bail!("Bitte Laufwerke angeben, z. B.: k9 funktion schattenkopien laufwerke C: F:");
    }
    for d in &list {
        if !std::path::Path::new(&format!("{d}\\")).exists() {
            bail!("Laufwerk {d} gibt es auf diesem PC nicht");
        }
    }
    let file = app.paths.config_file();
    let text = std::fs::read_to_string(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
    let before = k9_core::config::Config::parse(&text).with_context(|| format!("Fehler in {}", file.display()))?.schutz.schattenkopien_laufwerke;
    let before = k9_core::funktion::drives(&before);
    if before == list {
        say!("Schattenkopien: Laufwerke in config.toml bereits {}.", list.join(" "));
    } else {
        let new = k9_core::funktion::set_drives(&text, &list)?;
        std::fs::write(&file, new).with_context(|| format!("{} kann nicht geschrieben werden", file.display()))?;
        say!("Schattenkopien: Laufwerke in config.toml jetzt {}.", list.join(" "));
    }
    let added: Vec<_> = list.iter().filter(|d| !before.contains(d)).cloned().collect();
    let removed: Vec<_> = before.iter().filter(|d| !list.contains(d)).cloned().collect();
    if !added.is_empty() {
        say!("Neu: {} – der Dienst uebernimmt das innerhalb von 30 Sekunden, ohne Neustart.", added.join(" "));
    }
    if !removed.is_empty() && k9_core::schutz::confirmed_settings().is_some() {
        say!("Entfernt: {} – das schwaecht den Schutz: Bis du die Aenderung bestaetigst (Meldefenster \"Aenderung uebernehmen\"", removed.join(" "));
        say!("und Bestaetigungsfenster), werden diese Laufwerke weiter gesichert.");
    }
    if !app.config.schutz.schattenkopien {
        say!("Hinweis: Schattenkopien sind aus – einschalten mit: k9 funktion schattenkopien an");
    }
    Ok(())
}

/// `k9 sicherheitscheck`: runs the security check now, prints and stores it for the dashboard.
fn sicherheitscheck_command(app: &App, programme: bool) -> Result<()> {
    use k9_core::sicherheit::{self, Bericht};
    let dir = &app.paths.data_dir;
    let previous = Bericht::load(dir);
    let mut b = sicherheit::check(&app.config.sicherheitscheck, previous.as_ref());
    if programme {
        say!("Pruefe Programme mit winget (das dauert etwa eine Minute) ...");
        match sicherheit::outdated_programs() {
            Some(list) => {
                b.set_updates(list);
            }
            None => say!("winget ist nicht verfuegbar oder hat nicht geantwortet."),
        }
    }
    for p in &b.punkte {
        say!("[{:<10}] {:<24} {}", p.ampel.label(), p.name, p.text);
        if !p.tipp.is_empty() {
            say!("             -> {}", p.tipp);
        }
    }
    if programme {
        for u in b.updates.iter().flatten() {
            say!("  {} {} -> {}: {}", u.name, u.installiert, u.verfuegbar, u.command());
        }
    }
    b.save(dir)?;
    say!("K9 aendert keine dieser Einstellungen. Das Ergebnis steht auch im Dashboard (Kasten \"Sicherheits-Check\").");
    Ok(())
}

/// `k9 test-speicher`: keeps the harmless test signature in private executable memory (never
/// on disk, nothing is executed there) so the memory scan has something to find.
fn test_speicher_command(minuten: u64) -> Result<()> {
    use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
    let sig = k9_core::engine::test_pattern_bytes();
    let minuten = minuten.clamp(1, 120);
    // SAFETY: own allocation, written within its size, freed below; the bytes are never run.
    unsafe {
        let mem = VirtualAlloc(None, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if mem.is_null() {
            bail!("Speicher konnte nicht angelegt werden");
        }
        std::ptr::copy_nonoverlapping(sig.as_ptr(), (mem as *mut u8).add(64), sig.len());
        say!("Die harmlose Testsignatur steht jetzt {minuten} Minuten nur im Arbeitsspeicher dieses Programms (PID {}).", std::process::id());
        say!("Der Speicher-Scan findet sie, sobald du {} Minuten nichts eingegeben hast (Schalter: k9 funktion speicher-scan an).", 10);
        std::thread::sleep(std::time::Duration::from_secs(minuten * 60));
        let _ = VirtualFree(mem, 0, MEM_RELEASE);
    }
    say!("Testprogramm beendet.");
    Ok(())
}

/// `k9 speicher-scan`: preview of the memory scan (reads no memory).
fn speicher_command(app: &App) -> Result<()> {
    use k9_core::{autostart, realtime as rt, speicher};
    let cfg = &app.config;
    say!("Speicher-Scan: {} (Leerlauf ab {} Minuten)", if cfg.echtzeit.speicher_scan { "an" } else { "aus" }, cfg.echtzeit.speicher_scan_leerlauf_minuten.max(2));
    if let Some(ac) = speicher::always_on_anticheat() {
        say!("{ac} ist installiert und staendig geladen - auf diesem PC laeuft der Speicher-Scan nie.");
        return Ok(());
    }
    let procs: Vec<speicher::Prozess> = rt::process_snapshot()
        .values()
        .filter(|p| p.pid > 4)
        .map(|p| speicher::Prozess { pid: p.pid, name: p.name.clone(), path: rt::process_path(p.pid).map(|x| x.display().to_string()).unwrap_or_default() })
        .collect();
    match speicher::blocker(&procs, &cfg.gaming.spiele_ordner, &cfg.gaming.spiele_prozesse) {
        Some(why) => say!("Gerade wuerde NICHT geprueft: {why}."),
        None => say!("Gerade laeuft kein Spiel und kein Anti-Cheat-Programm."),
    }
    let own = k9_core::dienst::install_dir().display().to_string();
    let mut targets: Vec<String> = Vec::new();
    for p in &procs {
        let path = std::path::Path::new(&p.path);
        if p.path.is_empty() {
            continue;
        }
        let signer = autostart::is_signed(path).then(|| k9_core::treiber::signer_name(path)).flatten();
        if speicher::target_allowed(p, signer.as_deref(), autostart::is_user_writable(path), &cfg.gaming.spiele_ordner, &cfg.gaming.spiele_prozesse, &own, std::slice::from_ref(&cfg.quellen.clamav_programmordner)) {
            let line = format!("{} ({})", p.path, signer.as_deref().unwrap_or("unsigniert"));
            if !targets.contains(&line) {
                targets.push(line);
            }
        }
    }
    targets.sort();
    say!("{} von {} laufenden Programmen wuerden geprueft (Benutzerordner oder unsigniert; nie Windows, Store-Apps, Microsoft, Trend Micro, K9, ClamAV, Spiele, Anti-Cheat):", targets.len(), procs.len());
    for t in &targets {
        say!("  {t}");
    }
    say!("Es wurde kein Arbeitsspeicher gelesen.");
    Ok(())
}

/// `k9 luecken`: shows what the daily check would report for the last days (reports nothing).
fn luecken_command(tage: i64) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let from = now - chrono::Duration::days(tage.clamp(1, 14));
    say!("Lade neue Sicherheitsluecken (Hoch/Kritisch) der letzten {} Tage von der NVD (etwa 30 Sekunden) ...", tage.clamp(1, 14));
    let cves = k9_core::luecken::load(from, now).map_err(|e| anyhow::anyhow!(e))?;
    let found = k9_core::luecken::with_epss(k9_core::luecken::check(&k9_core::software::inventory(), &cves, &k9_core::software::winget_ids().unwrap_or_default()));
    say!("{} neue CVE (Hoch/Kritisch), {} betreffen installierte Programme.", cves.len(), found.len());
    for f in &found {
        let d = f.details.clone().unwrap_or_default();
        say!("[{}] {}{}", f.severity.label(), f.threat_name, if k9_core::arbeitsordner::reason_of(f.details.as_ref()).is_some() { "  (nur leise im Dashboard)" } else { "" });
        for c in d["cves"].as_array().into_iter().flatten() {
            say!(
                "    {} {}{}{}{} – {}",
                c["cve"].as_str().unwrap_or(""),
                c["schwere"].as_str().unwrap_or(""),
                c["behoben_ab"].as_str().map(|v| format!(", behoben ab {v}")).unwrap_or_default(),
                c["genannt"].as_str().map(|v| format!(", genannt: {v}")).unwrap_or_default(),
                c["epss_text"].as_str().unwrap_or(""),
                c["name"].as_str().unwrap_or("")
            );
        }
        say!("    {}", d["hinweis"].as_str().unwrap_or(""));
        say!("    Loesung: {}", d["loesung"].as_str().unwrap_or(""));
    }
    say!("Es wurde nichts gemeldet oder geaendert. Der Agent prueft einmal am Tag und meldet Treffer.");
    Ok(())
}

/// `k9 heimnetz`: the devices the agent knows in the home network.
fn heimnetz_command(app: &App) -> Result<()> {
    let store = app.store()?;
    let Some(json) = store.meta_get(k9_core::heimnetz::META_KEY)? else {
        say!("Noch keine Geraete bekannt – der Agent prueft das Heimnetz etwa 2 Minuten nach seinem Start und dann stuendlich.");
        return Ok(());
    };
    let known: k9_core::heimnetz::Bekannt = serde_json::from_str(&json)?;
    say!("{} bekannte Geraete im Heimnetz:", known.len());
    for (mac, g) in &known {
        say!(
            "  {:<16} {}  zuerst {}  zuletzt {}{}",
            g.ip,
            mac,
            g.erstmals,
            g.zuletzt,
            if k9_core::heimnetz::is_random_mac(mac) { "  (zufaellige Adresse: Handy/Tablet)" } else { "" }
        );
    }
    Ok(())
}

/// `k9 arbeitsordner`: shows or changes the work folder list in config.toml.
fn arbeitsordner_command(app: &App, aktion: &str, ordner: Option<&str>) -> Result<()> {
    let file = app.paths.config_file();
    let text = std::fs::read_to_string(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
    let cfg = k9_core::config::Config::parse(&text).with_context(|| format!("Fehler in {}", file.display()))?;
    let list = cfg.arbeitsordner.ordner.clone();
    let same = |a: &str, b: &str| a.trim().trim_end_matches('\\').eq_ignore_ascii_case(b.trim().trim_end_matches('\\'));
    match aktion.trim().to_lowercase().as_str() {
        "status" => {
            let mut effective = cfg.clone();
            k9_core::schutz::enforce_confirmed(&mut effective);
            say!("Arbeitsordner: {}", if effective.arbeitsordner.aktiv { "an" } else { "aus" });
            for o in &list {
                let wirkt = effective.arbeitsordner.ordner.iter().any(|e| same(e, o));
                say!("  {o}{}", if wirkt { "" } else { "  (wartet auf deine Bestaetigung)" });
            }
            for p in &cfg.arbeitsordner.programme {
                say!("  Programm: {p}");
            }
            say!("Verhaltensmeldungen von dort erscheinen nur leise im Dashboard; bekannte Schadsoftware wird immer normal gemeldet.");
            Ok(())
        }
        "hinzufuegen" | "hinzufügen" => {
            let o = ordner.context("Bitte den Ordner angeben, z. B.: k9 arbeitsordner hinzufuegen \"F:\\Projekte\"")?.trim().trim_end_matches('\\').to_string();
            let expanded = k9_core::paths::expand_env(&o);
            if !std::path::Path::new(&expanded).is_dir() {
                bail!("Ordner {o} gibt es nicht");
            }
            if expanded.trim_end_matches('\\').len() < 3 {
                bail!("Ein ganzes Laufwerk kann kein Arbeitsordner sein");
            }
            if list.iter().any(|e| same(e, &o)) {
                say!("{o} ist bereits ein Arbeitsordner.");
                return Ok(());
            }
            let mut new = list.clone();
            new.push(o.clone());
            std::fs::write(&file, k9_core::arbeitsordner::set_folders(&text, &new)?).with_context(|| format!("{} kann nicht geschrieben werden", file.display()))?;
            say!("Arbeitsordner {o} in config.toml eingetragen.");
            if k9_core::schutz::confirmed_settings().is_some() {
                say!("Das schwaecht den Schutz: Es wirkt erst, wenn du im Meldefenster \"Aenderung uebernehmen\" waehlst und im Bestaetigungsfenster \"Ja\".");
            }
            Ok(())
        }
        "entfernen" => {
            let o = ordner.context("Bitte den Ordner angeben, z. B.: k9 arbeitsordner entfernen \"F:\\Projekte\"")?;
            let new: Vec<String> = list.iter().filter(|e| !same(e, o)).cloned().collect();
            if new.len() == list.len() {
                bail!("{o} ist kein Arbeitsordner (k9 arbeitsordner status)");
            }
            std::fs::write(&file, k9_core::arbeitsordner::set_folders(&text, &new)?).with_context(|| format!("{} kann nicht geschrieben werden", file.display()))?;
            say!("Arbeitsordner {o} entfernt – Meldungen von dort kommen ab sofort wieder normal (spaetestens nach 30 Sekunden).");
            Ok(())
        }
        other => bail!("Unbekannte Aktion '{other}' (status, hinzufuegen, entfernen)"),
    }
}

fn virustotal_key_stored() -> bool {
    let name = k9_core::virustotal::VT_KEY;
    if k9_core::dienst::service_running() {
        if let Ok(names) = k9_core::dienst::service_secret_names() {
            return names.iter().any(|n| n == name);
        }
    }
    secrets::get(name).ok().flatten().is_some()
}

fn funktion_status(app: &App) -> Result<()> {
    use k9_core::funktion::FUNKTIONEN;
    let file = app.paths.config_file();
    let text = std::fs::read_to_string(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
    let in_file = k9_core::config::Config::parse(&text).with_context(|| format!("Fehler in {}", file.display()))?;
    let service = k9_core::dienst::service_running();
    say!("Funktionen (config.toml: {}):", file.display());
    for f in FUNKTIONEN {
        let (written, applies) = (f.value(&in_file), f.value(&app.config));
        let state = match (written, applies) {
            (true, true) => "an".to_string(),
            (false, false) => "aus".to_string(),
            (false, true) => "an – Ausschalten wartet auf deine Bestaetigung".to_string(),
            (true, false) => "aus (config.toml: an)".to_string(),
        };
        let restart = if f.live { "" } else { "  [Aenderung erst nach Neustart des Dienstes]" };
        say!("  {:<20} {:<46} {state}{restart}", f.name, k9_core::term::ascii(f.label()));
    }
    let drives = |c: &k9_core::config::Config| k9_core::funktion::drives(&c.schutz.schattenkopien_laufwerke).join(" ");
    let (written, applies) = (drives(&in_file), drives(&app.config));
    let extra = if written == applies { String::new() } else { format!("  (config.toml: {written} – Entfernen wartet auf deine Bestaetigung)") };
    say!("  {:<20} {:<46} {applies}{extra}", "", "Laufwerke der Schattenkopien");
    let ps = k9_core::skripte::policy_state();
    say!("  {:<20} {:<46} {}", "powershell-protokoll", "Vollstaendige PowerShell-Protokollierung",
        match ps { [true, true] => "an", [false, false] => "aus (nur verdaechtige Skripte)", _ => "teilweise an" });
    say!("  {:<20} {:<46} {}", "virustotal-key", "VirusTotal-Schluessel", if virustotal_key_stored() { "gespeichert" } else { "nicht gespeichert" });
    if !service {
        say!("Hinweis: Der Dienst laeuft nicht – die Funktionen des Dienstes sind gerade nicht aktiv.");
    }
    say!("Schalten: k9 funktion <name> an|aus   (an: sofort; aus: mit Bestaetigung)");
    Ok(())
}

fn firewall_command(app: &App, action: &str) -> Result<()> {
    use k9_core::firewall;
    match action.trim().to_lowercase().as_str() {
        "vorschau" => {
            // Read only: what the block would cover now (no firewall change).
            let today: String = k9_core::now_string().chars().take(10).collect();
            let mut targets = Vec::new();
            match k9_core::sources::download(firewall::FEODO_URL, &[], 10 * 1024 * 1024) {
                Ok(b) => targets.extend(firewall::parse_feodo(&String::from_utf8_lossy(&b), &today)),
                Err(e) => say!("Feodo Tracker nicht abrufbar: {e:#}"),
            }
            let dir = k9_core::schutz::protected_sources().or_else(|| app.sources().ok().map(|s| s.dir));
            if let Some(d) = &dir {
                targets.extend(firewall::threatfox_targets(&k9_core::sources::load_threatfox(d), &today));
            }
            let candidates = targets.len();
            let (cdn, notes) = firewall::load_cdn(dir.as_ref().map(|d| d.join("cdn")).as_deref(), true);
            let choice = firewall::select(targets, &cdn);
            say!("Firewall-Sperre – Vorschau (nichts wird geaendert):");
            say!("  Kandidaten: {candidates}, gesperrt wuerden: {} in {} Regeln", choice.count(), choice.groups.len());
            if let Some((from, to)) = &choice.dates {
                say!("  Zeitraum der gesperrten Eintraege: {from} bis {to}");
            }
            if choice.cut > 0 {
                say!("  Ueber der Grenze von {} (aeltere, nicht gesperrt): {}", firewall::MAX_TARGETS, choice.cut);
            }
            say!("  CDN-Netze: {}", notes.join(", "));
            say!("  {}", choice.skipped_text().unwrap_or_else(|| "Keine Adresse in geteilten CDN-Netzen.".into()));
            for (p, list) in &choice.skipped {
                for (ip, port, seen) in list {
                    say!("    {p}: {ip}:{port} (zuletzt {seen})");
                }
            }
            // Planned changes against the rules that exist now (reading only).
            use firewall::FwBackend;
            let wanted = firewall::wanted_rules(&choice.groups, &today, "");
            match firewall::ComFirewall::open().and_then(|mut f| f.list()) {
                Ok(current) => {
                    let plan = firewall::plan(&wanted, &current);
                    say!("  Abgleich mit den vorhandenen Regeln: {}", plan.summary());
                    for r in &plan.update {
                        say!("    aendern:   {}", r.name);
                    }
                    for r in &plan.add {
                        say!("    neu:       {}", r.name);
                    }
                    for n in &plan.remove {
                        say!("    entfernen: {n}");
                    }
                    for n in &plan.conflicts {
                        say!("    uebergangen (fremde Regel mit gleichem Namen): {n}");
                    }
                }
                Err(e) => say!("  Vorhandene Regeln nicht lesbar: {e:#}"),
            }
            Ok(())
        }
        "eingang" => {
            // Read only: which inbound rules would be reported if they were new.
            use k9_core::eingang;
            let rules = eingang::read_store();
            let inbound = rules.iter().filter(|r| r.inbound).count();
            let signed_ok = |p: &std::path::Path| k9_core::autostart::signature(p) != k9_core::autostart::Signature::Unsigned;
            let all: Vec<&eingang::InRule> = rules.iter().collect();
            let reps = eingang::reports(&all, &rules, &signed_ok);
            say!("Eingehende Regeln: {inbound} (von {} insgesamt). Wuerden gemeldet, wenn sie neu angelegt werden: {}", rules.len(), reps.len());
            for r in &reps {
                say!(
                    "  [{}] {} - {} {} - fuer {} ({}x)",
                    r.assessment.severity.label(),
                    r.rule.name,
                    r.rule.protocol_name(),
                    if r.rule.ports.is_empty() { "alle Ports".to_string() } else { format!("Port {}", r.rule.ports) },
                    if r.rule.app.is_empty() { "jedes Programm" } else { r.rule.app.as_str() },
                    r.ids.len()
                );
            }
            Ok(())
        }
        "status" => {
            say!("Firewall-Sperre (Botnetz-Steuerserver): {}", if app.config.schutz.firewall_sperre { "eingeschaltet" } else { "aus" });
            let own = firewall::list_own_rules();
            say!("  Eigene Regeln (Gruppe \"{}\"): {}", firewall::RULE_GROUP, own.len());
            for r in &own {
                say!("    {}", r.name);
            }
            Ok(())
        }
        "entfernen" => {
            if !k9_core::paths::is_elevated() {
                bail!("Bitte PowerShell als Administrator oeffnen und den Befehl dort erneut ausfuehren.");
            }
            // With the service running, it removes the rules itself – otherwise its guard would
            // restore them at once – and leaves them off until the next regular renewal.
            if k9_core::dienst::service_running() {
                use k9_core::dienst::{request, Message, PROTOCOL};
                match request(&Message::FirewallEntfernen { v: PROTOCOL })? {
                    Message::Ergebnis { ok: true, text, .. } => {
                        say!("Dienst: {text}. Die Sperre bleibt aus bis zur naechsten regulaeren Erneuerung (taeglich, neue ThreatFox-Daten oder Neustart des Dienstes).");
                        say!("Dauerhaft aus: k9 funktion firewall aus");
                    }
                    Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
                    other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
                }
                return Ok(());
            }
            let n = firewall::remove_own_rules()?;
            say!("{}", if n > 0 { format!("{n} Regel(n) der Firewall-Sperre entfernt (nur eigene).") } else { "Keine Regeln der Firewall-Sperre gefunden.".to_string() });
            if app.config.schutz.firewall_sperre {
                say!("Hinweis: firewall_sperre ist in config.toml noch eingeschaltet – der Dienst legt die Regeln sonst beim naechsten Abgleich wieder an.");
            }
            Ok(())
        }
        other => bail!("Unbekannt: '{other}' (status, vorschau, eingang, entfernen)"),
    }
}

/// Switches the Windows policy "Script Block Logging" (Windows PowerShell and PowerShell 7).
/// Only the user runs this (administrator); "aus" removes exactly the values set here.
fn powershell_protocol(action: &str) -> Result<()> {
    use k9_core::winreg::{create_key, delete_value, read_dword, set_dword, HKLM};
    const VALUE: &str = k9_core::skripte::POLICY_VALUE;
    let state = k9_core::skripte::policy_state;
    match action.trim().to_lowercase().as_str() {
        "status" => {
            let s = state();
            say!("Vollstaendige PowerShell-Skriptprotokollierung:");
            say!("  Windows PowerShell : {}", if s[0] { "an" } else { "aus (nur verdaechtige Skripte)" });
            say!("  PowerShell 7       : {}", if s[1] { "an" } else { "aus (nur verdaechtige Skripte)" });
            Ok(())
        }
        a @ ("an" | "aus") => {
            if !k9_core::paths::is_elevated() {
                bail!("Bitte PowerShell als Administrator oeffnen und den Befehl dort erneut ausfuehren.");
            }
            for k in k9_core::skripte::POLICY_KEYS {
                if a == "an" {
                    // The policy key usually does not exist yet.
                    create_key(HKLM, k)?;
                    set_dword(HKLM, k, VALUE, 1)?;
                } else if read_dword(HKLM, k, VALUE).is_some() {
                    delete_value(HKLM, k, VALUE)?;
                }
            }
            say!("Vollstaendige PowerShell-Skriptprotokollierung ist jetzt {a}. Wirkt fuer neu gestartete PowerShell-Fenster.");
            if a == "an" {
                say!("Hinweis: Windows schreibt die Skripte dann auch ins Ereignisprotokoll (Microsoft-Windows-PowerShell/Operational).");
            }
            Ok(())
        }
        other => bail!("Unbekannt: '{other}' (an, aus, status)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn ending_a_pause_reports_clearly() {
        assert_eq!(pause_result(true, false, true), "Pause beendet, Agent laeuft.");
        assert_eq!(pause_result(false, true, true), "Keine Pause aktiv, Agent laeuft bereits.");
        assert_eq!(pause_result(false, false, true), "Keine Pause aktiv – Agent gestartet, laeuft.");
        assert_eq!(pause_result(true, false, false), "Der Agent laeuft nicht.");
    }

    /// Help texts are printed by clap directly – they must be plain ASCII.
    #[test]
    fn help_texts_are_ascii() {
        let mut cmd = Cli::command();
        let mut texts = vec![cmd.render_long_help().to_string()];
        for sub in cmd.get_subcommands_mut() {
            texts.push(sub.render_long_help().to_string());
            for sub2 in sub.get_subcommands_mut() {
                texts.push(sub2.render_long_help().to_string());
            }
        }
        for t in texts {
            assert!(t.is_ascii(), "Nicht-ASCII im Hilfetext:\n{t}");
        }
    }

    /// All console output must go through say!/say_err!/sayw! (umlaut transliteration).
    #[test]
    fn console_output_uses_transliteration() {
        let src = include_str!("main.rs");
        for macro_name in [["print", "ln!("].concat(), ["eprint", "ln!("].concat(), ["write", "ln!("].concat()] {
            let hits: Vec<&str> = src.lines().filter(|l| l.contains(macro_name.as_str()) && !l.trim_start().starts_with("//")).collect();
            assert!(hits.is_empty(), "Direkte Ausgabe ohne Umlaut-Umschreibung: {hits:?}");
        }
    }
}
