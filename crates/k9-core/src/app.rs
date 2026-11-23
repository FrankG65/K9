//! Shared start-up for agent and CLI: paths, config, database, engines,
//! checks (files, software, URLs, autostart) and source updates.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;

use crate::config::{Channel, Config};
use crate::engine::{self, Engine, SortedHashEngine};
use crate::gaming::{self, GamingState};
use crate::model::Severity;
use crate::notify::{self, DashboardLink, DispatchReport};
use crate::paths::AppPaths;
use crate::pipeline::{self, Outcome};
use crate::scanner::{ScanCache, ScanControl, ScanStats, Scanner};
use crate::secrets;
use crate::sources::{SourceId, Sources};
use crate::store::Store;
use crate::window::{self, WindowChoice, WindowContent};
use crate::{autostart, clamav, software, urls};

pub struct App {
    pub paths: AppPaths,
    pub config: Config,
}

/// The checks a scan can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Dateien,
    Software,
    Urls,
    Autostart,
}

impl Check {
    pub const ALL: [Check; 4] = [Check::Dateien, Check::Software, Check::Urls, Check::Autostart];

    pub fn parse(s: &str) -> Option<Check> {
        match s.trim().to_lowercase().as_str() {
            "dateien" | "datei" | "files" => Some(Check::Dateien),
            "software" | "cve" | "programme" => Some(Check::Software),
            "urls" | "url" | "phishing" | "verlauf" => Some(Check::Urls),
            "autostart" | "autostarts" => Some(Check::Autostart),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Check::Dateien => "Dateien",
            Check::Software => "Software (CVE)",
            Check::Urls => "Phishing-/Schad-Adressen",
            Check::Autostart => "Autostarts",
        }
    }

    /// Checks of a schedule entry (empty = all).
    pub fn from_list(list: &[String]) -> Vec<Check> {
        let v: Vec<Check> = list.iter().filter_map(|s| Check::parse(s)).collect();
        if v.is_empty() {
            Check::ALL.to_vec()
        } else {
            v
        }
    }
}

pub struct ScanReport {
    pub stats: ScanStats,
    pub outcome: Outcome,
    pub notified: DispatchReport,
    pub gaming: GamingState,
    /// Notes about engines/sources (e.g. "ClamAV nicht installiert").
    pub notes: Vec<String>,
}

/// Loaded engines plus a running clamd (stopped when dropped).
pub struct EngineSet {
    pub scanner: Scanner,
    pub notes: Vec<String>,
    /// Signature state for the scan cache.
    pub state: String,
    _clamd: Option<clamav::Daemon>,
}

/// Scan cache backed by its own database connection (writes are buffered).
struct DbCache {
    store: Mutex<Store>,
    state: String,
    clean: Mutex<Vec<(String, u64, i64)>>,
}

impl ScanCache for DbCache {
    fn is_clean(&self, path: &str, size: u64, mtime: i64) -> bool {
        self.store.lock().unwrap().cache_is_clean(path, size, mtime, &self.state).unwrap_or(false)
    }
    fn mark_clean(&self, path: String, size: u64, mtime: i64) {
        self.clean.lock().unwrap().push((path, size, mtime));
    }
}

impl App {
    pub fn open() -> Result<Self> {
        let paths = AppPaths::resolve()?;
        paths.ensure()?;
        let mut config = Config::load_or_create(&paths.config_file())?;
        crate::sprache::apply(&config.sprache);
        if !paths.portable {
            let withheld = crate::schutz::enforce_confirmed(&mut config);
            if !withheld.is_empty() {
                tracing::warn!("Nicht bestätigte Sicherheitseinstellungen werden noch nicht angewendet: {}", withheld.join("; "));
            }
        }
        Ok(Self { paths, config })
    }

    /// For the Windows service: no folders are created and config.toml is only
    /// read (with the user's rights by the caller); missing or broken -> defaults.
    pub fn open_service(config_text: Option<String>) -> Result<Self> {
        let paths = AppPaths::resolve()?;
        let mut config = config_text.and_then(|t| Config::parse(&t).ok()).unwrap_or_default();
        crate::sprache::apply(&config.sprache);
        // The service is the authority: weaker values without confirmation never apply.
        let withheld = crate::schutz::enforce_confirmed(&mut config);
        if !withheld.is_empty() {
            tracing::warn!("Nicht bestätigte Sicherheitseinstellungen gelten nicht: {}", withheld.join("; "));
        }
        Ok(Self { paths, config })
    }

    pub fn store(&self) -> Result<Store> {
        Store::open(&self.paths.database())
    }

    pub fn sources(&self) -> Result<Sources> {
        Sources::open(&self.paths, &self.config.quellen)
    }

    pub fn excluded(&self) -> Vec<PathBuf> {
        let mut excluded = self.config.exclusions();
        excluded.push(self.paths.data_dir.clone());
        if let Ok(s) = self.sources() {
            excluded.push(s.dir);
        }
        excluded
    }

    /// Scanner with only the built-in test signatures and the user lists
    /// (no downloads needed). Used by tests and as a fallback.
    pub fn scanner(&self) -> Scanner {
        Scanner::new(engine::default_engines(&self.paths.signature_dir()), self.config.max_file_size(), self.excluded())
            .with_threads(self.config.scan.max_threads.min(crate::scanner::MAX_CONFIG_THREADS))
    }

    /// All available engines. `with_clamav` starts clamd if needed (only for
    /// real scans – it needs about 1 GB RAM while running).
    pub fn engines(&self, with_clamav: bool) -> EngineSet {
        self.engines_with(with_clamav, true)
    }

    /// Engine set for real-time use. `with_yara = false` gives the light set
    /// (hash lists, patterns, URLs) used while a game runs.
    pub fn engines_with(&self, with_clamav: bool, with_yara: bool) -> EngineSet {
        let q = &self.config.quellen;
        let mut notes = Vec::new();
        let mut list: Vec<Box<dyn Engine>> = engine::default_engines(&self.paths.signature_dir());
        let mut state = String::from("basis");
        let mut clamd = None;
        match self.sources() {
            Ok(src) => {
                state.push_str(&src.state_fingerprint());
                if q.abusech_aktiv {
                    let mb = std::fs::read(src.path(crate::sources::MB_HASH_FILE)).unwrap_or_default();
                    if mb.len() >= 32 {
                        list.push(Box::new(SortedHashEngine::new("malwarebazaar", "MalwareBazaar", mb)));
                    } else {
                        notes.push(t!("MalwareBazaar-Hashes fehlen (abuse.ch-Auth-Key nötig, dann 'k9 quellen aktualisieren')", "MalwareBazaar hashes are missing (abuse.ch auth key needed, then 'k9 quellen aktualisieren')").into());
                    }
                    let tf: String = crate::sources::load_threatfox(&src.dir)
                        .into_iter()
                        .filter(|(_, i)| i.typ == "sha256")
                        .map(|(v, _)| v + "\n")
                        .collect();
                    let tf = crate::sources::hashes_to_sorted_bin(&tf);
                    if !tf.is_empty() {
                        list.push(Box::new(SortedHashEngine::new("threatfox", "ThreatFox", tf)));
                    }
                }
                if q.yara_aktiv && with_yara {
                    match crate::yara::YaraEngine::load(&src.path(crate::sources::YARA_COMPILED_FILE), q.yara_min_score) {
                        Ok(y) => list.push(Box::new(y)),
                        Err(_) => notes.push("YARA-Regeln fehlen – 'k9 quellen aktualisieren'".into()),
                    }
                }
                let db = urls::UrlDb::load(&src.dir);
                if !db.is_empty() {
                    list.push(Box::new(urls::UrlFileEngine::new(db)));
                }
                if q.clamav_aktiv && with_clamav {
                    if clamav::installed(q).is_none() {
                        notes.push(t!("ClamAV ist nicht installiert (winget install Cisco.ClamAV) – ClamAV-Prüfung übersprungen", "ClamAV is not installed (winget install Cisco.ClamAV) – ClamAV check skipped").into());
                    } else {
                        match clamav::Daemon::start(&src.dir, q) {
                            Ok(d) => {
                                clamd = Some(d);
                                list.push(Box::new(clamav::ClamdEngine::new(q.clamav_port)));
                                state.push_str("+clamav");
                            }
                            Err(e) => notes.push(format!("ClamAV nicht verfügbar: {e:#}")),
                        }
                    }
                }
                for w in src.integrity_warnings() {
                    notes.push(w);
                }
            }
            Err(e) => notes.push(format!("Quellenordner nicht verfügbar: {e:#}")),
        }
        let ids: Vec<&str> = list.iter().map(|e| e.id()).collect();
        state.push_str(&ids.join(","));
        let state = crate::sha256_hex(state.as_bytes())[..16].to_string();
        let scanner = Scanner::new(list, self.config.max_file_size(), self.excluded()).with_threads(self.config.scan.max_threads.min(crate::scanner::MAX_CONFIG_THREADS));
        EngineSet { scanner, notes, state, _clamd: clamd }
    }

    pub fn dashboard_link(&self) -> Option<DashboardLink> {
        match secrets::dashboard_token(&self.paths) {
            Ok(token) => Some(DashboardLink { port: self.config.dashboard.port, token }),
            Err(e) => {
                tracing::warn!("Dashboard-Token nicht verfügbar: {e:#}");
                None
            }
        }
    }

    /// Decision check + store + notification for findings of any check.
    pub fn handle(&self, store: &Store, findings: &[crate::model::Finding]) -> Result<(Outcome, DispatchReport, GamingState)> {
        // Behaviour in work folders (other Claude projects, builds): stored quietly.
        let arbeit = crate::arbeitsordner::live(&self.paths.config_file(), &self.config);
        let findings = crate::arbeitsordner::mark(&arbeit, findings);
        let outcome = pipeline::process_findings(store, &self.paths.quarantine_dir(), &findings)?;
        let gaming = gaming::detect(&self.config.gaming);
        let loud: Vec<_> = outcome.new.iter().filter(|d| !crate::arbeitsordner::is_quiet(d)).cloned().collect();
        let notified = notify::dispatch(&self.config, store, loud, &gaming, self.dashboard_link())?;
        // "Später" in the Meldefenster lasts at most until the next check finds the item again.
        if self.config.meldungen.kanaele.contains(&Channel::Fenster) && !gaming.active {
            let now = crate::now_string();
            for id in &outcome.pending_again {
                if store.detection(*id)?.is_some_and(|d| !crate::arbeitsordner::is_quiet(&d)) {
                    store.enqueue_window(*id, &now, true)?;
                }
            }
        }
        Ok((outcome, notified, gaming))
    }

    /// File scan with the test signatures only (no downloads, no clamd).
    pub fn scan_and_notify(&self, roots: &[PathBuf], control: &dyn ScanControl) -> Result<ScanReport> {
        let scanner = self.scanner();
        let (findings, stats) = scanner.scan(roots, control);
        let store = self.store()?;
        let (outcome, notified, gaming) = self.handle(&store, &findings)?;
        self.log_summary(&store, "Scan", &stats, &outcome)?;
        Ok(ScanReport { stats, outcome, notified, gaming, notes: Vec::new() })
    }

    fn log_summary(&self, store: &Store, what: &str, stats: &ScanStats, outcome: &Outcome) -> Result<()> {
        store.log_event(
            "info",
            &format!(
                "{what} beendet: {} Dateien ({} unverändert übersprungen), {} neu, {} bereits offen, {} freigegeben, {} automatisch behandelt, {:.1} s",
                stats.files,
                stats.cached,
                outcome.new.len(),
                outcome.already_pending,
                outcome.ignored,
                outcome.auto.len(),
                stats.seconds
            ),
        )
    }

    /// Runs the selected checks with all available sources.
    /// `progress` receives short German status lines.
    pub fn run_checks(
        &self,
        checks: &[Check],
        roots: &[PathBuf],
        control: &dyn ScanControl,
        progress: &mut dyn FnMut(&str),
    ) -> Result<ScanReport> {
        self.run_checks_with_threads(checks, roots, control, progress, None)
    }

    /// Like `run_checks`; `threads` replaces `[scan] max_threads` for this one run
    /// (the fast full scan of the dashboard).
    pub fn run_checks_with_threads(
        &self,
        checks: &[Check],
        roots: &[PathBuf],
        control: &dyn ScanControl,
        progress: &mut dyn FnMut(&str),
        threads: Option<usize>,
    ) -> Result<ScanReport> {
        let store = self.store()?;
        let mut findings = Vec::new();
        let mut notes = Vec::new();
        let mut stats = ScanStats::default();
        let needs_engines = checks.contains(&Check::Dateien) || checks.contains(&Check::Autostart);
        let set = needs_engines.then(|| {
            progress(t!("Lade Signaturen und Regeln …", "Loading signatures and rules …"));
            let mut set = self.engines(true);
            if let Some(n) = threads {
                set.scanner.set_threads(n);
            }
            set
        });
        if let Some(s) = &set {
            progress(&format!("Aktive Engines: {}", s.scanner.engine_ids().join(", ")));
            notes.extend(s.notes.iter().cloned());
        }

        if checks.contains(&Check::Dateien) && !roots.is_empty() {
            let set = set.as_ref().expect("engines loaded");
            progress(t!("Prüfe Dateien …", "Checking files …"));
            let cache = DbCache { store: Mutex::new(self.store()?), state: set.state.clone(), clean: Mutex::new(Vec::new()) };
            let (f, s) = set.scanner.scan_with(roots, control, self.config.scan.cache.then_some(&cache as &dyn ScanCache));
            store.cache_store_clean(&cache.clean.into_inner().unwrap(), &set.state)?;
            findings.extend(f);
            stats = s;
        }
        if checks.contains(&Check::Autostart) {
            let set = set.as_ref().expect("engines loaded");
            progress(t!("Prüfe Autostarts (Run-Schlüssel, Autostart-Ordner, Aufgaben, Dienste) …", "Checking autostarts (Run keys, startup folder, tasks, services) …"));
            let entries = autostart::enumerate();
            progress(&format!("{} Autostart-Einträge gefunden", entries.len()));
            findings.extend(autostart::findings(&entries, &set.scanner));
        }
        drop(set); // stop clamd as early as possible
        if checks.contains(&Check::Urls) {
            progress(t!("Prüfe Browserverlauf und hosts-Datei …", "Checking browser history and hosts file …"));
            match self.sources() {
                Ok(src) => {
                    let db = urls::UrlDb::load(&src.dir);
                    if db.is_empty() {
                        notes.push("Keine Phishing-/Schad-URL-Listen vorhanden – 'k9 quellen aktualisieren'".into());
                    } else {
                        if self.config.quellen.browserverlauf_pruefen {
                            let (f, errors) = urls::history_findings(&db, &urls::find_histories());
                            findings.extend(f);
                            notes.extend(errors.into_iter().map(|e| format!("Browserverlauf nicht lesbar: {e}")));
                        }
                        if let Ok(text) = std::fs::read_to_string(urls::hosts_path()) {
                            findings.extend(urls::hosts_findings(&db, &text));
                        }
                    }
                }
                Err(e) => notes.push(format!("{e:#}")),
            }
        }
        if checks.contains(&Check::Software) && self.config.quellen.cve_aktiv {
            match self.check_software(progress) {
                Ok((f, n)) => {
                    findings.extend(f);
                    notes.extend(n);
                }
                Err(e) => notes.push(format!("Software-Prüfung: {e:#}")),
            }
        }
        let (outcome, notified, gaming) = self.handle(&store, &findings)?;
        self.log_summary(&store, "Prüfung", &stats, &outcome)?;
        Ok(ScanReport { stats, outcome, notified, gaming, notes })
    }

    /// Installed software against CISA KEV + NVD.
    pub fn check_software(&self, progress: &mut dyn FnMut(&str)) -> Result<(Vec<crate::model::Finding>, Vec<String>)> {
        let src = self.sources()?;
        let kev = software::load_kev(&src.path(crate::sources::KEV_FILE))?;
        let inv = software::inventory();
        progress(&format!("{} installierte Programme, {} KEV-Einträge – prüfe Kandidaten …", inv.len(), kev.len()));
        let mut nvd = software::Nvd::new(&src.dir);
        let mut notes = Vec::new();
        if !nvd.has_key() {
            notes.push(t!("Ohne NVD-API-Key ist die erste Software-Prüfung langsam (6 s je CVE). Kostenlos: https://nvd.nist.gov/developers/request-an-api-key, dann 'k9 geheimnis nvd-key'.", "Without an NVD API key the first software check is slow (6 s per CVE). Free: https://nvd.nist.gov/developers/request-an-api-key, then 'k9 geheimnis nvd-key'.").into());
        }
        let winget_found = software::winget_ids();
        // winget back: the message about its absence is closed.
        if winget_found.is_some() {
            if let Ok(store) = self.store() {
                for d in store.pending_detections().unwrap_or_default().iter().filter(|d| d.rule_id == software::WINGET_RULE) {
                    let _ = store.mark_detection(d.id, crate::model::DetectionStatus::Automatisch, Some(crate::model::Action::Gesehen));
                    let _ = store.log_event("info", &format!("Erledigt: winget startet wieder (Meldung #{})", d.id));
                }
            }
        }
        let winget_gone = winget_found.is_none();
        let winget = winget_found.unwrap_or_default();
        let mut last = std::time::Instant::now();
        let (mut f, total) = software::check(&inv, &kev, &mut |id| nvd.cve(id), &winget, &mut |done, total| {
            if last.elapsed().as_secs() >= 10 || done == total {
                last = std::time::Instant::now();
                progress(&format!("Software-Prüfung: {done}/{total} CVE-Kandidaten"));
            }
        });
        if nvd.offline {
            notes.push(t!("NVD war nicht erreichbar – nur zwischengespeicherte CVE-Daten genutzt.", "NVD was not reachable – only cached CVE data was used.").into());
        }
        if winget_gone {
            notes.push(t!("winget ließ sich nicht starten – veraltete Programme werden ohne Befehl zum Aktualisieren gemeldet.", "winget could not be started – outdated programs are reported without an update command.").into());
            f.push(software::winget_missing());
        }
        notes.push(format!("Software: {} Programme, {total} CVE-Kandidaten geprüft, {} NVD-Abfragen.", inv.len(), nvd.requests));
        Ok((f, notes))
    }

    /// Updates sources. `only_due`: respect the intervals (agent).
    pub fn update_sources(&self, only: Option<SourceId>, only_due: bool) -> Result<Vec<Result<String, String>>> {
        self.update_sources_with(&self.config.quellen, only, only_due)
    }

    /// Like `update_sources`, with the source settings to use. The service passes its live
    /// settings: a source switched on with `k9 funktion … an` is then loaded at the next update
    /// and not only after the service was restarted (found on 21.11.2026: Sigma and the two
    /// network lists were "an" but never loaded).
    pub fn update_sources_with(&self, quellen: &crate::config::QuellenConfig, only: Option<SourceId>, only_due: bool) -> Result<Vec<Result<String, String>>> {
        let mut src = self.sources()?;
        let now = chrono::Local::now().naive_local();
        let mut out = Vec::new();
        for id in SourceId::ALL {
            if only.is_some_and(|o| o != id) || !id.enabled(quellen) {
                continue;
            }
            if only_due && !src.is_due(id, quellen, now) {
                continue;
            }
            let res = src.update(id, quellen).map_err(|e| format!("{}: {e:#}", id.label()));
            // The service (without the user's rights) logs only to its own log.
            if let Ok(store) = self.store().map_err(|_| ()) {
                let _ = match &res {
                    Ok(m) => store.log_event("info", m),
                    Err(m) => store.log_event("fehler", m),
                };
            }
            out.push(res);
        }
        Ok(out)
    }

    /// Queues a Meldefenster for every pending detection that has none yet
    /// (agent start: e.g. detections from before the channel was enabled).
    pub fn queue_pending_windows(&self) -> Result<()> {
        if !self.config.meldungen.kanaele.contains(&Channel::Fenster) {
            return Ok(());
        }
        let store = self.store()?;
        let now = crate::now_string();
        for d in store.pending_detections()?.into_iter().filter(|d| !crate::arbeitsordner::is_quiet(d)) {
            store.enqueue_window(d.id, &now, false)?;
        }
        Ok(())
    }

    /// Shows due Meldefenster one after another (blocking). Stops as soon as
    /// `is_gaming` reports a game, so no window ever pops up during play.
    pub fn show_due_windows(&self, is_gaming: &dyn Fn() -> bool) -> Result<usize> {
        if !self.config.meldungen.kanaele.contains(&Channel::Fenster) || !window::available() {
            return Ok(0);
        }
        let store = self.store()?;
        let mut shown = 0;
        loop {
            let Some((det, more)) = store.next_window(&crate::now_string())? else { break };
            // Quiet (work folder): dashboard only.
            if crate::arbeitsordner::is_quiet(&det) {
                store.remove_window(det.id)?;
                continue;
            }
            // During a game only a ransomware alarm or a critical theft of logins may appear (configurable).
            let critical_theft = det.severity == Severity::Kritisch && (det.rule_id.starts_with("INFOSTEALER") || det.rule_id == "BROWSER:FERNSTEUERUNG" || det.rule_id == "KETTE:ANGRIFF" || det.rule_id.starts_with("SELBSTSCHUTZ:"));
            let urgent = (det.rule_id.starts_with("RANSOMWARE") || critical_theft) && self.config.echtzeit.ransomware_meldung_trotz_spiel;
            if !urgent && is_gaming() {
                break;
            }
            let url = self.dashboard_link().map(|l| l.home());
            let choice = window::show(&WindowContent::for_detection(&det, more, url.as_deref()))?;
            shown += 1;
            if let Err(e) = self.handle_window_choice(&store, det.id, choice) {
                window::show_error(&format!("Die Aktion konnte nicht ausgeführt werden:\n{e:#}\n\nDer Fund bleibt offen; du wirst später erneut gefragt."));
            }
        }
        Ok(shown)
    }

    /// Applies a choice from the Meldefenster exactly like the dashboard does.
    /// "Später" (or a failed action) keeps the detection pending and asks again
    /// after `spaeter_minuten`.
    pub fn handle_window_choice(&self, store: &Store, detection_id: i64, choice: WindowChoice) -> Result<()> {
        let later = (chrono::Local::now() + chrono::Duration::minutes(self.config.meldungen.spaeter_minuten.max(1) as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        match choice {
            WindowChoice::Later => {
                store.enqueue_window(detection_id, &later, true)?;
                Ok(())
            }
            WindowChoice::Decide(action) => {
                store.remove_window(detection_id)?;
                match pipeline::apply_decision(store, &self.paths.quarantine_dir(), detection_id, action, Some("im Meldefenster entschieden")) {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        // Decided meanwhile in the dashboard? Then there is nothing left to do.
                        if store.detection(detection_id)?.is_some_and(|d| d.status == crate::model::DetectionStatus::Offen) {
                            store.enqueue_window(detection_id, &later, true)?;
                            store.log_event("fehler", &format!("Meldefenster: {} fehlgeschlagen: {e:#}", action.label()))?;
                            return Err(e);
                        }
                        Ok(())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, DetectionStatus};

    /// Which YARA rules of a YARA Forge package fire on files that are certainly clean? Reads the
    /// rules straight from the downloaded archive K9_YARA_ZIP (nothing is unpacked to disk) and
    /// scans the folders in K9_BENCH_DIR (separated by ';', read only, nothing is stored or
    /// reported) with 16 threads, at most K9_BENCH_SECONDS seconds per folder.
    /// `cargo test --release -p k9-core yara_clean_files -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn yara_clean_files() {
        struct Deadline(std::time::Instant, u64);
        impl crate::scanner::ScanControl for Deadline {
            fn checkpoint(&self) -> bool {
                self.0.elapsed().as_secs() < self.1
            }
        }
        let zip = std::fs::read(std::env::var("K9_YARA_ZIP").expect("K9_YARA_ZIP")).unwrap();
        let (name, rules) = crate::sources::unzip_entry(&zip, |n| n.ends_with(".yar"), 400 * 1024 * 1024).unwrap();
        let source = String::from_utf8(rules).unwrap();
        let min_score: i64 = std::env::var("K9_YARA_MIN_SCORE").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
        let started = std::time::Instant::now();
        let engine = crate::yara::YaraEngine::from_source(&source, min_score).unwrap();
        println!("YARA {name}: {} Regeln kompiliert in {:.0} s, Mindestwert {min_score}", engine.rule_count(), started.elapsed().as_secs_f64());
        let scanner = Scanner::new(vec![Box::new(engine)], 256 * 1024 * 1024, vec![]).with_threads(16);
        let limit: u64 = std::env::var("K9_BENCH_SECONDS").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
        let mut per_rule: std::collections::BTreeMap<String, (usize, String)> = std::collections::BTreeMap::new();
        let mut loud = 0usize;
        for dir in std::env::var("K9_BENCH_DIR").expect("K9_BENCH_DIR").split(';') {
            let (found, s) = scanner.scan(&[PathBuf::from(dir)], &Deadline(std::time::Instant::now(), limit));
            println!(
                "YARA-ORDNER {dir}: dateien={} MB={:.0} sekunden={:.0} abgebrochen={} treffer={}",
                s.files,
                s.bytes as f64 / 1e6,
                s.seconds,
                s.aborted,
                found.len()
            );
            for f in found {
                // What K9 does with the hit since 0.43.0: quiet for settled, trusted files.
                let quiet = crate::arbeitsordner::yara_quiet_reason_for(&f);
                println!("YARA-DATEI {} | {} | {}", if quiet.is_some() { "leise" } else { "LAUT " }, f.rule_id, f.path.display());
                loud += quiet.is_none() as usize;
                let e = per_rule.entry(f.rule_id.clone()).or_insert((0, f.path.display().to_string()));
                e.0 += 1;
            }
        }
        println!("YARA-REGELN mit Treffern auf sauberen Dateien: {}, davon bleiben laut: {loud} Dateien", per_rule.len());
        let mut list: Vec<_> = per_rule.into_iter().collect();
        list.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
        for (rule, (n, example)) in list {
            println!("YARA-TREFFER {n:5} x {rule} | z. B. {example}");
        }
    }

    /// How does the scan speed grow with the number of threads on this PC? Scans the folder
    /// K9_BENCH_DIR (read only, nothing is stored or reported) with the real engines of the
    /// installed K9 (without ClamAV), once per number in K9_BENCH_THREADS ("8,16,24").
    /// `cargo test --release -p k9-core scan_scaling -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn scan_scaling() {
        let root = PathBuf::from(std::env::var("K9_BENCH_DIR").expect("K9_BENCH_DIR"));
        let counts: Vec<usize> = std::env::var("K9_BENCH_THREADS").unwrap_or_else(|_| "8,16".into()).split(',').filter_map(|v| v.trim().parse().ok()).collect();
        let app = App::open().unwrap();
        let mut set = app.engines_with(false, true);
        println!("Engines: {:?}", set.scanner.engine_ids());
        for n in counts {
            set.scanner.set_threads(n);
            let (found, s) = set.scanner.scan(std::slice::from_ref(&root), &crate::scanner::NoControl);
            println!(
                "BENCH threads={n} dateien={} MB={:.0} sekunden={:.1} MB_je_s={:.0} cpu_s={:.0} kerne={:.1} funde={} fehler={}",
                s.files,
                s.bytes as f64 / 1e6,
                s.seconds,
                s.bytes as f64 / 1e6 / s.seconds.max(0.001),
                s.cpu_seconds,
                s.cpu_seconds / s.seconds.max(0.001),
                found.len(),
                s.errors
            );
        }
    }

    #[test]
    fn quiet_findings_open_no_window() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let paths = AppPaths { config_dir: dir.path().into(), data_dir: dir.path().join("daten"), portable: true };
        paths.ensure().unwrap();
        let work = dir.path().join("arbeit");
        let mut config = Config::default();
        config.arbeitsordner.ordner = vec![work.display().to_string()];
        let text = crate::arbeitsordner::set_folders(crate::config::DEFAULT_CONFIG, &config.arbeitsordner.ordner).unwrap();
        std::fs::write(paths.config_file(), text).unwrap();
        let app = App { paths, config };
        let store = app.store().unwrap();
        let alarm = |file: &std::path::Path, sha: &str| crate::model::Finding {
            path: PathBuf::from("Ransomware-Verdacht: viele Dateien"),
            sha256: sha.into(),
            size: 0,
            rule_id: "RANSOMWARE:VERHALTEN".into(),
            threat_name: "Ransomware-Verdacht".into(),
            category: "Ransomware".into(),
            severity: Severity::Kritisch,
            engine: "echtzeit".into(),
            kind: crate::model::Kind::Prozess,
            details: Some(serde_json::json!({ "art": "viele", "dateien": [file.display().to_string()] })),
        };
        let (out, _, _) = app.handle(&store, &[alarm(&work.join("a"), "s1"), alarm(&work.join("b"), "s2")]).unwrap();
        assert_eq!(out.new.len(), 1, "zwei Alarme im selben Arbeitsordner: ein Eintrag");
        assert!(crate::arbeitsordner::is_quiet(&out.new[0]));
        app.queue_pending_windows().unwrap();
        assert_eq!(store.window_queue_count().unwrap(), 0, "leise: kein Meldefenster");
        let (out, _, _) = app.handle(&store, &[alarm(&dir.path().join("Dokumente").join("c.docx"), "s3")]).unwrap();
        assert!(!crate::arbeitsordner::is_quiet(&out.new[0]), "ausserhalb normal");
    }

    #[test]
    fn window_choices_map_to_decisions() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let paths = AppPaths { config_dir: dir.path().into(), data_dir: dir.path().join("daten"), portable: true };
        paths.ensure().unwrap();
        let app = App { paths, config: Config::default() };
        let store = app.store().unwrap();
        let scan_dir = dir.path().join("scan");
        std::fs::create_dir_all(&scan_dir).unwrap();
        let file = scan_dir.join("probe.txt");
        std::fs::write(&file, crate::engine::test_pattern_bytes()).unwrap();
        let (findings, _) = app.scanner().scan(std::slice::from_ref(&scan_dir),&crate::scanner::NoControl);
        let out = pipeline::process_findings(&store, &app.paths.quarantine_dir(), &findings).unwrap();
        let id = out.new[0].id;
        store.enqueue_window(id, "2000-01-01 00:00:00", false).unwrap();

        // Später: stays pending, not due right now any more.
        app.handle_window_choice(&store, id, WindowChoice::Later).unwrap();
        assert_eq!(store.detection(id).unwrap().unwrap().status, DetectionStatus::Offen);
        assert!(store.next_window(&crate::now_string()).unwrap().is_none());
        assert_eq!(store.window_queue_count().unwrap(), 1);

        // Quarantäne: applied and remembered like in the dashboard.
        app.handle_window_choice(&store, id, WindowChoice::Decide(Action::Quarantaene)).unwrap();
        assert!(!file.exists());
        let d = store.detection(id).unwrap().unwrap();
        assert_eq!((d.status, d.action), (DetectionStatus::Entschieden, Some(Action::Quarantaene)));
        assert_eq!(store.find_decision(&d.sha256, &d.rule_id).unwrap().unwrap().action, Action::Quarantaene);
        assert_eq!(store.window_queue_count().unwrap(), 0);

        // A late click after deciding in the dashboard is harmless.
        app.handle_window_choice(&store, id, WindowChoice::Decide(Action::Freigabe)).unwrap();
        assert_eq!(store.find_decision(&d.sha256, &d.rule_id).unwrap().unwrap().action, Action::Quarantaene);
    }
}
