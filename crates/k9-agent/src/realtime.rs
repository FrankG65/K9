//! Real-time protection in the agent (user mode, no driver).
//!
//! Threads: one file watcher per folder + one file worker, process monitor,
//! autostart monitor, network/DNS monitor and removable-drive monitor.
//! Every finding goes through the normal pipeline (remembered decisions,
//! Meldefenster/Dashboard). While a game runs only light checks run
//! (hash lists); YARA is deferred until the game ends. ClamAV is only used by
//! scheduled/manual scans (clamd needs ~1 GB RAM).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use k9_core::app::{Check, EngineSet};
use k9_core::model::{Finding, Kind, Severity};
use k9_core::paths::expand_env;
use k9_core::realtime::{self as rt, Change, FileEvent};
use k9_core::{autostart, urls};

use crate::{scheduler, Shared};

/// Shared state of the real-time threads.
struct Rt {
    shared: Arc<Shared>,
    tokio: tokio::runtime::Handle,
    light: RwLock<Option<EngineSet>>,
    heavy: RwLock<Option<EngineSet>>,
    /// Signature state the engine sets were built for.
    state: Mutex<String>,
    /// Recently started processes (pid -> start time, path), for ransomware suspects.
    recent: Mutex<HashMap<u32, (Instant, Option<PathBuf>)>>,
    /// Files seen while gaming – scanned with YARA after the game.
    deferred: Mutex<HashSet<PathBuf>>,
}

impl Rt {
    fn gaming(&self) -> bool {
        self.shared.gaming.lock().map(|g| g.active).unwrap_or(false)
    }

    /// (Re)builds the engine sets when the signature state changed.
    fn refresh_engines(&self) {
        let app = &self.shared.app;
        let current = app.sources().map(|s| s.state_fingerprint()).unwrap_or_default();
        let mut st = self.state.lock().unwrap();
        if *st == current && self.light.read().unwrap().is_some() {
            return;
        }
        *self.light.write().unwrap() = Some(app.engines_with(false, false));
        *self.heavy.write().unwrap() = Some(app.engines_with(false, true));
        *st = current;
        tracing::info!("Echtzeitschutz: Signaturen geladen");
    }

    /// Scans one file: light engines while gaming (YARA later), else all.
    fn scan_file(&self, path: &Path) -> Vec<Finding> {
        let gaming = self.gaming();
        let set = if gaming { &self.light } else { &self.heavy };
        let guard = set.read().unwrap();
        let Some(engines) = guard.as_ref() else { return Vec::new() };
        let found = engines.scanner.scan_file(path).ok().flatten().map(|(f, _)| f).unwrap_or_default();
        if gaming && found.is_empty() {
            self.deferred.lock().unwrap().insert(path.to_path_buf());
        }
        found
    }

    /// Hands findings to the pipeline and shows the Meldefenster right away.
    fn report(&self, findings: Vec<Finding>, urgent: bool) {
        if findings.is_empty() {
            return;
        }
        let app = &self.shared.app;
        let res = (|| -> anyhow::Result<usize> {
            let store = app.store()?;
            let (outcome, _, _) = app.handle(&store, &findings)?;
            if urgent {
                // Ransomware: first in the window queue, shown even during a game (configurable).
                for d in outcome.new.iter().filter(|d| !k9_core::arbeitsordner::is_quiet(d)) {
                    store.enqueue_window(d.id, "2000-01-01 00:00:00", true)?;
                }
            }
            Ok(outcome.new.len())
        })();
        match res {
            Ok(n) if n > 0 => {
                tracing::warn!("Echtzeitschutz: {n} neue Erkennung(en)");
                let _g = self.tokio.enter();
                scheduler::show_windows(&self.shared);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("Echtzeitschutz: Fund nicht verarbeitet: {e:#}"),
        }
    }
}

pub fn start(shared: Arc<Shared>, tokio: tokio::runtime::Handle) {
    let cfg = shared.app.config.echtzeit.clone();
    if !cfg.aktiv {
        tracing::info!("Echtzeitschutz ist ausgeschaltet ([echtzeit] aktiv = false)");
        return;
    }
    let _ = RUNTIME.set(tokio.clone());
    let rt = Arc::new(Rt {
        shared: shared.clone(),
        tokio,
        light: RwLock::new(None),
        heavy: RwLock::new(None),
        state: Mutex::new(String::new()),
        recent: Mutex::new(HashMap::new()),
        deferred: Mutex::new(HashSet::new()),
    });
    let r = rt.clone();
    spawn("vs-echtzeit-start", move || {
        // Monitors first, so nothing is missed while the signatures load.
        let loader = r.clone();
        spawn("vs-signaturen", move || loader.refresh_engines());
        start_file_protection(r.clone());
        if cfg.prozesse {
            let r2 = r.clone();
            spawn("vs-prozesse", move || process_monitor(r2));
        }
        if cfg.autostart {
            let r2 = r.clone();
            spawn("vs-autostart", move || autostart_monitor(r2));
            // Browser extensions are a common way to persist as well.
            let r2 = r.clone();
            spawn("vs-erweiterungen", move || extension_monitor(r2));
        }
        if cfg.netzwerk {
            let r2 = r.clone();
            spawn("vs-netzwerk", move || network_monitor(r2));
        }
        if cfg.usb {
            let r2 = r.clone();
            spawn("vs-usb", move || usb_monitor(r2));
        }
        let r2 = r.clone();
        spawn("vs-nachpruefung", move || deferred_worker(r2));
        let r2 = r.clone();
        spawn("vs-speicher", move || memory_monitor(r2));
        tracing::info!("Echtzeitschutz aktiv");
    });
}

/// When the service last reported ransomware behaviour: the agent then keeps its own alarm
/// for the same attack to itself (one message, and the service names the exact program).
static SERVICE_RANSOM: Mutex<Option<Instant>> = Mutex::new(None);

fn service_reported_ransomware(within: Duration) -> bool {
    SERVICE_RANSOM.lock().map(|g| g.is_some_and(|t| t.elapsed() < within)).unwrap_or(false)
}

/// Findings of the Windows service: same handling as the agent's own.
pub fn report_external(shared: &Arc<Shared>, findings: Vec<Finding>) {
    let app = &shared.app;
    let ransom = findings.iter().any(|f| f.rule_id == "RANSOMWARE:VERHALTEN");
    if ransom {
        if let Ok(mut g) = SERVICE_RANSOM.lock() {
            *g = Some(Instant::now());
        }
    }
    let res = (|| -> anyhow::Result<usize> {
        let store = app.store()?;
        let (outcome, _, _) = app.handle(&store, &findings)?;
        if ransom {
            // Ransomware: first in the window queue, shown even during a game (configurable).
            for d in outcome.new.iter().filter(|d| d.rule_id.starts_with("RANSOMWARE:") && !k9_core::arbeitsordner::is_quiet(d)) {
                store.enqueue_window(d.id, "2000-01-01 00:00:00", true)?;
            }
        }
        Ok(outcome.new.len())
    })();
    match res {
        Ok(n) if n > 0 => {
            tracing::warn!("Dienst: {n} neue Erkennung(en)");
            if let Some(h) = RUNTIME.get() {
                let _g = h.enter();
                scheduler::show_windows(shared);
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("Dienst: Fund nicht verarbeitet: {e:#}"),
    }
}

/// Tokio runtime of the agent (for threads outside of it).
static RUNTIME: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    let _ = std::thread::Builder::new().name(name.into()).spawn(f);
}

fn stopping(rt: &Rt) -> bool {
    rt.shared.is_stopping()
}

// ================================================================== files

fn start_file_protection(rt: Arc<Rt>) {
    let cfg = &rt.shared.app.config.echtzeit;
    let mut dirs: Vec<PathBuf> = if cfg.ordner.is_empty() {
        rt::default_watch_dirs()
    } else {
        cfg.ordner.iter().map(|d| PathBuf::from(expand_env(d))).filter(|p| p.is_dir()).collect()
    };
    let canary_base = dirs.clone();
    dirs.extend(cfg.zusatz_ordner.iter().map(|d| PathBuf::from(expand_env(d))).filter(|p| p.is_dir()));
    let (tx, rx) = mpsc::channel::<FileEvent>();
    for d in &dirs {
        let tx = tx.clone();
        let d = d.clone();
        spawn("vs-ordner", move || {
            if let Err(e) = rt::watch_directory(&d, tx) {
                tracing::warn!("{e:#}");
            }
        });
    }
    // Canary files in the folders ransomware goes for first.
    let canary_dirs: Vec<PathBuf> = if cfg.ransomware && !cfg.ordner.is_empty() {
        canary_base
    } else if cfg.ransomware {
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        ["Documents", "Desktop", "Pictures"].iter().map(|s| PathBuf::from(&profile).join(s)).filter(|p| p.is_dir()).collect()
    } else {
        Vec::new()
    };
    let canaries: HashSet<PathBuf> = rt::ensure_canaries(&canary_dirs).into_iter().collect();
    // Canaries outside the watched folders (e.g. Pictures) get their own watcher.
    for d in &canary_dirs {
        if !dirs.iter().any(|w| d.starts_with(w)) {
            let tx = tx.clone();
            let d = d.clone();
            spawn("vs-ordner", move || {
                let _ = rt::watch_directory(&d, tx);
            });
        }
    }
    drop(tx);
    tracing::info!("Echtzeit-Ordnerüberwachung: {} Ordner, {} Köderdateien", dirs.len(), canaries.len());
    {
        let r = rt.clone();
        let d = dirs.clone();
        spawn("vs-nachpruefung", move || catch_up(r, d));
    }
    let (clam_tx, clam_rx) = mpsc::channel();
    if cfg.clamav && rt.shared.app.config.quellen.clamav_aktiv {
        let r = rt.clone();
        spawn("vs-clamav", move || clamav_worker(r, clam_rx));
    }
    spawn("vs-dateien", move || file_worker(rt, rx, canaries, clam_tx));
}

/// Files that arrived while the agent was not running (e.g. a download before the
/// logon) are checked once after the start: changed in the last 24 hours, at most
/// 2000 files, gently and never while gaming. The scan cache skips known files.
fn catch_up(rt: Arc<Rt>, dirs: Vec<PathBuf>) {
    std::thread::sleep(Duration::from_secs(60));
    let since = std::time::SystemTime::now() - Duration::from_secs(24 * 3600);
    let max = rt.shared.app.config.echtzeit.max_dateigroesse_mb * 1024 * 1024;
    let data_dir = rt.shared.app.paths.data_dir.clone();
    let mut files = Vec::new();
    for d in &dirs {
        for entry in walkdir::WalkDir::new(d).max_depth(3).into_iter().filter_map(Result::ok) {
            if files.len() >= 2000 {
                break;
            }
            let p = entry.path();
            if !entry.file_type().is_file() || p.starts_with(&data_dir) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() == 0 || (max > 0 && meta.len() > max) || meta.modified().map_or(true, |m| m < since) {
                continue;
            }
            files.push(p.to_path_buf());
        }
    }
    let mut found = 0;
    for f in &files {
        while rt.gaming() {
            if stopping(&rt) {
                return;
            }
            std::thread::sleep(Duration::from_secs(30));
        }
        if stopping(&rt) {
            return;
        }
        let hits = rt.scan_file(f);
        found += hits.len();
        rt.report(hits, false);
        std::thread::sleep(Duration::from_millis(20));
    }
    tracing::info!("Nachprüfung nach dem Start: {} Dateien, {found} Funde", files.len());
}

fn file_worker(rt: Arc<Rt>, rx: mpsc::Receiver<FileEvent>, canaries: HashSet<PathBuf>, clam: mpsc::Sender<PathBuf>) {
    let app = &rt.shared.app;
    let cfg = app.config.echtzeit.clone();
    let max = cfg.max_dateigroesse_mb * 1024 * 1024;
    let data_dir = app.paths.data_dir.to_string_lossy().to_lowercase();
    let sources_dir = app.sources().map(|s| s.dir.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut debounce = rt::Debouncer::default();
    // Ransomware check on its own, short timer: every second counts (measured 19.11.2026 with
    // LockBit: 160 small files in under five seconds). The scan below keeps its longer pause.
    let mut quick = rt::Debouncer::default();
    let mut burst = rt::BurstDetector::new(Duration::from_secs(20), rt::RANSOMWARE_BURST);
    // The early stop for new unsigned programs: a second, much lower count.
    let mut fresh = rt::BurstDetector::new(Duration::from_secs(20), rt::RANSOMWARE_FRESH);
    // Canaries to look at: (path, not before, looks so far).
    let mut canary_due: Vec<(PathBuf, Instant, u8)> = Vec::new();
    let mut deletions = rt::Deletions::default();
    let mut last_refresh = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                let lower = ev.path.to_string_lossy().to_lowercase();
                if lower.starts_with(&data_dir) || (!sources_dir.is_empty() && lower.starts_with(&sources_dir)) {
                    continue;
                }
                if cfg.ransomware && canaries.contains(&ev.path) {
                    if !canary_due.iter().any(|(p, ..)| *p == ev.path) {
                        canary_due.push((ev.path.clone(), Instant::now(), 0));
                    }
                    continue;
                }
                match ev.change {
                    Change::Removed | Change::RenamedFrom => {
                        if ev.change == Change::Removed {
                            deletions.note(Instant::now());
                        }
                        debounce.forget(&ev.path);
                        quick.forget(&ev.path);
                    }
                    _ => {
                        if cfg.ransomware {
                            quick.touch(ev.path.clone(), Instant::now());
                        }
                        debounce.touch(ev.path, Instant::now());
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if stopping(&rt) {
            return;
        }
        // Canaries that were touched: one look each, never a wait (see `rt::canary_look`).
        let mut i = 0;
        while i < canary_due.len() {
            if canary_due[i].1 > Instant::now() {
                i += 1;
                continue;
            }
            let (path, _, tries) = canary_due[i].clone();
            match rt::canary_look(&path) {
                Some(true) => {
                    canary_due.swap_remove(i);
                    ransomware_alarm(&rt, vec![path], k9_core::t!("Köderdatei wurde verändert oder gelöscht", "a canary file was changed or deleted"), "koeder", true);
                }
                Some(false) => {
                    canary_due.swap_remove(i);
                }
                None => {
                    // Changed a moment ago and held open now: someone is writing it. A new
                    // unsigned program that runs is frozen at once; whether the canary really
                    // changed shows the next look.
                    if tries == 0 {
                        ransomware_alarm(&rt, vec![path.clone()], k9_core::t!("eine Köderdatei wird gerade verändert, während ein neues unsigniertes Programm läuft", "a canary file is being changed while a new unsigned program is running"), "neu", true);
                    }
                    if tries >= 20 {
                        tracing::debug!("Köderdatei {} bleibt gesperrt – kein Alarm", path.display());
                        canary_due.swap_remove(i);
                    } else {
                        canary_due[i] = (path, Instant::now() + Duration::from_millis(100), tries + 1);
                        i += 1;
                    }
                }
            }
        }
        // Ransomware heuristic: many documents suddenly with encrypted content.
        // 100 ms after the last change (250 ms until 0.36.0): measured on 21.11.2026 with the
        // test program at 40 files a second, 11 of 400 files were lost before the freeze,
        // whatever the count needed - the wait itself was the loss. A file checked too early
        // is checked again with its next change.
        for path in quick.ready(Instant::now(), Duration::from_millis(100)) {
            if !std::fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
                continue;
            }
            if rt::looks_encrypted_by_ransomware(&path, deletions.recent(Instant::now())) {
                if let Some((files, _)) = fresh.record(path.clone(), Instant::now()) {
                    ransomware_alarm(&rt, files, k9_core::t!("Dateien wurden verschlüsselt/überschrieben, während ein neues unsigniertes Programm läuft", "files were encrypted/overwritten while a new unsigned program is running"), "neu", true);
                }
                if let Some((files, new)) = burst.record(path.clone(), Instant::now()) {
                    ransomware_alarm(&rt, files, k9_core::t!("viele Dateien wurden in kurzer Zeit verschlüsselt/überschrieben", "many files were encrypted/overwritten within a short time"), "viele", new);
                }
            }
        }
        for path in debounce.ready(Instant::now(), Duration::from_millis(1500)) {
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if !meta.is_file() || meta.len() == 0 || (max > 0 && meta.len() > max) {
                continue;
            }
            let found = rt.scan_file(&path);
            if found.is_empty() && rt::is_high_risk_file(&path) {
                let _ = clam.send(path.clone()); // ignored when the ClamAV check is off
            }
            rt.report(found, false);
        }
        if last_refresh.elapsed() > Duration::from_secs(600) {
            last_refresh = Instant::now();
            rt.refresh_engines();
        }
    }
}

/// After a game: scan the files seen meanwhile with the full engine set.
/// ClamAV in real time: clamd is started only when a high-risk file arrives,
/// never while gaming (files wait until the game ends), and stopped again
/// after the idle time to give its memory back.
fn clamav_worker(rt: Arc<Rt>, rx: mpsc::Receiver<PathBuf>) {
    use k9_core::clamav;
    use k9_core::scanner::Scanner;
    let app = &rt.shared.app;
    let q = app.config.quellen.clone();
    let idle = Duration::from_secs(app.config.echtzeit.clamav_leerlauf_minuten.max(1) * 60);
    let mut daemon: Option<clamav::Daemon> = None;
    let mut last_use = Instant::now();
    let mut waiting: Vec<PathBuf> = Vec::new();
    let mut retry_at: Option<Instant> = None;
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(p) => {
                if !waiting.contains(&p) && waiting.len() < 500 {
                    waiting.push(p);
                }
                continue; // collect a burst first
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if stopping(&rt) {
            return;
        }
        if rt.gaming() {
            if daemon.take().is_some() {
                tracing::info!("ClamAV-Echtzeitprüfung: clamd beendet (Spiel läuft), {} Datei(en) warten", waiting.len());
            }
            continue;
        }
        if waiting.is_empty() {
            if daemon.is_some() && last_use.elapsed() > idle {
                daemon = None;
                tracing::info!("ClamAV-Echtzeitprüfung: clamd nach Leerlauf beendet");
            }
            continue;
        }
        if daemon.is_some() && !clamav::ping(q.clamav_port) {
            daemon = None; // e.g. the clamd of a finished scheduled scan
        }
        if daemon.is_none() {
            if retry_at.is_some_and(|t| Instant::now() < t) {
                waiting.clear();
                continue;
            }
            let started = Instant::now();
            match app.sources().and_then(|s| clamav::Daemon::start(&s.dir, &q)) {
                Ok(d) => {
                    tracing::info!("ClamAV-Echtzeitprüfung: clamd gestartet ({:?})", started.elapsed());
                    daemon = Some(d);
                }
                Err(e) => {
                    tracing::warn!("ClamAV-Echtzeitprüfung nicht möglich: {e:#} (neuer Versuch in 30 Minuten)");
                    retry_at = Some(Instant::now() + Duration::from_secs(1800));
                    waiting.clear();
                    continue;
                }
            }
        }
        let scanner = Scanner::new(vec![Box::new(clamav::ClamdEngine::new(q.clamav_port))], app.config.max_file_size(), app.excluded());
        let mut found = Vec::new();
        for p in waiting.drain(..) {
            if p.is_file() {
                found.extend(scanner.scan_file(&p).ok().flatten().map(|(f, _)| f).unwrap_or_default());
            }
        }
        rt.report(found, false);
        last_use = Instant::now();
    }
}

fn deferred_worker(rt: Arc<Rt>) {
    loop {
        std::thread::sleep(Duration::from_secs(20));
        if stopping(&rt) {
            return;
        }
        if rt.gaming() {
            continue;
        }
        let files: Vec<PathBuf> = rt.deferred.lock().unwrap().drain().collect();
        for f in files {
            if f.is_file() {
                let found = rt.scan_file(&f);
                rt.report(found, false);
            }
        }
    }
}

// ============================================================= ransomware

/// Programs that may be behind a ransomware alarm: started in the last 15 minutes (from the
/// agent's process watch) or – not yet in its list – in the last 60 seconds.
fn recent_programs(rt: &Rt) -> Vec<(u32, PathBuf)> {
    let me = std::process::id();
    let mut candidates: Vec<(u32, PathBuf)> = rt
        .recent
        .lock()
        .unwrap()
        .iter()
        .filter(|(pid, (t, p))| **pid != me && t.elapsed() < Duration::from_secs(900) && p.is_some())
        .filter_map(|(pid, (_, p))| p.clone().map(|p| (*pid, p)))
        .collect();
    // The process list is read once a second: a program started within the last moments is not
    // in it yet. Ask Windows now for everything that started in the last 60 seconds.
    let now_ft = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| (d.as_secs() as i64 + 11_644_473_600) * 10_000_000).unwrap_or(0);
    for pid in rt::process_snapshot().into_keys() {
        if pid == me || pid <= 4 || candidates.iter().any(|(p, _)| *p == pid) {
            continue;
        }
        if let Some((path, start)) = rt::process_path_and_start(pid) {
            if now_ft > 0 && (0..600_000_000).contains(&(now_ft - start)) {
                candidates.push((pid, path));
            }
        }
    }
    // K9's own programs are never suspects (seen in the sandbox on 22.11.2026: a canary alarm
    // named the K9 service, restarted a few minutes before, as the suspect).
    let own = k9_core::dienst::install_dir();
    candidates.retain(|(_, p)| !p.starts_with(&own));
    candidates
}

/// `new`: a new alarm. false: the same attack goes on – suspects that appeared since are
/// still frozen (if switched on), but a second message only comes when something was frozen.
///
/// `art`: "koeder" (a canary file was touched), "viele" (many files look encrypted) or "neu"
/// (a few files look encrypted while a new unsigned program runs – only such programs are
/// frozen, and without one nothing happens at all).
fn ransomware_alarm(rt: &Rt, files: Vec<PathBuf>, reason: &str, art: &str, new: bool) {
    /// Programs this function froze in the last minute: (process ID, when). The same attack
    /// raises several alarms in a row; freezing twice would need two releases.
    static FROZEN: std::sync::Mutex<Vec<(u32, Instant)>> = std::sync::Mutex::new(Vec::new());
    let fresh_only = art == "neu";
    let cfg = &rt.shared.app.config.echtzeit;
    let candidates = recent_programs(rt);
    // First of all, before anything that takes time (waiting for the service, checking the
    // signatures of all candidates): new unsigned programs are frozen. Ransomware that
    // encrypts at once is through within a second.
    let (fresh, mut suspended) = {
        let app = &rt.shared.app;
        let arbeit = k9_core::arbeitsordner::live(&app.paths.config_file(), &app.config);
        let own = k9_core::dienst::install_dir().display().to_string();
        let fresh: Vec<(u32, PathBuf)> = candidates
            .iter()
            .filter(|(_, p)| k9_core::ketten::root_of(p, arbeit.is_program(p) || arbeit.folder_of(&p.display().to_string()).is_some()).is_some())
            .cloned()
            .collect();
        let mut suspended = Vec::new();
        if cfg.ransomware_prozess_anhalten {
            let mut frozen = FROZEN.lock().unwrap_or_else(|e| e.into_inner());
            frozen.retain(|(_, t)| t.elapsed() < Duration::from_secs(60));
            for (pid, p) in &fresh {
                let path = p.display().to_string();
                if frozen.iter().any(|(f, _)| f == pid) || k9_core::anhalten::freeze_allowed(&path, None, &app.config.gaming.spiele_ordner, &app.config.gaming.spiele_prozesse, &own).is_err() {
                    continue;
                }
                if rt::suspend_process(*pid) {
                    tracing::warn!("Ransomware-Verdacht: Prozess {pid} ({path}) angehalten");
                    suspended.push(*pid);
                    frozen.push((*pid, Instant::now()));
                }
            }
        }
        (fresh, suspended)
    };
    if fresh_only && suspended.is_empty() {
        return; // no new unsigned program to freeze: the general threshold decides
    }
    // With the service running, the service detects the same burst and knows which program
    // wrote the files: give it a moment, and stay silent when it has reported. Without an
    // answer (service detection off or failed) the agent raises the alarm itself. Not when
    // the agent has just frozen something: that needs its message.
    if art == "viele" && suspended.is_empty() && rt.shared.dienst_prozesse.load(Ordering::Relaxed) {
        if !new && service_reported_ransomware(Duration::from_secs(60)) {
            return;
        }
        for _ in 0..25 {
            if service_reported_ransomware(Duration::from_secs(30)) {
                tracing::info!("Ransomware-Verdacht: der Dienst hat bereits gemeldet – keine zweite Meldung vom Agenten");
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // Suspects: processes started in the last 15 minutes from user-writable
    // folders or without valid signature (ransomware rarely runs from Program Files).
    let suspects: Vec<(u32, PathBuf)> = if fresh_only {
        fresh
    } else {
        candidates.into_iter().filter(|(_, p)| autostart::is_user_writable(p) || !autostart::is_trusted(p)).collect()
    };
    let already: Vec<u32> = FROZEN.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(p, _)| *p).collect();
    if cfg.ransomware_prozess_anhalten && !fresh_only {
        // Never frozen: games, anti-cheat, Windows parts, programs signed by Microsoft or
        // Trend Micro, K9 itself – and programs of the work folders (builds write many
        // packed files); nothing at all when every file lies in work folders.
        let app = &rt.shared.app;
        let arbeit = k9_core::arbeitsordner::live(&app.paths.config_file(), &app.config);
        let only_work = art == "viele" && !files.is_empty() && files.iter().all(|f| arbeit.folder_of(&f.to_string_lossy()).is_some());
        let own = k9_core::dienst::install_dir().display().to_string();
        let gaming = &app.config.gaming;
        for (pid, p) in suspects.iter().filter(|_| !only_work) {
            let path = p.display().to_string();
            let signer = autostart::is_signed(p).then(|| k9_core::treiber::signer_name(p)).flatten();
            if let Err(why) = k9_core::anhalten::freeze_allowed(&path, signer.as_deref(), &gaming.spiele_ordner, &gaming.spiele_prozesse, &own) {
                tracing::info!("Ransomware-Verdacht: nicht angehalten ({why}): {path}");
                continue;
            }
            if arbeit.is_program(p) || arbeit.folder_of(&path).is_some() {
                tracing::info!("Ransomware-Verdacht: nicht angehalten (Arbeitsordner): {path}");
                continue;
            }
            if already.contains(pid) {
                continue;
            }
            if rt::suspend_process(*pid) {
                tracing::warn!("Ransomware-Verdacht: Prozess {pid} ({}) angehalten", p.display());
                suspended.push(*pid);
                FROZEN.lock().unwrap_or_else(|e| e.into_inner()).push((*pid, Instant::now()));
            }
        }
    }
    if (!new || fresh_only) && suspended.is_empty() {
        return;
    }
    let pids: Vec<u32> = suspects.iter().map(|(p, _)| *p).collect();
    let first = suspects.first().map(|(_, p)| p.display().to_string()).unwrap_or_default();
    let names: Vec<String> = suspects.iter().map(|(pid, p)| format!("{} (PID {pid})", p.display())).collect();
    let sample: Vec<String> = files.iter().take(5).map(|f| f.display().to_string()).collect();
    let finding = Finding {
        path: PathBuf::from(k9_core::tf!("Ransomware-Verdacht: {reason}", "Suspected ransomware: {reason}")),
        sha256: k9_core::sha256_hex(format!("ransomware|{}|{}", k9_core::now_string(), sample.join("|")).as_bytes()),
        size: 0,
        rule_id: "RANSOMWARE:VERHALTEN".into(),
        threat_name: k9_core::tf!("Ransomware-Verdacht – {reason}", "Suspected ransomware – {reason}"),
        category: "Ransomware".into(),
        severity: Severity::Kritisch,
        engine: "echtzeit".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pids": pids,
            // Program and start time per process: "Prozess beenden" checks both.
            "prozesse": suspects.iter().map(|(pid, p)| serde_json::json!({ "pid": pid, "ziel": p.display().to_string(), "startzeit": rt::process_start(*pid) })).collect::<Vec<_>>(),
            "ziel": first,
            "angehalten": !suspended.is_empty(),
            // "koeder" (canary file) or "viele" (many encrypted files) – work folders only quiet "viele".
            "art": art,
            "befehl": names.join(", "),
            "dateien": sample,
            "hinweis": if suspended.is_empty() {
                k9_core::t!("Verdächtige Programme laufen weiter. „Prozess beenden“ stoppt sie, „Freigabe“ lässt sie weiterlaufen.", "Suspicious programs are still running. “End process” stops them, “Allow” lets them continue.")
            } else {
                k9_core::t!("Verdächtige Programme wurden ANGEHALTEN (nicht beendet). „Prozess beenden“ stoppt sie, „Freigabe“ lässt sie weiterlaufen.", "Suspicious programs were SUSPENDED (not ended). “End process” stops them, “Allow” lets them continue.")
            },
        })),
    };
    tracing::error!(
        "RANSOMWARE-VERDACHT: {reason}; Verdächtige: {}; Dateien (Beispiele): {}",
        if names.is_empty() { "keine".to_string() } else { names.join(", ") },
        files.iter().take(5).map(|f| f.display().to_string()).collect::<Vec<_>>().join(" | ")
    );
    rt.report(vec![finding], true);
}

// ============================================================== processes

fn process_monitor(rt: Arc<Rt>) {
    let mut known: HashSet<u32> = rt::process_snapshot().into_keys().collect();
    let mut checked: HashMap<PathBuf, ()> = HashMap::new();
    let me = std::process::id();
    // Every ten minutes one line with the load of the whole agent, split into time with and
    // without a game: "must not slow gaming down" is the first condition of this project, and
    // only numbers from real sessions can show whether it holds.
    let mut load_since = Instant::now();
    let mut load_cpu = k9_core::scanner::process_cpu_seconds();
    let (mut game_time, mut game_cpu) = (Duration::ZERO, 0.0f64);
    let (mut lap, mut lap_cpu) = (Instant::now(), load_cpu);
    loop {
        {
            // The time since the last round belongs to the state it was spent in.
            let now_cpu = k9_core::scanner::process_cpu_seconds();
            if rt.gaming() {
                game_time += lap.elapsed();
                game_cpu += now_cpu - lap_cpu;
            }
            lap = Instant::now();
            lap_cpu = now_cpu;
            if load_since.elapsed() >= Duration::from_secs(600) {
                let total = load_since.elapsed().as_secs_f64();
                let cpu = now_cpu - load_cpu;
                let rest = (total - game_time.as_secs_f64()).max(0.001);
                tracing::info!(
                    "Belastung durch den Agenten: {:.1} s Rechenzeit in {:.0} min ({:.2} % eines Kerns); im Spiel {:.0} min mit {:.2} %, sonst {:.2} %",
                    cpu,
                    total / 60.0,
                    cpu / total * 100.0,
                    game_time.as_secs_f64() / 60.0,
                    if game_time.as_secs() > 0 { game_cpu / game_time.as_secs_f64() * 100.0 } else { 0.0 },
                    (cpu - game_cpu).max(0.0) / rest * 100.0
                );
                load_since = Instant::now();
                load_cpu = now_cpu;
                game_time = Duration::ZERO;
                game_cpu = 0.0;
            }
        }
        // Four times a second (during a game every three seconds): a started program that is
        // known malware is frozen within a quarter of a second instead of a full one. Reading
        // the process list costs about a millisecond.
        // With the switch "neue-programme" 16 times a second: the program is to be frozen
        // before it writes its first file. Never in a game. A round costs next to nothing
        // since 0.44.2 (only the process IDs are asked for); until then it was 20 % of a core.
        let pause = if rt.gaming() {
            3000
        } else if rt.shared.app.config.echtzeit.neue_programme_anhalten {
            60
        } else {
            250
        };
        std::thread::sleep(Duration::from_millis(pause));
        if stopping(&rt) {
            return;
        }
        // First only the process IDs (cheap). The full snapshot is taken only when a process
        // has appeared; an empty list means the cheap call failed - then take the snapshot.
        let ids: HashSet<u32> = rt::process_ids().into_iter().collect();
        if !ids.is_empty() && ids.is_subset(&known) {
            if ids.len() != known.len() {
                known = ids;
                rt.recent.lock().unwrap().retain(|pid, (t, _)| known.contains(pid) && t.elapsed() < Duration::from_secs(1800));
            }
            continue;
        }
        let snap = rt::process_snapshot();
        let now: HashSet<u32> = snap.keys().copied().collect();
        {
            let mut recent = rt.recent.lock().unwrap();
            recent.retain(|pid, (t, _)| now.contains(pid) && t.elapsed() < Duration::from_secs(1800));
        }
        let new: Vec<u32> = now.difference(&known).copied().collect();
        known = now;
        let mut findings = Vec::new();
        for pid in new {
            let Some(p) = snap.get(&pid) else { continue };
            if p.ppid == me {
                continue; // our own helpers (clamd, freshclam, powershell for the PDF)
            }
            let path = rt::process_path(pid);
            rt.recent.lock().unwrap().insert(pid, (Instant::now(), path.clone()));
            let parent = snap.get(&p.ppid).map(|x| x.name.clone()).unwrap_or_default();
            let cmd = rt::process_command_line(pid).unwrap_or_default();
            tracing::debug!("Neuer Prozess {pid}: {} (Eltern {parent}), Befehlszeile {} Zeichen", p.name, cmd.len());
            let target = path.as_ref().map(|x| x.display().to_string()).unwrap_or_default();
            // With the service, ETW sees every start (also very short ones) and reports these.
            let by_service = rt.shared.dienst_prozesse.load(Ordering::Relaxed);
            if let Some((rule, text, sev)) = rt::assess_process(&parent, &p.name, &cmd).filter(|_| !by_service) {
                let mut f = rt::process_finding(pid, &p.name, &target, &cmd, &rule, &text, sev, &parent, "echtzeit");
                rt::note_start(&mut f, rt::process_start(pid));
                rt::note_parent(&mut f, p.ppid);
                findings.push(f);
            }
            // Switch "neue-programme": an unsigned program marked "from the internet" is frozen
            // at its start until the user releases it. Not during a game.
            if rt.shared.app.config.echtzeit.neue_programme_anhalten && !rt.gaming() {
                if let Some(f) = path.as_deref().and_then(|exe| freeze_new_download(&rt, pid, exe, &cmd, &parent)) {
                    findings.push(f);
                }
            }
            // The started program itself (once per file): known malware?
            if let Some(exe) = path.filter(|x| autostart::is_user_writable(x)) {
                if checked.insert(exe.clone(), ()).is_none() {
                    for f in rt.scan_file(&exe) {
                        let text = k9_core::tf!("Gestartetes Programm ist bekannt schädlich: {}", "The program that was started is known to be harmful: {}", f.threat_name);
                        let mut pf = rt::process_finding(pid, &p.name, &target, &cmd, &f.rule_id, &text, f.severity.max(Severity::Hoch), &parent, "echtzeit");
                        pf.sha256 = f.sha256.clone();
                        let start = rt::process_start(pid);
                        rt::note_start(&mut pf, start);
                        // Known malware: frozen at once (switch "anhalten"), before it does
                        // anything – ransomware needs seconds to minutes until it encrypts.
                        if rt.shared.app.config.echtzeit.kritische_prozesse_anhalten && k9_core::anhalten::known_malware_at_start(&f) {
                            let gaming = &rt.shared.app.config.gaming;
                            let own = k9_core::dienst::install_dir().display().to_string();
                            let signer = autostart::is_signed(&exe).then(|| k9_core::treiber::signer_name(&exe)).flatten();
                            match k9_core::anhalten::freeze_allowed(&target, signer.as_deref(), &gaming.spiele_ordner, &gaming.spiele_prozesse, &own) {
                                Ok(()) => {
                                    if let (true, Some(start)) = (rt::suspend_process(pid), start) {
                                        tracing::warn!("Bekannte Schadsoftware gestartet – angehalten bis zur Entscheidung: {target} (PID {pid}, {})", f.rule_id);
                                        pf.severity = Severity::Kritisch;
                                        k9_core::anhalten::mark_frozen(&mut pf, pid, &target, start);
                                    }
                                }
                                Err(why) => tracing::info!("Bekannte Schadsoftware gestartet, nicht angehalten ({why}): {target}"),
                            }
                        }
                        findings.push(pf);
                    }
                }
            }
        }
        if checked.len() > 5000 {
            checked.clear();
        }
        // A message that holds a program frozen goes to the front of the window queue: the
        // program waits for the user. (Sandbox run of 22.11.2026: the message about the frozen
        // program waited unseen behind an open window with an unrelated notice.)
        let (frozen, other): (Vec<Finding>, Vec<Finding>) =
            findings.into_iter().partition(|f| f.details.as_ref().is_some_and(|d| d["angehalten"].as_bool() == Some(true)));
        rt.report(frozen, true);
        rt.report(other, false);
    }
}


/// Switch "neue-programme": freezes the just started program `exe` if it is unsigned, marked
/// "from the internet" and not released by the user before. Returns the message to report.
fn freeze_new_download(rt: &Rt, pid: u32, exe: &Path, cmd: &str, parent: &str) -> Option<Finding> {
    let app = &rt.shared.app;
    let arbeit = k9_core::arbeitsordner::live(&app.paths.config_file(), &app.config);
    let target = exe.display().to_string();
    if arbeit.is_program(exe) || arbeit.folder_of(&target).is_some() {
        return None;
    }
    let zone = k9_core::herkunft::zone_of(exe).filter(|z| z.from_internet())?;
    if autostart::is_signed(exe) {
        return None;
    }
    let identity = k9_core::herkunft::program_identity(exe);
    let mut f = k9_core::herkunft::frozen_finding(exe, &zone, &identity, pid, cmd, parent);
    let store = app.store().ok()?;
    if k9_core::pipeline::released_before(&store, &f) {
        return None;
    }
    let own = k9_core::dienst::install_dir().display().to_string();
    if let Err(why) = k9_core::anhalten::freeze_allowed(&target, None, &app.config.gaming.spiele_ordner, &app.config.gaming.spiele_prozesse, &own) {
        tracing::info!("Neues Programm aus dem Internet nicht angehalten ({why}): {target}");
        return None;
    }
    let start = rt::process_start(pid)?;
    if !rt::suspend_process(pid) {
        tracing::info!("Neues Programm aus dem Internet ließ sich nicht anhalten (läuft mit höheren Rechten?): {target}");
        return None;
    }
    tracing::warn!("Neues unsigniertes Programm aus dem Internet – angehalten bis zur Freigabe: {target} (PID {pid})");
    rt::note_start(&mut f, Some(start));
    k9_core::anhalten::mark_frozen(&mut f, pid, &target, start);
    // Started again before the user decided: the message is the same one, and it must keep
    // every frozen process - otherwise the earlier one could never be released.
    let earlier: Vec<serde_json::Value> = store
        .pending_detections()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.rule_id == f.rule_id && d.sha256 == f.sha256)
        .and_then(|d| d.details)
        .and_then(|d| d["prozesse"].as_array().cloned())
        .unwrap_or_default();
    if let Some(d) = f.details.as_mut().and_then(|d| d.as_object_mut()) {
        let mut all = earlier;
        all.extend(d.get("prozesse").and_then(|p| p.as_array()).cloned().unwrap_or_default());
        d.insert("pids".into(), serde_json::Value::Array(all.iter().filter_map(|p| p.get("pid").cloned()).collect()));
        d.insert("prozesse".into(), serde_json::Value::Array(all));
        d.insert(
            "hinweis".into(),
            k9_core::t!("Das Programm stammt aus dem Internet, hat keine gültige Signatur eines Herstellers und wurde beim Start ANGEHALTEN (eingefroren, nicht beendet) – \
             der Schalter „neue-programme“ ist an. Kennst du es und weißt, woher es kommt: „Freigabe“ (gilt für genau diese Datei, künftig startet sie ohne Rückfrage). \
             Sonst: „Prozess beenden“ und die Datei in Quarantäne. Ohne deine Entscheidung bleibt es angehalten.", "The program comes from the internet, has no valid signature of a publisher and was SUSPENDED at start (frozen, not ended) – \
             the switch “neue-programme” is on. If you know it and know where it comes from: “Allow” (applies to exactly this file, in future it starts without asking). \
             Otherwise: “End process” and put the file into quarantine. Without your decision it stays suspended.")
                .into(),
        );
    }
    Some(f)
}

// ============================================================== autostart

fn autostart_key(e: &autostart::Entry) -> String {
    format!("{}|{}", e.identity(), e.command)
}

fn quick_entries() -> Vec<autostart::Entry> {
    autostart::enumerate_quick()
}

const AUTOSTART_KEY: &str = "autostart_bekannt";

/// Autostart entries seen before (kept across agent restarts).
fn load_known_autostarts(rt: &Rt) -> Option<HashSet<String>> {
    let json = rt.shared.app.store().ok()?.meta_get(AUTOSTART_KEY).ok()??;
    serde_json::from_str(&json).ok()
}

fn save_known_autostarts(rt: &Rt, known: &HashSet<String>) {
    let saved = rt.shared.app.store().and_then(|s| s.meta_set(AUTOSTART_KEY, &serde_json::to_string(known)?));
    if let Err(e) = saved {
        tracing::debug!("Bekannte Autostarts speichern: {e:#}");
    }
}

fn autostart_monitor(rt: Arc<Rt>) {
    // The first start takes the current state as known; later starts compare with the
    // saved set, so entries added while the agent was not running are reported too.
    let mut known = match load_known_autostarts(&rt) {
        Some(k) => k,
        None => {
            let k: HashSet<String> = autostart::enumerate().iter().map(autostart_key).collect();
            save_known_autostarts(&rt, &k);
            k
        }
    };
    // First round: complete (tasks and services too).
    let mut full_at = Instant::now().checked_sub(Duration::from_secs(601)).unwrap_or_else(Instant::now);
    // Windows wakes us at once when a Run key or a Startup folder changes; looking every
    // 30 seconds stays as a backstop (browser helper registrations, missed signals).
    let watch = autostart::quick_watch();
    tracing::info!("Autostart-Überwachung: {} Schlüssel/Ordner mit sofortiger Benachrichtigung", watch.len());
    loop {
        for _ in 0..30 {
            if stopping(&rt) {
                return;
            }
            if watch.wait(1000) {
                // An installer writes several values in a row.
                std::thread::sleep(Duration::from_millis(400));
                break;
            }
        }
        if stopping(&rt) {
            return;
        }
        // Run keys + Startup folders every 30 s; tasks and services every 10 min.
        let full = full_at.elapsed() > Duration::from_secs(600) && !rt.gaming();
        let entries = if full {
            full_at = Instant::now();
            autostart::enumerate()
        } else {
            quick_entries()
        };
        // Our own autostart entry (k9 autostart-agent an) is not reported.
        let new: Vec<autostart::Entry> = entries
            .into_iter()
            .filter(|e| !known.contains(&autostart_key(e)) && e.name != "K9-Agent")
            .collect();
        if new.is_empty() {
            continue;
        }
        let mut findings = Vec::new();
        {
            let guard = rt.heavy.read().unwrap();
            if let Some(set) = guard.as_ref() {
                findings.extend(autostart::findings(&new, &set.scanner));
            }
        }
        // New Run/Startup entries are always reported (with "Deaktivieren").
        for e in &new {
            known.insert(autostart_key(e));
            let quick = matches!(
                e.location,
                autostart::Location::Run { .. } | autostart::Location::Startup { .. } | autostart::Location::NativeHost { .. }
            );
            // Edge's own cleanup after an update (pattern + valid Microsoft signature): logged only.
            if quick && autostart::is_browser_update_cleanup(e) {
                tracing::info!("Autostart: Aufräumen nach Edge-Update übergangen (gültig signiert von Microsoft Corporation): {} → {}", e.describe(), e.command.trim());
                continue;
            }
            if (quick || autostart::starts_script_host(e)) && !findings.iter().any(|f| f.path == Path::new(&e.describe())) {
                findings.push(autostart::new_entry_finding(e));
            }
        }
        save_known_autostarts(&rt, &known);
        rt.report(findings, false);
    }
}

// ================================================================ browser extensions

const EXT_KEY: &str = "erweiterungen_bekannt";

/// Extension key -> (API rights, sites) as seen last time.
type KnownExtensions = HashMap<String, (BTreeSet<String>, BTreeSet<String>)>;

/// Known extensions (key -> rights) from the last run, kept across agent restarts.
fn load_known_extensions(rt: &Rt) -> Option<KnownExtensions> {
    let json = rt.shared.app.store().ok()?.meta_get(EXT_KEY).ok()??;
    serde_json::from_str(&json).ok()
}

fn save_known_extensions(rt: &Rt, known: &KnownExtensions) {
    let saved = rt.shared.app.store().and_then(|s| s.meta_set(EXT_KEY, &serde_json::to_string(known)?));
    if let Err(e) = saved {
        tracing::debug!("Bekannte Erweiterungen speichern: {e:#}");
    }
}

/// Extension IDs whose registered native helper is unsigned or lies in a user folder.
fn risky_native_helpers() -> HashSet<String> {
    let mut out = HashSet::new();
    for h in k9_core::nativehost::registered_hosts() {
        let Some(exe) = k9_core::nativehost::host_program(&h) else { continue };
        if k9_core::autostart::is_signed(&exe) && !k9_core::autostart::is_user_writable(&exe) {
            continue;
        }
        let manifest: serde_json::Value = std::fs::read_to_string(&h.manifest).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        for o in manifest["allowed_origins"].as_array().into_iter().flatten().filter_map(|o| o.as_str()) {
            if let Some(id) = o.strip_prefix("chrome-extension://") {
                out.insert(id.trim_end_matches('/').to_string());
            }
        }
    }
    out
}

/// Every 10 minutes (first after 2): new extensions, updates with new rights, forced
/// installs (policies, registry) and browser shortcuts with suspicious arguments.
/// Reads only; while a game runs the check waits.
fn extension_monitor(rt: Arc<Rt>) {
    use k9_core::erweiterungen as ext;
    std::thread::sleep(Duration::from_secs(120));
    loop {
        if stopping(&rt) {
            return;
        }
        if !rt.gaming() {
            let malicious = rt.shared.app.sources().map(|s| ext::load_malicious(&s.dir)).unwrap_or_default();
            let helpers = risky_native_helpers();
            let first_run = load_known_extensions(&rt).is_none();
            let mut known = load_known_extensions(&rt).unwrap_or_default();
            let mut findings = Vec::new();
            for e in ext::inventory() {
                let key = e.key();
                let helper = helpers.contains(&e.id).then_some(ext::NativeHelper { unsigned_or_writable: true });
                let before = known.get(&key).map(|(p, h)| ext::Extension { permissions: p.clone(), hosts: h.clone(), ..e.clone() });
                let changed = before.as_ref().is_some_and(|b| e.permissions.iter().any(|x| !b.permissions.contains(x)) || e.hosts.iter().any(|x| !b.hosts.contains(x)));
                let new = before.is_none();
                if let Some((sev, why)) = ext::assess(&e, &malicious, before.as_ref().filter(|_| changed), helper.as_ref()) {
                    // First run: only what is serious (the rest is the baseline). Later: every
                    // new extension and every update with new rights; a list hit always.
                    let listed = malicious.contains(&e.id.to_lowercase());
                    let report = listed || if first_run { sev >= Severity::Hoch } else { new || changed };
                    if report {
                        findings.push(ext::finding(&e, sev, &why));
                    }
                }
                known.insert(key, (e.permissions.clone(), e.hosts.clone()));
            }
            for f in ext::forced_installs() {
                if let Some(x) = ext::forced_finding(&f, &malicious) {
                    findings.push(x);
                }
            }
            for dir in ext::shortcut_folders() {
                for entry in walkdir::WalkDir::new(&dir).max_depth(3).into_iter().filter_map(Result::ok) {
                    let p = entry.path();
                    if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                        continue;
                    }
                    if let Some((target, args)) = k9_core::verknuepfung::target_of(p) {
                        if let Some(why) = ext::suspicious_shortcut_args(&target, &args) {
                            findings.push(ext::shortcut_finding(p, &target, &args, why));
                        }
                    }
                }
            }
            save_known_extensions(&rt, &known);
            if !findings.is_empty() {
                rt.report(findings, false);
            }
        }
        for _ in 0..60 {
            if stopping(&rt) {
                return;
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    }
}

// ================================================================ network

fn network_monitor(rt: Arc<Rt>) {
    let interval = rt.shared.app.config.echtzeit.netzwerk_intervall_sekunden.max(15);
    let mut db = urls::NetDb::default();
    let mut db_state = String::new();
    let mut dns_checked = false;
    let mut last_history: Option<Instant> = None;
    let phishing = &rt.shared.app.config.phishing;
    let lookalikes = phishing.aehnliche_domains.then(|| k9_core::phishing::Lookalikes::new(&phishing.eigene_marken));
    // Connections: every 2 seconds (5 while a game runs) – only the table of open connections
    // is read and compared with the lists in memory; each connection is looked at once.
    let mut seen: HashSet<(u32, std::net::Ipv4Addr, u16)> = HashSet::new();
    loop {
        let rounds_until = Instant::now() + Duration::from_secs(interval);
        while Instant::now() < rounds_until {
            std::thread::sleep(Duration::from_secs(if rt.gaming() { 5 } else { 2 }));
            if stopping(&rt) {
                return;
            }
            if db.is_empty() {
                continue;
            }
            let now: HashSet<(u32, std::net::Ipv4Addr, u16)> = rt::tcp_connections().into_iter().collect();
            let fresh: Vec<_> = now.difference(&seen).copied().collect();
            seen = now;
            if !fresh.is_empty() {
                rt.report(connection_findings(&db, fresh), false);
            }
        }
        if stopping(&rt) {
            return;
        }
        let state = rt.state.lock().unwrap().clone();
        if state != db_state || db.is_empty() {
            if let Ok(src) = rt.shared.app.sources() {
                db = urls::NetDb::load_with(&src.dir, &rt.shared.app.config.quellen);
            }
            db_state = state;
        }
        if !dns_checked {
            dns_checked = true;
            if rt::dns_cache_names().is_empty() {
                tracing::info!("DNS-Cache ist ohne Administratorrechte nicht lesbar – DNS-Pruefung nur mit Adminrechten; der Browserverlauf wird stattdessen alle 15 Minuten geprueft");
            }
        }
        if !db.is_empty() || lookalikes.is_some() {
            rt.report(network_findings(&db, lookalikes.as_ref()), false);
        }
        // Recently visited addresses (works without admin rights), never while gaming.
        let app = &rt.shared.app;
        if app.config.quellen.browserverlauf_pruefen && !rt.gaming() && last_history.is_none_or(|t| t.elapsed() > Duration::from_secs(900)) {
            last_history = Some(Instant::now());
            if let Ok(src) = app.sources() {
                let udb = urls::UrlDb::load(&src.dir);
                if !udb.is_empty() {
                    let (found, _) = urls::history_findings(&udb, &urls::find_histories());
                    rt.report(found, false);
                }
            }
        }
    }
}

pub fn network_findings(db: &urls::NetDb, lookalikes: Option<&k9_core::phishing::Lookalikes>) -> Vec<Finding> {
    let conns = rt::tcp_connections();
    let names = rt::dns_cache_names();
    tracing::debug!("Netzwerkpruefung: {} Verbindungen, {} DNS-Namen", conns.len(), names.len());
    let mut out = connection_findings(db, conns);
    for name in names {
        if let Some((domain, src)) = db.lookup_domain(&name) {
            out.push(rt::dns_finding(&name, domain, src, "echtzeit", None));
        } else if let Some(hit) = lookalikes.and_then(|l| l.check(&name)) {
            out.push(rt::lookalike_finding(&name, &hit, "echtzeit", None));
        }
    }
    out
}

/// Findings for connections to addresses on a malware list.
fn connection_findings(db: &urls::NetDb, conns: Vec<(u32, std::net::Ipv4Addr, u16)>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (pid, ip, port) in conns {
        if let Some(src) = db.lookup_ip(&ip) {
            let exe = rt::process_path(pid).map(|p| p.display().to_string()).unwrap_or_default();
            out.push(Finding {
                path: PathBuf::from(k9_core::tf!("Verbindung zu {ip}:{port} von {exe} (PID {pid})", "Connection to {ip}:{port} from {exe} (PID {pid})")),
                sha256: k9_core::sha256_hex(format!("netz|{ip}|{}", exe.to_lowercase()).as_bytes()),
                size: 0,
                rule_id: format!("NETZ:IP:{src}"),
                threat_name: k9_core::tf!("Verbindung zu bekannter Schad-Adresse {ip} ({src})", "Connection to the known malicious address {ip} ({src})"),
                category: k9_core::t!("Schad-Verbindung", "Malicious connection").into(),
                severity: Severity::Hoch,
                engine: "echtzeit".into(),
                kind: Kind::Prozess,
                details: Some(serde_json::json!({
                    "pid": pid, "ziel": exe, "befehl": format!("{ip}:{port}"),
                    "hinweis": k9_core::t!("Das Programm verbindet sich mit einer Adresse aus einer Schadsoftware-Liste.", "The program connects to an address from a malware list.")
                })),
            });
        }
    }
    out
}

// =============================================================== memory scan

/// Memory scan while idle (k9_core::speicher; off by default). The switch is read from
/// config.toml every round, so `k9 funktion speicher-scan an` works without a restart.
fn memory_monitor(rt: Arc<Rt>) {
    use k9_core::speicher;
    // (pid, start time) -> scanned at
    let mut done: HashMap<(u32, i64), Instant> = HashMap::new();
    let mut told = String::new();
    let own = k9_core::dienst::install_dir().display().to_string();
    loop {
        for _ in 0..60 {
            if stopping(&rt) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let app = &rt.shared.app;
        let cfg = k9_core::config::Config::live(&app.paths.config_file(), &app.config);
        if !cfg.echtzeit.speicher_scan {
            continue;
        }
        let idle_needed = Duration::from_secs(cfg.echtzeit.speicher_scan_leerlauf_minuten.max(2) * 60);
        if rt.gaming() || k9_core::gaming::idle_duration() < idle_needed {
            continue;
        }
        // Say once why nothing is scanned (and again when the reason changes).
        let mut skip = |why: String| {
            if told != why {
                tracing::info!("Speicher-Scan: übersprungen – {why}");
                told = why;
            }
        };
        if let Some(ac) = speicher::always_on_anticheat() {
            skip(format!("{ac} ist installiert und ständig geladen; auf diesem PC läuft der Speicher-Scan nie"));
            continue;
        }
        let snap = rt::process_snapshot();
        let procs: Vec<speicher::Prozess> = snap
            .values()
            .filter(|p| p.pid > 4)
            .map(|p| speicher::Prozess { pid: p.pid, name: p.name.clone(), path: rt::process_path(p.pid).map(|x| x.display().to_string()).unwrap_or_default() })
            .collect();
        if let Some(why) = speicher::blocker(&procs, &cfg.gaming.spiele_ordner, &cfg.gaming.spiele_prozesse) {
            skip(why);
            continue;
        }
        done.retain(|_, t| t.elapsed() < Duration::from_secs(6 * 3600));
        let me = std::process::id();
        let (mut scanned, mut hits) = (0usize, 0usize);
        for p in procs.iter().filter(|p| p.pid != me) {
            // The user is back or a game started: stop at once.
            if stopping(&rt) || rt.gaming() || k9_core::gaming::idle_duration() < Duration::from_secs(60) {
                break;
            }
            let Some(start) = rt::process_start(p.pid) else { continue };
            if done.contains_key(&(p.pid, start)) {
                continue;
            }
            let path = Path::new(&p.path);
            let signer = autostart::is_signed(path).then(|| k9_core::treiber::signer_name(path)).flatten();
            let skip = [cfg.quellen.clamav_programmordner.clone()];
            if !speicher::target_allowed(p, signer.as_deref(), autostart::is_user_writable(path), &cfg.gaming.spiele_ordner, &cfg.gaming.spiele_prozesse, &own, &skip) {
                done.insert((p.pid, start), Instant::now());
                continue;
            }
            let regions = speicher::executable_private_memory(p.pid, 48 * 1024 * 1024);
            let found = {
                let guard = rt.heavy.read().unwrap();
                speicher::scan_regions(&regions, &|data| guard.as_ref().map(|set| set.scanner.scan_memory(data, speicher::MIN_SCORE)).unwrap_or_default())
            };
            done.insert((p.pid, start), Instant::now());
            scanned += 1;
            if !found.is_empty() {
                hits += found.len();
                rt.report(found.iter().map(|t| speicher::finding(p, Some(start), t)).collect(), false);
            }
            // Leave room for everything else.
            std::thread::sleep(Duration::from_millis(200));
        }
        if scanned > 0 {
            told.clear();
            tracing::info!("Speicher-Scan: {scanned} Programme geprüft, {hits} Treffer");
        }
    }
}

// ================================================================== USB

fn usb_monitor(rt: Arc<Rt>) {
    let mut known: HashSet<PathBuf> = rt::removable_drives().into_iter().collect();
    let mut pending: Vec<PathBuf> = Vec::new();
    loop {
        std::thread::sleep(Duration::from_secs(5));
        if stopping(&rt) {
            return;
        }
        let now: HashSet<PathBuf> = rt::removable_drives().into_iter().collect();
        for d in now.difference(&known) {
            tracing::info!("Wechseldatenträger erkannt: {}", d.display());
            pending.push(d.clone());
        }
        known = now;
        pending.retain(|d| known.contains(d));
        if !pending.is_empty() && !rt.gaming() && !rt.shared.scan_running.load(Ordering::Relaxed) {
            let roots = std::mem::take(&mut pending);
            let _g = rt.tokio.enter();
            scheduler::start_scan(rt.shared.clone(), roots, vec![Check::Dateien], scheduler::ScanArt::Geplant);
        }
    }
}

