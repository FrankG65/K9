//! Scheduler loop: gaming detection, due schedules, queued notifications.

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, NaiveDateTime};
use k9_core::app::Check;
use k9_core::gaming::{self, GamingState};
use k9_core::notify;
use k9_core::scanner::ScanControl;
use k9_core::schedule::ScheduleKind;

use crate::Shared;

const TS_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Pauses a running scheduled scan while a game is running.
/// Worker threads of the fast full scan: a third of the processor's logical cores, at least 4
/// and at most 16. Measured on 22.11.2026 on the test PC (48 logical cores, 9.4 GB in 36,667
/// files, data already in memory): 8 threads 35 s, 16 threads 19 s, 24 threads 16 s, 32 threads
/// 16 s. Beyond 16 little is gained, and two thirds of the processor stay free for the user.
pub fn fast_threads() -> usize {
    fast_threads_for(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8))
}

fn fast_threads_for(logical_cores: usize) -> usize {
    (logical_cores / 3).clamp(4, 16)
}

/// How a scan was started: decides its name, its speed and whether it waits for a game to end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanArt {
    /// From the time plan or after plugging in a drive: pauses while a game runs.
    Geplant,
    /// Button "Schnellscan": the standard folders, at once – also during a game (as before).
    Schnell,
    /// All local drives with the few configured threads; pauses while a game runs.
    VollSchonend,
    /// All local drives with `fast_threads()` threads; pauses while a game runs.
    VollSchnell,
}

impl ScanArt {
    pub fn label(self) -> &'static str {
        match self {
            ScanArt::Geplant => k9_core::t!("Geplanter Scan", "Scheduled scan"),
            ScanArt::Schnell => k9_core::t!("Schnellscan (Standardordner)", "Quick scan (standard folders)"),
            ScanArt::VollSchonend => k9_core::t!("Vollständiger Scan (schonend)", "Full scan (gentle)"),
            ScanArt::VollSchnell => k9_core::t!("Vollständiger Scan (schnell)", "Full scan (fast)"),
        }
    }
    /// Gaming has priority: only the quick scan of a few folders, started by hand, runs on.
    pub fn pauses_for_games(self) -> bool {
        self != ScanArt::Schnell
    }
    /// Thread count of this run; `None` = `[scan] max_threads`.
    pub fn threads(self) -> Option<usize> {
        (self == ScanArt::VollSchnell).then(fast_threads)
    }
}

struct GamingPause {
    shared: Arc<Shared>,
    last_check: Cell<Instant>,
    art: ScanArt,
}

impl ScanControl for GamingPause {
    fn checkpoint(&self) -> bool {
        if self.shared.is_stopping() || self.shared.scan_cancel.load(Ordering::Relaxed) {
            return false;
        }
        if !self.art.pauses_for_games() || self.last_check.get().elapsed() < Duration::from_secs(2) {
            return true;
        }
        self.last_check.set(Instant::now());
        let mut announced = false;
        loop {
            let g = gaming::detect(&self.shared.app.config.gaming);
            let active = g.active;
            *self.shared.gaming.lock().unwrap() = g;
            if !active {
                if announced {
                    tracing::info!("Spiel beendet – Scan wird fortgesetzt");
                }
                return true;
            }
            if !announced {
                tracing::info!("Spiel erkannt – Scan pausiert");
                announced = true;
            }
            std::thread::sleep(Duration::from_secs(5));
            if self.shared.is_stopping() || self.shared.scan_cancel.load(Ordering::Relaxed) {
                return false;
            }
        }
    }

    fn progress(&self, seen: u64, current: &std::path::Path) {
        self.shared.scan_seen.store(seen, Ordering::Relaxed);
        // The folder is enough for the display; refreshed every 200 files to stay cheap.
        if seen % 200 == 1 {
            if let Some(dir) = current.parent() {
                *self.shared.scan_current.lock().unwrap() = dir.display().to_string();
            }
        }
    }
}

async fn detect_gaming(shared: &Arc<Shared>) -> GamingState {
    let s = shared.clone();
    tokio::task::spawn_blocking(move || gaming::detect(&s.app.config.gaming)).await.unwrap_or_default()
}

pub async fn run(shared: Arc<Shared>, schedules_enabled: bool) {
    let interval = Duration::from_secs(shared.app.config.gaming.pruefintervall_sekunden.max(5));
    let mut was_gaming = false;
    if shared.app.config.zeitplan.iter().any(|e| e.kind == ScheduleKind::Staendig) {
        tracing::info!("Zeitplan 'ständig' ist ein Platzhalter – Echtzeitschutz folgt in Schritt 3");
    }
    {
        let s = shared.clone();
        if let Ok(Err(e)) = tokio::task::spawn_blocking(move || s.app.queue_pending_windows()).await {
            tracing::warn!("Offene Funde nicht für das Meldefenster vorgemerkt: {e:#}");
        }
    }
    // Flush anything queued by an earlier session or by `k9 scan` during a game.
    let mut first = true;
    loop {
        let mut manual = false;
        if !first {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shared.scan_now.notified() => manual = true,
            }
        }
        first = false;
        if shared.is_stopping() {
            return;
        }

        let g = detect_gaming(&shared).await;
        let gaming_now = g.active;
        if gaming_now != was_gaming {
            tracing::info!("Gaming-Modus {}", if gaming_now { format!("aktiv: {}", g.reason.as_deref().unwrap_or("-")) } else { "beendet".into() });
        }
        // Tell the Windows service about a running game over its pipe (it then postpones its
        // updates and driver checks); repeated while the game runs, the service forgets it
        // after five minutes without a report.
        if gaming_now || gaming_now != was_gaming {
            let msg = k9_core::dienst::Message::Spielmodus { v: k9_core::dienst::PROTOCOL, aktiv: gaming_now };
            if let Err(e) = tokio::task::spawn_blocking(move || k9_core::dienst::request(&msg)).await {
                tracing::debug!("Spielmodus an den Dienst: {e}");
            }
        }
        // Idle time for the service's idle-only work (shadow copies; the service decides
        // whether they are switched on – it follows config.toml without a restart).
        if !gaming_now {
            let minuten = (k9_core::gaming::idle_duration().as_secs() / 60) as u32;
            if minuten >= 15 {
                let msg = k9_core::dienst::Message::Leerlauf { v: k9_core::dienst::PROTOCOL, minuten };
                let _ = tokio::task::spawn_blocking(move || k9_core::dienst::request(&msg)).await;
            }
        }
        *shared.gaming.lock().unwrap() = g;
        was_gaming = gaming_now;
        if !gaming_now {
            flush_queue(&shared).await;
            show_windows(&shared);
            crate::pflege::tick(&shared);
        }

        if shared.scan_running.load(Ordering::Relaxed) {
            continue;
        }
        let (roots, checks) = if manual {
            (existing(shared.app.config.default_scan_paths()), Check::ALL.to_vec())
        } else if schedules_enabled && !gaming_now {
            due_work(&shared).await
        } else {
            (Vec::new(), Vec::new())
        };
        if !checks.is_empty() {
            start_scan(shared.clone(), roots, checks, if manual { ScanArt::Schnell } else { ScanArt::Geplant });
        } else if !gaming_now && schedules_enabled {
            update_sources_if_due(&shared, false);
        }
    }
}

fn existing(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|p| p.exists()).collect()
}

/// Downloads due sources in the background (never while gaming or scanning).
pub fn update_sources_if_due(shared: &Arc<Shared>, force: bool) {
    // With the Windows service the protected source data is updated only there.
    if k9_core::schutz::protected_sources().is_some() {
        if force {
            match k9_core::dienst::request_source_update(None) {
                Ok(m) => tracing::info!("{m}"),
                Err(e) => tracing::warn!("Quellen-Aktualisierung über den Dienst: {e:#}"),
            }
        } else {
            refresh_pdf_if_sources_changed(shared);
        }
        return;
    }
    if shared.scan_running.load(Ordering::Relaxed) || shared.updating.swap(true, Ordering::SeqCst) {
        return;
    }
    let s = shared.clone();
    tokio::task::spawn_blocking(move || {
        let mut any_ok = false;
        match s.app.update_sources(None, !force) {
            Ok(results) => {
                for r in results {
                    match r {
                        Ok(m) => {
                            any_ok = true;
                            tracing::info!("Quelle {m}");
                        }
                        Err(e) => tracing::warn!("Quelle {e}"),
                    }
                }
            }
            Err(e) => tracing::warn!("Quellen-Aktualisierung: {e:#}"),
        }
        // Keep the numbers in the PDF guide current (never while gaming).
        if any_ok && !gaming::detect(&s.app.config.gaming).active {
            refresh_pdf_guide();
        }
        s.updating.store(false, Ordering::SeqCst);
    });
}

async fn flush_queue(shared: &Arc<Shared>) {
    let s = shared.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        let store = s.app.store()?;
        if store.queued_count()? == 0 {
            return Ok(0);
        }
        let r = notify::flush_queue(&s.app.config, &store, s.app.dashboard_link())?;
        Ok(r.sent.len())
    })
    .await;
    match res {
        Ok(Ok(n)) if n > 0 => tracing::info!("Gesammelte Meldungen nach dem Spiel zugestellt"),
        Ok(Err(e)) => tracing::warn!("Gesammelte Meldungen nicht zugestellt: {e:#}"),
        _ => {}
    }
}

/// Shows due Meldefenster on a blocking thread, one window at a time.
/// Each window re-checks gaming first, so none appears during a game.
pub fn show_windows(shared: &Arc<Shared>) {
    if shared.window_open.swap(true, Ordering::SeqCst) {
        return;
    }
    let s = shared.clone();
    tokio::task::spawn_blocking(move || {
        let is_gaming = || {
            let g = gaming::detect(&s.app.config.gaming);
            let active = g.active;
            *s.gaming.lock().unwrap() = g;
            active || s.is_stopping()
        };
        match s.app.show_due_windows(&is_gaming) {
            Ok(n) if n > 0 => tracing::info!("{n} Meldefenster angezeigt (Entscheidungen bzw. „Später“ stehen im Protokoll des Dashboards)"),
            Ok(_) => {}
            Err(e) => tracing::warn!("Meldefenster: {e:#}"),
        }
        s.window_open.store(false, Ordering::SeqCst);
    });
}

/// Collects paths and checks of all due schedule entries and marks them as run.
async fn due_work(shared: &Arc<Shared>) -> (Vec<PathBuf>, Vec<Check>) {
    let s = shared.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<PathBuf>, Vec<Check>)> {
        let store = s.app.store()?;
        let now_dt = Local::now().naive_local();
        let now = now_dt.format(TS_FORMAT).to_string();
        let idle = gaming::idle_duration();
        let mut roots: Vec<PathBuf> = Vec::new();
        let mut checks: Vec<Check> = Vec::new();
        for entry in &s.app.config.zeitplan {
            let key = entry.key();
            let last: Option<NaiveDateTime> = store
                .last_run(&key)?
                .and_then(|t| NaiveDateTime::parse_from_str(&t, TS_FORMAT).ok());
            if last.is_none() && entry.kind.is_recurring_timed() {
                // Start counting from now instead of catching up old slots.
                store.set_last_run(&key, &now)?;
                continue;
            }
            if entry.kind.is_due(now_dt, last, idle) {
                tracing::info!("Zeitplan fällig: {}", entry.label());
                store.set_last_run(&key, &now)?;
                for c in Check::from_list(&entry.pruefungen) {
                    if !checks.contains(&c) {
                        checks.push(c);
                    }
                }
                let paths: Vec<PathBuf> = if entry.pfade.is_empty() {
                    s.app.config.default_scan_paths()
                } else {
                    entry.pfade.iter().map(|p| PathBuf::from(k9_core::paths::expand_env(p))).collect()
                };
                for p in paths {
                    if !roots.contains(&p) {
                        roots.push(p);
                    }
                }
            }
        }
        Ok((existing(roots), checks))
    })
    .await
    .ok()
    .and_then(|r| r.map_err(|e| tracing::warn!("Zeitplan-Prüfung fehlgeschlagen: {e:#}")).ok())
    .unwrap_or_default()
}

pub fn start_scan(shared: Arc<Shared>, roots: Vec<PathBuf>, checks: Vec<Check>, art: ScanArt) {
    if shared.scan_running.swap(true, Ordering::SeqCst) {
        return;
    }
    shared.scan_cancel.store(false, Ordering::SeqCst);
    shared.scan_seen.store(0, Ordering::Relaxed);
    *shared.scan_kind.lock().unwrap() = art.label().to_string();
    shared.scan_current.lock().unwrap().clear();
    tokio::task::spawn_blocking(move || {
        tracing::info!("Prüfung gestartet ({}): {:?} {:?}", art.label(), checks, roots);
        let control = GamingPause { shared: shared.clone(), last_check: Cell::new(Instant::now()), art };
        let started = Local::now().format(TS_FORMAT).to_string();
        match shared.app.run_checks_with_threads(&checks, &roots, &control, &mut |m| tracing::info!("{m}"), art.threads()) {
            Ok(rep) => {
                let summary = k9_core::tf!(
                    "{started}, {}: {} Dateien ({} unverändert), {} neu, {} automatisch behandelt, {:.0} s{}", "{started}, {}: {} files ({} unchanged), {} new, {} handled automatically, {:.0} s{}",
                    art.label(),
                    rep.stats.files,
                    rep.stats.cached,
                    rep.outcome.new.len(),
                    rep.outcome.auto.len(),
                    rep.stats.seconds,
                    if rep.stats.aborted { k9_core::t!(" (abgebrochen)", " (cancelled)") } else { "" }
                );
                for n in &rep.notes {
                    tracing::info!("Hinweis: {n}");
                }
                tracing::info!("Prüfung beendet – {summary}");
                *shared.last_scan.lock().unwrap() = Some(summary);
            }
            Err(e) => tracing::error!("Prüfung fehlgeschlagen: {e:#}"),
        }
        shared.scan_running.store(false, Ordering::SeqCst);
        show_windows(&shared);
    });
}

/// The service updated the sources: keep the numbers in the PDF guide current.
fn refresh_pdf_if_sources_changed(shared: &Arc<Shared>) {
    static LAST: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    // The newest MalwareBazaar hashes arrive every hour: the PDF is rebuilt at most every 12 hours.
    static BUILT: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    const PAUSE: std::time::Duration = std::time::Duration::from_secs(12 * 3600);
    let Ok(state) = shared.app.sources().map(|s| s.state_fingerprint()) else { return };
    let mut last = LAST.lock().unwrap();
    let Some(known) = last.as_ref() else {
        *last = Some(state);
        return;
    };
    if *known == state || shared.gaming.lock().map(|g| g.active).unwrap_or(false) {
        return;
    }
    let mut built = BUILT.lock().unwrap();
    if built.is_some_and(|t| t.elapsed() < PAUSE) {
        return; // the change stays noted and is picked up after the pause
    }
    *built = Some(Instant::now());
    *last = Some(state);
    std::thread::spawn(refresh_pdf_guide);
}

/// Regenerates docs\Anleitung-K9.pdf (section "Aktueller Stand der
/// Erkennungsdaten") if the agent runs from the project folder. Low priority,
/// no window; failures are only logged.
fn refresh_pdf_guide() {
    use std::os::windows::process::CommandExt;
    let Some(script) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.ancestors().map(|d| d.join("scripts").join("anleitung-pdf.ps1")).find(|p| p.is_file()))
        // Installed under Program Files: the project folder is noted at installation.
        .or_else(|| k9_core::dienst::dev_dir().map(|d| d.join("scripts").join("anleitung-pdf.ps1")).filter(|p| p.is_file()))
    else {
        return;
    };
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let res = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .creation_flags(BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output();
    match res {
        Ok(o) if o.status.success() => tracing::info!("PDF-Anleitung mit aktuellen Erkennungsdaten neu erzeugt"),
        Ok(o) => tracing::warn!("PDF-Anleitung nicht erzeugt: {}", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("")),
        Err(e) => tracing::warn!("PDF-Anleitung nicht erzeugt: {e}"),
    }
}

#[cfg(test)]
mod scan_art_tests {
    use super::*;

    #[test]
    fn only_the_quick_scan_runs_on_during_a_game() {
        assert!(!ScanArt::Schnell.pauses_for_games());
        for art in [ScanArt::Geplant, ScanArt::VollSchonend, ScanArt::VollSchnell] {
            assert!(art.pauses_for_games(), "{art:?}");
        }
    }

    #[test]
    fn only_the_fast_full_scan_gets_more_threads() {
        assert_eq!(ScanArt::VollSchnell.threads(), Some(fast_threads()));
        assert_eq!((fast_threads_for(48), fast_threads_for(16), fast_threads_for(8), fast_threads_for(2)), (16, 5, 4, 4));
        assert!(fast_threads() <= k9_core::scanner::MAX_THREADS);
        for art in [ScanArt::Geplant, ScanArt::Schnell, ScanArt::VollSchonend] {
            assert_eq!(art.threads(), None, "{art:?}");
        }
        // The names shown in the dashboard and in "Letzter Scan".
        assert_eq!(ScanArt::VollSchonend.label(), "Vollständiger Scan (schonend)");
        assert_eq!(ScanArt::VollSchnell.label(), "Vollständiger Scan (schnell)");
        assert_eq!(ScanArt::Schnell.label(), "Schnellscan (Standardordner)");
    }
}
