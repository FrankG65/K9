//! Background care while no game runs: security check (every 6 hours, winget at most once a
//! day), home network (every hour) and the weekly report. Runs in its own thread, one at a
//! time; the switches in config.toml apply without a restart.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k9_core::config::Config;
use k9_core::sicherheit::{self, Bericht};

use crate::Shared;

static RUNNING: AtomicBool = AtomicBool::new(false);
static LAST_SWEEP: Mutex<Option<Instant>> = Mutex::new(None);

const CHECK_HOURS: i64 = 6;
const WINGET_HOURS: i64 = 24;
/// All addresses are asked every 5 minutes; in between (every tick, about 15 seconds) only
/// the devices Windows already knows are read – that sends nothing.
const SWEEP: Duration = Duration::from_secs(300);

/// Called by the scheduler when no game runs; returns at once.
pub fn tick(shared: &Arc<Shared>) {
    // Not in the first two minutes after the start (Windows and the agent are still busy).
    if shared.started.elapsed() < Duration::from_secs(120) || RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let s = shared.clone();
    std::thread::spawn(move || {
        run(&s);
        RUNNING.store(false, Ordering::SeqCst);
    });
}

fn gaming(s: &Shared) -> bool {
    s.gaming.lock().map(|g| g.active).unwrap_or(false)
}

fn run(s: &Arc<Shared>) {
    let cfg = Config::live(&s.app.paths.config_file(), &s.app.config);
    let c = &cfg.sicherheitscheck;
    if c.aktiv && !gaming(s) {
        security_check(s, &cfg);
    }
    if c.heimnetz && !gaming(s) {
        home_network(s);
    }
    if c.wochenbericht && !gaming(s) {
        weekly_report(s);
    }
    if c.neue_luecken && !gaming(s) {
        new_vulnerabilities(s);
    }
}

/// The check right now, on the user's click in the dashboard ("Jetzt neu prüfen"): reads the
/// settings again and stores the result. The list of outdated programs (winget, slow) stays
/// as it is. On 23.11.2026 the dashboard still showed "Speicherintegrität aus" forty minutes
/// after it had been switched on, because the last check was from before.
pub fn security_check_now(s: &Shared) -> anyhow::Result<()> {
    let cfg = Config::live(&s.app.paths.config_file(), &s.app.config);
    let dir = &s.app.paths.data_dir;
    let previous = Bericht::load(dir);
    let mut b = sicherheit::check(&cfg.sicherheitscheck, previous.as_ref());
    if !cfg.sicherheitscheck.programm_updates {
        b.updates = None;
        b.punkte.retain(|p| !sicherheit::is_program_updates(&p.name));
    }
    tracing::info!("Sicherheits-Check (auf Klick): {}", b.punkte.iter().map(|p| format!("{} {}", p.name, p.ampel.label())).collect::<Vec<_>>().join(", "));
    b.save(dir)
}

fn security_check(s: &Shared, cfg: &Config) {
    let dir = &s.app.paths.data_dir;
    let previous = Bericht::load(dir);
    // Fresh and in the right language: nothing to do. A language switch (dashboard, `k9 sprache`)
    // writes the points again at once.
    if previous.as_ref().is_some_and(Bericht::fits_language) && previous.as_ref().and_then(Bericht::age_hours).is_some_and(|h| h < CHECK_HOURS) {
        return;
    }
    let mut b = sicherheit::check(&cfg.sicherheitscheck, previous.as_ref());
    let winget_due = b.updates_zeit.as_deref().and_then(|t| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").ok()).is_none_or(|t| {
        (chrono::Local::now().naive_local() - t).num_hours() >= WINGET_HOURS
    });
    if cfg.sicherheitscheck.programm_updates && winget_due && !gaming(s) {
        if let Some(list) = sicherheit::outdated_programs() {
            tracing::info!("Sicherheits-Check: {} Programme mit neuerer Version (winget)", list.len());
            b.set_updates(list);
        }
    }
    if !cfg.sicherheitscheck.programm_updates {
        b.updates = None;
        b.punkte.retain(|p| !sicherheit::is_program_updates(&p.name));
    }
    tracing::info!("Sicherheits-Check: {}", b.punkte.iter().map(|p| format!("{} {}", p.name, p.ampel.label())).collect::<Vec<_>>().join(", "));
    if let Err(e) = b.save(dir) {
        tracing::warn!("Sicherheits-Check nicht gespeichert: {e:#}");
    }
}

fn home_network(s: &Arc<Shared>) {
    let Ok(store) = s.app.store() else { return };
    let saved = store.meta_get(k9_core::heimnetz::META_KEY).ok().flatten();
    let first = saved.is_none();
    let full = {
        let mut last = LAST_SWEEP.lock().unwrap_or_else(|e| e.into_inner());
        let due = first || last.is_none_or(|t| t.elapsed() >= SWEEP);
        if due {
            *last = Some(Instant::now());
        }
        due
    };
    let Some(seen) = (if full { k9_core::heimnetz::sweep() } else { k9_core::heimnetz::neighbours() }) else { return };
    let mut known: k9_core::heimnetz::Bekannt = saved.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
    let new = k9_core::heimnetz::merge(&mut known, &seen, &k9_core::now_string(), first);
    // The quick look in between saves and logs only when it found something new.
    if full || !new.is_empty() {
        if let Ok(j) = serde_json::to_string(&known) {
            let _ = store.meta_set(k9_core::heimnetz::META_KEY, &j);
        }
        tracing::info!("Heimnetz: {} Geräte erreichbar, {} bekannt, {} neu{}", seen.len(), known.len(), new.len(), if first { " (Ausgangsstand)" } else { "" });
    }
    if !new.is_empty() {
        crate::realtime::report_external(s, new.iter().map(|(ip, mac)| k9_core::heimnetz::finding(*ip, mac)).collect());
    }
}

/// Once a day: CVEs of severity High/Critical published since the last check, compared with
/// the installed programs. A failed request is tried again an hour later.
fn new_vulnerabilities(s: &Arc<Shared>) {
    static RETRY: Mutex<Option<Instant>> = Mutex::new(None);
    if RETRY.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
        return;
    }
    let Ok(store) = s.app.store() else { return };
    let now = chrono::Utc::now().naive_utc();
    let last = store.meta_get(k9_core::luecken::META_KEY).ok().flatten().and_then(|t| chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S").ok());
    // First run: the last 3 days. Never more than 14 days back.
    let from = last.unwrap_or(now - chrono::Duration::days(3)).max(now - chrono::Duration::days(14));
    if last.is_some() && now - from < chrono::Duration::hours(24) {
        return;
    }
    match k9_core::luecken::load(from, now) {
        Ok(cves) => {
            let found = k9_core::luecken::with_epss(k9_core::luecken::check(&k9_core::software::inventory(), &cves, &k9_core::software::winget_ids().unwrap_or_default()));
            tracing::info!("Neue Sicherheitslücken: {} CVE (Hoch/Kritisch) seit {from}, {} betreffen installierte Programme", cves.len(), found.len());
            let _ = store.meta_set(k9_core::luecken::META_KEY, &now.format("%Y-%m-%d %H:%M:%S").to_string());
            if !found.is_empty() {
                crate::realtime::report_external(s, found);
            }
        }
        Err(e) => {
            tracing::warn!("Neue Sicherheitslücken: {e} – neuer Versuch in einer Stunde");
            *RETRY.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }
    }
}

fn weekly_report(s: &Arc<Shared>) {
    use k9_core::wochenbericht as w;
    let Ok(store) = s.app.store() else { return };
    let now = chrono::Local::now().naive_local();
    let last = store.meta_get(w::META_KEY).ok().flatten();
    let Some(last) = last else {
        let _ = store.meta_set(w::META_KEY, &w::first_start(now));
        return;
    };
    if !w::due(Some(&last), now) {
        return;
    }
    let (Ok(dets), Ok(decs)) = (store.recent_detections(2000), store.list_decisions()) else { return };
    let report = w::build(now, &dets, &decs, Bericht::load(&s.app.paths.data_dir).as_ref());
    let _ = store.meta_set(w::META_KEY, &now.format("%Y-%m-%d %H:%M:%S").to_string());
    tracing::info!("{}", report.threat_name);
    crate::realtime::report_external(s, vec![report]);
}
