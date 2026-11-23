//! Source data (signatures, hash and address lists) in the protected
//! %ProgramData%\K9\quellen – updated only by the service, with
//! the API keys from its own protected store; never while a game runs.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use k9_core::app::App;
use k9_core::sources::SourceId;

use crate::Svc;

/// One-time takeover of the user's source data into the protected folder
/// (runs with the user's rights; the copies are written with the service's).
/// The protected folder is created only together with its content, so the
/// agent never switches to an empty folder.
pub fn migrate(app: &App, user_data: &std::path::Path) -> Result<()> {
    if k9_core::schutz::protected_sources().is_some() {
        return Ok(());
    }
    let old = user_data.join("quellen");
    if !old.join("status.json").is_file() {
        return Ok(()); // nothing to take over: the first update creates the folder
    }
    let staging = k9_core::schutz::protected_dir().join("quellen.neu");
    k9_core::schutz::as_system(|| {
        let _ = std::fs::remove_dir_all(&staging);
        k9_core::schutz::secure_dir(&staging, k9_core::schutz::SDDL_SHARED)
    })?;
    let n = copy_tree(&old, &staging)?;
    let target = k9_core::schutz::protected_dir().join("quellen");
    k9_core::schutz::as_system(|| std::fs::rename(&staging, &target))?;
    tracing::info!("Erkennungsdaten übernommen: {n} Dateien nach {}", target.display());
    app.store()?.log_event("info", &format!("Erkennungsdaten in den geschützten Ordner {} übernommen", target.display()))?;
    Ok(())
}

/// Copies the user's files (no links/junctions are followed – reading runs
/// with the user's rights anyway).
fn copy_tree(from: &Path, to: &Path) -> Result<usize> {
    use std::os::windows::fs::MetadataExt;
    let mut n = 0;
    for e in std::fs::read_dir(from)?.flatten() {
        let p = e.path();
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.file_attributes() & 0x400 != 0 {
            continue; // reparse point
        }
        let t = to.join(e.file_name());
        if meta.is_dir() {
            k9_core::schutz::as_system(|| std::fs::create_dir_all(&t))?;
            n += copy_tree(&p, &t)?;
        } else if meta.is_file() && !p.extension().is_some_and(|x| x == "conf" || x == "log" || x == "tmp") {
            crate::copy_to_protected(&p, &t)?;
            n += 1;
        }
    }
    Ok(n)
}

/// A game is running (reported by the agent over the pipe; nothing is read from the
/// user's folders).
pub fn gaming(svc: &Svc) -> bool {
    svc.gaming.active(std::time::Instant::now())
}

/// Due updates every 30 minutes (first after 10 minutes, so the start stays light).
pub fn run(svc: Arc<Svc>) {
    match k9_core::schutz::import_service_secrets() {
        Ok(n) if n > 0 => tracing::info!("{n} API-Schlüssel in den geschützten Speicher des Dienstes übernommen"),
        Ok(_) => {}
        Err(e) => tracing::warn!("API-Schlüssel nicht übernommen: {e:#}"),
    }
    std::thread::sleep(Duration::from_secs(600));
    loop {
        if svc.is_stopping() {
            return;
        }
        // Takeover not done yet (e.g. nobody was logged on at the start)?
        crate::migrate(&svc.app, &svc.settings);
        if !gaming(&svc) {
            start_update(&svc, None, false);
            // Outages of sources and of ClamAV: looked at with the state of the previous round.
            if let Err(e) = crate::stoerungen::check(&svc) {
                tracing::warn!("Störungsprüfung: {e:#}");
            }
        }
        std::thread::sleep(Duration::from_secs(1800));
    }
}

/// Starts an update in the background. `force`: also sources that are not due.
pub fn start_update(svc: &Arc<Svc>, only: Option<SourceId>, force: bool) -> String {
    if svc.updating.swap(true, Ordering::SeqCst) {
        return "Die Aktualisierung läuft bereits.".into();
    }
    let s = svc.clone();
    crate::spawn("vs-aktualisierung", move || {
        k9_core::priority::below_normal();
        // Without migrated data the first update creates the protected folder.
        if k9_core::schutz::protected_sources().is_none() {
            if let Err(e) = k9_core::schutz::setup_protected_sources() {
                tracing::warn!("Geschützter Quellordner: {e:#}");
                s.updating.store(false, Ordering::SeqCst);
                return;
            }
        }
        // With the live settings: a source that was just switched on is loaded now.
        let quellen = s.live().quellen.clone();
        match s.app.update_sources_with(&quellen, only, !force) {
            Ok(results) => {
                for r in results {
                    match r {
                        Ok(m) => tracing::info!("Quelle {m}"),
                        Err(e) => tracing::warn!("Quelle {e}"),
                    }
                }
            }
            Err(e) => tracing::warn!("Quellen-Aktualisierung: {e:#}"),
        }
        s.updating.store(false, Ordering::SeqCst);
    });
    "Aktualisierung im Dienst gestartet (Ergebnis im Dashboard unter „Erkennungsquellen“ und im Protokoll).".into()
}
