//! Driver watch in the service: every 6 hours all kernel drivers are checked
//! against the lists (Microsoft block rules, LOLDrivers); every minute newly
//! loaded drivers and new driver services are noticed. Hits and new
//! registrations go to the agent like every other finding.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use k9_core::model::{Finding, Kind, Severity};
use k9_core::treiber::{self, Driver, DriverIndex};
use k9_core::winreg::{self, HKLM};

use crate::Svc;

const FULL: Duration = Duration::from_secs(6 * 3600);
const QUICK: Duration = Duration::from_secs(60);
const TIDY: Duration = Duration::from_secs(600);
const SERVICES: &str = "SYSTEM\\CurrentControlSet\\Services";

fn index(svc: &Svc) -> DriverIndex {
    svc.app.sources().map(|s| DriverIndex::load(&s.dir)).unwrap_or_default()
}

/// Identity of the current driver set (service names + loaded images).
fn snapshot() -> HashSet<String> {
    let mut s: HashSet<String> = treiber::loaded_drivers();
    for name in winreg::subkeys(HKLM, SERVICES) {
        let typ = winreg::read_dword(HKLM, &format!("{SERVICES}\\{name}"), "Type").unwrap_or(0);
        if typ & 0x3 != 0 && typ & 0x30 == 0 {
            s.insert(format!("dienst:{}", name.to_ascii_lowercase()));
        }
    }
    s
}

pub fn run(svc: Arc<Svc>) {
    std::thread::sleep(Duration::from_secs(300));
    let mut known = snapshot();
    // Everything ever seen (kept across restarts): a driver that a program loads only
    // after logon (e.g. MSI Afterburner) is not "new" after every Windows start.
    // Only the very first start takes the current state as known; later starts compare
    // with the saved set, so drivers added while the service was off or starting are new.
    let mut seen = load_seen(&svc);
    if seen.is_empty() {
        seen.extend(known.iter().cloned());
        save_seen(&svc, &seen);
    }
    let mut last_full: Option<Instant> = None;
    let mut last_tidy: Option<Instant> = None;
    let mut last_state = String::new();
    loop {
        if svc.is_stopping() {
            return;
        }
        let gaming = crate::quellen::gaming(&svc);
        let state = svc.app.sources().map(|s| s.state_fingerprint()).unwrap_or_default();
        // Full check: every 6 hours and after new lists – never while gaming.
        if !gaming && (last_full.is_none_or(|t| t.elapsed() > FULL) || state != last_state) {
            last_full = Some(Instant::now());
            last_state = state;
            if let Err(e) = full_check(&svc) {
                tracing::warn!("Treiberprüfung: {e:#}");
            }
        }
        // Quick check: drivers never seen before.
        let now = snapshot();
        let new: Vec<String> = now.difference(&seen).cloned().collect();
        if !new.is_empty() {
            report_new(&svc, &new, &seen);
            seen.extend(new);
            save_seen(&svc, &seen);
        }
        // Something was removed – or regularly, also while gaming (only file and
        // registry checks): open findings of removed drivers are done. The regular
        // run also catches drivers removed while the service was not watching
        // (e.g. right after a restart).
        if known.difference(&now).next().is_some() || last_tidy.is_none_or(|t| t.elapsed() > TIDY) {
            last_tidy = Some(Instant::now());
            if let Err(e) = tidy(&svc, None) {
                tracing::debug!("Treiber-Meldungen aufräumen: {e:#}");
            }
            // Same for autostart findings whose entry was removed.
            if let Err(e) = crate::aufraeumen::autostart(&svc) {
                tracing::debug!("Autostart-Meldungen aufräumen: {e:#}");
            }
        }
        known = now;
        std::thread::sleep(QUICK);
    }
}

const SEEN_KEY: &str = "treiber_bekannt";

fn load_seen(svc: &Svc) -> HashSet<String> {
    svc.app
        .store()
        .ok()
        .and_then(|s| s.meta_get(SEEN_KEY).ok().flatten())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn save_seen(svc: &Svc, seen: &HashSet<String>) {
    let saved = svc.app.store().and_then(|s| s.meta_set(SEEN_KEY, &serde_json::to_string(seen)?));
    if let Err(e) = saved {
        tracing::debug!("Bekannte Treiber speichern: {e:#}");
    }
}

fn full_check(svc: &Svc) -> Result<()> {
    let idx = index(svc);
    if idx.is_empty() {
        return Ok(()); // lists not loaded yet
    }
    let mut drivers = treiber::inventory();
    treiber::analyze(&mut drivers, &idx, true);
    let hits: Vec<&Driver> = drivers.iter().filter(|d| !d.treffer.is_empty()).collect();
    tracing::info!("Treiberprüfung: {} Treiber, {} auf einer Liste", drivers.len(), hits.len());
    for d in hits {
        if let Some(f) = treiber::finding(d) {
            svc.report(&f);
        }
    }
    tidy(svc, Some(&drivers))
}

/// Open driver findings: done when the driver was uninstalled (file and
/// service gone), otherwise refreshed with the current facts. No user action needed.
fn tidy(svc: &Svc, drivers: Option<&[Driver]>) -> Result<()> {
    let store = svc.app.store()?;
    for det in store.pending_detections()?.into_iter().filter(|d| d.kind == Kind::Treiber) {
        let path = std::path::PathBuf::from(&det.path);
        let present = drivers.and_then(|ds| ds.iter().find(|d| d.datei == path && d.pe.is_some()));
        let service = det.details.as_ref().and_then(|d| d["dienst"].as_str()).unwrap_or("").to_string();
        let service_exists = !service.is_empty() && winreg::read_dword(HKLM, &format!("{SERVICES}\\{service}"), "Type").is_some();
        match treiber::tidy_decision(&det, present, service_exists) {
            treiber::Tidy::Removed => {
                store.mark_detection(det.id, k9_core::model::DetectionStatus::Automatisch, Some(k9_core::model::Action::Gesehen))?;
                store.log_event("info", &format!("Erledigt: Treiber {} wurde entfernt (Meldung #{})", det.path, det.id))?;
                tracing::info!("Treiber-Meldung #{} erledigt (entfernt)", det.id);
            }
            treiber::Tidy::Refresh(details) => store.update_details(det.id, &details)?,
            treiber::Tidy::Keep => {}
        }
    }
    Ok(())
}

/// New driver service or newly loaded driver: list check, otherwise a notice
/// like a new autostart entry (a driver can take over the whole PC).
/// A known driver service with a new, validly signed file: a normal driver update
/// (Windows Update, graphics driver installer) – logged, no finding. List hits and
/// unsigned files are always reported.
fn is_signed_update(d: &Driver, seen: &HashSet<String>) -> bool {
    d.signiert && !d.dienst.is_empty() && seen.contains(&format!("dienst:{}", d.dienst.to_ascii_lowercase()))
}

fn report_new(svc: &Svc, keys: &[String], seen: &HashSet<String>) {
    let idx = index(svc);
    let mut drivers = treiber::inventory();
    drivers.retain(|d| {
        let path = d.datei.display().to_string().to_ascii_lowercase();
        keys.iter().any(|k| *k == path || *k == format!("dienst:{}", d.dienst.to_ascii_lowercase()))
    });
    treiber::analyze(&mut drivers, &idx, true);
    for d in &drivers {
        if let Some(f) = treiber::finding(d) {
            svc.report(&f);
            continue;
        }
        if d.microsoft() {
            continue;
        }
        let Some(pe) = &d.pe else { continue };
        if is_signed_update(d, seen) {
            tracing::info!("Treiber aktualisiert (signiert): {} – {}", d.dienst, d.datei.display());
            if let Ok(store) = svc.app.store() {
                let _ = store.log_event("info", &format!("Treiber aktualisiert: {} ({}, {})", d.dienst, d.hersteller(), d.datei.display()));
            }
            continue;
        }
        tracing::info!("Neuer Treiber: {}", d.datei.display());
        svc.report(&new_driver_finding(d, &pe.sha256));
    }
}

fn new_driver_finding(d: &Driver, sha256: &str) -> Finding {
    let hvci = d.pe.as_ref().map(|p| p.hvci_probleme.clone()).unwrap_or_default();
    Finding {
        path: d.datei.clone(),
        sha256: sha256.to_string(),
        size: std::fs::metadata(&d.datei).map(|m| m.len()).unwrap_or(0),
        rule_id: "TREIBER:NEU".into(),
        threat_name: k9_core::tf!(
            "Neuer Treiber: {} ({}{})", "New driver: {} ({}{})",
            d.datei.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
            d.hersteller(),
            if d.signiert { "" } else { k9_core::t!(", nicht signiert", ", not signed") }
        ),
        category: k9_core::t!("Treiber", "Driver").into(),
        severity: if d.signiert { Severity::Niedrig } else { Severity::Hoch },
        engine: "treiber".into(),
        kind: Kind::Treiber,
        details: Some(serde_json::json!({
            "dienst": d.dienst,
            "start": d.start,
            "start_text": d.start_label(),
            "geladen": d.geladen,
            "version": d.info.version,
            "firma": d.hersteller(),
            "produkt": d.produkt_installiert.clone().unwrap_or_else(|| d.info.produkt.clone()),
            "signiert": d.signiert,
            "liste": "-",
            "abgleich": "nicht auf den Listen",
            "hvci": hvci,
            "ziel": d.datei.display().to_string(),
            "deaktivierbar": d.may_disable(),
            "hinweis": k9_core::t!("Ein neuer Treiber wurde installiert oder geladen. Wenn du gerade kein Programm oder Gerät installiert hast, \
                        „Treiber deaktivieren“ wählen (jederzeit wieder einschaltbar) und einen vollständigen Scan starten.", "A new driver was installed or loaded. If you have not just installed a program or device, \
                        choose “Disable driver” (can be switched on again at any time) and start a full scan."),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_update_of_a_known_driver_is_no_finding() {
        let seen: HashSet<String> = ["dienst:nvlddmkm".to_string()].into();
        let mut d = Driver { dienst: "nvlddmkm".into(), signiert: true, ..Default::default() };
        assert!(is_signed_update(&d, &seen));
        d.signiert = false;
        assert!(!is_signed_update(&d, &seen), "unsigniert bleibt eine Meldung");
        let new = Driver { dienst: "neuertreiber".into(), signiert: true, ..Default::default() };
        assert!(!is_signed_update(&new, &seen), "neuer Dienst bleibt eine Meldung");
    }
}
