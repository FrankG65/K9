//! Baseline for the tamper alarm: the program files of the installation as they were at
//! the last `k9 dienst aktualisieren`. Only that (elevated) update writes a new
//! baseline – a service restart never does. At every start and every 10 minutes the
//! service compares the files with it.
//!
//! Limit: an attacker with administrator rights could use the update path itself; without
//! code signing this cannot be closed completely (see docs/SICHERHEIT.md).

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::store::Store;

pub const FILES: [&str; 3] = ["k9-dienst.exe", "k9-agent.exe", "k9.exe"];
const META_BASELINE: &str = "selbstschutz_basis";
const META_UPDATE: &str = "selbstschutz_aktualisierung";
/// An update marker is valid this long (the service starts right after the update).
const UPDATE_VALID_SECS: u64 = 15 * 60;
/// A service start within this time after Windows started counts as start with Windows.
const BOOT_SECS: u64 = 10 * 60;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    /// (file, SHA-256) – None if the file was missing.
    pub files: Vec<(String, Option<String>)>,
    pub zeit: String,
}

pub fn hashes(dir: &Path) -> Vec<(String, Option<String>)> {
    FILES.iter().map(|f| (f.to_string(), crate::scanner::sha256_file(&dir.join(f)).ok())).collect()
}

/// Names of files that differ.
pub fn changed(before: &[(String, Option<String>)], now: &[(String, Option<String>)]) -> Vec<String> {
    FILES
        .iter()
        .filter(|f| {
            let a = before.iter().find(|(n, _)| n == *f).and_then(|(_, h)| h.clone());
            let b = now.iter().find(|(n, _)| n == *f).and_then(|(_, h)| h.clone());
            a != b
        })
        .map(|f| f.to_string())
        .collect()
}

pub fn load(store: &Store) -> Option<Baseline> {
    serde_json::from_str(&store.meta_get(META_BASELINE).ok()??).ok()
}

pub fn save(store: &Store, b: &Baseline) -> Result<()> {
    store.meta_set(META_BASELINE, &serde_json::to_string(b)?)
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Written only by the elevated `k9 dienst aktualisieren` (service stopped): the new
/// files are the baseline, and the next service start comes from this update.
pub fn record_update(store: &Store, dir: &Path) -> Result<()> {
    save(store, &Baseline { files: hashes(dir), zeit: crate::now_string() })?;
    store.meta_set(META_UPDATE, &epoch_secs().to_string())
}

/// Reads and clears the update marker: true if the update was a moment ago.
pub fn take_update_marker(store: &Store) -> bool {
    let at = store.meta_get(META_UPDATE).ok().flatten().and_then(|v| v.parse::<u64>().ok());
    let _ = store.meta_set(META_UPDATE, "");
    at.is_some_and(|t| marker_valid(t, epoch_secs()))
}

const META_RUNNING: &str = "dienst_laeuft";

/// Marks the service as running, with the moment Windows was started (seconds since 1970).
/// True if the service was ended by force while Windows kept running: the mark of the last run
/// is still there and belongs to the same start of Windows. Not after a power cut or a blue
/// screen (other start of Windows) and not after an ordinary end (mark cleared).
///
/// The start kind is no help here: within ten minutes after Windows started every start counts
/// as "with Windows" (sandbox run of 21.11.2026: the service was ended by force eight minutes
/// after the start and the restart was taken for a start with Windows).
pub fn mark_running(store: &Store, boot_epoch: u64) -> bool {
    let last = store.meta_get(META_RUNNING).ok().flatten().and_then(|v| v.parse::<u64>().ok());
    let _ = store.meta_set(META_RUNNING, &boot_epoch.to_string());
    last.is_some_and(|b| same_boot(b, boot_epoch))
}

/// The moment Windows started is computed from the clock and the running time; both drift a
/// little, and the clock may be set while Windows runs.
fn same_boot(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= 120
}

/// When Windows was started (seconds since 1970), from the running time in seconds.
pub fn boot_epoch(uptime_secs: u64) -> u64 {
    epoch_secs().saturating_sub(uptime_secs)
}

/// The service ends in the ordinary way (allowed stop, Windows shuts down).
pub fn mark_stopped(store: &Store) {
    let _ = store.meta_set(META_RUNNING, "");
}

fn marker_valid(at: u64, now: u64) -> bool {
    now >= at && now - at <= UPDATE_VALID_SECS
}

#[derive(Debug, PartialEq)]
pub enum StartKind {
    /// After `k9 dienst aktualisieren`.
    Update,
    /// With Windows.
    Boot,
    /// Anything else: stopped and started by someone, or restarted after a crash.
    Other,
}

pub fn start_kind(after_update: bool, uptime_secs: u64) -> StartKind {
    if after_update {
        StartKind::Update
    } else if uptime_secs <= BOOT_SECS {
        StartKind::Boot
    } else {
        StartKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_update_writes_the_baseline() {
        let store = Store::open_in_memory().unwrap();
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        for f in FILES {
            std::fs::write(dir.path().join(f), f.as_bytes()).unwrap();
        }
        assert!(load(&store).is_none());
        record_update(&store, dir.path()).unwrap();
        let b = load(&store).unwrap();
        assert!(changed(&b.files, &hashes(dir.path())).is_empty(), "eigene Aktualisierung: kein Alarm");
        assert!(take_update_marker(&store), "der nächste Dienststart kommt von der Aktualisierung");
        assert!(!take_update_marker(&store), "nur einmal");
        // Running mark: first start no mark; a start without an ordinary end finds it.
        let boot = 1_800_000_000;
        assert!(!mark_running(&store, boot), "erster Start");
        assert!(mark_running(&store, boot + 3), "nicht ordentlich beendet, Windows lief weiter");
        mark_stopped(&store);
        assert!(!mark_running(&store, boot), "ordentlich beendet");
        assert!(!mark_running(&store, boot + 3600), "Stromausfall: Windows wurde neu gestartet");
        assert!(mark_running(&store, boot + 3600));
        // Stop service, swap k9.exe, start it again: the baseline is NOT renewed -> alarm.
        std::fs::write(dir.path().join("k9.exe"), b"ausgetauscht").unwrap();
        assert_eq!(changed(&load(&store).unwrap().files, &hashes(dir.path())), vec!["k9.exe".to_string()]);
        assert_eq!(start_kind(take_update_marker(&store), 3600), StartKind::Other);
    }

    #[test]
    fn start_kinds() {
        assert_eq!(start_kind(true, 99_999), StartKind::Update);
        assert_eq!(start_kind(false, 120), StartKind::Boot);
        assert_eq!(start_kind(false, 3600), StartKind::Other);
        assert!(marker_valid(1000, 1000 + 60));
        assert!(!marker_valid(1000, 1000 + UPDATE_VALID_SECS + 1));
        assert!(!marker_valid(2000, 1000), "Zeit aus der Zukunft");
    }
}
