//! Outages of what K9 relies on: a detection source that can no longer be updated, a ClamAV
//! that does not start. Without a message such a failure stays unnoticed (on 19./20.11.2026
//! ClamAV was dead for two days because two of its program files were missing).
//!
//! Rules agreed with the user: every outage is reported once, the message is closed by the
//! service itself as soon as the cause is gone, and "too many requests" (429) is no outage.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use k9_core::model::{Action, DetectionStatus, Severity};
use k9_core::sources::{self, SourceId};

use crate::Svc;

const RULE_SOURCE: &str = "STOERUNG:QUELLE:";
const RULE_CLAMAV: &str = "STOERUNG:CLAMAV";
/// ClamAV is reported after this many failed start probes in a row (one probe per check).
const CLAMAV_PROBES: u32 = 2;

/// Episodes already reported since the service started (a dismissed message is not sent again).
static REPORTED: Mutex<Vec<String>> = Mutex::new(Vec::new());
static CLAMAV_FAILS: AtomicU32 = AtomicU32::new(0);
static CLAMAV_SINCE: Mutex<Option<String>> = Mutex::new(None);

fn report_once(svc: &Svc, rule: &str, episode: &str, title: &str, hint: &str, severity: Severity) {
    let mut seen = REPORTED.lock().unwrap_or_else(|e| e.into_inner());
    if seen.iter().any(|e| e == episode) {
        return;
    }
    seen.push(episode.to_string());
    let mut f = crate::wache::notice(rule, title, hint);
    // One message per outage: the same episode has the same identity.
    f.sha256 = k9_core::sha256_hex(episode.as_bytes());
    f.severity = severity;
    f.category = if rule.starts_with("HINWEIS") { k9_core::t!("Hinweis", "Note") } else { k9_core::t!("Störung", "Fault") }.into();
    tracing::warn!("Störung: {title}");
    svc.report(&f);
}

/// A recurring job of the service whose failure the user should hear about (shadow copies,
/// the firewall block).
pub struct Job<'a> {
    /// Part of the rule ID after "STOERUNG:", e.g. "SCHATTENKOPIE:C:".
    pub key: &'a str,
    /// Reported after this many failures in a row.
    pub threshold: u32,
    pub title: &'a str,
    pub hint: &'a str,
    /// Text for the event log when it works again.
    pub done: &'a str,
    pub severity: Severity,
}

/// Failures in a row per job: (key, failures, since when).
static JOBS: Mutex<Vec<(String, u32, String)>> = Mutex::new(Vec::new());

/// Counts the result of a job. Returns the failures in a row and since when (0 after success).
fn count(jobs: &mut Vec<(String, u32, String)>, key: &str, ok: bool, now: &str) -> (u32, String) {
    if ok {
        jobs.retain(|(k, ..)| k != key);
        return (0, String::new());
    }
    match jobs.iter_mut().find(|(k, ..)| k == key) {
        Some(j) => {
            j.1 += 1;
            (j.1, j.2.clone())
        }
        None => {
            jobs.push((key.to_string(), 1, now.to_string()));
            (1, now.to_string())
        }
    }
}

/// The result of one run of a job: reported once when it has failed `threshold` times in a row,
/// and the message is closed by the service as soon as the job works again.
pub fn job_result(svc: &Svc, job: &Job, ok: bool) {
    let (fails, since) = count(&mut JOBS.lock().unwrap_or_else(|e| e.into_inner()), job.key, ok, &k9_core::now_string());
    let rule = format!("STOERUNG:{}", job.key);
    let Ok(store) = svc.app.store() else { return };
    let open: Vec<_> = store.pending_detections().unwrap_or_default().into_iter().filter(|d| d.rule_id == rule).collect();
    if ok {
        for d in &open {
            let _ = store.mark_detection(d.id, DetectionStatus::Automatisch, Some(Action::Gesehen));
            let _ = store.log_event("info", &format!("Erledigt: {} (Meldung #{})", job.done, d.id));
            tracing::info!("Störungsmeldung #{} erledigt: {}", d.id, job.done);
        }
    } else if fails >= job.threshold && open.is_empty() {
        report_once(svc, &rule, &format!("stoerung|{}|{since}", job.key), job.title, job.hint, job.severity);
    }
}

/// Looks at all sources and at ClamAV; reports new outages and closes messages whose cause is gone.
pub fn check(svc: &Svc) -> Result<()> {
    let store = svc.app.store()?;
    let cfg = svc.live().quellen.clone();
    let src = svc.app.sources()?;
    let open: Vec<_> = store.pending_detections()?.into_iter().filter(|d| d.rule_id.starts_with("STOERUNG:")).collect();
    let close = |rule: &str, what: &str| -> Result<()> {
        for d in open.iter().filter(|d| d.rule_id == rule) {
            store.mark_detection(d.id, DetectionStatus::Automatisch, Some(Action::Gesehen))?;
            store.log_event("info", &format!("Erledigt: {what} (Meldung #{})", d.id))?;
            tracing::info!("Störungsmeldung #{} erledigt: {what}", d.id);
        }
        Ok(())
    };

    for id in SourceId::ALL {
        let rule = format!("{RULE_SOURCE}{}", id.key());
        let st = src.get(id);
        match id.enabled(&cfg).then(|| sources::outage_now(&st)).flatten() {
            Some(why) => {
                if !open.iter().any(|d| d.rule_id == rule) {
                    report_once(
                        svc,
                        &rule,
                        &sources::outage_episode(id, &st),
                        &format!("Erkennungsquelle fällt aus: {}", id.label()),
                        &format!(
                            "Diese Quelle lässt sich nicht mehr aktualisieren ({why}). K9 arbeitet mit dem letzten geladenen Stand weiter, neue Bedrohungen aus dieser Quelle fehlen. \
                             Meist liegt es am Internetzugang oder am Anbieter und behebt sich von selbst – dann schließt K9 diese Meldung. Hält es an: „k9 quellen aktualisieren {}“ ausführen und das Dienst-Protokoll ansehen.",
                            id.key()
                        ),
                        sources::outage_severity(id),
                    );
                }
            }
            None => close(&rule, &format!("Erkennungsquelle {} wird wieder aktualisiert", id.label()))?,
        }
    }

    // A provider K9 already uses has published a package K9 does not know: a hint, once.
    for (provider, name) in sources::new_packages(&src.dir) {
        report_once(
            svc,
            "HINWEIS:NEUES-PAKET",
            &format!("neuespaket|{provider}|{name}"),
            &format!("Neues Paket bei {provider}: {name}"),
            &format!(
                "{provider} bietet ein Paket an, das K9 noch nicht kennt („{name}“). K9 lädt es NICHT und nutzt es nicht – eine neue Quelle soll erst jemand auf \
                 Nutzen, Fehlalarme und Lizenz prüfen. Wenn du möchtest, dass es eingebaut wird, gib diesen Hinweis weiter. Mit „Gesehen“ verschwindet er."
            ),
            Severity::Niedrig,
        );
    }

    // ClamAV itself: does the program start at all?
    if cfg.clamav_aktiv && k9_core::clamav::installed(&cfg).is_some() {
        match k9_core::clamav::probe(&cfg) {
            Ok(()) => {
                CLAMAV_FAILS.store(0, Ordering::Relaxed);
                *CLAMAV_SINCE.lock().unwrap_or_else(|e| e.into_inner()) = None;
                close(RULE_CLAMAV, "ClamAV startet wieder")?;
            }
            Err(why) => {
                let fails = CLAMAV_FAILS.fetch_add(1, Ordering::Relaxed) + 1;
                let since = CLAMAV_SINCE.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(k9_core::now_string).clone();
                tracing::warn!("ClamAV startet nicht ({fails}. Versuch): {why}");
                if fails >= CLAMAV_PROBES && !open.iter().any(|d| d.rule_id == RULE_CLAMAV) {
                    report_once(
                        svc,
                        RULE_CLAMAV,
                        &format!("stoerung|clamav|{since}"),
                        k9_core::t!("ClamAV startet nicht – die ClamAV-Prüfung fällt aus", "ClamAV does not start – the ClamAV check is not available"),
                        &k9_core::tf!(
                            "{why} Solange das so ist, prüft K9 Dateien nur mit Hashlisten und YARA, nicht mit den ClamAV-Signaturen. \
                             Beheben: ClamAV neu installieren – in einer PowerShell „winget install Cisco.ClamAV --force“. Startet ClamAV wieder, schließt K9 diese Meldung von selbst.", "{why} As long as this is the case, K9 checks files only with hash lists and YARA, not with the ClamAV signatures. \
                             To fix it: install ClamAV again – in a PowerShell “winget install Cisco.ClamAV --force”. Once ClamAV starts again, K9 closes this finding by itself."
                        ),
                        Severity::Hoch,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_in_a_row_are_counted_per_job_and_a_success_starts_over() {
        let mut jobs = Vec::new();
        assert_eq!(count(&mut jobs, "SCHATTENKOPIE:C:", false, "t1"), (1, "t1".to_string()));
        assert_eq!(count(&mut jobs, "FIREWALL-SPERRE", false, "t2"), (1, "t2".to_string()));
        assert_eq!(count(&mut jobs, "SCHATTENKOPIE:C:", false, "t3"), (2, "t1".to_string()), "seit dem ersten Fehlschlag");
        assert_eq!(count(&mut jobs, "SCHATTENKOPIE:C:", true, "t4"), (0, String::new()));
        assert_eq!(count(&mut jobs, "SCHATTENKOPIE:C:", false, "t5"), (1, "t5".to_string()), "neue Störung, neue Meldung");
        assert_eq!(count(&mut jobs, "FIREWALL-SPERRE", false, "t6"), (2, "t2".to_string()));
    }
}
