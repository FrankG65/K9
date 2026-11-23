//! Firewall block of known botnet command servers (opt-in, `schutz.firewall_sperre`, see
//! k9_core::firewall). Refreshed daily, never during a game. Switched off, the service removes
//! its own rules (group "K9" with its name prefix, and the rules of older versions).

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use k9_core::firewall;

use crate::Svc;

const REFRESH: Duration = Duration::from_secs(24 * 3600);

/// Do own rules exist (also those of older versions)?
pub fn rules_exist() -> bool {
    !firewall::list_own_rules().is_empty()
}

pub fn remove_rules() -> bool {
    match firewall::remove_own_rules() {
        Ok(n) => n > 0,
        Err(e) => {
            tracing::warn!("Firewall-Sperre: {e:#}");
            false
        }
    }
}

fn refresh(svc: &Svc) -> anyhow::Result<(usize, Vec<firewall::FwRule>)> {
    let today: String = k9_core::now_string().chars().take(10).collect();
    let mut targets = Vec::new();
    let mut used = Vec::new();
    match k9_core::sources::download(firewall::FEODO_URL, &[], 10 * 1024 * 1024) {
        Ok(b) => {
            targets.extend(firewall::parse_feodo(&String::from_utf8_lossy(&b), &today));
            used.push("Feodo Tracker");
        }
        Err(e) => tracing::warn!("Firewall-Sperre: Feodo Tracker nicht abrufbar: {e:#}"),
    }
    if let Ok(src) = svc.app.sources() {
        let before = targets.len();
        targets.extend(firewall::threatfox_targets(&k9_core::sources::load_threatfox(&src.dir), &today));
        if targets.len() > before {
            used.push("ThreatFox");
        }
    }
    // Shared CDN networks are never blocked (lists fetched here, last copy or built-in as fallback).
    let cdn_dir = svc.app.sources().ok().map(|s| s.dir.join("cdn"));
    let (cdn, notes) = firewall::load_cdn(cdn_dir.as_deref(), true);
    tracing::info!("Firewall-Sperre: CDN-Netze {}", notes.join(", "));
    let choice = firewall::select(targets, &cdn);
    if let Some(t) = choice.skipped_text() {
        tracing::info!("Firewall-Sperre: {t}");
    }
    if choice.cut > 0 {
        tracing::info!("Firewall-Sperre: {} aeltere Eintraege ueber der Grenze von {} nicht gesperrt", choice.cut, firewall::MAX_TARGETS);
    }
    let groups = choice.groups;
    let n: usize = groups.values().map(Vec::len).sum();
    let wanted = firewall::wanted_rules(&groups, &today, &used.join(", "));
    // Compare with what is there and change only the differences: updates and new rules first,
    // obsolete ones last – the block never has a gap (before 0.2.2 everything was deleted and
    // rebuilt by one PowerShell process per rule, which took about 5 minutes).
    let started = Instant::now();
    let (mut fw, com_error) = firewall::open_backend();
    let mut current = fw.list();
    if let Some(e) = &com_error {
        tracing::warn!("Firewall-Sperre: Windows-Firewall-Schnittstelle nicht verfügbar ({e}) – Ersatzweg PowerShell");
    } else if let Err(e) = &current {
        tracing::warn!("Firewall-Sperre: Regeln über die Windows-Firewall-Schnittstelle nicht lesbar ({e:#}) – Ersatzweg PowerShell");
        fw = Box::new(firewall::PsFirewall);
        current = fw.list();
    }
    let plan = firewall::plan(&wanted, &current?);
    for c in &plan.conflicts {
        tracing::warn!("Firewall-Sperre: Regel „{c}“ übergangen – eine fremde Regel trägt denselben Namen");
    }
    match firewall::apply(fw.as_mut(), &plan) {
        Ok(_) => tracing::info!("Firewall-Sperre: Regeln {} in {} ms ({})", plan.summary(), started.elapsed().as_millis(), fw.label()),
        Err(e) => {
            // Nothing obsolete was removed: the previous rules stay until the next run.
            anyhow::bail!("Abgleich nach {} ms abgebrochen ({}), bisherige Regeln bleiben: {e:#}", started.elapsed().as_millis(), fw.label());
        }
    }
    Ok((n, wanted))
}

/// Rule ids of K9's own rules (name -> id), from the rule store: who removed or changed one
/// is looked up by its id in the firewall log.
fn own_ids() -> BTreeMap<String, String> {
    k9_core::eingang::read_store()
        .into_iter()
        .filter(|r| r.group == firewall::RULE_GROUP && r.name.starts_with(firewall::RULE_PREFIX))
        .map(|r| (r.name, r.id))
        .collect()
}

/// State of the guard between two passes.
#[derive(Default)]
struct Guard {
    ids: BTreeMap<String, String>,
    last_log: Option<Instant>,
    quiet: usize,
}

/// Restores K9's rules if something removed or changed them, and reports who did it.
fn guard(svc: &Svc, wanted: &[firewall::FwRule], g: &mut Guard) {
    let started = Instant::now();
    let (mut fw, _) = firewall::open_backend();
    let restored = match firewall::guard(fw.as_mut(), wanted) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Firewall-Sperre: Wiederherstellung fehlgeschlagen: {e:#}");
            return;
        }
    };
    if restored.is_empty() {
        return;
    }
    // Who did it: the newest delete/change event of one of the affected rules.
    let who_event = restored
        .missing
        .iter()
        .chain(&restored.altered)
        .filter_map(|name| g.ids.get(name))
        .find_map(|id| k9_core::eingang::changer(id));
    g.ids = own_ids();
    let who = firewall::Tamperer {
        signer: who_event.as_ref().and_then(|c| k9_core::treiber::signer_name(std::path::Path::new(&c.app))),
        app: who_event.as_ref().map(|c| c.app.clone()),
        user: who_event.as_ref().map(|c| if c.user == "S-1-5-18" { "SYSTEM".into() } else { c.user.clone() }),
        time: who_event.as_ref().map(|c| c.time.clone()),
    };
    // Log at most once a minute (something may delete the rules again and again).
    if g.last_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        tracing::warn!(
            "Firewall-Sperre: {} K9-Regel(n) {} – in {} ms wiederhergestellt (von {}){}",
            restored.count(),
            restored.verb(),
            started.elapsed().as_millis(),
            who.app.as_deref().unwrap_or("unbekannt"),
            if g.quiet > 0 { format!("; {} weitere Wiederherstellung(en) seit der letzten Zeile", g.quiet) } else { String::new() }
        );
        g.last_log = Some(Instant::now());
        g.quiet = 0;
    } else {
        g.quiet += 1;
    }
    // One open finding per program; repeats count up.
    let fp = firewall::tamper_fingerprint(who.app.as_deref());
    let before = svc
        .app
        .store()
        .ok()
        .and_then(|s| s.pending_with_fingerprint(&fp, firewall::TAMPER_RULE).ok())
        .and_then(|v| v.first().and_then(|d| d.details.as_ref().and_then(|x| x["vorfaelle"].as_u64())))
        .unwrap_or(0);
    svc.report(&firewall::tamper_finding(&restored, &who, before + 1, &k9_core::now_string()));
}

/// Time stamp of the ThreatFox data: new data -> the block is renewed at once (not only daily).
fn threatfox_stamp(svc: &Svc) -> Option<std::time::SystemTime> {
    let dir = svc.app.sources().ok()?.dir;
    std::fs::metadata(dir.join(k9_core::sources::THREATFOX_FILE)).and_then(|m| m.modified()).ok()
}

pub fn run(svc: Arc<Svc>) {
    let mut last: Option<Instant> = None;
    let mut stamp = None;
    let mut was_on = true; // at the start: remove leftover rules if switched off
    let mut wanted: Option<Vec<firewall::FwRule>> = None;
    let mut g = Guard::default();
    let notifier = crate::eingang_wache::Notifier::open();
    let mut last_guard = Instant::now();
    loop {
        if svc.is_stopping() {
            return;
        }
        // Switching on/off applies without a restart (the settings watcher updates `live`).
        let on = svc.live().schutz.firewall_sperre;
        if !on {
            // Switched off: our own rules (if any) go.
            if was_on && rules_exist() && remove_rules() {
                tracing::info!("Firewall-Sperre ausgeschaltet – eigene Regeln entfernt");
            }
            last = None;
            wanted = None;
            svc.fw_pause.store(false, Ordering::SeqCst);
        } else if (last.is_none_or(|t| t.elapsed() >= REFRESH) || threatfox_stamp(&svc) != stamp) && !crate::quellen::gaming(&svc) {
            stamp = threatfox_stamp(&svc);
            let result = refresh(&svc);
            crate::stoerungen::job_result(
                &svc,
                &crate::stoerungen::Job {
                    key: "FIREWALL-SPERRE",
                    threshold: 2,
                    title: k9_core::t!("Die Firewall-Sperre lässt sich nicht erneuern", "The firewall block cannot be renewed"),
                    hint: k9_core::t!("Zwei Versuche hintereinander sind gescheitert, die Sperrregeln für Botnetz-Steuerserver in der Windows-Firewall zu erneuern. \
                           Die bisherigen Regeln bleiben bestehen, neue Adressen fehlen. Häufige Gründe: Die Windows-Firewall ist ausgeschaltet oder wird von einem anderen Programm verwaltet. \
                           Den genauen Grund nennt das Dienst-Protokoll (Zeilen „Firewall-Sperre:“). Klappt die nächste Erneuerung, schließt K9 diese Meldung von selbst.", "Two attempts in a row to renew the block rules for botnet control servers in the Windows firewall have failed. \
                           The existing rules remain, new addresses are missing. Frequent reasons: the Windows firewall is switched off or managed by another program. \
                           The exact reason is in the service log (lines “Firewall-Sperre:”). If the next renewal works, K9 closes this finding by itself."),
                    done: "Die Firewall-Sperre wurde wieder erneuert",
                    severity: k9_core::model::Severity::Mittel,
                },
                result.is_ok(),
            );
            match result {
                Ok((n, w)) => {
                    // A regular renewal ends a pause from `k9 firewall entfernen`.
                    svc.fw_pause.store(false, Ordering::SeqCst);
                    wanted = Some(w);
                    g.ids = own_ids();
                    tracing::info!("Firewall-Sperre: {n} Adressen (Botnetz-Steuerserver) gesperrt");
                    if let Ok(s) = svc.app.store() {
                        let _ = s.log_event("info", &format!("Firewall-Sperre aktualisiert: {n} Adressen"));
                    }
                }
                Err(e) => tracing::warn!("Firewall-Sperre: {e:#}"),
            }
            last = Some(Instant::now());
        }
        was_on = on;
        // Wait up to 30 s; a change in the rule store wakes up at once (restore in ~2 s).
        let mut changed = false;
        for _ in 0..3 {
            if svc.is_stopping() {
                return;
            }
            let hit = match &notifier {
                Some(n) => n.wait(10_000),
                None => {
                    std::thread::sleep(Duration::from_secs(10));
                    false
                }
            };
            if hit {
                changed = true;
                break;
            }
        }
        let paused = svc.fw_pause.load(Ordering::SeqCst);
        if let Some(w) = wanted.as_deref().filter(|_| firewall::guard_active(svc.live().schutz.firewall_sperre, paused, true)) {
            // On a change (collect a burst for a moment) or every 10 minutes as a backstop.
            if changed || last_guard.elapsed() >= Duration::from_secs(600) {
                if changed {
                    std::thread::sleep(Duration::from_millis(700));
                    while notifier.as_ref().is_some_and(|n| n.wait(300)) {}
                }
                guard(&svc, w, &mut g);
                last_guard = Instant::now();
            }
        }
    }
}
