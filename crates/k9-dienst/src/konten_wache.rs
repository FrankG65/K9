//! Accounts and logons (see k9_core::anmeldungen): reads new events of the Security log
//! every minute (every 5 minutes while a game runs – reading costs almost nothing, the
//! findings wait anyway). The very first run only stores the newest record number, so
//! events from before K9 knew about them are not reported.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use k9_core::anmeldungen::{self, FailedLogons};

use crate::Svc;

const META_KEY: &str = "anmeldungen_letzter_eintrag";

fn load(svc: &Svc) -> Option<u64> {
    svc.app.store().ok()?.meta_get(META_KEY).ok().flatten()?.parse().ok()
}

fn save(svc: &Svc, record: u64) {
    if let Err(e) = svc.app.store().and_then(|s| s.meta_set(META_KEY, &record.to_string())) {
        tracing::warn!("Anmeldungen: Stand nicht gespeichert: {e:#}");
    }
}

pub fn run(svc: Arc<Svc>) {
    let mut last = load(&svc);
    let mut failed = FailedLogons::default();
    let mut new_accounts = anmeldungen::NeueKonten::default();
    let mut warned = false;
    // Windows tells us at once when a watched event is written; the regular reading below
    // stays as a backstop (every minute, every 5 minutes while a game runs).
    let signal = anmeldungen::Signal::open();
    tracing::info!("Anmeldungen: {}", if signal.is_some() { "sofortige Benachrichtigung durch Windows aktiv" } else { "keine sofortige Benachrichtigung – Prüfung jede Minute" });
    loop {
        if svc.stopping.load(Ordering::Relaxed) {
            return;
        }
        if svc.live().echtzeit.anmeldungen {
            match last {
                None => match anmeldungen::newest_record() {
                    Some(r) => {
                        tracing::info!("Anmeldungen: Ausgangsstand Sicherheitsprotokoll Nr. {r}");
                        save(&svc, r);
                        last = Some(r);
                    }
                    None if !warned => {
                        warned = true;
                        tracing::warn!("Anmeldungen: Sicherheitsprotokoll nicht lesbar");
                    }
                    None => {}
                },
                Some(after) => match anmeldungen::read_since(after, 500) {
                    // Log cleared: the numbers start again at 1 – read it from the start
                    // (the first entry is the "log cleared" event itself).
                    Some(events) if events.is_empty() && anmeldungen::newest_record().is_some_and(|n| n < after) => {
                        tracing::warn!("Anmeldungen: Sicherheitsprotokoll wurde geleert (Nr. {after} -> neu)");
                        save(&svc, 0);
                        last = Some(0);
                    }
                    Some(events) => {
                        for ev in &events {
                            if new_accounts.part_of_creation(ev) {
                                tracing::info!("Anmeldungen: Aktivierung von „{}“ gehört zum Anlegen des Kontos – keine eigene Meldung", ev.get("TargetUserName"));
                                continue;
                            }
                            let f = if ev.id == 4625 { failed.add(ev.clone()) } else { anmeldungen::assess(ev) };
                            if let Some(f) = f {
                                tracing::warn!("Anmeldungen: {}", f.threat_name);
                                svc.report(&f);
                            }
                        }
                        if let Some(r) = events.iter().map(|e| e.record).max() {
                            save(&svc, r);
                            last = Some(r);
                        }
                    }
                    None if !warned => {
                        warned = true;
                        tracing::warn!("Anmeldungen: Sicherheitsprotokoll nicht lesbar");
                    }
                    None => {}
                },
            }
        }
        let pause = if svc.gaming.active(Instant::now()) { 300 } else { 60 };
        for _ in 0..pause {
            if svc.stopping.load(Ordering::Relaxed) {
                return;
            }
            match &signal {
                Some(s) => {
                    if s.wait(1000) {
                        // Events that belong together (created + enabled) arrive in the same moment.
                        std::thread::sleep(Duration::from_millis(300));
                        break;
                    }
                }
                None => std::thread::sleep(Duration::from_secs(1)),
            }
        }
    }
}
