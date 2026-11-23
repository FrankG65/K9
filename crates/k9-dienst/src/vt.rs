//! VirusTotal lookups of new programs from the internet (opt-in): queued by the ETW
//! thread, sent one by one within the limits, never during a game.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use k9_core::virustotal::{self, Limiter, Lookup};

use crate::Svc;

/// Program and its SHA-256.
type Item = (PathBuf, String);

static QUEUE: OnceLock<Sender<Item>> = OnceLock::new();

/// Queues a program (path, SHA-256) – only if the lookup is switched on.
pub fn request(svc: &Svc, path: PathBuf, sha256: String) {
    if !svc.live().quellen.virustotal_aktiv || sha256.len() != 64 {
        return;
    }
    if let Some(tx) = QUEUE.get() {
        let _ = tx.send((path, sha256));
    }
}

pub fn run(svc: Arc<Svc>) {
    let (tx, rx): (Sender<Item>, Receiver<Item>) = mpsc::channel();
    let _ = QUEUE.set(tx);
    let mut was_on = false;
    let mut waiting: VecDeque<(PathBuf, String)> = VecDeque::new();
    let mut limiter = Limiter::default();
    let mut key_missing_logged = false;
    loop {
        if svc.is_stopping() {
            return;
        }
        while let Ok(item) = rx.recv_timeout(Duration::from_secs(if waiting.is_empty() { 30 } else { 5 })) {
            if waiting.len() < 500 && !waiting.iter().any(|(_, s)| *s == item.1) {
                waiting.push_back(item);
            }
        }
        // Switching on/off applies without a restart (the settings watcher updates `live`).
        let on = svc.live().quellen.virustotal_aktiv;
        if on != was_on {
            was_on = on;
            tracing::info!("VirusTotal-Abfrage: {}", if on { "aktiv (nur Prüfsummen neuer Programme aus dem Internet)" } else { "aus" });
        }
        if !on {
            waiting.clear();
            continue;
        }
        if waiting.is_empty() || crate::quellen::gaming(&svc) {
            continue;
        }
        let Some(key) = k9_core::secrets::get(virustotal::VT_KEY).ok().flatten() else {
            if !key_missing_logged {
                key_missing_logged = true;
                tracing::warn!("VirusTotal-Abfrage eingeschaltet, aber kein Schlüssel: k9 geheimnis {}", virustotal::VT_KEY);
            }
            waiting.clear();
            continue;
        };
        let Ok(store) = svc.app.store() else { continue };
        while let Some((path, sha)) = waiting.pop_front() {
            if let Some(v) = virustotal::cached(&store, &sha) {
                if let Some(f) = v.and_then(|v| virustotal::finding(&path, &sha, &v)) {
                    svc.report(&f);
                }
                continue;
            }
            let today: String = k9_core::now_string().chars().take(10).collect();
            if !limiter.allow(&store, Instant::now(), &today) {
                waiting.push_front((path, sha));
                break;
            }
            let result = virustotal::lookup(&sha, &key);
            if !matches!(result, Lookup::Failed(_)) {
                limiter.record(&store, Instant::now(), &today);
            }
            match result {
                Lookup::Known(v) => {
                    tracing::info!("VirusTotal: {} – {} von {} schädlich", path.display(), v.malicious, v.total);
                    virustotal::remember(&store, &sha, Some(v));
                    if let Some(f) = virustotal::finding(&path, &sha, &v) {
                        svc.report(&f);
                    }
                }
                Lookup::Unknown => {
                    tracing::info!("VirusTotal kennt {} nicht (nicht hochgeladen)", path.display());
                    virustotal::remember(&store, &sha, None);
                }
                Lookup::RateLimited => {
                    waiting.push_front((path, sha));
                    break;
                }
                Lookup::Failed(e) => tracing::warn!("VirusTotal-Abfrage fehlgeschlagen: {e}"),
            }
        }
    }
}
