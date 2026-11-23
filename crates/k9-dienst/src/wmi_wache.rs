//! Hidden WMI autostarts (see k9_core::wmi_autostart): checked shortly after the start and
//! then every 10 minutes, never while a game runs. The same entry is one finding; "Gesehen"
//! is remembered for exactly this entry.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Svc;

pub fn run(svc: Arc<Svc>) {
    let mut wait = 90u64;
    let mut warned = false;
    loop {
        for _ in 0..wait {
            if svc.stopping.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        wait = 600;
        if !svc.live().echtzeit.autostart || svc.gaming.active(Instant::now()) {
            continue;
        }
        match k9_core::wmi_autostart::read() {
            Some((consumers, bindings, filters)) => {
                tracing::debug!("WMI-Autostarts: {} ausführende Verbraucher, {} Bindungen", consumers.len(), bindings.len());
                for f in k9_core::wmi_autostart::findings(&consumers, &bindings, &filters) {
                    svc.report(&f);
                }
            }
            None if !warned => {
                warned = true;
                tracing::warn!("WMI-Autostarts: root\\subscription nicht lesbar");
            }
            None => {}
        }
    }
}
