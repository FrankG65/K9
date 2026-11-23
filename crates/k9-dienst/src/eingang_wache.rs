//! Inbound-rule watch in the service (see k9_core::eingang): notices new or changed inbound
//! firewall rules at once (change notification on the rule store) and every 10 minutes as a
//! backstop (not while gaming). The very first run only stores the current rules as the
//! baseline – no flood of findings for rules that existed before.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use k9_core::eingang;

use crate::Svc;

const META_KEY: &str = "eingangsregeln";
const BACKSTOP: Duration = Duration::from_secs(600);

fn load(svc: &Svc) -> Option<BTreeMap<String, String>> {
    svc.app.store().ok()?.meta_get(META_KEY).ok().flatten().and_then(|j| serde_json::from_str(&j).ok())
}

fn save(svc: &Svc, known: &BTreeMap<String, String>) {
    let saved = svc.app.store().and_then(|s| s.meta_set(META_KEY, &serde_json::to_string(known)?));
    if let Err(e) = saved {
        tracing::warn!("Eingangsregeln: Ausgangsstand nicht gespeichert: {e:#}");
    }
}

/// Change notification on the rule store (registry), re-armed after every signal.
pub(crate) struct Notifier {
    key: windows::Win32::System::Registry::HKEY,
    event: windows::Win32::Foundation::HANDLE,
}

impl Notifier {
    pub(crate) fn open() -> Option<Self> {
        use windows::core::HSTRING;
        use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY};
        use windows::Win32::System::Threading::CreateEventW;
        let mut key = HKEY::default();
        // SAFETY: opens a registry key and creates an event; both are closed in Drop.
        unsafe {
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, &HSTRING::from(eingang::STORE_KEY), None, KEY_NOTIFY, &mut key).is_err() {
                return None;
            }
            let event = CreateEventW(None, false, false, None).ok()?;
            let n = Self { key, event };
            n.arm().then_some(n)
        }
    }

    fn arm(&self) -> bool {
        use windows::Win32::System::Registry::{RegNotifyChangeKeyValue, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME};
        // SAFETY: valid key and event (asynchronous notification).
        unsafe { RegNotifyChangeKeyValue(self.key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, Some(self.event), true).is_ok() }
    }

    /// Waits up to `ms` for a change; re-arms after one.
    pub(crate) fn wait(&self, ms: u32) -> bool {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: valid event handle.
        let hit = unsafe { WaitForSingleObject(self.event, ms) } == WAIT_OBJECT_0;
        if hit {
            self.arm();
        }
        hit
    }
}

impl Drop for Notifier {
    fn drop(&mut self) {
        // SAFETY: handles owned by this struct.
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(self.key);
            let _ = windows::Win32::Foundation::CloseHandle(self.event);
        }
    }
}

fn check(svc: &Svc, known: &mut BTreeMap<String, String>) {
    let current = eingang::read_store();
    if current.is_empty() {
        return; // store not readable – keep the old baseline
    }
    let changed = eingang::changes(known, &current);
    let signed_ok = |p: &std::path::Path| k9_core::autostart::signature(p) != k9_core::autostart::Signature::Unsigned;
    let reports = eingang::reports(&changed, &current, &signed_ok);
    for rep in &reports {
        let sig = rep.rule.signature();
        let creator = changed.iter().filter(|r| r.signature() == sig).find_map(|r| eingang::creator(&r.id));
        let signer = creator.as_ref().and_then(|c| k9_core::treiber::signer_name(std::path::Path::new(&c.app)));
        tracing::warn!(
            "Eingangsregel gemeldet: „{}“ ({}-mal vorhanden), angelegt von {}",
            rep.rule.name,
            rep.ids.len(),
            creator.as_ref().map(|c| c.app.as_str()).unwrap_or("unbekannt (nicht mehr im Firewall-Protokoll)")
        );
        svc.report(&eingang::finding(rep, creator.as_ref(), signer.as_deref()));
    }
    // New inbound allows that are fine (validly signed program, limited addresses …): log only.
    for r in changed.iter().filter(|r| r.inbound && r.allow && r.enabled && !reports.iter().any(|x| x.rule.signature() == r.signature())) {
        tracing::info!("Eingangsregel neu oder geändert (nur Protokoll): „{}“ – {}", r.name, if r.app.is_empty() { r.service.as_str() } else { r.app.as_str() });
    }
    let now = eingang::snapshot(&current);
    if now != *known {
        *known = now;
        save(svc, known);
    }
}

pub fn run(svc: Arc<Svc>) {
    // Give the start some air (firewall service, other checks).
    for _ in 0..6 {
        if svc.is_stopping() {
            return;
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    let mut known = match load(&svc) {
        Some(k) => k,
        None => {
            let k = eingang::snapshot(&eingang::read_store());
            save(&svc, &k);
            tracing::info!("Eingangsregeln: Ausgangsstand gespeichert ({} Regeln) – ab jetzt werden neue gemeldet", k.len());
            k
        }
    };
    // Rules added while the service was not running.
    check(&svc, &mut known);
    let notifier = Notifier::open();
    if notifier.is_none() {
        tracing::warn!("Eingangsregeln: Änderungsmeldung nicht verfügbar – Prüfung alle 10 Minuten");
    }
    let mut last = Instant::now();
    loop {
        if svc.is_stopping() {
            return;
        }
        let changed = match &notifier {
            Some(n) => n.wait(10_000),
            None => {
                std::thread::sleep(Duration::from_secs(10));
                false
            }
        };
        if changed {
            // Programs often add several rules at once: collect them into one check.
            std::thread::sleep(Duration::from_secs(2));
            while notifier.as_ref().is_some_and(|n| n.wait(500)) {}
            check(&svc, &mut known);
            last = Instant::now();
        } else if last.elapsed() >= BACKSTOP && !crate::quellen::gaming(&svc) {
            check(&svc, &mut known);
            last = Instant::now();
        }
    }
}
