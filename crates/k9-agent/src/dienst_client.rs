//! Connection to the Windows service: receives its findings and keeps the
//! service status for the dashboard. Without the service nothing happens.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use k9_core::dienst::{self, Message, Pipe, PIPE_MELDUNGEN, PROTOCOL};

use crate::Shared;

pub fn start(shared: Arc<Shared>) {
    if shared.app.paths.portable {
        return; // test/portable agents never talk to the service
    }
    let _ = std::thread::Builder::new().name("k9-dienst".into()).spawn(move || run(shared));
}

fn set_text(shared: &Shared, text: String) {
    *shared.dienst_text.lock().unwrap() = text;
}

/// A running service that is gone this long (and Windows is not shutting down) is reported.
const SERVICE_GONE: Duration = Duration::from_secs(120);

fn run(shared: Arc<Shared>) {
    let mut was_running = false;
    let mut gone_since: Option<std::time::Instant> = None;
    let mut reported = false;
    loop {
        if shared.is_stopping() {
            return;
        }
        let state = dienst::service_state();
        if state.as_deref() == Some("läuft") {
            was_running = true;
            gone_since = None;
            reported = false;
        } else if was_running && !reported {
            let since = *gone_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() >= SERVICE_GONE && !shutting_down() {
                reported = true;
                tracing::warn!("Selbstschutz: K9-Dienst läuft nicht mehr ({state:?})");
                crate::realtime::report_external(&shared, vec![service_stopped_notice(state.as_deref().unwrap_or("entfernt"))]);
            }
        }
        match state {
            None => {
                shared.dienst_prozesse.store(false, Ordering::Relaxed);
                set_text(&shared, k9_core::t!("nicht eingerichtet (optional: k9 dienst installieren)", "not set up (optional: k9 dienst installieren)").into());
                std::thread::sleep(Duration::from_secs(60));
                continue;
            }
            Some(state) if state != "läuft" => {
                shared.dienst_prozesse.store(false, Ordering::Relaxed);
                set_text(
                    &shared,
                    k9_core::tf!(
                        "{state} – eingeschränkter Schutz: Programmstarts nur per Abfrage, keine DNS-Prüfung, keine Agent-Wache; \
                         Quarantäne und neue Entscheidungen erst wieder mit laufendem Dienst", "{state} – limited protection: program starts only by polling, no DNS check, no agent watch; \
                         quarantine and new decisions only again with the service running"
                    ),
                );
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            Some(_) => {}
        }
        refresh_status(&shared);
        if let Err(e) = receive(&shared) {
            tracing::debug!("Dienst-Verbindung: {e:#}");
        }
        shared.dienst_prozesse.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(10));
    }
}

fn shutting_down() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SHUTTINGDOWN};
    // SAFETY: plain query without pointers.
    unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
}

fn service_stopped_notice(state: &str) -> k9_core::model::Finding {
    let now = k9_core::now_string();
    k9_core::model::Finding {
        path: std::path::PathBuf::from(k9_core::tf!("K9-Dienst {state} ({now})", "K9 service {state} ({now})")),
        sha256: k9_core::sha256_hex(format!("hinweis|SELBSTSCHUTZ:DIENST-BEENDET|{now}").as_bytes()),
        size: 0,
        rule_id: "SELBSTSCHUTZ:DIENST-BEENDET".into(),
        threat_name: k9_core::t!("Der K9-Dienst läuft nicht mehr", "The K9 service is no longer running").into(),
        category: k9_core::t!("Selbstschutz", "Self-protection").into(),
        severity: k9_core::model::Severity::Kritisch,
        engine: "echtzeit".into(),
        kind: k9_core::model::Kind::Hinweis,
        details: Some(serde_json::json!({
            "hinweis": k9_core::tf!("Der Dienst ist seit mindestens 2 Minuten „{state}“. Ohne ihn gibt es keine Prüfung von Programmstarts, DNS-Abfragen, Zugangsdaten und Skripten.                      Hast du ihn nicht selbst gestoppt (z. B. „k9 dienst stoppen“), könnte ein Programm versucht haben, den Schutz abzuschalten –                      „k9 dienst starten“ (als Administrator) und einen vollständigen Scan starten.", "The service has been “{state}” for at least 2 minutes. Without it there is no check of program starts, DNS queries, sign-in data and scripts. \
                     If you did not stop it yourself (e.g. “k9 dienst stoppen”), a program might have tried to switch off the protection – \
                     “k9 dienst starten” (as administrator) and start a full scan."),
        })),
    }
}

fn refresh_status(shared: &Shared) {
    match dienst::request(&Message::Status { v: PROTOCOL }) {
        Ok(Message::StatusAntwort { version, etw_prozesse, etw_dns, agent_wache, schattenkopien, .. }) => {
            shared.dienst_prozesse.store(etw_prozesse, Ordering::Relaxed);
            let yes = |b: bool| if b { k9_core::t!("aktiv", "active") } else { k9_core::t!("inaktiv", "inactive") };
            set_text(
                shared,
                k9_core::tf!(
                    "läuft (Version {version}) – Prozessstarts {}, DNS-Abfragen {}, Agent-Wache {}{}", "running (version {version}) – process starts {}, DNS queries {}, agent watch {}{}",
                    yes(etw_prozesse),
                    yes(etw_dns),
                    yes(agent_wache),
                    schattenkopien.map(|s| k9_core::tf!("; Schattenkopien {s}", "; shadow copies {s}")).unwrap_or_default()
                ),
            );
        }
        _ => set_text(shared, k9_core::t!("läuft, antwortet aber nicht", "running, but does not answer").into()),
    }
}

/// Reads findings until the connection breaks; refreshes the status every minute.
fn receive(shared: &Arc<Shared>) -> anyhow::Result<()> {
    let pipe = Pipe::connect(PIPE_MELDUNGEN, Duration::from_secs(3))?;
    tracing::info!("Mit dem K9-Dienst verbunden");
    let mut pings = 0u32;
    loop {
        let msg = pipe.read_msg()?;
        if shared.is_stopping() {
            return Ok(());
        }
        dienst::validate(&msg)?;
        match msg {
            Message::Fund { token, fund, .. } => {
                let f = fund.into_finding(&token);
                crate::realtime::report_external(shared, vec![f]);
            }
            Message::Ping { .. } => {
                pings += 1;
                if pings.is_multiple_of(6) {
                    refresh_status(shared);
                }
            }
            _ => {}
        }
    }
}
