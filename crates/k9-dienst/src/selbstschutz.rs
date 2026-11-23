//! Tamper alarm: malware switches protection off first. At every start and every 10
//! minutes the service compares its program files with the baseline that only
//! `k9 dienst aktualisieren` writes (k9_core::basis), checks that it still starts
//! automatically and reports a restart that came neither from an update nor with Windows.
//! (A stopped agent is reported by the agent watch, a stopped service by the agent, a
//! stopped ETW session by the ETW thread.) Nothing is repaired automatically.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use k9_core::basis::{self, StartKind};
use k9_core::model::{Finding, Severity};

use crate::Svc;

const CHECK: Duration = Duration::from_secs(600);

/// A critical self-protection notice (shown even during a game).
pub fn alarm(rule: &str, title: &str, hint: &str) -> Finding {
    let mut f = crate::wache::notice(rule, title, hint);
    f.severity = Severity::Kritisch;
    f
}

fn files_alarm(diff: &[String]) -> Finding {
    alarm(
        "SELBSTSCHUTZ:DATEIEN-VERAENDERT",
        k9_core::t!("Programmdateien von K9 wurden verändert", "Program files of K9 were changed"),
        &k9_core::tf!(
            "Verändert seit der letzten Aktualisierung: {} in {}. „k9 dienst aktualisieren“ löst diese Meldung nicht aus. \
             Hast du nichts aktualisiert, könnte ein Programm versucht haben, K9 auszutauschen – vollständigen Scan starten und \
             K9 mit „k9 dienst aktualisieren“ (als Administrator) neu einspielen.", "Changed since the last update: {} in {}. “k9 dienst aktualisieren” does not trigger this finding. \
             If you did not update anything, a program might have tried to replace K9 – start a full scan and \
             install K9 again with “k9 dienst aktualisieren” (as administrator).",
            diff.join(", "),
            k9_core::dienst::install_dir().display()
        ),
    )
}

fn starts_automatically() -> Option<bool> {
    use windows_service::service::{ServiceAccess, ServiceStartType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let s = m.open_service(k9_core::dienst::SERVICE_NAME, ServiceAccess::QUERY_CONFIG).ok()?;
    Some(s.query_config().ok()?.start_type == ServiceStartType::AutoStart)
}

fn uptime_secs() -> u64 {
    // SAFETY: plain query.
    unsafe { windows::Win32::System::SystemInformation::GetTickCount64() / 1000 }
}

/// The service was ended by force and Windows has started it again (a second later, see the
/// failure actions set by `k9 dienst installieren/aktualisieren`). What the service knew about
/// running programs is gone, so it looks at what runs now: every unsigned program from the
/// internet (or new in a user's folder, or on a removable drive) started within the last
/// 30 minutes is reported as a critical attack chain and –
/// with "Kritische Programme anhalten" – frozen until the user decides.
fn after_forced_end(svc: &Svc) {
    use k9_core::ketten::{self, Chains, Step};
    let now = crate::etw::filetime_now();
    let mut chains = Chains::default();
    let arbeit = k9_core::arbeitsordner::Arbeit::from_config(&svc.live().arbeitsordner);
    for pid in k9_core::realtime::process_snapshot().into_keys() {
        let Some((path, start)) = k9_core::realtime::process_path_and_start(pid) else { continue };
        if start > now || now - start > ketten::WINDOW {
            continue;
        }
        let internet = k9_core::herkunft::zone_of(&path).is_some_and(|z| z.from_internet());
        let Some(root) = crate::etw::chain_root(&path, internet, &arbeit) else { continue };
        chains.start(pid, start, &path.display().to_string(), root);
    }
    let reports = chains.protection_attacked(now, Step::DienstBeendet, &|_, _| true);
    tracing::warn!("Selbstschutz: der Dienst wurde gewaltsam beendet und neu gestartet – {} laufende(s) verdächtige(s) Programm(e)", reports.len());
    for r in &reports {
        tracing::warn!("Angriffskette ({:?}) ausgehend von {}: {}", r.severity, r.root_exe, r.steps.join(" → "));
        svc.report(&ketten::finding(r));
    }
}

pub fn run(svc: Arc<Svc>) {
    let dir = k9_core::dienst::install_dir();
    let mut reported: BTreeSet<String> = BTreeSet::new();
    let mut check_files = |svc: &Svc| {
        let Ok(store) = svc.app.store() else { return };
        let now = basis::hashes(&dir);
        match basis::load(&store) {
            // First start of a version with this check (or the update could not write it).
            None => {
                let _ = basis::save(&store, &basis::Baseline { files: now, zeit: k9_core::now_string() });
                tracing::info!("Selbstschutz: Ausgangsstand der Programmdateien angelegt");
            }
            Some(b) => {
                let diff = basis::changed(&b.files, &now);
                let key = diff.join(",");
                if !diff.is_empty() && reported.insert(key) {
                    tracing::warn!("Selbstschutz: Programmdateien verändert: {}", diff.join(", "));
                    svc.report(&files_alarm(&diff));
                }
            }
        }
    };
    // At the start: files against the baseline, and how the service was started.
    if let Ok(store) = svc.app.store() {
        let kind = basis::start_kind(basis::take_update_marker(&store), uptime_secs());
        tracing::info!("Selbstschutz: Dienststart {kind:?}");
        svc.started_by_update.store(kind == StartKind::Update, std::sync::atomic::Ordering::Relaxed);
        if basis::mark_running(&store, basis::boot_epoch(uptime_secs())) {
            after_forced_end(&svc);
        }
        if kind == StartKind::Other {
            let mut f = crate::wache::notice(
                "SELBSTSCHUTZ:DIENST-NEUSTART",
                k9_core::t!("Der K9-Dienst wurde neu gestartet", "The K9 service was restarted"),
                k9_core::t!("Der Dienst wurde weder mit Windows noch über „k9 dienst aktualisieren“ gestartet – z. B. nach „k9 dienst stoppen/starten“, \
                 über die Diensteverwaltung oder nach einem Absturz. Warst du das nicht, könnte ein Programm den Schutz kurz abgeschaltet haben.", "The service was started neither with Windows nor via “k9 dienst aktualisieren” – e.g. after “k9 dienst stoppen/starten”, via the services management or after a crash. If that was not you, a program might have switched off the protection for a moment."),
            );
            f.severity = Severity::Mittel;
            svc.report(&f);
        }
    }
    check_files(&svc);
    let mut start_reported = false;
    // Full PowerShell logging (HKLM, administrators only): switched off -> notice.
    let mut ps_policy = k9_core::skripte::policy_state();
    loop {
        for _ in 0..(CHECK.as_secs() / 10) {
            if svc.is_stopping() {
                return;
            }
            std::thread::sleep(Duration::from_secs(10));
        }
        check_files(&svc);
        match starts_automatically() {
            Some(false) if !start_reported => {
                start_reported = true;
                tracing::warn!("Selbstschutz: Startart des Dienstes geändert");
                svc.report(&alarm(
                    "SELBSTSCHUTZ:DIENST-STARTART",
                    k9_core::t!("Der K9-Dienst startet nicht mehr automatisch", "The K9 service no longer starts automatically"),
                    k9_core::t!("Die Startart des Dienstes wurde geändert (z. B. auf „Manuell“ oder „Deaktiviert“). Nach dem nächsten Neustart wäre der Schutz aus. \
                     Hast du das nicht selbst gemacht: „k9 dienst aktualisieren“ (als Administrator) stellt die Startart wieder her.", "The start type of the service was changed (e.g. to “Manual” or “Disabled”). After the next restart the protection would be off. If you did not do this yourself: “k9 dienst aktualisieren” (as administrator) restores the start type."),
                ));
            }
            Some(true) => start_reported = false,
            _ => {}
        }
        let now = k9_core::skripte::policy_state();
        if policy_switched_off(ps_policy, now) {
            tracing::warn!("Selbstschutz: vollständige PowerShell-Protokollierung ausgeschaltet");
            svc.report(&policy_notice());
        }
        ps_policy = now;
    }
}

/// The policy was on (for one of the two PowerShells) and is off now.
fn policy_switched_off(before: [bool; 2], now: [bool; 2]) -> bool {
    before.iter().zip(now).any(|(b, n)| *b && !n)
}

fn policy_notice() -> k9_core::model::Finding {
    let mut f = crate::wache::notice(
        "SELBSTSCHUTZ:PS-PROTOKOLL-AUS",
        k9_core::t!("Die vollständige PowerShell-Protokollierung wurde ausgeschaltet", "The full PowerShell logging was switched off"),
        k9_core::t!("Die Windows-Richtlinie „Script Block Logging“ ist nicht mehr gesetzt – der Dienst sieht jetzt nur noch die Skripte, die PowerShell selbst für verdächtig hält. \
         Hast du „k9 powershell-protokoll aus“ ausgeführt, ist alles in Ordnung („Gesehen“). Sonst hat ein Programm mit Administratorrechten sie abgeschaltet: \
         vollständigen Scan starten und mit „k9 powershell-protokoll an“ (als Administrator) wieder einschalten.", "The Windows policy “Script Block Logging” is no longer set – the service now only sees the scripts PowerShell itself considers suspicious. If you ran “k9 powershell-protokoll aus”, everything is fine (“Seen”). Otherwise a program with administrator rights switched it off: start a full scan and switch it on again with “k9 powershell-protokoll an” (as administrator)."),
    );
    f.severity = Severity::Mittel;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_the_powershell_policy_off_is_noticed() {
        assert!(policy_switched_off([true, false], [false, false]));
        assert!(policy_switched_off([true, true], [true, false]));
        assert!(!policy_switched_off([false, false], [false, false]));
        assert!(!policy_switched_off([false, false], [true, true]), "einschalten ist kein Alarm");
        assert_eq!(policy_notice().severity, Severity::Mittel);
    }

    #[test]
    fn alarms_are_critical_and_name_the_files() {
        let f = files_alarm(&["k9.exe".to_string()]);
        assert_eq!(f.severity, Severity::Kritisch);
        assert!(f.details.unwrap()["hinweis"].as_str().unwrap().contains("k9.exe"));
    }
}
