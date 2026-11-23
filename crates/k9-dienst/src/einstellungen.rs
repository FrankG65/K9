//! Watches the security settings in config.toml: weakening changes wait for
//! the user's confirmation (Meldefenster/Dashboard), the confirmed values are
//! kept in %ProgramData%\K9 (written only by the service). Every 30 s the
//! effective configuration (`Svc::live`) is updated: stronger values apply at once,
//! weaker ones only after the confirmation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use k9_core::config::Config;
use k9_core::model::{Finding, Kind, Severity};
use k9_core::schutz::{self, SecuritySettings};

use crate::Svc;

pub const RULE: &str = "EINSTELLUNG:SICHERHEIT";

/// Reads config.toml – the caller acts with the user's rights (never creates or writes it).
fn current(svc: &Svc) -> Result<Config> {
    k9_core::schutz::ensure_user_context()?;
    let file = svc.app.paths.config_file();
    let text = std::fs::read_to_string(&file).map_err(|e| anyhow::anyhow!("{} nicht lesbar: {e}", file.display()))?;
    Config::parse(&text)
}

/// One check: what applies (config.toml with the weakening changes replaced by the confirmed
/// values), the new confirmed baseline (stronger values are confirmed at once, so switching
/// them back later is a weakening again) and the withheld changes.
pub fn step(file: &Config, confirmed: &SecuritySettings) -> (Config, SecuritySettings, Vec<String>) {
    let (eff, weak) = SecuritySettings::of(file).safe(confirmed);
    let mut live = file.clone();
    eff.apply(&mut live);
    (live, eff, weak)
}

pub fn run(svc: Arc<Svc>) {
    let mut reported = String::new();
    loop {
        if svc.is_stopping() {
            return;
        }
        // Only while the user is logged on (config.toml is read with the user's rights).
        if let Some(Err(e)) = crate::wache::as_session_user(&svc.settings.user_sid, || check(&svc, &mut reported)) {
            tracing::debug!("Einstellungsprüfung: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn check(svc: &Svc, reported: &mut String) -> Result<()> {
    let file = current(svc)?;
    // The language follows config.toml without a restart (switch in the dashboard, `k9 sprache`).
    k9_core::sprache::apply(&file.sprache);
    let now = SecuritySettings::of(&file);
    let Some(mut confirmed) = schutz::confirmed_settings() else {
        // First start with the service: the current settings are the confirmed ones.
        schutz::store_confirmed_settings(&now)?;
        tracing::info!("Sicherheitseinstellungen als bestätigt übernommen");
        *svc.live.write().unwrap_or_else(|e| e.into_inner()) = file;
        return Ok(());
    };
    // Switches that a newer version watches for the first time are taken as they are.
    let completed = confirmed.complete_from(&now);
    let (live, baseline, weak) = step(&file, &confirmed);
    *svc.live.write().unwrap_or_else(|e| e.into_inner()) = live;
    if completed || baseline != confirmed {
        // Stronger (or neutral) values are the new confirmed baseline – also while another
        // change still waits for the confirmation.
        schutz::store_confirmed_settings(&baseline)?;
        if !completed {
            tracing::info!("Sicherheitseinstellungen verschärft – übernommen");
        }
    }
    if weak.is_empty() {
        return Ok(());
    }
    // Once per change; the finding stays open until confirmed (or closed by the user).
    let fp = now.fingerprint();
    if *reported != fp {
        *reported = fp.clone();
        tracing::warn!("Abschwächende Änderung in config.toml (gilt erst nach Bestätigung): {}", weak.join("; "));
        svc.report(&finding(&fp, &weak));
    }
    Ok(())
}

fn finding(fingerprint: &str, changes: &[String]) -> Finding {
    Finding {
        path: format!("config.toml: {}", changes.join("; ")).into(),
        sha256: fingerprint.to_string(),
        size: 0,
        rule_id: RULE.into(),
        threat_name: k9_core::t!("Sicherheitseinstellung wurde abgeschwächt", "A security setting was weakened").into(),
        category: k9_core::t!("Selbstschutz", "Self-protection").into(),
        severity: Severity::Hoch,
        engine: "dienst".into(),
        kind: Kind::Einstellung,
        details: Some(serde_json::json!({
            "aenderungen": changes,
            "hinweis": k9_core::tf!(
                "In config.toml wurde geändert: {}. Bis du die Änderung übernimmst, gelten die bisherigen Werte. \
                 Warst du das nicht, könnte ein Programm versuchen, den Schutz abzuschalten – dann „Ablehnen“ wählen \
                 und einen vollständigen Scan starten.", "The following was changed in config.toml: {}. Until you accept the change, the previous values apply. \
                 If that was not you, a program might be trying to switch off the protection – then choose “Reject” \
                 and start a full scan.",
                changes.join("; ")
            ),
        })),
    }
}

/// The user confirmed the change: take the current settings, if they are
/// still exactly the ones that were reported.
pub fn confirm(svc: &Svc, fingerprint: &str) -> Result<()> {
    let file = current(svc)?;
    let baseline = accept(&file, fingerprint)?;
    schutz::store_confirmed_settings(&baseline)?;
    *svc.live.write().unwrap_or_else(|e| e.into_inner()) = file;
    tracing::info!("Geänderte Sicherheitseinstellungen vom Benutzer bestätigt");
    Ok(())
}

/// The new confirmed baseline when the user accepts the reported change – only if
/// config.toml still holds exactly the reported values.
pub fn accept(file: &Config, fingerprint: &str) -> Result<SecuritySettings> {
    let now = SecuritySettings::of(file);
    if now.fingerprint() != fingerprint {
        bail!("config.toml wurde inzwischen erneut geändert – bitte den neuen Hinweis bestätigen");
    }
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switched_on_is_confirmed_at_once_and_switching_off_again_waits_for_the_confirmation() {
        let mut file = Config::default();
        let mut confirmed = SecuritySettings::of(&file);
        // off -> on: applies and becomes the new baseline.
        file.echtzeit.kritische_prozesse_anhalten = true;
        file.quellen.virustotal_aktiv = true;
        let (live, baseline, weak) = step(&file, &confirmed);
        assert!(weak.is_empty());
        assert!(live.echtzeit.kritische_prozesse_anhalten && live.quellen.virustotal_aktiv);
        assert_ne!(baseline, confirmed, "verschärft = bestätigt");
        confirmed = baseline;
        // on -> off without confirmation (e.g. a program with the user's rights): stays on + alarm.
        file.echtzeit.kritische_prozesse_anhalten = false;
        let (live, baseline, weak) = step(&file, &confirmed);
        assert!(live.echtzeit.kritische_prozesse_anhalten, "bleibt an");
        assert_eq!(weak, vec!["Kritische Programme anhalten: aus".to_string()]);
        assert_eq!(baseline, confirmed, "nichts Neues bestätigt");
        // Meanwhile something else is switched on: confirmed at once, the pending change stays.
        file.schutz.firewall_sperre = true;
        let (live, baseline, weak) = step(&file, &confirmed);
        assert!(live.schutz.firewall_sperre && live.echtzeit.kritische_prozesse_anhalten);
        assert_eq!(weak.len(), 1);
        assert_eq!(baseline.schalter.get("schutz.firewall_sperre"), Some(&true));
        // Declined (the confirmation window answers "Nein" before anything changes): the
        // baseline stays, so the next check still withholds the change.
        let (live, _, weak) = step(&file, &confirmed);
        assert!(live.echtzeit.kritische_prozesse_anhalten && weak.len() == 1);
        // Accepted: only with the fingerprint of the reported values ...
        let reported = SecuritySettings::of(&file).fingerprint();
        let mut changed_again = file.clone();
        changed_again.quellen.virustotal_aktiv = false;
        assert!(accept(&changed_again, &reported).is_err(), "inzwischen erneut geändert");
        confirmed = accept(&file, &reported).unwrap();
        // ... then it takes effect and is the new baseline.
        let (live, baseline, weak) = step(&file, &confirmed);
        assert!(weak.is_empty());
        assert!(!live.echtzeit.kritische_prozesse_anhalten && live.schutz.firewall_sperre);
        assert_eq!(baseline, confirmed);
        assert_eq!(confirmed.schalter.get("echtzeit.kritische_prozesse_anhalten"), Some(&false));
    }
}
