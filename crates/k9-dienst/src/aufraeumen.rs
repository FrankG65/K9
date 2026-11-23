//! Open autostart findings whose registration is gone (Run value deleted, startup
//! file removed, service or browser helper uninstalled) are done by themselves,
//! like driver findings – no user action needed.

use anyhow::Result;
use k9_core::autostart;
use k9_core::model::{Action, DetectionStatus, Kind};

use crate::Svc;

/// HKCU entries can only be read in the user's context; everything else directly.
fn needs_user(details: &serde_json::Value) -> bool {
    details["hive"].as_str() == Some("HKCU")
}

pub fn autostart(svc: &Svc) -> Result<()> {
    let store = svc.app.store()?;
    let open: Vec<_> = store
        .pending_detections()?
        .into_iter()
        .filter(|d| d.kind == Kind::Autostart)
        .filter_map(|d| d.details.clone().map(|v| (d, v)))
        .collect();
    if open.is_empty() {
        return Ok(());
    }
    // HKCU entries: decided in the user's session (nobody logged on: not decided now);
    // the protected database is written by the service itself.
    let user_gone: Vec<Option<bool>> = crate::wache::as_session_user(&svc.settings.user_sid, || {
        open.iter().map(|(_, v)| needs_user(v).then(|| autostart::registration_gone(v) == Some(true))).collect()
    })
    .unwrap_or_else(|| vec![None; open.len()]);
    for ((det, v), user) in open.iter().zip(user_gone) {
        let removed = if needs_user(v) { user == Some(true) } else { autostart::registration_gone(v) == Some(true) };
        if !removed {
            continue;
        }
        store.mark_detection(det.id, DetectionStatus::Automatisch, Some(Action::Gesehen))?;
        store.log_event("info", &format!("Erledigt: Autostart-Eintrag entfernt – {} (Meldung #{})", det.path, det.id))?;
        tracing::info!("Autostart-Meldung #{} erledigt (Eintrag entfernt)", det.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hkcu_needs_the_user_session() {
        assert!(needs_user(&serde_json::json!({ "art": "run", "hive": "HKCU" })));
        assert!(!needs_user(&serde_json::json!({ "art": "run", "hive": "HKLM" })));
        assert!(!needs_user(&serde_json::json!({ "art": "dienst", "dienst": "x" })));
    }
}
