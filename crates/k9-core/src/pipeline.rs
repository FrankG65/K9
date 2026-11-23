//! Detection pipeline: finding -> remembered decision? -> (silently re-apply
//! or ignore) | (store as pending and notify). And the user-side half:
//! apply a decision and remember it.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::model::{Action, Detection, DetectionStatus, Finding, Kind};
use crate::quarantine;
use crate::store::{Store, Upsert};

#[derive(Debug)]
pub struct AutoAction {
    pub detection: Detection,
    pub action: Action,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    /// New detections that need a user decision (-> notify).
    pub new: Vec<Detection>,
    /// Already pending, no new notification.
    pub already_pending: usize,
    /// Ids of those already pending detections (Meldefenster asks again).
    pub pending_again: Vec<i64>,
    /// Silently ignored because of a remembered Freigabe.
    pub ignored: usize,
    /// Remembered Quarantäne/Löschen re-applied silently.
    pub auto: Vec<AutoAction>,
}

/// Processes scanner findings. Never quarantines or deletes anything on a
/// first detection – only remembered user decisions are applied.
/// Remembered decision that may be applied: with the Windows service only a
/// decision signed by the service counts (a program cannot allow itself).
fn trusted_decision(store: &Store, public_key: Option<&[u8]>, f: &Finding) -> Result<Option<crate::model::Decision>> {
    let Some(dec) = store.find_decision(&f.sha256, &f.rule_id)? else { return Ok(None) };
    match public_key {
        Some(pk) if !crate::schutz::verify(pk, &dec) => {
            tracing::warn!("Entscheidung #{} ohne gültige Unterschrift des Dienstes ignoriert ({})", dec.id, dec.threat_name);
            store.log_event(
                "warnung",
                &format!("Entscheidung „{}“ für {} ohne gültige Dienst-Unterschrift – wird ignoriert, der Fund wird gemeldet", dec.action.label(), dec.threat_name),
            )?;
            Ok(None)
        }
        _ => Ok(Some(dec)),
    }
}

/// Fingerprint of the decision "this rule for everything this work program starts".
pub fn rule_release_key(rule_id: &str, program: &str) -> String {
    crate::sha256_hex(format!("regelfreigabe|{rule_id}|{}", program.to_lowercase()).as_bytes())
}

/// May this finding be covered by a rule release at all? Only a quiet finding that a work
/// program started, about a process, below "Kritisch".
fn rule_release_scope(kind: Kind, severity: crate::model::Severity, details: Option<&serde_json::Value>) -> Option<(String, String)> {
    if kind != Kind::Prozess || severity >= crate::model::Severity::Kritisch {
        return None;
    }
    crate::arbeitsordner::work_program(details)
}

/// Did the user release this finding's rule for the work program that started it?
fn rule_released(store: &Store, public_key: Option<&[u8]>, f: &Finding) -> Result<bool> {
    let Some((_, program)) = rule_release_scope(f.kind, f.severity, f.details.as_ref()) else { return Ok(false) };
    let mut key = f.clone();
    key.sha256 = rule_release_key(&f.rule_id, &program);
    Ok(trusted_decision(store, public_key, &key)?.is_some_and(|d| d.action == Action::Regelfreigabe))
}

/// Has the user already decided to let this finding pass ("Freigabe", remembered and signed)?
pub fn released_before(store: &Store, f: &Finding) -> bool {
    let key = crate::schutz::public_key();
    trusted_decision(store, key.as_deref(), f).ok().flatten().is_some_and(|d| d.action.is_passive())
}

pub fn process_findings(store: &Store, quarantine_dir: &Path, findings: &[Finding]) -> Result<Outcome> {
    if store.is_remote() {
        return process_remote(store, findings);
    }
    let mut out = Outcome::default();
    let public_key = crate::schutz::public_key();
    for f in findings {
        // The rule is released for the work program that started this: no open finding, but
        // the row stays (status "automatisch") so it can be looked up.
        if rule_released(store, public_key.as_deref(), f)? {
            store.record_automatic(f, Action::Regelfreigabe)?;
            out.ignored += 1;
            continue;
        }
        match trusted_decision(store, public_key.as_deref(), f)? {
            Some(dec) if dec.action.is_passive() => {
                store.record_automatic(f, dec.action)?;
                out.ignored += 1;
            }
            Some(dec) => {
                let det = store.record_automatic(f, dec.action)?;
                let res = execute(store, quarantine_dir, &det, dec.action);
                let msg = match &res {
                    Ok(()) => format!(
                        "Gespeicherte Entscheidung '{}' automatisch angewendet: {} ({})",
                        dec.action.label(),
                        det.path,
                        det.threat_name
                    ),
                    Err(e) => format!("Gespeicherte Entscheidung '{}' für {} fehlgeschlagen: {e:#}", dec.action.label(), det.path),
                };
                tracing::info!("{msg}");
                store.log_event(if res.is_ok() { "info" } else { "fehler" }, &msg)?;
                out.auto.push(AutoAction { detection: det, action: dec.action, error: res.err().map(|e| format!("{e:#}")) });
            }
            None => match store.upsert_pending(f)? {
                Upsert::New(d) => {
                    store.log_event("warnung", &format!("Neue Erkennung: {} in {}", d.threat_name, d.path))?;
                    out.new.push(d);
                }
                Upsert::AlreadyPending(d) => {
                    out.already_pending += 1;
                    out.pending_again.push(d.id);
                }
            },
        }
    }
    Ok(out)
}

// ------------------------------------------------- with the Windows service

/// Summary of an outcome for the pipe (ids only, the agent reads the rows).
pub fn outcome_summary(o: &Outcome) -> String {
    serde_json::json!({
        "neu": o.new.iter().map(|d| d.id).collect::<Vec<_>>(),
        "wieder": o.pending_again,
        "offen": o.already_pending,
        "ignoriert": o.ignored,
        "auto": o.auto.iter().map(|a| serde_json::json!({ "id": a.detection.id, "aktion": a.action.as_str(), "fehler": a.error })).collect::<Vec<_>>(),
    })
    .to_string()
}

fn merge_summary(store: &Store, out: &mut Outcome, text: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(text).context("Antwort des Dienstes unlesbar")?;
    let ids = |k: &str| v[k].as_array().into_iter().flatten().filter_map(|x| x.as_i64()).collect::<Vec<_>>();
    for id in ids("neu") {
        if let Some(d) = store.detection(id)? {
            out.new.push(d);
        }
    }
    out.pending_again.extend(ids("wieder"));
    out.already_pending += v["offen"].as_u64().unwrap_or(0) as usize;
    out.ignored += v["ignoriert"].as_u64().unwrap_or(0) as usize;
    for a in v["auto"].as_array().into_iter().flatten() {
        let (Some(id), Some(action)) = (a["id"].as_i64(), a["aktion"].as_str().and_then(|s| s.parse::<Action>().ok())) else { continue };
        if let Some(detection) = store.detection(id)? {
            out.auto.push(AutoAction { detection, action, error: a["fehler"].as_str().map(str::to_string) });
        }
    }
    Ok(())
}

/// Findings go to the Windows service (it checks decisions and stores them).
/// If it is not reachable they are kept locally with a sequence number and
/// sent later; the service notices numbers that went missing.
fn process_remote(store: &Store, findings: &[Finding]) -> Result<Outcome> {
    let mut out = Outcome::default();
    // Older findings first.
    for (seq, json) in store.buffered_findings()? {
        let Ok(funde) = serde_json::from_str::<Vec<crate::dienst::WireFinding>>(&json) else {
            store.remove_buffered(seq)?;
            continue;
        };
        match crate::dienst::request_findings(seq, funde) {
            Ok(text) => {
                store.remove_buffered(seq)?;
                merge_summary(store, &mut out, &text)?;
            }
            Err(_) => break,
        }
    }
    for chunk in findings.chunks(10) {
        let funde: Vec<crate::dienst::WireFinding> = chunk.iter().map(crate::dienst::WireFinding::from).collect();
        let seq = store.next_seq()?;
        match crate::dienst::request_findings(seq, funde.clone()) {
            Ok(text) => merge_summary(store, &mut out, &text)?,
            Err(e) => {
                tracing::warn!("Dienst nicht erreichbar – {} Fund(e) werden zwischengespeichert: {e:#}", funde.len());
                store.buffer_findings(seq, &serde_json::to_string(&funde)?)?;
            }
        }
    }
    Ok(out)
}

/// Summary of a carried-out decision for the pipe.
pub fn decision_summary(r: &DecisionResult) -> String {
    let cut = |v: &[String]| v.iter().take(20).map(|p| p.chars().take(150).collect::<String>()).collect::<Vec<_>>();
    serde_json::json!({ "id": r.detection.id, "aktion": r.action.as_str(), "angewendet": cut(&r.applied), "fehlend": cut(&r.missing) }).to_string()
}

/// Executes an action; a finding of the Windows service that needs
/// administrator rights is handed to the service (only by its token).
fn execute(store: &Store, quarantine_dir: &Path, det: &Detection, action: Action) -> Result<()> {
    match execute_action(store, quarantine_dir, det, action) {
        Ok(()) => Ok(()),
        Err(e) if (!action.is_passive() || det.kind == Kind::Einstellung) && !crate::schutz::in_service() => {
            if !crate::dienst::service_running() {
                return Err(e);
            }
            let token = det.details.as_ref().and_then(|d| d["dienst_token"].as_str().map(str::to_string));
            let res = match token {
                Some(t) => crate::dienst::request_action(&t, det.id, action),
                // e.g. quarantine into the protected folder (no user access)
                None if !action.is_passive() => crate::dienst::request_execute(det.id, action),
                None => return Err(e),
            };
            res.with_context(|| format!("Ohne Dienst: {e:#}"))
        }
        Err(e) => Err(e),
    }
}

/// Executes an action on the detected item (no bookkeeping).
pub fn execute_action(store: &Store, quarantine_dir: &Path, det: &Detection, action: Action) -> Result<()> {
    let path = Path::new(&det.path);
    match (det.kind, action) {
        (Kind::Prozess, Action::Freigabe | Action::Einmalig | Action::Regelfreigabe) => {
            // A process suspended as ransomware suspect continues to run.
            for pid in suspended_pids(det) {
                crate::realtime::resume_process(pid);
            }
            Ok(())
        }
        (Kind::Einstellung, Action::Freigabe) => bail!("Bestätigen kann nur der Windows-Dienst"),
        (_, a) if a.is_passive() => Ok(()),
        (Kind::Prozess, Action::Beenden) => {
            let targets = process_targets(&det.details.clone().unwrap_or_default());
            if targets.is_empty() {
                bail!("Keine Prozess-ID gespeichert");
            }
            let mut ended = 0;
            let mut last_err = None;
            for (pid, exe, start) in targets {
                match crate::realtime::terminate_process(pid, exe.as_deref(), start) {
                    Ok(()) => ended += 1,
                    Err(e) => last_err = Some(e),
                }
            }
            match (ended, last_err) {
                (0, Some(e)) => Err(e),
                _ => Ok(()),
            }
        }
        (Kind::Prozess, Action::Quarantaene) => {
            let target = crate::autostart::target_of(det).context("Programmdatei unbekannt")?;
            let sha = crate::scanner::sha256_file(&target).with_context(|| format!("{} nicht lesbar", target.display()))?;
            quarantine::quarantine_file(store, quarantine_dir, &target, &sha, &det.threat_name, Some(det.id))
                .map(|_| ())
                .context("Programm läuft vermutlich noch – zuerst „Prozess beenden“ wählen")
        }
        (Kind::Datei, Action::Quarantaene) => {
            quarantine::quarantine_file(store, quarantine_dir, path, &det.sha256, &det.threat_name, Some(det.id)).map(|_| ())
        }
        (Kind::Datei, Action::Loeschen) => quarantine::delete_file(path, &det.sha256),
        (Kind::Autostart, Action::Deaktivieren) => crate::autostart::disable(store, det),
        (Kind::Treiber, Action::Deaktivieren) => crate::treiber::disable(store, det),
        // Firewall rules need the service's own rights; only exactly the reported rule(s).
        (Kind::Firewall, Action::Loeschen) => crate::schutz::as_system(|| crate::eingang::remove_for(det)).map(|n| {
            tracing::info!("Firewall-Regel „{}“ entfernt ({n}-mal)", det.path);
        }),
        (Kind::Autostart, Action::Quarantaene) => {
            let target = crate::autostart::target_of(det).context("Autostart ohne Zieldatei")?;
            let sha = crate::scanner::sha256_file(&target).with_context(|| format!("{} nicht lesbar", target.display()))?;
            quarantine::quarantine_file(store, quarantine_dir, &target, &sha, &det.threat_name, Some(det.id)).map(|_| ())
        }
        (k, a) => bail!("Aktion „{}“ ist für {} nicht möglich", a.label(), k.label()),
    }
}

/// File a finding is about: the path for files, the program for processes/autostarts.
pub fn target_file(det: &Detection) -> Option<std::path::PathBuf> {
    match det.kind {
        Kind::Datei => Some(std::path::PathBuf::from(&det.path)),
        Kind::Prozess | Kind::Autostart => crate::autostart::target_of(det),
        _ => None,
    }
}

/// Actions offered for one finding. Quarantine and delete are never offered
/// for Windows system files (powershell.exe, cmd.exe ...).
/// Processes of a process finding: (ID, program, start time). Ransomware alarms list several.
pub fn process_targets(d: &serde_json::Value) -> Vec<(u32, Option<std::path::PathBuf>, Option<i64>)> {
    if let Some(list) = d["prozesse"].as_array() {
        return list
            .iter()
            .filter_map(|p| Some((p["pid"].as_u64()? as u32, p["ziel"].as_str().map(std::path::PathBuf::from), p["startzeit"].as_i64())))
            .collect();
    }
    let exe = d["ziel"].as_str().filter(|s| !s.is_empty()).map(std::path::PathBuf::from);
    let mut out: Vec<(u32, Option<std::path::PathBuf>, Option<i64>)> =
        d["pids"].as_array().into_iter().flatten().filter_map(|p| p.as_u64()).map(|p| (p as u32, exe.clone(), None)).collect();
    if let Some(p) = d["pid"].as_u64() {
        out.push((p as u32, exe, d["startzeit"].as_i64()));
    }
    out
}

/// A process of the finding is still running (same program and start time).
pub fn process_running(det: &Detection) -> bool {
    det.kind == Kind::Prozess
        && process_targets(&det.details.clone().unwrap_or_default()).into_iter().any(|(pid, exe, start)| match (exe, start) {
            (Some(exe), Some(start)) => crate::realtime::same_process(pid, crate::realtime::process_path_and_start(pid), &exe, start).is_ok(),
            _ => false,
        })
}

/// The file of a file finding is gone (removed meanwhile, e.g. a temporary file).
/// One plain line for the dashboard: WHAT the finding is about – the file or program by name,
/// who signed it, and the program K9 was updating when it appeared. The threat name alone
/// ("ClamAV: PUA.Win.Packer…") does not say that it is the setup file of the AusweisApp.
pub fn subject(det: &Detection) -> Option<String> {
    let d = det.details.as_ref();
    let text = |k: &str| d.and_then(|d| d[k].as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let leaf = |p: &str| p.rsplit(['\\', '/']).next().unwrap_or(p).to_string();
    // "beim Update von AusweisApp (von dir in K9 gestartet)" -> "AusweisApp"
    let update = crate::arbeitsordner::reason_of(d).and_then(|r| crate::arbeitsordner::update_program(&r));
    let mut parts: Vec<String> = Vec::new();
    match det.kind {
        Kind::Datei => {
            let name = leaf(&det.path);
            if name.is_empty() || name == det.path {
                return None;
            }
            match &update {
                Some(program) => parts.push(tf!("Installationsdatei {name} zum Update von {program}", "setup file {name} for the update of {program}")),
                None => {
                    parts.push(tf!("Datei {name}", "file {name}"));
                    // winget unpacks its downloads to …\Temp\WinGet\<package>.<version>\…
                    let lower = det.path.to_lowercase();
                    if let Some(i) = lower.find("\\temp\\winget\\") {
                        let rest = &det.path[i + "\\temp\\winget\\".len()..];
                        if let Some(package) = rest.split('\\').next().filter(|p| !p.is_empty() && *p != name) {
                            parts.push(tf!("aus dem winget-Paket {package}", "from the winget package {package}"));
                        }
                    }
                }
            }
        }
        Kind::Prozess => {
            let program = text("ziel")?;
            if !std::path::Path::new(&program).is_absolute() {
                return None;
            }
            parts.push(tf!("Programm {}", "program {}", leaf(&program)));
            // Only findings that checked the signature carry the key at all.
            match d.and_then(|d| d.get("signierer")) {
                Some(serde_json::Value::String(s)) if !s.trim().is_empty() => parts.push(tf!("signiert von {}", "signed by {}", s.trim())),
                Some(serde_json::Value::Null) => parts.push(t!("ohne gültige Signatur", "without a valid signature").into()),
                _ => {}
            }
            if let Some(program) = &update {
                parts.push(tf!("gestartet beim Update von {program}", "started during the update of {program}"));
            }
        }
        _ => {
            parts.push(tf!("entstanden beim Update von {}", "created during the update of {}", update?));
        }
    }
    Some(parts.join(", "))
}

pub fn file_missing(det: &Detection) -> bool {
    det.kind == Kind::Datei && !Path::new(&det.path).exists()
}

/// Button text, by what the decision covers.
pub fn action_label(det: &Detection, a: Action) -> String {
    match (det.kind, a) {
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("INFOSTEALER:") => {
            let group = det.details.as_ref().and_then(|d| d["gruppe"].as_str()).and_then(crate::infostealer::group_name).unwrap_or(t!("dieses Programm", "this program"));
            tf!("Freigabe (dieses Programm für Daten von {group})", "Allow (this program for data of {group})")
        }
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("SKRIPT:") => t!("Freigabe (genau dieses Skript)", "Allow (exactly this script)").into(),
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("DOWNLOAD:SKRIPT") => t!("Freigabe (genau dieses Skript)", "Allow (exactly this script)").into(),
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("DOWNLOAD:") => t!("Freigabe (genau diese Programmdatei)", "Allow (exactly this program file)").into(),
        (Kind::Prozess, Action::Einmalig) if !process_running(det) => t!("Gesehen (Prozess beendet, nichts wird gemerkt)", "Seen (process has ended, nothing is remembered)").into(),
        (Kind::Prozess, Action::Regelfreigabe) => {
            let name = crate::arbeitsordner::work_program(det.details.as_ref()).map(|(n, _)| n).unwrap_or_else(|| "…".into());
            tf!("Freigabe (diese Regel für alles, was dein Arbeitsprogramm {name} startet)", "Allow (this rule for everything your work program {name} starts)")
        }
        (Kind::Datei, Action::Einmalig) => t!("Gesehen (Datei nicht mehr vorhanden, nichts wird gemerkt)", "Seen (file no longer exists, nothing is remembered)").into(),
        (Kind::Firewall, Action::Freigabe) if det.rule_id == crate::firewall::TAMPER_RULE => t!("Freigabe (dieses Programm darf K9-Regeln ändern)", "Allow (this program may change K9 rules)").into(),
        (Kind::Firewall, Action::Loeschen) => match det.details.as_ref().and_then(|d| d["anzahl"].as_u64()).unwrap_or(1) {
            n if n > 1 => tf!("Regel entfernen (alle {n} gleichen)", "Remove rule (all {n} identical ones)"),
            _ => t!("Regel entfernen", "Remove rule").into(),
        },
        _ => det.kind.action_label(a).to_string(),
    }
}

/// Title of the service's confirmation window: the label of the button that was clicked.
pub fn confirm_title(det: &Detection, a: Action) -> String {
    tf!("„{}“ bestätigen?", "Confirm “{}”?", action_label(det, a))
}

/// Explanation under a button in the Meldefenster (None: the kind's default).
pub fn action_hint(det: &Detection, a: Action) -> Option<String> {
    match (det.kind, a) {
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("INFOSTEALER:") => {
            Some(t!("Genau diese Programmdatei darf diese Daten künftig lesen (gilt nicht für andere Programme oder geänderte Dateien)", "Exactly this program file may read this data in future (does not apply to other programs or changed files)").into())
        }
        (Kind::Prozess, Action::Freigabe) if det.rule_id.starts_with("SKRIPT:") => Some(t!("Genau dieses Skript (gleicher Inhalt) künftig erlauben", "Allow exactly this script (same content) in future").into()),
        (Kind::Prozess, Action::Einmalig) if !process_running(det) => Some(t!("Das Programm läuft nicht mehr – Fund schließen, nichts wird gemerkt", "The program is no longer running – close the finding, nothing is remembered").into()),
        (Kind::Datei, Action::Einmalig) => Some(t!("Die Datei existiert nicht mehr – Fund schließen, nichts wird gemerkt", "The file no longer exists – close the finding, nothing is remembered").into()),
        _ => None,
    }
}

pub fn allowed_actions(det: &Detection) -> Vec<Action> {
    let protected = target_file(det).is_some_and(|p| quarantine::is_protected_system_path(&p));
    // A file that is gone can only be closed (or allowed); a process that no longer runs
    // (or whose ID now belongs to another process) cannot be ended.
    let missing = file_missing(det);
    let running = det.kind != Kind::Prozess || process_running(det);
    // Drivers: switching off only for drivers that start late (never boot/system drivers).
    let driver_off = det.details.as_ref().is_some_and(|d| d["deaktivierbar"].as_bool() == Some(true));
    det.kind
        .actions()
        .iter()
        .copied()
        .filter(|a| !(protected && matches!(a, Action::Quarantaene | Action::Loeschen)))
        .filter(|a| !(det.kind == Kind::Treiber && *a == Action::Deaktivieren && !driver_off))
        .filter(|a| det.kind != Kind::Datei || if missing { matches!(a, Action::Einmalig | Action::Freigabe) } else { *a != Action::Einmalig })
        .filter(|a| running || *a != Action::Beenden)
        .filter(|a| *a != Action::Regelfreigabe || rule_release_scope(det.kind, det.severity, det.details.as_ref()).is_some())
        // K9's own block rules are restored by the service: nothing to remove there.
        .filter(|a| !(det.rule_id == crate::firewall::TAMPER_RULE && *a == Action::Loeschen))
        .collect()
}

/// Suspended processes of a finding that are still the same processes (ID reuse is checked
/// when program and start time are known).
pub fn suspended_pids(det: &Detection) -> Vec<u32> {
    let d = det.details.clone().unwrap_or_default();
    if d["angehalten"].as_bool() != Some(true) {
        return Vec::new();
    }
    if d["prozesse"].is_array() {
        return process_targets(&d)
            .into_iter()
            .filter(|(pid, exe, start)| match (exe, start) {
                (Some(exe), Some(start)) => crate::realtime::same_process(*pid, crate::realtime::process_path_and_start(*pid), exe, *start).is_ok(),
                _ => false,
            })
            .map(|(pid, _, _)| pid)
            .collect();
    }
    d["pids"].as_array().into_iter().flatten().filter_map(|p| p.as_u64()).map(|p| p as u32).collect()
}

#[derive(Debug)]
pub struct DecisionResult {
    pub detection: Detection,
    pub action: Action,
    /// Paths the action was applied to.
    pub applied: Vec<String>,
    /// Paths that no longer existed (decision is remembered anyway).
    pub missing: Vec<String>,
}

/// Applies the user's choice to a pending detection and remembers it, so the
/// same detection (same SHA-256 + rule id) never notifies again. Other pending
/// copies with the same fingerprint are handled the same way.
pub fn apply_decision(store: &Store, quarantine_dir: &Path, detection_id: i64, action: Action, note: Option<&str>) -> Result<DecisionResult> {
    if store.is_remote() {
        // Carried out by the Windows service (releases need its confirmation window).
        let text = crate::dienst::request_decide(detection_id, action, note)?;
        let v: serde_json::Value = serde_json::from_str(&text).context("Antwort des Dienstes unlesbar")?;
        let list = |k: &str| v[k].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>();
        let detection = store.detection(detection_id)?.context("Erkennung verschwunden")?;
        let action = v["aktion"].as_str().and_then(|a| a.parse().ok()).unwrap_or(action);
        return Ok(DecisionResult { detection, action, applied: list("angewendet"), missing: list("fehlend") });
    }
    let det = store.detection(detection_id)?.with_context(|| format!("Erkennung {detection_id} existiert nicht"))?;
    let allowed = allowed_actions(&det);
    let action = det.kind.normalize(action).filter(|a| allowed.contains(a)).with_context(|| {
        let names: Vec<&str> = allowed.iter().map(|a| a.as_str()).collect();
        format!("Aktion „{}“ ist für diesen Fund nicht möglich (möglich: {})", action.label(), names.join(", "))
    })?;
    if det.status != DetectionStatus::Offen {
        bail!("Erkennung {detection_id} ist bereits entschieden ({})", det.action.map(Action::label).unwrap_or("-"));
    }
    if action == Action::Einmalig {
        // Close only this finding; nothing is remembered, the next identical one is reported again.
        execute(store, quarantine_dir, &det, action)?;
        store.mark_detection(det.id, DetectionStatus::Entschieden, Some(action))?;
        store.log_event("info", &format!("Nur diesmal erlaubt (nicht gemerkt): {} ({})", det.threat_name, det.path))?;
        let detection = store.detection(det.id)?.context("Erkennung verschwunden")?;
        return Ok(DecisionResult { detection, action, applied: vec![det.path.clone()], missing: Vec::new() });
    }
    if action == Action::Regelfreigabe {
        let (name, program) = rule_release_scope(det.kind, det.severity, det.details.as_ref()).context("Diese Meldung stammt nicht von einem Arbeitsprogramm")?;
        // Every open finding of this rule from the same work program is settled with it.
        let mut applied = Vec::new();
        for t in store.pending_detections()? {
            let same = t.rule_id == det.rule_id
                && rule_release_scope(t.kind, t.severity, t.details.as_ref()).is_some_and(|(_, p)| p.eq_ignore_ascii_case(&program));
            if !same {
                continue;
            }
            match execute(store, quarantine_dir, &t, action) {
                Ok(()) => {}
                Err(e) if t.id == det.id => return Err(e),
                Err(e) => {
                    tracing::warn!("{} für {} fehlgeschlagen: {e:#}", action.label(), t.path);
                    continue;
                }
            }
            store.mark_detection(t.id, DetectionStatus::Entschieden, Some(action))?;
            applied.push(t.path.clone());
        }
        let title = format!("Regel „{}“ für alles, was dein Arbeitsprogramm {name} startet ({program})", det.rule_id);
        let dec = store.set_decision(&rule_release_key(&det.rule_id, &program), &det.rule_id, &title, action, note)?;
        if let Err(e) = crate::schutz::request_signature(store, dec.id) {
            tracing::warn!("Entscheidung nicht unterschrieben: {e:#}");
            store.log_event("warnung", &format!("Entscheidung #{} konnte nicht vom Dienst unterschrieben werden ({e:#}) – sie gilt erst nach erneuter Entscheidung", dec.id))?;
        }
        store.log_event("info", &format!("Entscheidung gespeichert: {title} – {} offene Meldung(en) damit erledigt", applied.len()))?;
        let detection = store.detection(det.id)?.context("Erkennung verschwunden")?;
        return Ok(DecisionResult { detection, action, applied, missing: Vec::new() });
    }
    let mut targets = vec![det.clone()];
    targets.extend(store.pending_with_fingerprint(&det.sha256, &det.rule_id)?.into_iter().filter(|d| d.id != det.id));

    let mut applied = Vec::new();
    let mut missing = Vec::new();
    for (i, t) in targets.iter().enumerate() {
        if t.kind == Kind::Datei && !action.is_passive() && !Path::new(&t.path).exists() {
            missing.push(t.path.clone());
        } else {
            match execute(store, quarantine_dir, t, action) {
                Ok(()) => applied.push(t.path.clone()),
                // The selected detection must succeed, otherwise nothing is remembered.
                Err(e) if i == 0 => return Err(e),
                Err(e) => {
                    tracing::warn!("{} für Kopie {} fehlgeschlagen: {e:#}", action.label(), t.path);
                    continue;
                }
            }
        }
        store.mark_detection(t.id, DetectionStatus::Entschieden, Some(action))?;
    }
    let dec = store.set_decision(&det.sha256, &det.rule_id, &det.threat_name, action, note)?;
    if let Err(e) = crate::schutz::request_signature(store, dec.id) {
        tracing::warn!("Entscheidung nicht unterschrieben: {e:#}");
        store.log_event("warnung", &format!("Entscheidung #{} konnte nicht vom Dienst unterschrieben werden ({e:#}) – sie gilt erst nach erneuter Entscheidung", dec.id))?;
    }
    store.log_event(
        "info",
        &format!("Entscheidung '{}' für {} ({}) gespeichert", action.label(), det.threat_name, det.path),
    )?;
    let detection = store.detection(det.id)?.context("Erkennung verschwunden")?;
    Ok(DecisionResult { detection, action, applied, missing })
}

/// Restores a quarantined file. With `allow = true` the detection is
/// remembered as Freigabe (never reported again), otherwise the remembered
/// Quarantäne decision is revoked so the next scan asks the user again.
pub fn restore_from_quarantine(store: &Store, id: i64, target: Option<&Path>, allow: bool) -> Result<PathBuf> {
    if store.is_remote() {
        let entry = store.quarantine_entry(id)?.with_context(|| format!("Quarantäne-Eintrag {id} existiert nicht"))?;
        crate::dienst::request_restore(id, allow, target)?;
        return Ok(target.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&entry.original_path)));
    }
    let entry = store.quarantine_entry(id)?.with_context(|| format!("Quarantäne-Eintrag {id} existiert nicht"))?;
    let detection = match entry.detection_id {
        Some(did) => store.detection(did)?,
        None => None,
    };
    let dest = match quarantine::restore(store, id, target) {
        Ok(d) => d,
        // Protected quarantine: only the service can read it.
        Err(e) if !crate::schutz::in_service() && crate::dienst::service_running() => {
            crate::dienst::request_restore(id, allow, target).with_context(|| format!("Ohne Dienst: {e:#}"))?;
            return Ok(target.map(Path::to_path_buf).unwrap_or_else(|| std::path::PathBuf::from(&entry.original_path)));
        }
        Err(e) => return Err(e),
    };
    if let Some(det) = detection {
        if allow {
            let dec = store.set_decision(&det.sha256, &det.rule_id, &det.threat_name, Action::Freigabe, Some("nach Wiederherstellung freigegeben"))?;
            if let Err(e) = crate::schutz::request_signature(store, dec.id) {
                tracing::warn!("Freigabe nicht unterschrieben: {e:#}");
            }
            store.mark_detection(det.id, DetectionStatus::Entschieden, Some(Action::Freigabe))?;
        } else {
            store.revoke_decision_by_fingerprint(&det.sha256, &det.rule_id)?;
        }
    }
    store.log_event(
        "info",
        &format!("Aus Quarantäne wiederhergestellt: {}{}", dest.display(), if allow { " (freigegeben)" } else { "" }),
    )?;
    Ok(dest)
}

// ---------------------------------------------------------------------------------------------
// Several findings at once (dashboard: tick, then choose the action).
// ---------------------------------------------------------------------------------------------

/// Most findings handled together in one go.
pub const BATCH_MAX: usize = 200;

/// The result for one finding of a batch.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BatchItem {
    pub id: i64,
    pub ok: bool,
    pub text: String,
}

/// A neutral button text when the selected findings name the same action differently.
pub fn neutral_label(a: Action) -> &'static str {
    match a {
        Action::Einmalig => t!("Gesehen bzw. nur diesmal (nichts wird gemerkt)", "Seen or this once only (nothing is remembered)"),
        Action::Freigabe => t!("Freigabe", "Allow"),
        Action::Quarantaene => t!("Quarantäne", "Quarantine"),
        Action::Loeschen => t!("Löschen/Deaktivieren", "Delete/disable"),
        Action::Deaktivieren => t!("Deaktivieren", "Disable"),
        Action::Beenden => t!("Prozess beenden", "End process"),
        Action::Gesehen => t!("Gesehen", "Seen"),
        Action::Regelfreigabe => t!("Freigabe der Regel für dein Arbeitsprogramm", "Allow the rule for your work program"),
    }
}

/// The actions allowed for EVERY selected finding, with their button text: the findings' own
/// label if they all share it, otherwise a neutral one. Order as in the first finding.
pub fn common_actions(dets: &[Detection]) -> Vec<(Action, String)> {
    let Some(first) = dets.first() else { return Vec::new() };
    allowed_actions(first)
        .into_iter()
        .filter(|a| dets.iter().all(|d| allowed_actions(d).contains(a)))
        .map(|a| {
            let label = action_label(first, a);
            let same = dets.iter().all(|d| action_label(d, a) == label);
            (a, if same { label } else { neutral_label(a).to_string() })
        })
        .collect()
}

/// "Gleiche auswählen": same rule and the same file content or the same program.
pub fn same_group(det: &Detection) -> String {
    let target = det
        .details
        .as_ref()
        .and_then(|d| d["ziel"].as_str())
        .map(str::to_lowercase)
        .unwrap_or_else(|| det.sha256.clone());
    format!("{}|{target}", det.rule_id)
}

/// Checks a batch before anything happens: size, every finding open, the action allowed for
/// every one of them. A changed security setting is only ever handled on its own.
pub fn check_batch(dets: &[Detection], action: Action) -> Result<()> {
    if dets.is_empty() {
        bail!(t!("Keine Meldung ausgewählt", "No finding selected"));
    }
    if dets.len() > BATCH_MAX {
        bail!(tf!("Höchstens {BATCH_MAX} Meldungen auf einmal ({} ausgewählt)", "At most {BATCH_MAX} findings at once ({} selected)", dets.len()));
    }
    for d in dets {
        if d.kind == Kind::Einstellung {
            bail!(tf!("Meldung {}: geänderte Sicherheitseinstellungen bitte einzeln entscheiden", "Finding {}: please decide changed security settings one at a time", d.id));
        }
        if !allowed_actions(d).contains(&action) {
            bail!(tf!("Meldung {}: „{}“ ist dafür nicht möglich – nichts wurde ausgeführt", "Finding {}: “{}” is not possible for it – nothing was carried out", d.id, neutral_label(action)));
        }
    }
    Ok(())
}

/// Carries out a batch: every finding individually, through the same path as a single click.
/// A finding that an identical one already settled (same fingerprint) counts as done.
pub fn apply_batch(store: &Store, quarantine_dir: &Path, ids: &[i64], action: Action, note: Option<&str>) -> Result<Vec<BatchItem>> {
    if store.is_remote() {
        let text = crate::dienst::request_decide_many(ids, action, note)?;
        return serde_json::from_str(&text).context("Antwort des Dienstes unlesbar");
    }
    let mut dets = Vec::new();
    for id in ids {
        dets.push(store.detection(*id)?.with_context(|| format!("Meldung {id} existiert nicht"))?);
    }
    let open: Vec<Detection> = dets.into_iter().filter(|d| d.status == DetectionStatus::Offen).collect();
    check_batch(&open, action)?;
    let mut out = Vec::new();
    for id in ids {
        let now = store.detection(*id)?.context("Meldung verschwunden")?;
        if now.status != DetectionStatus::Offen {
            out.push(BatchItem { id: *id, ok: true, text: t!("schon erledigt (gleiche Meldung)", "already done (same finding)").into() });
            continue;
        }
        out.push(match apply_decision(store, quarantine_dir, *id, action, note) {
            Ok(r) => BatchItem { id: *id, ok: true, text: decision_summary(&r) },
            Err(e) => BatchItem { id: *id, ok: false, text: format!("{e:#}") },
        });
    }
    Ok(out)
}

/// "3 erledigt, 1 fehlgeschlagen: #12 …" for the dashboard.
pub fn batch_summary(items: &[BatchItem]) -> String {
    let ok = items.iter().filter(|i| i.ok).count();
    let failed: Vec<String> = items.iter().filter(|i| !i.ok).map(|i| format!("#{}: {}", i.id, i.text)).collect();
    if failed.is_empty() {
        format!("{ok} erledigt.")
    } else {
        format!("{ok} erledigt, {} fehlgeschlagen – {}", failed.len(), failed.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{test_pattern_bytes, HashListEngine, PatternEngine};
    use crate::scanner::{NoControl, Scanner};

    fn setup() -> (tempfile::TempDir, Store, Scanner, PathBuf) {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let store = Store::open_in_memory().unwrap();
        let scanner = Scanner::new(vec![Box::new(HashListEngine::new()), Box::new(PatternEngine::new())], 0, vec![]);
        let scan_dir = dir.path().join("scan");
        std::fs::create_dir_all(&scan_dir).unwrap();
        (dir, store, scanner, scan_dir)
    }

    fn scan(store: &Store, scanner: &Scanner, root: &Path, q: &Path) -> Outcome {
        let (f, _) = scanner.scan(&[root.to_path_buf()], &NoControl);
        process_findings(store, q, &f).unwrap()
    }

    #[test]
    fn firewall_rule_buttons() {
        use crate::model::Severity;
        let det = Detection {
            id: 1,
            path: "Eingehende Regel „allow 9009“ (3-mal vorhanden)".into(),
            sha256: "00".into(),
            rule_id: crate::eingang::RULE_ID.into(),
            threat_name: "x".into(),
            category: "Firewall".into(),
            severity: Severity::Hoch,
            engine: "dienst".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            status: DetectionStatus::Offen,
            action: None,
            kind: Kind::Firewall,
            details: Some(serde_json::json!({ "anzahl": 3 })),
        };
        let labels: Vec<String> = allowed_actions(&det).into_iter().map(|a| action_label(&det, a)).collect();
        assert_eq!(labels, ["Regel entfernen (alle 3 gleichen)", "Freigabe (diese Regel nicht mehr melden)", "Gesehen"]);
    }

    #[test]
    fn tamper_finding_buttons() {
        let f = crate::firewall::tamper_finding(
            &crate::firewall::Restored { missing: vec!["x".into()], ..Default::default() },
            &crate::firewall::Tamperer::default(),
            1,
            "jetzt",
        );
        let det = Detection {
            id: 1,
            path: f.path.to_string_lossy().into(),
            sha256: f.sha256,
            rule_id: f.rule_id,
            threat_name: f.threat_name,
            category: f.category,
            severity: f.severity,
            engine: f.engine,
            first_seen: String::new(),
            last_seen: String::new(),
            status: DetectionStatus::Offen,
            action: None,
            kind: f.kind,
            details: f.details,
        };
        let labels: Vec<String> = allowed_actions(&det).into_iter().map(|a| action_label(&det, a)).collect();
        assert_eq!(labels, ["Freigabe (dieses Programm darf K9-Regeln ändern)", "Gesehen"]);
    }

    #[test]
    fn confirmation_names_the_clicked_button() {
        use crate::model::Severity;
        let det = |kind: Kind, path: &str, rule: &str| Detection {
            id: 1,
            path: path.into(),
            sha256: "00".into(),
            rule_id: rule.into(),
            threat_name: "Test".into(),
            category: "Test".into(),
            severity: Severity::Mittel,
            engine: "test".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            status: DetectionStatus::Offen,
            action: None,
            kind,
            details: None,
        };
        let gone = crate::test_tmp().join("gibt-es-nicht-k9.bin");
        let d = det(Kind::Datei, &gone.to_string_lossy(), "MUSTER");
        assert_eq!(confirm_title(&d, Action::Einmalig), "„Gesehen (Datei nicht mehr vorhanden, nichts wird gemerkt)“ bestätigen?");
        let p = det(Kind::Prozess, "powershell.exe", "PROZESS:ARGUMENTE");
        assert_eq!(confirm_title(&p, Action::Einmalig), "„Gesehen (Prozess beendet, nichts wird gemerkt)“ bestätigen?");
        assert_eq!(confirm_title(&det(Kind::Prozess, "x", "SKRIPT:AMSI"), Action::Freigabe), "„Freigabe (genau dieses Skript)“ bestätigen?");
        assert_eq!(confirm_title(&det(Kind::Einstellung, "x", "EINSTELLUNG"), Action::Freigabe), "„Änderung übernehmen“ bestätigen?");
        // every kind and every button it can show: the window names exactly that button
        let kinds = [Kind::Datei, Kind::Software, Kind::Url, Kind::Autostart, Kind::Prozess, Kind::Hinweis, Kind::Einstellung, Kind::Treiber, Kind::Erweiterung, Kind::Firewall];
        for k in kinds {
            for path in [gone.to_string_lossy().to_string(), "x".into()] {
                let d = det(k, &path, "REGEL");
                for &a in k.actions() {
                    assert_eq!(confirm_title(&d, a), format!("„{}“ bestätigen?", action_label(&d, a)), "{k:?} {a:?}");
                }
            }
        }
    }

    #[test]
    fn freigabe_is_remembered() {
        let (dir, store, scanner, root) = setup();
        let q = dir.path().join("q");
        std::fs::write(root.join("a.txt"), test_pattern_bytes()).unwrap();
        let o = scan(&store, &scanner, &root, &q);
        assert_eq!(o.new.len(), 1);
        // Nothing happens automatically on first detection.
        assert!(root.join("a.txt").exists());
        assert_eq!(scan(&store, &scanner, &root, &q).already_pending, 1);
        apply_decision(&store, &q, o.new[0].id, Action::Freigabe, None).unwrap();
        // A copy elsewhere with identical content is also covered.
        std::fs::write(root.join("kopie.txt"), test_pattern_bytes()).unwrap();
        let o2 = scan(&store, &scanner, &root, &q);
        assert!(o2.new.is_empty());
        assert_eq!(o2.ignored, 2);
    }

    #[test]
    fn quarantine_is_reapplied_silently_and_restore_revokes() {
        let (dir, store, scanner, root) = setup();
        let q = dir.path().join("q");
        let file = root.join("b.txt");
        std::fs::write(&file, test_pattern_bytes()).unwrap();
        let o = scan(&store, &scanner, &root, &q);
        apply_decision(&store, &q, o.new[0].id, Action::Quarantaene, None).unwrap();
        assert!(!file.exists());
        // Same content appears again -> quarantined silently, no notification.
        std::fs::write(&file, test_pattern_bytes()).unwrap();
        let o2 = scan(&store, &scanner, &root, &q);
        assert!(o2.new.is_empty());
        assert_eq!(o2.auto.len(), 1);
        assert!(o2.auto[0].error.is_none());
        assert!(!file.exists());
        assert_eq!(store.list_quarantine().unwrap().len(), 2);
        // Restore without Freigabe -> decision revoked -> next scan asks again.
        let id = store.list_quarantine().unwrap()[0].id;
        restore_from_quarantine(&store, id, None, false).unwrap();
        assert!(file.exists());
        assert_eq!(scan(&store, &scanner, &root, &q).new.len(), 1);
    }

    fn powershell_finding() -> Finding {
        let windir = std::env::var("SystemRoot").unwrap();
        let ps = format!("{windir}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        Finding {
            path: PathBuf::from("Prozess powershell.exe (PID 1), gestartet von cmd.exe"),
            sha256: "ab".repeat(32),
            size: 0,
            rule_id: "PROZESSARGUMENTE:powershell.exe".into(),
            threat_name: "powershell.exe mit verdächtigen Argumenten".into(),
            category: "Test".into(),
            severity: crate::model::Severity::Hoch,
            engine: "echtzeit".into(),
            kind: Kind::Prozess,
            details: Some(serde_json::json!({ "pid": 1, "ziel": ps, "befehl": "powershell -Command Invoke-Expression x" })),
        }
    }

    #[test]
    fn button_texts_say_what_is_remembered() {
        let store = Store::open_in_memory().unwrap();
        let mut f = powershell_finding();
        f.rule_id = "INFOSTEALER:CHROME".into();
        f.details = Some(serde_json::json!({ "pid": 1, "ziel": r"C:\x\dieb.exe", "gruppe": "chrome" }));
        let crate::store::Upsert::New(d) = store.upsert_pending(&f).unwrap() else { panic!() };
        assert_eq!(action_label(&d, Action::Freigabe), "Freigabe (dieses Programm für Daten von Google Chrome)");
        // A file finding whose file is gone: only close (nothing remembered) or allow.
        let mut g = powershell_finding();
        g.kind = Kind::Datei;
        g.path = r"C:\gibt-es-nicht\clamav-1.tmp".into();
        g.sha256 = "cd".repeat(32);
        let crate::store::Upsert::New(e) = store.upsert_pending(&g).unwrap() else { panic!() };
        assert!(file_missing(&e));
        assert_eq!(allowed_actions(&e), vec![Action::Einmalig, Action::Freigabe]);
        assert!(action_label(&e, Action::Einmalig).starts_with("Gesehen"));
    }

    #[test]
    fn system_binary_process_offers_no_quarantine() {
        let (dir, store, _, _) = setup();
        let q = dir.path().join("q");
        let o = process_findings(&store, &q, &[powershell_finding()]).unwrap();
        let det = &o.new[0];
        let allowed = allowed_actions(det);
        // PID 1 without start time is not (verifiably) running: no "Prozess beenden".
        assert_eq!(allowed, vec![Action::Einmalig, Action::Freigabe]);
        assert_eq!(action_label(det, Action::Einmalig), "Gesehen (Prozess beendet, nichts wird gemerkt)");
        // The running process with matching program and start time: "Prozess beenden" is offered.
        let (exe, start) = crate::realtime::process_path_and_start(std::process::id()).unwrap();
        let mut running = det.clone();
        running.details = Some(serde_json::json!({ "pid": std::process::id(), "ziel": exe.display().to_string(), "startzeit": start }));
        assert!(process_running(&running));
        assert!(allowed_actions(&running).contains(&Action::Beenden));
        // Same ID, other start time (reused ID): not offered.
        running.details = Some(serde_json::json!({ "pid": std::process::id(), "ziel": exe.display().to_string(), "startzeit": start - 1_000_000_000 }));
        assert!(!allowed_actions(&running).contains(&Action::Beenden));
        // Even if requested directly (CLI, service), quarantine is refused.
        assert!(apply_decision(&store, &q, det.id, Action::Quarantaene, None).is_err());
        assert!(apply_decision(&store, &q, det.id, Action::Loeschen, None).is_err());
        assert!(store.list_quarantine().unwrap().is_empty());
    }

    #[test]
    fn self_made_allowance_without_signature_is_ignored() {
        let (dir, store, _, _) = setup();
        let q = dir.path().join("q");
        let f = powershell_finding();
        // A program with user rights writes a "Freigabe" directly into the database.
        let dec = store.set_decision(&f.sha256, &f.rule_id, &f.threat_name, Action::Freigabe, None).unwrap();
        let signer = crate::schutz::Signer::for_test();
        let pk = signer.public();
        assert!(trusted_decision(&store, Some(&pk), &f).unwrap().is_none(), "ohne Unterschrift ungültig");
        assert!(trusted_decision(&store, None, &f).unwrap().is_some(), "ohne Dienst wie bisher");
        // The service signs the user's decision -> valid.
        store.set_decision_signature(dec.id, &signer.sign(&dec)).unwrap();
        assert!(trusted_decision(&store, Some(&pk), &f).unwrap().is_some());
        // Changing the action afterwards (e.g. Quarantäne -> Freigabe) breaks the signature.
        store.set_decision(&f.sha256, &f.rule_id, &f.threat_name, Action::Beenden, None).unwrap();
        assert!(trusted_decision(&store, Some(&pk), &f).unwrap().is_none());
        let _ = q;
    }

    #[test]
    fn boot_drivers_cannot_be_switched_off() {
        let store = Store::open_in_memory().unwrap();
        let mut f = powershell_finding();
        f.kind = Kind::Treiber;
        f.details = Some(serde_json::json!({ "deaktivierbar": false }));
        let crate::store::Upsert::New(d) = store.upsert_pending(&f).unwrap() else { panic!() };
        assert!(!allowed_actions(&d).contains(&Action::Deaktivieren));
        let mut f2 = f.clone();
        f2.sha256 = "ef".repeat(32);
        f2.details = Some(serde_json::json!({ "deaktivierbar": true }));
        let crate::store::Upsert::New(d2) = store.upsert_pending(&f2).unwrap() else { panic!() };
        assert!(allowed_actions(&d2).contains(&Action::Deaktivieren));
        // Outside the service nothing is switched off.
        assert!(crate::treiber::disable(&store, &d2).is_err());
    }

    #[test]
    fn a_rule_can_be_released_for_everything_a_work_program_starts() {
        let (dir, store, _, _) = setup();
        let q = dir.path().join("q");
        let claude = r"C:\Users\f\.local\bin\claude.exe";
        let quiet = |hash: &str, cmd: &str, program: &str| {
            let mut f = powershell_finding();
            f.sha256 = hash.repeat(32);
            f.details = Some(serde_json::json!({ "befehl": cmd, "leise": format!("gestartet von deinem Arbeitsprogramm claude.exe ({program})") }));
            f
        };
        // Two open quiet findings of the same rule (different command lines), one loud one.
        let mut loud = powershell_finding();
        loud.sha256 = "e5".repeat(32);
        let o = process_findings(&store, &q, &[quiet("a1", "eins", claude), quiet("b2", "zwei", claude), loud.clone()]).unwrap();
        assert_eq!(o.new.len(), 3);
        assert!(allowed_actions(&o.new[0]).contains(&Action::Regelfreigabe));
        assert_eq!(action_label(&o.new[0], Action::Regelfreigabe), "Freigabe (diese Regel für alles, was dein Arbeitsprogramm claude.exe startet)");
        assert!(!allowed_actions(&o.new[2]).contains(&Action::Regelfreigabe), "nicht leise: keine Regelfreigabe");
        assert!(apply_decision(&store, &q, o.new[2].id, Action::Regelfreigabe, None).is_err());
        // One click settles both quiet ones; the loud one stays open.
        let r = apply_decision(&store, &q, o.new[0].id, Action::Regelfreigabe, None).unwrap();
        assert_eq!(r.applied.len(), 2);
        let open = store.pending_detections().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, o.new[2].id);
        let decs = store.list_decisions().unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].action, Action::Regelfreigabe);
        assert!(decs[0].threat_name.contains("claude.exe") && decs[0].threat_name.contains("PROZESSARGUMENTE:powershell.exe"), "{}", decs[0].threat_name);
        // A new command line of the same rule from the same program: no open finding any more.
        let o = process_findings(&store, &q, &[quiet("c3", "drei", claude)]).unwrap();
        assert!(o.new.is_empty());
        assert_eq!(o.ignored, 1);
        // Upper/lower case of the path does not matter.
        assert!(process_findings(&store, &q, &[quiet("c4", "vier", &claude.to_uppercase())]).unwrap().new.is_empty());
        // Another work program, another rule, a critical finding, a loud one: reported as before.
        assert_eq!(process_findings(&store, &q, &[quiet("d5", "fuenf", r"C:\Tools\anderes.exe")]).unwrap().new.len(), 1);
        let mut other_rule = quiet("d6", "sechs", claude);
        other_rule.rule_id = "SIGMA:x".into();
        assert_eq!(process_findings(&store, &q, &[other_rule]).unwrap().new.len(), 1);
        let mut critical = quiet("d7", "sieben", claude);
        critical.severity = crate::model::Severity::Kritisch;
        let o = process_findings(&store, &q, &[critical]).unwrap();
        assert_eq!(o.new.len(), 1);
        assert!(!allowed_actions(&o.new[0]).contains(&Action::Regelfreigabe), "kritisch: nie");
        let mut loud2 = powershell_finding();
        loud2.sha256 = "d8".repeat(32);
        assert_eq!(process_findings(&store, &q, &[loud2]).unwrap().new.len(), 1);
        // Revoked: the next finding is open again.
        store.revoke_decision(decs[0].id).unwrap();
        assert_eq!(process_findings(&store, &q, &[quiet("c9", "neun", claude)]).unwrap().new.len(), 1);
        // The reason text is read back exactly.
        let d = serde_json::json!({ "leise": format!("gestartet von deinem Arbeitsprogramm claude.exe ({claude})") });
        assert_eq!(crate::arbeitsordner::work_program(Some(&d)), Some(("claude.exe".to_string(), claude.to_string())));
        assert_eq!(crate::arbeitsordner::work_program(Some(&serde_json::json!({ "leise": "Programm bzw. Skript liegt im Arbeitsordner X" }))), None);
    }

    #[test]
    fn allow_once_remembers_nothing() {
        let (dir, store, _, _) = setup();
        let q = dir.path().join("q");
        let f = powershell_finding();
        let o = process_findings(&store, &q, std::slice::from_ref(&f)).unwrap();
        let r = apply_decision(&store, &q, o.new[0].id, Action::Einmalig, None).unwrap();
        assert_eq!(r.action, Action::Einmalig);
        assert!(store.list_decisions().unwrap().is_empty(), "nichts gemerkt");
        // The same finding later is reported again.
        assert_eq!(process_findings(&store, &q, &[f]).unwrap().new.len(), 1);
    }

    #[test]
    fn delete_decision() {
        let (dir, store, scanner, root) = setup();
        let q = dir.path().join("q");
        let file = root.join("c.txt");
        std::fs::write(&file, test_pattern_bytes()).unwrap();
        let o = scan(&store, &scanner, &root, &q);
        let r = apply_decision(&store, &q, o.new[0].id, Action::Loeschen, Some("weg")).unwrap();
        assert_eq!(r.applied.len(), 1);
        assert!(!file.exists());
        assert!(apply_decision(&store, &q, o.new[0].id, Action::Freigabe, None).is_err());
    }

    #[test]
    fn subject_names_the_file_or_program_and_the_update() {
        let leise = serde_json::json!({ "leise": "beim Update von AusweisApp (von dir in K9 gestartet)" });
        let mut msi = det_of(1, Kind::Datei, "CLAMAV:PUA.Win.Packer.Exesplitter-8", "a", Some(leise.clone()));
        msi.path = r"C:\Users\f\AppData\Local\Temp\WinGet\Governikus.AusweisApp.2.6.3\AusweisApp-2.6.3-AMD64.msi".into();
        assert_eq!(subject(&msi).as_deref(), Some("Installationsdatei AusweisApp-2.6.3-AMD64.msi zum Update von AusweisApp"));
        msi.details = None;
        assert_eq!(subject(&msi).as_deref(), Some("Datei AusweisApp-2.6.3-AMD64.msi, aus dem winget-Paket Governikus.AusweisApp.2.6.3"));
        msi.path = r"C:\Users\f\Downloads\rechnung.js".into();
        assert_eq!(subject(&msi).as_deref(), Some("Datei rechnung.js"));
        let inst = serde_json::json!({ "ziel": r"C:\Users\f\AppData\Local\Temp\7zS80C7CE4E\installer.exe", "signierer": "Opera Norway AS", "leise": "beim Update von Opera Stable 140.0 (von dir in K9 gestartet)" });
        assert_eq!(subject(&det_of(2, Kind::Prozess, "INFOSTEALER:OPERA", "b", Some(inst))).as_deref(), Some("Programm installer.exe, signiert von Opera Norway AS, gestartet beim Update von Opera Stable 140.0"));
        let dieb = serde_json::json!({ "ziel": r"C:\Users\f\Downloads\dieb.exe", "signierer": null });
        assert_eq!(subject(&det_of(3, Kind::Prozess, "INFOSTEALER:CHROME", "c", Some(dieb))).as_deref(), Some("Programm dieb.exe, ohne gültige Signatur"));
        let unsure = serde_json::json!({ "ziel": "Programm nicht sicher zuzuordnen (PID 5)" });
        assert_eq!(subject(&det_of(4, Kind::Prozess, "INFOSTEALER:EDGE", "d", Some(unsure))), None, "kein Programmpfad: nichts erfinden");
        let auto = serde_json::json!({ "leise": "beim Update von Opera Stable (von dir in K9 gestartet)" });
        assert_eq!(subject(&det_of(5, Kind::Autostart, "AUTOSTART:NEU", "e", Some(auto))).as_deref(), Some("entstanden beim Update von Opera Stable"));
        assert_eq!(subject(&det_of(6, Kind::Autostart, "AUTOSTART:NEU", "f", None)), None);
    }

    fn det_of(id: i64, kind: Kind, rule: &str, sha: &str, details: Option<serde_json::Value>) -> Detection {
        Detection {
            id,
            path: format!("p{id}"),
            sha256: sha.into(),
            rule_id: rule.into(),
            threat_name: "t".into(),
            category: "c".into(),
            severity: crate::model::Severity::Mittel,
            engine: "e".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            status: DetectionStatus::Offen,
            action: None,
            kind,
            details,
        }
    }

    #[test]
    fn common_actions_of_a_selection() {
        let gone = crate::test_tmp().join("gibt-es-nicht-sammel.bin").to_string_lossy().to_string();
        let mut a = det_of(1, Kind::Datei, "R", "aa", None);
        a.path = gone.clone();
        let mut b = det_of(2, Kind::Datei, "R", "bb", None);
        b.path = gone;
        // both files gone: "Gesehen (Datei nicht mehr vorhanden …)" and Freigabe, same labels
        let c = common_actions(&[a.clone(), b.clone()]);
        assert_eq!(c.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(), ["Gesehen (Datei nicht mehr vorhanden, nichts wird gemerkt)", "Freigabe"]);
        // a file and an ended process: both offer Einmalig, but with different labels -> neutral text
        let p = det_of(3, Kind::Prozess, "PROZESSARGUMENTE:powershell.exe", "cc", None);
        let c = common_actions(&[a.clone(), p.clone()]);
        assert!(c.iter().any(|(act, l)| *act == Action::Einmalig && l == neutral_label(Action::Einmalig)), "{c:?}");
        // a firewall rule and a file have nothing in common except Freigabe
        let fw = det_of(4, Kind::Firewall, crate::eingang::RULE_ID, "dd", Some(serde_json::json!({"anzahl": 1})));
        let c = common_actions(&[a, fw]);
        assert_eq!(c.iter().map(|(a, _)| *a).collect::<Vec<_>>(), [Action::Freigabe]);
        assert!(common_actions(&[]).is_empty());
    }

    #[test]
    fn same_group_is_rule_plus_content_or_program() {
        let p1 = det_of(1, Kind::Prozess, "INFOSTEALER:CHROME", "x1", Some(serde_json::json!({"ziel": "C:\\A\\Acrobat.exe"})));
        let p2 = det_of(2, Kind::Prozess, "INFOSTEALER:CHROME", "x2", Some(serde_json::json!({"ziel": "c:\\a\\acrobat.exe"})));
        let p3 = det_of(3, Kind::Prozess, "INFOSTEALER:STEAM", "x1", Some(serde_json::json!({"ziel": "C:\\A\\Acrobat.exe"})));
        assert_eq!(same_group(&p1), same_group(&p2));
        assert_ne!(same_group(&p1), same_group(&p3));
        let f1 = det_of(4, Kind::Datei, "R", "aa", None);
        let f2 = det_of(5, Kind::Datei, "R", "aa", None);
        let f3 = det_of(6, Kind::Datei, "R", "bb", None);
        assert_eq!(same_group(&f1), same_group(&f2));
        assert_ne!(same_group(&f1), same_group(&f3));
    }

    #[test]
    fn batch_runs_each_finding_and_reports_each_result() {
        let (dir, store, scanner, root) = setup();
        let q = dir.path().join("q");
        for n in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(root.join(n), test_pattern_bytes()).unwrap();
        }
        std::fs::write(root.join("d.txt"), [test_pattern_bytes(), b"x".to_vec()].concat()).unwrap();
        let o = scan(&store, &scanner, &root, &q);
        let ids: Vec<i64> = o.new.iter().map(|d| d.id).collect();
        assert_eq!(ids.len(), 4);
        // forbidden action for one of them: rejected as a whole, nothing happened
        assert!(apply_batch(&store, &q, &ids, Action::Beenden, None).is_err());
        assert_eq!(store.pending_detections().unwrap().len(), 4);
        // one file changes meanwhile: that one fails ("verändert"), the others are quarantined
        let changed = store.detection(ids[3]).unwrap().unwrap();
        std::fs::write(&changed.path, b"inzwischen anders").unwrap();
        let r = apply_batch(&store, &q, &ids, Action::Quarantaene, None).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r.iter().filter(|i| i.ok).count(), 3, "{r:?}");
        let s = batch_summary(&r);
        assert!(s.starts_with("3 erledigt, 1 fehlgeschlagen"), "{s}");
        // too many at once
        let many: Vec<Detection> = (0..=BATCH_MAX as i64).map(|i| det_of(i, Kind::Datei, "R", "aa", None)).collect();
        assert!(check_batch(&many, Action::Freigabe).is_err());
        assert!(check_batch(&[det_of(1, Kind::Einstellung, "E", "aa", None)], Action::Freigabe).is_err(), "Einstellungen einzeln");
    }

    #[test]
    fn identical_findings_in_one_batch_count_as_done() {
        let (dir, store, scanner, root) = setup();
        let q = dir.path().join("q");
        std::fs::write(root.join("a.txt"), test_pattern_bytes()).unwrap();
        std::fs::write(root.join("b.txt"), test_pattern_bytes()).unwrap();
        let o = scan(&store, &scanner, &root, &q);
        let ids: Vec<i64> = o.new.iter().map(|d| d.id).collect();
        // Freigabe for the first also settles the identical second one
        let r = apply_batch(&store, &q, &ids, Action::Freigabe, None).unwrap();
        assert!(r.iter().all(|i| i.ok), "{r:?}");
        assert!(store.pending_detections().unwrap().is_empty());
    }
}
