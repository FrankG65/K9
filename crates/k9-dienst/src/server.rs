//! The two named pipes: findings to the agent, requests from agent/k9.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use k9_core::dienst::{self, Message, Pipe, SecDesc, PIPE_BEFEHLE, PIPE_MELDUNGEN, PROTOCOL};
use k9_core::model::{Action, DetectionStatus, Kind};
use k9_core::{pipeline, realtime as rt};

use crate::Svc;

fn client_path(p: &Pipe) -> Option<PathBuf> {
    p.client_pid().and_then(rt::process_path)
}

/// Service -> agent. Only the installed agent program may connect.
pub fn findings_server(svc: Arc<Svc>, sd: Arc<SecDesc>) {
    loop {
        let pipe = match Pipe::serve(PIPE_MELDUNGEN, &sd) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Meldungs-Pipe: {e:#}");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let client = client_path(&pipe);
        if !client.as_deref().is_some_and(|c| svc.is_agent(c)) {
            tracing::warn!("Meldungs-Pipe: fremdes Programm abgewiesen ({})", client.map(|c| c.display().to_string()).unwrap_or_else(|| "?".into()));
            pipe.disconnect();
            continue;
        }
        tracing::info!("Agent verbunden");
        loop {
            match svc.next_message(Duration::from_secs(10)) {
                Some(msg) => {
                    if pipe.write_msg(&msg).is_err() {
                        svc.requeue(msg);
                        break;
                    }
                    svc.delivered(&msg);
                }
                None => {
                    if pipe.write_msg(&Message::Ping { v: PROTOCOL }).is_err() {
                        break;
                    }
                }
            }
        }
        tracing::info!("Agent getrennt");
        pipe.disconnect();
    }
}

/// Agent/k9 -> service: one request, one answer per connection.
pub fn command_server(svc: Arc<Svc>, sd: Arc<SecDesc>) {
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    loop {
        let pipe = match Pipe::serve(PIPE_BEFEHLE, &sd) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Befehls-Pipe: {e:#}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        if ACTIVE.load(Ordering::Relaxed) >= 3 {
            pipe.disconnect();
            continue;
        }
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        let s = svc.clone();
        crate::spawn("vs-befehl", move || {
            let answer = match pipe.read_msg() {
                // Every request runs with the rights of the calling user.
                Ok(msg) => match pipe.client_token() {
                    Some(tok) => {
                        let client = client_path(&pipe);
                        let r = k9_core::schutz::with_user(tok, || handle(&s, &msg, client));
                        // SAFETY: token from client_token.
                        unsafe {
                            let _ = windows::Win32::Foundation::CloseHandle(tok);
                        }
                        r.unwrap_or_else(|e| Message::Ergebnis { v: PROTOCOL, ok: false, text: format!("{e:#}") })
                    }
                    None => Message::Ergebnis { v: PROTOCOL, ok: false, text: "Aufrufer nicht prüfbar".into() },
                },
                Err(e) => Message::Ergebnis { v: PROTOCOL, ok: false, text: format!("Ungültige Anfrage: {e:#}") },
            };
            let _ = pipe.write_msg(&answer);
            pipe.disconnect();
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn known_caller(svc: &Svc, client: &Option<PathBuf>, caller: &str) -> Result<()> {
    if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
        bail!("Nur über Agent oder k9 aus dem Programmordner (Aufrufer: {caller})");
    }
    Ok(())
}

/// Decisions that make the protection weaker need the confirmation window.
/// Ends a running pause of the agent watch; true if one was active.
pub fn end_pause(pause: &std::sync::Mutex<Option<(Instant, Instant)>>) -> bool {
    let mut p = pause.lock().unwrap_or_else(|e| e.into_inner());
    let active = p.is_some_and(|(until, _)| Instant::now() < until);
    *p = None;
    active
}

/// Title of the confirmation for changing a stored service key (None = no confirmation).
pub fn secret_change_confirmation(exists: bool, new_value: bool) -> Option<&'static str> {
    match (exists, new_value) {
        (false, _) => None,
        (true, true) => Some(k9_core::t!("Schlüssel ersetzen?", "Replace key?")),
        (true, false) => Some(k9_core::t!("Schlüssel löschen?", "Delete key?")),
    }
}

/// "Änderung übernehmen" for a weakened setting: carried out by the service itself
/// (after the confirmation window), never by the generic decision code.
fn accepts_settings_change(det: &k9_core::model::Detection, action: Action) -> bool {
    det.kind == Kind::Einstellung && action == Action::Freigabe
}

fn weakens(det: &k9_core::model::Detection, action: Action) -> bool {
    if det.kind == Kind::Hinweis || (det.kind == Kind::Einstellung && action == Action::Gesehen) {
        return false; // a notice is only acknowledged; rejecting a weaker setting is stronger
    }
    action.is_passive()
}

/// What exactly is confirmed – only from the service's own database.
fn describe(det: &k9_core::model::Detection, action: Action) -> String {
    k9_core::tf!(
        "Entscheidung: {}\nBedrohung: {}\nFundort: {}\nRegel: {}\nSchweregrad: {}", "Decision: {}\nThreat: {}\nLocation: {}\nRule: {}\nSeverity: {}",
        pipeline::action_label(det, action),
        det.threat_name,
        det.path,
        det.rule_id,
        det.severity.label()
    )
}

fn ok(text: impl Into<String>) -> Message {
    Message::Ergebnis { v: PROTOCOL, ok: true, text: text.into() }
}

fn handle(svc: &Arc<Svc>, msg: &Message, client: Option<PathBuf>) -> Result<Message> {
    dienst::validate(msg)?;
    let caller = client.as_ref().map(|c| c.display().to_string()).unwrap_or_else(|| "unbekannt".into());
    match msg {
        Message::Status { .. } => Ok(Message::StatusAntwort {
            v: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").into(),
            etw_prozesse: svc.etw_processes.load(Ordering::Relaxed),
            etw_dns: svc.etw_dns.load(Ordering::Relaxed),
            agent_wache: svc.watchdog.load(Ordering::Relaxed),
            schattenkopien: svc.vss_status.lock().unwrap().clone(),
            gesundheit: svc.gesundheit.clone(),
        }),
        Message::Spielmodus { aktiv, .. } => {
            // Only the installed agent: another program could otherwise delay updates.
            if !client.as_deref().is_some_and(|c| svc.is_agent(c)) {
                bail!("Nur der K9-Agent meldet den Spielmodus");
            }
            if svc.gaming.report(*aktiv, Instant::now()) {
                tracing::info!("Spielmodus vom Agent: {}", if *aktiv { "Spiel läuft – Aktualisierungen und Prüfungen warten" } else { "beendet" });
            }
            Ok(ok(if *aktiv { "Spielmodus gemeldet" } else { "Spielmodus beendet" }))
        }
        Message::Leerlauf { minuten, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_agent(c)) {
                bail!("Nur der K9-Agent meldet den Leerlauf");
            }
            *svc.user_idle.lock().unwrap() = (*minuten >= 15).then(Instant::now);
            Ok(ok("Leerlauf gemeldet"))
        }
        Message::AgentStopp { minuten, .. } => {
            crate::bestaetigung::confirm(
                svc,
                "K9-Agent pausieren?",
                &format!("Der K9-Agent soll für {minuten} Minuten beendet werden.\nDer Echtzeitschutz ist in dieser Zeit eingeschränkt.\nAngefordert von: {caller}"),
            )?;
            *svc.agent_pause.lock().unwrap() = Some((Instant::now() + Duration::from_secs(u64::from(*minuten) * 60), Instant::now()));
            tracing::info!("Agent-Pause {minuten} Minuten angefordert von {caller}");
            let known = client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c));
            if !known {
                svc.report(&crate::wache::notice(
                    "SELBSTSCHUTZ:AGENT-PAUSE",
                    k9_core::t!("Ein unbekanntes Programm hat den K9-Agent pausiert", "An unknown program paused the K9 agent"),
                    &k9_core::tf!("Programm: {caller}. Wenn du das nicht warst, starte einen vollständigen Scan.", "Program: {caller}. If that was not you, start a full scan."),
                ));
            }
            Ok(ok(format!("Agent-Wache pausiert für {minuten} Minuten")))
        }
        Message::PauseBeenden { .. } => {
            // Ending a pause only strengthens the protection: no confirmation needed.
            let ended = end_pause(&svc.agent_pause);
            if ended {
                tracing::info!("Agent-Pause vorzeitig beendet von {caller}");
            }
            Ok(ok(if ended { "beendet" } else { "keine" }))
        }
        Message::FirewallEntfernen { .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c)) {
                bail!("Nur über k9 (Aufrufer: {caller})");
            }
            crate::bestaetigung::confirm(
                svc,
                k9_core::t!("Firewall-Sperre vorübergehend entfernen?", "Remove the firewall block temporarily?"),
                k9_core::t!("Alle K9-Regeln „Botnetz-Server gesperrt“ werden entfernt und bis zur nächsten regulären Erneuerung \
                 (täglich, neue ThreatFox-Daten oder Neustart des Dienstes) nicht wiederhergestellt.", "All K9 rules “Botnetz-Server gesperrt” are removed and not restored until the next regular renewal \
                 (daily, new ThreatFox data or a restart of the service)."),
            )?;
            svc.fw_pause.store(true, Ordering::SeqCst);
            let n = k9_core::firewall::remove_own_rules()?;
            tracing::info!("Firewall-Sperre: {n} Regel(n) auf Wunsch entfernt (k9 firewall entfernen, Aufrufer {caller}) – keine Wiederherstellung bis zur nächsten Erneuerung");
            Ok(ok(format!("{n} Regel(n) entfernt")))
        }
        Message::Signieren { entscheidung_id, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
                bail!("Unterschrift nur für Agent oder k9 (Aufrufer: {caller})");
            }
            let signer = svc.signer.as_ref().context("Dienst-Schlüssel nicht verfügbar")?;
            let store = svc.app.store()?;
            let d = store.decision_by_id(*entscheidung_id)?.context("Entscheidung existiert nicht")?;
            store.set_decision_signature(d.id, &signer.sign(&d))?;
            tracing::info!("Entscheidung #{} („{}“, {}) unterschrieben (Aufrufer {caller})", d.id, d.action.label(), d.threat_name);
            Ok(ok("unterschrieben"))
        }
        Message::Ausfuehren { detection_id, aktion, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
                bail!("Aktionen nur über Agent oder k9 (Aufrufer: {caller})");
            }
            let store = svc.app.store()?;
            let det = store.detection(*detection_id)?.context("Erkennung existiert nicht")?;
            if det.status != DetectionStatus::Offen {
                // A remembered (signed) decision applied automatically is fine too.
                let signed = k9_core::schutz::public_key().and_then(|pk| {
                    store.find_decision(&det.sha256, &det.rule_id).ok().flatten().filter(|d| d.action == *aktion && k9_core::schutz::verify(&pk, d))
                });
                if signed.is_none() {
                    bail!("Erkennung ist bereits entschieden");
                }
            }
            if !pipeline::allowed_actions(&det).contains(aktion) {
                bail!("Aktion „{}“ ist für diesen Fund nicht erlaubt", aktion.label());
            }
            pipeline::execute_action(&store, &svc.app.paths.quarantine_dir(), &det, *aktion)?;
            tracing::info!("Aktion „{}“ für Erkennung {detection_id} ausgeführt (Aufrufer {caller})", aktion.label());
            Ok(ok("ausgeführt"))
        }
        Message::QuellenAktualisieren { quelle, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
                bail!("Nur über Agent oder k9 (Aufrufer: {caller})");
            }
            let only = match quelle.as_deref() {
                Some(q) => Some(k9_core::sources::SourceId::parse(q).with_context(|| format!("Unbekannte Quelle '{q}'"))?),
                None => None,
            };
            Ok(ok(crate::quellen::start_update(svc, only, true)))
        }
        Message::GeheimnisSetzen { name, wert, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c)) {
                bail!("Schlüssel nur über k9 (Aufrufer: {caller})");
            }
            // The first key needs no confirmation; replacing or deleting one does (an invalid key
            // would silently switch the lookup off).
            let exists = k9_core::schutz::service_secret_names().iter().any(|n| n == name);
            if let Some(title) = secret_change_confirmation(exists, wert.is_some()) {
                crate::bestaetigung::confirm(svc, title, &k9_core::tf!("Schlüssel: {name}\nDer bisher gespeicherte Schlüssel wird {}.", "Key: {name}\nThe key stored so far will be {}.", if wert.is_some() { k9_core::t!("ersetzt", "replaced") } else { k9_core::t!("gelöscht", "deleted") }))?;
            }
            k9_core::schutz::service_secret_set(name, wert.as_deref())?;
            tracing::info!("Schlüssel {name} {} (Aufrufer {caller})", if wert.is_some() { "gespeichert" } else { "gelöscht" });
            Ok(ok("gespeichert"))
        }
        Message::Geheimnisse { .. } => Ok(ok(k9_core::schutz::service_secret_names().join(","))),
        Message::Funde { seq, funde, .. } => {
            known_caller(svc, &client, &caller)?;
            let store = svc.app.store()?;
            let gap = store.check_seq(*seq)?;
            if gap > 0 {
                tracing::warn!("{gap} Fundmeldung(en) des Agents fehlen (Nummer {seq})");
                svc.report(&crate::wache::notice(
                    "SELBSTSCHUTZ:FUNDE-FEHLEN",
                    k9_core::t!("Zwischengespeicherte Funde sind verschwunden", "Buffered findings have disappeared"),
                    &k9_core::tf!(
                        "{gap} Meldung(en) mit Funden, die der Agent zwischengespeichert hatte, kamen nie beim Dienst an. \
                         Ein Programm könnte sie gelöscht haben, um einen Fund zu verbergen. Bitte einen vollständigen Scan starten.", "{gap} message(s) with findings that the agent had buffered never arrived at the service. \
                         A program might have deleted them to hide a finding. Please start a full scan."
                    ),
                ));
            }
            let findings: Vec<k9_core::Finding> = funde.iter().cloned().map(|f| f.into_plain()).collect();
            let outcome = pipeline::process_findings(&store, &svc.app.paths.quarantine_dir(), &findings)?;
            Ok(ok(pipeline::outcome_summary(&outcome)))
        }
        Message::Entscheiden { detection_id, aktion, notiz, .. } => {
            known_caller(svc, &client, &caller)?;
            let store = svc.app.store()?;
            let det = store.detection(*detection_id)?.context("Erkennung existiert nicht")?;
            // Switching a driver off can stop a program or device: confirm as well.
            // Removing a firewall rule can stop a program from working: confirm as well.
            if weakens(&det, *aktion) || (det.kind == Kind::Treiber && *aktion == Action::Deaktivieren) || (det.kind == Kind::Firewall && *aktion == Action::Loeschen) {
                crate::bestaetigung::confirm(svc, &pipeline::confirm_title(&det, *aktion), &describe(&det, *aktion))?;
            }
            if accepts_settings_change(&det, *aktion) {
                // Meldefenster, Dashboard and k9: take the reported config.toml values (only
                // if the file still has exactly them) and close the finding.
                if det.status != DetectionStatus::Offen {
                    bail!("Erkennung ist bereits entschieden");
                }
                crate::einstellungen::confirm(svc, &det.sha256)?;
                store.mark_detection(det.id, DetectionStatus::Entschieden, Some(*aktion))?;
                store.log_event("info", &format!("Geänderte Sicherheitseinstellung übernommen: {}", det.path))?;
                tracing::info!("Geänderte Sicherheitseinstellung übernommen, Erkennung {detection_id} (Aufrufer {caller})");
                let detection = store.detection(det.id)?.context("Erkennung verschwunden")?;
                let r = pipeline::DecisionResult { detection, action: *aktion, applied: vec![det.path.clone()], missing: Vec::new() };
                return Ok(ok(pipeline::decision_summary(&r)));
            }
            let label = pipeline::action_label(&det, *aktion);
            let r = match pipeline::apply_decision(&store, &svc.app.paths.quarantine_dir(), *detection_id, *aktion, notiz.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Entscheidung „{label}“ für Erkennung {detection_id} fehlgeschlagen ({}): {e:#}", det.path);
                    return Err(e);
                }
            };
            tracing::info!("Entscheidung „{label}“ für Erkennung {detection_id} (Aufrufer {caller})");
            Ok(ok(pipeline::decision_summary(&r)))
        }
        Message::EntscheidenMehrere { ids, aktion, notiz, .. } => {
            known_caller(svc, &client, &caller)?;
            let store = svc.app.store()?;
            let mut dets = Vec::new();
            for id in ids {
                dets.push(store.detection(*id)?.with_context(|| format!("Meldung {id} existiert nicht"))?);
            }
            let open: Vec<_> = dets.iter().filter(|d| d.status == DetectionStatus::Offen).cloned().collect();
            // Same rules as a single click: every finding must allow exactly this action.
            pipeline::check_batch(&open, *aktion)?;
            let needs_confirm = open.iter().any(|d| {
                weakens(d, *aktion) || (d.kind == Kind::Treiber && *aktion == Action::Deaktivieren) || (d.kind == Kind::Firewall && *aktion == Action::Loeschen)
            });
            if needs_confirm {
                // One window for the whole batch, listing every finding.
                let label = pipeline::common_actions(&open).into_iter().find(|(a, _)| a == aktion).map(|(_, l)| l).unwrap_or_else(|| aktion.label().into());
                let mut text = k9_core::tf!("Entscheidung: {label}\nfür {} Meldungen:\n", "Decision: {label}\nfor {} findings:\n", open.len());
                for d in open.iter().take(25) {
                    text.push_str(&format!("#{} {} – {}\n", d.id, d.threat_name, d.path));
                }
                if open.len() > 25 {
                    text.push_str(&k9_core::tf!("… und {} weitere\n", "… and {} more\n", open.len() - 25));
                }
                crate::bestaetigung::confirm(svc, &k9_core::tf!("„{label}“ für {} Meldungen bestätigen?", "Confirm “{label}” for {} findings?", open.len()), &text)?;
            }
            let items = pipeline::apply_batch(&store, &svc.app.paths.quarantine_dir(), ids, *aktion, notiz.as_deref())?;
            for i in &items {
                if i.ok {
                    tracing::info!("Entscheidung „{}“ für Erkennung {} (Sammelbearbeitung, Aufrufer {caller}): {}", aktion.label(), i.id, i.text);
                } else {
                    tracing::warn!("Entscheidung „{}“ für Erkennung {} fehlgeschlagen (Sammelbearbeitung): {}", aktion.label(), i.id, i.text);
                }
            }
            Ok(ok(serde_json::to_string(&items)?))
        }
        Message::EntscheidungSpeichern { sha256, rule_id, threat_name, aktion, notiz, .. } => {
            known_caller(svc, &client, &caller)?;
            if aktion.is_passive() && !rule_id.starts_with("SELBSTSCHUTZ:") {
                crate::bestaetigung::confirm(
                    svc,
                    k9_core::t!("Freigabe bestätigen?", "Confirm release?"),
                    &k9_core::tf!("Entscheidung: {}\nBedrohung: {threat_name}\nRegel: {rule_id}\nDieser Fund wird danach nicht mehr gemeldet.", "Decision: {}\nThreat: {threat_name}\nRule: {rule_id}\nThis finding will not be reported again afterwards.", aktion.label()),
                )?;
            }
            let store = svc.app.store()?;
            let d = store.set_decision(sha256, rule_id, threat_name, *aktion, notiz.as_deref())?;
            k9_core::schutz::request_signature(&store, d.id)?;
            Ok(ok(d.id.to_string()))
        }
        Message::EntscheidungWiderrufen { id, sha256, rule_id, .. } => {
            known_caller(svc, &client, &caller)?;
            let store = svc.app.store()?;
            match (id, sha256, rule_id) {
                (Some(id), _, _) => {
                    store.revoke_decision(*id)?;
                }
                (None, Some(s), Some(r)) => {
                    store.revoke_decision_by_fingerprint(s, r)?;
                }
                _ => bail!("Ungültiger Widerruf"),
            }
            Ok(ok("widerrufen"))
        }
        Message::Reaktivieren { id, .. } => {
            known_caller(svc, &client, &caller)?;
            let store = svc.app.store()?;
            let label = store.disabled_entry(*id)?.map(|(_, l, _)| l).context("Eintrag nicht gefunden oder bereits reaktiviert")?;
            crate::bestaetigung::confirm(svc, "Autostart wieder einschalten?", &format!("Eintrag: {label}\nDer Eintrag startet danach wieder mit Windows."))?;
            Ok(ok(k9_core::autostart::restore(&store, *id)?))
        }
        Message::Ereignis { stufe, text, .. } => {
            known_caller(svc, &client, &caller)?;
            svc.app.store()?.log_event(stufe, text)?;
            Ok(ok("protokolliert"))
        }
        Message::Wiederherstellen { quarantaene_id, freigeben, ziel, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
                bail!("Wiederherstellen nur über Agent oder k9 (Aufrufer: {caller})");
            }
            let store = svc.app.store()?;
            let entry = store.quarantine_entry(*quarantaene_id)?.context("Quarantäne-Eintrag existiert nicht")?;
            crate::bestaetigung::confirm(
                svc,
                k9_core::t!("Aus der Quarantäne wiederherstellen?", "Restore from quarantine?"),
                &k9_core::tf!(
                    "Datei: {}\nBedrohung: {}\nZiel: {}{}", "File: {}\nThreat: {}\nTarget: {}{}",
                    entry.original_path,
                    entry.threat_name,
                    ziel.as_deref().unwrap_or(&entry.original_path),
                    if *freigeben { k9_core::t!("\nDie Datei wird außerdem dauerhaft freigegeben.", "\nThe file is also allowed permanently.") } else { "" }
                ),
            )?;
            let target = ziel.as_deref().map(std::path::Path::new);
            let dest = pipeline::restore_from_quarantine(&store, *quarantaene_id, target, *freigeben)?;
            tracing::info!("Quarantäne #{quarantaene_id} wiederhergestellt nach {} (Aufrufer {caller})", dest.display());
            Ok(ok(dest.display().to_string()))
        }
        Message::Aktion { token, detection_id, aktion, .. } => {
            if !client.as_deref().is_some_and(|c| svc.is_k9(c) || svc.is_agent(c)) {
                bail!("Aktionen nur über Agent oder k9 (Aufrufer: {caller})");
            }
            act(svc, token, *detection_id, *aktion)?;
            tracing::info!("Aktion „{}“ für Erkennung {detection_id} ausgeführt (Aufrufer {caller})", aktion.label());
            Ok(ok("ausgeführt"))
        }
        _ => bail!("Unerwartete Anfrage"),
    }
}

/// Carries out the user's decision for a finding of this service.
fn act(svc: &Svc, token: &str, detection_id: i64, action: Action) -> Result<()> {
    let Some(own) = svc.own_finding(token) else {
        bail!("Fund ist dem Dienst nicht (mehr) bekannt – z. B. nach einem Neustart des Dienstes");
    };
    let store = svc.app.store()?;
    let mut det = store.detection(detection_id)?.context("Erkennung existiert nicht")?;
    let det_token = det.details.as_ref().and_then(|d| d["dienst_token"].as_str().map(str::to_string));
    if det_token.as_deref() != Some(token) {
        bail!("Erkennung gehört nicht zu diesem Fund");
    }
    if det.status != DetectionStatus::Offen {
        bail!("Erkennung ist bereits entschieden");
    }
    // The database row may have been changed: only the service's own values count.
    if det.sha256 != own.sha256 || det.rule_id != own.rule_id || det.kind != own.kind {
        bail!("Erkennung passt nicht zum gemeldeten Fund");
    }
    det.details = own.details.clone();
    det.path = own.path.clone();
    if det.kind == Kind::Einstellung && action == Action::Freigabe {
        crate::bestaetigung::confirm(svc, k9_core::t!("Geänderte Einstellung übernehmen?", "Accept the changed setting?"), &describe(&det, action))?;
        return crate::einstellungen::confirm(svc, &det.sha256);
    }
    if action.is_passive() || !pipeline::allowed_actions(&det).contains(&action) {
        bail!("Aktion „{}“ ist für diesen Fund nicht erlaubt", action.label());
    }
    // SYSTEM rights only to end a process the service saw starting itself
    // (e.g. an elevated one); the exe check in terminate_process stays.
    if det.kind == Kind::Prozess && action == Action::Beenden {
        return k9_core::schutz::as_system(|| {
            let targets = pipeline::process_targets(&det.details.clone().unwrap_or_default());
            let (pid, exe, start) = targets.into_iter().next().context("Keine Prozess-ID")?;
            k9_core::realtime::terminate_process_privileged(pid, exe.as_deref(), start)
        });
    }
    // A process frozen by the service may run with higher rights: resume it with SYSTEM rights.
    if det.kind == Kind::Prozess && matches!(action, Action::Freigabe | Action::Einmalig | Action::Regelfreigabe) {
        let pids = pipeline::suspended_pids(&det);
        if !pids.is_empty() {
            k9_core::schutz::as_system(|| {
                for pid in &pids {
                    k9_core::realtime::resume_process(*pid);
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
    }
    pipeline::execute_action(&store, &svc.app.paths.quarantine_dir(), &det, action)
}

#[cfg(test)]
mod tests {
    use super::{accepts_settings_change, secret_change_confirmation, weakens};
    use k9_core::model::{Action, Detection, DetectionStatus, Kind, Severity};

    fn det(kind: Kind) -> Detection {
        Detection {
            id: 1,
            path: "config.toml: VirusTotal-Abfrage: aus".into(),
            sha256: "ab".into(),
            rule_id: "EINSTELLUNG:SICHERHEIT".into(),
            threat_name: "t".into(),
            category: "Selbstschutz".into(),
            severity: Severity::Hoch,
            engine: "dienst".into(),
            first_seen: "x".into(),
            last_seen: "x".into(),
            status: DetectionStatus::Offen,
            action: None,
            kind,
            details: None,
        }
    }

    #[test]
    fn accepting_a_settings_change_is_confirmed_and_done_by_the_service() {
        let d = det(Kind::Einstellung);
        // Needs the confirmation window and is not left to the generic code (which refuses it).
        assert!(weakens(&d, Action::Freigabe));
        assert!(accepts_settings_change(&d, Action::Freigabe));
        // "Gesehen" keeps the safer values: no confirmation, generic path.
        assert!(!weakens(&d, Action::Gesehen));
        assert!(!accepts_settings_change(&d, Action::Gesehen));
        assert!(!accepts_settings_change(&det(Kind::Datei), Action::Freigabe));
    }

    #[test]
    fn a_pause_can_be_ended_early_and_ending_twice_reports_no_pause() {
        use std::time::{Duration, Instant};
        let pause = std::sync::Mutex::new(Some((Instant::now() + Duration::from_secs(600), Instant::now())));
        assert!(super::end_pause(&pause));
        assert!(pause.lock().unwrap().is_none());
        assert!(!super::end_pause(&pause), "keine Pause mehr aktiv");
        let expired = std::sync::Mutex::new(Some((Instant::now() - Duration::from_secs(1), Instant::now() - Duration::from_secs(60))));
        assert!(!super::end_pause(&expired), "abgelaufene Pause zaehlt nicht");
    }

    #[test]
    fn replacing_or_deleting_a_stored_key_needs_the_confirmation() {
        assert_eq!(secret_change_confirmation(false, true), None, "erster Schluessel");
        assert_eq!(secret_change_confirmation(false, false), None);
        assert!(secret_change_confirmation(true, true).is_some());
        assert!(secret_change_confirmation(true, false).is_some());
    }
}
