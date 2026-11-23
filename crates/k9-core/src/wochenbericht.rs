//! Weekly report: once a week a short summary of the last 7 days as a notice (Meldefenster
//! and the other channels, never during a game): new findings by severity, how many came
//! quietly from work folders, what is still open, your decisions, the security check and the
//! outdated programs. Only "Gesehen".

use std::path::PathBuf;

use crate::model::{Decision, Detection, DetectionStatus, Finding, Kind, Severity};
use crate::sicherheit::{Ampel, Bericht};

pub const META_KEY: &str = "wochenbericht_zuletzt";
pub const DAYS: i64 = 7;

fn parse(t: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").ok()
}

/// Is a report due? `last`: time of the last one (None: never – the first comes one day
/// after K9 starts using it, so the week has some content).
pub fn due(last: Option<&str>, now: chrono::NaiveDateTime) -> bool {
    last.and_then(parse).is_some_and(|l| now - l >= chrono::Duration::days(DAYS))
}

/// Starting value when there was no report yet: the first one comes a day later.
pub fn first_start(now: chrono::NaiveDateTime) -> String {
    (now - chrono::Duration::days(DAYS - 1)).format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn build(now: chrono::NaiveDateTime, detections: &[Detection], decisions: &[Decision], check: Option<&Bericht>) -> Finding {
    let from = now - chrono::Duration::days(DAYS);
    let recent: Vec<&Detection> = detections.iter().filter(|d| parse(&d.first_seen).is_some_and(|t| t >= from)).collect();
    let quiet = recent.iter().filter(|d| crate::arbeitsordner::is_quiet(d)).count();
    let loud: Vec<&&Detection> = recent.iter().filter(|d| !crate::arbeitsordner::is_quiet(d) && d.rule_id != "BERICHT:WOCHE").collect();
    let by = |s: Severity| loud.iter().filter(|d| d.severity == s).count();
    let open = detections.iter().filter(|d| d.status == DetectionStatus::Offen && d.rule_id != "BERICHT:WOCHE").count();
    let decided = decisions.iter().filter(|d| parse(&d.decided_at).is_some_and(|t| t >= from)).count();
    let mut lines = vec![tf!(
        "Neue Meldungen: {} (kritisch {}, hoch {}, mittel {}, niedrig/info {}), dazu {quiet} leise aus Arbeitsordnern.", "New findings: {} (critical {}, high {}, medium {}, low/info {}), plus {quiet} quiet ones from work folders.",
        loud.len(),
        by(Severity::Kritisch),
        by(Severity::Hoch),
        by(Severity::Mittel),
        by(Severity::Niedrig) + by(Severity::Info)
    )];
    lines.push(tf!("Noch offen: {open}. Gemerkte Entscheidungen in dieser Woche: {decided}.", "Still open: {open}. Decisions remembered this week: {decided}."));
    let mut top: Vec<String> = loud.iter().filter(|d| d.severity >= Severity::Hoch).map(|d| d.threat_name.clone()).collect();
    top.dedup();
    if !top.is_empty() {
        lines.push(tf!("Wichtigste: {}", "Most important: {}", top.into_iter().take(5).collect::<Vec<_>>().join("; ")));
    }
    if let Some(c) = check {
        let bad: Vec<String> = c.punkte.iter().filter(|p| matches!(p.ampel, Ampel::Gelb | Ampel::Rot)).map(|p| format!("{} ({})", p.name, p.text)).collect();
        lines.push(if bad.is_empty() { t!("Sicherheits-Check: alles in Ordnung.", "Security check: everything is fine.").to_string() } else { tf!("Sicherheits-Check, bitte prüfen: {}.", "Security check, please look at: {}.", bad.join("; ")) });
        if let Some(u) = c.updates.as_ref().filter(|u| !u.is_empty()) {
            lines.push(tf!("{} Programme haben eine neuere Version – alle auf einmal: winget upgrade --all", "{} programs have a newer version – all at once: winget upgrade --all", u.len()));
        }
    }
    lines.push("Details im Dashboard.".into());
    let title = tf!("Wochenbericht {} – {}", "Weekly report {} – {}", from.format("%d.%m."), now.format("%d.%m.%Y"));
    Finding {
        path: PathBuf::from(title.clone()),
        sha256: crate::sha256_hex(format!("wochenbericht|{}", now.format("%Y-%m-%d %H:%M:%S")).as_bytes()),
        size: 0,
        rule_id: "BERICHT:WOCHE".into(),
        threat_name: title,
        category: t!("Wochenbericht", "Weekly report").into(),
        severity: Severity::Info,
        engine: "echtzeit".into(),
        kind: Kind::Hinweis,
        details: Some(serde_json::json!({ "hinweis": lines.join("\n") })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(id: i64, sev: Severity, first: &str, status: DetectionStatus, leise: bool) -> Detection {
        Detection {
            id,
            path: "p".into(),
            sha256: "s".into(),
            rule_id: "R".into(),
            threat_name: format!("Fund {id}"),
            category: "c".into(),
            severity: sev,
            engine: "e".into(),
            first_seen: first.into(),
            last_seen: first.into(),
            status,
            action: None,
            kind: Kind::Datei,
            details: leise.then(|| serde_json::json!({ "leise": "Arbeitsordner" })),
        }
    }

    #[test]
    fn summary_of_the_last_week() {
        let now = parse("2026-11-24 10:00:00").unwrap();
        let d = vec![
            det(1, Severity::Hoch, "2026-11-20 10:00:00", DetectionStatus::Offen, false),
            det(2, Severity::Kritisch, "2026-11-21 10:00:00", DetectionStatus::Offen, true),
            det(3, Severity::Mittel, "2026-11-01 10:00:00", DetectionStatus::Entschieden, false),
        ];
        let f = build(now, &d, &[], None);
        let text = f.details.unwrap()["hinweis"].as_str().unwrap().to_string();
        assert!(text.contains("Neue Meldungen: 1 (kritisch 0, hoch 1"), "{text}");
        assert!(text.contains("1 leise") && text.contains("Noch offen: 2") && text.contains("Fund 1"));
        assert_eq!((f.kind, f.severity), (Kind::Hinweis, Severity::Info));
        assert!(f.threat_name.starts_with("Wochenbericht 17.11."));
    }

    #[test]
    fn weekly_rhythm() {
        let now = parse("2026-11-24 10:00:00").unwrap();
        assert!(!due(None, now));
        assert!(due(Some(&first_start(now)), now + chrono::Duration::days(1)));
        assert!(!due(Some("2026-11-20 10:00:00"), now));
        assert!(due(Some("2026-11-17 10:00:00"), now));
    }
}
