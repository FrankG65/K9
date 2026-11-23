//! Scan schedules: sofort, ständig, täglich, wöchentlich, einmalig, Leerlauf.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, NaiveDateTime, NaiveTime, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduleEntry {
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub kind: ScheduleKind,
    /// Folders/files to scan. Empty = `standard_pfade` from `[scan]`.
    #[serde(default)]
    pub pfade: Vec<String>,
    /// Checks to run: "dateien", "software", "urls", "autostart". Empty = all.
    #[serde(default)]
    pub pruefungen: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "art", rename_all = "lowercase")]
pub enum ScheduleKind {
    /// Only on demand (`k9 scan`); never triggered by the agent.
    Sofort,
    /// Continuous monitoring – placeholder for real-time protection (step 3).
    #[serde(alias = "ständig")]
    Staendig,
    #[serde(alias = "täglich")]
    Taeglich { uhrzeit: String },
    #[serde(alias = "wöchentlich")]
    Woechentlich { tage: Vec<String>, uhrzeit: String },
    /// `zeitpunkt` = "JJJJ-MM-TT HH:MM"
    Einmalig { zeitpunkt: String },
    /// Runs when no keyboard/mouse input happened for `minuten`.
    Leerlauf {
        minuten: u32,
        #[serde(default = "default_idle_gap")]
        min_abstand_stunden: u32,
    },
}

fn default_idle_gap() -> u32 {
    24
}

pub fn parse_time(s: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").with_context(|| format!("Ungültige Uhrzeit '{s}' (Format HH:MM)"))
}

pub fn parse_datetime(s: &str) -> Result<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M")
        .with_context(|| format!("Ungültiger Zeitpunkt '{s}' (Format JJJJ-MM-TT HH:MM)"))
}

pub fn parse_weekday(s: &str) -> Result<Weekday> {
    Ok(match s.trim().to_lowercase().as_str() {
        "mo" | "montag" => Weekday::Mon,
        "di" | "dienstag" => Weekday::Tue,
        "mi" | "mittwoch" => Weekday::Wed,
        "do" | "donnerstag" => Weekday::Thu,
        "fr" | "freitag" => Weekday::Fri,
        "sa" | "samstag" => Weekday::Sat,
        "so" | "sonntag" => Weekday::Sun,
        other => bail!("Unbekannter Wochentag '{other}' (Mo, Di, Mi, Do, Fr, Sa, So)"),
    })
}

impl ScheduleKind {
    pub fn validate(&self) -> Result<()> {
        match self {
            ScheduleKind::Sofort | ScheduleKind::Staendig => {}
            ScheduleKind::Taeglich { uhrzeit } => {
                parse_time(uhrzeit)?;
            }
            ScheduleKind::Woechentlich { tage, uhrzeit } => {
                parse_time(uhrzeit)?;
                if tage.is_empty() {
                    bail!("Wöchentlicher Zeitplan braucht mindestens einen Tag");
                }
                for t in tage {
                    parse_weekday(t)?;
                }
            }
            ScheduleKind::Einmalig { zeitpunkt } => {
                parse_datetime(zeitpunkt)?;
            }
            ScheduleKind::Leerlauf { minuten, .. } => {
                if *minuten == 0 {
                    bail!("Leerlauf-Minuten müssen größer als 0 sein");
                }
            }
        }
        Ok(())
    }

    /// Human readable German description.
    pub fn describe(&self) -> String {
        match self {
            ScheduleKind::Sofort => t!("sofort (nur auf Anforderung)", "at once (only on request)").into(),
            ScheduleKind::Staendig => t!("ständig (Echtzeitschutz – folgt in Schritt 3)", "always (real-time protection)").into(),
            ScheduleKind::Taeglich { uhrzeit } => tf!("täglich um {uhrzeit}", "daily at {uhrzeit}"),
            ScheduleKind::Woechentlich { tage, uhrzeit } => tf!("wöchentlich {} um {uhrzeit}", "weekly {} at {uhrzeit}", tage.join(", ")),
            ScheduleKind::Einmalig { zeitpunkt } => tf!("einmalig am {zeitpunkt}", "once on {zeitpunkt}"),
            ScheduleKind::Leerlauf { minuten, min_abstand_stunden } => {
                tf!("im Leerlauf nach {minuten} min (höchstens alle {min_abstand_stunden} h)", "when idle after {minuten} min (at most every {min_abstand_stunden} h)")
            }
        }
    }

    /// True for kinds whose first run is anchored to "now" instead of being caught up.
    pub fn is_recurring_timed(&self) -> bool {
        matches!(self, ScheduleKind::Taeglich { .. } | ScheduleKind::Woechentlich { .. })
    }

    /// Most recent planned occurrence at or before `now` (timed kinds only).
    pub fn last_occurrence(&self, now: NaiveDateTime) -> Option<NaiveDateTime> {
        match self {
            ScheduleKind::Taeglich { uhrzeit } => {
                let t = parse_time(uhrzeit).ok()?;
                let today = now.date().and_time(t);
                Some(if today <= now { today } else { today - ChronoDuration::days(1) })
            }
            ScheduleKind::Woechentlich { tage, uhrzeit } => {
                let t = parse_time(uhrzeit).ok()?;
                let days: Vec<Weekday> = tage.iter().filter_map(|d| parse_weekday(d).ok()).collect();
                (0..=7)
                    .map(|back| (now.date() - ChronoDuration::days(back)).and_time(t))
                    .find(|cand| *cand <= now && days.contains(&cand.weekday()))
            }
            ScheduleKind::Einmalig { zeitpunkt } => parse_datetime(zeitpunkt).ok().filter(|zp| *zp <= now),
            _ => None,
        }
    }

    /// Next planned occurrence after `now` (for status display).
    pub fn next_occurrence(&self, now: NaiveDateTime) -> Option<NaiveDateTime> {
        match self {
            ScheduleKind::Taeglich { uhrzeit } => {
                let t = parse_time(uhrzeit).ok()?;
                let today = now.date().and_time(t);
                Some(if today > now { today } else { today + ChronoDuration::days(1) })
            }
            ScheduleKind::Woechentlich { tage, uhrzeit } => {
                let t = parse_time(uhrzeit).ok()?;
                let days: Vec<Weekday> = tage.iter().filter_map(|d| parse_weekday(d).ok()).collect();
                (0..=7)
                    .map(|fwd| (now.date() + ChronoDuration::days(fwd)).and_time(t))
                    .find(|cand| *cand > now && days.contains(&cand.weekday()))
            }
            ScheduleKind::Einmalig { zeitpunkt } => parse_datetime(zeitpunkt).ok().filter(|zp| *zp > now),
            _ => None,
        }
    }

    /// Decides whether a scan is due. `last_run = None` means never run.
    pub fn is_due(&self, now: NaiveDateTime, last_run: Option<NaiveDateTime>, idle: Duration) -> bool {
        match self {
            ScheduleKind::Sofort | ScheduleKind::Staendig => false,
            ScheduleKind::Taeglich { .. } | ScheduleKind::Woechentlich { .. } | ScheduleKind::Einmalig { .. } => {
                match (self.last_occurrence(now), last_run) {
                    (Some(occ), Some(last)) => last < occ,
                    (Some(_), None) => true,
                    (None, _) => false,
                }
            }
            ScheduleKind::Leerlauf { minuten, min_abstand_stunden } => {
                if idle < Duration::from_secs(u64::from(*minuten) * 60) {
                    return false;
                }
                match last_run {
                    Some(last) => now - last >= ChronoDuration::hours(i64::from(*min_abstand_stunden)),
                    None => true,
                }
            }
        }
    }
}

impl ScheduleEntry {
    /// Stable key for the `schedule_runs` table; changing the entry resets it.
    pub fn key(&self) -> String {
        serde_json::to_string(&self.kind).unwrap_or_default()
    }

    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => format!("{n}: {}", self.kind.describe()),
            None => self.kind.describe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(s: &str) -> NaiveDateTime {
        parse_datetime(s).unwrap()
    }

    #[derive(Deserialize)]
    struct Wrapper {
        zeitplan: Vec<ScheduleEntry>,
    }

    #[test]
    fn parses_all_kinds_from_toml() {
        let text = r#"
            [[zeitplan]]
            art = "sofort"
            [[zeitplan]]
            art = "ständig"
            [[zeitplan]]
            art = "täglich"
            uhrzeit = "03:30"
            pfade = ["C:\\Users"]
            [[zeitplan]]
            name = "Wochenende"
            art = "woechentlich"
            tage = ["Sa", "So"]
            uhrzeit = "10:00"
            [[zeitplan]]
            art = "einmalig"
            zeitpunkt = "2026-12-24 18:00"
            [[zeitplan]]
            art = "leerlauf"
            minuten = 15
        "#;
        let w: Wrapper = toml::from_str(text).unwrap();
        assert_eq!(w.zeitplan.len(), 6);
        assert_eq!(w.zeitplan[1].kind, ScheduleKind::Staendig);
        assert_eq!(w.zeitplan[2].kind, ScheduleKind::Taeglich { uhrzeit: "03:30".into() });
        assert_eq!(w.zeitplan[2].pfade, vec!["C:\\Users".to_string()]);
        assert_eq!(w.zeitplan[3].name.as_deref(), Some("Wochenende"));
        assert_eq!(w.zeitplan[5].kind, ScheduleKind::Leerlauf { minuten: 15, min_abstand_stunden: 24 });
        for e in &w.zeitplan {
            e.kind.validate().unwrap();
        }
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(ScheduleKind::Taeglich { uhrzeit: "25:00".into() }.validate().is_err());
        assert!(ScheduleKind::Woechentlich { tage: vec!["Xy".into()], uhrzeit: "10:00".into() }.validate().is_err());
        assert!(ScheduleKind::Einmalig { zeitpunkt: "24.12.2026".into() }.validate().is_err());
        assert!(ScheduleKind::Leerlauf { minuten: 0, min_abstand_stunden: 1 }.validate().is_err());
        let bad: Result<Wrapper, _> = toml::from_str("[[zeitplan]]\nart = \"stündlich\"\n");
        assert!(bad.is_err());
    }

    #[test]
    fn daily_due_logic() {
        let k = ScheduleKind::Taeglich { uhrzeit: "03:00".into() };
        let now = dt("2026-11-13 09:00");
        assert_eq!(k.last_occurrence(now), Some(dt("2026-11-13 03:00")));
        assert_eq!(k.next_occurrence(now), Some(dt("2026-11-14 03:00")));
        assert!(k.is_due(now, Some(dt("2026-11-12 03:01")), Duration::ZERO));
        assert!(!k.is_due(now, Some(dt("2026-11-13 03:05")), Duration::ZERO));
        // Before today's slot the previous day's slot counts.
        assert_eq!(k.last_occurrence(dt("2026-11-13 02:00")), Some(dt("2026-11-12 03:00")));
    }

    #[test]
    fn weekly_due_logic() {
        // 2026-11-13 is a Friday.
        let k = ScheduleKind::Woechentlich { tage: vec!["Mo".into(), "Fr".into()], uhrzeit: "20:00".into() };
        let now = dt("2026-11-13 19:00");
        assert_eq!(k.last_occurrence(now), Some(dt("2026-11-09 20:00")));
        assert_eq!(k.next_occurrence(now), Some(dt("2026-11-13 20:00")));
        assert!(!k.is_due(now, Some(dt("2026-11-09 20:10")), Duration::ZERO));
        assert!(k.is_due(dt("2026-11-13 20:01"), Some(dt("2026-11-09 20:10")), Duration::ZERO));
    }

    #[test]
    fn once_and_idle_logic() {
        let k = ScheduleKind::Einmalig { zeitpunkt: "2026-11-13 10:00".into() };
        assert!(!k.is_due(dt("2026-11-13 09:59"), None, Duration::ZERO));
        assert!(k.is_due(dt("2026-11-13 10:00"), None, Duration::ZERO));
        assert!(!k.is_due(dt("2026-11-14 10:00"), Some(dt("2026-11-13 10:00")), Duration::ZERO));

        let idle = ScheduleKind::Leerlauf { minuten: 10, min_abstand_stunden: 24 };
        let now = dt("2026-11-13 12:00");
        assert!(!idle.is_due(now, None, Duration::from_secs(9 * 60)));
        assert!(idle.is_due(now, None, Duration::from_secs(10 * 60)));
        assert!(!idle.is_due(now, Some(dt("2026-11-13 01:00")), Duration::from_secs(3600)));
        assert!(idle.is_due(now, Some(dt("2026-11-12 11:00")), Duration::from_secs(3600)));
    }
}
