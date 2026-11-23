//! VirusTotal lookup (opt-in, `quellen.virustotal_aktiv`, default off): only the SHA-256
//! of a new program from the internet is sent – never the file. Free personal key: only
//! private, non-commercial use; at most 4 lookups per minute and 500 per day. Results
//! are kept 7 days. Note: the hash goes to VirusTotal (Google).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::model::{Finding, Kind, Severity};
use crate::store::Store;

pub const VT_KEY: &str = "virustotal-key";
const PER_MINUTE: usize = 4;
const PER_DAY: u32 = 500;
const CACHE_DAYS: u64 = 7;
const CACHE_MAX: usize = 2000;
const META_CACHE: &str = "virustotal_cache";
const META_DAY: &str = "virustotal_tag";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub malicious: u32,
    pub suspicious: u32,
    pub total: u32,
}

#[derive(Debug, PartialEq)]
pub enum Lookup {
    Known(Verdict),
    /// VirusTotal does not know the file (it is never uploaded).
    Unknown,
    RateLimited,
    Failed(String),
}

/// `data.attributes.last_analysis_stats` of a /api/v3/files/{hash} answer.
pub fn parse_report(json: &str) -> Option<Verdict> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let s = &v["data"]["attributes"]["last_analysis_stats"];
    let n = |k: &str| s[k].as_u64().unwrap_or(0) as u32;
    s.is_object().then(|| Verdict {
        malicious: n("malicious"),
        suspicious: n("suspicious"),
        total: ["malicious", "suspicious", "undetected", "harmless", "timeout", "type-unsupported", "failure"].iter().map(|k| n(k)).sum(),
    })
}

/// One lookup (hash only, HTTPS, key in a header – never in the address).
pub fn lookup(sha256: &str, key: &str) -> Lookup {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Lookup::Failed("kein SHA-256".into());
    }
    let client = match crate::sources::http() {
        Ok(c) => c,
        Err(e) => return Lookup::Failed(format!("{e:#}")),
    };
    let resp = client.get(format!("https://www.virustotal.com/api/v3/files/{sha256}")).header("x-apikey", key).timeout(Duration::from_secs(30)).send();
    let resp = match resp {
        Ok(r) => r,
        Err(e) => return Lookup::Failed(tf!("nicht erreichbar: {}", "not reachable: {}", e.without_url())),
    };
    match resp.status().as_u16() {
        404 => Lookup::Unknown,
        429 => Lookup::RateLimited,
        401 | 403 => Lookup::Failed("Schlüssel ungültig oder gesperrt".into()),
        s if !(200..300).contains(&s) => Lookup::Failed(tf!("Antwort {s}", "response {s}")),
        _ => match resp.text().ok().as_deref().and_then(parse_report) {
            Some(v) => Lookup::Known(v),
            None => Lookup::Failed("Antwort nicht lesbar".into()),
        },
    }
}

/// 4 per minute, 500 per day (the day counter is kept in the database).
#[derive(Default)]
pub struct Limiter {
    minute: VecDeque<Instant>,
}

impl Limiter {
    fn today_count(store: &Store, today: &str) -> u32 {
        store
            .meta_get(META_DAY)
            .ok()
            .flatten()
            .and_then(|v| v.split_once('|').filter(|(d, _)| *d == today).map(|(_, n)| n.parse::<u32>().unwrap_or(0)))
            .unwrap_or(0)
    }

    /// May a lookup be made now? (Nothing is counted yet.)
    pub fn allow(&mut self, store: &Store, now: Instant, today: &str) -> bool {
        self.minute.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        self.minute.len() < PER_MINUTE && Self::today_count(store, today) < PER_DAY
    }

    /// Counts a lookup that reached VirusTotal (a failed connection is not counted).
    pub fn record(&mut self, store: &Store, now: Instant, today: &str) {
        let n = Self::today_count(store, today);
        let _ = store.meta_set(META_DAY, &format!("{today}|{}", n + 1));
        self.minute.push_back(now);
    }
}

fn epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

type Cache = BTreeMap<String, (u64, Option<Verdict>)>;

/// Cached result (`Some(None)`: VirusTotal did not know the file).
pub fn cached(store: &Store, sha256: &str) -> Option<Option<Verdict>> {
    let cache: Cache = serde_json::from_str(&store.meta_get(META_CACHE).ok()??).ok()?;
    cache.get(sha256).filter(|(t, _)| epoch().saturating_sub(*t) < CACHE_DAYS * 86_400).map(|(_, v)| *v)
}

pub fn remember(store: &Store, sha256: &str, v: Option<Verdict>) {
    let mut cache: Cache = store.meta_get(META_CACHE).ok().flatten().and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
    let now = epoch();
    cache.retain(|_, (t, _)| now.saturating_sub(*t) < CACHE_DAYS * 86_400);
    while cache.len() >= CACHE_MAX {
        let oldest = cache.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone());
        match oldest {
            Some(k) => cache.remove(&k),
            None => break,
        };
    }
    cache.insert(sha256.to_string(), (now, v));
    if let Ok(j) = serde_json::to_string(&cache) {
        let _ = store.meta_set(META_CACHE, &j);
    }
}

/// Finding: 3 or more engines = Hoch, 1–2 = Mittel, none = no finding.
pub fn finding(path: &Path, sha256: &str, v: &Verdict) -> Option<Finding> {
    let severity = match v.malicious {
        0 => return None,
        1 | 2 => Severity::Mittel,
        _ => Severity::Hoch,
    };
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    Some(Finding {
        path: PathBuf::from(path),
        sha256: sha256.to_string(),
        size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        rule_id: "VIRUSTOTAL:ERKANNT".into(),
        threat_name: tf!("VirusTotal: {} von {} Virenscannern erkennen {name} als schädlich", "VirusTotal: {} of {} virus scanners detect {name} as harmful", v.malicious, v.total),
        category: crate::model::category::MALWARE.into(),
        severity,
        engine: "virustotal".into(),
        kind: Kind::Datei,
        details: Some(serde_json::json!({
            "virustotal": tf!("{} von {} schädlich, {} verdächtig", "{} of {} harmful, {} suspicious", v.malicious, v.total, v.suspicious),
            "link": format!("https://www.virustotal.com/gui/file/{sha256}"),
            "hinweis": t!("Nur die Prüfsumme wurde bei VirusTotal abgefragt, die Datei wurde nicht hochgeladen. Einzelne Treffer können Fehlalarme sein (z. B. bei Spiel-Tools) – im Zweifel „Quarantäne“.", "Only the checksum was looked up at VirusTotal, the file was not uploaded. Single hits can be false alarms (e.g. with game tools) – if in doubt “Quarantine”."),
        })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"suspicious":1,"undetected":50,"harmless":0,"timeout":1,"type-unsupported":4,"failure":0}}}}"#;

    #[test]
    fn answer_is_read_and_turned_into_a_finding() {
        let v = parse_report(ANSWER).unwrap();
        assert_eq!(v, Verdict { malicious: 12, suspicious: 1, total: 68 });
        let f = finding(Path::new(r"C:\x\cheat.exe"), &"a".repeat(64), &v).unwrap();
        assert_eq!(f.severity, Severity::Hoch);
        assert!(f.threat_name.contains("12 von 68"));
        assert_eq!(finding(Path::new("x.exe"), &"a".repeat(64), &Verdict { malicious: 1, suspicious: 0, total: 70 }).unwrap().severity, Severity::Mittel);
        assert!(finding(Path::new("x.exe"), &"a".repeat(64), &Verdict { malicious: 0, suspicious: 3, total: 70 }).is_none());
        assert!(parse_report("{}").is_none());
        assert_eq!(lookup("kein-hash", "k"), Lookup::Failed("kein SHA-256".into()));
    }

    #[test]
    fn rate_limit_and_cache() {
        let store = Store::open_in_memory().unwrap();
        let mut l = Limiter::default();
        let t = Instant::now();
        // Failed lookups (offline) are never counted.
        for _ in 0..10 {
            assert!(l.allow(&store, t, "2026-11-15"));
        }
        assert_eq!(store.meta_get("virustotal_tag").unwrap(), None);
        for _ in 0..4 {
            assert!(l.allow(&store, t, "2026-11-15"));
            l.record(&store, t, "2026-11-15");
        }
        assert!(!l.allow(&store, t, "2026-11-15"), "höchstens 4 je Minute");
        assert!(l.allow(&store, t + Duration::from_secs(61), "2026-11-15"));
        store.meta_set("virustotal_tag", "2026-11-15|500").unwrap();
        let mut l = Limiter::default();
        assert!(!l.allow(&store, t, "2026-11-15"), "höchstens 500 je Tag");
        assert!(l.allow(&store, t, "2026-11-16"), "neuer Tag");
        assert_eq!(cached(&store, &"b".repeat(64)), None);
        remember(&store, &"b".repeat(64), None);
        assert_eq!(cached(&store, &"b".repeat(64)), Some(None));
        let v = parse_report(ANSWER).unwrap();
        remember(&store, &"c".repeat(64), Some(v));
        assert_eq!(cached(&store, &"c".repeat(64)), Some(Some(v)));
    }
}
