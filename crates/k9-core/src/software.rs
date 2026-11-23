//! Vulnerable software check: installed programs (registry Uninstall keys)
//! against the CISA KEV catalog (actively exploited vulnerabilities), with
//! version ranges from the NVD CVE API 2.0.
//!
//! Matching is deliberately conservative: a program is only reported when
//! the KEV entry matches by vendor and product name AND an NVD CPE entry for
//! the same product says the installed version is affected ("hoch"), or NVD
//! lists the product as affected in all versions ("mittel"). Nothing is ever
//! updated automatically – the finding shows the fix (e.g. winget command).

use std::collections::{BTreeSet, HashMap};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::model::{Finding, Kind, Severity};
use crate::winreg::{self, HKCU, HKLM};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub registry: String,
}

const UNINSTALL: [&str; 2] = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
];

/// Installed programs from HKLM (64/32 bit) and HKCU Uninstall keys.
pub fn inventory() -> Vec<Installed> {
    let mut out: Vec<Installed> = Vec::new();
    let roots = [(HKLM, UNINSTALL[0]), (HKLM, UNINSTALL[1]), (HKCU, UNINSTALL[0])];
    for (hive, root) in roots {
        for sub in winreg::subkeys(hive, root) {
            let path = format!("{root}\\{sub}");
            let Some(name) = winreg::read_string(hive, &path, "DisplayName").filter(|n| !n.trim().is_empty()) else { continue };
            if winreg::read_dword(hive, &path, "SystemComponent") == Some(1)
                || winreg::read_string(hive, &path, "ParentKeyName").is_some()
            {
                continue;
            }
            let version = winreg::read_string(hive, &path, "DisplayVersion").unwrap_or_default();
            let publisher = winreg::read_string(hive, &path, "Publisher").unwrap_or_default();
            let item = Installed { name: name.trim().into(), version: version.trim().into(), publisher: publisher.trim().into(), registry: format!("{}\\{path}", winreg::hive_name(hive)) };
            if !out.iter().any(|o| o.name == item.name && o.version == item.version) {
                out.push(item);
            }
        }
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

// --------------------------------------------------------------- matching

const STOP: [&str; 22] = [
    "inc", "corporation", "corp", "ltd", "gmbh", "llc", "co", "the", "x64", "x86", "64", "32", "bit", "version", "update",
    "edition", "software", "foundation", "and", "for", "systems", "technologies",
];

/// Lower-case alphanumeric tokens without noise words and pure numbers.
pub fn tokens(s: &str) -> BTreeSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty() && !STOP.contains(t) && !t.chars().all(|c| c.is_ascii_digit()))
        .map(|t| t.to_string())
        .collect()
}

/// Same as [`tokens`] but keeps the word order.
pub fn ordered_tokens(s: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty() && !STOP.contains(t) && !t.chars().all(|c| c.is_ascii_digit()))
        .filter(|t| seen.insert(t.to_string()))
        .map(|t| t.to_string())
        .collect()
}

/// Product name aliases (KEV token -> token in installed program names).
fn alias(token: &str) -> &str {
    match token {
        "chromium" => "chrome",
        _ => token,
    }
}

fn contains_all(have: &BTreeSet<String>, need: &BTreeSet<String>) -> bool {
    !need.is_empty() && need.iter().all(|t| have.contains(alias(t)))
}

/// The product words must start the program name (after the vendor words),
/// in order, with at most two extra words in between ("Java(TM) SE …").
/// This keeps "Teams Add-in for Microsoft Office" from matching "Office".
fn name_starts_with_product(name: &str, vendor: &BTreeSet<String>, product: &[String]) -> bool {
    let words: Vec<String> = ordered_tokens(name)
        .into_iter()
        .filter(|w| !vendor.contains(w) || product.iter().any(|p| alias(p) == w))
        .collect();
    if product.is_empty() || words.is_empty() {
        return false;
    }
    let window = &words[..words.len().min(product.len() + 2)];
    // First product word within the first two words ("Oracle VM VirtualBox").
    if !words.iter().take(2).any(|w| w == alias(&product[0])) {
        return false;
    }
    let mut it = window.iter();
    product.iter().all(|p| it.any(|w| w == alias(p)))
}

/// KEV entries that describe the operating system itself or are too generic
/// ("Microsoft/Microsoft"). Windows is patched via Windows Update.
fn kev_too_generic(k: &KevEntry) -> bool {
    let v = tokens(&k.vendor);
    let p = tokens(&k.product);
    let first = ordered_tokens(&k.product).into_iter().next().unwrap_or_default();
    p.is_empty() || (v.contains("microsoft") && (p.is_subset(&v) || first == "windows" || first == "win32k"))
}

/// Compares dotted versions numerically ("120.0.6099.62" < "120.0.6099.130").
pub fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u64> { s.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).map(|p| p.parse().unwrap_or(0)).collect() };
    let (mut x, mut y) = (parse(a), parse(b));
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    x.cmp(&y)
}

#[derive(Debug, Clone, Serialize)]
pub struct KevEntry {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub ransomware: bool,
    pub action: String,
}

pub fn load_kev(file: &Path) -> Result<Vec<KevEntry>> {
    let data = std::fs::read(file).with_context(|| format!("KEV-Katalog fehlt ({}) – bitte 'k9 quellen aktualisieren'", file.display()))?;
    parse_kev(&data)
}

pub fn parse_kev(data: &[u8]) -> Result<Vec<KevEntry>> {
    let v: serde_json::Value = serde_json::from_slice(data).context("KEV-Katalog ungültig")?;
    Ok(v["vulnerabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            Some(KevEntry {
                cve: e["cveID"].as_str()?.to_string(),
                vendor: e["vendorProject"].as_str().unwrap_or("").to_string(),
                product: e["product"].as_str().unwrap_or("").to_string(),
                name: e["vulnerabilityName"].as_str().unwrap_or("").to_string(),
                ransomware: e["knownRansomwareCampaignUse"].as_str() == Some("Known"),
                action: e["requiredAction"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect())
}

/// KEV entries whose vendor and product names fit an installed program.
pub fn kev_candidates<'a>(sw: &Installed, kev: &'a [KevEntry]) -> Vec<&'a KevEntry> {
    let name = tokens(&sw.name);
    let mut both = name.clone();
    both.extend(tokens(&sw.publisher));
    kev.iter()
        .filter(|k| !kev_too_generic(k))
        .filter(|k| {
            let vendor = tokens(&k.vendor);
            contains_all(&both, &vendor)
                && contains_all(&name, &tokens(&k.product))
                && name_starts_with_product(&sw.name, &vendor, &ordered_tokens(&k.product))
        })
        .collect()
}

/// Outcome of checking one CVE's NVD data against an installed program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Installed version lies in an affected range.
    Affected { fixed_in: Option<String> },
    /// Product listed as affected without version information.
    AllVersions,
    /// NVD knows the product but not this version -> not reported.
    NotAffected,
    /// No CPE for this product in the NVD data -> not reported.
    Unknown,
}

/// Evaluates NVD `configurations` for an installed program.
pub fn evaluate_nvd(cve_json: &serde_json::Value, sw: &Installed) -> Verdict {
    let name = tokens(&sw.name);
    let mut product_known = false;
    let mut all_versions = false;
    let configs = cve_json["configurations"].as_array().cloned().unwrap_or_default();
    for cfg in &configs {
        for node in cfg["nodes"].as_array().into_iter().flatten() {
            for m in node["cpeMatch"].as_array().into_iter().flatten() {
                if m["vulnerable"].as_bool() != Some(true) {
                    continue;
                }
                let crit = m["criteria"].as_str().unwrap_or("");
                let parts: Vec<&str> = crit.split(':').collect();
                if parts.len() < 6 || parts[2] != "a" {
                    continue;
                }
                // The vendor was already matched via KEV; CPE vendor names often
                // differ from the publisher ("git-scm" vs "Git Development Community").
                let product: BTreeSet<String> = tokens(&parts[4].replace('_', " "));
                if !contains_all(&name, &product) {
                    continue;
                }
                product_known = true;
                let exact = parts[5];
                let start_inc = m["versionStartIncluding"].as_str();
                let start_exc = m["versionStartExcluding"].as_str();
                let end_inc = m["versionEndIncluding"].as_str();
                let end_exc = m["versionEndExcluding"].as_str();
                let has_range = start_inc.or(start_exc).or(end_inc).or(end_exc).is_some();
                if !has_range {
                    if exact == "*" {
                        all_versions = true;
                    } else if exact != "-" && cmp_version(exact, &sw.version).is_eq() && !sw.version.is_empty() {
                        return Verdict::Affected { fixed_in: None };
                    }
                    continue;
                }
                if sw.version.is_empty() {
                    continue;
                }
                use std::cmp::Ordering::*;
                let v = &sw.version;
                let ok = start_inc.is_none_or(|s| cmp_version(v, s) != Less)
                    && start_exc.is_none_or(|s| cmp_version(v, s) == Greater)
                    && end_inc.is_none_or(|e| cmp_version(v, e) != Greater)
                    && end_exc.is_none_or(|e| cmp_version(v, e) == Less);
                if ok {
                    return Verdict::Affected { fixed_in: end_exc.map(str::to_string) };
                }
            }
        }
    }
    match (product_known, all_versions) {
        (true, true) => Verdict::AllVersions,
        (true, false) => Verdict::NotAffected,
        _ => Verdict::Unknown,
    }
}

/// CVSS base severity from NVD metrics ("CRITICAL", "HIGH", ...).
pub fn nvd_severity(cve_json: &serde_json::Value) -> Option<String> {
    let m = &cve_json["metrics"];
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
        if let Some(s) = m[key][0]["cvssData"]["baseSeverity"].as_str() {
            return Some(s.to_string());
        }
    }
    m["cvssMetricV2"][0]["baseSeverity"].as_str().map(str::to_string)
}

// ------------------------------------------------------------------ NVD client

/// NVD CVE API 2.0 with local cache (30 days) and rate limiting
/// (5 requests / 30 s without key, 50 with key).
pub struct Nvd {
    cache_dir: PathBuf,
    key: Option<String>,
    last: Option<Instant>,
    pub requests: usize,
    pub offline: bool,
    /// CVEs in a row that could not be fetched.
    failures: usize,
}

impl Nvd {
    pub fn new(sources_dir: &Path) -> Self {
        let key = crate::secrets::get(crate::sources::NVD_KEY).ok().flatten();
        Self { cache_dir: sources_dir.join("nvd"), key, last: None, requests: 0, offline: false, failures: 0 }
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// The `cve` object of the NVD answer, from cache or online.
    pub fn cve(&mut self, id: &str) -> Option<serde_json::Value> {
        let file = self.cache_dir.join(format!("{id}.json"));
        if let Ok(meta) = std::fs::metadata(&file) {
            let fresh = meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age < Duration::from_secs(30 * 86400));
            if fresh || self.offline {
                if let Some(v) = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
                    return Some(v);
                }
            }
        }
        if self.offline {
            return None;
        }
        let gap = if self.key.is_some() { Duration::from_millis(700) } else { Duration::from_millis(6500) };
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}");
        let headers: Vec<(&str, String)> = self.key.iter().map(|k| ("apiKey", k.clone())).collect();
        // NVD is often briefly overloaded (5xx); retry with growing pauses.
        for attempt in 0..3u32 {
            if let Some(last) = self.last {
                let wait = gap + Duration::from_secs(10 * u64::from(attempt));
                if let Some(rest) = wait.checked_sub(last.elapsed()) {
                    std::thread::sleep(rest);
                }
            }
            self.last = Some(Instant::now());
            self.requests += 1;
            match crate::sources::download(&url, &headers, 20 * 1024 * 1024) {
                Ok(body) => {
                    self.failures = 0;
                    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
                    let cve = v["vulnerabilities"][0]["cve"].clone();
                    if cve.is_null() {
                        return None;
                    }
                    let _ = std::fs::create_dir_all(&self.cache_dir);
                    let _ = std::fs::write(&file, serde_json::to_vec(&cve).unwrap_or_default());
                    return Some(cve);
                }
                Err(e) => tracing::warn!("NVD-Abfrage {id} fehlgeschlagen (Versuch {}): {e:#}", attempt + 1),
            }
        }
        self.failures += 1;
        if self.failures >= 3 {
            tracing::warn!("NVD wiederholt nicht erreichbar – nur noch Cache");
            self.offline = true;
        }
        None
    }
}

// ------------------------------------------------------------------- winget

/// Lower-case display name -> winget package id (best effort, for the fix hint).
/// None: winget cannot be started at all (not installed, not on the PATH).
pub fn winget_ids() -> Option<HashMap<String, String>> {
    let out = std::process::Command::new("winget")
        .args(["list", "--accept-source-agreements", "--disable-interactivity"])
        .creation_flags(0x0800_0000 | 0x0000_4000)
        .output()
        .ok()?;
    Some(parse_winget_list(&String::from_utf8_lossy(&out.stdout)))
}

pub const WINGET_RULE: &str = "STOERUNG:WINGET";

/// winget is missing: K9 still finds outdated programs, but cannot name the command that
/// updates them. One message (the same identity every time), closed by K9 when winget is back.
pub fn winget_missing() -> crate::model::Finding {
    crate::model::Finding {
        path: std::path::PathBuf::from(t!("winget fehlt", "winget is missing")),
        sha256: crate::sha256_hex(b"stoerung|winget"),
        size: 0,
        rule_id: WINGET_RULE.into(),
        threat_name: t!("winget lässt sich nicht starten – Befehle zum Aktualisieren fehlen", "winget cannot be started – the commands for updating are missing").into(),
        category: t!("Störung", "Fault").into(),
        severity: crate::model::Severity::Niedrig,
        engine: "software".into(),
        kind: crate::model::Kind::Hinweis,
        details: Some(serde_json::json!({
            "hinweis": t!("K9 nutzt winget (den Paketmanager von Windows), um zu einem veralteten Programm den passenden Befehl zum Aktualisieren zu nennen. \
                        winget ließ sich nicht starten. Veraltete Programme meldet K9 weiterhin, aber ohne fertigen Befehl. \
                        Beheben: im Microsoft Store den „App-Installer“ installieren oder aktualisieren. Startet winget wieder, schließt K9 diese Meldung bei der nächsten Software-Prüfung von selbst.", "K9 uses winget (the package manager of Windows) to name the matching update command for an outdated program. \
                        winget could not be started. K9 still reports outdated programs, but without a ready-made command. \
                        To fix it: install or update the “App Installer” in the Microsoft Store. Once winget starts again, K9 closes this finding by itself at the next software check."),
        })),
    }
}

pub fn parse_winget_list(text: &str) -> HashMap<String, String> {
    let lines: Vec<&str> = text.lines().map(|l| l.rsplit('\r').next().unwrap_or(l)).collect();
    let Some(h) = lines.iter().position(|l| l.trim_start().starts_with("Name") && (l.contains(" ID ") || l.contains(" Id "))) else {
        return HashMap::new();
    };
    let header: Vec<char> = lines[h].chars().collect();
    let hs: String = header.iter().collect();
    let id_col = hs.find(" ID ").or_else(|| hs.find(" Id ")).map(|b| hs[..b].chars().count() + 1).unwrap_or(0);
    let ver_col = hs.find(" Version").map(|b| hs[..b].chars().count() + 1).unwrap_or(0);
    let mut map = HashMap::new();
    if id_col == 0 || ver_col <= id_col {
        return map;
    }
    for l in lines.iter().skip(h + 2) {
        let c: Vec<char> = l.chars().collect();
        if c.len() <= id_col {
            continue;
        }
        let name: String = c[..id_col].iter().collect::<String>().trim().trim_end_matches('…').to_string();
        let id: String = c[id_col..ver_col.min(c.len())].iter().collect::<String>().trim().to_string();
        if !name.is_empty() && !id.is_empty() && !id.contains(' ') {
            map.insert(name.to_lowercase(), id);
        }
    }
    map
}

fn fix_hint(sw: &Installed, winget: &HashMap<String, String>) -> String {
    let lname = sw.name.to_lowercase();
    let id = winget.get(&lname).or_else(|| winget.iter().find(|(n, _)| n.len() >= 10 && lname.starts_with(n.as_str())).map(|(_, id)| id));
    match id {
        Some(id) if !id.starts_with("ARP\\") && !id.starts_with("MSIX\\") => format!("winget upgrade --id {id} -e"),
        _ => t!("Aktuelle Version vom Hersteller installieren (oder über die Update-Funktion des Programms).", "Install the current version from the publisher (or via the update function of the program).").into(),
    }
}

// --------------------------------------------------------------- the check

pub struct CheckStats {
    pub programs: usize,
    pub candidates: usize,
    pub nvd_requests: usize,
    pub nvd_offline: bool,
}

/// Runs the check. `fetch` returns the NVD `cve` object for a CVE id.
pub fn check(
    software: &[Installed],
    kev: &[KevEntry],
    fetch: &mut dyn FnMut(&str) -> Option<serde_json::Value>,
    winget: &HashMap<String, String>,
    progress: &mut dyn FnMut(usize, usize),
) -> (Vec<Finding>, usize) {
    let work: Vec<(&Installed, Vec<&KevEntry>)> =
        software.iter().map(|s| (s, kev_candidates(s, kev))).filter(|(_, c)| !c.is_empty()).collect();
    let total: usize = work.iter().map(|(_, c)| c.len()).sum();
    let mut done = 0;
    let mut out = Vec::new();
    for (sw, cands) in work {
        let mut hits = Vec::new();
        let mut confidence = "hoch";
        let mut ransomware = false;
        for k in cands {
            done += 1;
            progress(done, total);
            let Some(nvd) = fetch(&k.cve) else { continue };
            let verdict = evaluate_nvd(&nvd, sw);
            let fixed = match &verdict {
                Verdict::Affected { fixed_in } => fixed_in.clone(),
                Verdict::AllVersions => {
                    confidence = "mittel";
                    None
                }
                _ => continue,
            };
            ransomware |= k.ransomware;
            hits.push(serde_json::json!({
                "cve": k.cve,
                "name": k.name,
                "kev": true,
                "schwere": nvd_severity(&nvd).unwrap_or_else(|| "unbekannt".into()),
                "behoben_ab": fixed,
                "massnahme": k.action,
                "ransomware": k.ransomware,
            }));
        }
        if hits.is_empty() {
            continue;
        }
        let ids: BTreeSet<String> = hits.iter().filter_map(|h| h["cve"].as_str().map(str::to_string)).collect();
        let first = ids.iter().next().cloned().unwrap_or_default();
        let fix = fix_hint(sw, winget);
        out.push(Finding {
            path: PathBuf::from(format!("Software: {} {}", sw.name, sw.version)),
            sha256: crate::sha256_hex(format!("software|{}|{}", sw.name, sw.version).as_bytes()),
            size: 0,
            rule_id: format!("CVE:{}", &crate::sha256_hex(ids.iter().cloned().collect::<Vec<_>>().join(",").as_bytes())[..12]),
            threat_name: if ids.len() == 1 {
                tf!("Verwundbare Software: {} {} – {first} (aktiv ausgenutzt)", "Vulnerable software: {} {} – {first} (actively exploited)", sw.name, sw.version)
            } else {
                tf!("Verwundbare Software: {} {} – {first} und {} weitere (aktiv ausgenutzt)", "Vulnerable software: {} {} – {first} and {} more (actively exploited)", sw.name, sw.version, ids.len() - 1)
            },
            category: t!("Schwachstelle (CVE)", "Vulnerability (CVE)").into(),
            severity: if ransomware { Severity::Kritisch } else { Severity::Hoch },
            engine: "kev".into(),
            kind: Kind::Software,
            details: Some(serde_json::json!({
                "produkt": sw.name, "version": sw.version, "hersteller": sw.publisher, "registry": sw.registry,
                "cves": hits, "konfidenz": confidence, "loesung": fix,
                "hinweis": if confidence == "hoch" { t!("Version liegt laut NVD im betroffenen Bereich.", "According to NVD the version is in the affected range.") } else { t!("NVD nennt das Produkt ohne Versionsangabe – bitte prüfen, ob deine Version betroffen ist.", "NVD names the product without a version – please check whether your version is affected.") }
            })),
        });
    }
    (out, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(name: &str, version: &str, publisher: &str) -> Installed {
        Installed { name: name.into(), version: version.into(), publisher: publisher.into(), registry: "HKLM\\Test".into() }
    }

    /// Fake KEV entry for a fake product.
    fn fake_kev() -> Vec<KevEntry> {
        parse_kev(
            br#"{"vulnerabilities":[
              {"cveID":"CVE-2099-0001","vendorProject":"Beispielhersteller","product":"Beispiel Werkzeug","vulnerabilityName":"Testluecke","knownRansomwareCampaignUse":"Known","requiredAction":"Update installieren"},
              {"cveID":"CVE-2099-0002","vendorProject":"Andere Firma","product":"Werkzeug","vulnerabilityName":"Passt nicht","knownRansomwareCampaignUse":"Unknown","requiredAction":"-"}
            ]}"#,
        )
        .unwrap()
    }

    fn fake_nvd(end_excluding: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "CVE-2099-0001",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:beispielhersteller:beispiel_werkzeug:*:*:*:*:*:*:*:*", "versionEndExcluding": end_excluding},
                {"vulnerable": true, "criteria": "cpe:2.3:a:anderer:produkt:*:*:*:*:*:*:*:*"}
            ]}]}]
        })
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(cmp_version("120.0.6099.62", "120.0.6099.130").is_lt());
        assert!(cmp_version("2.10", "2.9").is_gt());
        assert!(cmp_version("1.0", "1").is_eq());
    }

    #[test]
    fn candidates_need_vendor_and_product() {
        let kev = fake_kev();
        let s = sw("Beispiel Werkzeug 3 (x64)", "3.1.0", "Beispielhersteller GmbH");
        let c = kev_candidates(&s, &kev);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cve, "CVE-2099-0001");
        // Same product word but other vendor -> no candidate.
        assert!(kev_candidates(&sw("Werkzeug", "1", "Irgendwer"), &kev).is_empty());
        // Product word only inside another program's name -> no candidate.
        assert!(kev_candidates(&sw("Zusatz für Beispiel Werkzeug", "1", "Beispielhersteller"), &kev).is_empty());
    }

    #[test]
    fn generic_and_os_entries_are_skipped() {
        let kev = parse_kev(
            br#"{"vulnerabilities":[
              {"cveID":"CVE-2099-1","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"x"},
              {"cveID":"CVE-2099-2","vendorProject":"Microsoft","product":"Microsoft","vulnerabilityName":"x"},
              {"cveID":"CVE-2099-3","vendorProject":"Microsoft","product":"Office","vulnerabilityName":"x"},
              {"cveID":"CVE-2099-4","vendorProject":"Oracle","product":"Java SE","vulnerabilityName":"x"}
            ]}"#,
        )
        .unwrap();
        assert!(kev_candidates(&sw("Microsoft Windows Desktop Runtime - 8.0", "8.0", "Microsoft Corporation"), &kev).is_empty());
        assert!(kev_candidates(&sw("Microsoft Teams Meeting Add-in for Microsoft Office", "1", "Microsoft"), &kev).is_empty());
        assert_eq!(kev_candidates(&sw("Microsoft Office Professional Plus 2019", "16.0", "Microsoft Corporation"), &kev).len(), 1);
        assert_eq!(kev_candidates(&sw("Java(TM) SE Development Kit 17.0.4 (64-bit)", "17.0.4", "Oracle Corporation"), &kev).len(), 1);
    }

    #[test]
    fn affected_version_is_reported_with_fix() {
        let kev = fake_kev();
        let soft = vec![sw("Beispiel Werkzeug", "3.1.0", "Beispielhersteller GmbH"), sw("Harmlos", "1.0", "X")];
        let mut winget = HashMap::new();
        winget.insert("beispiel werkzeug".to_string(), "Beispiel.Werkzeug".to_string());
        let mut fetch = |_: &str| Some(fake_nvd("3.2.0"));
        let (f, total) = check(&soft, &kev, &mut fetch, &winget, &mut |_, _| {});
        assert_eq!(total, 1);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::Software);
        assert_eq!(f[0].severity, Severity::Kritisch, "Ransomware-Nutzung bekannt");
        let d = f[0].details.as_ref().unwrap();
        assert_eq!(d["konfidenz"], "hoch");
        assert_eq!(d["cves"][0]["schwere"], "CRITICAL");
        assert_eq!(d["cves"][0]["behoben_ab"], "3.2.0");
        assert_eq!(d["loesung"], "winget upgrade --id Beispiel.Werkzeug -e");
    }

    #[test]
    fn fixed_version_is_not_reported() {
        let kev = fake_kev();
        let soft = vec![sw("Beispiel Werkzeug", "3.2.0", "Beispielhersteller")];
        let mut fetch = |_: &str| Some(fake_nvd("3.2.0"));
        assert!(check(&soft, &kev, &mut fetch, &HashMap::new(), &mut |_, _| {}).0.is_empty());
        // Without NVD data nothing is reported (no guessing).
        let mut none = |_: &str| None;
        assert!(check(&soft, &kev, &mut none, &HashMap::new(), &mut |_, _| {}).0.is_empty());
    }

    #[test]
    fn winget_list_parsing() {
        let text = "Name                     ID                         Version     Verfügbar Quelle\n\
                    ------------------------------------------------------------------------------\n\
                    7-Zip 24.08 (x64)        7zip.7zip                  24.08                 winget\n\
                    Google Chrome            Google.Chrome.EXE          120.0.1     121.0     winget\n\
                    Irgendwas                ARP\\Machine\\X64\\Foo        1.0\n";
        let m = parse_winget_list(text);
        assert_eq!(m.get("7-zip 24.08 (x64)").map(String::as_str), Some("7zip.7zip"));
        assert_eq!(m.get("google chrome").map(String::as_str), Some("Google.Chrome.EXE"));
    }

    /// Diagnose on the real PC: VS_KEV=<path to KEV json>, run with --ignored --nocapture.
    #[test]
    #[ignore]
    fn candidate_report() {
        let kev = load_kev(Path::new(&std::env::var("VS_KEV").unwrap())).unwrap();
        let mut total = 0;
        for s in inventory() {
            let c = kev_candidates(&s, &kev);
            if !c.is_empty() {
                total += c.len();
                let mut prods: Vec<String> = c.iter().map(|k| format!("{}/{}", k.vendor, k.product)).collect();
                prods.sort();
                prods.dedup();
                eprintln!("{:>4}  {} {} [{}] -> {}", c.len(), s.name, s.version, s.publisher, prods.join("; "));
            }
        }
        eprintln!("gesamt {total}");
        // Verdicts from the local NVD cache (no network).
        let mut nvd = Nvd::new(Path::new(&std::env::var("VS_KEV").unwrap()).parent().unwrap().parent().unwrap());
        nvd.offline = true;
        for s in inventory() {
            for k in kev_candidates(&s, &kev) {
                let v = nvd.cve(&k.cve).map(|j| format!("{:?}", evaluate_nvd(&j, &s))).unwrap_or_else(|| "kein NVD-Cache".into());
                eprintln!("  {} {} – {}: {v}", s.name, s.version, k.cve);
            }
        }
    }

    #[test]
    fn inventory_reads_registry() {
        // Every Windows PC has at least some entries; just make sure parsing works.
        let inv = inventory();
        assert!(inv.iter().all(|s| !s.name.is_empty()));
    }
}
