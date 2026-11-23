//! New vulnerabilities (CVE) of severity High/Critical for installed programs – also when
//! they are not (yet) known to be exploited. Once a day the agent asks the NVD for the CVEs
//! published since the last check (4 requests) and compares the affected vendors, products
//! and versions (as stated by the manufacturer in the CVE) with the installed programs.
//! Nothing is installed or changed; the finding names the CVE and how to update.
//!
//! * installed version in a stated range / exactly stated -> finding (Critical: Hoch, High: Mittel)
//! * product stated without usable version                 -> finding one level lower, "bitte prüfen"
//! * product stated, installed version not among the stated ones but lower than the highest
//!   stated one -> quiet note in the dashboard only (older, unsupported versions are often
//!   affected too, but that is not certain)

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use crate::model::{Finding, Kind, Severity};
use crate::software::{cmp_version, ordered_tokens, tokens, Installed};

pub const META_KEY: &str = "neue_luecken_zuletzt";
const NVD: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// One version statement of a CVE ("affected" entries only).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Bereich {
    pub version: String,
    pub less_than: Option<String>,
    pub less_or_equal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Produkt {
    pub vendor: String,
    pub product: String,
    pub versions: Vec<Bereich>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Luecke {
    pub id: String,
    /// "CRITICAL" or "HIGH"
    pub schwere: String,
    pub score: Option<f64>,
    pub beschreibung: String,
    pub veroeffentlicht: String,
    pub produkte: Vec<Produkt>,
}

fn severity_of(cve: &serde_json::Value) -> Option<(String, Option<f64>)> {
    let m = &cve["metrics"];
    let mut best: Option<(String, Option<f64>)> = None;
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
        for e in m[key].as_array().into_iter().flatten() {
            let d = &e["cvssData"];
            let Some(s) = d["baseSeverity"].as_str() else { continue };
            let score = d["baseScore"].as_f64();
            if best.as_ref().is_none_or(|(_, b)| score > *b) {
                best = Some((s.to_uppercase(), score));
            }
        }
    }
    best
}

/// Parses an NVD answer (list of CVEs with the manufacturer's "affected" data).
pub fn parse_nvd(body: &[u8]) -> Vec<Luecke> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return Vec::new() };
    let mut out = Vec::new();
    for item in v["vulnerabilities"].as_array().into_iter().flatten() {
        let c = &item["cve"];
        let Some(id) = c["id"].as_str() else { continue };
        if matches!(c["vulnStatus"].as_str(), Some("Rejected")) {
            continue;
        }
        let Some((schwere, score)) = severity_of(c).filter(|(s, _)| s == "HIGH" || s == "CRITICAL") else { continue };
        let beschreibung = c["descriptions"].as_array().into_iter().flatten().find(|d| d["lang"] == "en").and_then(|d| d["value"].as_str()).unwrap_or("").to_string();
        let mut produkte = Vec::new();
        for src in c["affected"].as_array().into_iter().flatten() {
            for a in src["affectedData"].as_array().into_iter().flatten() {
                let (Some(vendor), Some(product)) = (a["vendor"].as_str(), a["product"].as_str()) else { continue };
                let versions = a["versions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|x| x["status"].as_str().is_none_or(|s| s == "affected"))
                    .map(|x| Bereich {
                        version: x["version"].as_str().unwrap_or("").to_string(),
                        less_than: x["lessThan"].as_str().map(str::to_string),
                        less_or_equal: x["lessThanOrEqual"].as_str().map(str::to_string),
                    })
                    .collect();
                produkte.push(Produkt { vendor: vendor.to_string(), product: product.to_string(), versions });
            }
        }
        if produkte.is_empty() {
            continue;
        }
        out.push(Luecke { id: id.to_string(), schwere, score, beschreibung, veroeffentlicht: c["published"].as_str().unwrap_or("").to_string(), produkte });
    }
    out
}

/// Does the stated vendor/product describe this installed program? The vendor words must be
/// in the publisher or name; the product words (without the vendor's own words and tiny words
/// like "SE") must all be in the name and start it ("Oracle Java SE" -> "Java 8 Update 513").
pub fn matches(sw: &Installed, vendor: &str, product: &str) -> bool {
    let name = tokens(&sw.name);
    let mut both = name.clone();
    both.extend(tokens(&sw.publisher));
    let v = tokens(vendor);
    if v.is_empty() || !v.iter().all(|t| both.contains(t)) {
        return false;
    }
    let all: Vec<String> = ordered_tokens(product).into_iter().filter(|t| t.len() >= 3).collect();
    let mut p: Vec<String> = all.iter().filter(|t| !v.contains(*t)).cloned().collect();
    if p.is_empty() {
        p = all; // product named like its vendor ("Git", "PuTTY")
    }
    // The operating system itself and names without a distinctive word are not matched.
    if p.is_empty() || matches!(p[0].as_str(), "windows" | "win32k" | "kernel" | "server" | "client" | "driver" | "service" | "vpn" | "sdk" | "api" | "app" | "web" | "pro") {
        return false;
    }
    if !p.iter().all(|t| name.contains(t)) {
        return false;
    }
    // The first product word must be among the first words of the program name (after the vendor).
    let words: Vec<String> = ordered_tokens(&sw.name).into_iter().filter(|w| !v.contains(w) || p.contains(w)).collect();
    words.iter().take(2).any(|w| *w == p[0])
}

#[derive(Debug, Clone, PartialEq)]
pub enum Urteil {
    /// The installed version is stated as affected.
    Betroffen { behoben_ab: Option<String> },
    /// The product is stated without a usable version.
    OhneVersion,
    /// Not among the stated versions, but lower than the highest stated one.
    NichtGenannt { genannt: String },
    Nein,
}

fn unspecific(v: &str) -> bool {
    matches!(v.trim().to_lowercase().as_str(), "" | "*" | "0" | "n/a" | "na" | "unspecified" | "unknown" | "all" | "all versions" | "-")
}

fn has_digit(v: &str) -> bool {
    v.chars().any(|c| c.is_ascii_digit())
}

pub fn judge(p: &Produkt, installed: &str) -> Urteil {
    use std::cmp::Ordering::*;
    if p.versions.is_empty() {
        return Urteil::OhneVersion;
    }
    let mut without_version = false;
    let mut exact: Vec<&str> = Vec::new();
    for b in &p.versions {
        let end = b.less_than.as_deref().map(|e| (e, false)).or(b.less_or_equal.as_deref().map(|e| (e, true)));
        match end {
            Some((e, inclusive)) if has_digit(e) => {
                if installed.is_empty() || !has_digit(installed) {
                    without_version = true;
                    continue;
                }
                let from_ok = unspecific(&b.version) || !has_digit(&b.version) || cmp_version(installed, &b.version) != Less;
                let to_ok = match cmp_version(installed, e) {
                    Less => true,
                    Equal => inclusive,
                    Greater => false,
                };
                if from_ok && to_ok {
                    return Urteil::Betroffen { behoben_ab: (!inclusive).then(|| e.to_string()) };
                }
            }
            // "all versions" style statements
            Some(_) => without_version = true,
            None if unspecific(&b.version) || !has_digit(&b.version) => without_version = true,
            None => {
                if !installed.is_empty() && cmp_version(installed, &b.version) == Equal {
                    return Urteil::Betroffen { behoben_ab: None };
                }
                exact.push(&b.version);
            }
        }
    }
    if without_version {
        return Urteil::OhneVersion;
    }
    // Only exact versions are stated: an installed version of the same release line (same
    // first number) below a stated one may be an older, unsupported release – a quiet note,
    // not a claim. Other release lines (Java 21 for an installed Java 8) say nothing.
    let major = |v: &str| v.split(|c: char| !c.is_ascii_digit()).find(|p| !p.is_empty()).map(str::to_string);
    let same_line: Vec<&str> = exact.iter().copied().filter(|e| major(e).is_some() && major(e) == major(installed)).collect();
    if !installed.is_empty() && has_digit(installed) && same_line.iter().any(|e| cmp_version(installed, e) == Less) {
        return Urteil::NichtGenannt { genannt: same_line.join(", ") };
    }
    Urteil::Nein
}

fn short(text: &str) -> String {
    let t: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > 220 {
        format!("{}…", t.chars().take(220).collect::<String>())
    } else {
        t
    }
}

fn fix_hint(sw: &Installed, winget: &HashMap<String, String>) -> String {
    let lname = sw.name.to_lowercase();
    let id = winget.get(&lname).or_else(|| winget.iter().find(|(n, _)| n.len() >= 10 && lname.starts_with(n.as_str())).map(|(_, id)| id));
    match id {
        Some(id) if !id.starts_with("ARP\\") && !id.starts_with("MSIX\\") => format!("winget upgrade --id {id} -e"),
        _ => t!("Aktuelle Version vom Hersteller installieren (oder über die Update-Funktion des Programms).", "Install the current version from the publisher (or via the update function of the program).").into(),
    }
}

/// The version to compare. Oracle names Java 8 "8u513", Windows lists it as "8.0.5130.4":
/// "Java 8 Update 513" is compared as "8.513".
pub fn comparable_version(sw: &Installed) -> String {
    let words: Vec<&str> = sw.name.split_whitespace().collect();
    if let [first, major, update, n, ..] = words.as_slice() {
        if first.to_lowercase().starts_with("java") && update.eq_ignore_ascii_case("update") && major.chars().all(|c| c.is_ascii_digit()) && n.chars().all(|c| c.is_ascii_digit()) {
            return format!("{major}.{n}");
        }
    }
    sw.version.clone()
}

/// Compares the new CVEs with the installed programs: at most one loud and one quiet finding
/// per program (several CVEs are listed in it).
pub fn check(software: &[Installed], cves: &[Luecke], winget: &HashMap<String, String>) -> Vec<Finding> {
    // (program index, quiet) -> hits
    let mut groups: BTreeMap<(usize, bool), Vec<(&Luecke, Urteil)>> = BTreeMap::new();
    for (i, sw) in software.iter().enumerate() {
        for c in cves {
            let mut best: Option<Urteil> = None;
            for p in c.produkte.iter().filter(|p| matches(sw, &p.vendor, &p.product)) {
                let u = judge(p, &comparable_version(sw));
                let rank = |u: &Urteil| match u {
                    Urteil::Betroffen { .. } => 3,
                    Urteil::OhneVersion => 2,
                    Urteil::NichtGenannt { .. } => 1,
                    Urteil::Nein => 0,
                };
                if best.as_ref().is_none_or(|b| rank(&u) > rank(b)) {
                    best = Some(u);
                }
            }
            match best {
                Some(Urteil::Nein) | None => {}
                Some(u) => groups.entry((i, matches!(u, Urteil::NichtGenannt { .. }))).or_default().push((c, u)),
            }
        }
    }
    let mut out = Vec::new();
    for ((i, quiet), hits) in groups {
        let sw = &software[i];
        let ids: BTreeSet<&str> = hits.iter().map(|(c, _)| c.id.as_str()).collect();
        let first = ids.iter().next().copied().unwrap_or("");
        let critical = hits.iter().any(|(c, _)| c.schwere == "CRITICAL");
        let certain = hits.iter().any(|(_, u)| matches!(u, Urteil::Betroffen { .. }));
        let severity = match (quiet, certain, critical) {
            (true, _, _) => Severity::Niedrig,
            (false, true, true) => Severity::Hoch,
            (false, true, false) | (false, false, true) => Severity::Mittel,
            (false, false, false) => Severity::Niedrig,
        };
        let list: Vec<serde_json::Value> = hits
            .iter()
            .map(|(c, u)| {
                serde_json::json!({
                    "cve": c.id,
                    "name": short(&c.beschreibung),
                    "kev": false,
                    "schwere": match c.score { Some(s) => format!("{} {s:.1}", c.schwere), None => c.schwere.clone() },
                    "behoben_ab": match u { Urteil::Betroffen { behoben_ab } => behoben_ab.clone(), _ => None },
                    "genannt": match u { Urteil::NichtGenannt { genannt } => Some(genannt.clone()), _ => None },
                    "veroeffentlicht": c.veroeffentlicht,
                    "ransomware": false,
                })
            })
            .collect();
        let (konfidenz, hinweis) = if quiet {
            ("niedrig", t!("Der Hersteller nennt dein Programm als betroffen, aber nicht genau deine Version (genannt sind nur neuere Stände). Ältere, nicht mehr gepflegte Versionen sind oft ebenfalls betroffen – bitte prüfen und aktualisieren. Noch nicht als aktiv ausgenutzt bekannt.", "The publisher names your program as affected, but not exactly your version (only newer releases are named). Older versions that are no longer maintained are often affected as well – please check and update. Not yet known to be actively exploited."))
        } else if certain {
            ("hoch", t!("Deine Version liegt laut Hersteller im betroffenen Bereich. Noch nicht als aktiv ausgenutzt bekannt – bitte bald aktualisieren.", "According to the publisher your version is in the affected range. Not yet known to be actively exploited – please update soon."))
        } else {
            ("mittel", t!("Der Hersteller nennt das Produkt ohne genaue Versionsangabe – bitte prüfen, ob deine Version betroffen ist. Noch nicht als aktiv ausgenutzt bekannt.", "The publisher names the product without an exact version – please check whether your version is affected. Not yet known to be actively exploited."))
        };
        let what = if quiet { t!("Mögliche neue Sicherheitslücke", "Possible new vulnerability") } else { t!("Neue Sicherheitslücke", "New vulnerability") };
        let mut details = serde_json::json!({
            "produkt": sw.name, "version": sw.version, "hersteller": sw.publisher, "registry": sw.registry,
            "cves": list, "konfidenz": konfidenz, "loesung": fix_hint(sw, winget), "hinweis": hinweis,
        });
        if quiet {
            details[crate::arbeitsordner::LEISE] = t!("nur ein Hinweis: deine Version ist nicht ausdrücklich als betroffen genannt", "only a note: your version is not explicitly named as affected").into();
        }
        out.push(Finding {
            path: PathBuf::from(format!("Software: {} {}", sw.name, sw.version)),
            sha256: crate::sha256_hex(format!("cve-neu|{}|{}|{}", sw.name, sw.version, ids.iter().copied().collect::<Vec<_>>().join(",")).as_bytes()),
            size: 0,
            rule_id: format!("CVE-NEU:{}", &crate::sha256_hex(ids.iter().copied().collect::<Vec<_>>().join(",").as_bytes())[..12]),
            threat_name: if ids.len() == 1 {
                format!("{what}: {} {} – {first}", sw.name, sw.version)
            } else {
                tf!("{what}: {} {} – {first} und {} weitere", "{what}: {} {} – {first} and {} more", sw.name, sw.version, ids.len() - 1)
            },
            category: t!("Schwachstelle (CVE)", "Vulnerability (CVE)").into(),
            severity,
            engine: "nvd".into(),
            kind: Kind::Software,
            details: Some(details),
        });
    }
    out
}

// ------------------------------------------------------------------ EPSS

const EPSS: &str = "https://api.first.org/data/v1/epss";

/// Answer of the EPSS interface of FIRST.org: CVE -> (probability of exploitation within the
/// next 30 days, share of all CVEs with a lower value), both 0..1.
pub fn parse_epss(body: &[u8]) -> HashMap<String, (f64, f64)> {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let num = |x: &serde_json::Value| x.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| x.as_f64()).filter(|n| (0.0..=1.0).contains(n));
    v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| Some((d["cve"].as_str()?.to_string(), (num(&d["epss"])?, num(&d["percentile"]).unwrap_or(0.0)))))
        .collect()
}

/// Asks FIRST.org for the EPSS values of these CVEs (only the few that concern installed
/// programs – the interface is meant for look-ups, not for copying everything). A failure
/// only means that the messages come without the estimate.
pub fn load_epss(ids: &[String]) -> HashMap<String, (f64, f64)> {
    let mut out = HashMap::new();
    for batch in ids.chunks(80) {
        match crate::sources::download(&format!("{EPSS}?cve={}", batch.join(",")), &[], 2 * 1024 * 1024) {
            Ok(body) => out.extend(parse_epss(&body)),
            Err(e) => tracing::info!("EPSS-Werte nicht abrufbar: {e:#}"),
        }
    }
    out
}

fn percent(p: f64) -> String {
    if p < 0.001 {
        "unter 0,1".into()
    } else {
        format!("{:.1}", p * 100.0).replace('.', ",")
    }
}

/// " – Ausnutzung in 30 Tagen: 12,3 % wahrscheinlich (höher als 97 % aller Lücken)"
pub fn epss_text(p: f64, rank: f64) -> String {
    tf!(" – Ausnutzung in 30 Tagen: {} % wahrscheinlich (höher als {:.0} % aller Lücken)", " – exploitation within 30 days: {} % likely (higher than {:.0} % of all vulnerabilities)", percent(p), (rank * 100.0).floor())
}

/// Adds the EPSS estimate to every CVE of the findings, puts the most likely ones first and
/// says in the hint what the highest value means. Identity and severity of a finding stay
/// as they are – the estimate informs, it does not decide.
pub fn annotate_epss(findings: &mut [Finding], scores: &HashMap<String, (f64, f64)>) {
    for f in findings {
        let Some(d) = f.details.as_mut() else { continue };
        let Some(list) = d["cves"].as_array_mut() else { continue };
        let mut best: Option<f64> = None;
        let mut all_known = true;
        for c in list.iter_mut() {
            let Some((p, rank)) = c["cve"].as_str().and_then(|id| scores.get(id)).copied() else {
                all_known = false;
                continue;
            };
            c["epss"] = serde_json::json!(p);
            c["epss_rang"] = serde_json::json!(rank);
            c["epss_text"] = epss_text(p, rank).into();
            best = Some(best.map_or(p, |b: f64| b.max(p)));
        }
        list.sort_by(|a, b| b["epss"].as_f64().unwrap_or(-1.0).total_cmp(&a["epss"].as_f64().unwrap_or(-1.0)));
        let Some(best) = best else { continue };
        let extra = if best >= 0.10 {
            tf!(" Dringend: Nach der Schätzung von FIRST.org (EPSS) wird mindestens eine dieser Lücken mit {} % Wahrscheinlichkeit in den nächsten 30 Tagen ausgenutzt.", " Urgent: according to the estimate of FIRST.org (EPSS), at least one of these vulnerabilities will be exploited within the next 30 days with a probability of {} %.", percent(best))
        } else if best < 0.01 {
            t!(" Nach der Schätzung von FIRST.org (EPSS) ist eine Ausnutzung in den nächsten 30 Tagen unwahrscheinlich (unter 1 %).", " According to the estimate of FIRST.org (EPSS), exploitation within the next 30 days is unlikely (below 1 %).").to_string()
        } else {
            tf!(" Schätzung von FIRST.org (EPSS): bis zu {} % Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen.", " Estimate of FIRST.org (EPSS): up to {} % probability of exploitation within the next 30 days.", percent(best))
        };
        let hint = format!("{}{extra}", d["hinweis"].as_str().unwrap_or(""));
        d["hinweis"] = hint.into();
        // Every CVE of the message is unlikely to be exploited soon: only quiet in the dashboard.
        if best < 0.01 && all_known && d.get(crate::arbeitsordner::LEISE).is_none() {
            d[crate::arbeitsordner::LEISE] = "Ausnutzung in den nächsten 30 Tagen unwahrscheinlich (EPSS unter 1 %)".into();
        }
    }
}

/// `check` results with the EPSS estimates added (one small request to FIRST.org).
pub fn with_epss(mut findings: Vec<Finding>) -> Vec<Finding> {
    let mut ids: Vec<String> = findings
        .iter()
        .filter_map(|f| f.details.as_ref())
        .flat_map(|d| d["cves"].as_array().into_iter().flatten().filter_map(|c| c["cve"].as_str().map(str::to_string)).collect::<Vec<_>>())
        .collect();
    ids.sort();
    ids.dedup();
    if !ids.is_empty() {
        let scores = load_epss(&ids);
        annotate_epss(&mut findings, &scores);
    }
    findings
}

/// The NVD addresses for CVEs published in a time window (UTC), one per severity and CVSS version.
pub fn window_urls(from: chrono::NaiveDateTime, to: chrono::NaiveDateTime) -> Vec<String> {
    let f = |t: chrono::NaiveDateTime| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
    ["cvssV3Severity=CRITICAL", "cvssV3Severity=HIGH", "cvssV4Severity=CRITICAL", "cvssV4Severity=HIGH"]
        .iter()
        .map(|s| format!("{NVD}?pubStartDate={}&pubEndDate={}&{s}&resultsPerPage=2000", f(from), f(to)))
        .collect()
}

/// Loads the CVEs of severity High/Critical published in the window (each CVE once).
/// Err: the NVD could not be reached (then the window is tried again next time).
pub fn load(from: chrono::NaiveDateTime, to: chrono::NaiveDateTime) -> Result<Vec<Luecke>, String> {
    let key = crate::secrets::get(crate::sources::NVD_KEY).ok().flatten();
    let headers: Vec<(&str, String)> = key.iter().map(|k| ("apiKey", k.clone())).collect();
    let gap = std::time::Duration::from_millis(if key.is_some() { 800 } else { 7000 });
    let mut out: Vec<Luecke> = Vec::new();
    for (i, url) in window_urls(from, to).iter().enumerate() {
        if i > 0 {
            std::thread::sleep(gap);
        }
        let mut body = None;
        for attempt in 0..3u64 {
            match crate::sources::download(url, &headers, 80 * 1024 * 1024) {
                Ok(b) => {
                    body = Some(b);
                    break;
                }
                Err(e) => {
                    tracing::debug!("NVD (neue Lücken), Versuch {}: {e:#}", attempt + 1);
                    std::thread::sleep(gap + std::time::Duration::from_secs(10 * (attempt + 1)));
                }
            }
        }
        let Some(body) = body else { return Err("NVD nicht erreichbar".into()) };
        for c in parse_nvd(&body) {
            if !out.iter().any(|x| x.id == c.id) {
                out.push(c);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(name: &str, version: &str, publisher: &str) -> Installed {
        Installed { name: name.into(), version: version.into(), publisher: publisher.into(), registry: String::new() }
    }

    const JAVA: &str = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-114938","published":"2026-11-17T21:32:03.183","vulnStatus":"Undergoing Analysis",
      "descriptions":[{"lang":"en","value":"Vulnerability in the Oracle Java SE product (component: Compiler)."}],
      "affected":[{"source":"x","affectedData":[
        {"vendor":"Oracle Corporation","product":"Oracle Java SE","versions":[{"version":"8u511b33-perf","status":"affected"},{"version":"17.0.21.0.3","status":"affected"}]},
        {"vendor":"Oracle Corporation","product":"Oracle GraalVM for JDK","versions":[{"version":"17.0.21.0.3","status":"affected"}]}]}],
      "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]}}},
      {"cve":{"id":"CVE-2026-1","vulnStatus":"Received","descriptions":[],"affected":[{"affectedData":[{"vendor":"A","product":"B","versions":[]}]}],
       "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]}}}]}"#;

    #[test]
    fn parses_only_high_and_critical_with_products() {
        let l = parse_nvd(JAVA.as_bytes());
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].id.as_str(), l[0].schwere.as_str(), l[0].produkte.len()), ("CVE-2026-114938", "HIGH", 2));
        assert_eq!(l[0].produkte[0].versions.len(), 2);
    }

    #[test]
    fn products_match_installed_programs_narrowly() {
        assert!(matches(&sw("Java 8 Update 513 (64-bit)", "8.0.5130.4", "Oracle Corporation"), "Oracle Corporation", "Oracle Java SE"));
        assert!(matches(&sw("Java(TM) SE Development Kit 17.0.12 (64-bit)", "17.0.12.0", "Oracle Corporation"), "Oracle Corporation", "Oracle Java SE"));
        assert!(!matches(&sw("Java 8 Update 513 (64-bit)", "8.0.5130.4", "Oracle Corporation"), "Oracle Corporation", "Oracle GraalVM for JDK"));
        assert!(!matches(&sw("Eclipse Temurin JDK mit Hotspot 17.0.21+9 (x64)", "17.0.21.9", "Eclipse Adoptium"), "Oracle Corporation", "Oracle Java SE"));
        assert!(matches(&sw("Mozilla Firefox (x64 de)", "133.0", "Mozilla"), "Mozilla", "Firefox"));
        assert!(!matches(&sw("Mozilla Thunderbird (x64 de)", "115.0", "Mozilla"), "Mozilla", "Firefox"));
        assert!(!matches(&sw("Microsoft Visual C++ 2015 Redistributable", "14.0", "Microsoft Corporation"), "Microsoft", "Windows 11"));
        assert!(!matches(&sw("Teams Add-in for Microsoft Office", "1.0", "Microsoft"), "Microsoft", "Office"));
        assert!(!matches(&sw("GitHub Desktop", "3.0", "GitHub, Inc."), "Git", "Git"), "Git ist nicht GitHub");
        assert!(matches(&sw("Git", "2.47.1", "The Git Development Community"), "Git", "Git"));
        assert!(matches(&sw("PuTTY release 0.83 (64-bit)", "0.83", "Simon Tatham"), "PuTTY", "PuTTY"));
    }

    #[test]
    fn versions_are_judged_carefully() {
        let range = Produkt { vendor: "V".into(), product: "P".into(), versions: vec![Bereich { version: "0".into(), less_than: Some("4.1.5".into()), less_or_equal: None }] };
        assert_eq!(judge(&range, "4.1.4"), Urteil::Betroffen { behoben_ab: Some("4.1.5".into()) });
        assert_eq!(judge(&range, "4.1.5"), Urteil::Nein);
        let incl = Produkt { versions: vec![Bereich { version: "2.0".into(), less_than: None, less_or_equal: Some("2.5".into()) }], ..range.clone() };
        assert_eq!(judge(&incl, "2.5"), Urteil::Betroffen { behoben_ab: None });
        assert_eq!(judge(&incl, "1.9"), Urteil::Nein);
        let exact = Produkt { versions: vec![Bereich { version: "17.0.21.0.3".into(), ..Default::default() }], ..range.clone() };
        assert_eq!(judge(&exact, "17.0.21.0.3"), Urteil::Betroffen { behoben_ab: None });
        assert_eq!(judge(&exact, "17.0.12.0"), Urteil::NichtGenannt { genannt: "17.0.21.0.3".into() });
        assert_eq!(judge(&exact, "17.0.22"), Urteil::Nein, "neuer als alles Genannte");
        assert_eq!(judge(&exact, "8.0.5130.4"), Urteil::Nein, "andere Versionslinie sagt nichts");
        let java8 = Produkt { versions: vec![Bereich { version: "8u511b33".into(), ..Default::default() }, Bereich { version: "21.0.13.0.3".into(), ..Default::default() }], ..range.clone() };
        let j = |n: &str, v: &str| comparable_version(&sw(n, v, "Oracle Corporation"));
        assert_eq!(j("Java 8 Update 513 (64-bit)", "8.0.5130.4"), "8.513");
        assert_eq!(judge(&java8, &j("Java 8 Update 513 (64-bit)", "8.0.5130.4")), Urteil::Nein, "8u513 ist neuer als 8u511");
        assert_eq!(judge(&java8, &j("Java 8 Update 361 (64-bit)", "8.0.3610.9")), Urteil::NichtGenannt { genannt: "8u511b33".into() });
        assert_eq!(j("7-Zip 26.06 (x64)", "26.06"), "26.06");
        let all = Produkt { versions: vec![Bereich { version: "unspecified".into(), ..Default::default() }], ..range.clone() };
        assert_eq!(judge(&all, "1.0"), Urteil::OhneVersion);
        assert_eq!(judge(&Produkt { versions: vec![], ..range }, "1.0"), Urteil::OhneVersion);
    }

    #[test]
    fn findings_loud_when_stated_quiet_when_only_possible() {
        let cves = parse_nvd(JAVA.as_bytes());
        let old = [sw("Java(TM) SE Development Kit 17.0.12 (64-bit)", "17.0.12.0", "Oracle Corporation")];
        let f = check(&old, &cves, &HashMap::new());
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].severity, f[0].kind), (Severity::Niedrig, Kind::Software));
        assert!(f[0].threat_name.starts_with("Mögliche neue Sicherheitslücke") && f[0].threat_name.contains("CVE-2026-114938"));
        assert!(crate::arbeitsordner::reason_of(f[0].details.as_ref()).is_some(), "nur leise im Dashboard");
        let hit = [sw("Java(TM) SE Development Kit 17.0.21.0.3", "17.0.21.0.3", "Oracle Corporation")];
        let f = check(&hit, &cves, &HashMap::new());
        assert_eq!(f[0].severity, Severity::Mittel, "High + sicher betroffen");
        assert!(crate::arbeitsordner::reason_of(f[0].details.as_ref()).is_none());
        assert!(check(&[sw("7-Zip 26.06 (x64)", "26.06", "Igor Pavlov")], &cves, &HashMap::new()).is_empty());
        let urls = window_urls(chrono::NaiveDate::from_ymd_opt(2026, 11, 17).unwrap().and_hms_opt(0, 0, 0).unwrap(), chrono::NaiveDate::from_ymd_opt(2026, 11, 18).unwrap().and_hms_opt(14, 0, 0).unwrap());
        assert_eq!(urls.len(), 4);
        assert!(urls[0].contains("pubStartDate=2026-11-17T00:00:00.000Z&pubEndDate=2026-11-18T14:00:00.000Z&cvssV3Severity=CRITICAL"));
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "fragt die NVD ab und liest die installierten Programme"]
    fn near_misses() {
        let now = chrono::Utc::now().naive_utc();
        let cves = super::load(now - chrono::Duration::days(14), now).unwrap();
        let inv = crate::software::inventory();
        let mut seen = std::collections::BTreeSet::new();
        for c in &cves {
            for p in &c.produkte {
                let v = crate::software::tokens(&p.vendor);
                for sw in &inv {
                    let mut both = crate::software::tokens(&sw.name);
                    both.extend(crate::software::tokens(&sw.publisher));
                    if !v.is_empty() && v.iter().all(|t| both.contains(t)) && seen.insert((p.vendor.clone(), p.product.clone(), sw.name.clone())) {
                        println!("{} | {} / {} | {} {} | passt={} | {:?}", c.id, p.vendor, p.product, sw.name, sw.version, super::matches(sw, &p.vendor, &p.product), super::judge(p, &super::comparable_version(sw)));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod epss_tests {
    use super::*;

    fn finding(cves: &[&str]) -> Finding {
        Finding {
            path: PathBuf::from("Software: Beispiel 1.0"),
            sha256: "x".into(),
            size: 0,
            rule_id: "CVE-NEU:test".into(),
            threat_name: "Neue Sicherheitslücke".into(),
            category: "Schwachstelle (CVE)".into(),
            severity: Severity::Mittel,
            engine: "nvd".into(),
            kind: Kind::Software,
            details: Some(serde_json::json!({ "cves": cves.iter().map(|c| serde_json::json!({ "cve": c })).collect::<Vec<_>>(), "hinweis": "Bitte bald aktualisieren." })),
        }
    }

    #[test]
    fn the_answer_of_first_org_is_read() {
        let body = br#"{"status":"OK","data":[{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-11-20"},{"cve":"CVE-2020-0601","epss":"0.890780000","percentile":"0.997850000"},{"cve":"CVE-0","epss":"7"}]}"#;
        let m = parse_epss(body);
        assert_eq!(m.len(), 2, "ein Wert außerhalb von 0 bis 1 wird verworfen");
        assert_eq!(m["CVE-2020-0601"], (0.89078, 0.99785));
        assert!(parse_epss(b"kein json").is_empty());
    }

    #[test]
    fn the_estimate_is_added_sorted_and_explained_without_changing_the_finding() {
        let mut f = vec![finding(&["CVE-1", "CVE-2", "CVE-3"]), finding(&["CVE-4"]), finding(&["CVE-9"])];
        let scores: HashMap<String, (f64, f64)> = [("CVE-1", (0.002, 0.40)), ("CVE-2", (0.123, 0.97)), ("CVE-4", (0.0004, 0.05))].into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let before: Vec<(String, Severity)> = f.iter().map(|x| (x.sha256.clone(), x.severity)).collect();
        annotate_epss(&mut f, &scores);
        assert_eq!(before, f.iter().map(|x| (x.sha256.clone(), x.severity)).collect::<Vec<_>>(), "Kennung und Schwere bleiben");
        let d = f[0].details.as_ref().unwrap();
        let order: Vec<&str> = d["cves"].as_array().unwrap().iter().map(|c| c["cve"].as_str().unwrap()).collect();
        assert_eq!(order, ["CVE-2", "CVE-1", "CVE-3"], "das Wahrscheinlichste zuerst, ohne Wert zuletzt");
        assert_eq!(d["cves"][0]["epss_text"], " – Ausnutzung in 30 Tagen: 12,3 % wahrscheinlich (höher als 97 % aller Lücken)");
        assert!(d["hinweis"].as_str().unwrap().starts_with("Bitte bald aktualisieren. Dringend:") && d["hinweis"].as_str().unwrap().contains("12,3 %"));
        let low = f[1].details.as_ref().unwrap();
        assert_eq!(low["cves"][0]["epss_text"], " – Ausnutzung in 30 Tagen: unter 0,1 % wahrscheinlich (höher als 5 % aller Lücken)");
        assert!(low["hinweis"].as_str().unwrap().contains("unwahrscheinlich"));
        assert!(low[crate::arbeitsordner::LEISE].as_str().unwrap().contains("EPSS unter 1 %"), "nur leise im Dashboard");
        assert!(d.get(crate::arbeitsordner::LEISE).is_none(), "12 % und eine Lücke ohne Wert: normal gemeldet");
        // One CVE below 1 %, the other without a value: stays a normal message.
        let mut mixed = vec![finding(&["CVE-4", "CVE-9"])];
        annotate_epss(&mut mixed, &scores);
        assert!(mixed[0].details.as_ref().unwrap().get(crate::arbeitsordner::LEISE).is_none());
        // No value known: nothing is added.
        assert_eq!(f[2].details.as_ref().unwrap()["hinweis"], "Bitte bald aktualisieren.");
        assert!(f[2].details.as_ref().unwrap()["cves"][0].get("epss_text").is_none());
    }
}
