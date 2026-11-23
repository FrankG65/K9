//! Malicious/phishing URL checks (on demand): browser history (Chrome, Edge,
//! Brave, Vivaldi, Opera, Firefox – read from a temporary copy, read-only),
//! .url/.html/.eml/.svg files and the hosts file. Lists: URLhaus, OpenPhish,
//! ThreatFox. Everything stays local – nothing is uploaded.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::engine::{Engine, FileMeta, FileSession};
use crate::model::{Finding, Kind, Severity};
use crate::sources;

/// Normalizes a URL for comparison: lower-case scheme and host, default
/// port and trailing slash of an empty path removed, fragment dropped.
pub fn normalize(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches(['"', '\'', ')', '>', ',', ';']);
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let authority = authority.rsplit('@').next().unwrap_or("").to_ascii_lowercase();
    let authority = match (scheme.as_str(), authority.rsplit_once(':')) {
        ("http", Some((h, "80"))) | ("https", Some((h, "443"))) => h.to_string(),
        _ => authority,
    };
    if authority.is_empty() {
        return None;
    }
    let path = if path == "/" { "" } else { path };
    Some(format!("{scheme}://{authority}{path}"))
}

pub fn host_of(normalized: &str) -> &str {
    let rest = normalized.split_once("://").map(|(_, r)| r).unwrap_or(normalized);
    let auth = rest.split(['/', '?']).next().unwrap_or("");
    auth.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(auth)
}

/// Extracts http(s) URLs from text.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("http") {
        let start = pos + i;
        let tail = &text[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`' | '\\' | '{' | '}' | '|' | '^'))
            .unwrap_or(tail.len());
        if let Some(n) = normalize(&tail[..end]) {
            out.push(n);
        }
        pos = start + end.max(4);
        if pos >= lower.len() {
            break;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Known malicious URLs and domains.
#[derive(Default)]
pub struct UrlDb {
    urls: HashMap<String, &'static str>,
    domains: HashMap<String, &'static str>,
}

impl UrlDb {
    pub fn load(sources_dir: &Path) -> Self {
        let mut db = Self::default();
        if let Ok(t) = std::fs::read_to_string(sources_dir.join(sources::URLHAUS_FILE)) {
            db.add_urls(t.lines(), "URLhaus");
        }
        if let Ok(t) = std::fs::read_to_string(sources_dir.join(sources::OPENPHISH_FILE)) {
            db.add_urls(t.lines(), "OpenPhish");
        }
        for (value, ioc) in sources::load_threatfox(sources_dir) {
            match ioc.typ.as_str() {
                "url" => db.add_urls(std::iter::once(value.as_str()), "ThreatFox"),
                "domain" => {
                    db.domains.insert(value.to_ascii_lowercase(), "ThreatFox");
                }
                _ => {}
            }
        }
        db
    }

    pub fn add_urls<'a>(&mut self, urls: impl Iterator<Item = &'a str>, source: &'static str) {
        for u in urls {
            if let Some(n) = normalize(u) {
                self.urls.insert(n, source);
            }
        }
    }

    pub fn add_domain(&mut self, domain: &str, source: &'static str) {
        self.domains.insert(domain.to_ascii_lowercase(), source);
    }

    pub fn len(&self) -> usize {
        self.urls.len() + self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exact URL match, or the host is a known malicious domain (ThreatFox).
    /// Hosts of URLhaus/OpenPhish URLs are NOT blocked as a whole, because
    /// many are hacked legitimate sites – this keeps false alarms low.
    pub fn lookup(&self, url: &str) -> Option<&'static str> {
        let n = normalize(url)?;
        if let Some(s) = self.urls.get(&n) {
            return Some(s);
        }
        let host = host_of(&n);
        self.domains.get(host).copied()
    }

    /// Hosts that occur in any list (for the hosts-file check).
    fn all_hosts(&self) -> HashSet<String> {
        let mut h: HashSet<String> = self.urls.keys().map(|u| host_of(u).to_string()).collect();
        h.extend(self.domains.keys().cloned());
        h
    }
}

// ----------------------------------------------------------- file engine

/// Looks for known malicious URLs inside shortcut/HTML/e-mail/SVG files.
pub struct UrlFileEngine {
    db: UrlDb,
}

impl UrlFileEngine {
    pub fn new(db: UrlDb) -> Self {
        Self { db }
    }
}

const URL_FILE_EXT: [&str; 7] = ["url", "html", "htm", "eml", "svg", "mht", "website"];

struct UrlFileSession<'a> {
    engine: &'a UrlFileEngine,
    buf: Vec<u8>,
}

impl FileSession for UrlFileSession<'_> {
    fn feed(&mut self, chunk: &[u8]) {
        let room = (8 * 1024 * 1024usize).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&self.buf);
        let mut out = Vec::new();
        for url in extract_urls(&text) {
            if let Some(source) = self.engine.db.lookup(&url) {
                out.push(Finding {
                    path: meta.path.clone(),
                    sha256: sha256.to_string(),
                    size: meta.size,
                    rule_id: format!("URL:{source}"),
                    threat_name: tf!("Datei enthält bekannte Schad-/Phishing-Adresse ({source}): {url}", "File contains a known malicious/phishing address ({source}): {url}"),
                    category: t!("Phishing/Schad-URL", "Phishing/malicious URL").into(),
                    severity: Severity::Hoch,
                    engine: "urls".into(),
                    kind: Kind::Datei,
                    details: Some(serde_json::json!({ "url": url, "quelle": source })),
                });
                break; // one finding per file is enough
            }
        }
        out
    }
}

impl Engine for UrlFileEngine {
    fn id(&self) -> &'static str {
        "urls"
    }
    fn begin<'a>(&'a self, meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        if self.db.is_empty() || meta.size > 32 * 1024 * 1024 {
            return None;
        }
        let ext = meta.path.extension()?.to_string_lossy().to_ascii_lowercase();
        URL_FILE_EXT.contains(&ext.as_str()).then(|| Box::new(UrlFileSession { engine: self, buf: Vec::new() }) as Box<dyn FileSession + 'a>)
    }
}

// --------------------------------------------------------- browser history

/// A history database found on this PC.
#[derive(Debug, Clone)]
pub struct HistoryDb {
    pub browser: String,
    pub profile: String,
    pub path: PathBuf,
    pub firefox: bool,
}

pub fn find_histories() -> Vec<HistoryDb> {
    let mut out = Vec::new();
    let local = crate::paths::user_dir("LOCALAPPDATA");
    let roaming = crate::paths::user_dir("APPDATA");
    let chromium = [
        ("Chrome", local.as_ref().map(|l| l.join("Google\\Chrome\\User Data"))),
        ("Edge", local.as_ref().map(|l| l.join("Microsoft\\Edge\\User Data"))),
        ("Brave", local.as_ref().map(|l| l.join("BraveSoftware\\Brave-Browser\\User Data"))),
        ("Vivaldi", local.as_ref().map(|l| l.join("Vivaldi\\User Data"))),
    ];
    for (browser, base) in chromium {
        let Some(base) = base else { continue };
        for e in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let hist = e.path().join("History");
            if (name == "Default" || name.starts_with("Profile ")) && hist.is_file() {
                out.push(HistoryDb { browser: browser.into(), profile: name, path: hist, firefox: false });
            }
        }
    }
    if let Some(r) = &roaming {
        let opera = r.join("Opera Software\\Opera Stable\\History");
        if opera.is_file() {
            out.push(HistoryDb { browser: "Opera".into(), profile: "Standard".into(), path: opera, firefox: false });
        }
        for e in std::fs::read_dir(r.join("Mozilla\\Firefox\\Profiles")).into_iter().flatten().flatten() {
            let places = e.path().join("places.sqlite");
            if places.is_file() {
                out.push(HistoryDb {
                    browser: "Firefox".into(),
                    profile: e.file_name().to_string_lossy().to_string(),
                    path: places,
                    firefox: true,
                });
            }
        }
    }
    out
}

/// Reads the newest `limit` URLs from a temporary copy of the database.
pub fn read_history(h: &HistoryDb, limit: usize) -> Result<Vec<String>> {
    let tmp = std::env::temp_dir().join(format!("vs-verlauf-{}", hex::encode(crate::random_bytes(6))));
    std::fs::create_dir_all(&tmp)?;
    let result = (|| -> Result<Vec<String>> {
        let name = h.path.file_name().unwrap_or_default();
        let copy = tmp.join(name);
        std::fs::copy(&h.path, &copy)?;
        for suffix in ["-wal", "-journal"] {
            let side = PathBuf::from(format!("{}{suffix}", h.path.display()));
            if side.is_file() {
                let _ = std::fs::copy(&side, tmp.join(format!("{}{suffix}", name.to_string_lossy())));
            }
        }
        let conn = rusqlite::Connection::open_with_flags(&copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let sql = if h.firefox {
            "SELECT url FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT ?1"
        } else {
            "SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT ?1"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([limit as i64], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

pub fn history_findings(db: &UrlDb, histories: &[HistoryDb]) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for h in histories {
        match read_history(h, 50_000) {
            Ok(urls) => {
                for url in urls {
                    if let Some(source) = db.lookup(&url) {
                        let n = normalize(&url).unwrap_or(url.clone());
                        out.push(Finding {
                            path: PathBuf::from(tf!("Browserverlauf {} ({}): {n}", "Browser history {} ({}): {n}", h.browser, h.profile)),
                            sha256: crate::sha256_hex(format!("verlauf|{n}").as_bytes()),
                            size: 0,
                            rule_id: format!("URL:{source}"),
                            threat_name: tf!("Bekannte Schad-/Phishing-Adresse besucht ({source})", "Known malicious/phishing address visited ({source})"),
                            category: t!("Phishing/Schad-URL", "Phishing/malicious URL").into(),
                            severity: Severity::Mittel,
                            engine: "urls".into(),
                            kind: Kind::Url,
                            details: Some(serde_json::json!({
                                "url": n, "browser": h.browser, "profil": h.profile, "quelle": source,
                                "hinweis": t!("Falls dort Zugangsdaten eingegeben wurden: Passwort ändern.", "If sign-in data was entered there: change the password.")
                            })),
                        });
                    }
                }
            }
            Err(e) => errors.push(format!("{} ({}): {e:#}", h.browser, h.profile)),
        }
    }
    (out, errors)
}

// ---------------------------------------------------------------- hosts file

pub fn hosts_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("System32\\drivers\\etc\\hosts")
}

fn is_blocking_ip(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "0.0.0.0" || ip == "::1" || ip == "::" || ip == "0:0:0:0:0:0:0:1"
}

/// Hosts-file entries that redirect a known malicious host, or redirect any
/// public name to a non-local address (classic hijack technique).
pub fn hosts_findings(db: &UrlDb, text: &str) -> Vec<Finding> {
    let known = db.all_hosts();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts {
            let host = host.to_ascii_lowercase();
            if host == "localhost" || host.ends_with(".local") || host.ends_with(".localhost") {
                continue;
            }
            let (rule, name, sev) = if known.contains(&host) && !is_blocking_ip(ip) {
                ("HOSTS:BEKANNT", tf!("hosts-Datei leitet bekannte Schad-Adresse {host} nach {ip} um", "hosts file redirects the known malicious address {host} to {ip}"), Severity::Hoch)
            } else if !is_blocking_ip(ip) && host.contains('.') {
                ("HOSTS:UMLEITUNG", tf!("hosts-Datei leitet {host} nach {ip} um", "hosts file redirects {host} to {ip}"), Severity::Niedrig)
            } else {
                continue;
            };
            out.push(Finding {
                path: PathBuf::from(tf!("hosts-Datei: {ip} {host}", "hosts file: {ip} {host}")),
                sha256: crate::sha256_hex(format!("hosts|{ip}|{host}").as_bytes()),
                size: 0,
                rule_id: rule.into(),
                threat_name: name,
                category: t!("Umleitung", "Redirection").into(),
                severity: sev,
                engine: "hosts".into(),
                kind: Kind::Url,
                details: Some(serde_json::json!({
                    "ip": ip, "host": host, "datei": hosts_path().display().to_string(),
                    "hinweis": t!("Wenn du den Eintrag nicht selbst angelegt hast: Zeile in der hosts-Datei (als Administrator) entfernen.", "If you did not create the entry yourself: remove the line in the hosts file (as administrator).")
                })),
            });
        }
    }
    out
}

// ------------------------------------------------------------- network IOCs

/// Malicious domains and IPs for the real-time network check
/// (ThreatFox domains/IPs, URLhaus host list, IP hosts of URLhaus URLs).
#[derive(Default)]
pub struct NetDb {
    domains: HashMap<String, &'static str>,
    ips: HashMap<std::net::Ipv4Addr, &'static str>,
    /// Keys of the large optional domain list (`sperrlisten`), empty when switched off.
    big_domains: Vec<u64>,
    /// Address ranges of Spamhaus DROP, empty when switched off.
    drop_ranges: Vec<(u32, u32)>,
}

impl NetDb {
    pub fn load(sources_dir: &Path) -> Self {
        let mut db = Self::default();
        // First, so that the other lists win for the same domain. A whole public
        // suffix (shared hosting) is never taken over.
        if let Ok(t) = std::fs::read_to_string(sources_dir.join(crate::phishing::PHISHFILTER_FILE)) {
            for h in t.lines().filter(|h| !crate::phishing::is_public_suffix(h)) {
                db.add_domain(h, crate::phishing::PHISHFILTER_SOURCE);
            }
        }
        for (value, ioc) in sources::load_threatfox(sources_dir) {
            match ioc.typ.as_str() {
                "domain" => db.add_domain(&value, "ThreatFox"),
                "ip" => {
                    if let Some(ip) = value.split(':').next().and_then(|s| s.parse().ok()) {
                        db.ips.insert(ip, "ThreatFox");
                    }
                }
                _ => {}
            }
        }
        if let Ok(t) = std::fs::read_to_string(sources_dir.join(sources::URLHAUS_HOSTS_FILE)) {
            for h in t.lines() {
                db.add_domain(h, "URLhaus");
            }
        }
        if let Ok(t) = std::fs::read_to_string(sources_dir.join(sources::URLHAUS_FILE)) {
            for u in t.lines() {
                if let Some(n) = normalize(u) {
                    if let Ok(ip) = host_of(&n).parse::<std::net::Ipv4Addr>() {
                        db.ips.insert(ip, "URLhaus");
                    }
                }
            }
        }
        db
    }

    /// The usual lists plus the optional large ones that are switched on in `cfg`.
    pub fn load_with(sources_dir: &Path, cfg: &crate::config::QuellenConfig) -> Self {
        let mut db = Self::load(sources_dir);
        if cfg.hagezi_tif_aktiv {
            db.big_domains = crate::sperrlisten::load_keys(&sources_dir.join(crate::sperrlisten::TIF_FILE));
        }
        if cfg.spamhaus_drop_aktiv {
            db.drop_ranges = crate::sperrlisten::load_drop(&sources_dir.join(crate::sperrlisten::DROP_FILE));
        }
        db
    }

    pub fn add_domain(&mut self, d: &str, source: &'static str) {
        let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.contains('.') {
            if let Ok(ip) = d.parse::<std::net::Ipv4Addr>() {
                self.ips.insert(ip, source);
            } else {
                self.domains.insert(d, source);
            }
        }
    }

    pub fn add_ip(&mut self, ip: std::net::Ipv4Addr, source: &'static str) {
        self.ips.insert(ip, source);
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.big_domains.is_empty() && self.drop_ranges.is_empty()
    }

    /// Exact domain or one of its parent domains (sub.evil.example -> evil.example). The
    /// specific lists win; the large optional list is asked last.
    pub fn lookup_domain<'a>(&'a self, name: &'a str) -> Option<(&'a str, &'static str)> {
        let name = name.trim_end_matches('.');
        let mut cur = name;
        loop {
            if let Some((k, s)) = self.domains.get_key_value(cur) {
                return Some((k.as_str(), *s));
            }
            match cur.find('.') {
                Some(i) if cur[i + 1..].contains('.') => cur = &cur[i + 1..],
                _ => break,
            }
        }
        crate::sperrlisten::listed_parent(&self.big_domains, name).map(|d| (d, crate::sperrlisten::TIF_SOURCE))
    }

    pub fn lookup_ip(&self, ip: &std::net::Ipv4Addr) -> Option<&'static str> {
        self.ips.get(ip).copied().or_else(|| crate::sperrlisten::in_ranges(&self.drop_ranges, ip).then_some(crate::sperrlisten::DROP_SOURCE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAD: &str = "http://beispiel-phishing.invalid/login.php?x=1";

    fn db() -> UrlDb {
        let mut db = UrlDb::default();
        db.add_urls([BAD, "https://Schad.Invalid:443/a"].into_iter(), "Test");
        db.add_domain("boese-domain.invalid", "ThreatFox");
        db
    }

    #[test]
    fn normalization_and_lookup() {
        assert_eq!(normalize("HTTP://Example.COM:80/").as_deref(), Some("http://example.com"));
        assert_eq!(normalize("https://a.b/x#frag").as_deref(), Some("https://a.b/x"));
        assert_eq!(normalize("ftp://a.b"), None);
        let db = db();
        assert_eq!(db.lookup("HTTP://beispiel-phishing.invalid/login.php?x=1"), Some("Test"));
        assert_eq!(db.lookup("https://schad.invalid/a"), Some("Test"));
        assert_eq!(db.lookup("https://irgendwas.boese-domain.invalid/"), None, "nur exakte Domains");
        assert_eq!(db.lookup("https://boese-domain.invalid/egal"), Some("ThreatFox"));
        // Same host, other path: no hit (hacked legitimate sites).
        assert_eq!(db.lookup("http://beispiel-phishing.invalid/"), None);
    }

    #[test]
    fn extracts_urls_from_text() {
        let t = format!("<a href=\"{BAD}\">klick</a> und https://ok.example/ sowie (http://x.y/z)");
        let urls = extract_urls(&t);
        assert!(urls.contains(&normalize(BAD).unwrap()));
        assert!(urls.contains(&"https://ok.example".to_string()));
        assert!(urls.contains(&"http://x.y/z".to_string()));
    }

    #[test]
    fn url_file_engine_flags_shortcut() {
        let engine = UrlFileEngine::new(db());
        let meta = FileMeta { path: "C:\\x\\Bank.url".into(), size: 50 };
        let mut s = engine.begin(&meta).unwrap();
        s.feed(format!("[InternetShortcut]\nURL={BAD}\n").as_bytes());
        let f = s.finish(&meta, "ab");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::Datei);
        assert!(engine.begin(&FileMeta { path: "C:\\x\\bild.png".into(), size: 5 }).is_none());
    }

    #[test]
    fn history_from_chrome_and_firefox_copies() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let chrome = dir.path().join("History");
        let c = rusqlite::Connection::open(&chrome).unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE urls(url TEXT, last_visit_time INTEGER); INSERT INTO urls VALUES('https://harmlos.example/', 2), ('{BAD}', 1);"
        ))
        .unwrap();
        drop(c);
        let ff_dir = dir.path().join("ff");
        std::fs::create_dir_all(&ff_dir).unwrap();
        let ff = ff_dir.join("places.sqlite");
        let c = rusqlite::Connection::open(&ff).unwrap();
        c.execute_batch("CREATE TABLE moz_places(url TEXT, last_visit_date INTEGER); INSERT INTO moz_places VALUES('https://schad.invalid/a', 5), ('https://nie.example/', NULL);")
            .unwrap();
        drop(c);
        let hs = vec![
            HistoryDb { browser: "Chrome".into(), profile: "Default".into(), path: chrome.clone(), firefox: false },
            HistoryDb { browser: "Firefox".into(), profile: "p".into(), path: ff, firefox: true },
        ];
        let (f, errors) = history_findings(&db(), &hs);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.kind == Kind::Url));
        // Original database untouched (read from a copy).
        assert!(chrome.exists());
    }

    #[test]
    fn network_ioc_lookup() {
        // fake malicious domain and IP as from a fake DNS feed
        let mut db = NetDb::default();
        db.add_domain("boese-c2.invalid", "Test");
        db.add_ip("203.0.113.66".parse().unwrap(), "Test");
        assert_eq!(db.lookup_domain("boese-c2.invalid").map(|x| x.1), Some("Test"));
        assert_eq!(db.lookup_domain("cdn.boese-c2.invalid.").map(|x| x.0), Some("boese-c2.invalid"));
        assert!(db.lookup_domain("invalid").is_none());
        assert!(db.lookup_domain("harmlos.example").is_none());
        assert_eq!(db.lookup_ip(&"203.0.113.66".parse().unwrap()), Some("Test"));
        assert!(db.lookup_ip(&"203.0.113.67".parse().unwrap()).is_none());
        // The optional large lists: asked after the specific ones.
        let (_, keys) = crate::sperrlisten::parse_tif("gross-liste.invalid\nboese-c2.invalid\n");
        db.big_domains = keys;
        db.drop_ranges = vec![(u32::from(std::net::Ipv4Addr::new(198, 51, 100, 0)), u32::from(std::net::Ipv4Addr::new(198, 51, 100, 255)))];
        assert_eq!(db.lookup_domain("x.gross-liste.invalid"), Some(("gross-liste.invalid", crate::sperrlisten::TIF_SOURCE)));
        assert_eq!(db.lookup_domain("boese-c2.invalid").map(|x| x.1), Some("Test"), "die genauere Liste gewinnt");
        assert_eq!(db.lookup_ip(&"198.51.100.9".parse().unwrap()), Some(crate::sperrlisten::DROP_SOURCE));
        assert_eq!(db.lookup_ip(&"203.0.113.66".parse().unwrap()), Some("Test"));
    }

    #[test]
    fn hosts_file_checks() {
        let text = "# Kommentar\n127.0.0.1 localhost\n0.0.0.0 werbung.example\n10.0.0.5 meinnas.example\n1.2.3.4 boese-domain.invalid\n";
        let f = hosts_findings(&db(), text);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.rule_id == "HOSTS:BEKANNT" && x.severity == Severity::Hoch));
        assert!(f.iter().any(|x| x.rule_id == "HOSTS:UMLEITUNG" && x.severity == Severity::Niedrig));
    }
}
