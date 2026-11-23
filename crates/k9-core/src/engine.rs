//! Detection engines.
//!
//! Step 1 ships two minimal engines (SHA-256 hash list and byte patterns) to
//! exercise the whole pipeline. Step 2 plugs in ClamAV, YARA, abuse.ch etc.
//! by implementing [`Engine`]: the scanner streams each file once through all
//! engines, so adding an engine does not add extra disk reads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use memchr::memmem;

use crate::model::{category, Finding, Severity};

/// Metadata of the file currently being scanned.
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub path: PathBuf,
    pub size: u64,
}

/// A detection engine. Engines must be cheap to share between threads.
pub trait Engine: Send + Sync {
    /// Short identifier, stored with each finding.
    fn id(&self) -> &'static str;
    /// Starts scanning a file. Return `None` to skip the file entirely.
    fn begin<'a>(&'a self, meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>>;
    /// Rule hits in a block of process memory (rule id, readable name, severity); only
    /// rules with at least `min_score`. Engines without such rules return nothing.
    fn scan_memory(&self, _data: &[u8], _min_score: i64) -> Vec<(String, String, crate::model::Severity)> {
        Vec::new()
    }
}

/// Per-file state of an engine. `feed` receives the file content in order,
/// `finish` gets the final SHA-256 and returns the hits.
pub trait FileSession {
    fn feed(&mut self, _chunk: &[u8]) {}
    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding>;
}

// ---------------------------------------------------------------------------
// Harmless test signatures (instead of EICAR, which real AV products react to).
// Stored XOR-obfuscated so the scanner binaries do not contain the plain
// signature and therefore never detect themselves.
// ---------------------------------------------------------------------------

const OBF_KEY: u8 = 0x5A;

fn deobfuscate(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b ^ OBF_KEY).collect()
}

const fn obfuscate<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ OBF_KEY;
        i += 1;
    }
    out
}

// The const fn runs at compile time; only the XORed bytes end up in the binary.
const TEST_PATTERN_OBF: [u8; 28] = obfuscate(b"K9-TESTSIGNATUR-HARMLOS-2026");
const TEST_HASH_CONTENT_OBF: [u8; 24] = obfuscate(b"K9-HASHTEST-HARMLOS-2026");

/// The international EICAR anti-virus test string (harmless, used by external
/// test pages such as AMTSO/EICAR to check that a scanner reacts). Stored
/// XOR-obfuscated like our own test signature.
const EICAR_OBF: [u8; 68] = [0x02, 0x6f, 0x15, 0x7b, 0x0a, 0x7f, 0x1a, 0x1b, 0x0a, 0x01, 0x6e, 0x06, 0x0a, 0x00, 0x02, 0x6f, 0x6e, 0x72, 0x0a, 0x04, 0x73, 0x6d, 0x19, 0x19, 0x73, 0x6d, 0x27, 0x7e, 0x1f, 0x13, 0x19, 0x1b, 0x08, 0x77, 0x09, 0x0e, 0x1b, 0x14, 0x1e, 0x1b, 0x08, 0x1e, 0x77, 0x1b, 0x14, 0x0e, 0x13, 0x0c, 0x13, 0x08, 0x0f, 0x09, 0x77, 0x0e, 0x1f, 0x09, 0x0e, 0x77, 0x1c, 0x13, 0x16, 0x1f, 0x7b, 0x7e, 0x12, 0x71, 0x12, 0x70];

/// Rule id of the built-in EICAR detection.
pub const EICAR_RULE: &str = "EICAR-TEST";
/// Threat name of the built-in EICAR detection.
pub const EICAR_NAME: &str = "EICAR-Testdatei (harmloser Prüftext)";

/// Rule id of the built-in byte-pattern test signature.
pub const TEST_PATTERN_RULE: &str = "VS-TEST-0001";
/// Threat name of the built-in byte-pattern test signature.
pub const TEST_PATTERN_NAME: &str = "K9.Testsignatur.Muster (harmlos)";
/// Threat name of the built-in hash test entry.
pub const TEST_HASH_NAME: &str = "K9.Testsignatur.Hash (harmlos)";

/// Bytes that trigger the built-in pattern rule when contained anywhere in a file.
pub fn test_pattern_bytes() -> Vec<u8> {
    deobfuscate(&TEST_PATTERN_OBF)
}

/// Exact file content whose SHA-256 is on the built-in hash list.
pub fn test_hash_content() -> Vec<u8> {
    deobfuscate(&TEST_HASH_CONTENT_OBF)
}

// ---------------------------------------------------------------------------
// Hash list engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HashEntry {
    pub name: String,
    pub category: String,
    pub severity: Severity,
}

/// Matches the SHA-256 of whole files against a list.
pub struct HashListEngine {
    entries: HashMap<String, HashEntry>,
}

impl HashListEngine {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            crate::sha256_hex(&test_hash_content()),
            HashEntry { name: TEST_HASH_NAME.into(), category: category::TEST.into(), severity: Severity::Niedrig },
        );
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert(&mut self, sha256: &str, entry: HashEntry) {
        self.entries.insert(sha256.to_ascii_lowercase(), entry);
    }

    /// Loads a text file with lines `sha256;Name;Kategorie;Schweregrad`
    /// (only the hash is mandatory, `#` starts a comment).
    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path).with_context(|| format!("{} nicht lesbar", path.display()))?;
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(';').map(str::trim);
            let hash = parts.next().unwrap_or_default();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                tracing::warn!("Ungültiger Hash in {}: {line}", path.display());
                continue;
            }
            let name = parts.next().filter(|s| !s.is_empty()).unwrap_or("Unbekannt.Hashliste").to_string();
            let category = parts.next().filter(|s| !s.is_empty()).unwrap_or(category::MALWARE).to_string();
            let severity = parts.next().map(Severity::parse).unwrap_or(Severity::Hoch);
            self.insert(hash, HashEntry { name, category, severity });
            count += 1;
        }
        Ok(count)
    }
}

impl Default for HashListEngine {
    fn default() -> Self {
        Self::new()
    }
}

struct HashSession<'a> {
    engine: &'a HashListEngine,
}

impl FileSession for HashSession<'_> {
    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        match self.engine.entries.get(sha256) {
            Some(e) => vec![Finding {
                path: meta.path.clone(),
                sha256: sha256.to_string(),
                size: meta.size,
                rule_id: format!("HASH:{sha256}"),
                threat_name: e.name.clone(),
                category: e.category.clone(),
                severity: e.severity,
                engine: "hashliste".into(),
                kind: crate::model::Kind::Datei,
                details: None,
            }],
            None => Vec::new(),
        }
    }
}

impl Engine for HashListEngine {
    fn id(&self) -> &'static str {
        "hashliste"
    }
    fn begin<'a>(&'a self, _meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        if self.entries.is_empty() {
            None
        } else {
            Some(Box::new(HashSession { engine: self }))
        }
    }
}

// ---------------------------------------------------------------------------
// Byte pattern engine
// ---------------------------------------------------------------------------

pub struct PatternRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: Severity,
    pub pattern: Vec<u8>,
}

/// Searches files for byte sequences. Streams in chunks and keeps an overlap
/// so patterns spanning chunk borders are found.
pub struct PatternEngine {
    rules: Vec<(PatternRule, memmem::Finder<'static>)>,
    max_len: usize,
}

impl PatternEngine {
    pub fn new() -> Self {
        let mut engine = Self { rules: Vec::new(), max_len: 0 };
        engine.add(PatternRule {
            id: TEST_PATTERN_RULE.into(),
            name: TEST_PATTERN_NAME.into(),
            category: category::TEST.into(),
            severity: Severity::Niedrig,
            pattern: test_pattern_bytes(),
        });
        engine.add(PatternRule {
            id: EICAR_RULE.into(),
            name: EICAR_NAME.into(),
            category: category::TEST.into(),
            severity: Severity::Mittel,
            pattern: deobfuscate(&EICAR_OBF),
        });
        engine
    }

    pub fn add(&mut self, rule: PatternRule) {
        if rule.pattern.is_empty() {
            return;
        }
        self.max_len = self.max_len.max(rule.pattern.len());
        let finder = memmem::Finder::new(&rule.pattern).into_owned();
        self.rules.push((rule, finder));
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Loads lines `ID;Name;hex:4d5a90` or `ID;Name;text:irgendwas` (optional
    /// 4th/5th field: Kategorie, Schweregrad).
    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path).with_context(|| format!("{} nicht lesbar", path.display()))?;
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(5, ';').map(str::trim).collect();
            if parts.len() < 3 {
                tracing::warn!("Ungültige Musterzeile in {}: {line}", path.display());
                continue;
            }
            let pattern = if let Some(h) = parts[2].strip_prefix("hex:") {
                match hex::decode(h.replace(' ', "")) {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("Ungültiges Hex-Muster in {}: {line}", path.display());
                        continue;
                    }
                }
            } else if let Some(t) = parts[2].strip_prefix("text:") {
                t.as_bytes().to_vec()
            } else {
                tracing::warn!("Muster muss mit hex: oder text: beginnen: {line}");
                continue;
            };
            self.add(PatternRule {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                category: parts.get(3).filter(|s| !s.is_empty()).unwrap_or(&category::MALWARE).to_string(),
                severity: parts.get(4).map(|s| Severity::parse(s)).unwrap_or(Severity::Hoch),
                pattern,
            });
            count += 1;
        }
        Ok(count)
    }
}

impl Default for PatternEngine {
    fn default() -> Self {
        Self::new()
    }
}

struct PatternSession<'a> {
    engine: &'a PatternEngine,
    tail: Vec<u8>,
    hits: Vec<bool>,
}

impl FileSession for PatternSession<'_> {
    fn feed(&mut self, chunk: &[u8]) {
        if self.hits.iter().all(|h| *h) {
            return;
        }
        // Search in (tail of previous chunk + current chunk).
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        for (i, (_, finder)) in self.engine.rules.iter().enumerate() {
            if !self.hits[i] && finder.find(&window).is_some() {
                self.hits[i] = true;
            }
        }
        let keep = self.engine.max_len.saturating_sub(1).min(window.len());
        self.tail = window[window.len() - keep..].to_vec();
    }

    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        self.engine
            .rules
            .iter()
            .zip(self.hits.iter())
            .filter(|(_, hit)| **hit)
            .map(|((rule, _), _)| Finding {
                path: meta.path.clone(),
                sha256: sha256.to_string(),
                size: meta.size,
                rule_id: rule.id.clone(),
                threat_name: rule.name.clone(),
                category: rule.category.clone(),
                severity: rule.severity,
                engine: "muster".into(),
                kind: crate::model::Kind::Datei,
                details: None,
            })
            .collect()
    }
}

impl Engine for PatternEngine {
    fn id(&self) -> &'static str {
        "muster"
    }
    fn begin<'a>(&'a self, _meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        if self.rules.is_empty() {
            return None;
        }
        Some(Box::new(PatternSession { engine: self, tail: Vec::new(), hits: vec![false; self.rules.len()] }))
    }
}

// ---------------------------------------------------------------------------
// Bulk hash list (MalwareBazaar, ThreatFox): sorted 32-byte binary SHA-256
// values, binary search – about 32 MB RAM per million hashes, no per-entry
// allocations.
// ---------------------------------------------------------------------------

pub struct SortedHashEngine {
    id: &'static str,
    source_name: String,
    hashes: Vec<u8>,
}

impl SortedHashEngine {
    /// `hashes` must be sorted 32-byte blocks (see `sources::hashes_to_sorted_bin`).
    pub fn new(id: &'static str, source_name: &str, hashes: Vec<u8>) -> Self {
        Self { id, source_name: source_name.to_string(), hashes }
    }

    pub fn len(&self) -> usize {
        self.hashes.len() / 32
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.len() < 32
    }

    pub fn contains(&self, sha: &[u8; 32]) -> bool {
        let n = self.len();
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.hashes[mid * 32..mid * 32 + 32].cmp(&sha[..]) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }
}

struct SortedHashSession<'a> {
    engine: &'a SortedHashEngine,
}

impl FileSession for SortedHashSession<'_> {
    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        let mut raw = [0u8; 32];
        if hex::decode_to_slice(sha256, &mut raw).is_err() || !self.engine.contains(&raw) {
            return Vec::new();
        }
        // Community lists occasionally contain clean, validly signed files
        // (e.g. official installers). Still reported, but clearly marked.
        let signed = crate::autostart::is_signed(&meta.path);
        vec![Finding {
            path: meta.path.clone(),
            sha256: sha256.to_string(),
            size: meta.size,
            rule_id: format!("HASH:{}", self.engine.id),
            threat_name: if signed {
                tf!(
                    "In {} gelistet, aber gültig digital signiert – vermutlich Fehleintrag, bitte prüfen", "Listed in {}, but validly digitally signed – probably a wrong entry, please check",
                    self.engine.source_name
                )
            } else {
                tf!("Bekannte Schadsoftware ({})", "Known malware ({})", self.engine.source_name)
            },
            category: category::MALWARE.into(),
            severity: if signed { Severity::Niedrig } else { Severity::Hoch },
            engine: self.engine.id.into(),
            kind: crate::model::Kind::Datei,
            details: None,
        }]
    }
}

impl Engine for SortedHashEngine {
    fn id(&self) -> &'static str {
        self.id
    }
    fn begin<'a>(&'a self, _meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        (!self.is_empty()).then(|| Box::new(SortedHashSession { engine: self }) as Box<dyn FileSession + 'a>)
    }
}

/// Builds the default engine set: built-in test signatures plus the optional
/// user lists `hashliste.txt` and `muster.txt` in the signature folder.
pub fn default_engines(signature_dir: &Path) -> Vec<Box<dyn Engine>> {
    let mut hashes = HashListEngine::new();
    let hash_file = signature_dir.join("hashliste.txt");
    if hash_file.is_file() {
        match hashes.load_file(&hash_file) {
            Ok(n) => tracing::info!("{n} Hashes aus {} geladen", hash_file.display()),
            Err(e) => tracing::warn!("{e:#}"),
        }
    }
    let mut patterns = PatternEngine::new();
    let pattern_file = signature_dir.join("muster.txt");
    if pattern_file.is_file() {
        match patterns.load_file(&pattern_file) {
            Ok(n) => tracing::info!("{n} Muster aus {} geladen", pattern_file.display()),
            Err(e) => tracing::warn!("{e:#}"),
        }
    }
    vec![Box::new(hashes), Box::new(patterns)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(engine: &dyn Engine, chunks: &[&[u8]]) -> Vec<Finding> {
        let meta = FileMeta { path: "x".into(), size: 0 };
        let mut s = engine.begin(&meta).unwrap();
        let mut all = Vec::new();
        for c in chunks {
            s.feed(c);
            all.extend_from_slice(c);
        }
        s.finish(&meta, &crate::sha256_hex(&all))
    }

    #[test]
    fn eicar_string_is_recognised_but_not_in_clear_text() {
        let e = deobfuscate(&EICAR_OBF);
        assert_eq!(e.len(), 68);
        assert_eq!(crate::sha256_hex(&e), "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        let hits = run(&PatternEngine::new(), &[&e]);
        assert!(hits.iter().any(|f| f.rule_id == EICAR_RULE));
    }

    #[test]
    fn pattern_found_across_chunk_border() {
        let p = test_pattern_bytes();
        let (a, b) = p.split_at(10);
        let mut first = b"vorher ".to_vec();
        first.extend_from_slice(a);
        let hits = run(&PatternEngine::new(), &[&first, b, b" danach"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, TEST_PATTERN_RULE);
    }

    #[test]
    fn pattern_not_found_in_clean_data() {
        assert!(run(&PatternEngine::new(), &[b"harmlose Datei", b"K9-TESTSIGNATUR-"]).is_empty());
    }

    #[test]
    fn hash_list_matches_exact_content_only() {
        let content = test_hash_content();
        let hits = run(&HashListEngine::new(), &[&content]);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].rule_id.starts_with("HASH:"));
        let mut changed = content.clone();
        changed.push(b'\n');
        assert!(run(&HashListEngine::new(), &[&changed]).is_empty());
    }

    #[test]
    fn signature_not_stored_in_plain_text() {
        let plain = test_pattern_bytes();
        assert_ne!(&TEST_PATTERN_OBF[..], &plain[..]);
    }

    #[test]
    fn sorted_hash_engine_matches() {
        let content = b"gefaelschte Schadsoftware fuer den Test";
        let sha = crate::sha256_hex(content);
        let text = format!("{}\n{sha}\n{}\n", "f".repeat(64), "1".repeat(64));
        let engine = SortedHashEngine::new("malwarebazaar", "MalwareBazaar", crate::sources::hashes_to_sorted_bin(&text));
        assert_eq!(engine.len(), 3);
        let hits = run(&engine, &[content]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "HASH:malwarebazaar");
        assert!(run(&engine, &[b"harmlos"]).is_empty());
    }

    #[test]
    fn load_user_lists() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let hf = dir.path().join("h.txt");
        std::fs::write(&hf, format!("# Kommentar\n{};Test.Eins;Test;niedrig\nkaputt\n", "a".repeat(64))).unwrap();
        let mut h = HashListEngine::new();
        assert_eq!(h.load_file(&hf).unwrap(), 1);
        let pf = dir.path().join("m.txt");
        std::fs::write(&pf, "X-1;Hex;hex:4d 5a 90\nX-2;Text;text:boese\nX-3;kaputt\n").unwrap();
        let mut p = PatternEngine::new();
        assert_eq!(p.load_file(&pf).unwrap(), 2);
        assert_eq!(run(&p, &[b"..MZ\x90.."]).len(), 1);
    }
}
