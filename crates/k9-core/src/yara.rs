//! YARA engine based on yara-x (pure Rust). Rules come from YARA Forge and
//! are compiled once at update time; scans load the compiled form.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::engine::{Engine, FileMeta, FileSession};
use crate::model::{Finding, Kind, Severity};

pub struct Compiled {
    pub bytes: Vec<u8>,
    pub count: usize,
}

/// Compiles YARA source. Fails if the source has errors (the caller keeps
/// the previous rule set in that case).
pub fn compile(source: &str) -> Result<Compiled> {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler.error_on_slow_pattern(false);
    if let Err(e) = compiler.add_source(source) {
        bail!("YARA-Regeln lassen sich nicht übersetzen: {e}");
    }
    let rules = compiler.build();
    let count = rules.iter().len();
    let bytes = rules.serialize().context("YARA-Regeln können nicht gespeichert werden")?;
    Ok(Compiled { bytes, count })
}

pub struct YaraEngine {
    rules: yara_x::Rules,
    min_score: i64,
}

impl YaraEngine {
    pub fn from_compiled(bytes: &[u8], min_score: i64) -> Result<Self> {
        let rules = yara_x::Rules::deserialize(bytes).context("Kompilierte YARA-Regeln sind beschädigt – bitte 'k9 quellen aktualisieren'")?;
        Ok(Self { rules, min_score })
    }

    pub fn from_source(source: &str, min_score: i64) -> Result<Self> {
        Self::from_compiled(&compile(source)?.bytes, min_score)
    }

    pub fn load(file: &Path, min_score: i64) -> Result<Self> {
        let bytes = std::fs::read(file).with_context(|| format!("{} fehlt", file.display()))?;
        Self::from_compiled(&bytes, min_score)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().len()
    }
}

struct YaraSession<'a> {
    engine: &'a YaraEngine,
}

fn severity_from_score(score: i64) -> Severity {
    match score {
        s if s >= 90 => Severity::Kritisch,
        s if s >= 75 => Severity::Hoch,
        s if s >= 50 => Severity::Mittel,
        _ => Severity::Niedrig,
    }
}

impl FileSession for YaraSession<'_> {
    fn finish(self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        let mut scanner = yara_x::Scanner::new(&self.engine.rules);
        scanner.set_timeout(Duration::from_secs(20));
        let results = match scanner.scan_file(&meta.path) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("YARA-Scan von {} fehlgeschlagen: {e}", meta.path.display());
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut score: Option<i64> = None;
            let mut description = String::new();
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("score", yara_x::MetaValue::Integer(s)) => score = Some(s),
                    ("description", yara_x::MetaValue::String(d)) => description = d.to_string(),
                    _ => {}
                }
            }
            // Rules without score are treated as medium confidence.
            let score = score.unwrap_or(60);
            if score < self.engine.min_score {
                continue;
            }
            let name = if description.is_empty() {
                format!("YARA: {}", rule.identifier())
            } else {
                format!("YARA: {} – {}", rule.identifier(), description.chars().take(120).collect::<String>())
            };
            out.push(Finding {
                path: meta.path.clone(),
                sha256: sha256.to_string(),
                size: meta.size,
                rule_id: format!("YARA:{}:{}", rule.namespace(), rule.identifier()),
                threat_name: name,
                category: crate::model::category::MALWARE.into(),
                severity: severity_from_score(score),
                engine: "yara".into(),
                kind: Kind::Datei,
                details: Some(serde_json::json!({ "score": score })),
            });
        }
        out
    }
}

impl Engine for YaraEngine {
    fn id(&self) -> &'static str {
        "yara"
    }
    fn scan_memory(&self, data: &[u8], min_score: i64) -> Vec<(String, String, Severity)> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(Duration::from_secs(20));
        let Ok(results) = scanner.scan(data) else { return Vec::new() };
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut score: Option<i64> = None;
            let mut description = String::new();
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("score", yara_x::MetaValue::Integer(s)) => score = Some(s),
                    ("description", yara_x::MetaValue::String(d)) => description = d.to_string(),
                    _ => {}
                }
            }
            // In memory only rules that state a high score themselves.
            let Some(score) = score.filter(|s| *s >= min_score.max(self.min_score)) else { continue };
            let name = if description.is_empty() { rule.identifier().to_string() } else { format!("{} – {}", rule.identifier(), description.chars().take(120).collect::<String>()) };
            out.push((format!("{}:{}", rule.namespace(), rule.identifier()), name, severity_from_score(score)));
        }
        out
    }

    fn begin<'a>(&'a self, meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        // Very large files are left to ClamAV/hashes; YARA loads files into memory.
        if meta.size > 64 * 1024 * 1024 {
            return None;
        }
        Some(Box::new(YaraSession { engine: self }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_pattern_bytes;

    /// Test rule built at runtime from the obfuscated test signature.
    fn test_rule(score: i64) -> String {
        let hex: Vec<String> = test_pattern_bytes().iter().map(|b| format!("{b:02X}")).collect();
        format!(
            "rule K9_Test {{\n meta:\n  description = \"Harmlose Testsignatur\"\n  score = {score}\n strings:\n  $a = {{ {} }}\n condition:\n  $a\n}}\n",
            hex.join(" ")
        )
    }

    fn scan(engine: &YaraEngine, path: &Path) -> Vec<Finding> {
        let meta = FileMeta { path: path.to_path_buf(), size: std::fs::metadata(path).unwrap().len() };
        engine.begin(&meta).unwrap().finish(&meta, "00")
    }

    #[test]
    fn compiles_serializes_and_matches() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let hit = dir.path().join("treffer.bin");
        let mut data = b"vorher ".to_vec();
        data.extend(test_pattern_bytes());
        std::fs::write(&hit, data).unwrap();
        let clean = dir.path().join("sauber.bin");
        std::fs::write(&clean, b"nichts").unwrap();

        let c = compile(&test_rule(80)).unwrap();
        assert_eq!(c.count, 1);
        let engine = YaraEngine::from_compiled(&c.bytes, 60).unwrap();
        let f = scan(&engine, &hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "YARA:default:K9_Test");
        assert_eq!(f[0].severity, Severity::Hoch);
        assert!(f[0].threat_name.contains("Harmlose Testsignatur"));
        assert!(scan(&engine, &clean).is_empty());
        // Rules below the minimum score are ignored.
        let low = YaraEngine::from_source(&test_rule(30), 60).unwrap();
        assert!(scan(&low, &hit).is_empty());
    }

    #[test]
    fn broken_rules_are_rejected() {
        assert!(compile("rule kaputt { condition: $nicht_definiert }").is_err());
    }

    /// Manual check against a downloaded YARA Forge package:
    /// set VS_YARA_FORGE=<path to .yar> and run with --ignored.
    #[test]
    #[ignore]
    fn yara_forge_package_compiles() {
        let p = std::env::var("VS_YARA_FORGE").expect("VS_YARA_FORGE setzen");
        let src = std::fs::read_to_string(p).unwrap();
        let start = std::time::Instant::now();
        let c = compile(&src).unwrap();
        eprintln!("{} Regeln in {:?}, {} KB", c.count, start.elapsed(), c.bytes.len() / 1024);
    }
}
