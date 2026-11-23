//! Two large public block lists for the network checks, both optional:
//!
//! * HaGeZi "Threat Intelligence Feeds" (medium version): domains of malware, phishing and
//!   scam sites, several hundred thousand entries. Kept as sorted 64-bit keys (a few
//!   megabytes instead of a string per domain); an entry also covers its sub-domains.
//! * Spamhaus DROP: IPv4 networks that are hijacked or run by criminals.
//!
//! Licences: HaGeZi lists GPL-3.0 (loaded at update time, never shipped with K9);
//! Spamhaus DROP free of charge, Spamhaus must be credited.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Context, Result};

pub const TIF_URL: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt";
/// Sorted, unique 64-bit keys, little endian.
pub const TIF_FILE: &str = "hagezi/tif_medium.bin";
pub const TIF_SOURCE: &str = "HaGeZi TIF";

pub const DROP_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
pub const DROP_FILE: &str = "spamhaus/drop_v4.json";
pub const DROP_SOURCE: &str = "Spamhaus DROP";

/// Key of a domain: the first eight bytes of its SHA-256 (lower case, no trailing dot).
pub fn domain_key(domain: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(domain.trim_end_matches('.').to_ascii_lowercase().as_bytes());
    u64::from_le_bytes(d[..8].try_into().expect("acht Bytes"))
}

fn plausible_domain(d: &str) -> bool {
    d.len() <= 253 && d.contains('.') && !d.starts_with('.') && !d.ends_with('.') && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

/// Reads the list as published ("# Version: …" header, one domain per line, optionally
/// with a leading "*."). Returns the version and the sorted keys. A whole public suffix
/// (shared hosting such as `github.io`) is never taken over.
pub fn parse_tif(text: &str) -> (String, Vec<u64>) {
    let mut version = String::new();
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(c) = line.strip_prefix('#') {
            if let Some(v) = c.trim().strip_prefix("Version:") {
                version = v.trim().to_string();
            }
            continue;
        }
        let d = line.strip_prefix("*.").unwrap_or(line).to_ascii_lowercase();
        if plausible_domain(&d) && d.parse::<Ipv4Addr>().is_err() && !crate::phishing::is_public_suffix(&d) {
            keys.push(domain_key(&d));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    (version, keys)
}

pub fn encode_keys(keys: &[u64]) -> Vec<u8> {
    keys.iter().flat_map(|k| k.to_le_bytes()).collect()
}

/// The keys of the file; empty if it is missing or damaged.
pub fn load_keys(path: &Path) -> Vec<u64> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    if data.len() % 8 != 0 {
        tracing::warn!("{}: Länge passt nicht – Liste nicht geladen", path.display());
        return Vec::new();
    }
    let keys: Vec<u64> = data.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect();
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        tracing::warn!("{}: nicht sortiert – Liste nicht geladen", path.display());
        return Vec::new();
    }
    keys
}

/// The listed domain that covers `name`: the name itself or one of its parent domains
/// (never a bare top-level label). The result is a part of `name`.
pub fn listed_parent<'a>(keys: &[u64], name: &'a str) -> Option<&'a str> {
    if keys.is_empty() {
        return None;
    }
    let mut cur = name.trim_end_matches('.');
    loop {
        if keys.binary_search(&domain_key(cur)).is_ok() {
            return Some(cur);
        }
        match cur.find('.') {
            Some(i) if cur[i + 1..].contains('.') => cur = &cur[i + 1..],
            _ => return None,
        }
    }
}

/// Reads Spamhaus' `drop_v4.json` (one JSON object per line, the last one metadata).
/// Returns the networks as sorted, inclusive address ranges and the time stamp of the list.
pub fn parse_drop(text: &str) -> Result<(Vec<(u32, u32)>, i64)> {
    let mut ranges = Vec::new();
    let mut stamp = 0i64;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).context("Spamhaus DROP: Zeile nicht lesbar")?;
        if v["type"] == "metadata" {
            stamp = v["timestamp"].as_i64().unwrap_or(0);
            continue;
        }
        let Some(cidr) = v["cidr"].as_str() else { continue };
        let (addr, bits) = cidr.split_once('/').context("Spamhaus DROP: Netz ohne Länge")?;
        let addr: Ipv4Addr = addr.parse().with_context(|| format!("Spamhaus DROP: Adresse {addr}"))?;
        let bits: u32 = bits.parse().with_context(|| format!("Spamhaus DROP: Länge {bits}"))?;
        // Nothing wider than a /8: a mistake in the list must not flag half the internet.
        if !(8..=32).contains(&bits) {
            bail!("Spamhaus DROP: unplausibles Netz {cidr}");
        }
        let mask = u32::MAX << (32 - bits);
        let start = u32::from(addr) & mask;
        ranges.push((start, start | !mask));
    }
    ranges.sort_unstable();
    Ok((ranges, stamp))
}

/// The ranges of the stored file; empty if it is missing or unreadable.
pub fn load_drop(path: &Path) -> Vec<(u32, u32)> {
    std::fs::read_to_string(path).ok().and_then(|t| parse_drop(&t).ok()).map(|(r, _)| r).unwrap_or_default()
}

pub fn in_ranges(ranges: &[(u32, u32)], ip: &Ipv4Addr) -> bool {
    let x = u32::from(*ip);
    // The last range that starts at or before the address.
    let i = ranges.partition_point(|(start, _)| *start <= x);
    i > 0 && ranges[i - 1].1 >= x
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "# Title: Test\n# Version: 2026.1120.2303.06\n# Number of entries: 3\n#\n*.boese.example\nschlimm.test.invalid\nGross.Example\n\nnicht_gueltig\n203.0.113.5\ngithub.io\n";

    #[test]
    fn the_domain_list_becomes_sorted_keys_and_covers_sub_domains() {
        let (version, keys) = parse_tif(LIST);
        assert_eq!(version, "2026.1120.2303.06");
        assert_eq!(keys.len(), 3, "ohne Leerzeile, Wort ohne Punkt, IP-Adresse und gemeinsam genutzte Endung");
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(listed_parent(&keys, "boese.example"), Some("boese.example"));
        assert_eq!(listed_parent(&keys, "a.b.BOESE.example."), Some("BOESE.example"), "Unterdomain, Groß-/Kleinschreibung, Punkt am Ende");
        assert_eq!(listed_parent(&keys, "gross.example"), Some("gross.example"));
        assert_eq!(listed_parent(&keys, "harmlos.example"), None);
        assert_eq!(listed_parent(&keys, "nutzer.github.io"), None, "eine ganze gemeinsam genutzte Endung wird nie übernommen");
        assert_eq!(listed_parent(&keys, "example"), None);
        assert_eq!(listed_parent(&[], "boese.example"), None);
    }

    #[test]
    fn keys_survive_the_file_and_a_damaged_file_loads_nothing() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let (_, keys) = parse_tif(LIST);
        let file = dir.path().join("tif.bin");
        std::fs::write(&file, encode_keys(&keys)).unwrap();
        assert_eq!(load_keys(&file), keys);
        std::fs::write(&file, &encode_keys(&keys)[..10]).unwrap();
        assert!(load_keys(&file).is_empty(), "abgeschnitten");
        let mut wrong = keys.clone();
        wrong.reverse();
        std::fs::write(&file, encode_keys(&wrong)).unwrap();
        assert!(load_keys(&file).is_empty(), "unsortiert");
        assert!(load_keys(&dir.path().join("fehlt.bin")).is_empty());
    }

    /// With the real lists (not part of the repository, see `testlabor\sperrlisten`):
    /// `cargo test -p k9-core sperrlisten -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_lists_statistics() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testlabor/sperrlisten");
        let text = std::fs::read_to_string(dir.join("tif.medium-onlydomains.txt")).expect("Liste in testlabor/sperrlisten");
        let lines = text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
        let start = std::time::Instant::now();
        let (version, keys) = parse_tif(&text);
        println!("HaGeZi {version}: {lines} Zeilen, {} Schlüssel, {} KB, eingelesen in {:.2} s", keys.len(), keys.len() * 8 / 1024, start.elapsed().as_secs_f64());
        let start = std::time::Instant::now();
        let names = ["www.google.com", "login.microsoftonline.com", "store.steampowered.com", "github.com", "cdn.discordapp.com", "a.b.c.example.org"];
        let mut hits = 0;
        for i in 0..60_000 {
            hits += listed_parent(&keys, names[i % names.len()]).is_some() as usize;
        }
        println!("Abfrage: {:.1} Mikrosekunden je Name, Treffer bei bekannten harmlosen Namen: {hits}", start.elapsed().as_secs_f64() * 1e6 / 60_000.0);
        let (ranges, stamp) = parse_drop(&std::fs::read_to_string(dir.join("drop_v4.json")).expect("drop_v4.json")).unwrap();
        println!("Spamhaus DROP: {} Netze, Stand {stamp}", ranges.len());
    }

    #[test]
    fn spamhaus_networks_become_ranges() {
        let text = "{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL1\",\"rir\":\"x\"}\n{\"cidr\":\"203.0.113.64/26\",\"sblid\":\"SBL2\",\"rir\":\"x\"}\n{\"type\":\"metadata\",\"timestamp\":1795237004,\"records\":2}\n";
        let (ranges, stamp) = parse_drop(text).unwrap();
        assert_eq!((ranges.len(), stamp), (2, 1795237004));
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(in_ranges(&ranges, &ip("198.51.100.0")) && in_ranges(&ranges, &ip("198.51.100.255")));
        assert!(!in_ranges(&ranges, &ip("198.51.101.0")) && !in_ranges(&ranges, &ip("198.51.99.255")));
        assert!(in_ranges(&ranges, &ip("203.0.113.100")) && !in_ranges(&ranges, &ip("203.0.113.128")));
        assert!(!in_ranges(&[], &ip("198.51.100.1")));
        // A mistake in the list must not flag half the internet.
        assert!(parse_drop("{\"cidr\":\"0.0.0.0/0\"}\n").is_err());
        assert!(parse_drop("kein json\n").is_err());
    }
}
