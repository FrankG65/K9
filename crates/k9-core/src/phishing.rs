//! Phishing checks on domain names (no network, nothing uploaded):
//! - Public Suffix List: registrable domain of a host, so that a feed entry never
//!   covers a whole public suffix or shared-hosting parent (github.io, blogspot.com …).
//! - Second phishing feed "phishing-filter" (malware-filter, CC BY-SA 4.0).
//! - Lookalike domains of well-known brands: typos (only for longer names),
//!   confusable characters / punycode, brand plus lure word, brand domain in front
//!   of a foreign domain. Official domains (including CDNs) are never reported.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Public Suffix List (https://publicsuffix.org/list/, MPL-2.0), shipped unchanged.
const PSL: &str = include_str!("../data/public_suffix_list.dat");

pub const PHISHFILTER_URL: &str = "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt";
pub const PHISHFILTER_FILE: &str = "phishing/phishing-filter-hosts.txt";
/// Source name in findings and the network database.
pub const PHISHFILTER_SOURCE: &str = "Phishing-Filter";

struct Psl {
    rules: HashSet<&'static str>,
    wild: HashSet<&'static str>,
    except: HashSet<&'static str>,
}

fn psl() -> &'static Psl {
    static P: OnceLock<Psl> = OnceLock::new();
    P.get_or_init(|| {
        let mut p = Psl { rules: HashSet::new(), wild: HashSet::new(), except: HashSet::new() };
        for line in PSL.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            // Rules with non-ASCII letters are skipped: DNS names arrive as punycode,
            // for those top-level domains the default rule (last label) applies.
            if rule.is_empty() || rule.starts_with("//") || !rule.is_ascii() {
                continue;
            }
            if let Some(r) = rule.strip_prefix("*.") {
                p.wild.insert(r);
            } else if let Some(r) = rule.strip_prefix('!') {
                p.except.insert(r);
            } else {
                p.rules.insert(rule);
            }
        }
        p
    })
}

/// Index of the first label of the public suffix (longest rule wins, exceptions first).
fn suffix_start(labels: &[&str]) -> usize {
    let p = psl();
    let n = labels.len();
    for i in 0..n {
        let cand = labels[i..].join(".");
        if p.except.contains(cand.as_str()) {
            return i + 1;
        }
        if p.rules.contains(cand.as_str()) || (i + 1 < n && p.wild.contains(labels[i + 1..].join(".").as_str())) {
            return i;
        }
    }
    n - 1
}

fn host_labels(host: &str) -> Option<Vec<String>> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<String> = host.split('.').map(str::to_string).collect();
    let valid = |l: &String| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    labels.iter().all(valid).then_some(labels)
}

/// "login.example.co.uk" -> "example.co.uk"; None for a public suffix itself or an invalid name.
pub fn registrable_domain(host: &str) -> Option<String> {
    let labels = host_labels(host)?;
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let s = suffix_start(&refs);
    (s > 0).then(|| refs[s - 1..].join("."))
}

/// True for "com", "co.uk", "github.io", "blogspot.com" … (whole public/shared suffixes).
pub fn is_public_suffix(host: &str) -> bool {
    host_labels(host).is_some() && registrable_domain(host).is_none()
}

/// Host names from the hosts-format feed ("0.0.0.0 name"). Invalid names, IP
/// addresses, single labels and public suffixes are dropped.
pub fn parse_feed(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let first = parts.next()?;
            let host = parts.next().unwrap_or(first);
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            let ok = host.contains('.') && host_labels(&host).is_some() && !is_public_suffix(&host);
            ok.then_some(host)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

// ------------------------------------------------------------------ lookalikes

/// Names with at least 6 letters: typos count as well (on the registrable label;
/// from 9 letters any single edit, below only swapped, missing or doubled letters).
const LONG_BRANDS: &[(&str, &str)] = &[
    ("steamcommunity", "steamcommunity.com"),
    ("steampowered", "steampowered.com"),
    ("epicgames", "epicgames.com"),
    ("discord", "discord.com"),
    ("blizzard", "blizzard.com"),
    ("riotgames", "riotgames.com"),
    ("rockstargames", "rockstargames.com"),
    ("playstation", "playstation.com"),
    ("ubisoft", "ubisoft.com"),
    ("nvidia", "nvidia.com"),
    ("microsoft", "microsoft.com"),
    ("outlook", "outlook.com"),
    ("facebook", "facebook.com"),
    ("instagram", "instagram.com"),
    ("whatsapp", "whatsapp.com"),
    ("telegram", "telegram.org"),
    ("netflix", "netflix.com"),
    ("sparkasse", "sparkasse.de"),
];

/// Short or very common names: only confusable characters and brand + lure word.
const SHORT_BRANDS: &[(&str, &str)] = &[
    ("steam", "steampowered.com"),
    ("paypal", "paypal.com"),
    ("amazon", "amazon.com"),
    ("google", "google.com"),
    ("office", "office.com"),
    ("live", "live.com"),
    ("apple", "apple.com"),
    ("icloud", "icloud.com"),
    ("xbox", "xbox.com"),
    ("ebay", "ebay.com"),
];

/// Official registrable domains (including CDNs and well-known community sites)
/// that are never reported.
const OFFICIAL: &[&str] = &[
    "steamcommunity.com", "steampowered.com", "steamstatic.com", "steamcontent.com", "steamusercontent.com",
    "steamserver.net", "steamchina.com", "steamgames.com", "steam-chat.com", "steamdeck.com", "valvesoftware.com",
    "steamgifts.com", "steamdb.info",
    "epicgames.com", "epicgames.dev", "epicgamescdn.com", "unrealengine.com", "fortnite.com",
    "discord.com", "discord.gg", "discord.gift", "discord.media", "discord.new", "discord.dev", "discord.co",
    "discordapp.com", "discordapp.net", "discordcdn.com", "discordstatus.com", "dis.gd",
    "blizzard.com", "battle.net", "riotgames.com", "riotcdn.net", "rockstargames.com",
    "playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "ubisoft.com", "ubi.com",
    "nvidia.com", "geforce.com", "nvidia.de",
    "microsoft.com", "microsoftonline.com", "live.com", "live.net", "office.com", "office.net", "office365.com",
    "outlook.com", "msn.com", "xbox.com", "xboxlive.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net",
    "telegram.org", "telegram.me", "t.me", "netflix.com", "nflxvideo.net", "nflximg.net", "sparkasse.de",
    "paypal.com", "paypal.me", "paypalobjects.com",
    "amazon.com", "amazon.de", "amazonaws.com", "amazon-adsystem.com", "media-amazon.com", "ssl-images-amazon.com",
    "google.com", "google.de", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com", "googleadservices.com",
    "apple.com", "icloud.com", "ebay.com", "ebay.de", "ebaystatic.com", "telegra.ph", "s-microsoft.com",
    "microsoftrewards.com", "microsoftonline-p.com", "msftauth.net", "telesco.pe", "tdesktop.com", "rgpub.io",
    "nflxext.com", "nflxso.net", "netflix.net", "nvidia.cn", "geforce.cn", "nvidiagrid.net",
];

/// Registrable labels of ordinary sites that happen to look like a brand
/// (found with the false-alarm check against the Tranco list).
const ORDINARY: &[&str] = &["telegraf", "1cloud", "whatwapp"];

/// Lure words for brand + word combinations ("paypal-login", "discord-nitro").
const LURE_STRONG: &[&str] = &[
    "login", "signin", "logon", "verify", "verification", "secure", "account", "accounts", "konto", "password",
    "passwort", "billing", "payment", "auth", "confirm", "bestaetigen", "sicherheit",
];
/// Only together with longer brand names (too common next to "live" or "office").
const LURE_WEAK: &[&str] = &["gift", "nitro", "free", "bonus", "promo", "reward", "giveaway", "wallet", "claim", "airdrop", "support", "recovery"];

struct Brand {
    label: String,
    domain: String,
    short: bool,
}

/// What a lookalike hit looks like.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Registrable domain that was queried (e.g. "steamcommunlty.com").
    pub registrable: String,
    /// The official domain it resembles.
    pub brand: String,
    pub how: &'static str,
}

pub struct Lookalikes {
    brands: Vec<Brand>,
    official: HashSet<String>,
}

impl Lookalikes {
    /// Built-in brands plus the user's own (`phishing.eigene_marken`, e.g. "meinebank.de").
    pub fn new(own: &[String]) -> Self {
        let mut brands: Vec<Brand> = LONG_BRANDS
            .iter()
            .map(|(l, d)| Brand { label: l.to_string(), domain: d.to_string(), short: false })
            .chain(SHORT_BRANDS.iter().map(|(l, d)| Brand { label: l.to_string(), domain: d.to_string(), short: true }))
            .collect();
        let mut official: HashSet<String> = OFFICIAL.iter().map(|s| s.to_string()).collect();
        for d in own {
            let Some(reg) = registrable_domain(d) else { continue };
            let label = reg.split('.').next().unwrap_or("").to_string();
            if label.len() >= 3 {
                brands.push(Brand { short: label.len() < 6, label, domain: reg.clone() });
                official.insert(reg);
            }
        }
        Self { brands, official }
    }

    /// Checks a queried host name; None when it is harmless or official.
    pub fn check(&self, host: &str) -> Option<Hit> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let reg = registrable_domain(&host)?;
        if self.official.contains(&reg) {
            return None;
        }
        let label = reg.split('.').next()?;
        if ORDINARY.contains(&label) {
            return None;
        }
        let skel = skeleton(label);
        let hit = |b: &Brand, how| Some(Hit { registrable: reg.clone(), brand: b.domain.clone(), how });
        for b in &self.brands {
            // The brand's own name under another ending (amazon.de, google.at) is not a lookalike.
            if label == b.label {
                continue;
            }
            let bs = skeleton(&b.label);
            if skel == bs {
                return hit(b, t!("verwechselbare Zeichen", "look-alike characters"));
            }
            if !b.short && label.len() >= 5 {
                let typo = if b.label.len() >= 9 { osa_distance(label, &b.label) <= 1 } else { simple_typo(label, &b.label) };
                if typo {
                    return hit(b, t!("Tippfehler-Domain", "typo domain"));
                }
            }
            if combo(label, &b.label, b.short) {
                return hit(b, t!("Markenname mit Lockwort", "brand name with a lure word"));
            }
        }
        // "paypal.com.konto-check.example": the brand domain in front of a foreign domain.
        let prefix = host.strip_suffix(reg.as_str()).unwrap_or("").trim_end_matches('.');
        if !prefix.is_empty() {
            let p = format!(".{prefix}.");
            for b in &self.brands {
                if p.contains(&format!(".{}.", b.domain)) {
                    return hit(b, t!("Marken-Domain vor einer fremden Domain", "brand domain in front of a foreign domain"));
                }
            }
        }
        None
    }
}

fn combo(label: &str, brand: &str, short: bool) -> bool {
    if !label.contains(brand) {
        return false;
    }
    if short {
        let tokens: Vec<&str> = label.split('-').collect();
        if tokens.len() > 1 {
            return tokens.contains(&brand) && tokens.iter().any(|t| LURE_STRONG.contains(t));
        }
        let rest = label.strip_prefix(brand).or_else(|| label.strip_suffix(brand));
        return rest.is_some_and(|r| LURE_STRONG.contains(&r));
    }
    let rest = label.replacen(brand, "", 1);
    LURE_STRONG.iter().chain(LURE_WEAK).any(|w| rest.contains(w))
}

/// Label reduced to what it looks like: punycode decoded, confusable letters and
/// digits mapped (Cyrillic "а" -> a, 0 -> o, 1/i -> l, rn -> m, vv -> w), hyphens dropped.
fn skeleton(label: &str) -> String {
    let decoded = label.strip_prefix("xn--").and_then(punycode_decode);
    let src = decoded.as_deref().unwrap_or(label);
    let mut s = String::with_capacity(src.len());
    for c in src.chars().flat_map(char::to_lowercase) {
        let m = match c {
            '-' => continue,
            '0' | 'о' | 'ο' | 'օ' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' => 'o',
            '1' | 'i' | 'l' | 'ı' | 'і' | 'ӏ' | 'ɩ' | 'ì' | 'í' | 'î' | 'ï' | 'ł' | '|' => 'l',
            'а' | 'α' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'е' | 'ё' | 'ε' | 'è' | 'é' | 'ê' | 'ë' => 'e',
            'р' | 'ρ' => 'p',
            'с' | 'ϲ' | 'ç' => 'c',
            'у' | 'ү' | 'ý' | 'ÿ' => 'y',
            'х' | 'χ' => 'x',
            'ѕ' | 'ś' | 'š' => 's',
            'ԁ' => 'd',
            'ɡ' | 'ց' => 'g',
            'ս' | 'υ' | 'ù' | 'ú' | 'û' | 'ü' => 'u',
            'ν' => 'v',
            'κ' | 'к' => 'k',
            'т' | 'τ' => 't',
            'н' => 'h',
            'м' => 'm',
            'в' | 'β' => 'b',
            'ո' | 'ñ' => 'n',
            'ј' => 'j',
            'ԝ' | 'ѡ' => 'w',
            c => c,
        };
        s.push(m);
    }
    s.replace("rn", "m").replace("vv", "w")
}

/// Swapped neighbours, one letter missing or one letter doubled ("dicsord",
/// "faceboo", "faceboook") – no free substitutions, those hit ordinary words.
fn simple_typo(label: &str, brand: &str) -> bool {
    let a: Vec<char> = label.chars().collect();
    let b: Vec<char> = brand.chars().collect();
    let without = |v: &[char], i: usize| -> Vec<char> { v.iter().enumerate().filter(|(k, _)| *k != i).map(|(_, c)| *c).collect() };
    if a.len() == b.len() {
        let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        return diff.len() == 2 && diff[1] == diff[0] + 1 && a[diff[0]] == b[diff[1]] && a[diff[1]] == b[diff[0]];
    }
    if a.len() + 1 == b.len() {
        return (0..b.len()).any(|i| without(&b, i) == a);
    }
    if a.len() == b.len() + 1 {
        return (0..a.len()).any(|i| without(&a, i) == b && ((i > 0 && a[i - 1] == a[i]) || (i + 1 < a.len() && a[i + 1] == a[i])));
    }
    false
}

/// Optimal string alignment distance (Levenshtein plus swapped neighbours).
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > 2 {
        return 3;
    }
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// Punycode (RFC 3492) of one label without the "xn--" prefix.
fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    fn adapt(delta: u32, num: u32, first: bool) -> u32 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / num;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    }
    let (basic, ext) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() || ext.is_empty() {
        return None;
    }
    let mut out: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let mut it = ext.bytes().peekable();
    while it.peek().is_some() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let digit = match it.next()? {
                b @ b'a'..=b'z' => u32::from(b - b'a'),
                b @ b'0'..=b'9' => u32::from(b - b'0') + 26,
                _ => return None,
            };
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias { TMIN } else if k >= bias + TMAX { TMAX } else { k - bias };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len = out.len() as u32 + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len)?;
        i %= len;
        out.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_follow_the_public_suffix_list() {
        assert_eq!(registrable_domain("login.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("a.b.example.com.").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("Nutzer.GitHub.io").as_deref(), Some("nutzer.github.io"));
        assert_eq!(registrable_domain("www.ck").as_deref(), Some("www.ck"), "Ausnahme-Regel");
        assert_eq!(registrable_domain("x.y.ck").as_deref(), Some("x.y.ck"), "Platzhalter-Regel");
        assert_eq!(registrable_domain("beispiel.invalid").as_deref(), Some("beispiel.invalid"), "Standardregel");
        assert!(registrable_domain("192.0.2.1").is_none());
        assert!(registrable_domain("kaputt..example").is_none());
        for s in ["com", "co.uk", "github.io", "blogspot.com"] {
            assert!(is_public_suffix(s), "{s}");
        }
        assert!(!is_public_suffix("example.com"));
    }

    #[test]
    fn feed_never_contains_public_suffixes() {
        let text = "# Title: Test\n0.0.0.0 0002985647.weebly.com\n0.0.0.0 github.io\n0.0.0.0 phish.example.\n0.0.0.0 192.0.2.7\n0.0.0.0 localhost\nblogspot.com\n0.0.0.0 Phish.Example\n0.0.0.0 bad_name!.example\n";
        assert_eq!(parse_feed(text), vec!["0002985647.weebly.com".to_string(), "phish.example".to_string()]);
    }

    #[test]
    fn punycode_is_decoded() {
        assert_eq!(punycode_decode("pypal-4ve").as_deref(), Some("p\u{0430}ypal"));
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("b\u{fc}cher"));
        assert!(punycode_decode("!!").is_none());
    }

    #[test]
    fn lookalikes_are_recognised() {
        let l = Lookalikes::new(&[]);
        let how = |h: &str| l.check(h).map(|x| x.how);
        assert_eq!(how("steamcommunlty.com"), Some("verwechselbare Zeichen"));
        assert_eq!(how("steamcomunity.com"), Some("Tippfehler-Domain"));
        assert_eq!(how("login.stearncommunity.ru"), Some("verwechselbare Zeichen"));
        assert_eq!(how("dicsord.com"), Some("Tippfehler-Domain"));
        assert_eq!(how("faceboook.com"), Some("Tippfehler-Domain"));
        assert_eq!(how("instagran.com"), Some("Tippfehler-Domain"));
        assert_eq!(how("discord-nitro.example"), Some("Markenname mit Lockwort"));
        assert_eq!(how("freediscordgift.example"), Some("Markenname mit Lockwort"));
        assert_eq!(how("xn--pypal-4ve.com"), Some("verwechselbare Zeichen"));
        assert_eq!(how("paypa1.com"), Some("verwechselbare Zeichen"));
        assert_eq!(how("paypal-login.example"), Some("Markenname mit Lockwort"));
        assert_eq!(how("paypal.com.konto-check.example"), Some("Marken-Domain vor einer fremden Domain"));
        let hit = l.check("epicgarnes.com").unwrap();
        assert_eq!(hit.brand, "epicgames.com");
        assert_eq!(hit.registrable, "epicgarnes.com");
    }

    #[test]
    fn official_and_ordinary_domains_stay_quiet() {
        let l = Lookalikes::new(&[]);
        for h in [
            "steamcommunity.com", "store.steampowered.com", "cdn.akamai.steamstatic.com", "cdn.discordapp.com",
            "discord.gg", "discord.gift", "media.discordapp.net", "www.epicgames.com", "fortnite.com", "google.de",
            "amazon.de", "login.live.com", "outlook.office365.com", "www.steamgifts.com", "paypalobjects.com",
            // Short brands: no typo matching (would hit ordinary words).
            "olive.com", "lives.com", "offices.example", "appel.de", "googled.example", "live-support.example",
            "ebay-kleinanzeigen-hilfe.example", "liveticker.de", "officedepot.com", "steamboat.example",
            "github.com", "wikipedia.org", "discard.email", "dischord.com", "netfilm.store", "plantation.org",
            "starcommunity.com.au", "evidia.de", "officerecovery.com", "microsoftrewards.com", "192.0.2.5", "localhost", "com",
        ] {
            assert_eq!(l.check(h), None, "{h}");
        }
    }

    #[test]
    fn gaming_and_banking_sites_stay_quiet() {
        let l = Lookalikes::new(&[]);
        for h in [
            "steamgifts.com", "steamtrades.com", "steamdb.info", "steamcharts.com", "steamladder.com", "steamrep.com",
            "steamid.io", "isthereanydeal.com", "discord.me", "disboard.org", "discordbotlist.com", "discords.com",
            "discordapp.io", "top.gg", "epicgames.dev", "unrealengine.com", "battle.net", "blizzard.com", "riotgames.com",
            "leagueoflegends.com", "rockstargames.com", "socialclub.rockstargames.com", "ubisoftconnect.com",
            "nvidia.com", "geforce.com", "geforcenow.com", "playstation.com", "playstation.net",
            "playstationnetwork.com", "xbox.com", "outlook.com", "live.com", "office.com", "login.microsoftonline.com",
            "appleid.apple.com", "icloud.com", "paypal.me", "paypalobjects.com", "amazon.de", "amazonaws.com",
            "media-amazon.com", "ebay.de", "ebaystatic.com", "sparkasse.de", "sparkasse-koelnbonn.de",
            "sparkasse-hannover.de", "ksk-koeln.de", "ksk-tuebingen.de", "madfingergames.com", "grayzonewarfare.com",
            "telegra.ph", "t.me", "telesco.pe", "tdesktop.com", "discord.gift", "discord.new", "dis.gd", "discord.co",
            "discord.media", "discordstatus.com", "steamchina.com", "steamusercontent.com", "steamserver.net",
            "valvesoftware.com", "riotcdn.net", "rgpub.io", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net",
            "netflix.net", "nvidia.cn", "geforce.cn", "nvidiagrid.net", "sonyentertainmentnetwork.com", "xboxlive.com",
            "live.net", "office.net", "microsoftonline-p.com", "msftauth.net",
        ] {
            assert_eq!(l.check(h), None, "{h}");
        }
    }

    /// False-alarm check against a list of popular domains (one per line, e.g. Tranco):
    /// `$env:VS_TOPLISTE = "...\top100k.txt"; cargo test -p k9-core fehlalarme -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fehlalarme_bei_beliebten_domains() {
        let path = std::env::var("VS_TOPLISTE").expect("VS_TOPLISTE");
        let text = std::fs::read_to_string(path).unwrap();
        let l = Lookalikes::new(&[]);
        let hits: Vec<_> = text.lines().filter_map(|h| l.check(h.trim()).map(|x| format!("{h} -> {} ({})", x.brand, x.how))).collect();
        for h in &hits {
            println!("{h}");
        }
        println!("{} Treffer bei {} Domains", hits.len(), text.lines().count());
    }

    #[test]
    fn own_brands_from_the_configuration() {
        let l = Lookalikes::new(&["www.meinebank.de".into(), "x".into()]);
        assert_eq!(l.check("meinebamk.de").map(|h| h.brand), Some("meinebank.de".to_string()));
        assert_eq!(l.check("online.meinebank.de"), None);
    }
}
