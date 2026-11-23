//! Blocking known botnet command servers in the Windows firewall (opt-in,
//! `schutz.firewall_sperre`, default off). Only high-confidence entries: abuse.ch Feodo Tracker
//! (recommended list) and ThreatFox `ip:port` with threat type `botnet_cc` and confidence 100,
//! each seen within the last 30 days, public IPv4 only. Outbound TCP rules for exactly these
//! addresses AND ports, one rule per port (named "K9 – Botnetz-Server gesperrt (Port N)",
//! group "K9"), at most 1000 addresses. Only these rules (and the rules of older versions,
//! "Virenscanner C2-Sperre") are ever removed – never another rule, also not one in the same group.
//!
//! Risk: a listed address can be shared (cloud or hosting servers) – a legitimate service on
//! the same address and port would be blocked too.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::sources::Ioc;

/// Group of the own rules (shown in "Windows Defender Firewall mit erweiterter Sicherheit").
pub const RULE_GROUP: &str = "K9";
/// Start of the name of every own rule.
pub const RULE_PREFIX: &str = "K9 – Botnetz-Server gesperrt";
/// Names used by older versions (removed and replaced at the next refresh).
pub const OLD_RULE_NAMES: [&str; 1] = ["Virenscanner C2-Sperre"];
/// Group and name prefix before the rename to K9.
pub const OLD_RULE_GROUP: &str = "Virenscanner";
pub const OLD_RULE_PREFIX: &str = "Virenscanner – Botnetz-Server gesperrt";
pub const FEODO_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";
pub const MAX_TARGETS: usize = 1000;
const MAX_AGE_DAYS: i64 = 30;
/// Addresses per firewall rule (keeps the netsh command line short).
const PER_RULE: usize = 200;

/// Public unicast IPv4 only: never private, LAN, loopback, link-local, multicast, CGNAT,
/// documentation, benchmarking or reserved ranges.
pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240)
}

fn recent(date: &str, today: &str) -> bool {
    let d = |s: &str| chrono::NaiveDate::parse_from_str(s.get(..10).unwrap_or(""), "%Y-%m-%d").ok();
    match (d(date), d(today)) {
        (Some(a), Some(b)) => (b - a).num_days() <= MAX_AGE_DAYS,
        _ => false,
    }
}

/// A candidate for the block: address, port and the date it was last (or first) seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub seen: String,
}

/// Feodo Tracker JSON (ip_address, port, last_online).
pub fn parse_feodo(json: &str, today: &str) -> Vec<Target> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let ip: Ipv4Addr = e["ip_address"].as_str()?.parse().ok()?;
            let port = u16::try_from(e["port"].as_u64()?).ok()?;
            let seen = e["last_online"].as_str().or(e["first_seen"].as_str())?;
            (is_public_v4(ip) && port > 0 && recent(seen, today)).then(|| Target { ip, port, seen: seen.chars().take(10).collect() })
        })
        .collect()
}

/// ThreatFox `ip:port`, botnet_cc, confidence 100, seen within 30 days.
pub fn threatfox_targets(iocs: &BTreeMap<String, Ioc>, today: &str) -> Vec<Target> {
    iocs.iter()
        .filter(|(_, i)| i.typ == "ip" && i.threat_type == "botnet_cc" && i.confidence >= 100)
        .filter_map(|(v, i)| {
            let seen = if i.last_seen.is_empty() { &i.first_seen } else { &i.last_seen };
            if !recent(seen, today) {
                return None;
            }
            let (ip, port) = v.trim().rsplit_once(':')?;
            let ip: Ipv4Addr = ip.parse().ok()?;
            let port: u16 = port.parse().ok()?;
            (is_public_v4(ip) && port > 0).then(|| Target { ip, port, seen: seen.chars().take(10).collect() })
        })
        .collect()
}

/// Shared CDN and anycast networks: one address there serves many unrelated websites, so a
/// listed address is never blocked (it would break normal browsing). "-Google" networks are
/// Google Cloud customer ranges inside the Google list (single servers, not shared front ends).
#[derive(Debug, Clone, Default)]
pub struct Cdn {
    nets: Vec<(String, u32, u32)>,
    exempt: Vec<(u32, u32)>,
}

/// Built-in fallback (snapshot of the published lists, 15.11.2026).
pub const CDN_SNAPSHOT: &str = include_str!("../data/cdn-netze.txt");

fn cidr(s: &str) -> Option<(u32, u32)> {
    let (a, n) = s.trim().split_once('/')?;
    let a: Ipv4Addr = a.parse().ok()?;
    let n: u32 = n.parse().ok().filter(|n| *n <= 32)?;
    let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
    Some((u32::from(a) & mask, mask))
}

impl Cdn {
    /// Adds the networks of one provider ("-Google" = exempt Google Cloud customer networks).
    pub fn add(&mut self, provider: &str, cidrs: impl IntoIterator<Item = String>) -> usize {
        let mut n = 0;
        for c in cidrs {
            if let Some((net, mask)) = cidr(&c) {
                if provider == "-Google" {
                    self.exempt.push((net, mask));
                } else {
                    self.nets.push((provider.to_string(), net, mask));
                }
                n += 1;
            }
        }
        n
    }

    /// Lines "provider<TAB>network" (the built-in snapshot); only for the given providers.
    pub fn add_snapshot(&mut self, providers: &[&str]) {
        let mut by: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for l in CDN_SNAPSHOT.lines().filter(|l| !l.starts_with('#')) {
            if let Some((p, c)) = l.split_once('\t') {
                if providers.contains(&p) {
                    by.entry(p).or_default().push(c.to_string());
                }
            }
        }
        for (p, c) in by {
            self.add(p, c);
        }
    }

    /// The whole built-in snapshot.
    pub fn snapshot() -> Self {
        let mut c = Cdn::default();
        c.add_snapshot(&CDN_PROVIDERS);
        c
    }

    /// The provider whose shared network holds this address.
    pub fn provider(&self, ip: Ipv4Addr) -> Option<&str> {
        let a = u32::from(ip);
        let hit = self.nets.iter().find(|(_, net, mask)| a & mask == *net)?;
        if hit.0 == "Google" && self.exempt.iter().any(|(net, mask)| a & mask == *net) {
            return None;
        }
        Some(&hit.0)
    }
}

/// Providers in the snapshot (and their sources).
pub const CDN_PROVIDERS: [&str; 5] = ["Cloudflare", "CloudFront", "Fastly", "Google", "-Google"];
pub const CDN_URLS: [(&str, &str); 5] = [
    ("Cloudflare", "https://www.cloudflare.com/ips-v4"),
    ("CloudFront", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    ("Fastly", "https://api.fastly.com/public-ip-list"),
    ("Google", "https://www.gstatic.com/ipranges/goog.json"),
    ("-Google", "https://www.gstatic.com/ipranges/cloud.json"),
];

/// Networks of one provider from its published list (empty if the format is wrong).
pub fn parse_cdn_list(provider: &str, text: &str) -> Vec<String> {
    match provider {
        "Cloudflare" => text.lines().map(str::trim).filter(|l| cidr(l).is_some()).map(str::to_string).collect(),
        "CloudFront" => {
            let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            v["prefixes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| matches!(p["service"].as_str(), Some("CLOUDFRONT" | "CLOUDFRONT_ORIGIN_FACING")))
                .filter_map(|p| p["ip_prefix"].as_str().map(str::to_string))
                .collect()
        }
        "Fastly" => {
            let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            v["addresses"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect()
        }
        _ => {
            let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            v["prefixes"].as_array().into_iter().flatten().filter_map(|p| p["ipv4Prefix"].as_str().map(str::to_string)).collect()
        }
    }
}

/// The CDN networks: per provider the published list (downloaded if `download`, stored in
/// `cache`), otherwise the last good copy from `cache`, otherwise the built-in snapshot – a
/// missing list never lets CDN addresses through. Returns the networks and one note per provider.
pub fn load_cdn(cache: Option<&std::path::Path>, download: bool) -> (Cdn, Vec<String>) {
    let mut cdn = Cdn::default();
    let mut notes = Vec::new();
    for (provider, url) in CDN_URLS {
        let file = cache.map(|d| d.join(format!("{}.txt", provider.trim_start_matches('-').to_lowercase() + if provider.starts_with('-') { "-cloud" } else { "" })));
        let fresh = if download {
            crate::sources::download(url, &[], 20 * 1024 * 1024).ok().map(|b| String::from_utf8_lossy(&b).to_string()).filter(|t| !parse_cdn_list(provider, t).is_empty())
        } else {
            None
        };
        if let (Some(t), Some(f)) = (&fresh, &file) {
            if let Some(d) = f.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(f, t);
        }
        let text = fresh.map(|t| (t, "aktuell")).or_else(|| {
            file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()).filter(|t| !parse_cdn_list(provider, t).is_empty()).map(|t| (t, "letzte Kopie"))
        });
        match text {
            Some((t, from)) => {
                let n = cdn.add(provider, parse_cdn_list(provider, &t));
                notes.push(format!("{provider}: {n} Netze ({from})"));
            }
            None => {
                cdn.add_snapshot(&[provider]);
                notes.push(format!("{provider}: eingebaute Liste"));
            }
        }
    }
    (cdn, notes)
}

/// What the block covers: newest first, without shared CDN networks, at most MAX_TARGETS.
#[derive(Debug, Default)]
pub struct Auswahl {
    pub groups: BTreeMap<u16, Vec<Ipv4Addr>>,
    /// Skipped because of a shared CDN network: provider -> (address, port, date).
    pub skipped: BTreeMap<String, Vec<(Ipv4Addr, u16, String)>>,
    /// Oldest and newest date of the selected entries.
    pub dates: Option<(String, String)>,
    /// Candidates beyond the cap (not blocked).
    pub cut: usize,
}

impl Auswahl {
    pub fn count(&self) -> usize {
        self.groups.values().map(Vec::len).sum()
    }

    /// "3 Adressen in geteilten CDN-Netzen uebersprungen (CloudFront 3)" or None.
    pub fn skipped_text(&self) -> Option<String> {
        let n: usize = self.skipped.values().map(Vec::len).sum();
        (n > 0).then(|| {
            let by = self.skipped.iter().map(|(p, v)| format!("{p} {}", v.len())).collect::<Vec<_>>().join(", ");
            format!("{n} Adressen in geteilten CDN-Netzen uebersprungen ({by})")
        })
    }
}

pub fn select(targets: Vec<Target>, cdn: &Cdn) -> Auswahl {
    let mut a = Auswahl::default();
    // newest date per (address, port)
    let mut newest: BTreeMap<(Ipv4Addr, u16), String> = BTreeMap::new();
    for t in targets {
        let e = newest.entry((t.ip, t.port)).or_default();
        if t.seen > *e {
            *e = t.seen;
        }
    }
    let mut list: Vec<((Ipv4Addr, u16), String)> = Vec::new();
    for (k, seen) in newest {
        match cdn.provider(k.0) {
            Some(p) => a.skipped.entry(p.to_string()).or_default().push((k.0, k.1, seen)),
            None => list.push((k, seen)),
        }
    }
    // newest first; same date: by address (stable result)
    list.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    a.cut = list.len().saturating_sub(MAX_TARGETS);
    list.truncate(MAX_TARGETS);
    a.dates = list.last().map(|l| l.1.clone()).zip(list.first().map(|f| f.1.clone()));
    for ((ip, port), _) in list {
        a.groups.entry(port).or_default().push(ip);
    }
    for v in a.groups.values_mut() {
        v.sort();
    }
    a
}

/// Port -> addresses (deduplicated, capped at MAX_TARGETS in total), without CDN filter and dates.
pub fn group_by_port(targets: impl IntoIterator<Item = (Ipv4Addr, u16)>) -> BTreeMap<u16, Vec<Ipv4Addr>> {
    let unique: BTreeSet<(Ipv4Addr, u16)> = targets.into_iter().collect();
    let mut out: BTreeMap<u16, Vec<Ipv4Addr>> = BTreeMap::new();
    for (ip, port) in unique.into_iter().take(MAX_TARGETS) {
        out.entry(port).or_default().push(ip);
    }
    out
}

/// Name of the rule for a port (more than 200 addresses on one port: further parts).
pub fn rule_name(port: u16, part: usize) -> String {
    if part == 0 {
        format!("{RULE_PREFIX} (Port {port})")
    } else {
        format!("{RULE_PREFIX} (Port {port}, Teil {})", part + 1)
    }
}

/// Is this one of our rules? Ours: group "K9" AND our name prefix, or exactly the
/// name of an older version. A foreign rule in the same group or with a similar name is not.
pub fn is_own_rule(display_name: &str, group: &str) -> bool {
    (group == RULE_GROUP && display_name.starts_with(RULE_PREFIX))
        || (group == OLD_RULE_GROUP && display_name.starts_with(OLD_RULE_PREFIX))
        || OLD_RULE_NAMES.contains(&display_name)
}

/// A firewall rule as listed by [`PS_LIST`].
#[derive(Debug, Clone, PartialEq)]
pub struct Listed {
    /// Unique rule id ("Name" in PowerShell).
    pub id: String,
    pub name: String,
    pub group: String,
}

/// Lists all outbound rules as "id|display name|group" (UTF-8).
pub const PS_LIST: &str =
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetFirewallRule -Direction Outbound | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.DisplayName, $_.Group }";

pub fn parse_list(out: &str) -> Vec<Listed> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.trim_end_matches('\r').splitn(3, '|');
            let (id, name, group) = (p.next()?, p.next()?, p.next().unwrap_or(""));
            (!id.is_empty()).then(|| Listed { id: id.to_string(), name: name.to_string(), group: group.trim().to_string() })
        })
        .collect()
}

/// Our rules in a listing (ids that are safe to put into a command only).
pub fn own_rules(list: &[Listed]) -> Vec<Listed> {
    list.iter().filter(|r| is_own_rule(&r.name, &r.group) && safe_id(&r.id)).cloned().collect()
}

/// Rule ids are GUIDs or similar: letters, digits, braces, dashes, dots, underscores.
fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.chars().all(|c| c.is_ascii_alphanumeric() || "{}-_.".contains(c))
}

/// PowerShell command that removes exactly these rules (by id).
pub fn ps_remove(rules: &[Listed]) -> Option<String> {
    let ids: Vec<String> = rules.iter().filter(|r| safe_id(&r.id)).map(|r| format!("'{}'", r.id)).collect();
    (!ids.is_empty()).then(|| format!("Remove-NetFirewallRule -Name {} -ErrorAction Stop", ids.join(",")))
}

/// PowerShell commands that create the rules (one per port and chunk of addresses).
/// Only addresses, ports, the date and fixed texts go into them.
pub fn ps_add(groups: &BTreeMap<u16, Vec<Ipv4Addr>>, date: &str, sources: &str) -> Vec<String> {
    let date: String = date.chars().filter(|c| c.is_ascii_digit() || *c == '-').collect();
    let sources: String = sources.chars().filter(|c| c.is_ascii_alphanumeric() || " ,/".contains(*c)).collect();
    let mut out = Vec::new();
    for (port, ips) in groups {
        for (part, chunk) in ips.chunks(PER_RULE).enumerate() {
            let list = chunk.iter().map(|i| format!("'{i}'")).collect::<Vec<_>>().join(",");
            let description = format!(
                "Angelegt vom K9-Dienst: sperrt ausgehende TCP-Verbindungen zu {} bekannten Botnetz-Steuerservern auf Port {port}. \
                 Quelle: abuse.ch ({sources}). Stand: {date}. Entfernen: k9 firewall entfernen",
                chunk.len()
            );
            out.push(format!(
                "New-NetFirewallRule -DisplayName '{}' -Group '{RULE_GROUP}' -Description '{description}' -Direction Outbound -Action Block \
                 -Protocol TCP -RemotePort {port} -RemoteAddress {list} -Enabled True -ErrorAction Stop | Out-Null",
                rule_name(*port, part)
            ));
        }
    }
    out
}

/// Runs a PowerShell command (no profile, not interactive): (success, stdout).
pub fn powershell(cmd: &str) -> Option<(bool, String)> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = std::path::Path::new(&windir).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    let out = std::process::Command::new(exe).args(["-NoProfile", "-NonInteractive", "-Command", cmd]).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).to_string()))
}

/// Our rules on this PC (empty if the firewall cannot be read).
pub fn list_own_rules() -> Vec<Listed> {
    powershell(PS_LIST).map(|(_, out)| own_rules(&parse_list(&out))).unwrap_or_default()
}

/// Removes all our rules (and only those); the number removed.
pub fn remove_own_rules() -> anyhow::Result<usize> {
    let own = list_own_rules();
    let Some(cmd) = ps_remove(&own) else { return Ok(0) };
    match powershell(&cmd) {
        Some((true, _)) => Ok(own.len()),
        _ => anyhow::bail!("Firewall-Regeln konnten nicht entfernt werden"),
    }
}

// ---------------------------------------------------------------------------------------------
// Synchronising the rules: compare, then change only what differs (make-before-break).
// ---------------------------------------------------------------------------------------------

/// A firewall rule as far as the block is concerned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FwRule {
    pub name: String,
    pub group: String,
    pub description: String,
    /// Remote port(s) as text ("443").
    pub port: String,
    /// Remote addresses as text, as the firewall reports them.
    pub addresses: String,
    pub outbound: bool,
    pub block: bool,
    pub tcp: bool,
    pub enabled: bool,
}

impl FwRule {
    /// The remote addresses as single IPv4 addresses (None if anything else is in the list,
    /// e.g. a range or a subnet – such a rule never counts as "unchanged").
    pub fn address_set(&self) -> Option<BTreeSet<Ipv4Addr>> {
        let mut set = BTreeSet::new();
        for a in self.addresses.split(',').map(str::trim).filter(|a| !a.is_empty()) {
            let ip = a.strip_suffix("/255.255.255.255").or_else(|| a.strip_suffix("/32")).unwrap_or(a);
            // The COM interface reports a single address as the range "a-a".
            let ip = match ip.split_once('-') {
                Some((from, to)) if from == to => from,
                Some(_) => return None,
                None => ip,
            };
            set.insert(ip.parse().ok()?);
        }
        Some(set)
    }

    /// Blocks exactly what `wanted` blocks (description and date do not matter).
    pub fn same_block(&self, wanted: &FwRule) -> bool {
        self.outbound
            && self.block
            && self.tcp
            && self.enabled
            && self.port.trim() == wanted.port
            && self.address_set().is_some_and(|s| Some(s) == wanted.address_set())
    }
}

/// The rules the block should consist of (one per port and chunk of at most 200 addresses).
pub fn wanted_rules(groups: &BTreeMap<u16, Vec<Ipv4Addr>>, date: &str, sources: &str) -> Vec<FwRule> {
    let date: String = date.chars().filter(|c| c.is_ascii_digit() || *c == '-').collect();
    let sources: String = sources.chars().filter(|c| c.is_ascii_alphanumeric() || " ,/".contains(*c)).collect();
    let mut out = Vec::new();
    for (port, ips) in groups {
        for (part, chunk) in ips.chunks(PER_RULE).enumerate() {
            out.push(FwRule {
                name: rule_name(*port, part),
                group: RULE_GROUP.into(),
                description: format!(
                    "Angelegt vom K9-Dienst: sperrt ausgehende TCP-Verbindungen zu {} bekannten Botnetz-Steuerservern auf Port {port}. \
                     Quelle: abuse.ch ({sources}). Stand: {date}. Entfernen: k9 firewall entfernen",
                    chunk.len()
                ),
                port: port.to_string(),
                addresses: chunk.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>().join(","),
                outbound: true,
                block: true,
                tcp: true,
                enabled: true,
            });
        }
    }
    out
}

/// What has to change.
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// Already exactly right: untouched.
    pub keep: Vec<String>,
    /// Same name, other addresses (or switched off etc.): changed in place.
    pub update: Vec<FwRule>,
    pub add: Vec<FwRule>,
    /// Own rules no longer needed (also those of older versions): removed last.
    pub remove: Vec<String>,
    /// Names also used by a foreign rule: left alone (a change by name could hit the foreign rule).
    pub conflicts: Vec<String>,
}

impl Plan {
    pub fn writes(&self) -> usize {
        self.update.len() + self.add.len() + self.remove.len()
    }

    pub fn summary(&self) -> String {
        let mut s = tf!(
            "{} unverändert, {} aktualisiert, {} neu, {} entfernt", "{} unchanged, {} updated, {} new, {} removed",
            self.keep.len(),
            self.update.len(),
            self.add.len(),
            self.remove.len()
        );
        if !self.conflicts.is_empty() {
            s.push_str(&format!(", {} übergangen (gleicher Name wie eine fremde Regel)", self.conflicts.len()));
        }
        s
    }
}

pub fn plan(wanted: &[FwRule], current: &[FwRule]) -> Plan {
    let mut p = Plan::default();
    let foreign = |name: &str| current.iter().any(|c| c.name == name && !is_own_rule(&c.name, &c.group));
    let wanted_names: BTreeSet<&str> = wanted.iter().map(|w| w.name.as_str()).collect();
    for w in wanted {
        if foreign(&w.name) {
            p.conflicts.push(w.name.clone());
            continue;
        }
        let mine: Vec<&FwRule> = current.iter().filter(|c| c.name == w.name && c.group == RULE_GROUP).collect();
        match mine.as_slice() {
            [] => p.add.push(w.clone()),
            [one] if one.same_block(w) => p.keep.push(w.name.clone()),
            _ => p.update.push(w.clone()),
        }
    }
    let mut seen = BTreeSet::new();
    for c in current.iter().filter(|c| is_own_rule(&c.name, &c.group) && !wanted_names.contains(c.name.as_str())) {
        if !seen.insert(c.name.clone()) {
            continue;
        }
        if foreign(&c.name) {
            p.conflicts.push(c.name.clone());
        } else {
            p.remove.push(c.name.clone());
        }
    }
    p
}

/// Access to the Windows firewall (real: [`ComFirewall`] or [`PsFirewall`]; tests: a fake).
pub trait FwBackend {
    /// Our rules and every rule that has one of our names (a foreign rule may share a name).
    fn list(&mut self) -> anyhow::Result<Vec<FwRule>>;
    fn add(&mut self, rule: &FwRule) -> anyhow::Result<()>;
    /// Sets all block properties of the rule with this name.
    fn update(&mut self, rule: &FwRule) -> anyhow::Result<()>;
    /// Removes the rule(s) with this name.
    fn remove(&mut self, name: &str) -> anyhow::Result<()>;
    fn label(&self) -> &'static str;
}

/// Result of [`apply`].
#[derive(Debug, Default, PartialEq)]
pub struct Applied {
    pub updated: usize,
    pub added: usize,
    pub removed: usize,
}

/// Applies a plan: updates and new rules first, obsolete rules last – there is never a moment
/// with fewer of the still wanted addresses blocked. Stops at the first error (nothing is
/// removed then, so the previous rules stay).
pub fn apply(fw: &mut dyn FwBackend, plan: &Plan) -> anyhow::Result<Applied> {
    use anyhow::Context;
    let mut done = Applied::default();
    for r in &plan.update {
        fw.update(r).with_context(|| format!("Regel „{}“ nicht aktualisiert", r.name))?;
        done.updated += 1;
    }
    for r in &plan.add {
        fw.add(r).with_context(|| format!("Regel „{}“ nicht angelegt", r.name))?;
        done.added += 1;
    }
    for name in &plan.remove {
        fw.remove(name).with_context(|| format!("Regel „{name}“ nicht entfernt"))?;
        done.removed += 1;
    }
    Ok(done)
}

/// Is this a name we have to look at (ours, or one of the names of older versions)?
fn relevant_name(name: &str) -> bool {
    name.starts_with(RULE_PREFIX) || name.starts_with(OLD_RULE_PREFIX) || OLD_RULE_NAMES.contains(&name)
}

/// The Windows firewall through its COM interface (INetFwPolicy2): no process per rule,
/// a complete update takes seconds. Must be used on the thread that opened it.
pub struct ComFirewall {
    rules: windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
}

impl ComFirewall {
    pub fn open() -> anyhow::Result<Self> {
        use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, NetFwPolicy2};
        use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
        // SAFETY: plain COM calls; the interfaces are released when dropped.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
            Ok(Self { rules: policy.Rules()? })
        }
    }

    fn read(r: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule, name: String) -> windows::core::Result<FwRule> {
        use windows::Win32::NetworkManagement::WindowsFirewall::{NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_OUT};
        // SAFETY: property getters of a valid rule object.
        unsafe {
            Ok(FwRule {
                name,
                group: r.Grouping().map(|s| s.to_string()).unwrap_or_default(),
                description: r.Description().map(|s| s.to_string()).unwrap_or_default(),
                port: r.RemotePorts().map(|s| s.to_string()).unwrap_or_default(),
                addresses: r.RemoteAddresses().map(|s| s.to_string()).unwrap_or_default(),
                outbound: r.Direction()? == NET_FW_RULE_DIR_OUT,
                block: r.Action()? == NET_FW_ACTION_BLOCK,
                tcp: r.Protocol()? == 6,
                enabled: r.Enabled()?.as_bool(),
            })
        }
    }

    fn write(r: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule, w: &FwRule) -> windows::core::Result<()> {
        use windows::core::BSTR;
        use windows::Win32::Foundation::VARIANT_TRUE;
        use windows::Win32::NetworkManagement::WindowsFirewall::{NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT};
        // SAFETY: property setters of a valid rule object. Protocol before ports (the firewall
        // only accepts ports for TCP/UDP); addresses are set in one call (atomic for this rule).
        unsafe {
            r.SetDescription(&BSTR::from(w.description.as_str()))?;
            r.SetGrouping(&BSTR::from(w.group.as_str()))?;
            r.SetDirection(NET_FW_RULE_DIR_OUT)?;
            r.SetAction(NET_FW_ACTION_BLOCK)?;
            r.SetProtocol(6)?;
            r.SetRemotePorts(&BSTR::from(w.port.as_str()))?;
            r.SetRemoteAddresses(&BSTR::from(w.addresses.as_str()))?;
            r.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            r.SetEnabled(VARIANT_TRUE)?;
        }
        Ok(())
    }
}

impl FwBackend for ComFirewall {
    fn list(&mut self) -> anyhow::Result<Vec<FwRule>> {
        use windows::core::Interface;
        use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
        use windows::Win32::System::Com::IDispatch;
        use windows::Win32::System::Ole::IEnumVARIANT;
        use windows::Win32::System::Variant::{VariantClear, VARIANT};
        let mut out = Vec::new();
        // SAFETY: enumeration of the rule collection; every fetched VARIANT is cleared.
        unsafe {
            let en: IEnumVARIANT = self.rules._NewEnum()?.cast()?;
            loop {
                let mut v = [VARIANT::default()];
                let mut fetched = 0u32;
                let hr = en.Next(&mut v, &mut fetched);
                if hr.is_err() || fetched == 0 {
                    break;
                }
                let disp: Option<IDispatch> = (*v[0].Anonymous.Anonymous).Anonymous.pdispVal.as_ref().cloned();
                let _ = VariantClear(&mut v[0]);
                let Some(rule) = disp.and_then(|d| d.cast::<INetFwRule>().ok()) else { continue };
                let name = rule.Name().map(|s| s.to_string()).unwrap_or_default();
                if relevant_name(&name) {
                    out.push(Self::read(&rule, name)?);
                }
            }
        }
        Ok(out)
    }

    fn add(&mut self, w: &FwRule) -> anyhow::Result<()> {
        use windows::core::BSTR;
        use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, NetFwRule};
        use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
        // SAFETY: a new rule object, filled and handed to the collection.
        unsafe {
            let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
            r.SetName(&BSTR::from(w.name.as_str()))?;
            Self::write(&r, w)?;
            self.rules.Add(&r)?;
        }
        Ok(())
    }

    fn update(&mut self, w: &FwRule) -> anyhow::Result<()> {
        use windows::core::BSTR;
        // SAFETY: the rule with this name (the plan made sure no foreign rule shares it).
        unsafe {
            let r = self.rules.Item(&BSTR::from(w.name.as_str()))?;
            Self::write(&r, w)?;
        }
        Ok(())
    }

    fn remove(&mut self, name: &str) -> anyhow::Result<()> {
        use windows::core::BSTR;
        let n = BSTR::from(name);
        // SAFETY: removes by name; repeated while one is left (duplicates of an old version).
        unsafe {
            self.rules.Remove(&n)?;
            for _ in 0..20 {
                if self.rules.Item(&n).is_err() {
                    break;
                }
                self.rules.Remove(&n)?;
            }
        }
        Ok(())
    }

    fn label(&self) -> &'static str {
        "Windows-Firewall-Schnittstelle"
    }
}

/// Fallback when the COM interface is not available: PowerShell (NetSecurity), one process per
/// change – slow, but the same order (make-before-break).
pub struct PsFirewall;

/// Lists the rules with our names: name|group|port|addresses|direction|action|protocol|enabled|description.
const PS_SYNC_LIST: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'K9 – Botnetz-Server gesperrt*' -or $_.DisplayName -like 'Virenscanner – Botnetz-Server gesperrt*' -or $_.DisplayName -eq 'Virenscanner C2-Sperre' } | \
    ForEach-Object { $pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallAddressFilter; \
    '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $_.DisplayName, $_.Group, ($pf.RemotePort -join ','), ($af.RemoteAddress -join ','), $_.Direction, $_.Action, $pf.Protocol, $_.Enabled, ($_.Description -replace '[\\r\\n|]', ' ') }";

/// Text safe for a single-quoted PowerShell string.
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn parse_sync_list(out: &str) -> Vec<FwRule> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.trim_end_matches('\r').splitn(9, '|').collect();
            (p.len() == 9 && !p[0].is_empty()).then(|| FwRule {
                name: p[0].into(),
                group: p[1].trim().into(),
                port: p[2].trim().into(),
                addresses: p[3].trim().into(),
                outbound: p[4].trim() == "Outbound",
                block: p[5].trim() == "Block",
                tcp: p[6].trim().eq_ignore_ascii_case("TCP"),
                enabled: p[7].trim() == "True",
                description: p[8].trim().into(),
            })
        })
        .collect()
}

impl PsFirewall {
    fn run(cmd: &str) -> anyhow::Result<()> {
        match powershell(cmd) {
            Some((true, _)) => Ok(()),
            _ => anyhow::bail!("PowerShell-Befehl fehlgeschlagen"),
        }
    }

    fn checked(w: &FwRule) -> anyhow::Result<()> {
        // Only our own names, digits and addresses ever go into a command.
        anyhow::ensure!(relevant_name(&w.name) && w.port.chars().all(|c| c.is_ascii_digit()) && w.address_set().is_some(), "ungültige Regel");
        Ok(())
    }
}

impl FwBackend for PsFirewall {
    fn list(&mut self) -> anyhow::Result<Vec<FwRule>> {
        match powershell(PS_SYNC_LIST) {
            Some((true, out)) => Ok(parse_sync_list(&out)),
            _ => anyhow::bail!("Firewall-Regeln nicht lesbar"),
        }
    }

    fn add(&mut self, w: &FwRule) -> anyhow::Result<()> {
        Self::checked(w)?;
        Self::run(&format!(
            "New-NetFirewallRule -DisplayName {} -Group {} -Description {} -Direction Outbound -Action Block -Protocol TCP -RemotePort {} -RemoteAddress {} -Enabled True -ErrorAction Stop | Out-Null",
            ps_quote(&w.name),
            ps_quote(&w.group),
            ps_quote(&w.description),
            w.port,
            w.addresses
        ))
    }

    fn update(&mut self, w: &FwRule) -> anyhow::Result<()> {
        Self::checked(w)?;
        Self::run(&format!(
            "Set-NetFirewallRule -DisplayName {} -Description {} -Direction Outbound -Action Block -Protocol TCP -RemotePort {} -RemoteAddress {} -Enabled True -ErrorAction Stop",
            ps_quote(&w.name),
            ps_quote(&w.description),
            w.port,
            w.addresses
        ))
    }

    fn remove(&mut self, name: &str) -> anyhow::Result<()> {
        anyhow::ensure!(relevant_name(name), "fremder Regelname");
        Self::run(&format!("Remove-NetFirewallRule -DisplayName {} -ErrorAction Stop", ps_quote(name)))
    }

    fn label(&self) -> &'static str {
        "PowerShell (Ersatzweg)"
    }
}

/// Opens the firewall: COM interface, otherwise PowerShell.
pub fn open_backend() -> (Box<dyn FwBackend>, Option<String>) {
    match ComFirewall::open() {
        Ok(c) => (Box::new(c), None),
        Err(e) => (Box::new(PsFirewall), Some(format!("{e:#}"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Guard: K9's own block rules are restored at once when something removes or changes them.
// ---------------------------------------------------------------------------------------------

/// Finding rule for "someone removed or changed K9's block rules".
pub const TAMPER_RULE: &str = "FIREWALL:SPERRE-MANIPULIERT";

/// What a guard pass had to put right.
#[derive(Debug, Default, PartialEq)]
pub struct Restored {
    /// Rules that were gone (created again).
    pub missing: Vec<String>,
    /// Rules that were switched off or changed (addresses, ports, action …; set back).
    pub altered: Vec<String>,
    /// Rules with our name that do not belong to the block (removed).
    pub extra: Vec<String>,
}

impl Restored {
    pub fn count(&self) -> usize {
        self.missing.len() + self.altered.len() + self.extra.len()
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// "entfernt", "geändert" or "entfernt/geändert".
    pub fn verb(&self) -> &'static str {
        match (self.missing.is_empty(), self.altered.is_empty() && self.extra.is_empty()) {
            (false, true) => t!("entfernt", "removed"),
            (true, false) => t!("geändert", "changed"),
            _ => t!("entfernt/geändert", "removed/changed"),
        }
    }
}

/// Is the guard active? Not when the block is off, not after `k9 firewall entfernen`
/// (until the next regular renewal) and not before the block was set up once.
pub fn guard_active(on: bool, paused: bool, wanted_known: bool) -> bool {
    on && !paused && wanted_known
}

/// Compares K9's rules with `wanted` and restores every deviation (updates and missing rules
/// first, foreign additions with our name last). K9's own writes leave nothing to do.
pub fn guard(fw: &mut dyn FwBackend, wanted: &[FwRule]) -> anyhow::Result<Restored> {
    let current = fw.list()?;
    let p = plan(wanted, &current);
    if p.writes() == 0 {
        return Ok(Restored::default());
    }
    apply(fw, &p)?;
    Ok(Restored {
        missing: p.add.iter().map(|r| r.name.clone()).collect(),
        altered: p.update.iter().map(|r| r.name.clone()).collect(),
        extra: p.remove.clone(),
    })
}

/// Fingerprint of a tamper finding: one open finding per modifying program (repeats count up).
pub fn tamper_fingerprint(app: Option<&str>) -> String {
    crate::sha256_hex(format!("k9-sperre-manipuliert|{}", app.unwrap_or("unbekannt").to_lowercase()).as_bytes())
}

/// Who changed the rules (from the firewall log), for the finding.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tamperer {
    pub app: Option<String>,
    pub signer: Option<String>,
    pub user: Option<String>,
    pub time: Option<String>,
}

/// The finding: Hoch, waits during a game; `incidents` = how often so far (this one included).
pub fn tamper_finding(r: &Restored, who: &Tamperer, incidents: u64, now: &str) -> crate::model::Finding {
    use crate::model::{Finding, Kind, Severity};
    let n = r.count();
    let app = who.app.clone();
    let mut names: Vec<&String> = r.missing.iter().chain(&r.altered).chain(&r.extra).collect();
    names.truncate(10);
    let hint = tf!(
        "K9 hat die Regeln sofort wiederhergestellt – die Sperre ist vollständig. {}\
         „Freigabe“ bedeutet nur: dieses Programm wird dafür nicht mehr gemeldet; wiederhergestellt wird trotzdem immer. \
         Willst du die Sperre absichtlich abschalten, nimm `k9 firewall entfernen` oder `k9 funktion firewall aus`.", "K9 restored the rules at once – the block is complete. {}\
         “Allow” only means: this program is no longer reported for it; the rules are still always restored. \
         If you want to switch the block off on purpose, use `k9 firewall entfernen` or `k9 funktion firewall aus`.",
        match &app {
            Some(a) => tf!("Geändert hat sie: {a}{}. ", "Changed by: {a}{}. ", who.signer.as_deref().map(|s| tf!(" (signiert von {s})", " (signed by {s})")).unwrap_or_default()),
            None => t!("Welches Programm sie geändert hat, steht nicht (mehr) im Firewall-Protokoll. ", "Which program changed them is not (or no longer) in the firewall log. ").into(),
        }
    );
    Finding {
        path: std::path::PathBuf::from(t!("K9-Sperrregeln (Gruppe „K9“)", "K9 block rules (group “K9”)")),
        sha256: tamper_fingerprint(app.as_deref()),
        size: 0,
        rule_id: TAMPER_RULE.into(),
        threat_name: tf!("K9-Sperrregeln {} ({n} {}) – wiederhergestellt", "K9 block rules {} ({n} {}) – restored", r.verb(), if n == 1 { t!("Regel", "rule") } else { t!("Regeln", "rules") }),
        category: t!("Selbstschutz", "Self-protection").into(),
        severity: Severity::Hoch,
        engine: "dienst".into(),
        kind: Kind::Firewall,
        details: Some(serde_json::json!({
            "regeln": names,
            "fehlten": r.missing.len(),
            "geaendert": r.altered.len() + r.extra.len(),
            "ersteller": app,
            "ersteller_signatur": who.signer,
            "benutzer": who.user,
            "erstellt": who.time,
            "vorfaelle": incidents,
            "zuletzt": now,
            "hinweis": hint,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses() {
        for bad in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "100.64.0.1", "100.127.255.255", "0.1.2.3", "255.255.255.255", "198.18.0.1", "192.0.2.5", "240.0.0.1"] {
            assert!(!is_public_v4(bad.parse().unwrap()), "{bad}");
        }
        for good in ["8.8.8.8", "50.16.16.211", "100.128.0.1", "172.32.0.1"] {
            assert!(is_public_v4(good.parse().unwrap()), "{good}");
        }
    }

    #[test]
    fn feodo_and_threatfox_are_filtered_strictly() {
        let feodo = r#"[{"ip_address":"50.16.16.211","port":443,"last_online":"2026-03-12"},
                        {"ip_address":"203.0.113.9","port":8080,"last_online":"2026-11-14"},
                        {"ip_address":"45.1.2.3","port":8080,"last_online":"2026-11-14"},
                        {"ip_address":"192.168.0.1","port":80,"last_online":"2026-11-14"}]"#;
        let pairs = |v: Vec<Target>| v.into_iter().map(|t| (t.ip, t.port)).collect::<Vec<_>>();
        assert_eq!(pairs(parse_feodo(feodo, "2026-11-15")), vec![("45.1.2.3".parse().unwrap(), 8080)], "alt, Dokumentations- und private Adressen nicht");
        let mut iocs = BTreeMap::new();
        let ioc = |t: &str, c: u8, seen: &str| Ioc { typ: "ip".into(), malware: "x".into(), first_seen: seen.into(), threat_type: t.into(), confidence: c, last_seen: seen.into() };
        iocs.insert("45.9.9.9:4444".to_string(), ioc("botnet_cc", 100, "2026-11-10"));
        iocs.insert("45.9.9.8:4444".to_string(), ioc("botnet_cc", 75, "2026-11-10"));
        iocs.insert("45.9.9.7:4444".to_string(), ioc("payload_delivery", 100, "2026-11-10"));
        iocs.insert("45.9.9.6:4444".to_string(), ioc("botnet_cc", 100, "2026-09-01"));
        iocs.insert("10.0.0.1:4444".to_string(), ioc("botnet_cc", 100, "2026-11-10"));
        assert_eq!(pairs(threatfox_targets(&iocs, "2026-11-15")), vec![("45.9.9.9".parse().unwrap(), 4444)]);
    }

    #[test]
    fn rules_per_port_and_capped() {
        let many = (0..1500u32).map(|n| (Ipv4Addr::from(0x2D00_0000 + n), if n % 2 == 0 { 443 } else { 8080 }));
        let g = group_by_port(many);
        assert_eq!(g.values().map(Vec::len).sum::<usize>(), MAX_TARGETS);
        let cmds = ps_add(&g, "2026-11-15", "Feodo Tracker, ThreatFox");
        assert_eq!(cmds.len(), 6, "je Port 500 Adressen in 3 Regeln");
        assert!(cmds[0].contains("-DisplayName 'K9 – Botnetz-Server gesperrt (Port 443)'"), "{}", cmds[0]);
        assert!(cmds[1].contains("(Port 443, Teil 2)"));
        assert!(cmds.iter().all(|c| c.contains("-Group 'K9'") && c.contains("-Direction Outbound") && c.contains("-RemotePort ")));
        assert!(cmds[0].contains("zu 200 bekannten Botnetz-Steuerservern") && cmds[0].contains("Feodo Tracker, ThreatFox") && cmds[0].contains("Stand: 2026-11-15"));
        assert!(cmds[0].contains("Entfernen: k9 firewall entfernen"));
        // Nothing but fixed text, addresses, ports and the date: no quote can break out.
        let odd = ps_add(&group_by_port([("45.1.2.3".parse().unwrap(), 80)]), "2026'; x", "a'b");
        assert_eq!(odd[0].matches('\'').count() % 2, 0);
        assert!(!odd[0].contains("'; x"));
    }

    #[test]
    fn shared_cdn_addresses_are_never_blocked_and_the_newest_come_first() {
        let t = |ip: &str, port: u16, seen: &str| Target { ip: ip.parse().unwrap(), port, seen: seen.into() };
        let cdn = Cdn::snapshot();
        for ip in ["3.165.190.81", "18.65.39.69", "18.239.18.119"] {
            assert_eq!(cdn.provider(ip.parse().unwrap()), Some("CloudFront"), "{ip}");
        }
        assert_eq!(cdn.provider("104.16.1.1".parse().unwrap()), Some("Cloudflare"));
        assert_eq!(cdn.provider("151.101.1.1".parse().unwrap()), Some("Fastly"));
        assert_eq!(cdn.provider("142.250.1.1".parse().unwrap()), Some("Google"), "Google-Front-End");
        assert_eq!(cdn.provider("34.150.91.139".parse().unwrap()), None, "Google-Cloud-Kunde ist kein geteiltes Netz");
        assert_eq!(cdn.provider("8.209.1.1".parse().unwrap()), None, "Alibaba");
        assert_eq!(cdn.provider("88.198.1.1".parse().unwrap()), None, "Hetzner");
        let a = select(
            vec![
                t("3.165.190.81", 443, "2026-11-14"),
                t("104.16.1.1", 443, "2026-11-14"),
                t("88.198.1.1", 4444, "2026-11-01"),
                t("8.209.1.1", 443, "2026-11-15"),
                t("8.209.1.1", 443, "2026-11-10"),
            ],
            &cdn,
        );
        assert_eq!(a.count(), 2, "Hetzner und Alibaba bleiben");
        assert_eq!(a.skipped_text().unwrap(), "2 Adressen in geteilten CDN-Netzen uebersprungen (CloudFront 1, Cloudflare 1)");
        assert_eq!(a.dates, Some(("2026-11-01".to_string(), "2026-11-15".to_string())));
        // Over the cap: the newest win, not the lowest addresses.
        let many: Vec<Target> = (0..1200u32)
            .map(|n| Target { ip: Ipv4Addr::from(0x5800_0000 + n), port: 4444, seen: if n >= 1100 { "2026-11-15".into() } else { "2026-10-20".into() } })
            .collect();
        let a = select(many, &cdn);
        assert_eq!(a.count(), MAX_TARGETS);
        assert_eq!(a.cut, 200);
        assert!(a.groups[&4444].contains(&Ipv4Addr::from(0x5800_0000 + 1199)), "neuester Eintrag dabei");
        assert_eq!(a.dates.as_ref().unwrap().1, "2026-11-15");
    }

    #[test]
    fn published_cdn_lists_are_read_and_a_missing_list_falls_back_to_the_snapshot() {
        assert_eq!(parse_cdn_list("Cloudflare", "173.245.48.0/20\nkaputt\n104.16.0.0/13\n"), vec!["173.245.48.0/20", "104.16.0.0/13"]);
        let aws = r#"{"prefixes":[{"ip_prefix":"3.160.0.0/14","service":"CLOUDFRONT"},{"ip_prefix":"3.0.0.0/15","service":"EC2"},{"ip_prefix":"18.68.0.0/16","service":"CLOUDFRONT_ORIGIN_FACING"}]}"#;
        assert_eq!(parse_cdn_list("CloudFront", aws), vec!["3.160.0.0/14", "18.68.0.0/16"]);
        assert_eq!(parse_cdn_list("Fastly", r#"{"addresses":["151.101.0.0/16"]}"#), vec!["151.101.0.0/16"]);
        assert!(parse_cdn_list("CloudFront", "kein json").is_empty());
        let mut c = Cdn::default();
        c.add_snapshot(&["CloudFront"]);
        assert_eq!(c.provider("18.65.39.69".parse().unwrap()), Some("CloudFront"));
    }

    #[test]
    fn only_our_rules_are_removed_also_the_old_ones() {
        let list = parse_list(
            "{A1}|K9 – Botnetz-Server gesperrt (Port 443)|K9\r\n\
             {A2}|K9 – Botnetz-Server gesperrt (Port 8080, Teil 2)|K9\n\
             {B1}|Virenscanner C2-Sperre|\n\
             {F1}|K9 – Botnetz-Server gesperrt (Port 443)|Andere Gruppe\n\
             {F2}|K9 Updates erlauben|K9\n\
             {F3}|Virenscanner C2-Sperre alt|\n\
             {F4}|Steam|Steam\n\
             {C1}|Virenscanner – Botnetz-Server gesperrt (Port 443)|Virenscanner\n\
             {F5}|Virenscanner – Botnetz-Server gesperrt (Port 443)|K9-Fremd\n\
             x'; Remove-NetFirewallRule *|K9 – Botnetz-Server gesperrt (Port 1)|K9\n",
        );
        let own: Vec<String> = own_rules(&list).into_iter().map(|r| r.id).collect();
        assert_eq!(own, vec!["{A1}", "{A2}", "{B1}", "{C1}"], "fremde Regeln in derselben Gruppe oder mit ähnlichem Namen bleiben");
        let cmd = ps_remove(&own_rules(&list)).unwrap();
        assert_eq!(cmd, "Remove-NetFirewallRule -Name '{A1}','{A2}','{B1}','{C1}' -ErrorAction Stop");
        assert_eq!(ps_remove(&[]), None);
    }

    /// Fake firewall: records every write and what is blocked after each step.
    #[derive(Default)]
    struct Fake {
        rules: Vec<FwRule>,
        ops: Vec<String>,
        fail_at: Option<usize>,
        after_each: Vec<BTreeSet<(String, Ipv4Addr)>>,
    }

    impl Fake {
        fn blocked(&self) -> BTreeSet<(String, Ipv4Addr)> {
            self.rules
                .iter()
                .filter(|r| r.outbound && r.block && r.enabled)
                .flat_map(|r| r.address_set().unwrap_or_default().into_iter().map(move |ip| (r.port.clone(), ip)))
                .collect()
        }
        fn step(&mut self, op: String) -> anyhow::Result<()> {
            if self.fail_at == Some(self.ops.len()) {
                anyhow::bail!("Testfehler");
            }
            self.ops.push(op);
            Ok(())
        }
    }

    impl FwBackend for Fake {
        fn list(&mut self) -> anyhow::Result<Vec<FwRule>> {
            Ok(self.rules.clone())
        }
        fn add(&mut self, r: &FwRule) -> anyhow::Result<()> {
            self.step(format!("neu {}", r.name))?;
            self.rules.push(r.clone());
            self.after_each.push(self.blocked());
            Ok(())
        }
        fn update(&mut self, r: &FwRule) -> anyhow::Result<()> {
            self.step(format!("aendern {}", r.name))?;
            let x = self.rules.iter_mut().find(|x| x.name == r.name).unwrap();
            *x = r.clone();
            self.after_each.push(self.blocked());
            Ok(())
        }
        fn remove(&mut self, name: &str) -> anyhow::Result<()> {
            self.step(format!("weg {name}"))?;
            self.rules.retain(|x| x.name != name);
            self.after_each.push(self.blocked());
            Ok(())
        }
        fn label(&self) -> &'static str {
            "Test"
        }
    }

    fn groups(list: &[(u16, &[&str])]) -> BTreeMap<u16, Vec<Ipv4Addr>> {
        list.iter().map(|(p, ips)| (*p, ips.iter().map(|i| i.parse().unwrap()).collect())).collect()
    }

    /// As the firewall reports a rule: addresses with mask, other description/date.
    fn as_listed(mut r: FwRule) -> FwRule {
        r.addresses = r.address_set().unwrap().iter().map(|i| format!("{i}/255.255.255.255")).collect::<Vec<_>>().join(",");
        r.description = "Stand: gestern".into();
        r
    }

    #[test]
    fn address_lists_are_compared_as_sets() {
        let r = FwRule { addresses: "45.1.2.3/255.255.255.255, 45.1.2.4/32,45.1.2.5".into(), ..Default::default() };
        assert_eq!(r.address_set().unwrap().len(), 3);
        let com = FwRule { addresses: "1.15.82.253-1.15.82.253,5.231.31.57-5.231.31.57".into(), ..Default::default() };
        assert_eq!(com.address_set().unwrap().len(), 2, "so meldet die COM-Schnittstelle einzelne Adressen");
        assert_eq!(FwRule { addresses: "10.0.0.0/255.0.0.0".into(), ..Default::default() }.address_set(), None, "Netz statt Adresse");
        assert_eq!(FwRule { addresses: "45.1.2.3-45.1.2.9".into(), ..Default::default() }.address_set(), None, "Bereich");
    }

    #[test]
    fn unchanged_start_writes_nothing() {
        let wanted = wanted_rules(&groups(&[(443, &["45.1.2.3", "45.1.2.4"]), (8080, &["46.1.1.1"])]), "2026-11-16", "ThreatFox");
        let mut fw = Fake { rules: wanted.iter().cloned().map(as_listed).collect(), ..Default::default() };
        let p = plan(&wanted, &fw.list().unwrap());
        assert_eq!(p.writes(), 0, "{p:?}");
        assert_eq!(p.keep.len(), 2);
        assert_eq!(apply(&mut fw, &p).unwrap(), Applied::default());
        assert!(fw.ops.is_empty());
        // a rule switched off or with another port is not "unchanged"
        let mut off = as_listed(wanted[0].clone());
        off.enabled = false;
        assert_eq!(plan(&wanted[..1], &[off]).update.len(), 1);
    }

    #[test]
    fn refresh_adds_and_updates_before_removing_and_never_opens_a_gap() {
        let old = wanted_rules(&groups(&[(443, &["45.1.2.3", "45.1.2.4"]), (80, &["47.1.1.1"])]), "2026-11-15", "ThreatFox");
        let mut current: Vec<FwRule> = old.iter().cloned().map(as_listed).collect();
        // rule of an older version and a foreign rule that is never touched
        current.push(FwRule { name: OLD_RULE_NAMES[0].into(), group: String::new(), port: "4444".into(), addresses: "48.1.1.1".into(), outbound: true, block: true, tcp: true, enabled: true, ..Default::default() });
        current.push(FwRule { name: "Fremde Regel".into(), group: RULE_GROUP.into(), port: "1".into(), addresses: "49.1.1.1".into(), outbound: true, block: true, tcp: true, enabled: true, ..Default::default() });
        let wanted = wanted_rules(&groups(&[(443, &["45.1.2.4", "45.1.2.5"]), (8080, &["46.1.1.1"])]), "2026-11-16", "ThreatFox");
        let mut fw = Fake { rules: current.clone(), ..Default::default() };
        let p = plan(&wanted, &fw.list().unwrap());
        assert_eq!(p.update.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), [rule_name(443, 0)]);
        assert_eq!(p.add.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), [rule_name(8080, 0)]);
        assert_eq!(p.remove, vec![rule_name(80, 0), OLD_RULE_NAMES[0].to_string()]);
        let before = fw.blocked();
        let r = apply(&mut fw, &p).unwrap();
        assert_eq!(r, Applied { updated: 1, added: 1, removed: 2 });
        // order: every change before the first removal
        let first_remove = fw.ops.iter().position(|o| o.starts_with("weg")).unwrap();
        assert!(fw.ops[..first_remove].iter().all(|o| !o.starts_with("weg")) && first_remove == 2, "{:?}", fw.ops);
        // still wanted addresses stay blocked at every step
        let after = fw.blocked();
        for (i, snap) in fw.after_each.iter().enumerate() {
            for keep in before.intersection(&after) {
                assert!(snap.contains(keep), "Lücke nach Schritt {i}: {keep:?}");
            }
        }
        assert!(after.contains(&("8080".into(), "46.1.1.1".parse().unwrap())));
        assert!(!after.contains(&("80".into(), "47.1.1.1".parse().unwrap())));
        assert!(fw.rules.iter().any(|r| r.name == "Fremde Regel"), "fremde Regel bleibt");
        // a second run finds nothing to do
        assert_eq!(plan(&wanted, &fw.list().unwrap()).writes(), 0);
    }

    #[test]
    fn failure_midway_keeps_the_old_rules() {
        let old = wanted_rules(&groups(&[(443, &["45.1.2.3"]), (80, &["47.1.1.1"])]), "2026-11-15", "ThreatFox");
        let wanted = wanted_rules(&groups(&[(443, &["45.1.2.4"]), (8080, &["46.1.1.1"])]), "2026-11-16", "ThreatFox");
        let mut fw = Fake { rules: old.clone(), fail_at: Some(1), ..Default::default() };
        let p = plan(&wanted, &fw.list().unwrap());
        assert!(apply(&mut fw, &p).is_err());
        assert!(fw.ops.iter().all(|o| !o.starts_with("weg")), "nichts entfernt: {:?}", fw.ops);
        assert!(fw.rules.iter().any(|r| r.name == rule_name(80, 0)), "alte Regel bleibt");
        // the next run completes it
        fw.fail_at = None;
        let p = plan(&wanted, &fw.list().unwrap());
        apply(&mut fw, &p).unwrap();
        assert_eq!(plan(&wanted, &fw.list().unwrap()).writes(), 0);
    }

    #[test]
    fn a_foreign_rule_with_our_name_is_never_changed() {
        let wanted = wanted_rules(&groups(&[(443, &["45.1.2.3"])]), "2026-11-16", "ThreatFox");
        let foreign = FwRule { name: rule_name(443, 0), group: "Andere".into(), ..Default::default() };
        let p = plan(&wanted, std::slice::from_ref(&foreign));
        assert_eq!(p.conflicts, vec![rule_name(443, 0)]);
        assert_eq!(p.writes(), 0);
        // nor removed when it shares the name of one of our obsolete rules
        let mine = as_listed(wanted_rules(&groups(&[(80, &["47.1.1.1"])]), "x", "y")[0].clone());
        let twin = FwRule { name: mine.name.clone(), group: "Andere".into(), ..Default::default() };
        let p = plan(&[], &[mine, twin]);
        assert!(p.remove.is_empty() && p.conflicts.len() == 1, "{p:?}");
    }

    #[test]
    fn powershell_listing_is_parsed() {
        let out = "K9 – Botnetz-Server gesperrt (Port 443)|K9|443|45.1.2.3,45.1.2.4|Outbound|Block|TCP|True|Angelegt vom K9-Dienst\r\n";
        let r = &parse_sync_list(out)[0];
        assert!(r.outbound && r.block && r.tcp && r.enabled);
        assert_eq!((r.port.as_str(), r.address_set().unwrap().len()), ("443", 2));
    }

    #[test]
    fn guard_restores_deleted_disabled_and_changed_rules() {
        let wanted = wanted_rules(&groups(&[(443, &["45.1.2.3", "45.1.2.4"]), (80, &["47.1.1.1"]), (8080, &["46.1.1.1"])]), "2026-11-16", "ThreatFox");
        let fresh = || Fake { rules: wanted.iter().cloned().map(as_listed).collect(), ..Default::default() };
        // nothing changed (also right after K9's own sync): nothing to do, nothing to report
        let mut fw = fresh();
        assert!(guard(&mut fw, &wanted).unwrap().is_empty());
        assert!(fw.ops.is_empty());
        let mut synced = Fake::default();
        apply(&mut synced, &plan(&wanted, &[])).unwrap();
        synced.ops.clear();
        assert!(guard(&mut synced, &wanted).unwrap().is_empty(), "eigener Abgleich wird nicht gemeldet");
        // one rule deleted
        let mut fw = fresh();
        fw.rules.retain(|r| r.name != rule_name(80, 0));
        let r = guard(&mut fw, &wanted).unwrap();
        assert_eq!((r.missing.len(), r.verb()), (1, "entfernt"));
        assert!(guard(&mut fw, &wanted).unwrap().is_empty(), "danach wieder vollständig");
        // all deleted
        let mut fw = fresh();
        fw.rules.clear();
        assert_eq!(guard(&mut fw, &wanted).unwrap().missing.len(), 3);
        // switched off and addresses changed
        let mut fw = fresh();
        fw.rules[0].enabled = false;
        fw.rules[1].addresses = "8.8.8.8".into();
        let r = guard(&mut fw, &wanted).unwrap();
        assert_eq!((r.altered.len(), r.verb()), (2, "geändert"));
        assert_eq!(plan(&wanted, &fw.list().unwrap()).writes(), 0);
        // the guard never touches a foreign rule
        let mut fw = fresh();
        fw.rules.push(FwRule { name: "Fremde Regel".into(), group: "Andere".into(), ..Default::default() });
        fw.rules.retain(|r| r.name != rule_name(443, 0));
        guard(&mut fw, &wanted).unwrap();
        assert!(fw.rules.iter().any(|r| r.name == "Fremde Regel"));
    }

    #[test]
    fn guard_respects_off_and_entfernen() {
        assert!(guard_active(true, false, true));
        assert!(!guard_active(false, false, true), "Sperre aus");
        assert!(!guard_active(true, true, true), "nach k9 firewall entfernen bis zur nächsten Erneuerung");
        assert!(!guard_active(true, false, false), "vor dem ersten Abgleich");
    }

    #[test]
    fn repeated_tampering_is_one_finding_per_program() {
        let r = Restored { missing: vec![rule_name(80, 0)], ..Default::default() };
        let who = Tamperer { app: Some(r"C:\Windows\System32\netsh.exe".into()), ..Default::default() };
        let a = tamper_finding(&r, &who, 1, "2026-11-16 08:00:00");
        let b = tamper_finding(&r, &who, 2, "2026-11-16 08:05:00");
        assert_eq!(a.sha256, b.sha256, "gleicher Fund, Zähler steigt");
        assert_eq!(b.details.as_ref().unwrap()["vorfaelle"], 2);
        assert_eq!(a.severity, crate::model::Severity::Hoch);
        assert!(a.threat_name.contains("entfernt (1 Regel) – wiederhergestellt"), "{}", a.threat_name);
        let other = tamper_finding(&r, &Tamperer::default(), 1, "x");
        assert_ne!(a.sha256, other.sha256);
        assert!(!a.rule_id.starts_with("SELBSTSCHUTZ:"), "wartet während eines Spiels");
    }
}
