//! Watch over inbound firewall rules: a new rule that lets connections from anywhere in –
//! without a program (opens the port for every program), for a program in a user-writable
//! folder or for a program without a valid signature – becomes a finding. Rules for validly
//! signed programs elsewhere (Program Files, game libraries) are only logged.
//!
//! The rules are read from the firewall's rule store in the registry (fast, with the rule id);
//! the program that created a rule comes from the firewall's event log. Nothing is ever
//! changed automatically: removing a rule happens only on the user's decision, and only for
//! exactly the reported rule(s).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::model::{Finding, Kind, Severity};

/// Rule store of the Windows firewall (local rules; group policy rules live elsewhere).
pub const STORE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
pub const RULE_ID: &str = "FIREWALL:EINGANG";
const ALL_PROFILES: &str = "";

/// One firewall rule as stored in the registry ("v2.33|Action=Allow|Dir=In|...").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InRule {
    /// Value name in the rule store (the rule id, e.g. "{A7D8BF52-…}").
    pub id: String,
    pub name: String,
    pub group: String,
    pub inbound: bool,
    pub allow: bool,
    pub enabled: bool,
    /// Protocol number as text ("6" TCP, "17" UDP), empty = any.
    pub protocol: String,
    /// Local ports, comma-separated, empty = any.
    pub ports: String,
    /// Remote addresses, comma-separated, empty = any.
    pub remote: String,
    /// Profiles ("Public,Private"), empty = all.
    pub profiles: String,
    pub app: String,
    pub service: String,
    /// Store app (package) the rule belongs to.
    pub package: String,
    /// Network interfaces the rule is bound to (GUIDs, comma-separated), empty = all.
    pub interfaces: String,
}

/// Parses one value of the rule store.
pub fn parse_rule(id: &str, data: &str) -> Option<InRule> {
    let mut parts = data.split('|');
    if !parts.next()?.starts_with('v') {
        return None;
    }
    let mut r = InRule { id: id.to_string(), ..Default::default() };
    let mut lists: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for p in parts {
        let Some((k, v)) = p.split_once('=') else { continue };
        match k {
            "Action" => r.allow = v.eq_ignore_ascii_case("Allow"),
            "Active" => r.enabled = v.eq_ignore_ascii_case("TRUE"),
            "Dir" => r.inbound = v.eq_ignore_ascii_case("In"),
            "Protocol" => r.protocol = v.to_string(),
            "Name" => r.name = v.to_string(),
            "EmbedCtxt" => r.group = v.to_string(),
            "App" => r.app = v.to_string(),
            "Svc" => r.service = v.to_string(),
            "PFN" | "AppPkgId" => r.package = v.to_string(),
            "LPort" | "LPort2_10" | "RA4" | "RA42" | "RA6" | "RA62" | "Profile" | "IF" => lists.entry(k).or_default().push(v),
            _ => {}
        }
    }
    let join = |keys: &[&str]| keys.iter().flat_map(|k| lists.get(k).cloned().unwrap_or_default()).collect::<Vec<_>>().join(",");
    r.ports = join(&["LPort", "LPort2_10"]);
    r.remote = join(&["RA4", "RA42", "RA6", "RA62"]);
    r.profiles = join(&["Profile"]);
    r.interfaces = join(&["IF"]);
    Some(r)
}

/// All rules of the local rule store.
pub fn read_store() -> Vec<InRule> {
    crate::winreg::string_values(windows::Win32::System::Registry::HKEY_LOCAL_MACHINE, STORE_KEY)
        .into_iter()
        .filter_map(|(id, data)| parse_rule(&id, &data))
        .collect()
}

impl InRule {
    /// Rule of Windows' container networking (Windows Sandbox, WSL, Hyper-V containers): Windows
    /// creates "HNS Container Networking - DNS …" for the name service of the container's own
    /// virtual network every time one starts – bound to that one network interface, port 53/67/68
    /// only. All three must hold; the name alone hides nothing.
    pub fn container_network(&self) -> bool {
        self.name.starts_with("HNS Container Networking")
            && !self.interfaces.is_empty()
            && !self.ports.is_empty()
            && self.ports.split(',').all(|p| matches!(p.trim(), "53" | "67" | "68"))
    }

    /// Everything that makes up what the rule allows (not its id or description): identical
    /// rules added again and again share it.
    pub fn signature(&self) -> String {
        let s = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.name.to_lowercase(),
            self.inbound,
            self.allow,
            self.enabled,
            self.protocol,
            self.ports,
            self.remote.to_lowercase(),
            self.profiles.to_lowercase(),
            self.app.to_lowercase(),
            self.service.to_lowercase(),
            self.package.to_lowercase()
        );
        crate::sha256_hex(s.as_bytes())
    }

    pub fn remote_any(&self) -> bool {
        self.remote.split(',').map(str::trim).all(|a| a.is_empty() || a == "*")
    }

    /// Valid for the public profile (or all profiles).
    pub fn public(&self) -> bool {
        self.profiles == ALL_PROFILES || self.profiles.to_lowercase().contains("public")
    }

    pub fn protocol_name(&self) -> String {
        match self.protocol.as_str() {
            "" => t!("alle Protokolle", "all protocols").into(),
            "6" => "TCP".into(),
            "17" => "UDP".into(),
            "1" => "ICMPv4".into(),
            "58" => "ICMPv6".into(),
            p => tf!("Protokoll {p}", "protocol {p}"),
        }
    }

    pub fn profiles_text(&self) -> String {
        if self.profiles.is_empty() {
            t!("alle (Domäne, Privat, Öffentlich)", "all (domain, private, public)").into()
        } else {
            if crate::sprache::en() {
                self.profiles.replace(',', ", ")
            } else {
                if crate::sprache::en() {
                self.profiles.replace(',', ", ")
            } else {
                self.profiles.replace("Public", "Öffentlich").replace("Private", "Privat").replace("Domain", "Domäne").replace(',', ", ")
            }
            }
        }
    }

    /// The program path with environment variables expanded.
    pub fn app_path(&self) -> Option<PathBuf> {
        (!self.app.is_empty()).then(|| PathBuf::from(expand_env(&self.app)))
    }

    fn own(&self) -> bool {
        self.name.starts_with(crate::firewall::RULE_PREFIX) || self.group == crate::firewall::RULE_GROUP
    }
}

/// Expands %VAR% parts (as used in firewall rules: %SystemRoot%, %ProgramFiles% …).
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// A folder normal programs (and so malware without admin rights) can write to.
pub fn user_writable(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase().replace('/', "\\");
    let p = p.trim_start_matches(r"\\?\");
    p.starts_with(r"c:\users\") || p.starts_with(r"c:\programdata\") || p.contains(r"\appdata\") || p.contains(r"\temp\")
}

/// A part of Windows itself (system folder, not its Temp; or the kernel "System").
pub fn windows_component(app: &str, path: &Path) -> bool {
    if app.eq_ignore_ascii_case("System") {
        return true;
    }
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
    let p = path.to_string_lossy().to_lowercase();
    p.starts_with(&format!("{windir}\\")) && !user_writable(path)
}

/// Why a rule is reported (None: only logged).
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub severity: Severity,
    pub reason: String,
}

/// Assesses an inbound rule. `signed_ok(path)`: false only for a file that is definitely not
/// validly signed (a file that cannot be checked counts as fine).
pub fn assess(r: &InRule, signed_ok: &dyn Fn(&Path) -> bool) -> Option<Assessment> {
    if !(r.inbound && r.allow && r.enabled) || !r.remote_any() || r.own() || r.container_network() {
        return None;
    }
    if r.app.is_empty() && r.service.is_empty() && r.package.is_empty() {
        let severity = if r.public() { Severity::Hoch } else { Severity::Mittel };
        return Some(Assessment {
            severity,
            reason: t!("Die Regel gilt für jedes Programm: Jedes Programm auf diesem PC darf an diesem Port Verbindungen von überall annehmen.", "The rule applies to every program: every program on this PC may accept connections from anywhere on this port.").into(),
        });
    }
    if !r.package.is_empty() || r.app.is_empty() {
        return None; // Store app (runs in its sandbox) or Windows service
    }
    let path = r.app_path()?;
    if windows_component(&r.app, &path) {
        return None;
    }
    if user_writable(&path) {
        return Some(Assessment {
            severity: Severity::Mittel,
            reason: t!("Das Programm liegt in einem Ordner, in den jedes Programm schreiben kann (z. B. Benutzerordner, Temp).", "The program is in a folder every program can write to (e.g. user folder, Temp).").into(),
        });
    }
    if !path.is_file() {
        return None; // left over from an uninstalled program; Program Files needs admin rights
    }
    if !signed_ok(&path) {
        return Some(Assessment { severity: Severity::Mittel, reason: t!("Das Programm ist nicht gültig digital signiert.", "The program has no valid digital signature.").into() });
    }
    None
}

/// New or changed rules since `known` (id -> signature).
pub fn changes<'a>(known: &BTreeMap<String, String>, current: &'a [InRule]) -> Vec<&'a InRule> {
    current.iter().filter(|r| known.get(&r.id) != Some(&r.signature())).collect()
}

/// id -> signature of all current rules (the baseline for the next comparison).
pub fn snapshot(current: &[InRule]) -> BTreeMap<String, String> {
    current.iter().map(|r| (r.id.clone(), r.signature())).collect()
}

/// A reported rule, collapsed over all identical copies.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub rule: InRule,
    pub assessment: Assessment,
    /// Ids of all rules with the same signature (also older copies).
    pub ids: Vec<String>,
}

/// The reports for a set of changes: one per signature, with all identical copies.
pub fn reports(changed: &[&InRule], current: &[InRule], signed_ok: &dyn Fn(&Path) -> bool) -> Vec<Report> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in changed {
        let sig = r.signature();
        if !seen.insert(sig.clone()) {
            continue;
        }
        if let Some(assessment) = assess(r, signed_ok) {
            let ids = current.iter().filter(|c| c.signature() == sig).map(|c| c.id.clone()).collect();
            out.push(Report { rule: (*r).clone(), assessment, ids });
        }
    }
    out
}

/// Who created/changed the rule (from the firewall event log).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Creator {
    pub app: String,
    pub user: String,
    pub time: String,
}

/// Reads the creating application from a rule event (2004/2097 added, 2005/2099 changed).
pub fn parse_creator(xml: &str) -> Option<Creator> {
    let field = |name: &str| {
        let key = format!("<Data Name='{name}'>");
        let start = xml.find(&key)? + key.len();
        let end = xml[start..].find("</Data>")? + start;
        Some(xml[start..end].to_string())
    };
    let time = xml.find("SystemTime='").and_then(|i| xml[i + 12..].split('\'').next().map(str::to_string)).unwrap_or_default();
    Some(Creator { app: field("ModifyingApplication")?, user: field("ModifyingUser").unwrap_or_default(), time })
}

/// The newest add/change event of this rule id (None: not in the log any more).
pub fn creator(rule_id: &str) -> Option<Creator> {
    creator_with(rule_id, &[2004, 2005, 2097, 2099])
}

/// Who deleted or changed this rule (events 2006/2052 deleted, 2005/2099 changed).
pub fn changer(rule_id: &str) -> Option<Creator> {
    creator_with(rule_id, &[2005, 2006, 2052, 2099])
}

/// The newest event with one of these ids for this rule id.
pub fn creator_with(rule_id: &str, events: &[u32]) -> Option<Creator> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE};
    if !rule_id.chars().all(|c| c.is_ascii_alphanumeric() || "{}-_".contains(c)) {
        return None;
    }
    let channel = HSTRING::from("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall");
    let ids = events.iter().map(|e| format!("EventID={e}")).collect::<Vec<_>>().join(" or ");
    let query = HSTRING::from(format!("*[System[({ids})]] and *[EventData[Data[@Name='RuleId']='{rule_id}']]"));
    // SAFETY: event log query; every handle is closed, the buffer is sized by the API.
    unsafe {
        let q = EvtQuery(None, PCWSTR(channel.as_ptr()), PCWSTR(query.as_ptr()), EvtQueryChannelPath.0 | EvtQueryReverseDirection.0).ok()?;
        let mut ev = [0isize; 1];
        let mut got = 0u32;
        let found = EvtNext(q, &mut ev, 2000, 0, &mut got).is_ok() && got == 1;
        let mut out = None;
        if found {
            let h = EVT_HANDLE(ev[0]);
            let mut used = 0u32;
            let mut props = 0u32;
            let _ = EvtRender(None, h, EvtRenderEventXml.0, 0, None, &mut used, &mut props);
            let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
            if EvtRender(None, h, EvtRenderEventXml.0, (buf.len() * 2) as u32, Some(buf.as_mut_ptr().cast()), &mut used, &mut props).is_ok() {
                let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).min(buf.len())]);
                out = parse_creator(&xml);
            }
            let _ = EvtClose(h);
        }
        let _ = EvtClose(q);
        out
    }
}

/// The finding for a report.
pub fn finding(rep: &Report, creator: Option<&Creator>, creator_signer: Option<&str>) -> Finding {
    let r = &rep.rule;
    let n = rep.ids.len();
    let times = if n > 1 { tf!(" ({n}-mal vorhanden)", " (exists {n} times)") } else { String::new() };
    let program = if r.app.is_empty() && r.service.is_empty() && r.package.is_empty() {
        t!("jedes Programm", "every program").to_string()
    } else if !r.app.is_empty() {
        r.app.clone()
    } else if !r.service.is_empty() {
        tf!("Dienst {}", "service {}", r.service)
    } else {
        format!("App {}", r.package)
    };
    let hint = tf!(
        "{} „Regel entfernen“ löscht genau diese Regel{} – nichts anderes. Wird sie danach wieder angelegt, meldet K9 das erneut; \
         dann das genannte Programm prüfen. „Freigabe“ merkt sich genau diese Regel und meldet sie nicht mehr.", "{} “Remove rule” deletes exactly this rule{} – nothing else. If it is created again afterwards, K9 reports that again; \
         then check the program named. “Allow” remembers exactly this rule and does not report it any more.",
        rep.assessment.reason,
        if n > 1 { tf!(" und ihre {} gleichen Kopien", " and its {} identical copies", n - 1) } else { String::new() }
    );
    Finding {
        path: PathBuf::from(tf!("Eingehende Regel „{}“{times}", "Inbound rule “{}”{times}", r.name)),
        sha256: r.signature(),
        size: 0,
        rule_id: RULE_ID.into(),
        threat_name: tf!("Neue eingehende Freigaberegel „{}“ ({} {})", "New inbound allow rule “{}” ({} {})", r.name, r.protocol_name(), if r.ports.is_empty() { t!("alle Ports", "all ports").into() } else { format!("Port {}", r.ports) }),
        category: "Firewall".into(),
        severity: rep.assessment.severity,
        engine: "dienst".into(),
        kind: Kind::Firewall,
        details: Some(serde_json::json!({
            "name": r.name,
            "richtung": "eingehend",
            "aktion": "zulassen",
            "protokoll": r.protocol_name(),
            "ports": if r.ports.is_empty() { t!("alle", "all").to_string() } else { r.ports.clone() },
            "von": t!("jede Adresse", "any address"),
            "profile": r.profiles_text(),
            "programm": program,
            "gruppe": r.group,
            "ersteller": creator.map(|c| c.app.clone()),
            "ersteller_signatur": creator_signer,
            "erstellt": creator.map(|c| c.time.clone()),
            "anzahl": n,
            // the first ids only (removal finds all copies by their content anyway)
            "ids": rep.ids.iter().take(20).collect::<Vec<_>>(),
            "hinweis": hint,
        })),
    }
}

/// Ids to remove for a finding: only rules that still have exactly the reported signature
/// (never K9's own, never a rule that changed meanwhile).
pub fn removal_ids(current: &[InRule], reported_ids: &[String], signature: &str) -> Vec<String> {
    let wanted: BTreeSet<&str> = reported_ids.iter().map(String::as_str).collect();
    current
        .iter()
        .filter(|r| r.signature() == signature && !r.own() && (wanted.contains(r.id.as_str()) || wanted.is_empty()))
        .map(|r| r.id.clone())
        .collect()
}

/// Removes these rules (by id) with PowerShell's NetSecurity module, in chunks.
pub fn remove_ids(ids: &[String]) -> anyhow::Result<usize> {
    // The id goes into a single-quoted PowerShell string: everything printable except the quote
    // itself is literal there (Windows' own rules have ids with spaces and brackets).
    let safe: Vec<&String> = ids.iter().filter(|i| !i.is_empty() && i.len() <= 200 && i.chars().all(|c| (c.is_ascii_graphic() || c == ' ') && c != '\'' && c != '`')).collect();
    anyhow::ensure!(safe.len() == ids.len(), "ungültige Regel-Kennung");
    let mut done = 0;
    for chunk in safe.chunks(300) {
        let list = chunk.iter().map(|i| format!("'{i}'")).collect::<Vec<_>>().join(",");
        match crate::firewall::powershell(&format!("Remove-NetFirewallRule -Name {list} -ErrorAction Stop")) {
            Some((true, _)) => done += chunk.len(),
            _ => anyhow::bail!("Firewall-Regeln konnten nicht entfernt werden ({done} von {} entfernt)", ids.len()),
        }
    }
    Ok(done)
}

/// "Regel entfernen" for a finding: re-reads the store and removes exactly the reported rule(s).
pub fn remove_for(det: &crate::model::Detection) -> anyhow::Result<usize> {
    let ids: Vec<String> = det
        .details
        .as_ref()
        .and_then(|d| d["ids"].as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    anyhow::ensure!(!ids.is_empty(), "Regel-Kennung fehlt");
    let current = read_store();
    let mut targets = removal_ids(&current, &ids, &det.sha256);
    // Copies added after the report with exactly the same content go as well.
    for id in removal_ids(&current, &[], &det.sha256) {
        if !targets.contains(&id) {
            targets.push(id);
        }
    }
    if targets.is_empty() {
        return Ok(0); // already gone
    }
    remove_ids(&targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_9009: &str = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9009|Name=allow 9009|";

    fn rule(id: &str, data: &str) -> InRule {
        parse_rule(id, data).unwrap()
    }

    #[test]
    fn sandbox_network_rules_are_not_reported_and_ids_with_spaces_can_be_removed() {
        // As Windows creates it when the Windows Sandbox starts (18.11.2026, #237).
        let id = "HNS Container Networking - DNS (UDP-In) - C08CB7B8-9B3C-408E-8E30-5E16A3AEB445 - 0";
        let hns = rule(id, &format!("v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=53|IF={{F0150341-B93A-4A13-A60C-001D8EC459CD}}|Name={id}|Desc={id}|"));
        assert!(hns.container_network());
        assert!(assess(&hns, &|_| true).is_none(), "gehoert zur Sandbox: nur Protokoll");
        // The name alone hides nothing: without the interface binding or with another port it is reported.
        let all_networks = rule("x", &format!("v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=53|Name={id}|"));
        assert!(assess(&all_networks, &|_| true).is_some());
        let other_port = rule("y", &format!("v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|IF={{F0150341-B93A-4A13-A60C-001D8EC459CD}}|Name={id}|"));
        assert!(assess(&other_port, &|_| true).is_some());
        // Removing: such an id is valid (it failed with "ungültige Regel-Kennung"); a quote never is.
        let ok = |i: &str| !i.is_empty() && i.len() <= 200 && i.chars().all(|c| (c.is_ascii_graphic() || c == ' ') && c != '\'' && c != '`');
        assert!(ok(id) && ok("{A7D8BF52-1111-2222-3333-444444444444}"));
        assert!(!ok("x'; Remove-Item C:\\ -Recurse; '") && !ok("a`b") && !ok(""));
    }

    #[test]
    fn rule_store_values_are_parsed() {
        let r = rule("{A}", RULE_9009);
        assert!(r.inbound && r.allow && r.enabled && r.remote_any() && r.public());
        assert_eq!((r.protocol_name().as_str(), r.ports.as_str(), r.name.as_str()), ("TCP", "9009", "allow 9009"));
        let r = rule("{B}", "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Private|RA4=LocalSubnet|App=%ProgramFiles%\\x\\a.exe|Name=x|");
        assert!(!r.remote_any() && !r.public());
        assert_eq!(r.profiles_text(), "Privat");
        assert!(parse_rule("{C}", "kein Regeltext").is_none());
    }

    #[test]
    fn only_risky_inbound_allows_are_reported() {
        let signed = |_: &Path| true;
        let unsigned = |_: &Path| false;
        // no program, all profiles: Hoch
        assert_eq!(assess(&rule("{A}", RULE_9009), &signed).unwrap().severity, Severity::Hoch);
        // no program, private only: Mittel
        let private = rule("{A}", "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=1|Name=p|");
        assert_eq!(assess(&private, &signed).unwrap().severity, Severity::Mittel);
        // program in the user profile: Mittel even if signed
        let user = rule("{A}", "v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\\Users\\f\\AppData\\Local\\x\\x.exe|Name=x|");
        assert!(assess(&user, &signed).is_some());
        // signed program in Program Files or a game library: only logged; unsigned: reported;
        // a program that no longer exists there (uninstalled): only logged
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let exe = dir.path().join("spiel.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let game = rule("{A}", &format!("v2.33|Action=Allow|Active=TRUE|Dir=In|App={}|Name=g|", exe.display()));
        assert!(assess(&game, &signed).is_none());
        assert!(assess(&game, &unsigned).is_some());
        let gone = rule("{A}", "v2.33|Action=Allow|Active=TRUE|Dir=In|App=D:\\gibt-es-nicht-k9\\g.exe|Name=g|");
        assert!(assess(&gone, &unsigned).is_none());
        // Windows itself and Store apps: only logged
        for data in [
            "v2.33|Action=Allow|Active=TRUE|Dir=In|App=System|LPort=445|Name=w|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|App=%SystemRoot%\\system32\\svchost.exe|Name=w|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|AppPkgId=S-1-15-2-1|Name=@{app}|",
        ] {
            assert!(assess(&rule("{W}", data), &unsigned).is_none(), "{data}");
        }
        // not reported: blocked, disabled, outbound, limited remote, Windows service, K9's own
        for data in [
            "v2.33|Action=Block|Active=TRUE|Dir=In|LPort=1|Name=b|",
            "v2.33|Action=Allow|Active=FALSE|Dir=In|LPort=1|Name=d|",
            "v2.33|Action=Allow|Active=TRUE|Dir=Out|LPort=1|Name=o|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|RA4=LocalSubnet|LPort=1|Name=l|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Svc=Dnscache|Name=s|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|LPort=1|Name=K9 – Botnetz-Server gesperrt (Port 1)|EmbedCtxt=K9|",
        ] {
            assert!(assess(&rule("{X}", data), &unsigned).is_none(), "{data}");
        }
    }

    #[test]
    fn baseline_and_duplicates_collapse_into_one_report() {
        let signed = |_: &Path| true;
        let old: Vec<InRule> = (0..3).map(|i| rule(&format!("{{old{i}}}"), RULE_9009)).collect();
        let known = snapshot(&old);
        // nothing new: nothing to report
        assert!(changes(&known, &old).is_empty());
        // 5 more identical copies plus a harmless rule: one report naming all 8 copies
        let mut now = old.clone();
        now.extend((0..5).map(|i| rule(&format!("{{neu{i}}}"), RULE_9009)));
        now.push(rule("{ok}", "v2.33|Action=Allow|Active=TRUE|Dir=In|RA4=LocalSubnet|LPort=1|Name=lan|"));
        let changed = changes(&known, &now);
        assert_eq!(changed.len(), 6);
        let reps = reports(&changed, &now, &signed);
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].ids.len(), 8);
        let f = finding(&reps[0], Some(&Creator { app: "C:\\Windows\\System32\\netsh.exe".into(), ..Default::default() }), Some("Microsoft Windows"));
        assert_eq!(f.kind, Kind::Firewall);
        assert_eq!(f.sha256, now[0].signature(), "gleiche Regeln = gleicher Fund");
        assert!(f.path.to_string_lossy().contains("8-mal"));
        assert_eq!(f.details.as_ref().unwrap()["ersteller"], "C:\\Windows\\System32\\netsh.exe");
        // a changed rule (same id, now for all ports) counts as new
        let mut changed_rule = old[0].clone();
        changed_rule.ports.clear();
        assert_eq!(changes(&known, &[changed_rule]).len(), 1);
    }

    #[test]
    fn removal_takes_exactly_the_reported_rules() {
        let r1 = rule("{1}", RULE_9009);
        let r2 = rule("{2}", RULE_9009);
        let udp = rule("{3}", "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=9009|Name=allow 9009|");
        let own = rule("{4}", "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9009|Name=K9 – Botnetz-Server gesperrt (Port 9009)|EmbedCtxt=K9|");
        let current = vec![r1.clone(), r2.clone(), udp, own];
        let sig = r1.signature();
        // same name but other protocol, and K9's own rule: never
        assert_eq!(removal_ids(&current, &["{1}".into(), "{2}".into(), "{3}".into(), "{4}".into()], &sig), ["{1}", "{2}"]);
        // copies added later with the same content are found by signature
        assert_eq!(removal_ids(&current, &[], &sig), ["{1}", "{2}"]);
        assert!(remove_ids(&["{1}; Remove-Item C:\\".into()]).is_err(), "nur Regel-Kennungen");
    }

    #[test]
    fn creator_comes_from_the_event() {
        let xml = "<Event><System><TimeCreated SystemTime='2026-11-16T05:52:23.86Z'/></System><EventData>\
                   <Data Name='RuleId'>{A}</Data><Data Name='RuleName'>allow 9009</Data>\
                   <Data Name='ModifyingUser'>S-1-5-21-1</Data><Data Name='ModifyingApplication'>C:\\Tools\\server.exe</Data></EventData></Event>";
        let c = parse_creator(xml).unwrap();
        assert_eq!((c.app.as_str(), c.user.as_str(), c.time.as_str()), ("C:\\Tools\\server.exe", "S-1-5-21-1", "2026-11-16T05:52:23.86Z"));
        assert!(parse_creator("<Event/>").is_none());
    }

    #[test]
    fn writable_folders() {
        assert!(user_writable(Path::new(r"C:\Users\f\Downloads\x.exe")));
        assert!(user_writable(Path::new(r"C:\ProgramData\x\x.exe")));
        assert!(!user_writable(Path::new(r"C:\Program Files\x\x.exe")));
        assert!(!user_writable(Path::new(r"C:\Windows\System32\svchost.exe")));
        assert_eq!(expand_env("%K9_GIBT_ES_NICHT%\\a"), "%K9_GIBT_ES_NICHT%\\a");
    }
}

#[cfg(test)]
mod live {
    /// Read only, by hand: K9_REGEL_ID=<rule id> cargo test -p k9-core --lib eingang::live -- --ignored
    #[test]
    #[ignore]
    fn creator_from_the_real_log() {
        if let Ok(id) = std::env::var("K9_REGEL_ID") {
            println!("{:?}", super::creator(&id));
        }
    }
}
