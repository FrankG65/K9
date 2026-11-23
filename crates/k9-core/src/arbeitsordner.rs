//! Work folders and work programs: other Claude projects, builds and test runs write many
//! compressed files, start PowerShell with encoded commands or a browser for automation –
//! behaviour that looks like an attack. A behaviour finding whose evidence lies only in a
//! work folder, or whose program was started by a (validly signed) work program, is stored
//! "quietly": it appears in the dashboard (marked) but opens no Meldefenster and sends
//! nothing. Signature findings (hash lists, YARA, ClamAV), canary files, attack chains,
//! self-protection and every other critical finding are never quiet.

use std::path::{Path, PathBuf};
use crate::config::ArbeitsordnerConfig;
use crate::model::{Detection, Finding, Severity};

/// Key in the details of a quiet finding: why it is quiet.
pub const LEISE: &str = "leise";

/// Behaviour rules that may be quiet (below Kritisch only).
const QUIET_RULES: &[&str] = &[
    "PROZESSARGUMENTE",
    "PROZESSKETTE",
    "BROWSER:FERNSTEUERUNG",
    "SKRIPT:",
    "DOWNLOAD:UNSIGNIERT",
    "DOWNLOAD:SKRIPT",
    "INFOSTEALER:",
    "SIGMA:",
    "SCHUTZ:ABSCHALTEN",
];

/// Why a stored detection is quiet (None: normal).
pub fn reason_of(details: Option<&serde_json::Value>) -> Option<String> {
    details?.get(LEISE)?.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Start of the reason "started by your work program".
const WORK_PREFIX: &str = "gestartet von deinem Arbeitsprogramm ";
/// The same in English. Stored findings keep their language, so both are read.
const WORK_PREFIX_EN: &str = "started by your work program ";
const UPDATE_PREFIX: &str = "beim Update von ";
const UPDATE_PREFIX_EN: &str = "during the update of ";

/// The program whose update (started in K9) explains a quiet finding:
/// "beim Update von AusweisApp (von dir in K9 gestartet)" -> "AusweisApp".
pub fn update_program(reason: &str) -> Option<String> {
    let rest = reason.strip_prefix(UPDATE_PREFIX).or_else(|| reason.strip_prefix(UPDATE_PREFIX_EN))?;
    let name = rest.split(" (von dir").next().unwrap_or(rest).split(" (started by you").next().unwrap_or(rest).trim();
    Some(name.to_string())
}

/// The work program a quiet finding was started by: (file name, full path). None when the
/// finding is not quiet or quiet for another reason.
pub fn work_program(details: Option<&serde_json::Value>) -> Option<(String, String)> {
    let why = reason_of(details)?;
    let (name, path) = why.strip_prefix(WORK_PREFIX).or_else(|| why.strip_prefix(WORK_PREFIX_EN))?.split_once(" (")?;
    let path = path.strip_suffix(')')?;
    (!name.is_empty() && !path.is_empty()).then(|| (name.to_string(), path.to_string()))
}

pub fn is_quiet(d: &Detection) -> bool {
    reason_of(d.details.as_ref()).is_some()
}

/// Ransomware alarm because of many encrypted files (not a canary file).
fn many_files_alarm(f: &Finding) -> bool {
    f.rule_id == "RANSOMWARE:VERHALTEN" && f.details.as_ref().and_then(|d| d.get("art")).and_then(|a| a.as_str()) == Some("viele")
}

/// May this finding be quiet at all?
pub fn eligible(f: &Finding) -> bool {
    many_files_alarm(f) || (f.severity < Severity::Kritisch && QUIET_RULES.iter().any(|r| f.rule_id.starts_with(r)))
}

/// The work folders and programs of a configuration, ready for comparisons.
#[derive(Debug, Clone, Default)]
pub struct Arbeit {
    /// Lowercase, with a trailing backslash; shown name next to it.
    ordner: Vec<(String, String)>,
    programme: Vec<String>,
}

fn norm(p: &str) -> String {
    p.trim().replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

impl Arbeit {
    pub fn from_config(c: &ArbeitsordnerConfig) -> Self {
        if !c.aktiv {
            return Self::default();
        }
        let ordner = c
            .ordner
            .iter()
            .map(|o| crate::paths::expand_env(o))
            .filter(|o| norm(o).len() >= 3) // never a whole drive like "C:"
            .map(|o| (format!("{}\\", norm(&o)), o.trim().trim_end_matches('\\').to_string()))
            .collect();
        let programme = c.programme.iter().map(|p| norm(&crate::paths::expand_env(p))).filter(|p| !p.is_empty()).collect();
        Self { ordner, programme }
    }

    pub fn is_empty(&self) -> bool {
        self.ordner.is_empty() && self.programme.is_empty()
    }

    /// The work folder that contains `path` (as written in config.toml).
    pub fn folder_of(&self, path: &str) -> Option<&str> {
        let p = format!("{}\\", norm(path));
        self.ordner.iter().find(|(o, _)| p.starts_with(o.as_str())).map(|(_, shown)| shown.as_str())
    }

    pub fn is_program(&self, path: &Path) -> bool {
        let p = norm(&path.display().to_string());
        self.programme.contains(&p)
    }

    /// Why `f` is quiet. `chain`: the process and its parents (program files, nearest first);
    /// `signed`: valid digital signature of a program.
    pub fn reason(&self, f: &Finding, chain: &[PathBuf], signed: &dyn Fn(&Path) -> bool) -> Option<String> {
        if self.is_empty() || !eligible(f) {
            return None;
        }
        let d = f.details.as_ref()?;
        if many_files_alarm(f) {
            let files: Vec<&str> = d.get("dateien")?.as_array()?.iter().filter_map(|x| x.as_str()).collect();
            let first = self.folder_of(files.first()?)?;
            return files
                .iter()
                .all(|x| self.folder_of(x) == Some(first))
                .then(|| tf!("alle betroffenen Dateien liegen im Arbeitsordner {first}", "all affected files are in the work folder {first}"));
        }
        for key in ["ziel", "skriptdatei"] {
            if let Some(o) = d.get(key).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).and_then(|x| self.folder_of(x)) {
                return Some(tf!("Programm bzw. Skript liegt im Arbeitsordner {o}", "the program or script is in the work folder {o}"));
            }
        }
        chain.iter().find(|p| self.is_program(p) && signed(p)).map(|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            format!("{}{name} ({})", t!(WORK_PREFIX, WORK_PREFIX_EN), p.display())
        })
    }
}

/// The running process `pid` and its parents (nearest first, at most 10). A parent counts
/// only if it started before its child – Windows reuses process IDs quickly. If `pid` has
/// already ended, the walk starts at `parent_hint` (from the start event) with `start` as the
/// child's start time.
pub fn ancestors(pid: u32, parent_hint: Option<u32>, start: Option<i64>) -> Vec<PathBuf> {
    let snap = crate::realtime::process_snapshot();
    let mut out = Vec::new();
    let (mut next, mut child_start) = match crate::realtime::process_path_and_start(pid) {
        Some((path, s)) if start.is_none_or(|st| st == s) => {
            out.push(path);
            (snap.get(&pid).map(|p| p.ppid), s)
        }
        _ => (parent_hint, start.unwrap_or(i64::MAX)),
    };
    let mut seen = vec![pid];
    while let Some(p) = next.filter(|p| *p > 4 && !seen.contains(p)) {
        if out.len() >= 10 {
            break;
        }
        seen.push(p);
        let Some((path, s)) = crate::realtime::process_path_and_start(p) else { break };
        if s > child_start {
            break; // another process got the ID
        }
        out.push(path);
        child_start = s;
        next = snap.get(&p).map(|x| x.ppid);
    }
    out
}

fn chain_of(f: &Finding) -> Vec<PathBuf> {
    let Some(d) = f.details.as_ref() else { return Vec::new() };
    let num = |k: &str| d.get(k).and_then(|x| x.as_u64()).and_then(|x| u32::try_from(x).ok());
    let Some(pid) = num("pid") else { return Vec::new() };
    ancestors(pid, num("eltern_pid"), d.get("startzeit").and_then(|x| x.as_i64()))
}

/// A YARA rule fires on a file that is very likely clean: why the message is only quiet.
/// Measured on 22.11.2026 on 269,000 clean files of this PC: 14 hits of the package "core",
/// 25 of "extended" – 12 of them in the pattern files of Trend Micro (a virus scanner carries
/// the patterns of malware), the rest in signed files of NVIDIA, Adobe, Microsoft and others.
///
/// `path` lower case; `signer`: valid signature of a manufacturer; `age_days`: since the file
/// was created or last changed (the later one); `from_internet`: marked by Windows.
/// A file that arrived recently or from the internet is never quiet, signed or not.
pub fn yara_quiet_reason(path: &str, signer: Option<&str>, age_days: Option<u64>, from_internet: bool) -> Option<String> {
    const MIN_DAYS: u64 = 7;
    if from_internet {
        return None;
    }
    let p = path.to_lowercase();
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    // Folders only an administrator can write to (after the drive letter).
    let rest = p.get(1..).unwrap_or("");
    let program_files = rest.starts_with(":\\program files\\") || rest.starts_with(":\\program files (x86)\\");
    let in_windows = p.starts_with(&format!("{windir}\\"));
    let settled = age_days.is_some_and(|d| d >= MIN_DAYS);
    // The pattern files of a virus scanner are renewed every day: no waiting time here.
    let security_product = (program_files && ["\\trend micro\\", "\\windows defender\\", "\\clamav\\"].iter().any(|d| p.contains(d)))
        || rest.starts_with(":\\programdata\\microsoft\\windows defender\\");
    if security_product {
        return Some(t!("Datei eines Schutzprogramms – dessen Signaturdateien enthalten die Muster von Schadsoftware", "file of a security program – its signature files contain the patterns of malware").into());
    }
    match signer {
        // An installed, signed program: updates replace its files all the time.
        Some(s) if program_files || in_windows => Some(format!("gültig signiert von {s}, in einem Ordner, in den nur ein Administrator schreiben kann")),
        Some(s) if settled => Some(format!("gültig signiert von {s} und seit über {MIN_DAYS} Tagen unverändert auf dem PC")),
        None if in_windows && settled => Some(format!("Teil von Windows oder eines installierten Treibers, seit über {MIN_DAYS} Tagen unverändert")),
        _ => None,
    }
}

/// `yara_quiet_reason` with the facts read from the file. Only for file findings of YARA rules.
pub fn yara_quiet_reason_for(f: &Finding) -> Option<String> {
    if !f.rule_id.starts_with("YARA:") || f.kind != crate::model::Kind::Datei {
        return None;
    }
    let meta = std::fs::metadata(&f.path).ok()?;
    let newest = [meta.created().ok(), meta.modified().ok()].into_iter().flatten().max()?;
    let age_days = newest.elapsed().ok().map(|d| d.as_secs() / 86_400);
    let from_internet = crate::herkunft::zone_of(&f.path).is_some_and(|z| z.from_internet());
    let signer = crate::autostart::is_signed(&f.path).then(|| crate::treiber::signer_name(&f.path).unwrap_or_else(|| "einem Hersteller".into()));
    yara_quiet_reason(&f.path.display().to_string(), signer.as_deref(), age_days, from_internet)
}

// ------------------------------------------------ work files of security programs

/// Key in the details of a file finding: which programs held the file open when it was found.
pub const OFFEN_BEI: &str = "geoeffnet_von";
/// A virus scanner that only checks a file lets go of it within milliseconds; a program that
/// works with the file still holds it after this time.
const HOLD_SECS: u64 = 2;

/// A program that holds a reported file open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    /// Full path of the program ("" when Windows does not tell).
    pub exe: String,
    /// Manufacturer of a valid signature.
    pub signer: Option<String>,
}

impl Holder {
    fn name(&self) -> &str {
        self.exe.rsplit('\\').next().filter(|n| !n.is_empty()).unwrap_or(t!("unbekanntes Programm", "unknown program"))
    }
    fn label(&self) -> String {
        match (&self.signer, self.exe.is_empty()) {
            (_, true) => format!("Prozess {} (Programm nicht lesbar)", self.pid),
            (Some(s), _) => format!("{} ({}, gültig signiert von {s})", self.name(), self.exe),
            (None, _) => format!("{} ({}, nicht signiert)", self.name(), self.exe),
        }
    }
}

/// The program of an installed security product (folder only an administrator can write to).
fn security_program(exe: &str) -> bool {
    let p = exe.to_lowercase();
    let rest = p.get(1..).unwrap_or("");
    let program_files = rest.starts_with(":\\program files\\") || rest.starts_with(":\\program files (x86)\\");
    (program_files && ["\\trend micro\\", "\\windows defender\\", "\\clamav\\"].iter().any(|d| p.contains(d)))
        || rest.starts_with(":\\programdata\\microsoft\\windows defender\\platform\\")
}

/// A ClamAV or YARA pattern fires on the work file of a security program: why the message is
/// only quiet. Seen 20. and 22.11.2026: Trend Micro keeps a packed work file open in the Temp
/// folder for as long as its window program runs and rewrites it; ClamAV reported it again
/// after every change (findings 285 and 387).
///
/// Quiet only if all of this holds: a pattern finding of at most medium severity (never the
/// hash lists), not from the internet, no program or script, and every program that holds the
/// file open is the validly signed program of an installed security product – at the time of
/// the finding (`first`) and still two seconds later (`second`).
pub fn holder_quiet_reason(rule_id: &str, severity: Severity, from_internet: bool, program_like: bool, first: &[Holder], second: &[Holder]) -> Option<String> {
    let pattern = rule_id.starts_with("CLAMAV:") || rule_id.starts_with("YARA:");
    if !pattern || severity > Severity::Mittel || from_internet || program_like {
        return None;
    }
    let trusted = |h: &Holder| h.signer.is_some() && security_program(&h.exe);
    if first.is_empty() || !first.iter().all(trusted) || !second.iter().all(trusted) {
        return None;
    }
    let h = first.iter().find(|h| second.iter().any(|s| s.pid == h.pid && s.exe == h.exe))?;
    Some(tf!(
        "Arbeitsdatei eines Schutzprogramms – dauerhaft geöffnet von {} ({}, gültig signiert von {})", "work file of a security program – kept open by {} ({}, validly signed by {})",
        h.name(),
        h.exe,
        h.signer.as_deref().unwrap_or("")
    ))
}

/// A program or script by its name or its first bytes (those are never quiet as "work file").
fn program_like(path: &Path) -> bool {
    const EXT: &[&str] = &["exe", "dll", "scr", "com", "sys", "cpl", "msi", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "jar"];
    if path.extension().and_then(|e| e.to_str()).is_some_and(|e| EXT.contains(&e.to_lowercase().as_str())) {
        return true;
    }
    let mut head = [0u8; 2];
    std::fs::File::open(path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"MZ"
}

/// The programs that hold this file open right now.
pub fn holders_of(path: &Path) -> Vec<Holder> {
    crate::realtime::file_holders(path)
        .into_iter()
        .filter(|pid| *pid != std::process::id())
        .map(|pid| {
            let exe = crate::realtime::process_path(pid);
            let signer = exe.as_ref().filter(|p| crate::autostart::is_signed(p)).map(|p| crate::treiber::signer_name(p).unwrap_or_else(|| "einem Hersteller".into()));
            Holder { pid, exe: exe.map(|p| p.display().to_string()).unwrap_or_default(), signer }
        })
        .collect()
}

/// File finding: notes which programs hold the file open, and makes it quiet when it is the
/// work file of a security program (`holder_quiet_reason`). None: nobody holds the file.
fn holder_note(f: &Finding) -> Option<Finding> {
    if f.kind != crate::model::Kind::Datei {
        return None;
    }
    let first = holders_of(&f.path);
    if first.is_empty() {
        return None;
    }
    let mut f = f.clone();
    let mut d = f.details.take().filter(|d| d.is_object()).unwrap_or_else(|| serde_json::json!({}));
    d[OFFEN_BEI] = first.iter().map(Holder::label).collect::<Vec<_>>().join("; ").into();
    let from_internet = crate::herkunft::zone_of(&f.path).is_some_and(|z| z.from_internet());
    // Ask a second time only when everything else already fits.
    if holder_quiet_reason(&f.rule_id, f.severity, from_internet, program_like(&f.path), &first, &first).is_some() {
        std::thread::sleep(std::time::Duration::from_secs(HOLD_SECS));
        if let Some(why) = holder_quiet_reason(&f.rule_id, f.severity, from_internet, false, &first, &holders_of(&f.path)) {
            tracing::info!("Leise Meldung ({why}): {} – {}", f.threat_name, f.path.display());
            d[LEISE] = why.into();
        }
    }
    f.details = Some(d);
    Some(f)
}

/// Marks quiet findings (details "leise" + the start chain). Quiet ransomware alarms of the
/// same work folder share one fingerprint, so a busy build gives one entry, not hundreds.
pub fn mark(arbeit: &Arbeit, findings: &[Finding]) -> Vec<Finding> {
    findings
        .iter()
        .map(|f| {
            if let Some(why) = update_reason(f, current_update().as_deref(), &std::env::temp_dir().display().to_string()) {
                let mut f = f.clone();
                let mut d = f.details.take().filter(|d| d.is_object()).unwrap_or_else(|| serde_json::json!({}));
                d[LEISE] = why.clone().into();
                f.details = Some(d);
                tracing::info!("Leise Meldung ({why}): {} – {}", f.threat_name, f.path.display());
                return f;
            }
            if let Some(why) = yara_quiet_reason_for(f) {
                let mut f = f.clone();
                let mut d = f.details.take().filter(|d| d.is_object()).unwrap_or_else(|| serde_json::json!({}));
                d[LEISE] = why.clone().into();
                f.details = Some(d);
                tracing::info!("Leise Meldung ({why}): {} – {}", f.threat_name, f.path.display());
                return f;
            }
            let noted;
            let f = match holder_note(f) {
                Some(n) => {
                    noted = n;
                    &noted
                }
                None => f,
            };
            if reason_of(f.details.as_ref()).is_some() {
                return f.clone();
            }
            if arbeit.is_empty() || !eligible(f) {
                return f.clone();
            }
            let chain = if many_files_alarm(f) { Vec::new() } else { chain_of(f) };
            let Some(why) = arbeit.reason(f, &chain, &crate::autostart::is_signed) else { return f.clone() };
            let mut f = f.clone();
            if let Some(d) = f.details.as_mut().and_then(|d| d.as_object_mut()) {
                d.insert(LEISE.into(), why.clone().into());
                if !chain.is_empty() {
                    d.insert("vorfahren".into(), chain.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().into());
                }
            }
            if many_files_alarm(&f) {
                // The fingerprint always uses the German reason: a decision fits in every language.
                let key = crate::sprache::with(crate::sprache::Sprache::De, || arbeit.reason(&f, &chain, &crate::autostart::is_signed)).unwrap_or_else(|| why.clone());
                f.sha256 = crate::sha256_hex(format!("ransomware|leise|{}", key.to_lowercase()).as_bytes());
            }
            tracing::info!("Leise Meldung ({why}): {} – {}", f.threat_name, f.path.display());
            f
        })
        .collect()
}

// ------------------------------------------------ updates started by K9 itself

/// Program K9 is updating/installing right now on the user's click (and when it ended).
static UPDATE: std::sync::Mutex<Option<(String, Option<std::time::Instant>)>> = std::sync::Mutex::new(None);
/// Side effects of an installer still show up shortly after it ended.
const UPDATE_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// The dashboard starts an update/installation of this program.
pub fn begin_update(name: &str) {
    *UPDATE.lock().unwrap_or_else(|e| e.into_inner()) = Some((name.to_string(), None));
}

/// The update/installation ended (its side effects stay quiet for two more minutes).
pub fn end_update() {
    if let Some((_, ended)) = UPDATE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        ended.get_or_insert_with(std::time::Instant::now);
    }
}

fn current_update() -> Option<String> {
    let g = UPDATE.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().filter(|(_, ended)| ended.is_none_or(|t| t.elapsed() < UPDATE_GRACE)).map(|(n, _)| n.clone())
}

/// Why a finding is quiet because K9 itself is installing `program` right now. Only what
/// clearly comes from an installer: heuristic file findings (YARA "indicator"/"suspicious"
/// rules, ClamAV "PUA") on helper files in the temp folder, and new autostart entries of
/// severity Info (run-once entries, update checkers) – and the installer of a browser that
/// reads this browser's own data while K9 updates exactly this browser (Opera's installer
/// runs from the temp folder and reads the Opera profile; reported on 19.11.2026): a validly
/// signed program from the temp folder, one store, severity Mittel. Hash lists, every
/// critical finding, firewall rules, logins, network and devices stay loud.
pub fn update_reason(f: &Finding, program: Option<&str>, temp: &str) -> Option<String> {
    let program = program?;
    if f.severity >= Severity::Kritisch {
        return None;
    }
    let installer_file = || {
        let rule = f.rule_id.to_uppercase();
        let heuristic = (rule.starts_with("YARA:") && (rule.contains("INDICATOR") || rule.contains("SUSP"))) || rule.starts_with("CLAMAV:PUA.");
        let p = format!("{}\\", norm(&f.path.display().to_string()));
        let t = format!("{}\\", norm(temp));
        heuristic && f.kind == crate::model::Kind::Datei && t.len() > 4 && p.starts_with(&t)
    };
    let autostart = f.rule_id == "AUTOSTART:NEU" && f.severity == Severity::Info;
    let own_installer = || {
        let d = f.details.as_ref();
        let text = |k: &str| d.and_then(|d| d[k].as_str()).unwrap_or("").to_string();
        let group = text("gruppe").to_lowercase();
        let exe = format!("{}\\", norm(&text("ziel")));
        let t = format!("{}\\", norm(temp));
        f.rule_id.starts_with("INFOSTEALER:")
            && f.severity == Severity::Mittel
            && !text("signierer").is_empty()
            && group.len() >= 4
            && program.to_lowercase().contains(&group)
            && t.len() > 4
            && exe.starts_with(&t)
    };
    (autostart || installer_file() || own_installer()).then(|| tf!("beim Update von {program} (von dir in K9 gestartet)", "during the update of {program} (started by you in K9)"))
}

/// Work folders of config.toml, read again at most every 30 seconds (a confirmed new folder
/// applies without restarting the agent). Unconfirmed weakening changes are not used.
pub fn live(config_file: &Path, fallback: &crate::config::Config) -> Arbeit {
    Arbeit::from_config(&crate::config::Config::live(config_file, fallback).arbeitsordner)
}

/// config.toml text with the work folder list set to `list` (each entry a TOML literal
/// string, so backslashes stay as typed).
pub fn set_folders(text: &str, list: &[String]) -> anyhow::Result<String> {
    if let Some(bad) = list.iter().find(|p| p.contains('\'') || p.contains('\n') || p.trim().is_empty()) {
        anyhow::bail!("Ungueltiger Ordner: {bad}");
    }
    let literal = format!("[{}]", list.iter().map(|d| format!("'{d}'")).collect::<Vec<_>>().join(", "));
    crate::funktion::set_value(text, "arbeitsordner", "ordner", &literal, |c| c.arbeitsordner.ordner == list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_read_in_both_languages() {
        assert_eq!(update_program("beim Update von Opera Stable 140.0 (von dir in K9 gestartet)").as_deref(), Some("Opera Stable 140.0"));
        assert_eq!(update_program("during the update of Opera Stable 140.0 (started by you in K9)").as_deref(), Some("Opera Stable 140.0"));
        assert_eq!(update_program("etwas anderes"), None);
        let de = serde_json::json!({ "leise": r"gestartet von deinem Arbeitsprogramm claude.exe (C:\x\claude.exe)" });
        let en = serde_json::json!({ "leise": r"started by your work program claude.exe (C:\x\claude.exe)" });
        assert_eq!(work_program(Some(&de)), Some(("claude.exe".to_string(), r"C:\x\claude.exe".to_string())));
        assert_eq!(work_program(Some(&de)), work_program(Some(&en)));
    }

    #[test]
    fn yara_hits_on_settled_trusted_files_are_quiet_but_never_on_new_ones() {
        // Pattern files of a virus scanner are renewed daily: quiet at any age.
        let tm = r"C:\Program Files\Trend Micro\AMSP\module\10000\icrc$oth.457";
        assert!(yara_quiet_reason(tm, None, Some(0), false).unwrap().starts_with("Datei eines Schutzprogramms"));
        // An installed signed program, just updated.
        let nv = r"C:\Program Files\NVIDIA Corporation\Installer2\PhysXExt.dll";
        assert!(yara_quiet_reason(nv, Some("NVIDIA Corporation"), Some(0), false).unwrap().starts_with("gültig signiert von NVIDIA Corporation, in einem Ordner"));
        // A signed file in a user folder: only after a week.
        let dl = r"C:\Users\x\Downloads\tool.exe";
        assert_eq!(yara_quiet_reason(dl, Some("Hersteller"), Some(2), false), None);
        assert_eq!(yara_quiet_reason(dl, Some("Hersteller"), None, false), None);
        assert!(yara_quiet_reason(dl, Some("Hersteller"), Some(30), false).unwrap().contains("seit über 7 Tagen"));
        // From the internet: always loud, whatever the signature or the folder says.
        assert_eq!(yara_quiet_reason(nv, Some("NVIDIA Corporation"), Some(400), true), None);
        assert_eq!(yara_quiet_reason(tm, None, Some(400), true), None);
        // Unsigned in a program folder or in a user folder: loud.
        assert_eq!(yara_quiet_reason(r"C:\Program Files\PDF24\lib\jspdf.js", None, Some(400), false), None);
        assert_eq!(yara_quiet_reason(r"C:\Users\x\Downloads\Program Files\Trend Micro\a.exe", None, Some(400), false), None);
        assert_eq!(yara_quiet_reason(r"C:\ProgramData\Trend Micro\a.exe", None, Some(400), false), None, "ProgramData ist für Benutzer beschreibbar");
        // An unsigned script of a driver package inside the Windows folder.
        assert!(yara_quiet_reason(r"C:\Windows\System32\DriverStore\FileRepository\nv\a.ps1", None, Some(90), false).unwrap().starts_with("Teil von Windows"));
        assert_eq!(yara_quiet_reason(r"C:\Windows\Temp\a.ps1", None, Some(1), false), None);
    }

    /// Who holds the file K9_HOLDER_FILE open on this PC, and would a ClamAV finding of medium
    /// severity on it be quiet? Reads only. `cargo test -p k9-core holders_live -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn holders_live() {
        let path = PathBuf::from(std::env::var("K9_HOLDER_FILE").expect("K9_HOLDER_FILE"));
        let f = Finding {
            path,
            rule_id: "CLAMAV:PUA.Win.Exploit.CVE_2012_1461-1".into(),
            kind: crate::model::Kind::Datei,
            severity: Severity::Mittel,
            sha256: String::new(),
            size: 0,
            threat_name: "Test".into(),
            category: "Test".into(),
            engine: "clamav".into(),
            details: None,
        };
        let start = std::time::Instant::now();
        let noted = holder_note(&f);
        let d = noted.as_ref().and_then(|n| n.details.clone()).unwrap_or_default();
        println!("HALTER {}", d[OFFEN_BEI].as_str().unwrap_or("niemand"));
        println!("LEISE {}", d[LEISE].as_str().unwrap_or("nein (laut)"));
        println!("DAUER {} ms", start.elapsed().as_millis());
    }

    #[test]
    fn work_file_of_a_security_program_is_quiet() {
        let tm = Holder { pid: 7, exe: r"C:\Program Files\Trend Micro\Titanium\UIFramework\uiWinMgr.exe".into(), signer: Some("Trend Micro, Inc.".into()) };
        let other = Holder { pid: 9, exe: r"C:\Program Files\Editor\editor.exe".into(), signer: Some("Hersteller".into()) };
        let pua = "CLAMAV:PUA.Win.Exploit.CVE_2012_1461-1";
        let m = Severity::Mittel;
        let ok = |first: &[Holder], second: &[Holder]| holder_quiet_reason(pua, m, false, false, first, second);
        // Findings 285 and 387: held by Trend Micro's window program the whole time.
        let why = ok(std::slice::from_ref(&tm), std::slice::from_ref(&tm)).unwrap();
        assert!(why.starts_with("Arbeitsdatei eines Schutzprogramms – dauerhaft geöffnet von uiWinMgr.exe"), "{why}");
        assert!(why.contains("Trend Micro, Inc."));
        assert!(holder_quiet_reason("YARA:regel", Severity::Niedrig, false, false, std::slice::from_ref(&tm), std::slice::from_ref(&tm)).is_some());
        // A scanner that only looked at the file has let go two seconds later: loud.
        assert_eq!(ok(std::slice::from_ref(&tm), &[]), None);
        // Another process with the same number is not the same holder.
        let reused = Holder { exe: r"C:\Program Files\Trend Micro\AMSP\coreServiceShell.exe".into(), ..tm.clone() };
        assert_eq!(ok(std::slice::from_ref(&tm), std::slice::from_ref(&reused)), None);
        // Nobody holds it, or someone else holds it too (at the start or later): loud.
        assert_eq!(ok(&[], &[]), None);
        assert_eq!(ok(&[tm.clone(), other.clone()], std::slice::from_ref(&tm)), None);
        assert_eq!(ok(std::slice::from_ref(&tm), &[tm.clone(), other.clone()]), None);
        // The name alone is not enough: unsigned, or outside the protected program folders.
        let unsigned = Holder { signer: None, ..tm.clone() };
        assert_eq!(ok(std::slice::from_ref(&unsigned), std::slice::from_ref(&unsigned)), None);
        for exe in [r"C:\Users\x\Trend Micro\uiWinMgr.exe", r"C:\ProgramData\Trend Micro\a.exe", r"C:\Users\x\Downloads\Program Files\Trend Micro\a.exe", ""] {
            let fake = Holder { exe: exe.into(), ..tm.clone() };
            assert_eq!(ok(std::slice::from_ref(&fake), std::slice::from_ref(&fake)), None, "{exe}");
        }
        // Never quiet: hash lists and other engines, high severity, from the internet, programs.
        let both = std::slice::from_ref(&tm);
        assert_eq!(holder_quiet_reason("HASH:malwarebazaar", m, false, false, both, both), None);
        assert_eq!(holder_quiet_reason(pua, Severity::Hoch, false, false, both, both), None);
        assert_eq!(holder_quiet_reason(pua, m, true, false, both, both), None);
        assert_eq!(holder_quiet_reason(pua, m, false, true, both, both), None);
        // Programs and scripts are recognised by name and by their first bytes.
        let dir = tempfile::tempdir().unwrap();
        let mz = dir.path().join("daten.tmp");
        std::fs::write(&mz, b"MZ\x90\x00").unwrap();
        let data = dir.path().join("archiv.tmp");
        std::fs::write(&data, b"\x1f\x8b\x08\x00").unwrap();
        assert!(program_like(&mz));
        assert!(!program_like(&data));
        assert!(program_like(Path::new(r"C:\x\a.PS1")));
        // A file nobody else holds: no note. (The test itself does not count as a holder.)
        let _open = std::fs::File::open(&data).unwrap();
        assert!(holders_of(&data).is_empty());
        let f = Finding {
            path: data.clone(),
            rule_id: pua.into(),
            kind: crate::model::Kind::Datei,
            severity: m,
            sha256: String::new(),
            size: 4,
            threat_name: "Test".into(),
            category: "Test".into(),
            engine: "clamav".into(),
            details: None,
        };
        assert!(holder_note(&f).is_none());
        // The Restart Manager really names a holder: the test process itself.
        assert!(crate::realtime::file_holders(&data).contains(&std::process::id()));
    }
    use crate::model::Kind;

    fn arbeit() -> Arbeit {
        Arbeit::from_config(&ArbeitsordnerConfig {
            aktiv: true,
            ordner: vec!["D:\\Projekte".into(), "C:".into()],
            programme: vec!["C:\\Users\\x\\.local\\bin\\claude.exe".into()],
        })
    }

    fn finding(rule: &str, sev: Severity, details: serde_json::Value) -> Finding {
        Finding {
            path: PathBuf::from("Prozess a.exe"),
            sha256: "abc".into(),
            size: 0,
            rule_id: rule.into(),
            threat_name: "T".into(),
            category: "Verdächtiges Verhalten".into(),
            severity: sev,
            engine: "echtzeit".into(),
            kind: Kind::Prozess,
            details: Some(details),
        }
    }

    #[test]
    fn folders_match_whole_names_and_never_a_drive() {
        let a = arbeit();
        assert_eq!(a.folder_of("D:\\Projekte\\Beispiel-A\\a.txt"), Some("D:\\Projekte"));
        assert_eq!(a.folder_of("d:/projekte/x"), Some("D:\\Projekte"), "Gross-/Kleinschreibung und / egal");
        assert_eq!(a.folder_of("D:\\Projekte-privat\\a.txt"), None, "nur ganze Ordnernamen");
        assert_eq!(a.folder_of("C:\\Windows\\x.exe"), None, "ein ganzes Laufwerk ist nie Arbeitsordner");
        assert!(Arbeit::from_config(&ArbeitsordnerConfig { aktiv: false, ..Default::default() }).is_empty());
    }

    #[test]
    fn ransomware_many_files_quiet_only_when_all_files_are_in_one_work_folder() {
        let a = arbeit();
        let all = finding("RANSOMWARE:VERHALTEN", Severity::Kritisch, serde_json::json!({ "art": "viele", "dateien": ["D:\\Projekte\\a\\1", "D:\\Projekte\\b\\2"] }));
        assert!(a.reason(&all, &[], &|_| true).is_some());
        let mixed = finding("RANSOMWARE:VERHALTEN", Severity::Kritisch, serde_json::json!({ "art": "viele", "dateien": ["D:\\Projekte\\a\\1", "C:\\Users\\x\\Documents\\b.docx"] }));
        assert!(a.reason(&mixed, &[], &|_| true).is_none(), "eine Datei ausserhalb: normal melden");
        let canary = finding("RANSOMWARE:VERHALTEN", Severity::Kritisch, serde_json::json!({ "art": "koeder", "dateien": ["D:\\Projekte\\a\\1"] }));
        assert!(a.reason(&canary, &[], &|_| true).is_none(), "Koederdatei immer normal");
    }

    #[test]
    fn processes_quiet_by_folder_or_signed_work_program_never_when_critical() {
        let a = arbeit();
        let claude = PathBuf::from("C:\\Users\\x\\.local\\bin\\claude.exe");
        let f = finding("PROZESSARGUMENTE:powershell.exe", Severity::Hoch, serde_json::json!({ "pid": 1, "ziel": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }));
        let chain = vec![PathBuf::from("C:\\Windows\\System32\\cmd.exe"), claude.clone()];
        assert!(a.reason(&f, &chain, &|_| true).unwrap().contains("claude.exe"));
        assert!(a.reason(&f, &chain, &|_| false).is_none(), "ohne gueltige Signatur kein Arbeitsprogramm");
        assert!(a.reason(&f, &[], &|_| true).is_none());
        let built = finding("DOWNLOAD:UNSIGNIERT-GESTARTET", Severity::Mittel, serde_json::json!({ "pid": 1, "ziel": "D:\\Projekte\\Beispiel-B\\target\\a.exe" }));
        assert!(a.reason(&built, &[], &|_| true).is_some());
        let critical = finding("BROWSER:FERNSTEUERUNG", Severity::Kritisch, serde_json::json!({ "pid": 1, "ziel": "D:\\Projekte\\x.exe" }));
        assert!(a.reason(&critical, &chain, &|_| true).is_none(), "Kritisch bleibt laut");
        let hash = finding("HASH:malwarebazaar", Severity::Hoch, serde_json::json!({ "ziel": "D:\\Projekte\\x.exe" }));
        assert!(a.reason(&hash, &chain, &|_| true).is_none(), "Signaturfunde nie leise");
    }

    #[test]
    fn mark_sets_reason_and_one_fingerprint_per_work_folder() {
        let a = arbeit();
        let mk = |files: serde_json::Value, sha: &str| {
            let mut f = finding("RANSOMWARE:VERHALTEN", Severity::Kritisch, serde_json::json!({ "art": "viele", "dateien": files }));
            f.sha256 = sha.into();
            f
        };
        let out = mark(&a, &[mk(serde_json::json!(["D:\\Projekte\\a\\1"]), "x1"), mk(serde_json::json!(["D:\\Projekte\\b\\2"]), "x2")]);
        assert_eq!(out[0].sha256, out[1].sha256, "ein Eintrag je Arbeitsordner");
        assert!(reason_of(out[0].details.as_ref()).unwrap().contains("D:\\Projekte"));
        let loud = mark(&a, &[mk(serde_json::json!(["C:\\Users\\x\\Documents\\a.docx"]), "x3")]);
        assert_eq!(loud[0].sha256, "x3");
        assert!(reason_of(loud[0].details.as_ref()).is_none());
    }

    #[test]
    fn installer_side_effects_are_quiet_only_during_an_update_started_in_k9() {
        let temp = "C:\\Users\\x\\AppData\\Local\\Temp";
        let file = |rule: &str, sev: Severity, path: &str| {
            let mut f = finding(rule, sev, serde_json::json!({}));
            f.kind = Kind::Datei;
            f.path = PathBuf::from(path);
            f
        };
        let nsis = file("YARA:default:DITEKSHEN_INDICATOR_TOOL_UAC_NSISUAC", Severity::Hoch, "C:\\Users\\x\\AppData\\Local\\Temp\\nss9E6F.tmp\\UAC.dll");
        assert!(update_reason(&nsis, Some("Reolink"), temp).unwrap().contains("Reolink"));
        assert!(update_reason(&nsis, None, temp).is_none(), "ohne laufendes Update normal");
        let pua = file("CLAMAV:PUA.Win.Packer.Exesplitter-8", Severity::Mittel, "C:\\Users\\x\\AppData\\Local\\Temp\\WinGet\\a\\a.msi");
        assert!(update_reason(&pua, Some("X"), temp).is_some());
        // The installer of the browser K9 is updating reads this browser's data.
        let opera = |sev, ziel: &str, signer: Option<&str>, gruppe: &str| {
            let mut f = finding(&format!("INFOSTEALER:{}", gruppe.to_uppercase()), sev, serde_json::json!({ "ziel": ziel, "gruppe": gruppe, "signierer": signer }));
            f.kind = Kind::Prozess;
            f
        };
        let inst = "C:\\Users\\x\\AppData\\Local\\Temp\\7zS80C7CE4E\\installer.exe";
        assert!(update_reason(&opera(Severity::Mittel, inst, Some("Opera Norway AS"), "opera"), Some("Opera Stable"), temp).is_some());
        assert!(update_reason(&opera(Severity::Mittel, inst, Some("Opera Norway AS"), "opera"), Some("PDF24 Creator"), temp).is_none(), "anderes Programm wird aktualisiert");
        assert!(update_reason(&opera(Severity::Mittel, inst, Some("Opera Norway AS"), "chrome"), Some("Opera Stable"), temp).is_none(), "fremder Speicher");
        assert!(update_reason(&opera(Severity::Mittel, inst, None, "opera"), Some("Opera Stable"), temp).is_none(), "unsigniert");
        assert!(update_reason(&opera(Severity::Hoch, inst, Some("Opera Norway AS"), "opera"), Some("Opera Stable"), temp).is_none(), "nur Schwere Mittel");
        assert!(update_reason(&opera(Severity::Mittel, "C:\\Users\\x\\Downloads\\installer.exe", Some("Opera Norway AS"), "opera"), Some("Opera Stable"), temp).is_none(), "nur aus dem Temp-Ordner");
        assert!(update_reason(&opera(Severity::Mittel, inst, Some("Opera Norway AS"), "opera"), None, temp).is_none(), "ohne laufendes Update normal");
        let hash = file("HASH:malwarebazaar", Severity::Hoch, "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe");
        assert!(update_reason(&hash, Some("X"), temp).is_none(), "bekannte Schadsoftware immer laut");
        let malware = file("YARA:default:MALWARE_Win_AgentTesla", Severity::Hoch, "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe");
        assert!(update_reason(&malware, Some("X"), temp).is_none());
        let elsewhere = file("YARA:default:DITEKSHEN_INDICATOR_TOOL_UAC_NSISUAC", Severity::Hoch, "C:\\Users\\x\\Downloads\\UAC.dll");
        assert!(update_reason(&elsewhere, Some("X"), temp).is_none(), "nur Hilfsdateien im Temp-Ordner");
        let mut auto = finding("AUTOSTART:NEU", Severity::Info, serde_json::json!({}));
        auto.kind = Kind::Autostart;
        assert!(update_reason(&auto, Some("PDF24"), temp).is_some());
        auto.severity = Severity::Mittel;
        assert!(update_reason(&auto, Some("PDF24"), temp).is_none(), "auffaellige Autostarts bleiben laut");
        let fw = finding("FIREWALL:EINGANG", Severity::Mittel, serde_json::json!({}));
        assert!(update_reason(&fw, Some("Fiddler"), temp).is_none());
        // begin/end: quiet during the update and shortly after.
        begin_update("Testprogramm");
        assert_eq!(current_update().as_deref(), Some("Testprogramm"));
        end_update();
        assert_eq!(current_update().as_deref(), Some("Testprogramm"), "Nachlauf");
        *UPDATE.lock().unwrap() = None;
    }

    #[test]
    fn set_folders_writes_literal_strings() {
        let text = crate::config::DEFAULT_CONFIG;
        let new = set_folders(text, &["%TEMP%\\claude".into(), "D:\\Projekte".into()]).unwrap();
        let c = crate::config::Config::parse(&new).unwrap();
        assert_eq!(c.arbeitsordner.ordner, vec!["%TEMP%\\claude".to_string(), "D:\\Projekte".to_string()]);
        assert!(set_folders(text, &["a'b".into()]).is_err());
    }
}
