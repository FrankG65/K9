//! Attack chains: single steps are often harmless, together they are not. A chain starts
//! with an unsigned program from the internet (Mark of the Web) and follows its child
//! processes for 30 minutes. Steps of the chain members:
//! starting a script host, setting up an autostart, opening stored logins, querying a
//! malicious address, running a suspicious PowerShell script.
//!
//! Pure bookkeeping (no system calls) – the Windows service feeds the events.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use crate::model::{Finding, Kind, Severity};

/// How long a chain stays open after its start (FILETIME units: 30 minutes).
pub const WINDOW: i64 = 30 * 60 * 10_000_000;
/// Start times of the same process from different sources differ by less than this (1 s).
const SAME_START: i64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Download,
    /// Root of a chain without the mark "from the internet": an unsigned program whose file
    /// is at most a day old and lies in a user's folder (unpacked from an archive, copied).
    NeuesProgramm,
    /// Root of a chain: an unsigned program started from a removable drive (USB stick).
    Wechseldatentraeger,
    ScriptHost,
    Autostart,
    Credentials,
    BadAddress,
    Script,
    ScriptCritical,
    /// A member of the chain tries to delete the recovery data (shadow copies, boot recovery).
    Wiederherstellung,
    /// The K9 agent was ended from outside while the chain was running.
    AgentBeendet,
    /// Something asked Windows to stop the K9 service (refused) while the chain was running.
    DienstStopp,
    /// The K9 service was ended by force while the chain was running (seen after its restart).
    DienstBeendet,
}

/// The steps a chain can start with.
const ROOTS: [Step; 3] = [Step::Download, Step::NeuesProgramm, Step::Wechseldatentraeger];

/// How old the file of a program in a user's folder may be to count as new.
pub const NEW_SECS: u64 = 24 * 3600;

/// Is an unsigned program without the mark "from the internet" the root of a chain? The mark
/// is missing for everything unpacked from an archive by most packers, copied from a USB stick
/// or written by another program – the usual ways malware arrives. `age_secs`: time since the
/// file was created; `removable`: it lies on a removable drive.
pub fn local_root(path: &str, age_secs: Option<u64>, removable: bool) -> Option<Step> {
    if removable {
        return Some(Step::Wechseldatentraeger);
    }
    let p = path.to_lowercase();
    let in_profile = p.get(1..).is_some_and(|rest| rest.starts_with(":\\users\\"));
    (in_profile && age_secs.is_some_and(|a| a <= NEW_SECS)).then_some(Step::NeuesProgramm)
}

/// Is the program file `exe` the root of a possible attack chain, and why? Unsigned and marked
/// "from the internet", or without that mark new in a user's folder or on a removable drive.
/// `in_work_folder`: it lies in one of the user's work folders (own builds) – then only the
/// internet mark counts.
pub fn root_of(exe: &std::path::Path, in_work_folder: bool) -> Option<Step> {
    let root = if crate::herkunft::zone_of(exe).is_some_and(|z| z.from_internet()) {
        Step::Download
    } else {
        if in_work_folder {
            return None;
        }
        let age = std::fs::metadata(exe).ok().and_then(|m| m.created().ok()).and_then(|c| c.elapsed().ok()).map(|d| d.as_secs());
        local_root(&exe.display().to_string(), age, crate::realtime::is_removable(exe))?
    };
    (!crate::autostart::is_signed(exe)).then_some(root)
}

/// The steps that are an attack on K9 itself.
const ATTACKS: [Step; 3] = [Step::AgentBeendet, Step::DienstStopp, Step::DienstBeendet];

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::Download => t!("unsigniertes Programm aus dem Internet gestartet", "unsigned program from the internet started"),
            Step::NeuesProgramm => t!("neues unsigniertes Programm aus einem Benutzerordner gestartet", "new unsigned program from a user folder started"),
            Step::Wechseldatentraeger => t!("unsigniertes Programm von einem Wechseldatenträger gestartet", "unsigned program from a removable drive started"),
            Step::ScriptHost => t!("Skript-Programm gestartet (PowerShell, cmd, mshta …)", "script host started (PowerShell, cmd, mshta …)"),
            Step::Autostart => t!("Autostart eingerichtet (Aufgabe oder Run-Eintrag)", "autostart set up (task or Run entry)"),
            Step::Credentials => t!("gespeicherte Zugangsdaten geöffnet", "stored sign-in data opened"),
            Step::BadAddress => t!("bekannte Schad- oder Phishing-Adresse abgefragt", "known malicious or phishing address queried"),
            Step::Script => t!("verdächtiges PowerShell-Skript ausgeführt", "suspicious PowerShell script run"),
            Step::ScriptCritical => t!("PowerShell-Skript mit kritischem Inhalt ausgeführt", "PowerShell script with critical content run"),
            Step::Wiederherstellung => t!("Wiederherstellungsdaten sollen gelöscht werden", "recovery data is to be deleted"),
            Step::AgentBeendet => t!("K9-Agent von außen beendet", "K9 agent ended from outside"),
            Step::DienstStopp => t!("Versuch, den K9-Dienst zu beenden", "attempt to stop the K9 service"),
            Step::DienstBeendet => t!("K9-Dienst gewaltsam beendet", "K9 service killed"),
        }
    }

    /// The K9 program an attack step is aimed at.
    fn target(self) -> &'static str {
        if self == Step::AgentBeendet {
            "k9-agent.exe"
        } else {
            "k9-dienst.exe"
        }
    }
}

const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"];

/// A started process that sets up an autostart (scheduled task or Run key).
pub fn sets_autostart(exe: &str, cmd: &str) -> bool {
    let name = exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_lowercase();
    let c = cmd.to_lowercase();
    (name == "schtasks.exe" && c.contains("/create"))
        || (name == "reg.exe" && c.contains(" add") && c.contains("\\currentversion\\run"))
        || (["powershell.exe", "pwsh.exe"].contains(&name.as_str())
            && (c.contains("register-scheduledtask") || (c.contains("currentversion\\run") && (c.contains("new-itemproperty") || c.contains("set-itemproperty")))))
}

#[derive(Debug)]
struct Chain {
    root_pid: u32,
    root_start: i64,
    root_exe: String,
    root: Step,
    steps: BTreeSet<Step>,
    /// (step, program) in the order seen.
    log: Vec<(Step, String)>,
    reported: Option<Severity>,
}

#[derive(Default)]
pub struct Chains {
    chains: Vec<Chain>,
    /// (pid, start) -> chain index.
    members: HashMap<u32, Vec<(i64, usize)>>,
    /// When K9 itself was last attacked (agent ended, stop of the service asked for) and how.
    /// Windows delivers the start of a program up to a few seconds late: a download that
    /// started before that moment but becomes known only afterwards must still count
    /// (sandbox run of 21.11.2026: known 0.2 s too late).
    attacked: Option<(i64, Step)>,
}

/// What to report: the chain as one finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub severity: Severity,
    pub root_pid: u32,
    pub root_start: i64,
    pub root_exe: String,
    /// How the chain began (`Step::Download`, `NeuesProgramm` or `Wechseldatentraeger`).
    pub root: Step,
    pub steps: Vec<String>,
}

impl Chains {
    fn chain_of(&self, pid: u32, start: Option<i64>) -> Option<usize> {
        let start = start?;
        self.members.get(&pid)?.iter().find(|(s, _)| (s - start).abs() < SAME_START).map(|(_, i)| *i)
    }

    fn join(&mut self, pid: u32, start: i64, idx: usize) {
        self.members.entry(pid).or_default().push((start, idx));
    }

    /// An unsigned program from the internet started: a new chain. Reports at once if the K9
    /// agent was ended from outside after this start (the start became known late).
    pub fn start_download(&mut self, pid: u32, start: i64, exe: &str) -> Option<Report> {
        self.start(pid, start, exe, Step::Download)
    }

    /// A program that is the root of a chain started (`root`: why, see `ROOTS`).
    pub fn start(&mut self, pid: u32, start: i64, exe: &str, root: Step) -> Option<Report> {
        debug_assert!(ROOTS.contains(&root));
        if self.chain_of(pid, Some(start)).is_some() {
            return None;
        }
        self.chains.push(Chain {
            root_pid: pid,
            root_start: start,
            root_exe: exe.to_string(),
            root,
            steps: BTreeSet::from([root]),
            log: vec![(root, exe.to_string())],
            reported: None,
        });
        let idx = self.chains.len() - 1;
        self.join(pid, start, idx);
        match self.attacked {
            Some((at, step)) if start <= at && at - start <= WINDOW => self.add(idx, step, step.target()),
            _ => None,
        }
    }

    /// A process started. If its parent belongs to a chain, it joins it.
    pub fn process_started(&mut self, pid: u32, start: i64, parent: u32, parent_start: Option<i64>, exe: &str, cmd: &str) -> Option<Report> {
        let idx = self.chain_of(parent, parent_start)?;
        if start - self.chains[idx].root_start > WINDOW {
            return None;
        }
        self.join(pid, start, idx);
        let name = exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_lowercase();
        let mut report = None;
        if SCRIPT_HOSTS.contains(&name.as_str()) {
            report = self.add(idx, Step::ScriptHost, exe);
        }
        if sets_autostart(exe, cmd) {
            report = self.add(idx, Step::Autostart, exe).or(report);
        }
        report
    }

    /// A step of a process (identified by ID and start time).
    pub fn event(&mut self, pid: u32, start: Option<i64>, at: i64, step: Step, program: &str) -> Option<Report> {
        let idx = self.chain_of(pid, start)?;
        if at - self.chains[idx].root_start > WINDOW {
            return None;
        }
        self.add(idx, step, program)
    }

    /// The K9 agent was ended from outside at `at`. For every chain of the last 30 minutes
    /// that still has a running member (`alive`: process ID and start time) this is a critical
    /// step – malware often switches the protection off first. Seen with the ransomware Conti
    /// on 21.11.2026: agent ended, five seconds later the service, then everything encrypted.
    pub fn agent_ended(&mut self, at: i64, alive: &dyn Fn(u32, i64) -> bool) -> Vec<Report> {
        self.protection_attacked(at, Step::AgentBeendet, alive)
    }

    /// K9 itself was attacked at `at` (`step`: agent ended, stop of the service asked for,
    /// service ended by force). Critical for every chain of the last 30 minutes that still has
    /// a running member.
    pub fn protection_attacked(&mut self, at: i64, step: Step, alive: &dyn Fn(u32, i64) -> bool) -> Vec<Report> {
        debug_assert!(ATTACKS.contains(&step));
        self.attacked = Some((at, step));
        let mut hit: BTreeSet<usize> = BTreeSet::new();
        for (pid, lives) in &self.members {
            for (start, idx) in lives {
                let root = self.chains[*idx].root_start;
                if root <= at && at - root <= WINDOW && *start <= at && alive(*pid, *start) {
                    hit.insert(*idx);
                }
            }
        }
        hit.into_iter().filter_map(|idx| self.add(idx, step, step.target())).collect()
    }

    fn add(&mut self, idx: usize, step: Step, program: &str) -> Option<Report> {
        let c = &mut self.chains[idx];
        if c.steps.insert(step) {
            c.log.push((step, program.to_string()));
        }
        let sev = severity(&c.steps)?;
        if c.reported.is_some_and(|r| r >= sev) {
            return None;
        }
        c.reported = Some(sev);
        Some(Report {
            severity: sev,
            root_pid: c.root_pid,
            root_start: c.root_start,
            root_exe: c.root_exe.clone(),
            root: c.root,
            steps: c.log.iter().map(|(s, p)| format!("{} – {}", s.label(), p.rsplit(['\\', '/']).next().unwrap_or(p))).collect(),
        })
    }

    /// Chains older than the window are dropped (`now` in FILETIME units).
    pub fn prune(&mut self, now: i64) {
        if self.chains.iter().all(|c| now - c.root_start <= 2 * WINDOW) {
            return;
        }
        let keep: Vec<bool> = self.chains.iter().map(|c| now - c.root_start <= 2 * WINDOW).collect();
        let mut map = HashMap::new();
        let mut kept = Vec::new();
        for (i, c) in std::mem::take(&mut self.chains).into_iter().enumerate() {
            if keep[i] {
                map.insert(i, kept.len());
                kept.push(c);
            }
        }
        self.chains = kept;
        for list in self.members.values_mut() {
            list.retain_mut(|(_, i)| match map.get(i) {
                Some(n) => {
                    *i = *n;
                    true
                }
                None => false,
            });
        }
        self.members.retain(|_, l| !l.is_empty());
    }
}

/// Severity of a chain (None: not worth a report yet).
fn severity(steps: &BTreeSet<Step>) -> Option<Severity> {
    if !ROOTS.iter().any(|r| steps.contains(r)) {
        return None;
    }
    if steps.contains(&Step::Credentials) || steps.contains(&Step::BadAddress) || steps.contains(&Step::ScriptCritical) || steps.contains(&Step::Wiederherstellung) || ATTACKS.iter().any(|a| steps.contains(a)) {
        Some(Severity::Kritisch)
    } else if steps.contains(&Step::Script) || steps.contains(&Step::Autostart) {
        Some(Severity::Hoch)
    } else {
        None // download + script host alone: typical for installers
    }
}

/// Where the program at the root of a chain came from, for the title of the finding.
fn origin(root: Step) -> &'static str {
    match root {
        Step::NeuesProgramm => t!("(neu im Benutzerordner)", "(new in the user folder)"),
        Step::Wechseldatentraeger => t!("vom Wechseldatenträger", "from the removable drive"),
        _ => t!("aus dem Internet", "from the internet"),
    }
}

/// One finding per chain (a higher level later is a new finding).
pub fn finding(r: &Report) -> Finding {
    let name = r.root_exe.rsplit(['\\', '/']).next().unwrap_or(&r.root_exe).to_string();
    Finding {
        path: PathBuf::from(tf!("Angriffskette ausgehend von {name}", "Attack chain starting from {name}")),
        sha256: crate::sha256_hex(format!("kette|{}|{}|{:?}", r.root_exe.to_lowercase(), r.root_start, r.severity).as_bytes()),
        size: 0,
        rule_id: "KETTE:ANGRIFF".into(),
        threat_name: tf!("Angriffskette: {name} {} – {}", "Attack chain: {name} {} – {}", origin(r.root), r.steps.iter().skip(1).cloned().collect::<Vec<_>>().join(", ")),
        category: t!("Angriffskette", "Attack chain").into(),
        severity: r.severity,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pid": r.root_pid, "ziel": r.root_exe, "startzeit": r.root_start, "befehl": "", "eltern": "",
            "schritte": r.steps,
            "hinweis": t!("Mehrere Schritte zusammen ergeben ein typisches Angriffsmuster. Kennst du das Programm nicht: „Prozess beenden“, Datei in Quarantäne, einen vollständigen Scan starten und – bei „Zugangsdaten geöffnet“ – von einem anderen Gerät aus Passwörter ändern.", "Several steps together form a typical attack pattern. If you do not know the program: “End process”, put the file into quarantine, start a full scan and – with “sign-in data opened” – change passwords from another device."),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 10_000_000; // one second

    #[test]
    fn download_then_credentials_is_critical() {
        let mut c = Chains::default();
        c.start_download(100, 1000 * S, r"C:\Users\x\Downloads\cheat.exe");
        // Child: PowerShell (script host alone is no report – installers do that).
        assert_eq!(c.process_started(200, 1001 * S, 100, Some(1000 * S), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -nop"), None);
        // The child opens browser passwords.
        let r = c.event(200, Some(1001 * S), 1002 * S, Step::Credentials, "powershell.exe").unwrap();
        assert_eq!(r.severity, Severity::Kritisch);
        assert_eq!(r.root_pid, 100);
        assert!(r.steps.iter().any(|s| s.contains("Zugangsdaten")));
        // Same level again: no second report.
        assert_eq!(c.event(100, Some(1000 * S), 1003 * S, Step::BadAddress, "cheat.exe"), None);
        let f = finding(&r);
        assert_eq!(f.rule_id, "KETTE:ANGRIFF");
        assert_eq!(f.details.unwrap()["startzeit"], 1000 * S);
    }

    #[test]
    fn autostart_makes_it_high_then_critical() {
        let mut c = Chains::default();
        c.start_download(7, 10 * S, r"C:\Users\x\Downloads\mod.exe");
        let r = c.process_started(8, 11 * S, 7, Some(10 * S), r"C:\Windows\System32\schtasks.exe", "schtasks /create /tn x /tr y").unwrap();
        assert_eq!(r.severity, Severity::Hoch);
        let r = c.event(8, Some(11 * S), 12 * S, Step::ScriptCritical, "schtasks.exe").unwrap();
        assert_eq!(r.severity, Severity::Kritisch);
    }

    #[test]
    fn no_chain_without_a_download_and_no_mixup_with_reused_ids() {
        let mut c = Chains::default();
        assert_eq!(c.event(5, Some(S), 2 * S, Step::Credentials, "x.exe"), None);
        c.start_download(5, 100 * S, "dl.exe");
        // Same ID, other start time (another process): not a member.
        assert_eq!(c.event(5, Some(500 * S), 501 * S, Step::Credentials, "anders.exe"), None);
        assert_eq!(c.event(5, None, 101 * S, Step::Credentials, "unbekannt"), None);
        // After the window nothing is added.
        assert_eq!(c.event(5, Some(100 * S), 100 * S + WINDOW + S, Step::Credentials, "dl.exe"), None);
        c.prune(100 * S + 3 * WINDOW);
        assert!(c.chains.is_empty() && c.members.is_empty());
    }

    #[test]
    fn autostart_commands_are_recognised() {
        assert!(sets_autostart(r"C:\Windows\System32\schtasks.exe", "schtasks.exe /Create /SC ONLOGON /TN a /TR b"));
        assert!(sets_autostart("reg.exe", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y"));
        assert!(sets_autostart("powershell.exe", "powershell Register-ScheduledTask -TaskName x"));
        assert!(!sets_autostart("schtasks.exe", "schtasks /query"));
        assert!(!sets_autostart("reg.exe", r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"));
    }

    #[test]
    fn ending_the_agent_while_a_download_runs_is_critical() {
        let mut c = Chains::default();
        c.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        // A helper started by the download belongs to the chain.
        assert_eq!(c.process_started(200, 1010 * S, 100, Some(1000 * S), r"C:\Users\x\AppData\Local\Temp\helfer.exe", "helfer"), None);
        // A second download that has already ended, and one from more than 30 minutes ago.
        c.start_download(300, 1005 * S, r"C:\Users\x\Downloads\fertig.exe");
        c.start_download(400, 1000 * S - WINDOW - S, r"C:\Users\x\Downloads\alt.exe");
        let running = |pid: u32, start: i64| (pid == 100 && start == 1000 * S) || (pid == 200 && start == 1010 * S) || pid == 400;
        let reports = c.agent_ended(1036 * S, &running);
        assert_eq!(reports.len(), 1, "nur die Kette, von der noch etwas läuft und die jung genug ist");
        let r = &reports[0];
        assert_eq!((r.severity, r.root_pid, r.root_start), (Severity::Kritisch, 100, 1000 * S));
        assert!(r.steps.last().unwrap().starts_with("K9-Agent von außen beendet"), "{:?}", r.steps);
        let f = finding(r);
        assert_eq!((f.rule_id.as_str(), f.kind, f.severity), ("KETTE:ANGRIFF", Kind::Prozess, Severity::Kritisch));
        assert!(crate::anhalten::qualifies(&f), "wird über den üblichen Weg angehalten");
        // Reported once: a second end of the agent adds nothing for the same chain.
        assert!(c.agent_ended(1040 * S, &running).is_empty());
        // Nothing from the internet is running: no report.
        let mut quiet = Chains::default();
        quiet.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        assert!(quiet.agent_ended(1036 * S, &|_, _| false).is_empty());
        assert!(Chains::default().agent_ended(1036 * S, &|_, _| true).is_empty());
        // Only the helper is still running (the download itself has ended): the chain still counts.
        let mut helper = Chains::default();
        helper.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        helper.process_started(200, 1010 * S, 100, Some(1000 * S), r"C:\Users\x\AppData\Local\Temp\helfer.exe", "helfer");
        assert_eq!(helper.agent_ended(1036 * S, &|pid, _| pid == 200).len(), 1);
    }

    #[test]
    fn new_unsigned_programs_without_the_internet_mark_start_a_chain_too() {
        // Unpacked from an archive an hour ago, in a user's folder.
        assert_eq!(local_root(r"C:\Users\x\Downloads\entpackt\tool.exe", Some(3600), false), Some(Step::NeuesProgramm));
        assert_eq!(local_root(r"c:\users\x\AppData\Local\Temp\a.exe", Some(0), false), Some(Step::NeuesProgramm));
        // Older than a day, age unknown, or outside the users' folders: no.
        assert_eq!(local_root(r"C:\Users\x\Spiele\alt.exe", Some(NEW_SECS + 1), false), None);
        assert_eq!(local_root(r"C:\Users\x\Downloads\a.exe", None, false), None);
        assert_eq!(local_root(r"D:\Spiele\neu.exe", Some(10), false), None);
        assert_eq!(local_root(r"C:\Program Files\App\neu.exe", Some(10), false), None);
        // From a USB stick: at any age.
        assert_eq!(local_root(r"I:\tool.exe", Some(10 * NEW_SECS), true), Some(Step::Wechseldatentraeger));

        let mut c = Chains::default();
        assert_eq!(c.start(100, 1000 * S, r"C:\Users\x\Downloads\entpackt\tool.exe", Step::NeuesProgramm), None);
        let r = c.agent_ended(1036 * S, &|_, _| true);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].severity, r[0].root), (Severity::Kritisch, Step::NeuesProgramm));
        assert_eq!(r[0].steps[0], "neues unsigniertes Programm aus einem Benutzerordner gestartet – tool.exe");
        let f = finding(&r[0]);
        assert!(f.threat_name.starts_with("Angriffskette: tool.exe (neu im Benutzerordner) – "), "{}", f.threat_name);
        assert!(crate::anhalten::qualifies(&f));
        let mut usb = Chains::default();
        usb.start(100, 1000 * S, r"I:\tool.exe", Step::Wechseldatentraeger);
        let r = usb.event(100, Some(1000 * S), 1010 * S, Step::Credentials, "tool.exe").expect("kritisch");
        assert!(finding(&r).threat_name.starts_with("Angriffskette: tool.exe vom Wechseldatenträger – "));
        // The title of a chain from the internet stays as it was.
        let mut net = Chains::default();
        net.start_download(100, 1000 * S, r"C:\Users\x\Downloads\a.exe");
        assert!(finding(&net.agent_ended(1036 * S, &|_, _| true)[0]).threat_name.starts_with("Angriffskette: a.exe aus dem Internet – "));
    }

    #[test]
    fn deleting_the_recovery_data_makes_a_chain_critical() {
        // Babuk in the test of 21.11.2026: the sample starts cmd.exe, that starts vssadmin –
        // six seconds before the first file is encrypted.
        let mut c = Chains::default();
        c.start_download(100, 1000 * S, r"C:\Users\x\Downloads\probe.exe");
        assert_eq!(c.process_started(200, 1030 * S, 100, Some(1000 * S), r"C:\Windows\System32\cmd.exe", "cmd /c vssadmin delete shadows /all /quiet"), None);
        assert_eq!(c.process_started(300, 1030 * S, 200, Some(1030 * S), r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet"), None);
        let r = c.event(300, Some(1030 * S), 1030 * S, Step::Wiederherstellung, "vssadmin.exe").expect("kritisch");
        assert_eq!((r.severity, r.root_pid), (Severity::Kritisch, 100));
        assert_eq!(r.steps.last().unwrap(), "Wiederherstellungsdaten sollen gelöscht werden – vssadmin.exe");
        assert!(crate::anhalten::qualifies(&finding(&r)), "die Probe wird über die Kette angehalten");
        // Without a chain (e.g. an administrator's own command): nothing.
        assert_eq!(Chains::default().event(300, Some(1030 * S), 1030 * S, Step::Wiederherstellung, "vssadmin.exe"), None);
    }

    #[test]
    fn an_attack_on_the_service_is_critical_too() {
        let running = |_: u32, _: i64| true;
        // A stop of the service was asked for while a download runs.
        let mut c = Chains::default();
        c.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        let r = c.protection_attacked(1041 * S, Step::DienstStopp, &running);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Kritisch);
        assert_eq!(r[0].steps.last().unwrap(), "Versuch, den K9-Dienst zu beenden – k9-dienst.exe");
        assert!(crate::anhalten::qualifies(&finding(&r[0])));
        // The agent was ended before: the chain is critical already, nothing new to report.
        let mut both = Chains::default();
        both.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        assert_eq!(both.agent_ended(1036 * S, &running).len(), 1);
        assert!(both.protection_attacked(1041 * S, Step::DienstStopp, &running).is_empty());
        // After a restart the service finds the download still running.
        let mut after = Chains::default();
        after.start_download(100, 1000 * S, r"C:\Users\x\Downloads\rechnung.exe");
        let r = after.protection_attacked(1043 * S, Step::DienstBeendet, &running);
        assert_eq!(r[0].steps.last().unwrap(), "K9-Dienst gewaltsam beendet – k9-dienst.exe");
        // A download that becomes known late counts for the stop request as well.
        let mut late = Chains::default();
        assert!(late.protection_attacked(1002 * S, Step::DienstStopp, &running).is_empty());
        assert!(late.start_download(100, 1000 * S, r"C:\Users\x\Downloads\a.exe").is_some());
    }

    #[test]
    fn a_download_that_becomes_known_after_the_agent_ended_still_counts() {
        // Sandbox run of 21.11.2026: program started, agent ended 2 s later, but Windows
        // delivered the start of the program 0.2 s after the end of the agent.
        let mut c = Chains::default();
        assert!(c.agent_ended(1002 * S, &|_, _| true).is_empty());
        let r = c.start_download(100, 1000 * S, r"C:\Users\x\Downloads\unbekannt.exe").expect("gemeldet");
        assert_eq!(r.severity, Severity::Kritisch);
        assert!(r.steps.last().unwrap().starts_with("K9-Agent von außen beendet"), "{:?}", r.steps);
        // A program started after the agent was ended has not ended it.
        assert_eq!(c.start_download(200, 1003 * S, r"C:\Users\x\Downloads\spaeter.exe"), None);
        // No end of the agent: nothing.
        assert_eq!(Chains::default().start_download(100, 1000 * S, r"C:\Users\x\Downloads\a.exe"), None);
    }
}
