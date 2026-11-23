//! Ransomware detection in the service: who wrote the files that suddenly look encrypted?
//!
//! The agent (user rights) can be ended by malware before it encrypts – a test on 20.11.2026
//! showed one sample (Conti) encrypting everything without a single alarm. The service runs as
//! SYSTEM, watches the users' document folders itself and already sees every file open with
//! the process ID (ETW Kernel-File). This module keeps these opens for the watched folders
//! and names the process that opened most of the files of a burst: exactly this program is
//! reported and – if switched on – frozen, instead of every recently started program.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::model::{Finding, Kind, Severity};

/// Folders of a user profile that are watched (lower case, with backslashes around).
const USER_FOLDERS: [&str; 4] = ["\\documents\\", "\\desktop\\", "\\pictures\\", "\\downloads\\"];
/// Opens older than this do not explain a change any more.
const KEEP: Duration = Duration::from_secs(90);
const MAX_PATHS: usize = 30_000;

/// The part of a path from `\users\` on, lower case – the same for the NT path of an ETW
/// event (`\Device\HarddiskVolume3\Users\f\Documents\a.docx`) and the path of the folder
/// watcher (`C:\Users\f\Documents\a.docx`). None outside the watched user folders.
pub fn user_tail(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    let tail = &lower[lower.find("\\users\\")?..];
    // \users\<name>\<folder>\…
    let after_name = &tail[7..];
    let rest = &after_name[after_name.find('\\')?..];
    USER_FOLDERS.iter().any(|f| rest.starts_with(f)).then(|| tail.to_string())
}

/// Fast check for the ETW callback (UTF-16, no allocation): could this be a watched path?
pub fn maybe_user_file(name: &[u16]) -> bool {
    let lower = |c: u16| if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c };
    let needle: [u16; 7] = [b'\\' as u16, b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16, b's' as u16, b'\\' as u16];
    name.len() > 20 && name.windows(7).any(|w| w.iter().zip(&needle).all(|(a, b)| lower(*a) == *b))
}

/// Who opened which file lately (per file the first openers, oldest first).
#[derive(Default)]
pub struct Openers {
    by_path: HashMap<String, Vec<(u32, Instant)>>,
    order: VecDeque<(String, Instant)>,
}

impl Openers {
    /// Notes that `pid` opened the file with this tail (see `user_tail`).
    pub fn record(&mut self, tail: String, pid: u32, now: Instant) {
        while self.order.front().is_some_and(|(_, t)| now.duration_since(*t) > KEEP) || self.order.len() >= MAX_PATHS {
            if let Some((old, t)) = self.order.pop_front() {
                if let Some(v) = self.by_path.get_mut(&old) {
                    v.retain(|(_, at)| *at > t);
                    if v.is_empty() {
                        self.by_path.remove(&old);
                    }
                }
            }
        }
        let v = self.by_path.entry(tail.clone()).or_default();
        if v.len() < 6 && !v.iter().any(|(p, _)| *p == pid) {
            v.push((pid, now));
            self.order.push_back((tail, now));
        }
    }

    /// The processes that opened the files of a burst, most files first: (pid, number of
    /// files). Ransomware often renames a file after encrypting it (`a.docx` → `a.docx.lock`):
    /// the open of the old name counts for the new one. `ignore`: K9's own processes.
    pub fn culprits(&self, files: &[PathBuf], ignore: &[u32], now: Instant) -> Vec<(u32, usize)> {
        let mut count: HashMap<u32, usize> = HashMap::new();
        for f in files {
            let Some(tail) = user_tail(&f.to_string_lossy()) else { continue };
            let stem = Path::new(&tail).with_extension("").to_string_lossy().to_string();
            let mut pids: Vec<u32> = Vec::new();
            for key in [tail.as_str(), stem.as_str()] {
                for (pid, at) in self.by_path.get(key).into_iter().flatten() {
                    if now.duration_since(*at) <= KEEP && !ignore.contains(pid) && !pids.contains(pid) {
                        pids.push(*pid);
                    }
                }
            }
            for pid in pids {
                *count.entry(pid).or_default() += 1;
            }
        }
        let mut v: Vec<(u32, usize)> = count.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// How many of these files have any recorded open (for the log: is the event session late?).
    pub fn known(&self, files: &[PathBuf]) -> usize {
        files
            .iter()
            .filter(|f| {
                user_tail(&f.to_string_lossy()).is_some_and(|tail| {
                    let stem = Path::new(&tail).with_extension("").to_string_lossy().to_string();
                    self.by_path.contains_key(&tail) || self.by_path.contains_key(&stem)
                })
            })
            .count()
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

/// The watched folders of all real user profiles (Documents, Desktop, Pictures, Downloads).
pub fn profile_dirs() -> Vec<PathBuf> {
    use crate::winreg::{self, HKLM};
    const LIST: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    let mut out = Vec::new();
    for sid in winreg::subkeys(HKLM, LIST) {
        // Real users only (S-1-5-21-…), not SYSTEM or the service accounts.
        if !sid.starts_with("S-1-5-21-") {
            continue;
        }
        let Some(profile) = winreg::read_string(HKLM, &format!("{LIST}\\{sid}"), "ProfileImagePath") else { continue };
        let profile = PathBuf::from(crate::paths::expand_env(&profile));
        for sub in ["Documents", "Desktop", "Pictures", "Downloads"] {
            let d = profile.join(sub);
            if d.is_dir() {
                out.push(d);
            }
        }
    }
    out
}

/// One program of a ransomware finding.
pub struct Suspect {
    pub pid: u32,
    pub path: PathBuf,
    pub start: Option<i64>,
    /// Files of the burst this program had opened.
    pub files: usize,
}

/// The finding of the service: `suspects` are the programs that opened the changed files.
pub fn finding(reason: &str, art: &str, files: &[PathBuf], suspects: &[Suspect], frozen: bool) -> Finding {
    let sample: Vec<String> = files.iter().take(5).map(|f| f.display().to_string()).collect();
    let names: Vec<String> = suspects.iter().map(|s| tf!("{} (PID {}, {} der Dateien)", "{} (PID {}, {} of the files)", s.path.display(), s.pid, s.files)).collect();
    let hint = match (suspects.is_empty(), frozen) {
        (true, _) => t!("Welches Programm die Dateien verändert hat, ließ sich nicht bestimmen. Prüfe sofort, ob Dateien unlesbar geworden sind oder neue Endungen tragen; im Zweifel den PC vom Netz trennen und herunterfahren.", "Which program changed the files could not be determined. Check at once whether files have become unreadable or carry new extensions; if in doubt, disconnect the PC from the network and shut it down."),
        (false, true) => t!("Das Programm, das diese Dateien geöffnet hat, wurde ANGEHALTEN (nicht beendet). „Prozess beenden“ stoppt es, „Freigabe“ lässt es weiterlaufen.", "The program that opened these files was SUSPENDED (not ended). “End process” stops it, “Allow” lets it continue."),
        (false, false) => t!("Das Programm, das diese Dateien geöffnet hat, läuft weiter. „Prozess beenden“ stoppt es, „Freigabe“ lässt es weiterlaufen.", "The program that opened these files is still running. “End process” stops it, “Allow” lets it continue."),
    };
    Finding {
        path: PathBuf::from(tf!("Ransomware-Verdacht: {reason}", "Suspected ransomware: {reason}")),
        sha256: crate::sha256_hex(format!("ransomware-dienst|{}|{}", crate::now_string(), sample.join("|")).as_bytes()),
        size: 0,
        rule_id: "RANSOMWARE:VERHALTEN".into(),
        threat_name: tf!("Ransomware-Verdacht – {reason}", "Suspected ransomware – {reason}"),
        category: "Ransomware".into(),
        severity: Severity::Kritisch,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pids": suspects.iter().map(|s| s.pid).collect::<Vec<_>>(),
            "prozesse": suspects.iter().map(|s| serde_json::json!({ "pid": s.pid, "ziel": s.path.display().to_string(), "startzeit": s.start })).collect::<Vec<_>>(),
            "ziel": suspects.first().map(|s| s.path.display().to_string()).unwrap_or_default(),
            "angehalten": frozen,
            "art": art,
            "befehl": names.join(", "),
            "dateien": sample,
            "hinweis": hint,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tails_match_between_event_and_watcher_and_only_in_user_folders() {
        let event = r"\Device\HarddiskVolume3\Users\Anna\Documents\Steuer\2025.xlsx";
        let watcher = r"C:\Users\anna\Documents\Steuer\2025.xlsx";
        assert_eq!(user_tail(event), user_tail(watcher));
        assert_eq!(user_tail(watcher).as_deref(), Some(r"\users\anna\documents\steuer\2025.xlsx"));
        assert!(user_tail(r"C:\Users\anna\Desktop\a.txt").is_some());
        assert!(user_tail(r"C:\Users\anna\AppData\Local\Temp\a.txt").is_none(), "nicht ueberwacht");
        assert!(user_tail(r"C:\Windows\System32\a.dll").is_none());
        assert!(user_tail(r"C:\Users\anna").is_none());
        let wide: Vec<u16> = event.encode_utf16().collect();
        assert!(maybe_user_file(&wide));
        assert!(!maybe_user_file(&r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll".encode_utf16().collect::<Vec<_>>()));
    }

    #[test]
    fn the_program_that_opened_most_files_is_the_culprit() {
        let now = Instant::now();
        let mut o = Openers::default();
        let files: Vec<PathBuf> = (0..12).map(|i| PathBuf::from(format!(r"C:\Users\f\Documents\d{i}.docx.lock"))).collect();
        for i in 0..12 {
            // The ransomware (PID 500) opened the original name, a virus scanner (PID 77) the new one.
            o.record(user_tail(&format!(r"\Device\HarddiskVolume3\Users\f\Documents\d{i}.docx")).unwrap(), 500, now);
            if i < 5 {
                o.record(user_tail(&format!(r"\Device\HarddiskVolume3\Users\f\Documents\d{i}.docx.lock")).unwrap(), 77, now);
            }
        }
        o.record(user_tail(r"C:\Users\f\Documents\anderes.txt").unwrap(), 900, now);
        assert_eq!(o.culprits(&files, &[], now), vec![(500, 12), (77, 5)]);
        assert_eq!(o.culprits(&files, &[500], now), vec![(77, 5)], "eigene Prozesse zaehlen nicht");
        assert!(o.culprits(&files, &[], now + Duration::from_secs(200)).is_empty(), "alte Zugriffe erklaeren nichts mehr");
        assert!(o.culprits(&[PathBuf::from(r"C:\Windows\a.dll")], &[], now).is_empty());
    }

    #[test]
    fn old_opens_are_dropped_and_the_table_stays_bounded() {
        let start = Instant::now();
        let mut o = Openers::default();
        for i in 0..100 {
            o.record(format!(r"\users\f\documents\{i}.txt"), 5, start);
        }
        assert_eq!(o.len(), 100);
        o.record(r"\users\f\documents\neu.txt".into(), 5, start + Duration::from_secs(120));
        assert_eq!(o.len(), 1, "nach 90 Sekunden vergessen");
        // The same program opening a file again and again is one entry.
        for _ in 0..50 {
            o.record(r"\users\f\documents\neu.txt".into(), 5, start + Duration::from_secs(121));
        }
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn finding_names_the_program_and_says_what_happened() {
        let s = [Suspect { pid: 500, path: PathBuf::from(r"C:\Users\f\Downloads\x.exe"), start: Some(1), files: 12 }];
        let f = finding("viele Dateien wurden in kurzer Zeit verschlüsselt/überschrieben", "viele", &[PathBuf::from(r"C:\Users\f\Documents\a.lock")], &s, true);
        assert_eq!((f.rule_id.as_str(), f.severity, f.engine.as_str()), ("RANSOMWARE:VERHALTEN", Severity::Kritisch, "dienst"));
        let d = f.details.unwrap();
        assert_eq!(d["ziel"], r"C:\Users\f\Downloads\x.exe");
        assert_eq!(d["angehalten"], true);
        assert!(d["hinweis"].as_str().unwrap().contains("ANGEHALTEN"));
        let none = finding("x", "viele", &[], &[], false);
        assert!(none.details.unwrap()["hinweis"].as_str().unwrap().contains("nicht bestimmen"));
    }
}
