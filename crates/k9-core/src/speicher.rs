//! Memory scan while the PC is idle: finds malicious code that lives only in memory (injected
//! or unpacked there, never written to disk). Off by default.
//!
//! Anti-cheat systems treat foreign access to the memory of a game or of the anti-cheat as an
//! attack – in the worst case the game account gets banned. Therefore the scan is built so
//! that it can't meet one:
//!   * never while a game is detected, never while ANY anti-cheat or game process runs –
//!     then the whole run is skipped (not only those processes);
//!   * never at all on a PC with an anti-cheat that is always loaded (Riot Vanguard, FACEIT);
//!   * only programs from folders a user can write to, or without a valid signature – never
//!     Windows, Microsoft or Trend Micro programs, K9 itself, games or anti-cheat;
//!   * read only, with the rights of the logged-on user (no debug right, no code injection,
//!     nothing is suspended); only private executable memory, at most 48 MB per process.
//!
//! Only YARA rules with a high score count (75 and more) – memory contains many harmless strings.

use std::path::{Path, PathBuf};

use crate::model::{Finding, Kind, Severity};

/// Anti-cheat systems whose driver is loaded all the time (service key in the registry).
const ALWAYS_ON: &[(&str, &str)] = &[("vgk", "Riot Vanguard"), ("vgc", "Riot Vanguard"), ("FACEIT", "FACEIT Anti-Cheat"), ("ESEADriver2", "ESEA Anti-Cheat")];

/// Process names of anti-cheat services and helpers (lowercase).
const ANTI_CHEAT_NAMES: &[&str] = &[
    "beservice", "beservice_x64", "easyanticheat", "easyanticheat_eos", "easyanticheat_setup", "vgc", "vgtray", "faceit", "faceitservice", "eaanticheat",
    "eaanticheat.gameservicelauncher", "gameguard", "gamemon", "xigncode", "pnkbstra", "pnkbstrb", "mhyprot2", "atvi-crowdstrike", "randgrid",
];

/// An anti-cheat that is always loaded: the memory scan never runs on such a PC.
pub fn always_on_anticheat() -> Option<&'static str> {
    ALWAYS_ON.iter().find(|(key, _)| crate::winreg::key_exists(crate::winreg::HKLM, &format!("SYSTEM\\CurrentControlSet\\Services\\{key}"))).map(|(_, name)| *name)
}

fn is_anticheat(name: &str, path: &str) -> bool {
    let n = name.to_lowercase();
    let stem = n.strip_suffix(".exe").unwrap_or(&n);
    let p = path.to_lowercase();
    ANTI_CHEAT_NAMES.contains(&stem) || ["easyanticheat", "battleye", "riot vanguard", "faceit", "anticheat", "anti-cheat", "gameguard", "xigncode"].iter().any(|a| p.contains(a))
}

fn is_game(name: &str, path: &str, game_dirs: &[String], game_names: &[String]) -> bool {
    let p = path.to_lowercase();
    game_names.iter().any(|g| g.eq_ignore_ascii_case(name)) || game_dirs.iter().any(|d| !d.is_empty() && p.contains(&d.to_lowercase()))
}

/// A running process as the scan sees it.
#[derive(Debug, Clone)]
pub struct Prozess {
    pub pid: u32,
    pub name: String,
    /// Full path of the program ("" when it can't be read).
    pub path: String,
}

/// Why nothing may be scanned right now (None: allowed). Any game or anti-cheat process
/// stops the whole run.
pub fn blocker(processes: &[Prozess], game_dirs: &[String], game_names: &[String]) -> Option<String> {
    processes.iter().find_map(|p| {
        if is_anticheat(&p.name, &p.path) {
            Some(tf!("Anti-Cheat läuft ({})", "anti-cheat is running ({})", p.name))
        } else if is_game(&p.name, &p.path, game_dirs, game_names) {
            Some(tf!("ein Spiel läuft ({})", "a game is running ({})", p.name))
        } else {
            None
        }
    })
}

/// May this process be scanned? `signer`: valid signer (None: unsigned), `user_writable`:
/// the program lies in a folder a user can write to.
/// `skip_dirs`: further folders that are never scanned (K9's helper ClamAV).
pub fn target_allowed(p: &Prozess, signer: Option<&str>, user_writable: bool, game_dirs: &[String], game_names: &[String], own_dir: &str, skip_dirs: &[String]) -> bool {
    let lower = p.path.to_lowercase();
    // Store apps are signed through their package (the single file looks unsigned) and lie
    // in a folder only Windows can write to.
    let store_app = std::env::var("ProgramFiles").is_ok_and(|pf| lower.starts_with(&format!("{}\\windowsapps\\", pf.to_lowercase())));
    let skipped = skip_dirs.iter().any(|d| d.len() > 3 && lower.starts_with(&format!("{}\\", d.to_lowercase().trim_end_matches('\\'))));
    !p.path.is_empty()
        && !store_app
        && !skipped
        && (user_writable || signer.is_none())
        && !is_anticheat(&p.name, &p.path)
        && crate::anhalten::freeze_allowed(&p.path, signer, game_dirs, game_names, own_dir).is_ok()
}

/// Private, committed, executable memory of a process (where injected or unpacked code
/// lives), read with the minimal rights. At most `max_total` bytes; regions over 16 MB are
/// skipped. Empty when the process can't be opened (protected, other user, ended).
pub fn executable_private_memory(pid: u32, max_total: usize) -> Vec<Vec<u8>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ};
    let mut out = Vec::new();
    let mut total = 0usize;
    // SAFETY: handle closed below; buffers sized as passed; only reading.
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid) else { return out };
        let mut addr = 0usize;
        let mut info = MEMORY_BASIC_INFORMATION::default();
        while VirtualQueryEx(h, Some(addr as *const core::ffi::c_void), &mut info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            let size = info.RegionSize;
            let exec = (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)).0 != 0;
            let readable = (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)).0 == 0;
            if info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && exec && readable && size <= 16 * 1024 * 1024 && total + size <= max_total {
                let mut buf = vec![0u8; size];
                let mut got = 0usize;
                if ReadProcessMemory(h, info.BaseAddress, buf.as_mut_ptr().cast(), size, Some(&mut got)).is_ok() && got > 0 {
                    buf.truncate(got);
                    total += got;
                    out.push(buf);
                }
            }
            let next = (info.BaseAddress as usize).saturating_add(size.max(4096));
            if next <= addr || total >= max_total {
                break;
            }
            addr = next;
        }
        let _ = CloseHandle(h);
    }
    out
}

/// A hit in memory: rule, readable name, severity.
#[derive(Debug, Clone, PartialEq)]
pub struct Treffer {
    pub rule: String,
    pub name: String,
    pub severity: Severity,
}

/// Rule hits of the engines in a block of memory: (rule id, readable name, severity).
pub type SpeicherTreffer = Vec<(String, String, Severity)>;

/// YARA rules need this score to count in memory.
pub const MIN_SCORE: i64 = 75;

/// Scans memory regions: the harmless test signature and the rules of `engines` (YARA rules
/// with a score of 75 or more). Each rule once.
pub fn scan_regions(regions: &[Vec<u8>], engines: &dyn Fn(&[u8]) -> SpeicherTreffer) -> Vec<Treffer> {
    let mut out: Vec<Treffer> = Vec::new();
    let test = crate::engine::test_pattern_bytes();
    for r in regions {
        if !test.is_empty() && r.windows(test.len()).any(|w| w == test.as_slice()) && !out.iter().any(|t| t.rule == "TEST") {
            out.push(Treffer { rule: "TEST".into(), name: "K9-Testsignatur im Arbeitsspeicher (harmlos)".into(), severity: Severity::Niedrig });
        }
        for (rule, name, severity) in engines(r) {
            if !out.iter().any(|t| t.rule == rule) {
                out.push(Treffer { rule, name, severity });
            }
        }
    }
    out
}

pub fn finding(p: &Prozess, start: Option<i64>, t: &Treffer) -> Finding {
    let mut details = serde_json::json!({
        "pid": p.pid, "ziel": p.path, "befehl": "", "eltern": "",
        "hinweis": t!("Im Arbeitsspeicher dieses Programms steht Code, auf den eine Regel für Schadsoftware passt – auch wenn die Programmdatei selbst unauffällig ist. Nichts wurde beendet. Kennst du das Programm nicht: „Prozess beenden“ und einen vollständigen Scan starten.", "The memory of this program contains code that matches a rule for malware – even if the program file itself is inconspicuous. Nothing was ended. If you do not know the program: “End process” and start a full scan."),
    });
    if let Some(s) = start {
        details["startzeit"] = s.into();
    }
    Finding {
        path: PathBuf::from(tf!("Arbeitsspeicher von {} (PID {})", "Memory of {} (PID {})", Path::new(&p.path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.name.clone()), p.pid)),
        // One finding per program and rule: a "Freigabe" holds for exactly this pair.
        sha256: crate::sha256_hex(format!("speicher|{}|{}", p.path.to_lowercase(), t.rule).as_bytes()),
        size: 0,
        rule_id: format!("SPEICHER:{}", t.rule),
        threat_name: tf!("Schadcode im Arbeitsspeicher: {}", "Malicious code in memory: {}", t.name),
        category: t!("Speicher-Scan", "Memory scan").into(),
        severity: t.severity,
        engine: "speicher".into(),
        kind: Kind::Prozess,
        details: Some(details),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, path: &str) -> Prozess {
        Prozess { pid: 1, name: name.into(), path: path.into() }
    }

    fn dirs() -> Vec<String> {
        vec!["\\steamapps\\common\\".to_string()]
    }

    #[test]
    fn any_game_or_anticheat_process_stops_the_whole_run() {
        let normal = [p("notepad.exe", "C:\\Windows\\notepad.exe"), p("tool.exe", "C:\\Users\\f\\Downloads\\tool.exe")];
        assert!(blocker(&normal, &dirs(), &[]).is_none());
        let be = [normal[0].clone(), p("BEService.exe", "C:\\Program Files (x86)\\Common Files\\BattlEye\\BEService.exe")];
        assert!(blocker(&be, &dirs(), &[]).unwrap().contains("Anti-Cheat"));
        let eac = [p("EasyAntiCheat_EOS.exe", "")];
        assert!(blocker(&eac, &dirs(), &[]).is_some(), "auch ohne lesbaren Pfad");
        let game = [p("Spiel.exe", "D:\\Spiele\\steamapps\\common\\Beispielspiel\\Spiel.exe")];
        assert!(blocker(&game, &dirs(), &[]).unwrap().contains("Spiel"));
        assert!(blocker(&[p("eldenring.exe", "E:\\x\\eldenring.exe")], &[], &["eldenring.exe".to_string()]).is_some());
    }

    #[test]
    fn only_unsigned_or_user_folder_programs_are_targets() {
        let own = "C:\\Program Files\\K9";
        let skip = vec!["C:\\Program Files\\ClamAV".to_string()];
        assert!(!target_allowed(&p("clamd.exe", "C:\\Program Files\\ClamAV\\clamd.exe"), None, false, &dirs(), &[], own, &skip), "K9s Hilfsprogramm ClamAV nie");
        if let Ok(pf) = std::env::var("ProgramFiles") {
            assert!(!target_allowed(&p("WidgetService.exe", &format!("{pf}\\WindowsApps\\X_1.0_x64__abc\\WidgetService.exe")), None, false, &dirs(), &[], own, &skip), "Store-Apps nie");
        }
        let dl = p("tool.exe", "C:\\Users\\f\\Downloads\\tool.exe");
        assert!(target_allowed(&dl, None, true, &dirs(), &[], own, &skip));
        assert!(target_allowed(&dl, Some("Irgendwer GmbH"), true, &dirs(), &[], own, &skip), "Benutzerordner auch signiert");
        assert!(!target_allowed(&p("app.exe", "C:\\Program Files\\App\\app.exe"), Some("Irgendwer GmbH"), false, &dirs(), &[], own, &skip), "signiert in Programme: nicht");
        assert!(target_allowed(&p("app.exe", "C:\\Program Files\\App\\app.exe"), None, false, &dirs(), &[], own, &skip), "unsigniert: ja");
        assert!(!target_allowed(&p("svchost.exe", "C:\\Windows\\System32\\svchost.exe"), None, false, &dirs(), &[], own, &skip));
        assert!(!target_allowed(&p("Code.exe", "C:\\Users\\f\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"), Some("Microsoft Corporation"), true, &dirs(), &[], own, &skip));
        assert!(!target_allowed(&p("k9-agent.exe", "C:\\Program Files\\K9\\k9-agent.exe"), None, false, &dirs(), &[], own, &skip));
        assert!(!target_allowed(&p("Spiel.exe", "D:\\steamapps\\common\\Spiel\\Spiel.exe"), None, false, &dirs(), &[], own, &skip));
        assert!(!target_allowed(&p("x.exe", ""), None, true, &dirs(), &[], own, &skip), "ohne Pfad nie");
    }

    #[test]
    fn test_signature_is_found_in_the_own_private_executable_memory() {
        use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        let sig = crate::engine::test_pattern_bytes();
        // SAFETY: own allocation of one page region, written within its size and freed below.
        unsafe {
            let mem = VirtualAlloc(None, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            assert!(!mem.is_null());
            std::ptr::copy_nonoverlapping(sig.as_ptr(), (mem as *mut u8).add(100), sig.len());
            let regions = executable_private_memory(std::process::id(), 48 * 1024 * 1024);
            let hits = scan_regions(&regions, &|_| Vec::new());
            let _ = VirtualFree(mem, 0, MEM_RELEASE);
            assert_eq!(hits.len(), 1, "{} Bereiche gelesen", regions.len());
            assert_eq!(hits[0].rule, "TEST");
        }
        let f = finding(&p("tool.exe", "C:\\Users\\f\\Downloads\\tool.exe"), Some(5), &Treffer { rule: "TEST".into(), name: "n".into(), severity: Severity::Niedrig });
        assert_eq!((f.rule_id.as_str(), f.kind), ("SPEICHER:TEST", Kind::Prozess));
        assert!(executable_private_memory(4, 1024).is_empty(), "System-Prozess: nichts");
    }
}
