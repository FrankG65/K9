//! Autostart audit: Run/RunOnce keys, Startup folders, scheduled tasks and
//! services. Each target program is scanned with all engines; additionally,
//! unsigned programs started from user-writable folders are flagged.
//! "Deaktivieren" is reversible (backup in the database / quarantine).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows::core::{Interface, BSTR, PCWSTR};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, STGM_READ,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC, TASK_ENUM_HIDDEN,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink, SLGP_RAWPATH};

use crate::model::{Detection, Finding, Kind, Severity};
use crate::paths::expand_env;
use crate::scanner::Scanner;
use crate::store::Store;
use crate::winreg::{self, HKCU, HKLM};

#[derive(Debug, Clone, PartialEq)]
pub enum Location {
    Run { hive: &'static str, key: String },
    Startup { file: PathBuf },
    Task { path: String },
    Service { name: String },
    /// Browser helper registration (native messaging host).
    NativeHost { hive: &'static str, key: String, browser: &'static str },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub location: Location,
    pub name: String,
    pub command: String,
    pub target: Option<PathBuf>,
}

impl Entry {
    /// The entry as text for the user, in the active language.
    pub fn describe(&self) -> String {
        if !crate::sprache::en() {
            return self.identity();
        }
        match &self.location {
            Location::Run { hive, key } => format!("Autostart {hive}\\{key} → {}", self.name),
            Location::Startup { file } => format!("Startup folder: {}", file.display()),
            Location::Task { path } => format!("Scheduled task: {path}"),
            Location::Service { name } => format!("Service: {name}"),
            Location::NativeHost { hive, key, browser } => format!("Browser helper ({browser}) {hive}\\{key}"),
        }
    }

    /// The entry as a fixed text: part of the fingerprint of a finding and of the list of
    /// known entries. Never translated - a decision has to fit in every language.
    pub fn identity(&self) -> String {
        match &self.location {
            Location::Run { hive, key } => format!("Autostart {hive}\\{key} → {}", self.name),
            Location::Startup { file } => format!("Autostart-Ordner: {}", file.display()),
            Location::Task { path } => format!("Geplante Aufgabe: {path}"),
            Location::Service { name } => format!("Dienst: {name}"),
            Location::NativeHost { hive, key, browser } => format!("Browser-Hilfsprogramm ({browser}) {hive}\\{key}"),
        }
    }

    fn details(&self) -> serde_json::Value {
        let mut v = match &self.location {
            Location::Run { hive, key } => serde_json::json!({ "art": "run", "hive": hive, "schluessel": key, "name": self.name }),
            Location::Startup { file } => serde_json::json!({ "art": "startordner", "datei": file.display().to_string(), "name": self.name }),
            Location::Task { path } => serde_json::json!({ "art": "aufgabe", "aufgabe": path, "name": self.name }),
            Location::Service { name } => serde_json::json!({ "art": "dienst", "dienst": name, "name": self.name }),
            Location::NativeHost { hive, key, browser } => {
                serde_json::json!({ "art": "browserhelfer", "hive": hive, "schluessel": key, "browser": browser, "name": self.name })
            }
        };
        v["befehl"] = self.command.clone().into();
        v["ziel"] = self.target.as_ref().map(|t| t.display().to_string()).into();
        v
    }
}

const RUN_KEYS: [&str; 4] = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

const SCRIPT_HOSTS: [&str; 8] = ["rundll32.exe", "regsvr32.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
const PAYLOAD_EXT: [&str; 9] = [".dll", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta"];

/// Extracts the started program (or the script/DLL a script host runs).
pub fn target_from_command(cmd: &str) -> Option<PathBuf> {
    let c = expand_env(cmd.trim());
    let c = c.strip_prefix("\\??\\").unwrap_or(&c).to_string();
    let c = match c.to_ascii_lowercase().strip_prefix("\\systemroot\\") {
        Some(_) => format!("{}\\{}", std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()), &c[12..]),
        None => c,
    };
    let (exe, args) = if let Some(rest) = c.strip_prefix('"') {
        let end = rest.find('"')?;
        (rest[..end].to_string(), rest[end + 1..].to_string())
    } else {
        let lower = c.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(i) => (c[..i + 4].to_string(), c[i + 4..].to_string()),
            None => {
                let first = c.split_whitespace().next()?.to_string();
                let rest = c[first.len()..].to_string();
                (first, rest)
            }
        }
    };
    let exe_name = Path::new(&exe).file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if SCRIPT_HOSTS.contains(&exe_name.as_str()) {
        // The interesting file is the script/DLL in the arguments.
        for part in args.split(['"', ',', ' ']).filter(|p| !p.is_empty()) {
            let l = part.to_ascii_lowercase();
            if PAYLOAD_EXT.iter().any(|e| l.ends_with(e)) && part.contains('\\') {
                return Some(PathBuf::from(part));
            }
        }
    }
    let exe = exe.trim();
    if !exe.contains('\\') {
        return None; // bare name like "ctfmon.exe" -> resolved by Windows from system folders
    }
    Some(PathBuf::from(exe))
}

/// Folders a normal user (or malware running as the user) can write to: the user
/// profile, TEMP and Public always; below %ProgramData% it depends on the real
/// permissions (e.g. "Package Cache" is only writable for administrators).
pub fn is_user_writable(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let mut roots: Vec<String> = ["USERPROFILE", "TEMP", "PUBLIC"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|s| s.to_lowercase())
        .collect();
    roots.push("c:\\users\\".into());
    if roots.iter().any(|r| !r.is_empty() && p.starts_with(r.as_str())) {
        return true;
    }
    match std::env::var("ProgramData") {
        Ok(pd) if !pd.is_empty() && p.starts_with(&format!("{}\\", pd.to_lowercase())) => programdata_writable(path, Path::new(&pd)),
        _ => false,
    }
}

/// A file below %ProgramData% is user-writable if a non-administrator may change the
/// file, its folder, or replace a folder on the way up (up to %ProgramData%).
/// Unreadable permissions count as writable (as before).
fn programdata_writable(path: &Path, programdata: &Path) -> bool {
    use crate::schutz::{non_admin_can, CHANGE_RIGHTS, REPLACE_CHILD_RIGHTS};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<(PathBuf, u32), bool>>> = OnceLock::new();
    let cached = |dir: &Path, mask: u32| -> bool {
        let cache = CACHE.get_or_init(Default::default);
        let key = (dir.to_path_buf(), mask);
        if let Some(v) = cache.lock().unwrap().get(&key) {
            return *v;
        }
        let v = non_admin_can(dir, mask).unwrap_or(true);
        let mut c = cache.lock().unwrap();
        if c.len() > 2000 {
            c.clear();
        }
        c.insert(key, v);
        v
    };
    if path.exists() && non_admin_can(path, CHANGE_RIGHTS).unwrap_or(true) {
        return true;
    }
    let root = programdata.to_string_lossy().to_lowercase();
    for (i, dir) in path.ancestors().skip(1).enumerate() {
        let mask = if i == 0 { CHANGE_RIGHTS } else { REPLACE_CHILD_RIGHTS };
        if cached(dir, mask) {
            return true;
        }
        if dir.to_string_lossy().to_lowercase() == root {
            break;
        }
    }
    false
}

/// `%LOCALAPPDATA%\Microsoft\WindowsApps\...` entries are App Execution
/// Aliases (reparse points) that start a signed, installed Store app.
pub fn is_store_app_alias(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    p.contains("\\appdata\\local\\microsoft\\windowsapps\\") && std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true)
}

/// Signed, or a Windows system file below %SystemRoot% (those are catalog-signed,
/// which the embedded-signature check does not see).
pub fn is_trusted(path: &Path) -> bool {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    path.to_string_lossy().to_lowercase().starts_with(&format!("{windir}\\")) || is_signed(path)
}

/// Result of an Authenticode check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Signed,
    /// No signature, or an invalid/untrusted one.
    Unsigned,
    /// Could not be checked: file missing, locked (e.g. during an installation) or unreadable.
    NotCheckable,
}

/// Authenticode check of an embedded signature (no network revocation check).
pub fn is_signed(path: &Path) -> bool {
    signature(path) == Signature::Signed
}

/// Maps a WinVerifyTrust result: file access errors (HRESULT_FROM_WIN32, facility 7)
/// and CRYPT_E_FILE_ERROR mean "not checkable", everything else that is not 0 "unsigned".
pub fn classify_trust_result(r: i32) -> Signature {
    let u = r as u32;
    if u == 0 {
        Signature::Signed
    } else if u & 0xFFFF_0000 == 0x8007_0000 || u == 0x8009_2003 {
        Signature::NotCheckable
    } else {
        Signature::Unsigned
    }
}

pub fn signature(path: &Path) -> Signature {
    if !path.is_file() {
        return Signature::NotCheckable;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide_nul();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: structures are fully initialized and outlive both calls.
    unsafe {
        let r = WinVerifyTrust(windows::Win32::Foundation::HWND(-1isize as _), &mut action, &mut data as *mut _ as *mut _);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(windows::Win32::Foundation::HWND(-1isize as _), &mut action, &mut data as *mut _ as *mut _);
        classify_trust_result(r)
    }
}

trait WideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}
impl WideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

fn com_init() {
    // SAFETY: per-thread COM init; a different existing mode is fine.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
}

/// Target of a .lnk shortcut.
fn resolve_lnk(path: &Path) -> Option<PathBuf> {
    com_init();
    // SAFETY: COM objects are released when dropped.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let pf: IPersistFile = link.cast().ok()?;
        let w = path.as_os_str().encode_wide_nul();
        pf.Load(PCWSTR(w.as_ptr()), STGM_READ).ok()?;
        let mut buf = [0u16; 1024];
        link.GetPath(&mut buf, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32).ok()?;
        let len = buf.iter().position(|c| *c == 0).unwrap_or(0);
        (len > 0).then(|| PathBuf::from(expand_env(&String::from_utf16_lossy(&buf[..len]))))
    }
}

fn startup_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(a) = std::env::var("APPDATA") {
        v.push(PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(p) = std::env::var("ProgramData") {
        v.push(PathBuf::from(p).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    v
}

fn task_service() -> Result<ITaskService> {
    com_init();
    // SAFETY: standard COM activation of the Task Scheduler.
    unsafe {
        let svc: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        svc.Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())?;
        Ok(svc)
    }
}

fn walk_tasks(folder: &ITaskFolder, out: &mut Vec<Entry>) {
    // SAFETY: COM calls on valid interfaces.
    unsafe {
        if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0) {
            let n = tasks.Count().unwrap_or(0);
            for i in 1..=n {
                let Ok(task) = tasks.get_Item(&VARIANT::from(i)) else { continue };
                if task.Enabled().map(|e| !e.as_bool()).unwrap_or(false) {
                    continue;
                }
                let path = task.Path().map(|p| p.to_string()).unwrap_or_default();
                let Ok(def) = task.Definition() else { continue };
                let Ok(actions) = def.Actions() else { continue };
                let mut c = 0i32;
                let _ = actions.Count(&mut c);
                for j in 1..=c {
                    let Ok(a) = actions.get_Item(j) else { continue };
                    let mut typ = Default::default();
                    if a.Type(&mut typ).is_err() || typ != TASK_ACTION_EXEC {
                        continue;
                    }
                    let Ok(exec) = a.cast::<IExecAction>() else { continue };
                    let mut p = BSTR::new();
                    let mut args = BSTR::new();
                    let _ = exec.Path(&mut p);
                    let _ = exec.Arguments(&mut args);
                    let cmd = format!("\"{}\" {}", p.to_string().trim_matches('"'), args);
                    out.push(Entry {
                        location: Location::Task { path: path.clone() },
                        name: path.rsplit('\\').next().unwrap_or("").to_string(),
                        target: target_from_command(&cmd),
                        command: cmd,
                    });
                }
            }
        }
        if let Ok(subs) = folder.GetFolders(0) {
            for k in 1..=subs.Count().unwrap_or(0) {
                if let Ok(sub) = subs.get_Item(&VARIANT::from(k)) {
                    walk_tasks(&sub, out);
                }
            }
        }
    }
}

/// All autostart entries of this PC (current user + machine).
pub fn enumerate() -> Vec<Entry> {
    let mut out = enumerate_quick();
    enumerate_tasks_and_services(&mut out);
    out
}

/// Wake-up signal for the quick autostart places: the Run/RunOnce keys (user and machine,
/// 64 and 32 bit) and the Startup folders. Windows signals a change at once.
pub fn quick_watch() -> crate::sofort::Wecker {
    let mut w = crate::sofort::Wecker::new();
    for hive in [HKCU, HKLM] {
        for key in RUN_KEYS {
            w.registry(hive, key);
        }
    }
    for dir in startup_folders() {
        w.ordner(&dir);
    }
    w
}

/// Run/RunOnce keys and Startup folders only (cheap, for the real-time monitor).
pub fn enumerate_quick() -> Vec<Entry> {
    let mut out = Vec::new();
    for (hive, hive_name) in [(HKCU, "HKCU"), (HKLM, "HKLM")] {
        for key in RUN_KEYS {
            for (name, cmd) in winreg::string_values(hive, key) {
                out.push(Entry {
                    location: Location::Run { hive: hive_name, key: key.to_string() },
                    target: target_from_command(&cmd),
                    name,
                    command: cmd,
                });
            }
        }
    }
    // Browser helpers: a way for malicious extensions to start programs.
    for h in crate::nativehost::registered_hosts() {
        out.push(Entry {
            target: crate::nativehost::host_program(&h),
            command: h.manifest.display().to_string(),
            name: h.name.clone(),
            location: Location::NativeHost { hive: h.hive, key: h.key.clone(), browser: h.browser },
        });
    }
    for dir in startup_folders() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if !p.is_file() || p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("desktop.ini")) {
                continue;
            }
            let target = if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) { resolve_lnk(&p) } else { Some(p.clone()) };
            out.push(Entry {
                name: e.file_name().to_string_lossy().to_string(),
                command: target.as_ref().map(|t| t.display().to_string()).unwrap_or_default(),
                target,
                location: Location::Startup { file: p },
            });
        }
    }
    out
}

fn enumerate_tasks_and_services(out: &mut Vec<Entry>) {
    if let Ok(svc) = task_service() {
        // SAFETY: COM call on a connected service.
        if let Ok(root) = unsafe { svc.GetFolder(&BSTR::from("\\")) } {
            walk_tasks(&root, out);
        }
    }
    let services = "SYSTEM\\CurrentControlSet\\Services";
    for name in winreg::subkeys(HKLM, services) {
        let path = format!("{services}\\{name}");
        let typ = winreg::read_dword(HKLM, &path, "Type").unwrap_or(0);
        let start = winreg::read_dword(HKLM, &path, "Start").unwrap_or(4);
        if typ & 0x30 == 0 || start > 2 {
            continue; // drivers, manual or disabled services
        }
        let Some(image) = winreg::read_string(HKLM, &path, "ImagePath") else { continue };
        if image.to_ascii_lowercase().contains("svchost.exe") {
            continue; // shared Windows host; the DLLs are system components
        }
        out.push(Entry { location: Location::Service { name: name.clone() }, target: target_from_command(&image), name, command: image });
    }
}

/// Edge's cleanup after its own update: a one-time HKLM RunOnce entry
/// `msedge_cleanup_{GUID}` → `…\Microsoft\Edge\Application\<version>\Installer\setup.exe` with only the
/// known cleanup flags. Pure pattern check (name, place, path, flags); the signature is checked by
/// [`is_browser_update_cleanup`]. Returns the expected signer.
pub fn browser_cleanup_pattern(e: &Entry, program_files: &[&Path]) -> Option<&'static str> {
    let Location::Run { hive, key } = &e.location else { return None };
    if *hive != "HKLM" || !key.to_ascii_lowercase().ends_with("\\runonce") {
        return None;
    }
    let guid = e.name.strip_prefix("msedge_cleanup_{")?.strip_suffix('}')?;
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    let g: Vec<&str> = guid.split('-').collect();
    if !(g.len() == 5 && hex(g[0], 8) && hex(g[1], 4) && hex(g[2], 4) && hex(g[3], 4) && hex(g[4], 12)) {
        return None;
    }
    // Program: exactly setup.exe of an installed Edge version under Program Files.
    let target = e.target.as_ref()?;
    let ok_place = program_files.iter().any(|pf| {
        let rel = target.strip_prefix(pf.join("Microsoft").join("Edge").join("Application")).ok();
        rel.is_some_and(|r| {
            let parts: Vec<String> = r.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect();
            parts.len() == 3
                && !parts[0].is_empty()
                && parts[0].split('.').all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
                && parts[1] == "installer"
                && parts[2] == "setup.exe"
        })
    });
    if !ok_place {
        return None;
    }
    // Flags: only the known cleanup flags, and the cleanup itself must be one of them.
    let args = e.command.trim().strip_prefix('"').and_then(|r| r.split_once('"')).map(|(_, a)| a)?;
    let mut cleanup = false;
    for a in args.split_whitespace() {
        match a {
            "--delete-old-versions" => cleanup = true,
            "--msedge" | "--system-level" | "--verbose-logging" | "--on-logon" => {}
            a if a.strip_prefix("--channel=").is_some_and(|c| matches!(c, "stable" | "beta" | "dev" | "canary")) => {}
            _ => return None,
        }
    }
    cleanup.then_some("Microsoft Corporation")
}

/// The pattern above plus a valid Authenticode signature from exactly that signer:
/// such an entry is logged only, no finding.
pub fn is_browser_update_cleanup(e: &Entry) -> bool {
    let pf: Vec<PathBuf> = ["ProgramFiles(x86)", "ProgramFiles"].iter().filter_map(|v| std::env::var_os(v).map(PathBuf::from)).collect();
    let pf_refs: Vec<&Path> = pf.iter().map(PathBuf::as_path).collect();
    let Some(signer) = browser_cleanup_pattern(e, &pf_refs) else { return false };
    let Some(target) = &e.target else { return false };
    cleanup_signature_ok(signer, is_signed(target), crate::treiber::signer_name(target).as_deref())
}

/// Valid signature from exactly the expected signer.
pub fn cleanup_signature_ok(expected: &str, valid: bool, signer: Option<&str>) -> bool {
    valid && signer == Some(expected)
}

/// Finding for a newly added Run/Startup entry (reported once, with "Deaktivieren").
pub fn new_entry_finding(e: &Entry) -> Finding {
    let mut details = e.details();
    details["hinweis"] = t!("Neuer Autostart-Eintrag. Wenn du dieses Programm nicht selbst installiert hast: „Deaktivieren“.", "New autostart entry. If you did not install this program yourself: “Disable”.").into();
    let signed = e.target.as_ref().is_some_and(|t| is_trusted(t));
    // A task/service that runs cmd, PowerShell, mshta … is the interesting part, not the
    // (signed) Windows program itself.
    let (title, severity) = if starts_script_host(e) {
        (tf!("Neuer Autostart startet ein Skript-Programm: {} ({})", "New autostart starts a script host: {} ({})", e.name, e.command.trim()), Severity::Mittel)
    } else if signed {
        (tf!("Neuer Autostart-Eintrag: {}", "New autostart entry: {}", e.name), Severity::Info)
    } else if e.target.is_none() {
        (tf!("Neuer Autostart-Eintrag: {} (Programm nicht prüfbar)", "New autostart entry: {} (program cannot be checked)", e.name), Severity::Niedrig)
    } else {
        (tf!("Neuer Autostart-Eintrag: {} (Programm nicht signiert)", "New autostart entry: {} (program not signed)", e.name), Severity::Niedrig)
    };
    Finding {
        path: PathBuf::from(e.describe()),
        sha256: crate::sha256_hex(format!("autostart-neu|{}|{}", e.identity(), e.command).as_bytes()),
        size: 0,
        rule_id: "AUTOSTART:NEU".into(),
        threat_name: title,
        category: t!("Neuer Autostart", "New autostart").into(),
        severity,
        engine: "echtzeit".into(),
        kind: Kind::Autostart,
        details: Some(details),
    }
}

/// Evaluates entries: engine hits on the target, or unsigned target in a
/// user-writable folder. `scanner` runs all file engines.
pub fn findings(entries: &[Entry], scanner: &Scanner) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let Some(target) = e.target.as_ref().filter(|t| t.is_file()) else { continue };
        if is_store_app_alias(target) {
            continue; // 0-byte App Execution Alias of a signed Store app
        }
        let mut details = e.details();
        let hits = scanner.scan_file(target).ok().flatten().map(|(f, _)| f).unwrap_or_default();
        if let Some(hit) = hits.into_iter().max_by_key(|f| f.severity) {
            details["erkennung"] = hit.threat_name.clone().into();
            out.push(Finding {
                path: PathBuf::from(e.describe()),
                sha256: hit.sha256.clone(),
                size: hit.size,
                rule_id: hit.rule_id.clone(),
                threat_name: tf!("Autostart startet Schadsoftware: {}", "Autostart starts malware: {}", hit.threat_name),
                category: hit.category.clone(),
                severity: hit.severity.max(Severity::Hoch),
                engine: hit.engine.clone(),
                kind: Kind::Autostart,
                details: Some(details),
            });
            continue;
        }
        if !is_user_writable(target) {
            continue;
        }
        let mut sig = signature(target);
        if sig == Signature::NotCheckable {
            // Often a file still being written or removed by an installer: look once more.
            std::thread::sleep(std::time::Duration::from_secs(3));
            sig = signature(target);
        }
        let (rule, title, severity, signed) = match sig {
            Signature::Signed => continue,
            Signature::Unsigned => (
                "AUTOSTART:UNSIGNIERT-BENUTZERORDNER",
                t!("Unsigniertes Programm startet automatisch aus einem für Benutzer beschreibbaren Ordner", "Unsigned program starts automatically from a folder users can write to"),
                Severity::Mittel,
                serde_json::Value::from(false),
            ),
            Signature::NotCheckable => (
                "AUTOSTART:SIGNATUR-UNPRUEFBAR",
                t!("Autostart aus einem für Benutzer beschreibbaren Ordner – Signatur nicht prüfbar (Datei gesperrt oder fehlt)", "Autostart from a folder users can write to – signature cannot be checked (file locked or missing)"),
                Severity::Niedrig,
                serde_json::Value::from(t!("nicht prüfbar", "cannot be checked")),
            ),
        };
        details["signiert"] = signed;
        out.push(Finding {
            path: PathBuf::from(e.describe()),
            sha256: crate::sha256_hex(format!("autostart|{}|{}", e.identity(), target.display()).as_bytes()),
            size: 0,
            rule_id: rule.into(),
            threat_name: format!("{title}: {}", target.display()),
            category: t!("Verdächtiger Autostart", "Suspicious autostart").into(),
            severity,
            engine: "autostart".into(),
            kind: Kind::Autostart,
            details: Some(details),
        });
    }
    out
}

/// For an open autostart finding: is the registration gone (Run value, startup file,
/// service, browser helper key)? None for kinds that are not checked (scheduled tasks).
/// HKCU entries need the user's context (impersonation in the service).
pub fn registration_gone(details: &serde_json::Value) -> Option<bool> {
    let s = |k: &str| details[k].as_str().unwrap_or("");
    match s("art") {
        "run" if !s("schluessel").is_empty() => {
            let hive = winreg::hive_from_name(s("hive"));
            Some(!winreg::value_exists(hive, s("schluessel"), s("name")))
        }
        "startordner" if !s("datei").is_empty() => Some(!Path::new(s("datei")).exists()),
        "dienst" if !s("dienst").is_empty() => Some(!winreg::key_exists(winreg::HKLM, &format!("SYSTEM\\CurrentControlSet\\Services\\{}", s("dienst")))),
        "browserhelfer" if !s("schluessel").is_empty() => Some(!winreg::key_exists(winreg::hive_from_name(s("hive")), s("schluessel"))),
        _ => None,
    }
}

/// A scheduled task or service that starts a script host (cmd, PowerShell, mshta, …):
/// a common way to persist, reported like a new Run entry. The program comes from
/// the resolved target or, for bare names like "cmd.exe /c …", from the command.
pub fn starts_script_host(e: &Entry) -> bool {
    const HOSTS: [&str; 8] = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"];
    if !matches!(e.location, Location::Task { .. } | Location::Service { .. }) {
        return false;
    }
    let first = e.command.trim_start();
    let program = if let Some(rest) = first.strip_prefix('"') { rest.split('"').next().unwrap_or("") } else { first.split_whitespace().next().unwrap_or("") };
    let from_command = Path::new(program).file_name().map(|n| n.to_string_lossy().to_ascii_lowercase());
    let from_target = e.target.as_ref().and_then(|t| t.file_name()).map(|n| n.to_string_lossy().to_ascii_lowercase());
    [from_target, from_command].into_iter().flatten().any(|n| {
        let n = if n.contains('.') { n } else { format!("{n}.exe") };
        HOSTS.contains(&n.as_str())
    })
}

pub fn target_of(det: &Detection) -> Option<PathBuf> {
    det.details.as_ref()?["ziel"].as_str().map(PathBuf::from)
}

/// Explorer's switch list for Run entries (the same one Task Manager uses): a value with the
/// entry's name, first byte 2 = on, 3 = off. Covers Run and the 32-bit Run, not RunOnce.
pub const APPROVED_RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
pub const APPROVED_RUN32: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";

/// The switch list for a Run key, if Windows has one for it.
pub fn startup_approved_key(run_key: &str) -> Option<&'static str> {
    match run_key.to_ascii_lowercase().replace('/', "\\").trim_matches('\\') {
        r"software\microsoft\windows\currentversion\run" => Some(APPROVED_RUN),
        r"software\wow6432node\microsoft\windows\currentversion\run" => Some(APPROVED_RUN32),
        _ => None,
    }
}

/// A Run/RunOnce key K9 reports on – the only keys it may change (with the service's rights for HKLM).
pub fn is_run_location(key: &str) -> bool {
    let k = key.to_ascii_lowercase().replace('/', "\\");
    let k = k.trim_matches('\\');
    let k = k.strip_prefix(r"software\wow6432node\").map(|r| format!(r"software\{r}")).unwrap_or_else(|| k.to_string());
    matches!(
        k.as_str(),
        r"software\microsoft\windows\currentversion\run"
            | r"software\microsoft\windows\currentversion\runonce"
            | r"software\microsoft\windows\currentversion\policies\explorer\run"
    )
        // unit tests use their own key, never the real Run keys
        || (cfg!(test) && k.starts_with(r"software\k9-test"))
}

/// The 12-byte switch value: on = 02 00…, off = 03 00 00 00 + the time (FILETIME) as Task Manager writes it.
pub fn approved_value(enabled: bool, filetime: u64) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[0] = if enabled { 2 } else { 3 };
    if !enabled {
        v[4..].copy_from_slice(&filetime.to_le_bytes());
    }
    v
}

/// Is the entry switched off in the list (odd first byte)?
pub fn approved_off(v: &[u8]) -> bool {
    v.first().is_some_and(|b| b & 1 == 1)
}

fn filetime_now() -> u64 {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() / 100).unwrap_or(0) as u64;
    unix + 116_444_736_000_000_000
}

/// Runs a registry change: HKLM with the service's own rights (users may only read there),
/// HKCU as the user. Only for keys K9 reports on.
fn with_rights<R>(hive: windows::Win32::System::Registry::HKEY, f: impl FnOnce() -> Result<R>) -> Result<R> {
    if hive == HKLM {
        crate::schutz::as_system(f)
    } else {
        f()
    }
}

/// Switches a Run entry off/on in the switch list `approved` (creates the list if missing).
pub fn set_startup_approved(hive: windows::Win32::System::Registry::HKEY, approved: &str, name: &str, enabled: bool) -> Result<()> {
    with_rights(hive, || {
        winreg::create_key(hive, approved)?;
        winreg::set_binary(hive, approved, name, &approved_value(enabled, filetime_now()))
    })
}

/// Disables the autostart entry of a detection (reversible).
pub fn disable(store: &Store, det: &Detection) -> Result<()> {
    crate::schutz::ensure_user_context()?;
    let d = det.details.clone().context("Autostart-Details fehlen")?;
    let art = d["art"].as_str().unwrap_or("");
    let mut backup = d.clone();
    match art {
        "run" => {
            let hive = winreg::hive_from_name(d["hive"].as_str().unwrap_or("HKCU"));
            let key = d["schluessel"].as_str().context("Schlüssel fehlt")?;
            let name = d["name"].as_str().context("Name fehlt")?;
            let data = winreg::read_string(hive, key, name).context("Autostart-Eintrag existiert nicht mehr")?;
            backup["daten"] = data.into();
            if !is_run_location(key) {
                bail!("Unerwarteter Autostart-Schlüssel {key} – nichts geändert");
            }
            match startup_approved_key(key) {
                // Like Task Manager: the entry stays, Windows just does not start it any more.
                Some(approved) => {
                    set_startup_approved(hive, approved, name, false)?;
                    backup["methode"] = "startupapproved".into();
                    backup["liste"] = approved.into();
                }
                // RunOnce/policy entries have no switch: the value is removed (saved for "Wieder einschalten").
                None => with_rights(hive, || winreg::delete_value(hive, key, name))?,
            }
        }
        "startordner" => {
            let file = PathBuf::from(d["datei"].as_str().context("Datei fehlt")?);
            let sha = crate::scanner::sha256_file(&file).context("Datei im Autostart-Ordner fehlt")?;
            let qdir = crate::paths::AppPaths::resolve()?.quarantine_dir();
            let qid = crate::quarantine::quarantine_file(store, &qdir, &file, &sha, &det.threat_name, Some(det.id))?;
            backup["quarantaene_id"] = qid.into();
        }
        "aufgabe" => {
            let path = d["aufgabe"].as_str().context("Aufgabe fehlt")?;
            set_task_enabled(path, false)?;
        }
        "browserhelfer" => {
            // Removing the manifest path switches the helper off; the key stays for "Wieder einschalten".
            let hive = winreg::hive_from_name(d["hive"].as_str().unwrap_or("HKCU"));
            let key = d["schluessel"].as_str().context("Schlüssel fehlt")?;
            let data = winreg::read_string(hive, key, "").context("Registrierung existiert nicht mehr")?;
            backup["daten"] = data.into();
            winreg::delete_value(hive, key, "")?;
        }
        "dienst" => {
            if !crate::paths::is_elevated() {
                bail!("Dienste können nur mit Administratorrechten deaktiviert werden (k9 als Administrator starten)");
            }
            let name = d["dienst"].as_str().context("Dienst fehlt")?;
            let key = format!("SYSTEM\\CurrentControlSet\\Services\\{name}");
            backup["start"] = winreg::read_dword(HKLM, &key, "Start").unwrap_or(2).into();
            winreg::set_dword(HKLM, &key, "Start", 4)?;
        }
        other => bail!("Unbekannte Autostart-Art '{other}'"),
    }
    store.insert_disabled(det.id, &det.path, &backup)?;
    Ok(())
}

/// Re-enables a disabled autostart entry.
pub fn restore(store: &Store, id: i64) -> Result<String> {
    if store.is_remote() {
        return crate::dienst::request_reenable(id);
    }
    let (det_id, label, d) = store.disabled_entry(id)?.context("Eintrag nicht gefunden oder bereits reaktiviert")?;
    match d["art"].as_str().unwrap_or("") {
        "run" => {
            let hive = winreg::hive_from_name(d["hive"].as_str().unwrap_or("HKCU"));
            let key = d["schluessel"].as_str().context("Schlüssel fehlt")?;
            let name = d["name"].as_str().context("Name fehlt")?;
            if !is_run_location(key) {
                bail!("Unerwarteter Autostart-Schlüssel {key} – nichts geändert");
            }
            if d["methode"].as_str() == Some("startupapproved") {
                let approved = startup_approved_key(key).context("Schalterliste unbekannt")?;
                set_startup_approved(hive, approved, name, true)?;
            } else {
                let data = d["daten"].as_str().context("Gesicherter Befehl fehlt")?.to_string();
                with_rights(hive, || winreg::set_string(hive, key, name, &data))?;
            }
        }
        "startordner" => {
            let qid = d["quarantaene_id"].as_i64().context("Quarantäne-Verweis fehlt")?;
            // Via the pipeline: with the service the quarantine is only readable by it.
            crate::pipeline::restore_from_quarantine(store, qid, None, false)?;
        }
        "treiber" => {
            // Only the service (SYSTEM) may change driver start values.
            if !crate::schutz::in_service() {
                bail!("Treiber schaltet nur der Windows-Dienst wieder ein");
            }
            let key = format!("SYSTEM\\CurrentControlSet\\Services\\{}", d["dienst"].as_str().context("Dienst fehlt")?);
            let start = d["start"].as_u64().unwrap_or(3).min(3) as u32;
            crate::schutz::as_system(|| winreg::set_dword(HKLM, &key, "Start", start))?;
        }
        "browserhelfer" => {
            let hive = winreg::hive_from_name(d["hive"].as_str().unwrap_or("HKCU"));
            winreg::set_string(
                hive,
                d["schluessel"].as_str().context("Schlüssel fehlt")?,
                "",
                d["daten"].as_str().context("Gesicherter Manifest-Pfad fehlt")?,
            )?;
        }
        "aufgabe" => set_task_enabled(d["aufgabe"].as_str().context("Aufgabe fehlt")?, true)?,
        "dienst" => {
            if !crate::paths::is_elevated() {
                bail!("Dienste können nur mit Administratorrechten reaktiviert werden");
            }
            let key = format!("SYSTEM\\CurrentControlSet\\Services\\{}", d["dienst"].as_str().context("Dienst fehlt")?);
            winreg::set_dword(HKLM, &key, "Start", d["start"].as_u64().unwrap_or(2) as u32)?;
        }
        other => bail!("Unbekannte Autostart-Art '{other}'"),
    }
    store.mark_reenabled(id)?;
    // Without revoking, the remembered "Deaktivieren" would apply again on the next check.
    if let Some(det) = store.detection(det_id)? {
        store.revoke_decision_by_fingerprint(&det.sha256, &det.rule_id)?;
    }
    Ok(label)
}

fn set_task_enabled(path: &str, enabled: bool) -> Result<()> {
    let svc = task_service()?;
    // SAFETY: COM calls on a connected service.
    unsafe {
        let root = svc.GetFolder(&BSTR::from("\\"))?;
        let task: IRegisteredTask = root.GetTask(&BSTR::from(path)).with_context(|| format!("Aufgabe {path} nicht gefunden"))?;
        task.SetEnabled(enabled.into()).with_context(|| format!("Aufgabe {path} kann nicht geändert werden (Administratorrechte nötig?)"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_entries_are_switched_off_like_task_manager_does() {
        assert_eq!(startup_approved_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"), Some(APPROVED_RUN));
        assert_eq!(startup_approved_key(r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"), Some(APPROVED_RUN32));
        assert_eq!(startup_approved_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"), None, "RunOnce hat keine Schalterliste");
        assert!(is_run_location(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        assert!(is_run_location(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"));
        assert!(!is_run_location(r"SYSTEM\CurrentControlSet\Services\x"), "nie andere Schlüssel mit Dienstrechten");
        assert!(!is_run_location(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\..\..\Policies"));
        let off = approved_value(false, 0x0102030405060708);
        assert_eq!(off[0], 3);
        assert_eq!(&off[4..], &0x0102030405060708u64.to_le_bytes());
        assert!(approved_off(&off) && !approved_off(&approved_value(true, 1)) && !approved_off(&[]));
        // writing the switch, in our own test key only (never the real StartupApproved list)
        let base = format!(r"Software\K9-Test-{}-approved", std::process::id());
        let list = format!(r"{base}\StartupApproved\Run");
        set_startup_approved(HKCU, &list, "Probe", false).unwrap();
        assert!(approved_off(&winreg::read_binary(HKCU, &list, "Probe").unwrap()));
        set_startup_approved(HKCU, &list, "Probe", true).unwrap();
        assert!(!approved_off(&winreg::read_binary(HKCU, &list, "Probe").unwrap()));
        winreg::delete_tree(HKCU, &base).unwrap();
    }

    #[test]
    fn command_parsing() {
        assert_eq!(target_from_command("\"C:\\Program Files\\App\\app.exe\" --min"), Some(PathBuf::from("C:\\Program Files\\App\\app.exe")));
        assert_eq!(target_from_command("C:\\Tools\\x.exe /s"), Some(PathBuf::from("C:\\Tools\\x.exe")));
        assert_eq!(target_from_command("ctfmon.exe"), None);
        assert_eq!(
            target_from_command("rundll32.exe C:\\Users\\a\\AppData\\boese.dll,Start"),
            Some(PathBuf::from("C:\\Users\\a\\AppData\\boese.dll"))
        );
        assert_eq!(
            target_from_command("wscript.exe \"C:\\Users\\a\\x.vbs\""),
            Some(PathBuf::from("C:\\Users\\a\\x.vbs"))
        );
        std::env::set_var("VS_AUTOSTART_TEST", "C:\\Daten");
        assert_eq!(target_from_command("%VS_AUTOSTART_TEST%\\y.exe"), Some(PathBuf::from("C:\\Daten\\y.exe")));
    }

    #[test]
    fn user_writable_detection() {
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(is_user_writable(&Path::new(&profile).join("AppData\\Local\\x.exe")));
        assert!(!is_user_writable(Path::new("C:\\Windows\\System32\\notepad.exe")));
    }

    #[test]
    fn signature_check() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        // explorer.exe carries an embedded Microsoft signature.
        assert!(is_signed(&Path::new(&windir).join("explorer.exe")));
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let f = dir.path().join("x.exe");
        std::fs::write(&f, b"MZ nicht signiert").unwrap();
        assert!(!is_signed(&f));
    }

    #[test]
    fn signature_states() {
        assert_eq!(classify_trust_result(0), Signature::Signed);
        assert_eq!(classify_trust_result(0x800B_0100_u32 as i32), Signature::Unsigned, "TRUST_E_NOSIGNATURE");
        assert_eq!(classify_trust_result(0x8009_6010_u32 as i32), Signature::Unsigned, "TRUST_E_BAD_DIGEST");
        assert_eq!(classify_trust_result(0x8007_0020_u32 as i32), Signature::NotCheckable, "Freigabeverletzung");
        assert_eq!(classify_trust_result(0x8007_0002_u32 as i32), Signature::NotCheckable, "Datei fehlt");
        assert_eq!(classify_trust_result(0x8009_2003_u32 as i32), Signature::NotCheckable, "CRYPT_E_FILE_ERROR");
        assert_eq!(signature(Path::new(r"C:\gibt\es\nicht.exe")), Signature::NotCheckable);
    }

    #[test]
    fn programdata_uses_real_permissions() {
        use crate::schutz::{non_admin_can, CHANGE_RIGHTS, REPLACE_CHILD_RIGHTS};
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        assert_eq!(non_admin_can(Path::new(&windir), REPLACE_CHILD_RIGHTS), Some(false));
        // Created by the user: the owner may change it.
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        assert_eq!(non_admin_can(dir.path(), CHANGE_RIGHTS), Some(true));
        assert_eq!(non_admin_can(&dir.path().join("fehlt"), CHANGE_RIGHTS), None);
        // %ProgramData% itself: users may create files there, but not replace other folders.
        let pd = std::env::var("ProgramData").unwrap();
        assert_eq!(non_admin_can(Path::new(&pd), CHANGE_RIGHTS), Some(true));
        assert_eq!(non_admin_can(Path::new(&pd), REPLACE_CHILD_RIGHTS), Some(false));
        // An admin-only folder below %ProgramData% (Windows default: users may only read).
        let prot = Path::new(&pd).join("Microsoft");
        if prot.is_dir() && non_admin_can(&prot, CHANGE_RIGHTS) == Some(false) {
            assert!(!is_user_writable(&prot.join("x.exe")), "nur Administratoren");
        }
    }

    #[test]
    fn tasks_starting_script_hosts_are_suspicious() {
        let task = |cmd: &str| Entry { location: Location::Task { path: r"\T".into() }, name: "T".into(), command: cmd.into(), target: None };
        assert!(starts_script_host(&task("cmd.exe /c calc.exe")), "Atomic Red Team T1053.005");
        let f = new_entry_finding(&task("cmd.exe /c calc.exe"));
        let _ = &f;
        {
            let pf = [Path::new(r"C:\Program Files (x86)"), Path::new(r"C:\Program Files")];
            let edge = |hive: &'static str, name: &str, exe: &str, args: &str| Entry {
                location: Location::Run { hive, key: r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce".into() },
                name: name.into(),
                command: format!("\"{exe}\" {args}"),
                target: Some(PathBuf::from(exe)),
            };
            let name = "msedge_cleanup_{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}";
            let exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.60\Installer\setup.exe";
            let args = "--msedge --channel=stable --delete-old-versions --system-level --verbose-logging --on-logon";
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, exe, args), &pf), Some("Microsoft Corporation"));
            // signature: valid and exactly Microsoft Corporation
            assert!(cleanup_signature_ok("Microsoft Corporation", true, Some("Microsoft Corporation")));
            assert!(!cleanup_signature_ok("Microsoft Corporation", true, Some("Microsoft Corporation Fake")), "falscher Signierer");
            assert!(!cleanup_signature_ok("Microsoft Corporation", false, Some("Microsoft Corporation")), "unsigniert/ungueltig");
            assert!(!cleanup_signature_ok("Microsoft Corporation", true, None));
            // user-writable path (or anywhere else than the Edge program folder)
            let user = r"C:\Users\f\AppData\Local\Temp\Microsoft\Edge\Application\157.0.4341.60\Installer\setup.exe";
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, user, args), &pf), None);
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, r"C:\Program Files (x86)\Microsoft\Edge\Application\x\Installer\setup.exe", args), &pf), None);
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, r"C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.60\Installer\evil.exe", args), &pf), None);
            // extra flag
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, exe, &format!("{args} --run-as-admin")), &pf), None);
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", name, exe, "--msedge --on-logon"), &pf), None, "ohne --delete-old-versions");
            // wrong value name, wrong hive
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", "msedge_cleanup_{nicht-guid}", exe, args), &pf), None);
            assert_eq!(browser_cleanup_pattern(&edge("HKLM", "edge_cleanup_{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", exe, args), &pf), None);
            assert_eq!(browser_cleanup_pattern(&edge("HKCU", name, exe, args), &pf), None);
        }
        assert_eq!(f.severity, Severity::Mittel);
        assert!(f.threat_name.contains("Skript-Programm") && !f.threat_name.contains("nicht signiert"));
        assert!(starts_script_host(&task("powershell -w hidden -c x")));
        assert!(starts_script_host(&task(r#""C:\Windows\System32\mshta.exe" vbscript:x"#)));
        assert!(!starts_script_host(&task(r#""C:\Program Files\App\update.exe" /check"#)));
        let run = Entry { location: Location::Run { hive: "HKCU", key: "x".into() }, name: "x".into(), command: "cmd.exe /c x".into(), target: None };
        assert!(!starts_script_host(&run), "Run-Einträge werden ohnehin immer gemeldet");
    }

    #[test]
    fn removed_registrations_are_recognised() {
        let run = serde_json::json!({ "art": "run", "hive": "HKCU", "schluessel": "Software\\K9-Test\\GibtEsNicht", "name": "x" });
        assert_eq!(registration_gone(&run), Some(true));
        let run_present = serde_json::json!({ "art": "run", "hive": "HKLM", "schluessel": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "name": "ProductName" });
        assert_eq!(registration_gone(&run_present), Some(false));
        assert_eq!(registration_gone(&serde_json::json!({ "art": "dienst", "dienst": "Winmgmt" })), Some(false));
        assert_eq!(registration_gone(&serde_json::json!({ "art": "dienst", "dienst": "Gibt-Es-Nicht-K9" })), Some(true));
        assert_eq!(registration_gone(&serde_json::json!({ "art": "startordner", "datei": "C:\\gibt\\es\\nicht.lnk" })), Some(true));
        assert_eq!(registration_gone(&serde_json::json!({ "art": "aufgabe", "aufgabe": "\\x" })), None, "Aufgaben werden nicht geprüft");
    }

    #[test]
    fn unsigned_user_autostart_is_flagged_and_run_key_disable_restore() {
        // A user folder the agent does not watch (never %TEMP%: a running agent would react).
        let dir = tempfile::tempdir_in(crate::test_user_tmp()).unwrap();
        let exe = dir.path().join("autostart-probe.exe");
        std::fs::write(&exe, b"MZ harmlose Testdatei").unwrap();
        // own key per test run (other tests use Software\K9-Test in parallel)
        let base = format!("Software\\K9-Test-{}-run", std::process::id());
        let key = &format!("{base}\\Run");
        let w: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut k = windows::Win32::System::Registry::HKEY::default();
            let _ = windows::Win32::System::Registry::RegCreateKeyW(HKCU, PCWSTR(w.as_ptr()), &mut k);
            let _ = windows::Win32::System::Registry::RegCloseKey(k);
        }
        let cmd = format!("\"{}\" /hidden", exe.display());
        winreg::set_string(HKCU, key, "Probe", &cmd).unwrap();
        let entry = Entry {
            location: Location::Run { hive: "HKCU", key: key.into() },
            name: "Probe".into(),
            target: target_from_command(&cmd),
            command: cmd.clone(),
        };
        let scanner = Scanner::new(vec![], 0, vec![]);
        let f = findings(std::slice::from_ref(&entry), &scanner);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "AUTOSTART:UNSIGNIERT-BENUTZERORDNER");

        let store = Store::open_in_memory().unwrap();
        let crate::store::Upsert::New(det) = store.upsert_pending(&f[0]).unwrap() else { panic!() };
        disable(&store, &det).unwrap();
        assert!(winreg::read_string(HKCU, key, "Probe").is_none());
        let list = store.list_disabled().unwrap();
        assert_eq!(list.len(), 1);
        restore(&store, list[0].0).unwrap();
        assert_eq!(winreg::read_string(HKCU, key, "Probe").as_deref(), Some(cmd.as_str()));
        assert!(store.list_disabled().unwrap().is_empty());

        winreg::delete_value(HKCU, key, "Probe").unwrap();
        winreg::delete_tree(HKCU, &base).unwrap();
    }

    #[test]
    fn enumerate_runs() {
        // Real system data: must not crash; every task/run entry has a name.
        let e = enumerate();
        assert!(e.iter().all(|x| !x.describe().is_empty()));
    }
}
