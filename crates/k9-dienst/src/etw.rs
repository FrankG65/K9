//! ETW real-time session: process starts, DNS queries (Microsoft-Windows-DNS-Client)
//! and file opens of stored logins (Microsoft-Windows-Kernel-File, infostealer
//! protection). Needs LocalSystem/admin.
//!
//! Process starts come from the kernel's system process provider: its start
//! event carries the command line itself, so even a process that ends after a
//! few milliseconds is checked. Fallback: Microsoft-Windows-Kernel-Process
//! (no command line in the event; read from the process while it runs).
//!
//! The callback only copies the few needed values into a channel; all checks
//! run in a worker thread with below-normal priority.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use k9_core::realtime as rt;
use k9_core::urls::NetDb;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, SystemProcessProviderGuid,
    TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    PROPERTY_DATA_DESCRIPTOR, SYSTEM_PROCESS_KW_GENERAL, WNODE_FLAG_TRACED_GUID,
};

use crate::Svc;

const SESSION: &str = "K9-Dienst-ETW";
const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
/// WINEVENT_KEYWORD_PROCESS
const KW_PROCESS: u64 = 0x10;
const EV_PROCESS_START: u16 = 1;
/// Classic kernel "Process" event class (events of the system process provider).
const KERNEL_PROCESS_CLASS: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const OPCODE_START: u8 = 1;
const OPCODE_END: u8 = 2;
/// Two start events of one process (classic and Kernel-Process) lie closer than this (1 s).
const SAME_START: i64 = 10_000_000;
const EV_PROCESS_STOP: u16 = 2;
const EV_DNS_QUERY: u16 = 3008;
/// Microsoft-Windows-PowerShell, event 4104 (script block, plain text before running).
const POWERSHELL: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);
const EV_SCRIPT_BLOCK: u16 = 4104;
const KERNEL_FILE: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// KERNEL_FILE_KEYWORD_CREATE (file opens)
const KW_FILE_CREATE: u64 = 0x80;
const EV_FILE_CREATE: u16 = 12;
/// Parts of the paths of stored logins (lower case): only these file opens are passed on.
/// Compared in the callback regardless of upper/lower case. A filter in the kernel is not
/// used: in the sandbox it compared case-sensitively ("user data" got through).
const FILE_NEEDLES: [&str; 12] = [
    "\\user data\\", "\\opera software\\", "\\profiles\\", "\\steam\\", "\\discord", "\\tdata\\", "wallet",
    "\\local extension settings\\", "\\ethereum\\", "\\exodus\\", "\\electrum\\", "\\atomic\\",
];

/// File-open events seen in the callback / passed on (for the 10-minute statistics).
static FILE_SEEN: AtomicU64 = AtomicU64::new(0);
static FILE_PASSED: AtomicU64 = AtomicU64::new(0);
/// Process starts come from the classic kernel provider (with command line); the
/// Kernel-Process provider then only adds the full image path.
static CLASSIC_STARTS: AtomicBool = AtomicBool::new(false);

/// `ts`: ETW time stamp (FILETIME, 100 ns since 1601).
enum Ev {
    Process { pid: u32, ppid: u32, image: String, cmd: Option<String>, ts: i64 },
    Stop { pid: u32, ts: i64 },
    /// Full image path of a start (Kernel-Process), NT path.
    Image { pid: u32, ts: i64, image: String },
    Dns { pid: u32, name: String, ts: i64 },
    /// One part of a PowerShell script block.
    Script { pid: u32, ts: i64, id: String, number: usize, total: usize, text: String, path: String },
    File { pid: u32, name: String, ts: i64 },
    /// The same after waiting for the start event of its process.
    FileAgain { pid: u32, name: String, ts: i64 },
    /// K9 itself was attacked: the agent was ended from outside, or a stop of the service was
    /// asked for (from the agent watch / the service control handler, not an ETW event).
    Attacked { ts: i64, step: k9_core::ketten::Step },
}

static SENDER: OnceLock<Sender<Ev>> = OnceLock::new();

/// Called by the agent watch the moment the agent was ended from outside: the event loop
/// then treats it as a step of every attack chain that is still running.
pub fn agent_ended() {
    if let Some(tx) = SENDER.get() {
        let _ = tx.send(Ev::Attacked { ts: filetime_now(), step: k9_core::ketten::Step::AgentBeendet });
    }
}

/// Called when something asked Windows to stop the service without the announcement of `k9`.
pub fn stop_attempt() {
    if let Some(tx) = SENDER.get() {
        let _ = tx.send(Ev::Attacked { ts: filetime_now(), step: k9_core::ketten::Step::DienstStopp });
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// EVENT_TRACE_PROPERTIES followed by room for the session name.
fn properties(system: bool) -> Vec<u64> {
    let base = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = base + 1024;
    let mut buf = vec![0u64; total.div_ceil(8)];
    // SAFETY: buffer is large enough and 8-byte aligned.
    let p = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    p.Wnode.BufferSize = total as u32;
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.Wnode.ClientContext = 1; // QPC timestamps
    p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | if system { EVENT_TRACE_SYSTEM_LOGGER_MODE } else { 0 };
    p.FlushTimer = 1; // deliver events within a second
    p.BufferSize = 64; // KB
    p.MinimumBuffers = 4;
    p.MaximumBuffers = 32;
    p.LoggerNameOffset = base as u32;
    buf
}

/// Stops our session (also a leftover one after a crash).
pub fn stop() {
    let mut props = properties(true);
    let name = wide(SESSION);
    // SAFETY: valid properties buffer and session name.
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Delivers the events still waiting in the buffers of our session now (normally they come
/// within a second). The ransomware detection asks for it when files suddenly look encrypted:
/// it needs the opens of exactly these files to name the program.
pub fn flush() {
    let mut props = properties(true);
    let name = wide(SESSION);
    // SAFETY: valid properties buffer and session name.
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_FLUSH,
        );
    }
}

fn start_session(system: bool) -> anyhow::Result<CONTROLTRACE_HANDLE> {
    let name = wide(SESSION);
    let mut handle = CONTROLTRACE_HANDLE::default();
    for attempt in 0..2 {
        let mut props = properties(system);
        // SAFETY: valid buffer and name.
        let r = unsafe { StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        if r == ERROR_SUCCESS {
            return Ok(handle);
        }
        if r == ERROR_ALREADY_EXISTS && attempt == 0 {
            stop();
            continue;
        }
        anyhow::bail!("ETW-Sitzung kann nicht gestartet werden ({r:?}) – Administratorrechte nötig");
    }
    anyhow::bail!("ETW-Sitzung kann nicht gestartet werden")
}

fn enable(h: CONTROLTRACE_HANDLE, provider: &GUID, keywords: u64) -> bool {
    // SAFETY: valid session handle and provider GUID.
    let r = unsafe { EnableTraceEx2(h, provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, 4, keywords, 0, 0, None) };
    r == ERROR_SUCCESS
}

/// Event-ID filter (EVENT_FILTER_EVENT_ID): FilterIn, reserved, count, IDs.
fn event_id_filter(ids: &[u16]) -> Vec<u8> {
    let mut b = vec![1u8, 0];
    b.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        b.extend_from_slice(&id.to_le_bytes());
    }
    b
}

/// PowerShell: script blocks are logged at "verbose" when the policy is on (all scripts)
/// and at "warning" when PowerShell itself finds them suspicious – so level 5, but only
/// event 4104 (filter in the kernel), else the other verbose PowerShell events would come too.
fn enable_powershell(h: CONTROLTRACE_HANDLE) -> bool {
    use windows::Win32::System::Diagnostics::Etw::{ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_FILTER_DESCRIPTOR};
    const EVENT_FILTER_TYPE_EVENT_ID: u32 = 0x8000_0200;
    let data = event_id_filter(&[EV_SCRIPT_BLOCK]);
    let mut fd = EVENT_FILTER_DESCRIPTOR { Ptr: data.as_ptr() as u64, Size: data.len() as u32, Type: EVENT_FILTER_TYPE_EVENT_ID };
    let params = ENABLE_TRACE_PARAMETERS { Version: ENABLE_TRACE_PARAMETERS_VERSION_2, EnableFilterDesc: &mut fd, FilterDescCount: 1, ..Default::default() };
    // SAFETY: valid session handle, provider GUID and filter data that outlive the call.
    let filtered = unsafe { EnableTraceEx2(h, &POWERSHELL, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, 5, 0, 0, 0, Some(&params)) } == ERROR_SUCCESS;
    if filtered {
        return true;
    }
    // SAFETY: as above, without filter (the callback ignores other events).
    unsafe { EnableTraceEx2(h, &POWERSHELL, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, 5, 0, 0, 0, None) == ERROR_SUCCESS }
}

pub fn run(svc: Arc<Svc>) {
    let (tx, rx) = mpsc::channel();
    let _ = SENDER.set(tx);
    let worker = svc.clone();
    crate::spawn("vs-etw-pruefung", move || check_events(worker, rx));
    let mut wait = 10;
    while !svc.is_stopping() {
        // System logger session first (process events with command line).
        let session = start_session(true).map(|h| (h, true)).or_else(|_| start_session(false).map(|h| (h, false)));
        match session {
            Ok((h, system)) => {
                let with_cmd = system && enable(h, &SystemProcessProviderGuid, SYSTEM_PROCESS_KW_GENERAL);
                // Kernel-Process as well: the full image path of every start, from the kernel
                // (the classic event has only the file name; the command line can be forged).
                let image = enable(h, &KERNEL_PROCESS, KW_PROCESS);
                CLASSIC_STARTS.store(with_cmd, Ordering::Relaxed);
                let p = with_cmd || image;
                tracing::info!("Prozessstarts über {}", if with_cmd { "Kernel-Systemanbieter (mit Befehlszeile)" } else { "Kernel-Process (Befehlszeile nachträglich)" });
                let d = enable(h, &DNS_CLIENT, 0);
                if svc.app.config.echtzeit.powershell_skripte {
                    let on = enable_powershell(h);
                    tracing::info!("PowerShell-Skriptprüfung: {}", if on { "aktiv" } else { "nicht verfügbar" });
                }
                if svc.app.config.echtzeit.infostealer {
                    let on = enable(h, &KERNEL_FILE, KW_FILE_CREATE);
                    tracing::info!(
                        "Schutz vor Datendieben: {}",
                        if on { "aktiv (alle Dateiöffnungen, Auswahl im Dienst ohne Rücksicht auf Groß-/Kleinschreibung)" } else { "nicht verfügbar" }
                    );
                }
                svc.etw_processes.store(p, Ordering::Relaxed);
                svc.etw_dns.store(d, Ordering::Relaxed);
                tracing::info!("ETW aktiv: Prozessstarts {}, DNS-Abfragen {}", yes(p), yes(d));
                consume();
                if !svc.is_stopping() {
                    // The session was stopped from outside (e.g. "logman stop"): protection was blind.
                    tracing::warn!("Selbstschutz: ETW-Sitzung von außen beendet – wird neu gestartet");
                    svc.report(&crate::selbstschutz::alarm(
                        "SELBSTSCHUTZ:ETW-GESTOPPT",
                        k9_core::t!("Die Überwachung des Dienstes wurde von außen gestoppt", "The monitoring of the service was stopped from outside"),
                        k9_core::t!("Die Windows-Ereignisverfolgung von K9 (Programmstarts, DNS, Zugangsdaten, Skripte) wurde beendet, ohne dass der Dienst                          gestoppt wurde. Der Dienst hat sie neu gestartet. Hast du das nicht selbst getan, könnte ein Programm versucht haben,                          die Überwachung abzuschalten – vollständigen Scan starten.", "The Windows event tracing of K9 (program starts, DNS, sign-in data, scripts) was ended without the service \
                         being stopped. The service has started it again. If you did not do this yourself, a program might have tried \
                         to switch off the monitoring – start a full scan."),
                    ));
                }
                svc.etw_processes.store(false, Ordering::Relaxed);
                svc.etw_dns.store(false, Ordering::Relaxed);
                stop();
                wait = 10;
            }
            Err(e) => {
                tracing::warn!("{e:#}");
                wait = (wait * 2).min(600);
            }
        }
        if svc.is_stopping() {
            return;
        }
        std::thread::sleep(Duration::from_secs(wait));
    }
}

fn yes(b: bool) -> &'static str {
    if b {
        "ja"
    } else {
        "nein"
    }
}

/// Blocks until the session is stopped.
fn consume() {
    let mut name = wide(SESSION);
    let mut log = EVENT_TRACE_LOGFILEW { LoggerName: PWSTR(name.as_mut_ptr()), ..Default::default() };
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(on_event);
    // SAFETY: logfile struct valid during OpenTraceW; the handle is closed below.
    unsafe {
        let h = OpenTraceW(&mut log);
        if h.Value == u64::MAX {
            tracing::warn!("ETW: OpenTrace fehlgeschlagen");
            return;
        }
        let r = ProcessTrace(&[h], None, None);
        tracing::info!("ETW-Verarbeitung beendet ({r:?})");
        let _ = CloseTrace(h);
    }
}

unsafe extern "system" fn on_event(ev: *mut EVENT_RECORD) {
    let Some(ev) = ev.as_ref() else { return };
    let Some(tx) = SENDER.get() else { return };
    let id = ev.EventHeader.EventDescriptor.Id;
    let provider = ev.EventHeader.ProviderId;
    let ts = ev.EventHeader.TimeStamp;
    let opcode = ev.EventHeader.EventDescriptor.Opcode;
    if (provider == KERNEL_PROCESS_CLASS && opcode == OPCODE_END) || (provider == KERNEL_PROCESS && id == EV_PROCESS_STOP) {
        if let Some(pid) = prop_u32(ev, "ProcessId").or_else(|| prop_u32(ev, "ProcessID")) {
            let _ = tx.send(Ev::Stop { pid, ts });
        }
    } else if provider == KERNEL_PROCESS_CLASS && opcode == OPCODE_START {
        let pid = prop_u32(ev, "ProcessId");
        let ppid = prop_u32(ev, "ParentId");
        let image = prop_ansi(ev, "ImageFileName");
        let cmd = prop_string(ev, "CommandLine");
        if let (Some(pid), Some(image)) = (pid, image) {
            let _ = tx.send(Ev::Process { pid, ppid: ppid.unwrap_or(0), image, cmd, ts });
        }
    } else if provider == KERNEL_PROCESS && id == EV_PROCESS_START {
        let pid = prop_u32(ev, "ProcessID");
        let ppid = prop_u32(ev, "ParentProcessID");
        let image = prop_string(ev, "ImageName");
        if let (Some(pid), Some(image)) = (pid, image) {
            if CLASSIC_STARTS.load(Ordering::Relaxed) {
                let _ = tx.send(Ev::Image { pid, ts, image });
            } else {
                let _ = tx.send(Ev::Process { pid, ppid: ppid.unwrap_or(0), image, cmd: None, ts });
            }
        }
    } else if provider == KERNEL_FILE && id == EV_FILE_CREATE {
        FILE_SEEN.fetch_add(1, Ordering::Relaxed);
        if let Some(name) = file_name_of(ev) {
            FILE_PASSED.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(Ev::File { pid: ev.EventHeader.ProcessId, name, ts });
        }
    } else if provider == POWERSHELL && id == EV_SCRIPT_BLOCK {
        if let Some(text) = prop_string(ev, "ScriptBlockText") {
            let _ = tx.send(Ev::Script {
                pid: ev.EventHeader.ProcessId,
                ts,
                id: prop_string(ev, "ScriptBlockId").unwrap_or_default(),
                number: prop_u32(ev, "MessageNumber").unwrap_or(1) as usize,
                total: prop_u32(ev, "MessageTotal").unwrap_or(1) as usize,
                text,
                path: prop_string(ev, "Path").unwrap_or_default(),
            });
        }
    } else if provider == DNS_CLIENT && id == EV_DNS_QUERY {
        if let Some(name) = prop_string(ev, "QueryName") {
            let _ = tx.send(Ev::Dns { pid: ev.EventHeader.ProcessId, name, ts });
        }
    }
}

/// File name of a Kernel-File create event, only if it looks like a store of logins.
/// Fast path for the callback: no TDH call, no allocation for uninteresting files.
fn file_name_of(ev: &EVENT_RECORD) -> Option<String> {
    if ev.UserData.is_null() || ev.UserDataLength < 24 {
        return None;
    }
    // SAFETY: UserData points to UserDataLength bytes of the event.
    let data = unsafe { std::slice::from_raw_parts(ev.UserData as *const u8, ev.UserDataLength as usize) };
    let words: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let name = nt_file_name(&words)?;
    // Opens in the users' document folders: remembered for the ransomware detection
    // (who touched the files that later look encrypted).
    if k9_core::ransom::maybe_user_file(name) {
        if let Some(tail) = k9_core::ransom::user_tail(&String::from_utf16_lossy(name)) {
            crate::ransom_wache::opened(tail, ev.EventHeader.ProcessId);
        }
    }
    interesting(name).then(|| String::from_utf16_lossy(name))
}

/// The NT path ("\Device\...") inside the event data (the field offsets differ by version).
fn nt_file_name(words: &[u16]) -> Option<&[u16]> {
    let marker: Vec<u16> = "\\Device\\".encode_utf16().collect();
    let start = words.windows(marker.len()).position(|w| w == marker.as_slice())?;
    let rest = &words[start..];
    let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Case-insensitive search for the needles (ASCII letters) in a UTF-16 path.
fn interesting(name: &[u16]) -> bool {
    let lower = |c: u16| if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c };
    FILE_NEEDLES.iter().any(|n| {
        let n: Vec<u16> = n.encode_utf16().collect();
        name.len() >= n.len() && name.windows(n.len()).any(|w| w.iter().zip(&n).all(|(a, b)| lower(*a) == *b))
    })
}

fn prop_raw(ev: &EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let n = wide(name);
    let desc = [PROPERTY_DATA_DESCRIPTOR { PropertyName: n.as_ptr() as u64, ArrayIndex: u32::MAX, Reserved: 0 }];
    let mut size = 0u32;
    // SAFETY: event record from ETW, descriptor valid during the calls.
    unsafe {
        if TdhGetPropertySize(ev, None, &desc, &mut size) != ERROR_SUCCESS.0 || size == 0 || size > 65536 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if TdhGetProperty(ev, None, &desc, &mut buf) != ERROR_SUCCESS.0 {
            return None;
        }
        Some(buf)
    }
}

fn prop_u32(ev: &EVENT_RECORD, name: &str) -> Option<u32> {
    let b = prop_raw(ev, name)?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn prop_ansi(ev: &EVENT_RECORD, name: &str) -> Option<String> {
    let b = prop_raw(ev, name)?;
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    Some(String::from_utf8_lossy(&b[..end]).to_string())
}

fn prop_string(ev: &EVENT_RECORD, name: &str) -> Option<String> {
    let b = prop_raw(ev, name)?;
    let words: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let end = words.iter().position(|c| *c == 0).unwrap_or(words.len());
    Some(String::from_utf16_lossy(&words[..end]))
}

// ================================================================= checks

/// Maps "\Device\HarddiskVolume3\x" to "C:\x".
struct DosDevices(Vec<(String, String)>);

impl DosDevices {
    fn load() -> Self {
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
        let mut out = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let w = wide(&drive);
            let mut buf = [0u16; 1024];
            // SAFETY: valid name and buffer.
            let n = unsafe { QueryDosDeviceW(PCWSTR(w.as_ptr()), Some(&mut buf)) } as usize;
            if n > 0 {
                let end = buf[..n].iter().position(|c| *c == 0).unwrap_or(n);
                out.push((String::from_utf16_lossy(&buf[..end]), drive));
            }
        }
        Self(out)
    }

    fn to_win32(&self, nt: &str) -> String {
        for (dev, drive) in &self.0 {
            if let Some(rest) = nt.strip_prefix(dev.as_str()) {
                if rest.starts_with('\\') {
                    return format!("{drive}{rest}");
                }
            }
        }
        nt.to_string()
    }
}

/// Program part of a command line (`"C:\\a b\\x.exe" -y` or `C:\\x.exe -y`).
fn program_of(cmd: &str) -> Option<String> {
    let c = cmd.trim_start();
    let prog = if let Some(rest) = c.strip_prefix('"') { rest.split('"').next()? } else { c.split_whitespace().next()? };
    (!prog.is_empty()).then(|| prog.to_string())
}

/// Program shown in process findings: running process, else a full path from the command
/// line or the event, else whatever name there is. Never used to decide whose a file access
/// is (the command line can be forged) – that uses only kernel sources (`Lives`).
fn program_path(running: Option<String>, cmd: Option<&str>, image: &str) -> String {
    let full = |p: &String| std::path::Path::new(p).is_absolute();
    let from_cmd = cmd.and_then(program_of);
    running
        .or_else(|| from_cmd.clone().filter(full))
        .or_else(|| Some(image.to_string()).filter(full))
        .or(from_cmd)
        .unwrap_or_else(|| image.to_string())
}

fn file_name(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

/// One process that ran under a process ID (Windows reuses IDs quickly).
#[derive(Debug, Clone)]
struct Life {
    start: i64,
    /// Stop event, or the next start under the same ID.
    stop: Option<i64>,
    path: String,
    /// Process ID of the starter, from the start event (kernel source).
    parent: Option<u32>,
}

/// Who opened a file at a given time.
#[derive(Debug, PartialEq)]
enum Owner {
    Known(String),
    /// No or more than one process fits – never guessed.
    Unsure,
}

/// Process lives per ID from the start/stop events.
#[derive(Default)]
struct Lives(HashMap<u32, Vec<Life>>);

impl Lives {
    /// A start: `path` is the full path when it comes from the kernel or the running process,
    /// else only the file name (classic event). Both events of one start are merged; a
    /// full path always wins over a bare name.
    fn started(&mut self, pid: u32, ts: i64, path: &str) {
        let v = self.0.entry(pid).or_default();
        if let Some(last) = v.last_mut() {
            if (last.start - ts).abs() < SAME_START && last.stop.is_none_or(|s| s >= ts) {
                if is_full(path) && !is_full(&last.path) {
                    last.path = path.to_string();
                }
                last.start = last.start.min(ts);
                return;
            }
            if last.stop.is_none() {
                last.stop = Some(ts);
            }
        }
        v.push(Life { start: ts, stop: None, path: path.to_string(), parent: None });
        if v.len() > 4 {
            v.remove(0);
        }
    }

    /// The programs already running when the service starts (process ID, start time, full
    /// path – from the running processes themselves). Returns how many were taken.
    fn seed(&mut self, running: impl Iterator<Item = (u32, i64, String)>) -> usize {
        let mut n = 0;
        for (pid, start, path) in running {
            if is_full(&path) {
                self.started(pid, start, &path);
                n += 1;
            }
        }
        n
    }

    /// Remembers who started the process that has `pid` at `ts`.
    fn set_parent(&mut self, pid: u32, ts: i64, parent: u32) {
        if let Some(l) = self.0.get_mut(&pid).and_then(|v| v.iter_mut().rev().find(|l| (l.start - ts).abs() < SAME_START)) {
            l.parent = Some(parent);
        }
    }

    /// Full paths of the starters of the process `pid` (running at `ts`), nearest first, at
    /// most ten. Works for starters that have already ended as long as their life is still
    /// remembered – short command chains (shell → shell → tool) are gone within milliseconds.
    /// A starter counts only if it was running when its child started (process IDs are reused).
    /// The second value: where the remembered chain ends – the ID of the next starter and the
    /// start time of its child. That starter began before the service did (no start event);
    /// the caller asks Windows about it.
    fn ancestors(&self, pid: u32, ts: i64) -> (Vec<std::path::PathBuf>, Option<(u32, i64)>) {
        let life_at = |pid: u32, at: i64| self.0.get(&pid)?.iter().rev().find(|l| l.start <= at + SAME_START && l.stop.is_none_or(|s| s >= at - SAME_START));
        let mut out = Vec::new();
        let Some(mut cur) = life_at(pid, ts) else { return (out, None) };
        for _ in 0..10 {
            let Some(parent) = cur.parent else { return (out, None) };
            let Some(p) = life_at(parent, cur.start) else { return (out, Some((parent, cur.start))) };
            if is_full(&p.path) {
                out.push(std::path::PathBuf::from(&p.path));
            }
            cur = p;
        }
        (out, None)
    }

    /// The starters of the process that had `pid` at `ts`, nearest first: process ID, start
    /// time and program – also those that have ended meanwhile. Windows reports a start a
    /// second or two late; by then a short-lived helper (cmd.exe) is gone, and asking Windows
    /// for "the parent of the parent" leads nowhere.
    fn ancestor_ids(&self, pid: u32, ts: i64) -> Vec<(u32, i64, String)> {
        let life_at = |pid: u32, at: i64| self.0.get(&pid)?.iter().rev().find(|l| l.start <= at + SAME_START && l.stop.is_none_or(|s| s >= at - SAME_START));
        let mut out = Vec::new();
        let Some(mut cur) = life_at(pid, ts) else { return out };
        for _ in 0..10 {
            let Some(parent) = cur.parent else { break };
            let Some(p) = life_at(parent, cur.start) else { break };
            out.push((parent, p.start, p.path.clone()));
            cur = p;
        }
        out
    }

    fn stopped(&mut self, pid: u32, ts: i64) {
        if let Some(last) = self.0.get_mut(&pid).and_then(|v| v.last_mut()) {
            if last.stop.is_none() {
                last.stop = Some(ts);
            }
        }
    }

    /// Lives ended before `before` are dropped.
    fn prune(&mut self, before: i64) {
        self.0.retain(|_, v| {
            v.retain(|l| l.stop.is_none_or(|s| s >= before));
            !v.is_empty()
        });
    }

    /// Start time of the one process that had `pid` at time `ts`.
    fn start_at(&self, pid: u32, ts: i64) -> Option<i64> {
        let fits: Vec<&Life> = self.0.get(&pid).into_iter().flatten().filter(|l| l.start <= ts && l.stop.is_none_or(|s| s >= ts)).collect();
        match fits.as_slice() {
            [one] => Some(one.start),
            _ => None,
        }
    }

    /// The process that had `pid` at time `ts`. `live`: the process running now under this ID
    /// (program, creation time) – used only if it already existed at `ts`. Only full paths
    /// from the kernel count; a bare name (or anything from the command line) is "unsure".
    fn owner(&self, pid: u32, ts: i64, live: Option<(String, i64)>) -> Owner {
        let fits: Vec<&Life> = self.0.get(&pid).into_iter().flatten().filter(|l| l.start <= ts && l.stop.is_none_or(|s| s >= ts)).collect();
        match (fits.as_slice(), live) {
            ([one], _) if is_full(&one.path) => Owner::Known(one.path.clone()),
            ([one], Some((path, created))) if created <= ts && (created - one.start).abs() < SAME_START => Owner::Known(path),
            ([], Some((path, created))) if created <= ts => Owner::Known(path),
            _ => Owner::Unsure,
        }
    }
}

fn is_full(path: &str) -> bool {
    std::path::Path::new(path).is_absolute()
}

impl Lives {
    /// For a finding "Programm nicht sicher zuzuordnen": the bare program name of the start
    /// event, if exactly one process had this ID at that time. Only a hint for the reader
    /// (a name proves nothing – it is never used to allow anything).
    fn name_hint(&self, pid: u32, ts: i64) -> Option<String> {
        let fits: Vec<&Life> = self.0.get(&pid).into_iter().flatten().filter(|l| l.start <= ts && l.stop.is_none_or(|s| s >= ts)).collect();
        match fits.as_slice() {
            [one] if !one.path.is_empty() => {
                let name: String = one.path.rsplit(['\\', '/']).next().unwrap_or(&one.path).chars().filter(|c| !c.is_control()).take(60).collect();
                (!name.is_empty()).then_some(name)
            }
            _ => None,
        }
    }
}

/// Is the program `exe` the root of a possible attack chain, and why? Only unsigned programs:
/// marked "from the internet" (`internet`), or without that mark new in a user's folder or on a
/// removable drive – but never inside one of the user's work folders (own builds).
pub(crate) fn chain_root(exe: &std::path::Path, internet: bool, arbeit: &k9_core::arbeitsordner::Arbeit) -> Option<k9_core::ketten::Step> {
    let root = if internet {
        k9_core::ketten::Step::Download
    } else {
        let path = exe.display().to_string();
        if arbeit.folder_of(&path).is_some() {
            return None;
        }
        let age = std::fs::metadata(exe).ok().and_then(|m| m.created().ok()).and_then(|c| c.elapsed().ok()).map(|d| d.as_secs());
        k9_core::ketten::local_root(&path, age, rt::is_removable(exe))?
    };
    (!k9_core::autostart::is_signed(exe)).then_some(root)
}

fn report_chain(svc: &Svc, r: &k9_core::ketten::Report) {
    tracing::warn!("Angriffskette ({:?}) ausgehend von {}: {}", r.severity, r.root_exe, r.steps.join(" → "));
    svc.report(&k9_core::ketten::finding(r));
}

/// Current time as FILETIME (like the ETW time stamps).
pub(crate) fn filetime_now() -> i64 {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (unix.as_nanos() / 100) as i64 + 116_444_736_000_000_000
}

/// Infostealer protection: who opened which store of logins.
struct LoginWatch {
    /// Process lives per ID (for file events that arrive after the process ended).
    lives: Lives,
    /// program (lower case) -> program facts and identity (signer or file hash), cached briefly.
    programs: HashMap<String, (k9_core::infostealer::Opener, String, Instant)>,
    /// program -> groups touched recently (stealer pattern: several within a minute).
    recent: HashMap<String, Vec<(&'static str, Instant)>>,
    /// (program, group) -> last report / log entry (one per 10 minutes).
    reported: HashMap<(String, &'static str), Instant>,
    own: Vec<std::path::PathBuf>,
    stats_at: Instant,
    /// CPU seconds of the service at the last statistics line.
    cpu_at: f64,
}

impl LoginWatch {
    fn new() -> Self {
        let dir = k9_core::dienst::install_dir();
        Self {
            lives: Lives::default(),
            programs: HashMap::new(),
            recent: HashMap::new(),
            reported: HashMap::new(),
            own: ["k9-agent.exe", "k9-dienst.exe", "k9.exe"].iter().map(|n| dir.join(n)).collect(),
            stats_at: Instant::now(),
            cpu_at: k9_core::scanner::process_cpu_seconds(),
        }
    }

    /// Facts about a program (signature, folder), cached per path for 10 minutes.
    fn program(&mut self, path: &str) -> (k9_core::infostealer::Opener, String) {
        let key = path.to_lowercase();
        if let Some((o, id, t)) = self.programs.get(&key) {
            if t.elapsed() < Duration::from_secs(600) {
                return (o.clone(), id.clone());
            }
        }
        let p = std::path::Path::new(path);
        let signed = k9_core::autostart::is_signed(p);
        let signer = signed.then(|| k9_core::treiber::signer_name(p)).flatten();
        let identity = signer.clone().unwrap_or_else(|| k9_core::scanner::sha256_file(p).unwrap_or_else(|_| key.clone()));
        let o = k9_core::infostealer::Opener { path: path.to_string(), signer, user_writable: k9_core::autostart::is_user_writable(p) };
        if self.programs.len() > 5000 {
            self.programs.clear();
        }
        self.programs.insert(key, (o.clone(), identity.clone(), Instant::now()));
        (o, identity)
    }

    /// A store of logins was opened, but which program did it is not known (yet): neither a
    /// start event with a full path nor a running process fits.
    fn program_unknown(&self, devices: &DosDevices, pid: u32, ts: i64, nt_name: &str) -> bool {
        if pid == std::process::id() || pid <= 4 {
            return false;
        }
        if k9_core::infostealer::group_of(&devices.to_win32(nt_name)).is_none() {
            return false;
        }
        let live = rt::process_path_and_start(pid).map(|(p, created)| (p.display().to_string(), created));
        self.lives.owner(pid, ts, live) == Owner::Unsure
    }

    /// Returns (start time, program) when the access was reported (for the attack chains).
    fn handle(&mut self, svc: &Svc, devices: &DosDevices, pid: u32, ts: i64, nt_name: &str) -> Option<(Option<i64>, String)> {
        if pid == std::process::id() || pid <= 4 {
            return None;
        }
        let file = devices.to_win32(nt_name);
        let group = k9_core::infostealer::group_of(&file)?;
        // Only a folder was opened (listing, adding up sizes): nothing is read, whoever did it.
        if k9_core::infostealer::lists_folder(&file) {
            return None;
        }
        let live = rt::process_path_and_start(pid).map(|(p, created)| (p.display().to_string(), created));
        let start = self.lives.start_at(pid, ts).or(live.as_ref().filter(|(_, c)| *c <= ts).map(|(_, c)| *c));
        let (opener, identity, unsure) = match self.lives.owner(pid, ts, live) {
            Owner::Known(path) => {
                let (o, id) = self.program(&path);
                (o, id, false)
            }
            Owner::Unsure => {
                // The name from the start event helps to see what it was (e.g. a browser helper).
                let hint = self.lives.name_hint(pid, ts).map(|n| format!(", laut Startereignis „{n}“ – Name ungeprüft")).unwrap_or_default();
                let o = k9_core::infostealer::Opener { path: format!("Programm nicht sicher zuzuordnen (PID {pid}{hint})"), signer: None, user_writable: false };
                (o, "unbekannt".to_string(), true)
            }
        };
        // The Explorer shows a folder (tooltip, folder tree, search): nothing is read.
        if !unsure && k9_core::infostealer::explorer_lists_folder(&opener, &file) {
            return None;
        }
        let now = Instant::now();
        let list = self.recent.entry(opener.path.to_lowercase()).or_default();
        list.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));
        if !list.iter().any(|(g, _)| *g == group.id) {
            list.push((group.id, now));
        }
        let groups = list.len();
        let verdict = if unsure {
            // Several stores in a row under the same ID: more likely a stealer.
            let sev = if groups >= 2 { k9_core::model::Severity::Hoch } else { k9_core::model::Severity::Mittel };
            k9_core::infostealer::Verdict::Report(sev, k9_core::t!("Programm nicht sicher zuzuordnen – der Prozess war beim Auswerten schon beendet", "program cannot be assigned reliably – the process had already ended when it was evaluated"))
        } else {
            k9_core::infostealer::assess(group, &opener, groups, &self.own)
        };
        let key = (opener.path.to_lowercase(), group.id);
        let due = self.reported.get(&key).is_none_or(|t| now.duration_since(*t) > Duration::from_secs(600));
        // Every access with its verdict (log level "debug", set K9_LOG=debug): the sandbox tests
        // with real info stealers use it to see whether a sample touched the decoys at all.
        tracing::debug!("Zugangsdaten-Zugriff: {} | {} | {:?}", opener.path, file, verdict);
        match verdict {
            k9_core::infostealer::Verdict::Allowed => {}
            k9_core::infostealer::Verdict::Logged => {
                if due {
                    self.reported.insert(key, now);
                    if let Ok(store) = svc.app.store() {
                        let _ = store.log_event("info", &format!("Browser-Import: {} liest {}", opener.path, group.label));
                    }
                }
            }
            k9_core::infostealer::Verdict::Report(sev, why) => {
                // Per program and store once per 10 minutes; a further store is a new key.
                if due {
                    self.reported.insert(key, now);
                    tracing::warn!("Zugangsdaten: {} öffnet {} ({file})", opener.path, group.label);
                    let mut f = k9_core::infostealer::finding(group, &opener, &file, pid, sev, why, &identity);
                    rt::note_start(&mut f, start);
                    svc.report(&f);
                }
                return Some((start, opener.path.clone()));
            }
        }
        None
    }

    /// Every 10 minutes: statistics for the log, old entries out.
    fn housekeeping(&mut self) {
        if self.stats_at.elapsed() < Duration::from_secs(600) {
            return;
        }
        let seen = FILE_SEEN.swap(0, Ordering::Relaxed);
        let passed = FILE_PASSED.swap(0, Ordering::Relaxed);
        let minutes = self.stats_at.elapsed().as_secs_f64() / 60.0;
        let cpu = k9_core::scanner::process_cpu_seconds();
        tracing::info!(
            "Schutz vor Datendieben: {seen} Dateiöffnungen in {minutes:.0} min ({:.0} je Sekunde), davon {passed} geprüft; CPU-Zeit des Dienstes {:.1} s ({:.2} % eines Kerns)",
            seen as f64 / (minutes * 60.0).max(1.0),
            cpu - self.cpu_at,
            (cpu - self.cpu_at) / (minutes * 60.0).max(1.0) * 100.0
        );
        self.stats_at = Instant::now();
        self.cpu_at = cpu;
        self.recent.retain(|_, l| l.iter().any(|(_, t)| t.elapsed() < Duration::from_secs(60)));
        self.lives.prune(filetime_now() - 30 * 60 * 10_000_000);
        self.reported.retain(|_, t| t.elapsed() < Duration::from_secs(600));
    }
}

fn check_events(svc: Arc<Svc>, rx: mpsc::Receiver<Ev>) {
    k9_core::priority::below_normal();
    let mut devices = DosDevices::load();
    let mut db = NetDb::default();
    let mut db_state = String::new();
    let mut db_checked: Option<Instant> = None;
    let mut dns_seen: HashMap<String, Instant> = HashMap::new();
    // Recently started processes (pid -> program, command line) for DNS queries
    // of programs that are already gone again.
    let mut started: HashMap<u32, (String, String, Instant)> = HashMap::new();
    let me = std::process::id();
    let mut logins = LoginWatch::new();
    // Programs that were running before the service started have no start event. Without
    // their lives a program that opens a store of logins and ends right away could not be
    // named: a browser writes its "Local State" when it closes, and after every restart of the
    // service (update) closing a browser that was already open gave the finding "Programm nicht
    // sicher zuzuordnen" (four of them on 20./21.11.2026, each for the browser's own file).
    let known = logins.lives.seed(rt::process_snapshot().into_keys().filter_map(|pid| rt::process_path_and_start(pid).map(|(p, start)| (pid, start, p.display().to_string()))));
    tracing::info!("Schutz vor Datendieben: {known} laufende Programme übernommen");
    let mut scripts = k9_core::skripte::Assembler::default();
    // Programs from the internet already checked (path -> unsigned from the internet), so a
    // program is checked only once; the finding comes at the first start.
    let mut downloads_seen: HashMap<String, Option<k9_core::ketten::Step>> = HashMap::new();
    let mut chains = k9_core::ketten::Chains::default();
    let phishing = &svc.app.config.phishing;
    let lookalikes = phishing.aehnliche_domains.then(|| k9_core::phishing::Lookalikes::new(&phishing.eigene_marken));
    // Names already checked for lookalikes (most queries repeat).
    let mut names_checked: HashSet<String> = HashSet::new();
    // File opens whose program is not known yet: looked at again a moment later. The start of
    // a process and its file opens come from different event sources and may arrive in the
    // wrong order – a very short-lived program then seemed to have no name at all (the
    // "Edge every six hours" findings of November 2026).
    let mut waiting: std::collections::VecDeque<(Instant, u32, String, i64)> = std::collections::VecDeque::new();
    loop {
        let timeout = match waiting.front() {
            Some((due, ..)) => due.saturating_duration_since(Instant::now()).min(Duration::from_secs(60)),
            None => Duration::from_secs(60),
        };
        let ev = if waiting.front().is_some_and(|(due, ..)| *due <= Instant::now()) {
            // Final look: whatever is known now decides.
            waiting.pop_front().map(|(_, pid, name, ts)| Ev::FileAgain { pid, name, ts })
        } else {
            match rx.recv_timeout(timeout) {
                Ok(ev) => Some(ev),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(_) => return,
            }
        };
        if db_checked.is_none_or(|t| t.elapsed() > Duration::from_secs(600)) {
            db_checked = Some(Instant::now());
            if let Ok(src) = svc.app.sources() {
                let state = src.state_fingerprint();
                if state != db_state {
                    db = NetDb::load_with(&src.dir, &svc.live().quellen);
                    db_state = state;
                    tracing::info!("DNS-Prüfung: Schad-Domains geladen");
                }
            }
            dns_seen.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
            if names_checked.len() > 20_000 {
                names_checked.clear();
            }
            started.retain(|_, (_, _, t)| t.elapsed() < Duration::from_secs(1800));
            chains.prune(filetime_now());
            devices = DosDevices::load();
        }
        match ev {
            Some(Ev::Attacked { ts, step }) => {
                // Malware often switches the protection off first. A program from the internet
                // that is still running when the agent is ended is reported as a critical chain
                // and – with "Kritische Programme anhalten" – frozen by the usual way.
                let running = |pid: u32, start: i64| rt::process_path_and_start(pid).is_some_and(|(_, began)| (began - start).abs() < 10_000_000);
                let reports = chains.protection_attacked(ts, step, &running);
                if reports.is_empty() {
                    tracing::info!("{} – kein Programm aus dem Internet läuft, kein Zusammenhang erkennbar", step.label());
                }
                for r in &reports {
                    report_chain(&svc, r);
                }
            }
            Some(Ev::Stop { pid, ts }) => logins.lives.stopped(pid, ts),
            Some(Ev::Image { pid, ts, image }) => logins.lives.started(pid, ts, &devices.to_win32(&image)),
            Some(Ev::Process { pid, ppid, image, cmd, ts }) => {
                // Full path: from the running process, else from the command line / event
                // (short-lived processes are often gone already; the classic event has only the name).
                let running = rt::process_path(pid).map(|p| p.display().to_string());
                // Life of the process: only kernel sources (never the command line, it can be forged).
                logins.lives.started(pid, ts, &running.clone().unwrap_or_else(|| devices.to_win32(&image)));
                logins.lives.set_parent(pid, ts, ppid);
                if ppid == me {
                    continue;
                }
                let path = program_path(running, cmd.as_deref(), &devices.to_win32(&image));
                let name = file_name(&path);
                let parent = rt::process_path(ppid)
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .or_else(|| rt::process_snapshot().get(&ppid).map(|p| p.name.clone()))
                    .unwrap_or_default();
                let cmd = cmd.filter(|c| !c.is_empty()).or_else(|| rt::process_command_line(pid)).unwrap_or_default();
                tracing::debug!("Prozessstart {pid}: {name} (Eltern {parent})");
                if started.len() < 20_000 {
                    started.insert(pid, (path.clone(), cmd.clone(), Instant::now()));
                }
                // Child process of a chain member: joins the chain (script host, autostart).
                if svc.live().echtzeit.angriffsketten {
                    if let Some(r) = chains.process_started(pid, ts, ppid, logins.lives.start_at(ppid, ts), &path, &cmd) {
                        report_chain(&svc, &r);
                    }
                }
                if svc.live().echtzeit.download_herkunft && is_full(&path) {
                    if downloads_seen.len() > 10_000 {
                        downloads_seen.clear();
                    }
                    let first = !downloads_seen.contains_key(&path.to_lowercase());
                    let exe = std::path::Path::new(&path);
                    let zone = if first { k9_core::herkunft::zone_of(exe).filter(|z| z.from_internet()) } else { None };
                    // Root of a possible attack chain: unsigned and from the internet, new in a
                    // user's folder or on a removable drive (decided once per program file).
                    let root = *downloads_seen
                        .entry(path.to_lowercase())
                        .or_insert_with(|| chain_root(exe, zone.is_some(), &k9_core::arbeitsordner::Arbeit::from_config(&svc.live().arbeitsordner)));
                    let from_internet = root == Some(k9_core::ketten::Step::Download);
                    if let (true, Some(zone)) = (first && from_internet, &zone) {
                        let identity = k9_core::herkunft::program_identity(exe);
                        let mut f = k9_core::herkunft::finding(exe, zone, &identity, pid, &cmd, &parent);
                        rt::note_start(&mut f, rt::process_start(pid).or(Some(ts)));
                        tracing::warn!("Programm aus dem Internet ohne Signatur gestartet: {path}");
                        svc.report(&f);
                        crate::vt::request(&svc, exe.to_path_buf(), identity.clone());
                    }
                    if let (Some(root), true) = (root, svc.live().echtzeit.angriffsketten) {
                        if !from_internet {
                            tracing::debug!("Kette beginnt ({}): {path}", root.label());
                        }
                        if let Some(r) = chains.start(pid, ts, &path, root) {
                            report_chain(&svc, &r);
                        }
                    }
                }
                // A script from the internet run by a script host (wscript, mshta, PowerShell, cmd):
                // the host itself is a signed Windows program, the script is what came from outside.
                if svc.live().echtzeit.download_herkunft {
                    if let Some(script) = k9_core::herkunft::script_of(&name, &cmd, || rt::process_current_dir(pid)) {
                        let key = format!("skript|{}", script.display().to_string().to_lowercase());
                        // `insert` returns None the first time this script is seen.
                        let zone = k9_core::herkunft::zone_of(&script).filter(|z| z.from_internet());
                        if downloads_seen.insert(key, zone.as_ref().map(|_| k9_core::ketten::Step::Download)).is_none() {
                            if let Some(zone) = zone {
                                let identity = k9_core::herkunft::program_identity(&script);
                                let mut f = k9_core::herkunft::script_finding(&script, &zone, &identity, pid, &path, &cmd, &parent);
                                rt::note_start(&mut f, rt::process_start(pid).or(Some(ts)));
                                rt::note_parent(&mut f, ppid);
                                tracing::warn!("Skript aus dem Internet gestartet: {} über {name}", script.display());
                                svc.report(&f);
                                if svc.live().echtzeit.angriffsketten {
                                    if let Some(r) = chains.start_download(pid, ts, &script.display().to_string()) {
                                        report_chain(&svc, &r);
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some((rule, text, sev)) = rt::assess_process(&parent, &name, &cmd) {
                    let mut f = rt::process_finding(pid, &name, &path, &cmd, &rule, &text, sev, &parent, "dienst");
                    // Creation time of the running process, else the ETW start time.
                    rt::note_start(&mut f, rt::process_start(pid).or(Some(ts)));
                    rt::note_parent(&mut f, ppid);
                    let recovery = rule == "RANSOMWARE:WIEDERHERSTELLUNG";
                    if recovery && svc.live().echtzeit.ransomware_prozess_anhalten {
                        svc.freeze_starter(&mut f, ppid, &logins.lives.ancestor_ids(pid, ts));
                    }
                    svc.report(&f);
                    // Started by a program that is followed as an attack chain: a critical step
                    // (the chain's finding freezes the program at the root).
                    if recovery && svc.live().echtzeit.angriffsketten {
                        if let Some(r) = chains.event(pid, logins.lives.start_at(pid, ts), ts, k9_core::ketten::Step::Wiederherstellung, &name) {
                            report_chain(&svc, &r);
                        }
                    }
                } else if svc.live().quellen.sigma_aktiv || svc.live().quellen.lolbas_aktiv {
                    // Sigma rules (SigmaHQ) – only when K9's own rules found nothing for this start.
                    // First the package "core" (high and critical); if that has no hit, the rules
                    // of the level "medium" that LOLBAS refers to (switch "lolbas", quiet).
                    static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
                    let dir = DIR.get_or_init(|| svc.app.sources().ok().map(|s| s.dir));
                    let (core_on, lolbas_on) = {
                        let q = &svc.live().quellen;
                        (q.sigma_aktiv, q.lolbas_aktiv)
                    };
                    let image = if path.is_empty() { format!("\\{name}") } else { path.clone() };
                    let parent_image = format!("\\{parent}");
                    let ev = k9_core::sigma::Event { image: &image, command_line: &cmd, parent_image: &parent_image, parent_command_line: None };
                    let core = if core_on { dir.as_deref().and_then(k9_core::sigma::live) } else { None };
                    let extra = if lolbas_on { dir.as_deref().and_then(k9_core::sigma::live_lolbas) } else { None };
                    let hit = core
                        .as_ref()
                        .and_then(|s| s.matches(&ev).first().map(|r| (k9_core::sigma::finding_parts(r), false)))
                        .or_else(|| extra.as_ref().and_then(|s| s.matches(&ev).first().map(|r| (k9_core::sigma::lolbas_finding_parts(r), true))));
                    {
                        if let Some(((rule, text, sev), lolbas)) = hit {
                            let mut f = rt::process_finding(pid, &name, &path, &cmd, &rule, &text, sev, &parent, "dienst");
                            rt::note_start(&mut f, rt::process_start(pid).or(Some(ts)));
                            rt::note_parent(&mut f, ppid);
                            // Started (also over several short-lived steps) by one of the user's work
                            // programs, e.g. a Claude session: only quiet in the dashboard. The chain
                            // comes from the service's own start events – the agent could no longer
                            // follow it, the steps in between have ended by then.
                            let arbeit = k9_core::arbeitsordner::Arbeit::from_config(&svc.live().arbeitsordner);
                            let (mut chain, open_end) = logins.lives.ancestors(pid, ts);
                            if let Some((starter, child_start)) = open_end {
                                // A starter from before the service started (e.g. the work program
                                // itself, running for hours): still alive, Windows knows it.
                                // Only if it really began before its child (process IDs are reused);
                                // the walk further up checks every step the same way.
                                if rt::process_path_and_start(starter).is_some_and(|(_, began)| began <= child_start) {
                                    chain.extend(k9_core::arbeitsordner::ancestors(starter, None, None));
                                }
                            }
                            if let Some(why) = arbeit.reason(&f, &chain, &|p| k9_core::autostart::is_signed(p)) {
                                if let Some(d) = f.details.as_mut() {
                                    d[k9_core::arbeitsordner::LEISE] = why.into();
                                }
                            } else if lolbas {
                                if let Some(d) = f.details.as_mut() {
                                    d[k9_core::arbeitsordner::LEISE] = k9_core::sigma::LOLBAS_QUIET.into();
                                }
                            }
                            tracing::warn!("{text}: {name} (PID {pid})");
                            svc.report(&f);
                        }
                    }
                }
            }
            Some(Ev::Dns { pid, name, ts }) => {
                let lower = name.to_ascii_lowercase();
                let listed = db.lookup_domain(&lower);
                let lookalike = match (&listed, &lookalikes) {
                    (None, Some(l)) if names_checked.insert(lower.clone()) => l.check(&lower),
                    _ => None,
                };
                if listed.is_none() && lookalike.is_none() {
                    continue;
                }
                // Who asked: the running process, else what we saw at its start.
                let (program, cmd) = match rt::process_path(pid) {
                    Some(p) => (p.display().to_string(), rt::process_command_line(pid).unwrap_or_default()),
                    None => started.get(&pid).map(|(p, c, _)| (p.clone(), c.clone())).unwrap_or_default(),
                };
                let key = format!("{lower}|{}", program.to_lowercase());
                if dns_seen.contains_key(&key) {
                    continue;
                }
                dns_seen.insert(key, Instant::now());
                if svc.live().echtzeit.angriffsketten {
                    if let Some(r) = chains.event(pid, logins.lives.start_at(pid, ts), ts, k9_core::ketten::Step::BadAddress, &program) {
                        report_chain(&svc, &r);
                    }
                }
                let asker = (!program.is_empty()).then(|| rt::Asker { pid, program: &program, cmd: &cmd });
                match (listed, lookalike) {
                    (Some((domain, src)), _) => svc.report(&rt::dns_finding(&name, domain, src, "dienst", asker)),
                    (None, Some(hit)) => svc.report(&rt::lookalike_finding(&name, &hit, "dienst", asker)),
                    (None, None) => {}
                }
            }
            Some(Ev::File { pid, name, ts }) if waiting.len() < 500 && logins.program_unknown(&devices, pid, ts, &name) => {
                waiting.push_back((Instant::now() + Duration::from_millis(2000), pid, name, ts));
            }
            Some(Ev::File { pid, name, ts }) | Some(Ev::FileAgain { pid, name, ts }) => {
                if let Some((start, program)) = logins.handle(&svc, &devices, pid, ts, &name) {
                    if svc.live().echtzeit.angriffsketten {
                        if let Some(r) = chains.event(pid, start, ts, k9_core::ketten::Step::Credentials, &program) {
                            report_chain(&svc, &r);
                        }
                    }
                }
            }
            Some(Ev::Script { pid, ts, id, number, total, text, path }) => {
                let Some(whole) = scripts.add(&id, number, total, text) else { continue };
                let Some((rule, title, sev, pos)) = k9_core::skripte::assess(&whole) else { continue };
                // Which program ran it: only kernel sources (as for file accesses).
                let live = rt::process_path_and_start(pid).map(|(p, created)| (p.display().to_string(), created));
                let start = logins.lives.start_at(pid, ts).or(live.as_ref().filter(|(_, c)| *c <= ts).map(|(_, c)| *c));
                let program = match logins.lives.owner(pid, ts, live) {
                    Owner::Known(p) => p,
                    Owner::Unsure => String::new(),
                };
                tracing::warn!("PowerShell-Skript: {rule} (PID {pid})");
                let mut f = k9_core::skripte::finding(rule, title, sev, &whole, pos, &path, pid, &program);
                rt::note_start(&mut f, start);
                svc.report(&f);
                if svc.live().echtzeit.angriffsketten {
                    let step = if sev == k9_core::model::Severity::Kritisch { k9_core::ketten::Step::ScriptCritical } else { k9_core::ketten::Step::Script };
                    if let Some(r) = chains.event(pid, start, ts, step, &program) {
                        report_chain(&svc, &r);
                    }
                }
            }
            None => {}
        }
        logins.housekeeping();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_filter_layout() {
        // FilterIn = TRUE, reserved, Count = 1, Events[0] = 4104 (0x1008), little endian.
        assert_eq!(event_id_filter(&[4104]), vec![1, 0, 1, 0, 0x08, 0x10]);
    }

    #[test]
    fn nt_paths_become_drive_paths() {
        let d = DosDevices(vec![("\\Device\\HarddiskVolume3".into(), "C:".into())]);
        assert_eq!(d.to_win32("\\Device\\HarddiskVolume3\\Windows\\a.exe"), "C:\\Windows\\a.exe");
        assert_eq!(d.to_win32("\\Device\\HarddiskVolume30\\x.exe"), "\\Device\\HarddiskVolume30\\x.exe");
        assert_eq!(file_name("C:\\Windows\\System32\\cmd.exe"), "cmd.exe");
        assert_eq!(program_of("\"C:\\Program Files\\a.exe\" -x").as_deref(), Some("C:\\Program Files\\a.exe"));
        assert_eq!(program_of("certutil.exe -urlcache").as_deref(), Some("certutil.exe"));
    }

    #[test]
    fn file_events_pass_only_stores_of_logins() {
        // Event data like Kernel-File "Create" v1: two pointers, four u32, then the name.
        let make = |name: &str| {
            let mut w: Vec<u16> = vec![0x1111; 16];
            w.extend(name.encode_utf16());
            w.push(0);
            w
        };
        let chrome = make(r"\Device\HarddiskVolume3\Users\f\AppData\Local\Google\Chrome\User Data\Default\Login Data");
        let name = nt_file_name(&chrome).unwrap();
        assert_eq!(String::from_utf16_lossy(name), r"\Device\HarddiskVolume3\Users\f\AppData\Local\Google\Chrome\User Data\Default\Login Data");
        assert!(interesting(name));
        // Lower case (a stealer can open paths in any case) is found as well.
        let lower = make(r"\Device\HarddiskVolume3\users\f\appdata\local\google\chrome\user data\default\login data");
        assert!(interesting(nt_file_name(&lower).unwrap()));
        let other = make(r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll");
        assert!(!interesting(nt_file_name(&other).unwrap()));
        assert!(nt_file_name(&[0x41, 0x42, 0]).is_none());
        // Converted to a drive path, the core assigns the group.
        let d = DosDevices(vec![("\\Device\\HarddiskVolume3".into(), "C:".into())]);
        let file = d.to_win32(&String::from_utf16_lossy(name));
        assert_eq!(k9_core::infostealer::group_of(&file).unwrap().id, "chrome");
    }

    #[test]
    fn program_path_prefers_full_paths() {
        let exe = r"C:\Users\x\Downloads\unbekannt.exe";
        assert_eq!(program_path(None, Some(&format!("\"{exe}\" scan x")), "unbekannt.exe"), exe);
        let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        assert_eq!(program_path(None, Some("powershell.exe -NoProfile"), ps), ps);
        assert_eq!(program_path(None, Some("cmd.exe /c type x"), "cmd.exe"), "cmd.exe");
        assert_eq!(program_path(Some(r"C:\a.exe".into()), Some(&format!("\"{exe}\"")), "b.exe"), r"C:\a.exe");
    }

    #[test]
    fn the_start_chain_is_remembered_for_starters_that_have_already_ended() {
        let t = |n: i64| n * 100_000_000; // steps of 10 s
        let claude = r"C:\Users\x\.local\bin\claude.exe";
        let bash1 = r"C:\Program Files\Git\bin\bash.exe";
        let bash2 = r"C:\Program Files\Git\usr\bin\bash.exe";
        // Work program (10) -> shell (20) -> shell (30) -> tool (40); the shells end at once.
        let mut lives = Lives::default();
        lives.started(10, t(1), claude);
        for (pid, parent, at, path) in [(20, 10, t(5), bash1), (30, 20, t(5) + 1000, bash2), (40, 30, t(5) + 2000, r"C:\Program Files\Git\usr\bin\grep.exe")] {
            lives.started(pid, at, path);
            lives.set_parent(pid, at, parent);
        }
        lives.stopped(30, t(5) + 3000);
        lives.stopped(20, t(5) + 4000);
        let paths = |v: &[std::path::PathBuf]| v.iter().map(|p| p.display().to_string()).collect::<Vec<_>>();
        let (chain, open) = lives.ancestors(40, t(5) + 2000);
        assert_eq!(paths(&chain), [bash2, bash1, claude], "nächster Starter zuerst, auch wenn er schon beendet ist");
        assert_eq!(open, None);
        // The ID 20 is used again later by another program: the chain of the old start stays the same.
        lives.started(20, t(9), r"C:\Windows\System32\notepad.exe");
        assert_eq!(paths(&lives.ancestors(40, t(5) + 2000).0), [bash2, bash1, claude]);
        // The work program began before the service did: the chain ends open at its ID.
        let mut late = Lives::default();
        late.started(20, t(5), bash1);
        late.set_parent(20, t(5), 10);
        assert_eq!(late.ancestors(20, t(5)), (Vec::new(), Some((10, t(5)))));
        assert_eq!(late.ancestors(99, t(5)), (Vec::new(), None), "unbekannter Prozess");
    }

    #[test]
    fn file_events_go_to_the_process_that_had_the_id_at_that_time() {
        let t = |n: i64| n * 100_000_000; // steps of 10 s
        let a = r"C:\Users\x\Downloads\dieb.exe".to_string();
        let b = r"C:\Windows\System32\notepad.exe".to_string();
        let mut lives = Lives::default();
        // A runs from 1 to 2, B gets the same ID at 3 and is still running.
        lives.started(100, t(1), &a);
        lives.stopped(100, t(2));
        lives.started(100, t(3), &b);
        let live_b = Some((b.clone(), t(3)));
        assert_eq!(lives.owner(100, t(1) + 5, live_b.clone()), Owner::Known(a.clone()), "Ereignis kommt verspätet an, A ist schon beendet");
        assert_eq!(lives.owner(100, t(4), live_b.clone()), Owner::Known(b.clone()));
        assert_eq!(lives.owner(100, t(2) + 5, live_b.clone()), Owner::Unsure, "zwischen den Prozessen: nicht raten");
        // Without a stop event the next start ends A; the switch-over moment is ambiguous.
        let mut lives = Lives::default();
        lives.started(7, t(1), &a);
        lives.started(7, t(3), &b);
        assert_eq!(lives.owner(7, t(2), None), Owner::Known(a.clone()));
        assert_eq!(lives.owner(7, t(3), None), Owner::Unsure);
        // Programs running before the service started are taken over at its start: a browser
        // that was open then and writes its file while closing is known although it has ended.
        let mut seeded = Lives::default();
        assert_eq!(seeded.seed([(70, t(1), a.clone()), (71, t(1), "nur-name.exe".to_string())].into_iter()), 1, "nur volle Pfade");
        assert_eq!(seeded.owner(70, t(9), None), Owner::Known(a.clone()));
        assert_eq!(seeded.owner(71, t(9), None), Owner::Unsure);
        seeded.stopped(70, t(10));
        assert_eq!(seeded.owner(70, t(9) + 5, None), Owner::Known(a.clone()), "beendet, das Ereignis kommt verspätet");
        // Unknown start (process older than the service): only the running process, if it existed then.
        let empty = Lives::default();
        assert_eq!(empty.owner(9, t(5), Some((b.clone(), t(4)))), Owner::Known(b.clone()));
        assert_eq!(empty.owner(9, t(5), Some((b.clone(), t(6)))), Owner::Unsure, "neuer Prozess mit alter ID");
        assert_eq!(empty.owner(9, t(5), None), Owner::Unsure);
        // Ended lives are dropped after a while, running ones stay.
        lives.prune(t(3) + 1);
        assert_eq!(lives.owner(7, t(4), None), Owner::Known(b));
        assert_eq!(lives.owner(7, t(2), None), Owner::Unsure);
    }

    #[test]
    fn a_forged_command_line_never_decides_who_read_the_file() {
        // A stealer starts itself as "C:\Program Files\Google\Chrome\Application\chrome.exe" in
        // argv[0] and ends at once. The classic start event knows only the file name, the
        // command line is not used for the life at all.
        let t = |n: i64| n * 100_000_000;
        let real = r"C:\Users\x\AppData\Local\Temp\dieb.exe";
        let mut lives = Lives::default();
        lives.started(40, t(1), "dieb.exe");
        assert_eq!(lives.owner(40, t(1) + 5, None), Owner::Unsure, "nur ein Name: nicht sicher");
        assert_eq!(lives.name_hint(40, t(1) + 5).as_deref(), Some("dieb.exe"), "der Name steht als Hinweis in der Meldung");
        assert_eq!(lives.name_hint(99, t(1) + 5), None, "unbekannte ID: kein Hinweis");
        // The Kernel-Process event of the same start brings the real path (in any order).
        lives.started(40, t(1) + 3, real);
        assert_eq!(lives.owner(40, t(1) + 5, None), Owner::Known(real.into()));
        lives.started(40, t(1) + 4, "chrome.exe");
        assert_eq!(lives.owner(40, t(1) + 5, None), Owner::Known(real.into()), "ein Name überschreibt nie den vollen Pfad");
        // Only a name, but the process is still running and started then: its real path counts.
        let mut lives = Lives::default();
        lives.started(41, t(1), "dieb.exe");
        assert_eq!(lives.owner(41, t(1) + 5, Some((real.into(), t(1)))), Owner::Known(real.into()));
        assert_eq!(lives.owner(41, t(1) + 5, Some((real.into(), t(5)))), Owner::Unsure, "laufender Prozess ist ein anderer");
    }

    #[test]
    fn real_dos_devices_resolve_system_drive() {
        let d = DosDevices::load();
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let nt = d.0.iter().find(|(_, l)| l.eq_ignore_ascii_case(&drive)).map(|(n, _)| n.clone()).unwrap();
        assert_eq!(d.to_win32(&format!("{nt}\\Windows")), format!("{drive}\\Windows"));
    }
}
