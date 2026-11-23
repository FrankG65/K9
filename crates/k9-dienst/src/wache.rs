//! Agent-Wache (self-protection): keeps the agent running in the user's
//! session and reports when it disappears without the user asking for it.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use k9_core::model::{Finding, Kind, Severity};
use k9_core::realtime as rt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcess, WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOW,
};

use crate::Svc;

/// How long the agent may be missing after logon before the service starts it
/// itself (the logon autostart usually does it first).
const LOGON_GRACE: Duration = Duration::from_secs(180);
const CHECK: Duration = Duration::from_secs(5);
/// A missing agent is reported only if the service and the user session are
/// still there after this time: at a restart/shutdown Windows ends the agent
/// a few seconds before it stops the service – that is no alarm.
const REPORT_DELAY: Duration = Duration::from_secs(30);

/// A notice finding (nothing to act on, only "Gesehen").
pub fn notice(rule: &str, title: &str, hint: &str) -> Finding {
    let now = k9_core::now_string();
    Finding {
        path: PathBuf::from(format!("{title} ({now})")),
        // Unique per event: every stop is reported, a decision never hides the next one.
        sha256: k9_core::sha256_hex(format!("hinweis|{rule}|{now}|{}", dienst_nonce()).as_bytes()),
        size: 0,
        rule_id: rule.into(),
        threat_name: title.into(),
        category: k9_core::t!("Selbstschutz", "Self-protection").into(),
        severity: Severity::Hoch,
        engine: "dienst".into(),
        kind: Kind::Hinweis,
        details: Some(serde_json::json!({ "hinweis": hint })),
    }
}

fn dienst_nonce() -> String {
    hex_encode(&k9_core::random_bytes(8))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn run(svc: Arc<Svc>) {
    if !k9_core::dienst::is_installed_program(std::path::Path::new(&svc.settings.agent_path)) {
        // Never start a program from a user-writable folder with the service.
        tracing::warn!(
            "Agent-Wache aus: {} liegt nicht in {} – bitte 'k9 dienst aktualisieren' ausführen",
            svc.settings.agent_path,
            k9_core::dienst::install_dir().display()
        );
        return;
    }
    svc.watchdog.store(true, Ordering::Relaxed);
    let mut seen_running = false;
    let mut missing_since: Option<Instant> = None;
    let mut misses = 0u32;
    let mut pending_report: Option<Instant> = None;
    loop {
        std::thread::sleep(CHECK);
        if svc.is_stopping() {
            return;
        }
        let Some(session) = user_session(&svc.settings.user_sid) else {
            // Nobody (or another user) logged on: nothing to guard, no alarm at logoff.
            seen_running = false;
            missing_since = None;
            misses = 0;
            pending_report = None;
            continue;
        };
        if pending_report.is_some_and(|t| t.elapsed() >= REPORT_DELAY) {
            pending_report = None;
            svc.report(&agent_stopped_notice());
        }
        if agent_running(&svc, session) {
            // Running again (restarted by the user or by us): a pause is used up
            // (not in the first 30 s – the agent is still shutting down then).
            let mut p = svc.agent_pause.lock().unwrap();
            if p.is_some_and(|(_, set)| set.elapsed() > Duration::from_secs(30)) {
                *p = None;
            }
            drop(p);
            seen_running = true;
            missing_since = None;
            misses = 0;
            continue;
        }
        let paused = {
            let mut p = svc.agent_pause.lock().unwrap();
            match *p {
                Some((until, _)) if Instant::now() < until => true,
                Some(_) => {
                    *p = None;
                    false
                }
                None => false,
            }
        };
        if paused {
            seen_running = false;
            missing_since = None;
            continue;
        }
        if seen_running {
            // Two checks in a row: no alarm for a short restart.
            misses += 1;
            if misses < 2 {
                continue;
            }
            seen_running = false;
            misses = 0;
            tracing::warn!("Selbstschutz: Agent läuft nicht mehr – wird neu gestartet");
            // Reported after REPORT_DELAY unless Windows is restarting or the user logs off.
            pending_report = Some(Instant::now());
            start_agent_logged(&svc, session);
            continue;
        }
        let since = *missing_since.get_or_insert_with(Instant::now);
        let after_update = svc.started_by_update.load(Ordering::Relaxed) && svc.started.elapsed() < LOGON_GRACE;
        if start_now(since.elapsed(), session_age(session), after_update) {
            tracing::info!("Agent läuft nicht – Dienst startet ihn");
            start_agent_logged(&svc, session);
            missing_since = None;
        }
    }
}

/// Start a missing agent now? Right after a logon (session younger than LOGON_GRACE) the
/// user's own autostart gets time first; otherwise, and always right after
/// `k9 dienst aktualisieren` (run from an administrator PowerShell nobody else starts the
/// agent), after two checks. The agent allows only one instance per user, so a race with the
/// autostart or a non-elevated `k9` never leads to two agents.
pub fn start_now(missing_for: Duration, session_age: Option<Duration>, after_update: bool) -> bool {
    if missing_for >= LOGON_GRACE {
        return true;
    }
    (after_update || session_age.is_some_and(|a| a >= LOGON_GRACE)) && missing_for >= 2 * CHECK
}

/// How long the user of the session has been logged on.
fn session_age(session: u32) -> Option<Duration> {
    use windows::Win32::System::RemoteDesktop::{WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfo, WTSINFOW, WTS_CURRENT_SERVER_HANDLE};
    let mut buf = windows::core::PWSTR::null();
    let mut len = 0u32;
    // SAFETY: buffer from WTS, freed below; size checked before reading.
    unsafe {
        WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), session, WTSSessionInfo, &mut buf, &mut len).ok()?;
        let logon = (len as usize >= std::mem::size_of::<WTSINFOW>()).then(|| (*(buf.0 as *const WTSINFOW)).LogonTime);
        WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
        let logon = logon?.max(0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos() as i64 / 100 + 116_444_736_000_000_000;
        (logon > 0 && now > logon).then(|| Duration::from_secs(((now - logon) / 10_000_000) as u64))
    }
}

fn agent_stopped_notice() -> Finding {
    notice(
        "SELBSTSCHUTZ:AGENT-BEENDET",
        k9_core::t!("Der K9-Agent wurde unerwartet beendet", "The K9 agent was ended unexpectedly"),
        k9_core::t!("Der Agent lief nicht mehr, ohne dass er über „k9 agent-beenden“ beendet wurde. Der Dienst hat ihn neu gestartet. \
         Wenn du ihn nicht selbst beendet hast (z. B. im Task-Manager), könnte ein Programm versucht haben, den Schutz abzuschalten – \
         starte dann einen vollständigen Scan.", "The agent was no longer running without having been ended via “k9 agent-beenden”. The service has started it again. If you did not end it yourself (e.g. in Task Manager), a program might have tried to switch off the protection – then start a full scan."),
    )
}

fn start_agent_logged(svc: &Svc, session: u32) {
    match start_agent(&svc.settings.agent_path, session) {
        Ok(pid) => tracing::info!("Agent gestartet (PID {pid})"),
        Err(e) => tracing::warn!("Agent konnte nicht gestartet werden: {e:#}"),
    }
}

/// Token of the logged-on installing user for the confirmation window: the
/// elevated (linked) token if the user is an administrator, so programs with
/// normal rights cannot operate the window (UIPI).
pub fn elevated_user_token(sid: &str) -> Option<HANDLE> {
    use windows::Win32::Security::{GetTokenInformation, TokenLinkedToken, TOKEN_LINKED_TOKEN};
    let token = user_token(user_session(sid)?)?;
    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut len = 0u32;
    // SAFETY: fixed-size output struct; needs SE_TCB (LocalSystem) for a usable primary token.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenLinkedToken,
            Some(&mut linked as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut len,
        )
        .is_ok()
    };
    if ok && !linked.LinkedToken.is_invalid() {
        // SAFETY: token from WTSQueryUserToken.
        unsafe {
            let _ = CloseHandle(token);
        }
        return Some(linked.LinkedToken);
    }
    Some(token)
}

/// Runs `f` with the rights of the installing user, if logged on at the console.
pub fn as_session_user<R>(sid: &str, f: impl FnOnce() -> R) -> Option<R> {
    let token = user_token(user_session(sid)?)?;
    let r = k9_core::schutz::with_user(token, f);
    // SAFETY: token from WTSQueryUserToken.
    unsafe {
        let _ = CloseHandle(token);
    }
    Some(r)
}

/// Session id of the console session if the installing user is logged on there.
/// The user's active session: the console first, otherwise any active session
/// (Remote Desktop, Windows Sandbox – they do not use the console session).
fn user_session(sid: &str) -> Option<u32> {
    // SAFETY: plain query.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let console = (console != u32::MAX).then_some(console);
    pick_session(console, &active_sessions(), |session| {
        let Some(token) = user_token(session) else { return false };
        let same = token_sid(token).is_some_and(|s| s.eq_ignore_ascii_case(sid));
        // SAFETY: token from WTSQueryUserToken.
        unsafe {
            let _ = CloseHandle(token);
        }
        same
    })
}

/// Only a session of the registered user counts: the console first, then the active
/// (never disconnected) sessions. Sessions of other users are never chosen.
fn pick_session(console: Option<u32>, active: &[u32], is_owner: impl Fn(u32) -> bool) -> Option<u32> {
    console.into_iter().chain(active.iter().copied().filter(|s| Some(*s) != console)).find(|&s| is_owner(s))
}

/// IDs of all sessions in the state "active".
fn active_sessions() -> Vec<u32> {
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: out pointers valid; the array is freed with WTSFreeMemory.
    unsafe {
        if WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count).is_err() || info.is_null() {
            return Vec::new();
        }
        let ids = std::slice::from_raw_parts(info, count as usize)
            .iter()
            .filter(|s| s.State == WTSActive)
            .map(|s| s.SessionId)
            .collect();
        WTSFreeMemory(info as _);
        ids
    }
}

fn user_token(session: u32) -> Option<HANDLE> {
    let mut token = HANDLE::default();
    // SAFETY: needs SE_TCB (LocalSystem); out pointer valid.
    unsafe { WTSQueryUserToken(session, &mut token).ok()? };
    Some(token)
}

fn token_sid(token: HANDLE) -> Option<String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    // SAFETY: buffer sized by the first call.
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), len, &mut len).ok()?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).ok()?;
        let sid = s.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        sid
    }
}

/// Is the agent program running in the given session?
fn agent_running(svc: &Svc, session: u32) -> bool {
    agent_pid(svc, session).is_some()
}

/// Process ID of the installed agent running in this session.
fn agent_pid(svc: &Svc, session: u32) -> Option<u32> {
    let name = std::path::Path::new(&svc.settings.agent_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    rt::process_snapshot()
        .values()
        .filter(|p| p.name.to_lowercase() == name)
        .find(|p| {
            let mut s = 0u32;
            // SAFETY: plain query.
            let in_session = unsafe { ProcessIdToSessionId(p.pid, &mut s).is_ok() } && s == session;
            in_session && rt::process_path(p.pid).is_some_and(|x| svc.is_agent(&x))
        })
        .map(|p| p.pid)
}

/// Was the end of the agent an attack on K9? Not when the service itself is stopping (an
/// update stops the service before it ends the agent), when the user confirmed a pause
/// (every pause needs the confirmation window), or when nobody is logged on any more.
fn hostile_end(stopping: bool, paused: bool, session_present: bool) -> bool {
    !stopping && !paused && session_present
}

/// Notices the end of the agent at once. The regular watch looks every five seconds and
/// waits for two misses – far too slow for malware that switches the protection off and
/// starts its work seconds later (Conti in the test of 21.11.2026: agent ended, five seconds
/// later the service). This thread waits on the agent's process itself and tells the event
/// loop, which treats the end as a critical step of every attack chain still running.
/// Restarting the agent and the ordinary notice stay with the regular watch.
pub fn run_instant(svc: Arc<Svc>) {
    loop {
        if svc.is_stopping() {
            return;
        }
        let Some(pid) = user_session(&svc.settings.user_sid).and_then(|s| agent_pid(&svc, s)) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        // SAFETY: a handle only to wait on; closed below.
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let mut ended = false;
        while !svc.is_stopping() {
            // SAFETY: the handle is valid until CloseHandle below.
            if unsafe { WaitForSingleObject(handle, 1000) } == WAIT_OBJECT_0 {
                ended = true;
                break;
            }
        }
        // SAFETY: opened above.
        unsafe {
            let _ = CloseHandle(handle);
        }
        if !ended {
            return;
        }
        let paused = svc.agent_pause.lock().unwrap().is_some_and(|(until, _)| Instant::now() < until);
        let session_present = user_session(&svc.settings.user_sid).is_some();
        if hostile_end(svc.is_stopping(), paused, session_present) {
            tracing::warn!("Selbstschutz: Agent (PID {pid}) wurde von außen beendet");
            crate::etw::agent_ended();
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Starts the agent hidden (conhost --headless, like the logon autostart)
/// in the user's session with the user's normal (not elevated) rights.
fn start_agent(agent: &str, session: u32) -> Result<u32> {
    if !std::path::Path::new(agent).is_file() {
        bail!("{agent} nicht gefunden");
    }
    let Some(token) = user_token(session) else { bail!("Kein Benutzer-Token für Sitzung {session}") };
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let conhost = format!("{system_root}\\System32\\conhost.exe");
    let mut cmd = wide(&format!("\"{conhost}\" --headless \"{agent}\""));
    let app = wide(&conhost);
    let dir = std::path::Path::new(agent).parent().map(|p| p.display().to_string()).unwrap_or_default();
    let dir_w = wide(&dir);
    let mut desktop = wide("winsta0\\default");
    // SAFETY: all buffers live until the call returns; handles closed below.
    unsafe {
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, Some(token), false).is_ok();
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let r = CreateProcessAsUserW(
            Some(token),
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
            if have_env { Some(env) } else { None },
            PCWSTR(dir_w.as_ptr()),
            &si,
            &mut pi,
        );
        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(token);
        r?;
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        Ok(pi.dwProcessId)
    }
}

#[cfg(test)]
mod tests {
    use super::{pick_session, start_now, CHECK, LOGON_GRACE};
    use std::time::Duration;

    #[test]
    fn a_missing_agent_is_started_right_away_unless_the_user_just_logged_on() {
        let long = Some(Duration::from_secs(3600));
        // Agent killed while the user has been logged on for an hour: start after two checks.
        assert!(!start_now(CHECK, long, false));
        assert!(start_now(2 * CHECK, long, false));
        // Fresh logon: the user's own autostart gets the grace time first.
        assert!(!start_now(2 * CHECK, Some(Duration::from_secs(30)), false));
        // Logon time unknown: grace time as before.
        assert!(!start_now(2 * CHECK, None, false));
        // Right after "k9 dienst aktualisieren": promptly, even from an administrator
        // PowerShell (there k9 does not start the agent) and whatever the session age.
        assert!(!start_now(CHECK, long, true));
        assert!(start_now(2 * CHECK, long, true));
        assert!(start_now(2 * CHECK, None, true));
        assert!(start_now(2 * CHECK, Some(Duration::from_secs(30)), true));
        // After the grace time always.
        assert!(start_now(LOGON_GRACE, None, true));
    }

    #[test]
    fn the_end_of_the_agent_is_hostile_unless_it_was_wanted() {
        // (service stopping, pause confirmed by the user, somebody still logged on)
        use super::hostile_end;
        assert!(hostile_end(false, false, true), "weder Update noch Pause noch Abmeldung");
        assert!(!hostile_end(true, false, true), "der Dienst wird selbst beendet (Update, Herunterfahren)");
        assert!(!hostile_end(false, true, true), "vom Nutzer im Bestätigungsfenster erlaubte Pause");
        assert!(!hostile_end(false, false, false), "niemand mehr angemeldet");
    }

    #[test]
    fn only_sessions_of_the_owner_are_chosen() {
        // Console belongs to another user, the owner is in a Remote-Desktop/Sandbox session.
        assert_eq!(pick_session(Some(1), &[1, 3], |s| s == 3), Some(3));
        // Owner at the console: preferred over an active RDP session of the owner.
        assert_eq!(pick_session(Some(1), &[1, 3], |_| true), Some(1));
        // Only other users logged on: no session.
        assert_eq!(pick_session(Some(1), &[1, 2], |_| false), None);
        // No console session at all.
        assert_eq!(pick_session(None, &[4], |s| s == 4), Some(4));
        assert_eq!(pick_session(None, &[], |_| true), None);
    }
}
