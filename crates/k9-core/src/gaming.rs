//! Gaming detection and idle time.
//!
//! A game is assumed when Windows reports a fullscreen/D3D/presentation state
//! (SHQueryUserNotificationState) or a process runs from a configured game
//! folder / with a configured process name.

use std::time::Duration;

use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::Shell::{
    SHQueryUserNotificationState, QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
};

use crate::config::GamingConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GamingState {
    pub active: bool,
    pub reason: Option<String>,
}

/// Checks whether the user is currently gaming. Cheap enough to call every few seconds.
pub fn detect(cfg: &GamingConfig) -> GamingState {
    if !cfg.aktiv {
        return GamingState::default();
    }
    if cfg.vollbild_erkennen {
        if let Some(reason) = fullscreen_state() {
            return GamingState { active: true, reason: Some(reason.into()) };
        }
    }
    if cfg.spiele_prozesse.is_empty() && cfg.spiele_ordner.is_empty() {
        return GamingState::default();
    }
    let names: Vec<String> = cfg.spiele_prozesse.iter().map(|s| s.to_lowercase()).collect();
    let folders: Vec<String> = cfg.spiele_ordner.iter().map(|s| s.to_lowercase()).collect();
    let no_games: Vec<String> = cfg.keine_spiele.iter().map(|s| s.to_lowercase()).collect();
    for (pid, exe) in processes() {
        if names.contains(&exe.to_lowercase()) {
            return GamingState { active: true, reason: Some(tf!("Spiel-Prozess {exe}", "game process {exe}")) };
        }
        // A helper program from a games folder (overlay, wallpaper tool) is no game.
        if folders.is_empty() || no_games.contains(&exe.to_lowercase()) {
            continue;
        }
        if let Some(path) = process_path(pid) {
            let lower = path.to_lowercase();
            if folders.iter().any(|f| lower.contains(f.as_str())) {
                return GamingState { active: true, reason: Some(tf!("Spiel aus Spieleordner: {exe}", "game from a games folder: {exe}")) };
            }
        }
    }
    GamingState::default()
}

fn fullscreen_state() -> Option<&'static str> {
    // SAFETY: simple query without pointers.
    let state = unsafe { SHQueryUserNotificationState() }.ok()?;
    if state == QUNS_RUNNING_D3D_FULL_SCREEN {
        Some("Direct3D-Vollbildanwendung")
    } else if state == QUNS_BUSY {
        Some("Vollbildanwendung")
    } else if state == QUNS_PRESENTATION_MODE {
        Some(t!("Präsentationsmodus", "presentation mode"))
    } else {
        None
    }
}

/// (pid, exe file name) of all running processes.
fn processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    // SAFETY: snapshot handle is closed below; entry has correct dwSize.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
                out.push((entry.th32ProcessID, String::from_utf16_lossy(&entry.szExeFile[..len])));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

fn process_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    // SAFETY: handle closed below; buffer length passed correctly.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(handle);
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Time since the last keyboard/mouse input of the interactive user.
/// Note: gamepad input is not counted by Windows – gaming detection covers that.
pub fn idle_duration() -> Duration {
    let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    // SAFETY: info has correct cbSize.
    unsafe {
        if !GetLastInputInfo(&mut info).as_bool() {
            return Duration::ZERO;
        }
        let now = GetTickCount();
        Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_mode_never_reports_gaming() {
        let cfg = GamingConfig { aktiv: false, ..Default::default() };
        assert!(!detect(&cfg).active);
    }

    #[test]
    fn detects_configured_process_name() {
        // The test runner itself is a running process -> must be found by name.
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().to_string();
        let cfg = GamingConfig {
            aktiv: true,
            vollbild_erkennen: false,
            spiele_prozesse: vec![name.to_uppercase()],
            spiele_ordner: vec![],
            ..Default::default()
        };
        assert!(detect(&cfg).active);
        assert!(!processes().is_empty());
        let _ = idle_duration();
    }

    #[test]
    fn a_helper_program_in_a_games_folder_is_no_game() {
        // The test runner lies in its folder: with that folder as a games folder it is a game …
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().to_string();
        let folder = format!("\\{}\\", exe.parent().unwrap().file_name().unwrap().to_string_lossy());
        let mut cfg = GamingConfig { aktiv: true, vollbild_erkennen: false, spiele_prozesse: vec![], spiele_ordner: vec![folder], keine_spiele: vec![], ..Default::default() };
        let seen = detect(&cfg);
        assert!(seen.active, "Ordner {:?}", cfg.spiele_ordner);
        // … unless every program found there is listed as "no game". (Other test runners may
        // run in the same folder: list whatever is reported until nothing is left.)
        let mut state = seen;
        for _ in 0..50 {
            let Some(reason) = state.reason.clone().filter(|_| state.active) else { break };
            cfg.keine_spiele.push(reason.rsplit(": ").next().unwrap().to_uppercase());
            state = detect(&cfg);
        }
        assert!(!state.active, "{:?}", state.reason);
        assert!(cfg.keine_spiele.iter().any(|n| n.eq_ignore_ascii_case(&name)));
        // Named explicitly as a game it counts, whatever the other list says.
        cfg.spiele_prozesse = vec![name.clone()];
        assert!(detect(&cfg).active);
        // The defaults know the usual helpers.
        assert!(GamingConfig::default().keine_spiele.contains(&"crosshairx.exe".to_string()));
    }
}
