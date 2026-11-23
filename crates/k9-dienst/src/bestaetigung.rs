//! Confirmation window for decisions that weaken the protection (releases,
//! restoring from quarantine, taking over weaker settings, pausing the agent).
//!
//! The service starts `k9.exe bestaetigen` from the protected program
//! folder in the user's session with the user's *elevated* token: Windows
//! (UIPI) then prevents normal programs from clicking or typing into it, so
//! the dashboard or a program with the user's rights cannot confirm remotely.
//! The window shows only static text built from the service's own data and
//! the buttons "Ja"/"Nein"; no answer within 2 minutes counts as "Nein".

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::Svc;

/// Exit code of the window for "Ja" (IDYES).
const YES: u32 = 6;
const TIMEOUT: Duration = Duration::from_secs(120);

/// One window at a time.
static ONE: Mutex<()> = Mutex::new(());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Text for the command line: no quotes, no control characters, limited length.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if c == '"' { '\'' } else if c.is_control() && c != '\n' { ' ' } else { c })
        .map(|c| if c == '\n' { '|' } else { c })
        .take(max)
        .collect()
}

/// Asks the user; Ok only after "Ja" in the protected window.
pub fn confirm(svc: &Svc, title: &str, text: &str) -> Result<()> {
    let _one = ONE.lock().unwrap();
    k9_core::schutz::as_system(|| ask(svc, title, text))
}

fn ask(svc: &Svc, title: &str, text: &str) -> Result<()> {
    let exe = k9_core::dienst::install_dir().join("k9.exe");
    if !exe.is_file() || !k9_core::dienst::is_installed_program(&exe) {
        bail!("Bestätigungsfenster nicht verfügbar ({} fehlt)", exe.display());
    }
    let token = crate::wache::elevated_user_token(&svc.settings.user_sid).context("Niemand angemeldet – Bestätigung nicht möglich")?;
    let cmd = format!("\"{}\" bestaetigen --titel \"{}\" --text \"{}\"", exe.display(), clean(title, 120), clean(text, 1500));
    let mut cmd_w = wide(&cmd);
    let app = wide(&exe.display().to_string());
    let dir = wide(&k9_core::dienst::install_dir().display().to_string());
    let mut desktop = wide("winsta0\\default");
    // SAFETY: buffers live until the calls return; handles closed below.
    let result = unsafe {
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, Some(token), false).is_ok();
        let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        let r = CreateProcessAsUserW(
            Some(token),
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            if have_env { Some(env) } else { None },
            PCWSTR(dir.as_ptr()),
            &si,
            &mut pi,
        );
        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(token);
        r.context("Bestätigungsfenster konnte nicht gestartet werden")?;
        let _ = CloseHandle(pi.hThread);
        let waited = WaitForSingleObject(pi.hProcess, TIMEOUT.as_millis() as u32);
        let mut code = 0u32;
        if waited == WAIT_OBJECT_0 {
            let _ = GetExitCodeProcess(pi.hProcess, &mut code);
        } else {
            let _ = TerminateProcess(pi.hProcess, 1);
        }
        let _ = CloseHandle(pi.hProcess);
        code
    };
    if result == YES {
        tracing::info!("Bestätigt: {title}");
        Ok(())
    } else {
        tracing::info!("Nicht bestätigt: {title}");
        bail!("Nicht bestätigt – es wurde nichts geändert")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_cannot_break_out_of_the_command_line() {
        let c = clean("a\"b\r\nc\u{7}d", 100);
        assert!(!c.contains('"'));
        assert!(!c.chars().any(|x| x.is_control()));
        assert_eq!(clean(&"x".repeat(5000), 10).len(), 10);
    }
}
