//! K9 icon in the notification area (tray): shows the state at a glance.
//! Normal = all quiet, amber dot = open finding (Mittel/Hoch), red dot = open Kritisch finding,
//! grey = the Windows service is not reachable. Left click opens the dashboard, the right-click
//! menu offers the dashboard. Ending the agent stays `k9 agent-beenden` (with confirmation).

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;

use k9_core::model::Severity;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW,
    GetSystemMetrics, KillTimer, LoadImageW, PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetTimer,
    TrackPopupMenu, HICON, HWND_MESSAGE, IMAGE_ICON, LR_SHARED, MF_STRING, MSG, SM_CXSMICON, SM_CYSMICON, TPM_RIGHTBUTTON, WINDOW_EX_STYLE,
    WM_APP, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
};

use crate::Shared;

/// State shown by the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Normal,
    Warnung,
    Kritisch,
    Gestoppt,
}

impl State {
    /// Icon resource of the agent (see build.rs).
    fn icon_id(self) -> usize {
        match self {
            State::Normal => 2,
            State::Warnung => 3,
            State::Kritisch => 4,
            State::Gestoppt => 5,
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            State::Normal => k9_core::t!("K9: alles ruhig", "K9: all quiet"),
            State::Warnung => k9_core::t!("K9: neue Meldung", "K9: new finding"),
            State::Kritisch => k9_core::t!("K9: kritische Meldung", "K9: critical finding"),
            State::Gestoppt => k9_core::t!("K9: Dienst gestoppt", "K9: service stopped"),
        }
    }
}

/// The state from the open findings and whether the service is reachable (a stopped service
/// matters most, then a critical finding).
pub fn state(service_ok: bool, open: &[Severity]) -> State {
    if !service_ok {
        State::Gestoppt
    } else if open.contains(&Severity::Kritisch) {
        State::Kritisch
    } else if open.iter().any(|s| *s >= Severity::Mittel) {
        State::Warnung
    } else {
        State::Normal
    }
}

const WM_TRAY: u32 = WM_APP + 1;
const ID_DASHBOARD: usize = 1;
const TIMER: usize = 1;
static WINDOW: AtomicIsize = AtomicIsize::new(0);
static SHARED: std::sync::OnceLock<Arc<Shared>> = std::sync::OnceLock::new();
static TASKBAR_CREATED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

fn current_state(s: &Shared) -> State {
    let service_ok = s.app.paths.portable || k9_core::dienst::service_running();
    let open: Vec<Severity> = s.app.store().and_then(|st| st.pending_detections()).map(|d| d.into_iter().filter(|d| !k9_core::arbeitsordner::is_quiet(d)).map(|d| d.severity).collect()).unwrap_or_default();
    state(service_ok, &open)
}

fn data(hwnd: HWND, st: State) -> NOTIFYICONDATAW {
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_ICON | NIF_TIP | NIF_MESSAGE,
        uCallbackMessage: WM_TRAY,
        ..Default::default()
    };
    // SAFETY: own module; icon resources 2..5 exist (build.rs); shared icons are not destroyed.
    unsafe {
        if let Ok(m) = GetModuleHandleW(None) {
            let (cx, cy) = (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
            if let Ok(h) = LoadImageW(Some(m.into()), PCWSTR(std::ptr::without_provenance(st.icon_id())), IMAGE_ICON, cx, cy, LR_SHARED) {
                nid.hIcon = HICON(h.0);
            }
        }
    }
    for (i, c) in st.tooltip().encode_utf16().take(nid.szTip.len() - 1).enumerate() {
        nid.szTip[i] = c;
    }
    nid
}

fn open_dashboard(s: &Shared) {
    let url = format!("http://127.0.0.1:{}/?t={}", s.port(), s.token);
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let shared = SHARED.get();
    // SAFETY: plain Win32 calls on our own window.
    unsafe {
        if Some(&msg) == TASKBAR_CREATED.get() {
            // Explorer restarted: show the icon again.
            if let Some(s) = shared {
                let _ = Shell_NotifyIconW(NIM_ADD, &data(hwnd, current_state(s)));
            }
            return LRESULT(0);
        }
        match msg {
            WM_TIMER => {
                if let Some(s) = shared {
                    if s.stopping.load(Ordering::Relaxed) {
                        let _ = DestroyWindow(hwnd);
                    } else {
                        let _ = Shell_NotifyIconW(NIM_MODIFY, &data(hwnd, current_state(s)));
                    }
                }
                LRESULT(0)
            }
            WM_TRAY => {
                let event = (lparam.0 & 0xFFFF) as u32;
                if event == WM_LBUTTONUP {
                    if let Some(s) = shared {
                        open_dashboard(s);
                    }
                } else if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
                    if let Ok(menu) = CreatePopupMenu() {
                        let _ = AppendMenuW(menu, MF_STRING, ID_DASHBOARD, if k9_core::sprache::en() { w!("Open dashboard") } else { w!("Dashboard öffnen") });
                        let mut pt = POINT::default();
                        let _ = GetCursorPos(&mut pt);
                        let _ = SetForegroundWindow(hwnd);
                        let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, Some(0), hwnd, None);
                        let _ = DestroyMenu(menu);
                    }
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                if wparam.0 & 0xFFFF == ID_DASHBOARD {
                    if let Some(s) = shared {
                        open_dashboard(s);
                    }
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                let _ = KillTimer(Some(hwnd), TIMER);
                let nid = NOTIFYICONDATAW { cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: 1, ..Default::default() };
                let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Starts the tray icon on its own thread (with its own message loop).
pub fn start(shared: Arc<Shared>) {
    let _ = SHARED.set(shared);
    let _ = std::thread::Builder::new().name("k9-tray".into()).spawn(|| {
        // SAFETY: window class/window of this thread; the message loop runs until WM_DESTROY.
        unsafe {
            let Ok(module) = GetModuleHandleW(None) else { return };
            let class = w!("K9TrayFenster");
            let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: module.into(), lpszClassName: class, ..Default::default() };
            RegisterClassW(&wc);
            let _ = TASKBAR_CREATED.set(RegisterWindowMessageW(w!("TaskbarCreated")));
            let Ok(hwnd) = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("K9"), WS_OVERLAPPED, 0, 0, 0, 0, Some(HWND_MESSAGE), None, Some(module.into()), None)
            else {
                tracing::warn!("Symbol im Infobereich nicht verfügbar");
                return;
            };
            WINDOW.store(hwnd.0 as isize, Ordering::Relaxed);
            if let Some(s) = SHARED.get() {
                let _ = Shell_NotifyIconW(NIM_ADD, &data(hwnd, current_state(s)));
            }
            SetTimer(Some(hwnd), TIMER, 30_000, None);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    });
}

/// Removes the icon (agent ends).
pub fn stop() {
    let h = WINDOW.load(Ordering::Relaxed);
    if h != 0 {
        // SAFETY: our window handle; the message is handled on the tray thread.
        unsafe {
            let _ = PostMessageW(Some(HWND(h as *mut _)), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_icon_shows_the_most_important_state() {
        assert_eq!(state(true, &[]), State::Normal);
        assert_eq!(state(true, &[Severity::Niedrig]), State::Normal);
        assert_eq!(state(true, &[Severity::Niedrig, Severity::Mittel]), State::Warnung);
        assert_eq!(state(true, &[Severity::Hoch, Severity::Kritisch]), State::Kritisch);
        assert_eq!(state(false, &[Severity::Kritisch]), State::Gestoppt);
        assert_eq!(State::Kritisch.tooltip(), "K9: kritische Meldung");
    }
}
