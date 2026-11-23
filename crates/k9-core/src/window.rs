//! Own notification window ("Meldefenster"), independent of the Windows
//! notification settings. Uses the native TaskDialog (comctl32 v6) with four
//! command-link buttons: Quarantäne, Löschen/Deaktivieren, Freigabe, Später.
//!
//! TaskDialogIndirect is resolved at runtime: it only exists when the
//! executable carries a Common-Controls-6 manifest (k9-agent and k9 embed
//! one via build.rs). Without it, [`available`] returns false.

use anyhow::{bail, Result};
use windows::core::{BOOL, HRESULT, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, S_OK, WPARAM};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::{
    TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TASKDIALOG_NOTIFICATIONS, TDF_ALLOW_DIALOG_CANCELLATION, TDF_ENABLE_HYPERLINKS, TDF_USE_COMMAND_LINKS,
    TDN_CREATED, TDN_HYPERLINK_CLICKED, TD_INFORMATION_ICON, TD_WARNING_ICON,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    SetForegroundWindow, SetWindowPos, HWND_TOPMOST, SWP_NOMOVE, SWP_NOSIZE, SW_SHOWNORMAL,
};

use crate::model::{Action, Detection, Kind};

/// What the user chose in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowChoice {
    Decide(Action),
    /// Keep the detection pending and ask again later.
    Later,
}

const ID_BASE: i32 = 101;
const ID_LATER: i32 = 199;

fn button_id(a: Action) -> i32 {
    ID_BASE + Action::ALL.iter().position(|x| *x == a).unwrap_or(0) as i32
}

/// Maps a TaskDialog button id to the user's choice. Closing the window
/// (Esc, X, IDCANCEL) counts as "Später" – nothing is ever decided implicitly.
pub fn choice_from_button(id: i32) -> WindowChoice {
    let idx = id - ID_BASE;
    if (0..Action::ALL.len() as i32).contains(&idx) {
        WindowChoice::Decide(Action::ALL[idx as usize])
    } else {
        WindowChoice::Later
    }
}

/// Second line of a command-link button.
fn action_hint(kind: Kind, a: Action) -> &'static str {
    match (kind, a) {
        (Kind::Datei, Action::Quarantaene) => t!("Datei sicher wegschließen – jederzeit wiederherstellbar", "Lock the file away safely – can be restored at any time"),
        (Kind::Datei, Action::Loeschen) => t!("Datei endgültig entfernen", "Remove the file for good"),
        (Kind::Datei, Action::Freigabe) => t!("Datei ist in Ordnung – nicht mehr melden", "The file is fine – do not report it again"),
        (Kind::Software, Action::Gesehen) => t!("Ich aktualisiere das Programm – nicht erneut melden, solange die Version gleich bleibt", "I will update the program – do not report again while the version stays the same"),
        (Kind::Url, Action::Gesehen) => t!("Zur Kenntnis genommen – nicht erneut melden", "Noted – do not report again"),
        (Kind::Hinweis, Action::Gesehen) => t!("Zur Kenntnis genommen", "Noted"),
        (Kind::Einstellung, Action::Freigabe) => t!("Die geänderten Werte aus config.toml gelten – beim Dienst innerhalb von 30 Sekunden, beim Agent ab seinem nächsten Start", "The changed values from config.toml apply – in the service within 30 seconds, in the agent from its next start"),
        (Kind::Einstellung, Action::Gesehen) => t!("Änderung nicht übernehmen – die bisherigen, sichereren Werte bleiben aktiv", "Do not accept the change – the previous, safer values stay active"),
        (Kind::Software | Kind::Url, Action::Freigabe) => t!("Bewusst ignorieren – nicht mehr melden", "Ignore on purpose – do not report again"),
        (Kind::Autostart, Action::Deaktivieren) => t!("Autostart abschalten – jederzeit wieder einschaltbar", "Switch the autostart off – can be switched on again at any time"),
        (Kind::Autostart, Action::Quarantaene) => t!("Gestartetes Programm in die Quarantäne verschieben", "Move the started program into quarantine"),
        (Kind::Autostart, Action::Freigabe) => t!("Autostart ist in Ordnung – nicht mehr melden", "The autostart is fine – do not report it again"),
        (Kind::Prozess, Action::Beenden) => t!("Laufendes Programm jetzt beenden (nur auf deinen Wunsch)", "End the running program now (only because you ask for it)"),
        (Kind::Prozess, Action::Quarantaene) => t!("Programmdatei in die Quarantäne verschieben", "Move the program file into quarantine"),
        (Kind::Prozess, Action::Freigabe) => t!("Genau diese Befehlszeile künftig erlauben (nur dieser Fall wird gemerkt)", "Allow exactly this command line in future (only this case is remembered)"),
        (Kind::Datei, Action::Einmalig) => t!("Fund schließen, nichts wird gemerkt", "Close the finding, nothing is remembered"),
        (Kind::Prozess, Action::Einmalig) => t!("Dieses eine Mal weiterlaufen lassen – nichts wird gemerkt", "Let it continue this once – nothing is remembered"),
        _ => "",
    }
}

type TaskDialogIndirectFn =
    unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut BOOL) -> HRESULT;

fn task_dialog_fn() -> Option<TaskDialogIndirectFn> {
    let name: Vec<u16> = "comctl32.dll\0".encode_utf16().collect();
    // SAFETY: loading a system DLL and looking up a documented export.
    unsafe {
        let module = LoadLibraryW(PCWSTR(name.as_ptr())).ok()?;
        let proc = GetProcAddress(module, windows::core::s!("TaskDialogIndirect"))?;
        Some(std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskDialogIndirectFn>(proc))
    }
}

/// True when the native dialog can be shown by this executable.
pub fn available() -> bool {
    task_dialog_fn().is_some()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn callback(hwnd: HWND, msg: TASKDIALOG_NOTIFICATIONS, _w: WPARAM, l: LPARAM, _data: isize) -> HRESULT {
    if msg == TDN_CREATED {
        // Visible on top and in the taskbar. Only shown when no game runs.
        let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        let _ = SetForegroundWindow(hwnd);
    } else if msg == TDN_HYPERLINK_CLICKED {
        let href = PCWSTR(l.0 as *const u16);
        let open: Vec<u16> = wide("open");
        ShellExecuteW(None, PCWSTR(open.as_ptr()), href, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
    }
    S_OK
}

const SAMPLE_ACTIONS: [Action; 3] = [Action::Quarantaene, Action::Loeschen, Action::Freigabe];

/// Content of one window.
pub struct WindowContent {
    pub title: String,
    pub instruction: String,
    pub content: String,
    pub footer: Option<String>,
    pub kind: Kind,
    /// Buttons offered (without "Später").
    pub actions: Vec<Action>,
    /// Button text and explanation per action (same order as `actions`).
    pub labels: Vec<(String, String)>,
    /// Sample window (test message): different icon, buttons change nothing.
    pub sample: bool,
}

fn detail_text(d: &Detection) -> String {
    let v = d.details.clone().unwrap_or_default();
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    match d.kind {
        Kind::Datei => tf!(
            "Datei: {}\nRegel: {} ({})\nKategorie: {} · Schweregrad: {}\nErstmals erkannt: {}",
            "File: {}\nRule: {} ({})\nCategory: {} · Severity: {}\nFirst seen: {}",
            d.path, d.rule_id, d.engine, d.category, d.severity.label(), d.first_seen
        ),
        Kind::Software => {
            let cves: Vec<String> = v["cves"]
                .as_array()
                .into_iter()
                .flatten()
                .take(6)
                .map(|c| {
                    format!(
                        "• {} ({}{}){}{}",
                        c["cve"].as_str().unwrap_or("?"),
                        c["schwere"].as_str().unwrap_or("?"),
                        if c["ransomware"].as_bool() == Some(true) { ", Ransomware" } else { "" },
                        c["behoben_ab"].as_str().map(|f| tf!(" – behoben ab {f}", " – fixed in {f}")).unwrap_or_default(),
                        c["epss_text"].as_str().unwrap_or("")
                    )
                })
                .collect();
            tf!(
                "Programm: {} {}\nHersteller: {}\nAktiv ausgenutzte Schwachstellen (CISA KEV):\n{}\nTreffersicherheit: {}\n\nLösung: {}",
                "Program: {} {}\nVendor: {}\nActively exploited vulnerabilities (CISA KEV):\n{}\nConfidence: {}\n\nSolution: {}",
                s("produkt"),
                s("version"),
                s("hersteller"),
                cves.join("\n"),
                s("konfidenz"),
                s("loesung")
            )
        }
        Kind::Url => tf!("{}\nQuelle: {}\n{}", "{}\nSource: {}\n{}", d.path, d.engine, s("hinweis")),
        Kind::Hinweis | Kind::Einstellung => format!("{}\n{}", d.path, s("hinweis")),
        Kind::Erweiterung => {
            let list = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let mut t = d.path.clone();
            for (label, key) in [(t!("Rechte", "Permissions"), "rechte"), (t!("Webseiten", "Websites"), "seiten"), (t!("Quelle", "Source"), "update_url"), ("Registry", "schluessel")] {
                let val = if key == "rechte" || key == "seiten" { list(key) } else { s(key) };
                if !val.is_empty() {
                    t.push_str(&format!("\n{label}: {val}"));
                }
            }
            format!("{t}\n\n{}", s("hinweis"))
        }
        Kind::Firewall => {
            let mut t = d.path.clone();
            for (label, key) in [(t!("Erlaubt", "Allows"), "protokoll"), ("Ports", "ports"), (t!("Von", "From"), "von"), (t!("Profile", "Profiles"), "profile"), (t!("Für", "For"), "programm"), (t!("Angelegt von", "Created by"), "ersteller")] {
                let val = s(key);
                if !val.is_empty() {
                    t.push_str(&format!("
{label}: {val}"));
                }
            }
            format!("{t}

{}", s("hinweis"))
        }
        Kind::Treiber => tf!(
            "Treiber: {}\n{}\ngeladen: {}{}\n\nEmpfehlung: {}",
            "Driver: {}\n{}\nloaded: {}{}\n\nRecommendation: {}",
            d.path,
            crate::treiber::summary_parts(&v).join(" · "),
            if v["geladen"].as_bool() == Some(true) { t!("ja", "yes") } else { t!("nein", "no") },
            v["cve"].as_array().filter(|c| !c.is_empty()).map(|c| format!("\nCVE: {}", c.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))).unwrap_or_default(),
            s("hinweis")
        ),
        Kind::Prozess => tf!(
            "{}\nProgramm: {}\nProzess-ID: {}{}{}\n{}\nRegel: {}\nErstmals erkannt: {}",
            "{}\nProgram: {}\nProcess ID: {}{}{}\n{}\nRule: {}\nFirst seen: {}",
            d.path,
            s("ziel"),
            v["pid"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            if crate::pipeline::process_running(d) { "" } else { t!(" (läuft nicht mehr)", " (no longer running)") },
            Some(s("befehl")).filter(|b| !b.is_empty()).map(|b| tf!("\nBefehlszeile: {}", "\nCommand line: {}", b.chars().take(300).collect::<String>())).unwrap_or_default()
                + &Some(s("skript")).filter(|b| !b.is_empty()).map(|b| tf!("\nSkript (Ausschnitt): {b}", "\nScript (excerpt): {b}")).unwrap_or_default()
                + &v["dateien"]
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .map(|a| tf!("\nBetroffene Dateien (Beispiele):{}", "\nAffected files (examples):{}", a.iter().filter_map(|x| x.as_str()).map(|x| format!("\n  • {x}")).collect::<String>()))
                    .unwrap_or_default()
                + &v["schritte"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(|x| format!("\n  • {x}")).collect::<String>()).unwrap_or_default(),
            s("hinweis"),
            d.rule_id,
            d.first_seen
        ),
        Kind::Autostart => tf!(
            "{}\nBefehl: {}\nProgramm: {}\nRegel: {}\nErstmals erkannt: {}",
            "{}\nCommand: {}\nProgram: {}\nRule: {}\nFirst seen: {}",
            d.path,
            s("befehl"),
            s("ziel"),
            d.rule_id,
            d.first_seen
        ),
    }
}

impl WindowContent {
    pub fn for_detection(d: &Detection, more_pending: usize, dashboard_url: Option<&str>) -> Self {
        // First what it is about in plain words (file or program, signer, the update it belongs to).
        let subject = crate::pipeline::subject(d).map(|s| tf!("Betrifft: {s}\n\n", "Concerns: {s}\n\n")).unwrap_or_default();
        let content = tf!(
            "{subject}{}\n\nNichts wurde verändert. Deine Entscheidung wird gespeichert – derselbe Fund wird danach nicht mehr gemeldet.",
            "{subject}{}\n\nNothing has been changed. Your decision is remembered – the same finding will not be reported again.",
            detail_text(d)
        );
        let mut footer = String::new();
        if more_pending > 0 {
            footer.push_str(&tf!("Danach folgen noch {more_pending} weitere offene Funde. ", "{more_pending} more open findings follow. "));
        }
        if let Some(url) = dashboard_url {
            footer.push_str(&tf!("<a href=\"{url}\">Alle anzeigen im Dashboard</a>", "<a href=\"{url}\">Show all in the dashboard</a>"));
        }
        let instruction = match d.kind {
            Kind::Software => d.threat_name.clone(),
            _ => tf!("{} erkannt: {}", "{} detected: {}", d.kind.label(), d.threat_name),
        };
        Self {
            title: "K9".into(),
            instruction,
            content,
            footer: (!footer.is_empty()).then_some(footer),
            kind: d.kind,
            labels: crate::pipeline::allowed_actions(d)
                .iter()
                .map(|a| (crate::pipeline::action_label(d, *a), crate::pipeline::action_hint(d, *a).unwrap_or_else(|| action_hint(d.kind, *a).to_string())))
                .collect(),
            actions: crate::pipeline::allowed_actions(d),
            sample: false,
        }
    }

    pub fn sample() -> Self {
        Self {
            title: t!("K9 – Testmeldung", "K9 – test message").into(),
            instruction: t!("Bedrohung erkannt: Beispiel.Testfund (harmlos)", "Threat detected: Example.TestFinding (harmless)").into(),
            content: t!(
                "Datei: C:\\Beispiel\\nicht-vorhanden.txt\nRegel: BEISPIEL-0001 (muster)\n\nDies ist nur ein Beispiel. Keine Schaltfläche verändert eine Datei oder speichert eine Entscheidung.",
                "File: C:\\Example\\does-not-exist.txt\nRule: BEISPIEL-0001 (muster)\n\nThis is only an example. No button changes a file or stores a decision."
            )
            .into(),
            footer: None,
            kind: Kind::Datei,
            actions: SAMPLE_ACTIONS.to_vec(),
            labels: SAMPLE_ACTIONS.iter().map(|a| (Kind::Datei.action_label(*a).to_string(), action_hint(Kind::Datei, *a).to_string())).collect(),
            sample: true,
        }
    }
}

/// Shows the window and blocks until the user chose. Must run on a thread
/// that may block (agent: blocking thread pool).
pub fn show(c: &WindowContent) -> Result<WindowChoice> {
    let Some(task_dialog) = task_dialog_fn() else {
        bail!(t!("Meldefenster nicht verfügbar (Common Controls 6 fehlen in diesem Programm)", "Alert window not available (Common Controls 6 are missing in this program)"));
    };
    let title = wide(&c.title);
    let instruction = wide(&c.instruction);
    let content = wide(&c.content);
    let footer = c.footer.as_deref().map(wide);
    let mut labels: Vec<(i32, String)> = c
        .actions
        .iter()
        .zip(&c.labels)
        .map(|(a, (label, hint))| (button_id(*a), format!("{label}\n{hint}")))
        .collect();
    labels.push((ID_LATER, t!("Später\nNoch nicht entscheiden – erneut nachfragen", "Later\nDo not decide yet – ask again").into()));
    let texts: Vec<Vec<u16>> = labels.iter().map(|(_, t)| wide(t)).collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = labels
        .iter()
        .zip(&texts)
        .map(|((id, _), t)| TASKDIALOG_BUTTON { nButtonID: *id, pszButtonText: PCWSTR(t.as_ptr()) })
        .collect();

    let mut cfg = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_ENABLE_HYPERLINKS,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(instruction.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: ID_LATER,
        pfCallback: Some(callback),
        ..Default::default()
    };
    // The K9 icon of this program (embedded resource 1); without it the Windows symbol.
    match program_icon() {
        Some(icon) => {
            let flags = cfg.dwFlags;
            cfg.dwFlags = flags | windows::Win32::UI::Controls::TDF_USE_HICON_MAIN;
            cfg.Anonymous1.hMainIcon = icon;
        }
        None => cfg.Anonymous1.pszMainIcon = if c.sample { TD_INFORMATION_ICON } else { TD_WARNING_ICON },
    }
    if let Some(f) = &footer {
        cfg.pszFooter = PCWSTR(f.as_ptr());
    }
    // With our own icon Windows plays no sound by itself (it only does for its standard
    // symbols): the warning (or, for the test message, information) sound as before.
    play_sound(c.sample);
    let mut pressed = 0i32;
    // SAFETY: all strings/buttons outlive the call; pointers are valid.
    unsafe {
        task_dialog(&cfg, &mut pressed, std::ptr::null_mut(), std::ptr::null_mut()).ok()?;
    }
    Ok(choice_from_button(pressed))
}

/// Windows sound of a K9 window: with the standard symbols (before the K9 icon) Windows played
/// "Hinweis" (SystemAsterisk) for the test message and "Warnung" (SystemExclamation) for every
/// finding and for the confirmation window. Returns the sound and its name for the log.
pub fn sound_for(information: bool) -> (windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE, &'static str) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONASTERISK, MB_ICONEXCLAMATION};
    if information {
        (MB_ICONASTERISK, "SystemAsterisk")
    } else {
        (MB_ICONEXCLAMATION, "SystemExclamation")
    }
}

/// Plays that sound via the Windows sound scheme (the user's sounds and volume apply).
pub fn play_sound(information: bool) {
    let (style, name) = sound_for(information);
    tracing::info!("Ton: {name}");
    // SAFETY: plain call.
    unsafe {
        let _ = windows::Win32::System::Diagnostics::Debug::MessageBeep(style);
    }
}

/// The K9 program icon (resource 1 of the running exe), if embedded.
pub fn program_icon() -> Option<windows::Win32::UI::WindowsAndMessaging::HICON> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{LoadImageW, IMAGE_ICON, LR_DEFAULTSIZE};
    // SAFETY: own module; resource id 1 as MAKEINTRESOURCE; the shared icon must not be destroyed.
    unsafe {
        let module = GetModuleHandleW(None).ok()?;
        let h = LoadImageW(Some(module.into()), PCWSTR(std::ptr::without_provenance(1)), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | windows::Win32::UI::WindowsAndMessaging::LR_SHARED).ok()?;
        Some(windows::Win32::UI::WindowsAndMessaging::HICON(h.0))
    }
}

/// Simple error box (user32, always available).
pub fn show_error(text: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST};
    let t = wide(text);
    let title = wide("K9");
    // SAFETY: NUL-terminated strings.
    unsafe {
        MessageBoxW(None, PCWSTR(t.as_ptr()), PCWSTR(title.as_ptr()), MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_mapping() {
        for a in Action::ALL {
            assert_eq!(choice_from_button(button_id(a)), WindowChoice::Decide(a));
        }
        assert_eq!(choice_from_button(ID_LATER), WindowChoice::Later);
        // Every kind offers only its own actions, each with an explanation.
        for k in [Kind::Datei, Kind::Software, Kind::Url, Kind::Autostart] {
            for a in k.actions() {
                assert!(!action_hint(k, *a).is_empty(), "{k:?} {a:?}");
            }
        }
        assert_eq!(Kind::Software.action_label(Action::Freigabe), "Ignorieren");
        // The sounds the standard symbols played before the K9 icon.
        assert_eq!(sound_for(false).1, "SystemExclamation");
        assert_eq!(sound_for(true).1, "SystemAsterisk");
        assert_eq!(sound_for(false).0, windows::Win32::UI::WindowsAndMessaging::MB_ICONEXCLAMATION);
        // Closing with Esc/X (IDCANCEL = 2) or anything unknown never decides.
        assert_eq!(choice_from_button(2), WindowChoice::Later);
        assert_eq!(choice_from_button(0), WindowChoice::Later);
    }

    #[test]
    fn content_mentions_details_and_dashboard() {
        let d = Detection {
            id: 7,
            path: "C:\\x\\datei.exe".into(),
            sha256: "ab".repeat(32),
            rule_id: "VS-TEST-0001".into(),
            threat_name: "Test.Fund".into(),
            category: "Test".into(),
            severity: crate::model::Severity::Hoch,
            engine: "muster".into(),
            first_seen: "2026-11-13 10:00:00".into(),
            last_seen: "2026-11-13 10:00:00".into(),
            status: crate::model::DetectionStatus::Offen,
            action: None,
            kind: crate::model::Kind::Datei,
            details: None,
        };
        let c = WindowContent::for_detection(&d, 2, Some("http://127.0.0.1:1/?t=x"));
        assert!(c.instruction.contains("Test.Fund"));
        assert!(c.content.contains("C:\\x\\datei.exe") && c.content.contains("VS-TEST-0001") && c.content.contains("2026-11-13"));
        let f = c.footer.unwrap();
        assert!(f.contains("2 weitere") && f.contains("Alle anzeigen im Dashboard"));
        assert!(WindowContent::for_detection(&d, 0, None).footer.is_none());

        let mut sw = d.clone();
        sw.kind = Kind::Software;
        sw.details = Some(serde_json::json!({
            "produkt": "Beispiel Werkzeug", "version": "3.1", "hersteller": "X", "konfidenz": "hoch",
            "loesung": "winget upgrade --id Beispiel.Werkzeug -e",
            "cves": [{"cve": "CVE-2099-0001", "schwere": "CRITICAL", "behoben_ab": "3.2"}]
        }));
        let c = WindowContent::for_detection(&sw, 0, None);
        assert!(c.content.contains("CVE-2099-0001") && c.content.contains("behoben ab 3.2") && c.content.contains("winget upgrade"));
        assert_eq!(c.kind, Kind::Software);
    }
}
