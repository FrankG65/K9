//! `k9 dienst …` – sets up the Windows service "K9-Dienst".
//!
//! Installing, starting and stopping need administrator rights: k9 asks
//! for them with the normal Windows UAC prompt (a second k9 runs elevated
//! and writes its result to a file this one prints).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use k9_core::app::App;
use k9_core::dienst::{self, Message, Settings, PROTOCOL, SERVICE_DISPLAY, SERVICE_NAME};
use k9_core::say;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const DESCRIPTION: &str = "K9: meldet Prozessstarts und DNS-Abfragen (ETW), bewacht den Agenten und führt bestätigte Aktionen mit Administratorrechten aus. Ändert nie etwas ohne deine Entscheidung.";

/// Programs copied to the installation folder (the service only trusts these).
const PROGRAMS: [&str; 3] = ["k9-dienst.exe", "k9-agent.exe", "k9.exe"];

/// Scripts that need administrator rights (copied next to the programs).
const ADMIN_SCRIPTS: [&str; 1] = ["treiber-aufraeumen.ps1"];

fn install_dir() -> PathBuf {
    dienst::install_dir()
}

/// Entry point. `elevated`: this is the elevated helper writing to `result`.
pub fn run(app: &App, action: &str, elevated: bool, result: Option<PathBuf>) -> Result<()> {
    let action = action.trim().to_lowercase();
    match action.as_str() {
        "status" => status(),
        "installieren" | "aktualisieren" | "deinstallieren" | "starten" | "stoppen" => {
            if elevated {
                let out = result.context("--ergebnis fehlt")?;
                let mut lines = Vec::new();
                let r = match action.as_str() {
                    "installieren" | "aktualisieren" => install(app, &mut lines),
                    "deinstallieren" => uninstall(&mut lines),
                    "starten" => start(&mut lines),
                    _ => stop(&mut lines),
                };
                if let Err(e) = r {
                    lines.push(format!("FEHLER: {e:#}"));
                }
                std::fs::write(&out, lines.join("\n"))?;
                return Ok(());
            }
            if k9_core::paths::is_elevated() {
                let mut lines = Vec::new();
                let r = match action.as_str() {
                    "installieren" | "aktualisieren" => install(app, &mut lines),
                    "deinstallieren" => uninstall(&mut lines),
                    "starten" => start(&mut lines),
                    _ => stop(&mut lines),
                };
                for l in &lines {
                    say!("{l}");
                }
                if r.is_ok() {
                    if matches!(action.as_str(), "installieren" | "aktualisieren") {
                        // Never start the agent from this elevated process: the service starts it
                        // in the user's session with the normal (limited) token.
                        say!("Agent startet in etwa 10 Sekunden ueber den Dienst (mit deinen normalen Rechten).");
                        remove_user_copies();
                    }
                    shortcuts(&action);
                }
                return r;
            }
            run_elevated(app, &action)?;
            if matches!(action.as_str(), "installieren" | "aktualisieren") {
                start_installed_agent(app);
                remove_user_copies();
            }
            shortcuts(&action);
            Ok(())
        }
        other => bail!("Unbekannt: '{other}' (installieren, aktualisieren, deinstallieren, status, starten, stoppen)"),
    }
}

/// Shortcuts "K9-Dashboard" (desktop, Start menu) of this user: created or
/// refreshed on install/update, removed on uninstall.
fn shortcuts(action: &str) {
    use k9_core::verknuepfung;
    match action {
        "installieren" | "aktualisieren" => {
            for r in verknuepfung::create_all(&install_dir().join("k9.exe")) {
                match r {
                    Ok(p) => say!("Verknuepfung: {}", p.display()),
                    Err(e) => say!("Verknuepfung nicht angelegt: {e:#}"),
                }
            }
        }
        "deinstallieren" => {
            for p in verknuepfung::remove_all() {
                say!("Verknuepfung entfernt: {}", p.display());
            }
        }
        _ => {}
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Runs `k9 dienst <action>` elevated (UAC prompt) and prints its result.
fn run_elevated(app: &App, action: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let exe = std::env::current_exe()?;
    let out = app.paths.log_dir().join(format!("dienst-{action}.txt"));
    std::fs::create_dir_all(app.paths.log_dir())?;
    let _ = std::fs::remove_file(&out);
    let params = format!(
        "dienst {action} --erhoeht --daten \"{}\" --ergebnis \"{}\"",
        app.paths.data_dir.display(),
        out.display()
    );
    say!("Windows fragt jetzt nach Administratorrechten (UAC) – bitte mit „Ja“ bestätigen.");
    let verb = wide("runas");
    let file = wide(&exe.display().to_string());
    let par = wide(&params);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(par.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: all strings live until the call returns; process handle closed below.
    unsafe {
        if let Err(e) = ShellExecuteExW(&mut info) {
            if e.code() == windows::Win32::Foundation::ERROR_CANCELLED.to_hresult() {
                bail!("Abgebrochen – ohne Administratorrechte kann der Dienst nicht eingerichtet werden");
            }
            bail!("Start mit Administratorrechten fehlgeschlagen: {e}");
        }
        let _ = WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
    }
    let text = std::fs::read_to_string(&out).unwrap_or_else(|_| "FEHLER: Kein Ergebnis erhalten".into());
    let _ = std::fs::remove_file(&out);
    let mut failed = false;
    for l in text.lines() {
        failed |= l.starts_with("FEHLER");
        say!("{l}");
    }
    if failed {
        bail!("Dienst-Befehl „{action}“ nicht erfolgreich");
    }
    Ok(())
}

/// Starts the installed agent hidden with the normal user rights (this k9
/// is not elevated). A second agent is never started (single instance).
pub fn start_installed_agent(app: &App) {
    use std::os::windows::process::CommandExt;
    let agent = install_dir().join("k9-agent.exe");
    if !agent.is_file() || agent_answers(app) {
        return;
    }
    let conhost = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\conhost.exe");
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    match std::process::Command::new(conhost).arg("--headless").arg(&agent).current_dir(install_dir()).creation_flags(CREATE_NO_WINDOW).spawn() {
        Ok(_) => say!("Agent gestartet: {} (unsichtbar)", agent.display()),
        Err(e) => say!("Agent bitte selbst starten (K9 starten.cmd): {e}"),
    }
}

fn agent_answers(app: &App) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], app.config.dashboard.port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

/// Ends the running agent (any copy) so its program file can be replaced.
fn stop_agent(app: &App, lines: &mut Vec<String>) {
    let Some(link) = app.dashboard_link() else { return };
    if !agent_answers(app) {
        return;
    }
    if ask_agent_to_end(app, &link) {
        lines.push("Agent für die Aktualisierung beendet (startet gleich wieder).".into());
    }
}

/// Asks the agent (with this token) to end and waits for it; true if asked.
fn ask_agent_to_end(app: &App, link: &k9_core::notify::DashboardLink) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", link.port)) else { return false };
    let body = format!("t={}", link.token);
    let req = format!(
        "POST /beenden HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        link.port,
        body.len()
    );
    if s.write_all(req.as_bytes()).is_ok() {
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        let t = Instant::now();
        while agent_answers(app) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(300));
        }
        std::thread::sleep(Duration::from_millis(800));
        return true;
    }
    false
}

/// Points the user's logon autostart (if switched on) to the installed agent.
fn update_user_autostart(agent: &Path, lines: &mut Vec<String>) {
    use k9_core::winreg::{self, HKCU};
    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const RUN_VALUE: &str = "K9-Agent";
    // Switched on: either for K9 or (before the move) for the old installation.
    if winreg::read_string(HKCU, RUN_KEY, RUN_VALUE).is_none() && winreg::read_string(HKCU, RUN_KEY, k9_core::umzug::OLD_RUN_VALUE).is_none() {
        return;
    }
    let conhost = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\conhost.exe");
    let cmd = format!("\"{}\" --headless \"{}\"", conhost.display(), agent.display());
    if winreg::set_string(HKCU, RUN_KEY, RUN_VALUE, &cmd).is_ok() {
        lines.push(format!("Autostart bei der Anmeldung zeigt jetzt auf {}", agent.display()));
    }
}

/// API keys for the source updates go to the service (it imports and
/// encrypts them for SYSTEM at its start). This elevated k9 runs as the
/// same user and can read them from the Credential Manager.
fn hand_over_secrets(lines: &mut Vec<String>) {
    let mut map = std::collections::BTreeMap::new();
    for name in k9_core::schutz::SERVICE_SECRETS {
        if let Ok(Some(v)) = k9_core::secrets::get(name) {
            map.insert(name.to_string(), v);
        }
    }
    if map.is_empty() {
        return;
    }
    let dir = k9_core::schutz::private_dir();
    let res = (|| -> Result<()> {
        // The folder exists since the first service start (only SYSTEM/Administrators);
        // the file inherits these rights.
        if !dir.is_dir() {
            anyhow::bail!("{} fehlt – zuerst den Dienst einmal starten", dir.display());
        }
        std::fs::write(dir.join(k9_core::schutz::SECRETS_IMPORT_FILE), serde_json::to_vec(&map)?)?;
        Ok(())
    })();
    match res {
        Ok(()) => lines.push(format!("API-Schlüssel an den Dienst übergeben: {}", map.keys().cloned().collect::<Vec<_>>().join(", "))),
        Err(e) => lines.push(format!("API-Schlüssel nicht übergeben ({e:#}) – später: k9 geheimnis abusech-key")),
    }
}

/// After the update: if the service holds the abuse.ch key, the readable copy
/// in the user's Credential Manager is removed.
fn remove_user_copies() {
    // Keys only the service needs: no readable copy for programs with the user's rights
    // (a changed copy must never replace the service's key at an update).
    const ONLY_SERVICE: [(&str, &str); 2] = [(k9_core::sources::ABUSECH_KEY, "abuse.ch"), (k9_core::virustotal::VT_KEY, "VirusTotal")];
    for _ in 0..20 {
        if let Ok(names) = dienst::service_secret_names() {
            for (key, label) in ONLY_SERVICE {
                if names.iter().any(|n| n == key) && k9_core::secrets::delete(key).unwrap_or(false) {
                    say!("{label}-Schlüssel liegt jetzt nur noch geschützt beim Dienst (Kopie in der Anmeldeinformationsverwaltung entfernt).");
                }
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).context("Dienstverwaltung nicht erreichbar (Administratorrechte?)")
}

fn wait_for(svc: &windows_service::service::Service, state: ServiceState, max: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < max {
        if svc.query_status().map(|s| s.current_state == state).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// Stops the K9 service. Since 0.33.0 the service refuses a plain stop request (malware stops
/// protection services first); `k9` announces its stop with a control code of its own. An
/// older service does not know the code and stops as before.
fn stop_announced(svc: &windows_service::service::Service) {
    if let Ok(code) = windows_service::service::UserEventCode::from_raw(dienst::STOP_CODE) {
        let _ = svc.notify(code);
    }
    let _ = svc.stop();
}

fn stop_if_running(lines: &mut Vec<String>) -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::USER_DEFINED_CONTROL;
    let Ok(svc) = m.open_service(SERVICE_NAME, access) else { return Ok(()) };
    if svc.query_status()?.current_state != ServiceState::Stopped {
        stop_announced(&svc);
        if !wait_for(&svc, ServiceState::Stopped, Duration::from_secs(20)) {
            bail!("Dienst lässt sich nicht stoppen");
        }
        lines.push("Dienst gestoppt.".into());
    }
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().trim_end_matches('\\').eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches('\\'))
}

fn copy_with_retry(from: &Path, to: &Path) -> Result<()> {
    let mut last = None;
    for _ in 0..20 {
        match std::fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(last.unwrap()).with_context(|| format!("{} kann nicht nach {} kopiert werden", from.display(), to.display()))
}

fn install(app: &App, lines: &mut Vec<String>) -> Result<()> {
    let here = std::env::current_exe()?.parent().context("Programmordner unbekannt")?.to_path_buf();
    let dir = install_dir();
    if same_dir(&here, &dir) {
        bail!("Bitte aus dem Build-Ordner aufrufen (dort liegt die neue Version), z. B. C:\\K9-Quelltext\\target\\release");
    }
    for p in PROGRAMS {
        if !here.join(p).is_file() {
            bail!("{p} nicht neben k9.exe gefunden ({}) – bitte zuerst bauen", here.display());
        }
    }
    // Move from the old installation ("Virenscanner"): only once, before the new folder has data.
    let moving = k9_core::umzug::old_installation_present() && !k9_core::schutz::protected_db_path().exists();
    if moving {
        lines.push("Bisherige Installation (Virenscanner) gefunden – wird nach K9 übernommen.".into());
        stop_old_installation(app, lines)?;
        if let Err(e) = k9_core::umzug::copy_user_data(lines) {
            undo_move(lines);
            return Err(e.context("Übernahme der Benutzerdaten fehlgeschlagen"));
        }
    }
    stop_if_running(lines)?;
    stop_agent(app, lines);
    std::fs::create_dir_all(&dir).with_context(|| format!("{} kann nicht angelegt werden", dir.display()))?;
    for p in PROGRAMS {
        copy_with_retry(&here.join(p), &dir.join(p))?;
    }
    lines.push(format!("Programme kopiert nach {} ({})", dir.display(), PROGRAMS.join(", ")));
    // Admin scripts are run from the protected program folder only (a copy in the
    // user-writable project folder could be changed by any program of the user).
    for script in ADMIN_SCRIPTS {
        if let Some(src) = here.ancestors().map(|d| d.join("scripts").join(script)).find(|p| p.is_file()) {
            copy_with_retry(&src, &dir.join(script))?;
            lines.push(format!("Skript kopiert: {}", dir.join(script).display()));
        }
    }
    // Baseline for the tamper alarm: only this update writes it (the service only compares).
    // On a first installation the protected database does not exist yet – the service then
    // takes the files it finds at its first start.
    let db = k9_core::schutz::protected_db_path();
    if db.is_file() {
        match k9_core::store::Store::open_protected_admin(&db).and_then(|s| k9_core::basis::record_update(&s, &dir)) {
            Ok(()) => lines.push("Ausgangsstand für den Manipulationsschutz gespeichert (Prüfsummen der Programme).".into()),
            Err(e) => lines.push(format!("Hinweis: Ausgangsstand für den Manipulationsschutz nicht gespeichert: {e:#}")),
        }
    }
    let exe = dir.join("k9-dienst.exe");
    let agent = dir.join("k9-agent.exe");
    update_user_autostart(&agent, lines);

    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let settings = Settings {
        user_sid: dienst::current_user_sid()?,
        profile: env("USERPROFILE"),
        appdata: env("APPDATA"),
        localappdata: env("LOCALAPPDATA"),
        temp: env("TEMP"),
        // Always the protected folder – independent of whether this shell was elevated.
        data_dir: k9_core::schutz::protected_dir().display().to_string(),
        agent_path: agent.display().to_string(),
    };
    dienst::write_settings(&settings)?;
    if moving {
        // The new service copies the protected folder at its first start (only SYSTEM can).
        k9_core::winreg::set_string(
            k9_core::winreg::HKLM,
            dienst::REG_KEY,
            k9_core::umzug::PENDING_VALUE,
            &k9_core::umzug::programdata().old.display().to_string(),
        )?;
    }
    hand_over_secrets(lines);
    // Project folder (scripts for the PDF guide), if k9 runs from a build there.
    if let Some(dev) = here.ancestors().find(|d| d.join("scripts").join("anleitung-pdf.ps1").is_file()) {
        k9_core::winreg::set_string(k9_core::winreg::HKLM, dienst::REG_KEY, "Entwicklungsordner", &dev.display().to_string())?;
    }
    lines.push(format!(
        "Einstellungen gespeichert (HKLM\\{}): Agent {}, Datenordner des Dienstes {}",
        dienst::REG_KEY,
        settings.agent_path,
        settings.data_dir
    ));

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem (needed for ETW and the agent restart)
        account_password: None,
    };
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG;
    let svc = match m.open_service(SERVICE_NAME, access) {
        Ok(s) => {
            s.change_config(&info)?;
            lines.push("Dienst aktualisiert.".into());
            s
        }
        Err(_) => {
            let s = m.create_service(&info, access)?;
            lines.push(format!("Dienst „{SERVICE_DISPLAY}“ angelegt (Konto: LocalSystem)."));
            s
        }
    };
    svc.set_description(DESCRIPTION)?;
    svc.set_delayed_auto_start(true)?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            // One second: a service ended by force is back before ransomware gets far. The
            // second time as well - an attacker simply ends it twice (sandbox run of
            // 21.11.2026: with 60 seconds for the second restart 22 of 400 files were lost).
            // From the third time on five seconds, so that a service that keeps crashing does
            // not keep the PC busy.
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(1) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(1) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
        ]),
    })?;
    let _ = svc.set_failure_actions_on_non_crash_failures(true);
    lines.push("Start: automatisch (verzögert), bei Absturz Neustart.".into());
    svc.start::<&str>(&[])?;
    if wait_for(&svc, ServiceState::Running, Duration::from_secs(20)) {
        lines.push("Dienst läuft.".into());
    } else {
        lines.push("FEHLER: Dienst startet nicht – siehe Protokoll logs\\dienst.log".into());
    }
    if moving {
        // Nothing old is removed before the new service confirms that everything came over.
        match wait_for_health() {
            Some(h) if h.problems(true).is_empty() => {
                lines.push(format!(
                    "Selbsttest von K9: in Ordnung ({} Entscheidungen gültig unterschrieben, {} Quarantäne-Dateien, Schlüssel und Einstellungen übernommen).",
                    h.unterschrieben, h.quarantaene_da
                ));
                finish_move(lines);
            }
            other => {
                let why = other.map(|h| h.problems(true).join("; ")).unwrap_or_else(|| "keine Antwort des neuen Dienstes".into());
                lines.push(format!("FEHLER: Selbsttest von K9 nicht bestanden: {why}"));
                undo_move(lines);
                bail!("Übernahme abgebrochen – es wurde nichts Altes entfernt");
            }
        }
    }
    Ok(())
}

// ============================================================ move from "Virenscanner"

/// Stops the old service and its agent (the old agent is asked to end, like at every update).
fn stop_old_installation(app: &App, lines: &mut Vec<String>) -> Result<()> {
    use k9_core::umzug;
    let m = manager(ServiceManagerAccess::CONNECT)?;
    if let Ok(svc) = m.open_service(umzug::OLD_SERVICE, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS) {
        if svc.query_status()?.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            if !wait_for(&svc, ServiceState::Stopped, Duration::from_secs(20)) {
                bail!("Der alte Dienst ({}) lässt sich nicht stoppen", umzug::OLD_SERVICE);
            }
        }
        lines.push(format!("Alter Dienst „{}“ gestoppt.", umzug::OLD_SERVICE));
    }
    if let Ok(Some(token)) = k9_core::secrets::get_in(umzug::OLD_APP, k9_core::secrets::DASHBOARD_TOKEN) {
        let link = k9_core::notify::DashboardLink { port: app.config.dashboard.port, token };
        if agent_answers(app) {
            ask_agent_to_end(app, &link);
            if agent_answers(app) {
                bail!("Der alte Agent läuft noch – bitte im Task-Manager „vs-agent.exe“ beenden und erneut versuchen");
            }
            lines.push("Alter Agent beendet.".into());
        }
    }
    Ok(())
}

/// After the self-test of the new service: removes the old programs and registrations and keeps
/// the old data folders as backup (*.alt).
fn finish_move(lines: &mut Vec<String>) {
    use k9_core::umzug;
    use k9_core::winreg::{self, HKCU, HKLM};
    if let Ok(m) = manager(ServiceManagerAccess::CONNECT) {
        if let Ok(svc) = m.open_service(umzug::OLD_SERVICE, ServiceAccess::DELETE) {
            if svc.delete().is_ok() {
                lines.push(format!("Alter Dienst „{}“ entfernt.", umzug::OLD_SERVICE));
            }
        }
    }
    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    if winreg::read_string(HKCU, RUN_KEY, umzug::OLD_RUN_VALUE).is_some() && winreg::delete_value(HKCU, RUN_KEY, umzug::OLD_RUN_VALUE).is_ok() {
        lines.push(format!("Alter Autostart „{}“ entfernt.", umzug::OLD_RUN_VALUE));
    }
    for p in k9_core::verknuepfung::remove_old() {
        lines.push(format!("Alte Verknüpfung entfernt: {}", p.display()));
    }
    let _ = winreg::delete_tree(HKCU, umzug::OLD_AUMID_KEY);
    let _ = winreg::delete_tree(HKLM, umzug::OLD_REG_KEY);
    let old_programs = umzug::programfiles().old;
    if old_programs.is_dir() {
        let gone = (0..20).any(|_| {
            let ok = std::fs::remove_dir_all(&old_programs).is_ok();
            if !ok {
                std::thread::sleep(Duration::from_millis(300));
            }
            ok
        });
        lines.push(if gone { format!("Alte Programme entfernt: {}", old_programs.display()) } else { format!("{} bitte später von Hand löschen.", old_programs.display()) });
    }
    for p in umzug::keep_as_backup() {
        lines.push(format!("Sicherung der alten Daten: {}", p.display()));
    }
    lines.push("Die Sicherung bleibt, bis du sie entfernst: k9 alte-installation entfernen (als Administrator).".into());
}

/// The self-test of the new service failed: K9 is removed again, the old installation runs on.
fn undo_move(lines: &mut Vec<String>) {
    use k9_core::umzug;
    if let Ok(m) = manager(ServiceManagerAccess::CONNECT) {
        let access = ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::USER_DEFINED_CONTROL;
        if let Ok(svc) = m.open_service(SERVICE_NAME, access) {
            stop_announced(&svc);
            wait_for(&svc, ServiceState::Stopped, Duration::from_secs(20));
            let _ = svc.delete();
        }
    }
    let _ = k9_core::winreg::delete_tree(k9_core::winreg::HKLM, dienst::REG_KEY);
    let mut dirs = vec![umzug::programdata().new, umzug::programfiles().new];
    dirs.extend(umzug::user_folders().into_iter().map(|f| f.new));
    for d in dirs {
        for _ in 0..10 {
            if !d.exists() || std::fs::remove_dir_all(&d).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    if let Ok(m) = manager(ServiceManagerAccess::CONNECT) {
        if let Ok(svc) = m.open_service(umzug::OLD_SERVICE, ServiceAccess::START) {
            let _ = svc.start::<&str>(&[]);
        }
    }
    lines.push("K9 wurde wieder entfernt, die bisherige Installation (Virenscanner) läuft unverändert weiter.".into());
}

/// Waits for the self-test of the new service (at most 90 s).
fn wait_for_health() -> Option<k9_core::umzug::Gesundheit> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(90) {
        if let Ok(Message::StatusAntwort { gesundheit: Some(g), .. }) = dienst::request(&Message::Status { v: PROTOCOL }) {
            return serde_json::from_str(&g).ok();
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    None
}

/// `k9 alte-installation entfernen`: deletes the backup of the old installation.
pub fn remove_backup(confirmed: bool) -> Result<()> {
    use k9_core::umzug;
    let dirs = umzug::backups();
    if dirs.is_empty() {
        say!("Keine Sicherung der alten Installation (Virenscanner) gefunden.");
        return Ok(());
    }
    if !k9_core::paths::is_elevated() {
        bail!("Bitte PowerShell als Administrator oeffnen und den Befehl dort erneut ausfuehren.");
    }
    say!("Sicherung der alten Installation:");
    for d in &dirs {
        say!("  {}", d.display());
    }
    if !confirmed {
        say!("Diese Ordner und die alten Anmeldeinformationen (\"Virenscanner\") endgueltig loeschen? (j/n)");
        let mut a = String::new();
        std::io::stdin().read_line(&mut a)?;
        if !a.trim().eq_ignore_ascii_case("j") {
            say!("Abgebrochen – nichts geloescht.");
            return Ok(());
        }
    }
    for d in &dirs {
        match std::fs::remove_dir_all(d) {
            Ok(()) => say!("Geloescht: {}", d.display()),
            Err(e) => say!("Nicht geloescht: {} ({e})", d.display()),
        }
    }
    let mut names: Vec<&str> = k9_core::secrets::USER_SECRETS.to_vec();
    names.push(k9_core::secrets::DASHBOARD_TOKEN);
    let n = names.into_iter().filter(|n| k9_core::secrets::delete_in(umzug::OLD_APP, n).unwrap_or(false)).count();
    say!("Alte Anmeldeinformationen geloescht: {n}");
    Ok(())
}

fn uninstall(lines: &mut Vec<String>) -> Result<()> {
    stop_if_running(lines)?;
    let m = manager(ServiceManagerAccess::CONNECT)?;
    match m.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS) {
        Ok(svc) => {
            svc.delete()?;
            lines.push("Dienst entfernt.".into());
        }
        Err(_) => lines.push("Dienst war nicht eingerichtet.".into()),
    }
    k9_core::winreg::delete_tree(k9_core::winreg::HKLM, dienst::REG_KEY)?;
    let dir = install_dir();
    if dir.exists() {
        let mut ok = false;
        for _ in 0..20 {
            if std::fs::remove_dir_all(&dir).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        lines.push(if ok { format!("{} gelöscht.", dir.display()) } else { format!("{} bitte später von Hand löschen.", dir.display()) });
    }
    lines.push("Der Agent läuft ohne Dienst weiter aus dem Build-Ordner: K9 starten.cmd bzw. k9 autostart-agent an (dort aufrufen).".into());
    Ok(())
}

fn start(lines: &mut Vec<String>) -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS).context("Dienst ist nicht eingerichtet")?;
    if svc.query_status()?.current_state != ServiceState::Running {
        svc.start::<&str>(&[])?;
    }
    if !wait_for(&svc, ServiceState::Running, Duration::from_secs(20)) {
        bail!("Dienst startet nicht – siehe logs\\dienst.log");
    }
    lines.push("Dienst läuft.".into());
    Ok(())
}

fn stop(lines: &mut Vec<String>) -> Result<()> {
    stop_if_running(lines)?;
    lines.push("Dienst ist gestoppt (startet beim nächsten Windows-Start wieder).".into());
    Ok(())
}

fn status() -> Result<()> {
    let Some(state) = dienst::service_state() else {
        say!("Windows-Dienst: nicht eingerichtet (einrichten: k9 dienst installieren)");
        return Ok(());
    };
    say!("Windows-Dienst \"{SERVICE_NAME}\": {state}");
    if let Some(s) = dienst::read_settings() {
        say!("  Agent        : {}", s.agent_path);
        say!("  Datenordner  : {}", s.data_dir);
    }
    if state == "läuft" {
        match dienst::request(&Message::Status { v: PROTOCOL }) {
            Ok(Message::StatusAntwort { version, etw_prozesse, etw_dns, agent_wache, schattenkopien, .. }) => {
                let yes = |b: bool| if b { "aktiv" } else { "inaktiv" };
                say!("  Version      : {version}");
                say!("  Prozessstarts: {}", yes(etw_prozesse));
                say!("  DNS-Abfragen : {}", yes(etw_dns));
                say!("  Agent-Wache  : {}", yes(agent_wache));
                if let Some(s) = schattenkopien {
                    say!("  Schattenkopien: {s}");
                }
            }
            Ok(other) => say!("  Unerwartete Antwort: {other:?}"),
            Err(e) => say!("  Keine Antwort: {e:#}"),
        }
    }
    Ok(())
}
