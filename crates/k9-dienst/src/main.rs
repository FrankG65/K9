//! k9-dienst – Windows service "K9-Dienst".
//!
//! Runs as LocalSystem and only does what the agent cannot do in user mode:
//! * ETW: every process start (also very short ones) and every DNS query,
//!   checked with the same rules/lists as the agent,
//! * Agent-Wache: restarts the agent in the user's session and reports
//!   unexpected stops (self-protection),
//! * carries out a user decision that needs administrator rights – only for
//!   findings it reported itself (random token), never arbitrary commands.
//!
//! Findings are never acted on automatically: they go to the agent, which
//! asks the user like for every other finding.
//!
//! `k9-dienst --konsole` runs the same code in a console (tests, as admin).

mod aufraeumen;
mod bestaetigung;
mod eingang_wache;
mod konten_wache;
mod wmi_wache;
mod einstellungen;
mod etw;
mod quellen;
mod ransom_wache;
mod schattenkopie;
mod selbstschutz;
mod server;
mod sperre;
mod stoerungen;
mod treiber_wache;
mod vt;
mod wache;

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use k9_core::app::App;
use k9_core::dienst::{self, Message, Settings, WireFinding, PROTOCOL};
use k9_core::model::Finding;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

/// Findings waiting for the agent (kept while the agent is not connected).
const MAX_QUEUE: usize = 200;

pub struct Svc {
    pub app: App,
    pub settings: Settings,
    queue: Mutex<VecDeque<Message>>,
    queue_cv: Condvar,
    /// Tokens of findings this service reported (only these can be acted on).
    /// Own copy of every finding reported (by token); only these values are
    /// used for actions with SYSTEM rights – never values from the user's database.
    tokens: Mutex<HashMap<String, WireFinding>>,
    pub etw_processes: AtomicBool,
    pub etw_dns: AtomicBool,
    pub watchdog: AtomicBool,
    /// The user paused the agent on purpose (`k9 agent-beenden`) until then.
    /// (until, requested at)
    pub agent_pause: Mutex<Option<(Instant, Instant)>>,
    pub stopping: AtomicBool,
    /// Signs the user's decisions (None if the key could not be set up).
    pub signer: Option<&'static k9_core::schutz::Signer>,
    /// A source update is running.
    pub updating: AtomicBool,
    /// Gaming state reported by the agent over the pipe.
    pub gaming: GamingState,
    /// Last report of the agent that the user is idle (15+ minutes without input).
    pub user_idle: Mutex<Option<Instant>>,
    /// Shadow copy state for the status (only when switched on).
    pub vss_status: Mutex<Option<String>>,
    /// This start came from `k9 dienst aktualisieren` (the update starts the agent itself).
    pub started_by_update: AtomicBool,
    pub started: Instant,
    /// Effective configuration: config.toml with only confirmed weakenings, updated by the
    /// settings watcher (switches read from here take effect without a restart).
    pub live: std::sync::RwLock<k9_core::config::Config>,
    /// Self-test at the start (JSON of k9_core::umzug::Gesundheit), asked for by the update.
    pub gesundheit: Option<String>,
    /// `k9 firewall entfernen`: K9's block rules stay removed (no restore) until the next
    /// regular renewal.
    pub fw_pause: AtomicBool,
}

/// "A game is running", as last reported by the agent. Expires after five minutes
/// without a new report (agent ended, no longer connected = not gaming).
#[derive(Default)]
pub struct GamingState(Mutex<Option<Instant>>);

const GAMING_VALID: Duration = Duration::from_secs(300);

impl GamingState {
    /// Stores the report; true if the state changed (for the log).
    pub fn report(&self, active: bool, now: Instant) -> bool {
        let mut g = self.0.lock().unwrap();
        let before = g.is_some_and(|until| now < until);
        *g = active.then_some(now + GAMING_VALID);
        before != active
    }

    pub fn active(&self, now: Instant) -> bool {
        self.0.lock().unwrap().is_some_and(|until| now < until)
    }
}

impl Svc {
    /// Freezes the process of a critical finding (opt-in) and marks the finding.
    fn freeze(&self, f: &mut Finding) {
        let d = f.details.clone().unwrap_or_default();
        let Some((pid, Some(exe), Some(start))) = k9_core::pipeline::process_targets(&d).into_iter().next() else { return };
        let path = exe.display().to_string();
        if k9_core::realtime::same_process(pid, k9_core::realtime::process_path_and_start(pid), &exe, start).is_err() {
            return; // already gone or another process
        }
        let signer = k9_core::autostart::is_signed(&exe).then(|| k9_core::treiber::signer_name(&exe)).flatten();
        let (ordner, prozesse) = {
            let l = self.live();
            (l.gaming.spiele_ordner.clone(), l.gaming.spiele_prozesse.clone())
        };
        let own = k9_core::dienst::install_dir().display().to_string();
        if let Err(why) = k9_core::anhalten::freeze_allowed(&path, signer.as_deref(), &ordner, &prozesse, &own) {
            tracing::info!("Nicht angehalten ({why}): {path}");
            return;
        }
        let ok = k9_core::schutz::as_system(|| Ok::<bool, anyhow::Error>(k9_core::realtime::suspend_process(pid))).unwrap_or(false);
        if ok {
            tracing::warn!("Angehalten bis zur Entscheidung: {path} (PID {pid})");
            k9_core::anhalten::mark_frozen(f, pid, &path, start);
        }
    }

    /// Ransomware deletes the recovery data through Windows tools (vssadmin, wmic, bcdedit) before
    /// it encrypts. The tool itself is a Windows part and already running; frozen is the program
    /// that started it: the nearest ancestor that may be frozen (never Windows parts, games,
    /// anti-cheat, Microsoft/Trend Micro, K9). Only with "ransomware-anhalten" switched on.
    ///
    /// `recorded`: the starters as the service saw them start (process ID, start time), nearest
    /// first. They are tried first: when the event arrives, the helper in between (cmd.exe) has
    /// often ended, and the walk over the running processes then stops before it reaches the
    /// program (Babuk in the test of 21.11.2026: the deletion was reported six seconds before
    /// the first file was encrypted, but nothing was frozen).
    pub fn freeze_starter(&self, f: &mut Finding, ppid: u32, recorded: &[(u32, i64, String)]) {
        let procs = k9_core::realtime::process_snapshot();
        let (ordner, prozesse) = {
            let l = self.live();
            (l.gaming.spiele_ordner.clone(), l.gaming.spiele_prozesse.clone())
        };
        let own = k9_core::dienst::install_dir().display().to_string();
        for (pid, began, _) in recorded {
            // Still the same process? (IDs are reused.)
            let Some((exe, start)) = k9_core::realtime::process_path_and_start(*pid) else { continue };
            if (start - began).abs() >= 10_000_000 {
                continue;
            }
            let path = exe.display().to_string();
            let signer = k9_core::autostart::is_signed(&exe).then(|| k9_core::treiber::signer_name(&exe)).flatten();
            if k9_core::anhalten::freeze_allowed(&path, signer.as_deref(), &ordner, &prozesse, &own).is_ok() {
                let ok = k9_core::schutz::as_system(|| Ok::<bool, anyhow::Error>(k9_core::realtime::suspend_process(*pid))).unwrap_or(false);
                if ok {
                    tracing::warn!("Wiederherstellung wird sabotiert - angehalten bis zur Entscheidung: {path} (PID {pid})");
                    k9_core::anhalten::mark_frozen(f, *pid, &path, start);
                }
                return;
            }
        }
        let mut pid = ppid;
        for _ in 0..5 {
            let Some((exe, start)) = k9_core::realtime::process_path_and_start(pid) else { return };
            let path = exe.display().to_string();
            let signer = k9_core::autostart::is_signed(&exe).then(|| k9_core::treiber::signer_name(&exe)).flatten();
            if k9_core::anhalten::freeze_allowed(&path, signer.as_deref(), &ordner, &prozesse, &own).is_ok() {
                let ok = k9_core::schutz::as_system(|| Ok::<bool, anyhow::Error>(k9_core::realtime::suspend_process(pid))).unwrap_or(false);
                if ok {
                    tracing::warn!("Wiederherstellung wird sabotiert - angehalten bis zur Entscheidung: {path} (PID {pid})");
                    k9_core::anhalten::mark_frozen(f, pid, &path, start);
                }
                return;
            }
            // cmd.exe, powershell.exe …: one step further up.
            match procs.get(&pid).map(|p| p.ppid) {
                Some(next) if next > 4 && next != pid => pid = next,
                _ => return,
            }
        }
    }

    /// The effective configuration (see `live`).
    pub fn live(&self) -> std::sync::RwLockReadGuard<'_, k9_core::config::Config> {
        self.live.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues a finding for the agent (with a new token).
    pub fn report(&self, f: &Finding) {
        let mut frozen;
        let freeze_on = self.live().echtzeit.kritische_prozesse_anhalten;
        let f = if freeze_on && k9_core::anhalten::qualifies(f) {
            frozen = f.clone();
            self.freeze(&mut frozen);
            &frozen
        } else {
            f
        };
        let token = dienst::new_token();
        let msg = Message::Fund { v: PROTOCOL, token: token.clone(), fund: WireFinding::from(f) };
        if let Err(e) = dienst::validate(&msg) {
            tracing::warn!("Fund nicht gesendet (ungültig): {e:#}");
            return;
        }
        // Kept in the service database until delivered: a restart before the agent
        // connects loses nothing; the same finding is not queued twice.
        let key = format!("{}|{}|{}", f.rule_id, f.sha256, f.path.display());
        let stored = serde_json::to_string(&msg)
            .map_err(anyhow::Error::from)
            .and_then(|json| self.app.store()?.outbox_add(&token, &key, &json, MAX_QUEUE));
        match stored {
            Ok(false) => {
                tracing::debug!("Fund wartet bereits auf den Agent: {}", f.path.display());
                return;
            }
            Ok(true) => {}
            Err(e) => tracing::warn!("Fund nicht dauerhaft gespeichert: {e:#}"),
        }
        tracing::warn!("Fund: {} – {}", f.threat_name, f.path.display());
        self.remember_token(&token, WireFinding::from(f));
        self.enqueue(msg);
    }

    fn remember_token(&self, token: &str, f: WireFinding) {
        let mut t = self.tokens.lock().unwrap();
        if t.len() > 10_000 {
            t.clear();
        }
        t.insert(token.to_string(), f);
    }

    fn enqueue(&self, msg: Message) {
        let mut q = self.queue.lock().unwrap();
        if q.len() >= MAX_QUEUE {
            q.pop_front();
        }
        q.push_back(msg);
        self.queue_cv.notify_all();
    }

    /// After a restart: findings not yet delivered go to the agent again.
    fn restore_outbox(&self) {
        let waiting = match self.app.store().and_then(|s| s.outbox_all()) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!("Wartende Funde nicht gelesen: {e:#}");
                return;
            }
        };
        let mut n = 0;
        for json in waiting {
            if let Ok(msg @ Message::Fund { .. }) = serde_json::from_str::<Message>(&json) {
                if let Message::Fund { token, fund, .. } = &msg {
                    self.remember_token(token, fund.clone());
                }
                self.enqueue(msg);
                n += 1;
            }
        }
        if n > 0 {
            tracing::info!("{n} wartende Funde für den Agent übernommen");
        }
    }

    /// The agent received the message: no longer kept.
    fn delivered(&self, msg: &Message) {
        if let Message::Fund { token, .. } = msg {
            if let Err(e) = self.app.store().and_then(|s| s.outbox_remove(token)) {
                tracing::debug!("Zugestellten Fund nicht ausgetragen: {e:#}");
            }
        }
    }

    /// The finding behind a token, as the service reported it.
    pub fn own_finding(&self, token: &str) -> Option<WireFinding> {
        self.tokens.lock().unwrap().get(token).cloned()
    }

    /// Next message for the agent, waits up to `wait`.
    fn next_message(&self, wait: Duration) -> Option<Message> {
        let mut q = self.queue.lock().unwrap();
        if q.is_empty() {
            q = self.queue_cv.wait_timeout(q, wait).unwrap().0;
        }
        q.pop_front()
    }

    fn requeue(&self, msg: Message) {
        self.queue.lock().unwrap().push_front(msg);
    }

    /// True if `path` is the installed agent program (only under Program Files).
    pub fn is_agent(&self, path: &Path) -> bool {
        let agent = Path::new(&self.settings.agent_path);
        dienst::is_installed_program(agent) && same_path(path, agent)
    }

    /// True for k9.exe next to the agent (the user's command line).
    pub fn is_k9(&self, path: &Path) -> bool {
        let k9 = Path::new(&self.settings.agent_path).with_file_name("k9.exe");
        dienst::is_installed_program(&k9) && same_path(path, &k9)
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--konsole") {
        k9_core::term::init_console();
        let (tx, rx) = mpsc::channel();
        let _ = std::thread::spawn(move || {
            let mut line = String::new();
            k9_core::say!("Dienst läuft in der Konsole – Eingabetaste beendet.");
            let _ = std::io::stdin().read_line(&mut line);
            let _ = tx.send(());
        });
        if let Err(e) = run(rx) {
            k9_core::say_err!("Fehler: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = service_dispatcher::start(dienst::SERVICE_NAME, ffi_service_main) {
        k9_core::say_err!("k9-dienst ist ein Windows-Dienst (Einrichtung: k9 dienst installieren). Test: k9-dienst --konsole ({e})");
        std::process::exit(2);
    }
}

/// When `k9` last announced a stop (seconds since 1970; 0: never).
static STOP_ANNOUNCED: AtomicU64 = AtomicU64::new(0);
/// Tells the main body to end (allowed stop, Windows shuts down).
static STOP_NOW: std::sync::OnceLock<mpsc::Sender<()>> = std::sync::OnceLock::new();
/// Stop requests that were refused, for the thread that reports them.
static STOP_ATTEMPTS: std::sync::OnceLock<mpsc::Sender<()>> = std::sync::OnceLock::new();

fn epoch_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// May the service obey a stop request? Only shortly after the announcement of `k9`.
fn stop_allowed(announced: u64, now: u64) -> bool {
    announced != 0 && now >= announced && now - announced <= dienst::STOP_VALID_SECS
}

/// Reports refused stop requests: a notice (at most one a minute), and for every program from
/// the internet that is still running a critical step of its attack chain.
fn stop_attempts(svc: Arc<Svc>, rx: mpsc::Receiver<()>) {
    let mut last: Option<Instant> = None;
    while rx.recv().is_ok() {
        tracing::warn!("Selbstschutz: Stopp des Dienstes ohne Ankündigung von k9 abgelehnt");
        etw::stop_attempt();
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            continue;
        }
        last = Some(Instant::now());
        svc.report(&wache::notice(
            "SELBSTSCHUTZ:DIENST-STOPPVERSUCH",
            k9_core::t!("Ein Programm wollte den K9-Dienst beenden", "A program wanted to stop the K9 service"),
            k9_core::t!("Windows wurde gebeten, den K9-Dienst zu stoppen – nicht über „k9 dienst stoppen“ oder „k9 dienst aktualisieren“. K9 hat das abgelehnt und läuft weiter. \
             Schadsoftware schaltet Schutzprogramme oft zuerst ab. Warst du das selbst (z. B. in der Diensteverwaltung von Windows oder mit „sc stop“), ist alles in Ordnung: \
             Zum Stoppen nimm „k9 dienst stoppen“.", "Windows was asked to stop the K9 service – not via “k9 dienst stoppen” or “k9 dienst aktualisieren”. K9 refused and keeps running. Malware often switches off security programs first. If that was you (e.g. in the services management of Windows or with “sc stop”), everything is fine: to stop it, use “k9 dienst stoppen”."),
        ));
    }
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let _ = STOP_NOW.set(tx);
    let end = || {
        if let Some(tx) = STOP_NOW.get() {
            let _ = tx.send(());
        }
    };
    // The handler must not own anything: the `windows-service` crate frees the handler after
    // the first stop request, because it takes the service to be over then. This service
    // refuses stop requests and lives on, and Windows keeps calling the handler. A closure
    // without captured values has no memory that could be freed (checked below); everything
    // it needs lives in statics. Seen in the sandbox on 21.11.2026: with a captured sender the
    // refused stop request ended the service all the same.
    let handler = move |ev| match ev {
        // Windows shuts down: always.
        ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            end();
            ServiceControlHandlerResult::NoError
        }
        // `k9` announces a stop (administrators only).
        ServiceControl::UserEvent(code) if code.to_raw() == dienst::STOP_CODE => {
            STOP_ANNOUNCED.store(epoch_secs(), Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Stop => {
            if stop_allowed(STOP_ANNOUNCED.load(Ordering::Relaxed), epoch_secs()) {
                end();
                ServiceControlHandlerResult::NoError
            } else {
                // Refused (the caller gets "access denied"), reported by `stop_attempts`.
                if let Some(a) = STOP_ATTEMPTS.get() {
                    let _ = a.send(());
                }
                ServiceControlHandlerResult::Other(5)
            }
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    assert_eq!(std::mem::size_of_val(&handler), 0, "der Handler darf nichts besitzen (siehe oben)");
    let Ok(handle) = service_control_handler::register(dienst::SERVICE_NAME, handler) else { return };
    let status = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    let code = match run(rx) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("Dienst beendet mit Fehler: {e:#}");
            1
        }
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, code));
}

/// Main body: until `stop` receives something.
fn run(stop: mpsc::Receiver<()>) -> Result<()> {
    k9_core::schutz::mark_service();
    harden_process();
    let settings = dienst::read_settings().context("Dienst ist nicht eingerichtet (k9 dienst installieren)")?;
    // Move from the old installation: before anything is created in the new folder.
    let moved = move_from_old_installation();
    // Own protected folders: log and temporary files never in a user folder.
    let own = k9_core::schutz::protected_dir();
    k9_core::schutz::secure_dir(&own, k9_core::schutz::SDDL_SHARED)?;
    let temp = own.join("temp");
    k9_core::schutz::secure_dir(&temp, k9_core::schutz::SDDL_PRIVATE)?;
    let logs = own.join("logs");
    k9_core::schutz::secure_dir(&logs, k9_core::schutz::SDDL_SHARED)?;
    // The installing user's folders (config, data) – touched only with the user's rights.
    for (k, v) in [
        ("USERPROFILE", settings.profile.as_str()),
        ("APPDATA", settings.appdata.as_str()),
        ("LOCALAPPDATA", settings.localappdata.as_str()),
    ] {
        std::env::set_var(k, v);
    }
    // Own data only in the protected folder – never a folder in the user profile.
    let (data_dir, accepted) = k9_core::schutz::service_data_dir(&settings.data_dir);
    std::env::set_var(k9_core::paths::DATA_ENV, &data_dir);
    std::env::set_var("TEMP", &temp);
    std::env::set_var("TMP", &temp);
    let _log = init_logging(&logs);
    match &moved {
        Some(r) if r == "ok" => tracing::info!("Übernahme aus der alten Installation (Virenscanner): ok"),
        Some(r) => tracing::error!("Übernahme aus der alten Installation (Virenscanner): {r}"),
        None => {}
    }
    let config_text = wache::as_session_user(&settings.user_sid, || {
        std::fs::read_to_string(std::path::Path::new(&settings.appdata).join(k9_core::APP_NAME).join("config.toml")).ok()
    })
    .flatten();
    let app = App::open_service(config_text)?;
    k9_core::priority::below_normal();
    tracing::info!("Dienst gestartet (Version {}), Daten: {}", env!("CARGO_PKG_VERSION"), data_dir.display());
    if !accepted {
        tracing::warn!(
            "Eingetragener Datenordner {} wird nicht verwendet (nur {} ist erlaubt) – bitte 'k9 dienst aktualisieren' ausführen",
            settings.data_dir,
            data_dir.display()
        );
    }

    if let Err(e) = k9_core::schutz::setup_protected_quarantine() {
        tracing::warn!("Geschützte Quarantäne nicht eingerichtet: {e:#}");
    }
    migrate(&app, &settings);
    let settings_sid = settings.user_sid.clone();
    let (signer, key_created) = setup_signer(&app, &settings_sid);
    let health = health(&app, key_created, moved.clone());
    let problems = health.problems(moved.is_some());
    if problems.is_empty() {
        tracing::info!("Selbsttest beim Start: in Ordnung ({} Entscheidungen gültig, {} Quarantäne-Dateien)", health.unterschrieben, health.quarantaene_da);
    } else {
        tracing::error!("Selbsttest beim Start: {}", problems.join("; "));
    }
    let live = std::sync::RwLock::new(app.config.clone());
    let svc = Arc::new(Svc {
        app,
        settings,
        queue: Mutex::new(VecDeque::new()),
        queue_cv: Condvar::new(),
        tokens: Mutex::new(HashMap::new()),
        etw_processes: AtomicBool::new(false),
        etw_dns: AtomicBool::new(false),
        watchdog: AtomicBool::new(false),
        agent_pause: Mutex::new(None),
        stopping: AtomicBool::new(false),
        signer,
        updating: AtomicBool::new(false),
        gaming: GamingState::default(),
        user_idle: Mutex::new(None),
        vss_status: Mutex::new(None),
        started_by_update: AtomicBool::new(false),
        started: Instant::now(),
        live,
        gesundheit: serde_json::to_string(&health).ok(),
        fw_pause: AtomicBool::new(false),
    });
    svc.restore_outbox();
    {
        let (atx, arx) = mpsc::channel();
        let _ = STOP_ATTEMPTS.set(atx);
        spawn("vs-stoppversuch", { let s = svc.clone(); move || stop_attempts(s, arx) });
    }

    let sd = Arc::new(dienst::SecDesc::from_sddl(&dienst::pipe_sddl(&svc.settings.user_sid))?);
    spawn("vs-meldungen", { let s = svc.clone(); let sd = sd.clone(); move || server::findings_server(s, sd) });
    spawn("vs-befehle", { let s = svc.clone(); let sd = sd.clone(); move || server::command_server(s, sd) });
    spawn("vs-etw", { let s = svc.clone(); move || etw::run(s) });
    spawn("vs-wache", { let s = svc.clone(); move || wache::run(s) });
    spawn("vs-wache-sofort", { let s = svc.clone(); move || wache::run_instant(s) });
    spawn("vs-einstellungen", { let s = svc.clone(); move || einstellungen::run(s) });
    spawn("vs-quellen", { let s = svc.clone(); move || quellen::run(s) });
    spawn("vs-treiber", { let s = svc.clone(); move || treiber_wache::run(s) });
    spawn("vs-selbstschutz", { let s = svc.clone(); move || selbstschutz::run(s) });
    spawn("vs-virustotal", { let s = svc.clone(); move || vt::run(s) });
    spawn("vs-schattenkopie", { let s = svc.clone(); move || schattenkopie::run(s) });
    spawn("vs-firewall", { let s = svc.clone(); move || sperre::run(s) });
    spawn("vs-eingangsregeln", { let s = svc.clone(); move || eingang_wache::run(s) });
    spawn("vs-anmeldungen", { let s = svc.clone(); move || konten_wache::run(s) });
    spawn("vs-wmi-autostart", { let s = svc.clone(); move || wmi_wache::run(s) });
    spawn("vs-ransomware", { let s = svc.clone(); move || ransom_wache::run(s) });

    let _ = stop.recv();
    tracing::info!("Dienst wird beendet");
    svc.stopping.store(true, Ordering::Relaxed);
    if let Ok(store) = svc.app.store() {
        k9_core::basis::mark_stopped(&store);
    }
    etw::stop();
    std::thread::sleep(Duration::from_millis(300));
    Ok(())
}

/// First start of K9 after the update: copies the protected folder of the old installation,
/// if the update asked for it (only exactly %ProgramData%\Virenscanner). Some(result) if asked.
fn move_from_old_installation() -> Option<String> {
    use k9_core::umzug;
    let asked = k9_core::winreg::read_string(k9_core::winreg::HKLM, dienst::REG_KEY, umzug::PENDING_VALUE)?;
    let _ = k9_core::winreg::delete_value(k9_core::winreg::HKLM, dienst::REG_KEY, umzug::PENDING_VALUE);
    let dirs = umzug::programdata();
    if !Path::new(&asked).eq(&dirs.old) {
        return Some(format!("Fehler: unerwarteter Ordner {asked}"));
    }
    Some(match umzug::copy_protected(&dirs.old, &dirs.new) {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("Fehler: {e:#}"),
    })
}

/// Self-test at the start: database, signatures of all decisions, key store, confirmed settings,
/// quarantine files.
fn health(app: &App, key_created: bool, moved: Option<String>) -> k9_core::umzug::Gesundheit {
    let mut h = k9_core::umzug::Gesundheit {
        schluessel_neu: key_created,
        schluessel_lesbar: k9_core::schutz::service_secrets_readable(),
        einstellungen_ok: k9_core::schutz::confirmed_settings_ok(),
        umzug: moved,
        ..Default::default()
    };
    if let Ok(store) = app.store() {
        h.db_ok = true;
        let pk = k9_core::schutz::public_key();
        if let Ok(d) = store.list_decisions() {
            h.entscheidungen = d.len();
            h.unterschrieben = d.iter().filter(|x| pk.as_deref().is_some_and(|k| k9_core::schutz::verify(k, x))).count();
        }
        if let Ok(q) = store.quarantine_files() {
            h.quarantaene = q.len();
            h.quarantaene_da = q.iter().filter(|p| Path::new(p).is_file()).count();
        }
    }
    h
}

/// Loads (or creates) the signing key. A new key signs the decisions that
/// already exist once (taken over at installation/update). Also returns whether it is new.
fn setup_signer(app: &App, sid: &str) -> (Option<&'static k9_core::schutz::Signer>, bool) {
    match k9_core::schutz::Signer::load_or_create() {
        Ok((signer, created)) => {
            if created {
                // The database lies in the user's folder: only with the user's rights.
                match wache::as_session_user(sid, || sign_existing(&signer, app)) {
                    Some(Ok(n)) => tracing::info!("Dienst-Schlüssel erzeugt, {n} bestehende Entscheidung(en) übernommen"),
                    Some(Err(e)) => tracing::warn!("Bestehende Entscheidungen nicht übernommen: {e:#}"),
                    None => tracing::warn!("Bestehende Entscheidungen nicht übernommen (niemand angemeldet)"),
                }
            }
            (Some(k9_core::schutz::set_local_signer(signer)), created)
        }
        Err(e) => {
            tracing::error!("Dienst-Schlüssel nicht verfügbar: {e:#}");
            (None, false)
        }
    }
}

/// One-time takeover of the user's quarantine and source data (with the
/// user's rights for reading, the service's rights for the protected copy).
/// The agent's data folder of the installing user: read only for the one-time takeover,
/// always with the user's rights.
fn user_data_dir(settings: &Settings) -> PathBuf {
    Path::new(&settings.localappdata).join(k9_core::APP_NAME)
}

pub fn migrate(app: &App, settings: &Settings) {
    let user = user_data_dir(settings);
    let r = wache::as_session_user(&settings.user_sid, || -> Result<()> {
        migrate_db(&user)?;
        migrate_quarantine(app, &user)?;
        quellen::migrate(app, &user)
    });
    match r {
        Some(Err(e)) => tracing::warn!("Übernahme in die geschützten Ordner: {e:#}"),
        None => tracing::debug!("Übernahme später (niemand angemeldet)"),
        Some(Ok(())) => {}
    }
}

/// The service's own database: findings, decisions, quarantine list, events
/// and disabled autostarts move there once (read with the user's rights).
fn migrate_db(user: &Path) -> Result<()> {
    let path = k9_core::schutz::protected_db_path();
    let store = k9_core::Store::open_protected(&path)?;
    k9_core::schutz::as_system(|| k9_core::schutz::set_security(&path, k9_core::schutz::SDDL_SHARED))?;
    if store.meta_get("uebernommen")?.is_some() {
        return Ok(());
    }
    let n = store.import_user_db(&user.join("k9.db"))?;
    store.meta_set("uebernommen", &k9_core::now_string())?;
    tracing::info!("Datenbank übernommen: {n} Einträge nach {}", path.display());
    store.log_event("info", &format!("Funde, Entscheidungen und Quarantäne-Liste in die geschützte Datenbank des Dienstes übernommen ({n} Einträge)"))?;
    Ok(())
}

/// Copies an open (user) file into a new protected file.
pub fn copy_to_protected(src: &Path, dest: &Path) -> Result<()> {
    let mut from = std::fs::File::open(src)?;
    let mut to = k9_core::schutz::as_system(|| std::fs::File::create(dest))?;
    std::io::copy(&mut from, &mut to)?;
    Ok(())
}

fn migrate_quarantine(app: &App, user: &Path) -> Result<()> {
    let Some(dir) = k9_core::schutz::protected_quarantine() else { return Ok(()) };
    let old = user.join("quarantaene");
    let store = app.store()?;
    let mut moved = 0;
    for e in store.list_quarantine()? {
        let file = PathBuf::from(&e.stored_file);
        if e.restored_at.is_some() || !file.starts_with(&old) || !file.is_file() {
            continue;
        }
        let Some(name) = file.file_name().filter(|n| n.to_string_lossy().ends_with(".vsq")) else { continue };
        let dest = dir.join(name);
        copy_to_protected(&file, &dest)?;
        store.set_quarantine_file(e.id, &dest.display().to_string())?;
        let _ = std::fs::remove_file(&file);
        moved += 1;
    }
    if moved > 0 {
        tracing::info!("{moved} Datei(en) in die geschützte Quarantäne {} verschoben", dir.display());
        store.log_event("info", &format!("{moved} Quarantäne-Datei(en) in den geschützten Ordner {} verschoben", dir.display()))?;
    }
    Ok(())
}

fn sign_existing(signer: &k9_core::schutz::Signer, app: &App) -> Result<usize> {
    let store = app.store()?;
    let list = store.list_decisions()?;
    for d in &list {
        store.set_decision_signature(d.id, &signer.sign(d))?;
    }
    Ok(list.len())
}

/// DLLs only from System32 and the program folder (never the working
/// directory or PATH); working directory = program folder.
fn harden_process() {
    use windows::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    // SAFETY: process-wide settings without pointers (empty string removes the cwd).
    unsafe {
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        let _ = SetDllDirectoryW(windows::core::w!(""));
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        let _ = std::env::set_current_dir(dir);
    }
}

pub fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    let _ = std::thread::Builder::new().name(name.into()).spawn(f);
}

fn init_logging(dir: &Path) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::prelude::*;
    std::fs::create_dir_all(dir).ok()?;
    let file = tracing_appender::rolling::daily(dir, "dienst.log");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = tracing_subscriber::EnvFilter::try_from_env("K9_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(writer).with_ansi(false))
        .with(tracing_subscriber::fmt::layer().with_target(false).with_writer(|| k9_core::term::AsciiWriter(std::io::stdout())))
        .try_init()
        .ok()?;
    Some(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_is_obeyed_only_shortly_after_the_announcement_of_k9() {
        assert!(!stop_allowed(0, 1000), "nie angekündigt");
        assert!(stop_allowed(1000, 1000));
        assert!(stop_allowed(1000, 1000 + dienst::STOP_VALID_SECS));
        assert!(!stop_allowed(1000, 1001 + dienst::STOP_VALID_SECS), "Ankündigung abgelaufen");
        assert!(!stop_allowed(2000, 1000), "Uhr zurückgestellt");
    }

    #[test]
    fn gaming_report_reaches_the_service_and_expires() {
        // The agent's message passes the protocol check and survives the pipe (JSON).
        let msg = Message::Spielmodus { v: PROTOCOL, aktiv: true };
        dienst::validate(&msg).unwrap();
        let back: Message = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
        // The service keeps it for five minutes; "beendet" or silence ends it.
        let state = GamingState::default();
        let t0 = Instant::now();
        assert!(!state.active(t0));
        assert!(state.report(true, t0), "erste Meldung ist eine Änderung");
        assert!(!state.report(true, t0 + Duration::from_secs(30)), "Wiederholung ist keine Änderung");
        assert!(state.active(t0 + Duration::from_secs(60)));
        assert!(!state.active(t0 + Duration::from_secs(31) + GAMING_VALID), "ohne neue Meldung vorbei");
        state.report(true, t0);
        assert!(state.report(false, t0 + Duration::from_secs(10)));
        assert!(!state.active(t0 + Duration::from_secs(11)));
    }
}
