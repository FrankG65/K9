//! k9-agent – background agent of the K9.
//!
//! Runs in user mode at low priority, executes scheduled scans (postponed
//! while gaming), delivers queued notifications after a game and serves the
//! local dashboard on 127.0.0.1.

mod dashboard;
mod dienst_client;
mod pflege;
mod realtime;
mod scheduler;
mod tray;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::Notify;
use k9_core::app::App;
use k9_core::gaming::GamingState;
use k9_core::{priority, secrets};

#[derive(Parser)]
#[command(name = "k9-agent", version, about = "K9 - Hintergrund-Agent mit Dashboard")]
struct Args {
    /// Keine geplanten Scans und keine automatischen Quellen-Updates (nur Dashboard und Meldungen)
    #[arg(long)]
    ohne_zeitplan: bool,
    /// Dashboard nach dem Start im Browser oeffnen
    #[arg(long)]
    browser: bool,
    /// Echtzeitschutz nicht starten (z. B. fuer Tests)
    #[arg(long)]
    ohne_echtzeit: bool,
}

/// State shared between scheduler and dashboard.
pub struct Shared {
    pub app: App,
    pub token: String,
    pub gaming: Mutex<GamingState>,
    pub scan_running: AtomicBool,
    /// A Meldefenster is currently on screen.
    pub window_open: AtomicBool,
    /// A source update is running.
    pub updating: AtomicBool,
    pub stopping: AtomicBool,
    pub scan_now: Notify,
    pub last_scan: Mutex<Option<String>>,
    /// The running scan is asked to stop ("Scan abbrechen" in the dashboard).
    pub scan_cancel: AtomicBool,
    /// For the dashboard: what kind of scan runs, how many files it has reached, where it is.
    pub scan_kind: Mutex<String>,
    pub scan_seen: std::sync::atomic::AtomicU64,
    pub scan_current: Mutex<String>,
    /// The Windows service watches process starts (the agent then skips its own start heuristics).
    pub dienst_prozesse: AtomicBool,
    /// Service status for the dashboard.
    pub dienst_text: Mutex<String>,
    /// Start of the agent (background care waits a moment after it).
    pub started: std::time::Instant,
}

impl Shared {
    pub fn port(&self) -> u16 {
        self.app.config.dashboard.port
    }
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }
}

fn main() {
    k9_core::term::init_console();
    if let Err(e) = start(Args::parse()) {
        k9_core::say_err!("Fehler: {e:#}");
        std::process::exit(1);
    }
}

/// Exit code of a second start (the agent already runs).
pub const ALREADY_RUNNING: i32 = 3;

fn start(args: Args) -> Result<()> {
    let app = App::open()?;
    if !single_instance(&app) {
        // Second start (e.g. double-click on the start file): just open the dashboard.
        k9_core::say!("Der K9-Agent laeuft bereits – es wird kein zweiter gestartet.");
        if args.browser {
            let token = secrets::dashboard_token(&app.paths)?;
            let url = format!("http://127.0.0.1:{}/?t={token}", app.config.dashboard.port);
            let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
            k9_core::say!("Dashboard wird geoeffnet.");
        }
        std::process::exit(ALREADY_RUNNING);
    }
    let _log_guard = init_logging(&app);
    priority::enter_background_mode();

    let token = secrets::dashboard_token(&app.paths)?;
    let shared = Arc::new(Shared {
        app,
        token,
        gaming: Mutex::new(GamingState::default()),
        scan_running: AtomicBool::new(false),
        window_open: AtomicBool::new(false),
        updating: AtomicBool::new(false),
        stopping: AtomicBool::new(false),
        scan_now: Notify::new(),
        last_scan: Mutex::new(None),
        scan_cancel: AtomicBool::new(false),
        scan_kind: Mutex::new(String::new()),
        scan_seen: std::sync::atomic::AtomicU64::new(0),
        scan_current: Mutex::new(String::new()),
        dienst_prozesse: AtomicBool::new(false),
        dienst_text: Mutex::new(k9_core::t!("wird geprüft …", "being checked …").into()),
        started: std::time::Instant::now(),
    });

    // Few worker threads: the agent is mostly idle.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    if !args.ohne_echtzeit {
        realtime::start(shared.clone(), rt.handle().clone());
        dienst_client::start(shared.clone());
    }
    rt.block_on(run(shared, args))
}

async fn run(shared: Arc<Shared>, args: Args) -> Result<()> {
    let port = shared.port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("Port {port} ist belegt – läuft der Agent schon? (Port in config.toml unter [dashboard] änderbar)"))?;
    let url = format!("http://127.0.0.1:{port}/?t={}", shared.token);
    tracing::info!("Agent gestartet. Daten: {}", shared.app.paths.data_dir.display());
    k9_core::say!("K9-Agent läuft (niedrige Priorität). Beenden mit Strg+C.");
    k9_core::say!("Dashboard: {url}");
    if args.browser {
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
    }

    let router = dashboard::router(shared.clone());
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("Dashboard-Server beendet: {e}");
        }
    });
    let sched = tokio::spawn(scheduler::run(shared.clone(), !args.ohne_zeitplan));
    // Not in test/portable mode (K9_HOME): tests never put an icon on the user's taskbar.
    if !shared.app.paths.portable {
        tray::start(shared.clone());
    }

    tokio::signal::ctrl_c().await?;
    k9_core::say!("Agent wird beendet …");
    // Strg+C in the visible window is a deliberate stop: no self-protection alarm.
    if !shared.app.paths.portable && k9_core::dienst::service_running() {
        let _ = k9_core::dienst::request(&k9_core::dienst::Message::AgentStopp { v: k9_core::dienst::PROTOCOL, minuten: 60 });
    }
    shared.stopping.store(true, Ordering::Relaxed);
    tray::stop();
    server.abort();
    sched.abort();
    Ok(())
}

fn init_logging(app: &App) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::prelude::*;
    let file = tracing_appender::rolling::daily(app.paths.log_dir(), "agent.log");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = tracing_subscriber::EnvFilter::try_from_env("K9_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(writer).with_ansi(false))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_writer(|| k9_core::term::AsciiWriter(std::io::stdout())),
        )
        .init();
    guard
}

/// Named mutex per data folder: only one agent per user and data folder.
/// The handle is kept open for the lifetime of the process.
fn single_instance(app: &App) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    let id = &k9_core::sha256_hex(app.paths.data_dir.to_string_lossy().to_lowercase().as_bytes())[..16];
    let name: Vec<u16> = format!("Local\\K9-Agent-{id}\0").encode_utf16().collect();
    // SAFETY: valid NUL-terminated name; the handle is intentionally leaked.
    unsafe {
        match CreateMutexW(None, true, PCWSTR(name.as_ptr())) {
            Ok(h) => {
                let exists = GetLastError() == ERROR_ALREADY_EXISTS;
                if exists {
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                }
                !exists
            }
            Err(_) => true,
        }
    }
}
