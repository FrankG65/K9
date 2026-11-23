//! Ransomware detection in the service (see `k9_core::ransom`): watches the document folders
//! of all users, counts files that suddenly look encrypted and names – from the file opens the
//! ETW session sees anyway – the program that did it. Runs as SYSTEM: malware with user rights
//! cannot end it the way it can end the agent.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use k9_core::ransom::{self, Openers, Suspect};
use k9_core::realtime::{self as rt, Change, FileEvent};

use crate::Svc;

const REASON: &str = "viele Dateien wurden in kurzer Zeit verschlüsselt/überschrieben";
/// Without a culprit the message waits this long: the file opens reach the service through
/// the event session a moment after the change itself (measured 20.11.2026: up to seconds).
const NAME_WAIT: Duration = Duration::from_millis(1500);
/// How long the search for the culprit of a burst goes on.
const SEARCH: Duration = Duration::from_secs(20);
/// An unknown program (unsigned or from a user-writable folder) is stopped earlier: after this
/// many files that look encrypted, provided all of them were opened by it. Signed, installed
/// programs keep the general threshold (`rt::RANSOMWARE_BURST`).
const EARLY: usize = 5;

fn openers() -> &'static Mutex<Openers> {
    static O: OnceLock<Mutex<Openers>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(Openers::default()))
}

/// Opens seen by the ETW callback, and how many of them could not be noted at once.
static OPENS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WAITED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Called from the ETW callback for every file open in a watched user folder.
pub fn opened(tail: String, pid: u32) {
    use std::sync::atomic::Ordering::Relaxed;
    OPENS.fetch_add(1, Relaxed);
    let mut o = match openers().try_lock() {
        Ok(o) => o,
        // The search for a culprit holds the lock only for a moment: wait instead of losing
        // exactly the opens it is looking for.
        Err(_) => {
            WAITED.fetch_add(1, Relaxed);
            match openers().lock() {
                Ok(o) => o,
                Err(_) => return,
            }
        }
    };
    o.record(tail, pid, Instant::now());
}

/// A burst whose culprit is not known yet.
struct Pending {
    files: Vec<PathBuf>,
    since: Instant,
    /// The message "program unknown" has gone out.
    reported: bool,
}

pub fn run(svc: Arc<Svc>) {
    let dirs = ransom::profile_dirs();
    if dirs.is_empty() {
        tracing::info!("Ransomware-Wache: keine Benutzerordner gefunden");
        return;
    }
    let (tx, rx) = mpsc::channel::<FileEvent>();
    for d in &dirs {
        let (d, tx) = (d.clone(), tx.clone());
        crate::spawn("vs-ransom-ordner", move || {
            if let Err(e) = rt::watch_directory(&d, tx) {
                tracing::warn!("Ransomware-Wache: {e:#}");
            }
        });
    }
    drop(tx);
    tracing::info!("Ransomware-Wache: {} Benutzerordner überwacht (Erkennung im Dienst)", dirs.len());
    let mut quick = rt::Debouncer::default();
    let mut burst = rt::BurstDetector::new(Duration::from_secs(20), rt::RANSOMWARE_BURST);
    let mut pending: Option<Pending> = None;
    // Files that looked encrypted in the last 20 seconds (for the early stop of unknown programs).
    let mut recent: std::collections::VecDeque<(Instant, PathBuf)> = std::collections::VecDeque::new();
    let mut last_flush = Instant::now();
    let mut last_report: Option<Instant> = None;
    let mut deletions = rt::Deletions::default();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(ev) => match ev.change {
                Change::Removed | Change::RenamedFrom => {
                    if ev.change == Change::Removed {
                        deletions.note(Instant::now());
                    }
                    quick.forget(&ev.path);
                }
                _ => quick.touch(ev.path, Instant::now()),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if svc.is_stopping() {
            return;
        }
        if !svc.live().echtzeit.ransomware {
            let _ = quick.ready(Instant::now(), Duration::ZERO);
            pending = None;
            recent.clear();
            continue;
        }
        // 80 ms after the last change (150 ms until 0.36.0), see the agent's file watch.
        for path in quick.ready(Instant::now(), Duration::from_millis(80)) {
            if !std::fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
                continue;
            }
            if rt::looks_encrypted_by_ransomware(&path, deletions.recent(Instant::now())) {
                recent.push_back((Instant::now(), path.clone()));
                if let Some((files, new)) = burst.record(path, Instant::now()) {
                    // The opens of these files may still sit in the buffers of the event session.
                    crate::etw::flush();
                    match pending.as_mut() {
                        // The attack goes on while its program is still searched: more evidence.
                        Some(p) => {
                            p.files.extend(files);
                            let cut = p.files.len().saturating_sub(240);
                            p.files.drain(..cut);
                        }
                        None => {
                            // The same attack after its program was frozen or reported: only
                            // a newly frozen program is worth a second message.
                            let just_reported = last_report.is_some_and(|t| t.elapsed() < Duration::from_secs(20));
                            pending = Some(Pending { files, since: Instant::now(), reported: !new || just_reported });
                        }
                    }
                }
            }
        }
        // Early stop: a few encrypted files, all opened by one unknown program.
        while recent.front().is_some_and(|(t, _)| t.elapsed() > Duration::from_secs(20)) {
            recent.pop_front();
        }
        if pending.is_none() && recent.len() >= EARLY {
            if last_flush.elapsed() >= Duration::from_millis(150) {
                crate::etw::flush();
                last_flush = Instant::now();
            }
            let files: Vec<PathBuf> = recent.iter().map(|(_, p)| p.clone()).collect();
            if let Outcome::Suspects(suspects, frozen) = resolve(&svc, &files, true) {
                let just_reported = last_report.is_some_and(|t| t.elapsed() < Duration::from_secs(20));
                if frozen || !just_reported {
                    report(&svc, &files, &suspects, frozen);
                    last_report = Some(Instant::now());
                }
                recent.clear();
                burst = rt::BurstDetector::new(Duration::from_secs(20), rt::RANSOMWARE_BURST);
            }
        }
        // Search the culprit of an open burst again and again: with every tick more opens
        // have arrived.
        if let Some(p) = pending.as_mut() {
            match resolve(&svc, &p.files, false) {
                Outcome::Harmless => pending = None,
                Outcome::Suspects(suspects, frozen) => {
                    if frozen || !p.reported {
                        report(&svc, &p.files, &suspects, frozen);
                        last_report = Some(Instant::now());
                    }
                    pending = None;
                    recent.clear();
                }
                Outcome::Unknown => {
                    if !p.reported && p.since.elapsed() >= NAME_WAIT {
                        report(&svc, &p.files, &[], false);
                        last_report = Some(Instant::now());
                        p.reported = true;
                    }
                    if p.since.elapsed() >= SEARCH {
                        pending = None;
                    }
                }
            }
        }
    }
}

/// Programs this module has frozen: (process ID, creation time) – the ID alone is reused by Windows.
fn frozen() -> &'static Mutex<Vec<(u32, i64, Instant)>> {
    static F: OnceLock<Mutex<Vec<(u32, i64, Instant)>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(Vec::new()))
}

fn frozen_before(pid: u32, start: i64) -> bool {
    frozen().lock().map(|f| f.iter().any(|(p, s, _)| *p == pid && *s == start)).unwrap_or(false)
}

fn note_frozen(pid: u32, start: i64) {
    if let Ok(mut f) = frozen().lock() {
        f.retain(|(_, _, t)| t.elapsed() < Duration::from_secs(3600));
        f.push((pid, start, Instant::now()));
    }
}

enum Outcome {
    /// Packed files written by a game: no alarm.
    Harmless,
    /// The programs that opened the files, and whether one was frozen.
    Suspects(Vec<Suspect>, bool),
    /// No program is known (yet).
    Unknown,
}

/// K9's own processes (the agent scans changed files and opens them too).
fn own_pids() -> Vec<u32> {
    let own = k9_core::dienst::install_dir();
    let mut v = vec![std::process::id()];
    for (pid, p) in rt::process_snapshot() {
        if p.name.to_ascii_lowercase().starts_with("k9") && rt::process_path(pid).is_some_and(|path| path.starts_with(&own)) {
            v.push(pid);
        }
    }
    v
}

/// `early`: only an unknown program that opened at least `EARLY` of the files counts.
fn resolve(svc: &Svc, files: &[PathBuf], early: bool) -> Outcome {
    let live = svc.live().clone();
    let ignore = own_pids();
    let (culprits, known, table) = match openers().lock() {
        Ok(o) => (o.culprits(files, &ignore, Instant::now()), o.known(files), o.len()),
        Err(_) => (Vec::new(), 0, 0),
    };
    // One line per second while a culprit is searched (shows whether the opens arrive late).
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let due = LAST.lock().map(|mut l| {
        let due = l.is_none_or(|t| t.elapsed() >= Duration::from_secs(1));
        if due {
            *l = Some(Instant::now());
        }
        due
    });
    if !early && due.unwrap_or(false) {
        tracing::debug!(
            "Ransomware-Wache: {} Dateien, zu {known} ist ein Öffnen bekannt, Tabelle {table}, Öffnungen gesamt {} (gewartet {}), Kandidaten {:?}",
            files.len(),
            OPENS.load(std::sync::atomic::Ordering::Relaxed),
            WAITED.load(std::sync::atomic::Ordering::Relaxed),
            culprits.iter().take(4).collect::<Vec<_>>()
        );
    }
    let arbeit = k9_core::arbeitsordner::Arbeit::from_config(&live.arbeitsordner);
    let only_work = files.iter().all(|f| arbeit.folder_of(&f.to_string_lossy()).is_some());
    let own = k9_core::dienst::install_dir().display().to_string();
    // A program counts when it opened at least three of the files and at least half as many
    // as the program that opened most (a single open proves nothing; the opens of the newest
    // files may not have arrived yet, so the share of all files says little).
    let enough = (culprits.first().map(|(_, n)| *n).unwrap_or(0) / 2).max(if early { EARLY } else { 3 });
    let mut suspects: Vec<Suspect> = Vec::new();
    let mut frozen = false;
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    for (pid, count) in culprits.into_iter().filter(|(_, n)| *n >= enough) {
        let Some((path, start)) = rt::process_path_and_start(pid) else { continue };
        let text = path.display().to_string();
        let signer = k9_core::autostart::is_signed(&path).then(|| k9_core::treiber::signer_name(&path)).flatten();
        match k9_core::anhalten::freeze_allowed(&text, signer.as_deref(), &live.gaming.spiele_ordner, &live.gaming.spiele_prozesse, &own) {
            // Games write packed save files, anti-cheat guards them: no alarm from these.
            Err(why @ ("Spiel" | "Anti-Cheat")) => {
                if !early {
                    tracing::info!("Ransomware-Wache: {} gepackte Dateien von {text} ({why}) – kein Alarm", files.len());
                }
                return Outcome::Harmless;
            }
            // Windows parts, Microsoft/Trend Micro, K9: readers of the changed files (search
            // index, virus scan, preview), not the writer.
            Err(_) => continue,
            Ok(()) => {}
        }
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        // Early: only programs nobody vouches for (no valid signature, or run from a folder
        // every program of the user may write to).
        if early && signer.is_some() && !k9_core::autostart::is_user_writable(&path) {
            continue;
        }
        let work = only_work || arbeit.is_program(&path) || arbeit.folder_of(&text).is_some();
        // A program frozen a moment ago is not frozen (and not reported) a second time: the
        // files it wrote just before still arrive afterwards.
        let already = frozen_before(pid, start);
        if live.echtzeit.ransomware_prozess_anhalten && !work && !already {
            let ok = k9_core::schutz::as_system(|| Ok::<bool, anyhow::Error>(rt::suspend_process(pid))).unwrap_or(false);
            if ok {
                note_frozen(pid, start);
                tracing::warn!("Ransomware-Verdacht: angehalten bis zur Entscheidung: {text} (PID {pid}, {count} von {} Dateien)", files.len());
                frozen = true;
            }
        }
        suspects.push(Suspect { pid, path, start: Some(start), files: count });
        if suspects.len() >= 3 {
            break;
        }
    }
    if suspects.is_empty() { Outcome::Unknown } else { Outcome::Suspects(suspects, frozen) }
}

fn report(svc: &Svc, files: &[PathBuf], suspects: &[Suspect], frozen: bool) {
    let names: Vec<String> = suspects.iter().map(|s| format!("{} (PID {})", s.path.display(), s.pid)).collect();
    tracing::error!(
        "RANSOMWARE-VERDACHT (Dienst): {} Dateien verschlüsselt/überschrieben; Programme: {}; Dateien (Beispiele): {}",
        files.len(),
        if names.is_empty() { "nicht bestimmbar".to_string() } else { names.join(", ") },
        files.iter().take(5).map(|f| f.display().to_string()).collect::<Vec<_>>().join(" | ")
    );
    svc.report(&ransom::finding(k9_core::sprache::tr(REASON), "viele", files, suspects, frozen));
}
