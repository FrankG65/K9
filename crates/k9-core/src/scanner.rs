//! File walker: reads every file once in chunks, computes SHA-256 and feeds
//! all engines. A limited number of worker threads scan in parallel; files
//! that are unchanged since a clean scan with the same signature state are
//! skipped (scan cache).

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Instant, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::engine::{Engine, FileMeta};
use crate::model::Finding;

const CHUNK: usize = 256 * 1024;

/// Hook called between files; lets the agent pause scans while a game runs.
pub trait ScanControl {
    /// Called before each file. Return `false` to abort the scan.
    fn checkpoint(&self) -> bool {
        true
    }
    /// Called for each file the walk reaches (also unchanged and skipped ones): how many so far
    /// and which one. For a progress display; must be cheap.
    fn progress(&self, _files_seen: u64, _current: &Path) {}
}

/// Never pauses, never aborts (on-demand scans).
pub struct NoControl;
impl ScanControl for NoControl {}

/// Remembers files that were scanned clean.
pub trait ScanCache: Sync {
    fn is_clean(&self, path: &str, size: u64, mtime: i64) -> bool;
    fn mark_clean(&self, path: String, size: u64, mtime: i64);
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    /// Unchanged files skipped thanks to the scan cache.
    pub cached: u64,
    pub errors: u64,
    pub aborted: bool,
    pub seconds: f64,
    /// CPU time of the whole process during the scan (user + kernel).
    pub cpu_seconds: f64,
}

pub struct Scanner {
    engines: Vec<Box<dyn Engine>>,
    max_file_size: u64,
    excluded: Vec<PathBuf>,
    threads: usize,
}

impl Scanner {
    /// Rule hits of all engines in a block of process memory (see [`Engine::scan_memory`]).
    pub fn scan_memory(&self, data: &[u8], min_score: i64) -> Vec<(String, String, crate::model::Severity)> {
        self.engines.iter().flat_map(|e| e.scan_memory(data, min_score)).collect()
    }
}

/// Process CPU time (user + kernel) in seconds.
pub fn process_cpu_seconds() -> f64 {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: pseudo handle and valid out pointers.
    if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) }.is_err() {
        return 0.0;
    }
    let t = |f: FILETIME| ((u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)) as f64 / 1e7;
    t(k) + t(u)
}

fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    meta.modified().ok().and_then(|m| m.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The largest number of worker threads a scanner accepts. Which number a scan really uses is
/// decided by its caller (the configuration for ordinary scans – at most `MAX_CONFIG_THREADS` –,
/// `fast_threads()` of the agent for the fast full scan).
pub const MAX_CONFIG_THREADS: usize = 8;

pub const MAX_THREADS: usize = 32;

impl Scanner {
    pub fn new(engines: Vec<Box<dyn Engine>>, max_file_size: u64, excluded: Vec<PathBuf>) -> Self {
        let excluded = excluded.into_iter().map(|p| normalize(&p)).collect();
        Self { engines, max_file_size, excluded, threads: 1 }
    }

    /// Number of parallel worker threads (1 to `MAX_THREADS`).
    pub fn with_threads(mut self, n: usize) -> Self {
        self.threads = n.clamp(1, MAX_THREADS);
        self
    }

    /// Changes the number of worker threads of an existing scanner (1 to `MAX_THREADS`).
    pub fn set_threads(&mut self, n: usize) {
        self.threads = n.clamp(1, MAX_THREADS);
    }

    pub fn engine_ids(&self) -> Vec<&'static str> {
        self.engines.iter().map(|e| e.id()).collect()
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let p = normalize(path);
        self.excluded.iter().any(|ex| p.starts_with(ex))
    }

    pub fn scan(&self, roots: &[PathBuf], control: &dyn ScanControl) -> (Vec<Finding>, ScanStats) {
        self.scan_with(roots, control, None)
    }

    /// Scans files and folders recursively. Symlinks are not followed.
    pub fn scan_with(&self, roots: &[PathBuf], control: &dyn ScanControl, cache: Option<&dyn ScanCache>) -> (Vec<Finding>, ScanStats) {
        let started = Instant::now();
        let cpu_start = process_cpu_seconds();
        let findings = Mutex::new(Vec::new());
        let files = AtomicU64::new(0);
        let bytes = AtomicU64::new(0);
        let errors = AtomicU64::new(0);
        let mut stats = ScanStats::default();
        let mut seen = 0u64;
        let (tx, rx) = mpsc::sync_channel::<(PathBuf, u64, i64)>(256);
        let rx = Mutex::new(rx);

        std::thread::scope(|s| {
            for _ in 0..self.threads {
                s.spawn(|| loop {
                    let next = rx.lock().unwrap().recv();
                    let Ok((path, size, mtime)) = next else { break };
                    match self.scan_file(&path) {
                        Ok(Some((mut f, _))) => {
                            files.fetch_add(1, Ordering::Relaxed);
                            bytes.fetch_add(size, Ordering::Relaxed);
                            if f.is_empty() {
                                if let Some(c) = cache {
                                    c.mark_clean(path.to_string_lossy().to_string(), size, mtime);
                                }
                            } else {
                                findings.lock().unwrap().append(&mut f);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!("Fehler bei {}: {e}", path.display());
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }

            'roots: for root in roots {
                let walker = walkdir::WalkDir::new(root).follow_links(false).into_iter();
                let mut it = walker.filter_entry(|e| !self.is_excluded(e.path()));
                loop {
                    let entry = match it.next() {
                        None => break,
                        Some(Ok(e)) => e,
                        Some(Err(e)) => {
                            tracing::debug!("Nicht lesbar: {e}");
                            errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    // Before any skipping: "Abbrechen", the pause for a game and the progress
                    // display must also work while a repeated scan runs through files it knows.
                    if !control.checkpoint() {
                        stats.aborted = true;
                        break 'roots;
                    }
                    seen += 1;
                    control.progress(seen, entry.path());
                    let Ok(meta) = entry.metadata() else {
                        errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let size = meta.len();
                    if self.max_file_size > 0 && size > self.max_file_size {
                        stats.skipped += 1;
                        continue;
                    }
                    let path = absolute(entry.path());
                    let mtime = mtime_of(&meta);
                    if let Some(c) = cache {
                        if c.is_clean(&path.to_string_lossy(), size, mtime) {
                            stats.cached += 1;
                            continue;
                        }
                    }
                    if tx.send((path, size, mtime)).is_err() {
                        break 'roots;
                    }
                }
            }
            drop(tx);
        });

        stats.files = files.into_inner();
        stats.bytes = bytes.into_inner();
        stats.errors += errors.into_inner();
        stats.seconds = started.elapsed().as_secs_f64();
        stats.cpu_seconds = (process_cpu_seconds() - cpu_start).max(0.0);
        (findings.into_inner().unwrap(), stats)
    }

    /// Scans a single file. Returns `None` if it was skipped (too large).
    pub fn scan_file(&self, path: &Path) -> std::io::Result<Option<(Vec<Finding>, u64)>> {
        let size = std::fs::metadata(path)?.len();
        if self.max_file_size > 0 && size > self.max_file_size {
            return Ok(None);
        }
        let meta = FileMeta { path: absolute(path), size };
        let mut sessions: Vec<_> = self.engines.iter().filter_map(|e| e.begin(&meta)).collect();
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            for s in sessions.iter_mut() {
                s.feed(&buf[..n]);
            }
        }
        let sha = hex::encode(hasher.finalize());
        let findings = sessions.into_iter().flat_map(|s| s.finish(&meta, &sha)).collect();
        Ok(Some((findings, size)))
    }
}

/// Computes the SHA-256 of a file (streaming).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Lowercased absolute path for prefix comparisons (Windows paths are case-insensitive).
fn normalize(path: &Path) -> PathBuf {
    PathBuf::from(absolute(path).to_string_lossy().to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{test_pattern_bytes, HashListEngine, PatternEngine};

    fn engines() -> Vec<Box<dyn Engine>> {
        vec![Box::new(HashListEngine::new()), Box::new(PatternEngine::new())]
    }

    #[test]
    fn finds_test_file_and_respects_exclusions() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let sub = dir.path().join("sub");
        let skip = dir.path().join("ausgenommen");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&skip).unwrap();
        std::fs::write(sub.join("test.txt"), test_pattern_bytes()).unwrap();
        std::fs::write(skip.join("test.txt"), test_pattern_bytes()).unwrap();
        std::fs::write(dir.path().join("sauber.txt"), b"nichts").unwrap();
        let scanner = Scanner::new(engines(), 0, vec![skip.clone()]).with_threads(3);
        let (findings, stats) = scanner.scan(&[dir.path().to_path_buf()], &NoControl);
        assert_eq!(stats.files, 2);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].path.ends_with("sub\\test.txt"));
        assert_eq!(findings[0].sha256, crate::sha256_hex(&test_pattern_bytes()));
    }

    #[derive(Default)]
    struct MemCache(Mutex<std::collections::HashMap<String, (u64, i64)>>);
    impl ScanCache for MemCache {
        fn is_clean(&self, path: &str, size: u64, mtime: i64) -> bool {
            self.0.lock().unwrap().get(path) == Some(&(size, mtime))
        }
        fn mark_clean(&self, path: String, size: u64, mtime: i64) {
            self.0.lock().unwrap().insert(path, (size, mtime));
        }
    }

    #[test]
    fn cache_skips_unchanged_clean_files_only() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        for i in 0..20 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), format!("sauber {i}")).unwrap();
        }
        std::fs::write(dir.path().join("treffer.txt"), test_pattern_bytes()).unwrap();
        let scanner = Scanner::new(engines(), 0, vec![]).with_threads(2);
        let cache = MemCache::default();
        let (f1, s1) = scanner.scan_with(&[dir.path().to_path_buf()], &NoControl, Some(&cache));
        assert_eq!((s1.files, s1.cached, f1.len()), (21, 0, 1));
        let (f2, s2) = scanner.scan_with(&[dir.path().to_path_buf()], &NoControl, Some(&cache));
        // Clean files are skipped, the hit is scanned (and reported) again.
        assert_eq!((s2.files, s2.cached, f2.len()), (1, 20, 1));
        assert!(s2.seconds >= 0.0 && s2.cpu_seconds >= 0.0);
    }

    /// Records what the walk reports and stops it after `stop_after` files (0 = never).
    struct Probe {
        seen: AtomicU64,
        checks: AtomicU64,
        stop_after: u64,
    }
    impl Probe {
        fn new(stop_after: u64) -> Self {
            Self { seen: AtomicU64::new(0), checks: AtomicU64::new(0), stop_after }
        }
    }
    impl ScanControl for Probe {
        fn checkpoint(&self) -> bool {
            let n = self.checks.fetch_add(1, Ordering::Relaxed) + 1;
            self.stop_after == 0 || n <= self.stop_after
        }
        fn progress(&self, files_seen: u64, _current: &Path) {
            self.seen.store(files_seen, Ordering::Relaxed);
        }
    }

    #[test]
    fn cancel_and_progress_also_work_for_files_the_cache_skips() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        for i in 0..30 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), format!("sauber {i}")).unwrap();
        }
        let roots = [dir.path().to_path_buf()];
        let scanner = Scanner::new(engines(), 0, vec![]).with_threads(2);
        let cache = MemCache::default();
        let (_, first) = scanner.scan_with(&roots, &NoControl, Some(&cache));
        assert_eq!((first.files, first.cached, first.aborted), (30, 0, false));

        // Second run: every file is known – the progress display still counts all of them ...
        let all = Probe::new(0);
        let (_, s) = scanner.scan_with(&roots, &all, Some(&cache));
        assert_eq!((s.files, s.cached, s.aborted), (0, 30, false));
        assert_eq!(all.seen.load(Ordering::Relaxed), 30);

        // ... and "Scan abbrechen" stops the walk although no file is scanned any more.
        let stop = Probe::new(10);
        let (_, s) = scanner.scan_with(&roots, &stop, Some(&cache));
        assert!(s.aborted);
        assert_eq!(s.cached, 10);
        assert_eq!(stop.seen.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn the_thread_count_of_a_scanner_can_be_changed_within_its_limits() {
        let mut scanner = Scanner::new(engines(), 0, vec![]).with_threads(2);
        scanner.set_threads(8);
        assert_eq!(scanner.threads, 8);
        scanner.set_threads(64);
        assert_eq!(scanner.threads, MAX_THREADS, "nie mehr als die Obergrenze");
        scanner.set_threads(0);
        assert_eq!(scanner.threads, 1);
    }
}
