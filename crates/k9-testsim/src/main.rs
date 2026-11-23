//! Test tool only, never installed: behaves like ransomware on SHAM files so that the speed of
//! K9's ransomware alarm (and of the freeze) can be measured without real malware.
//!
//! Safety: it touches nothing but the files of one folder that contains the marker file
//! `K9-TESTORDNER.txt` with the expected first line – without the marker it refuses to run.
//! It overwrites each file with random bytes of the same length and appends `.k9test` to the
//! name. With `--wiederherstellung` it first calls `vssadmin delete shadows` for a shadow copy
//! ID that cannot exist (all zeros): the command fails harmlessly but looks to K9 like the
//! recovery sabotage real ransomware performs before encrypting. With
//! `--wiederherstellung-cmd` the same harmless command goes through `cmd.exe /c` (as Babuk does
//! it; cmd.exe has ended before K9 hears of it), and `--pause N` waits N seconds between that
//! command and the first file. With `--koeder <Datei> [--sperren-ms N]` it first opens one of
//! K9's own canary files without sharing, overwrites it and keeps it open for N milliseconds
//! while the test files are already being overwritten – as BlackBasta did on 22.11.2026, when
//! K9's file watch waited for the locked canary. Only a file with the exact name of a K9 canary
//! is accepted (K9 writes its canaries anew at the next start).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MARKER: &str = "K9-TESTORDNER.txt";
pub const MARKER_LINE: &str = "K9-Testordner: Dateien hier duerfen vom Testprogramm ueberschrieben werden";

/// xorshift64*: enough for bytes that look encrypted (no dependency needed).
struct Rng(u64);
impl Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let v = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// The files the tool may overwrite: only directly in a marked folder, never the marker.
pub fn targets(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let marker = std::fs::read_to_string(dir.join(MARKER)).map_err(|_| format!("Kein Testordner: {MARKER} fehlt in {}", dir.display()))?;
    if marker.lines().next().map(str::trim) != Some(MARKER_LINE) {
        return Err(format!("Kein Testordner: {MARKER} hat nicht den erwarteten Inhalt"));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.file_name().is_some_and(|n| n != MARKER) && p.extension().is_none_or(|e| e != "k9test"))
        .collect();
    files.sort();
    Ok(files)
}

fn encrypt(path: &Path, rng: &mut Rng) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len() as usize;
    let mut buf = vec![0u8; len.min(64 * 1024 * 1024)];
    rng.fill(&mut buf);
    std::fs::OpenOptions::new().write(true).truncate(true).open(path)?.write_all(&buf)?;
    let mut renamed = path.as_os_str().to_owned();
    renamed.push(".k9test");
    std::fs::rename(path, renamed)
}

/// Writes the "encrypted" content to a new file next to the original and deletes the original.
fn encrypt_copy(path: &Path, rng: &mut Rng) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len() as usize;
    let mut buf = vec![0u8; len.min(64 * 1024 * 1024)];
    rng.fill(&mut buf);
    let mut copy = path.as_os_str().to_owned();
    copy.push(".k9test");
    std::fs::write(copy, &buf)?;
    std::fs::remove_file(path)
}

/// Only K9's own canary files may be touched outside the test folder.
fn is_k9_canary(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "!vs-koeder-nicht-loeschen.docx" || n == "~vs-koeder-nicht-loeschen.docx")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")).map(PathBuf::from) else {
        eprintln!("Aufruf: k9-testsim <Testordner> [--pro-sekunde N] [--warten SEKUNDEN] [--wiederherstellung] [--entpacken N | --kopieren]");
        std::process::exit(2);
    };
    let rate: u64 = args.iter().position(|a| a == "--pro-sekunde").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).filter(|v| *v > 0).unwrap_or(40);
    // Real ransomware takes seconds to minutes before it encrypts (measured: 5 to 74 seconds).
    let wait: u64 = args.iter().position(|a| a == "--warten").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(wait.min(300)));
    let files = match targets(&dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if args.iter().any(|a| a == "--wiederherstellung") {
        // A shadow copy with this ID cannot exist: the command fails and deletes nothing.
        let _ = std::process::Command::new("vssadmin.exe").args(["delete", "shadows", "/shadow={00000000-0000-0000-0000-000000000000}", "/quiet"]).spawn();
    }
    if args.iter().any(|a| a == "--wiederherstellung-cmd") {
        // The same harmless command, started by a short-lived cmd.exe; waits until cmd has ended.
        let _ = std::process::Command::new("cmd.exe").args(["/c", "vssadmin.exe delete shadows /shadow={00000000-0000-0000-0000-000000000000} /quiet"]).status();
    }
    let pause: u64 = args.iter().position(|a| a == "--pause").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(pause.min(300)));
    let mut rng = Rng(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1) | 1);
    if let Some(canary) = args.iter().position(|a| a == "--koeder").and_then(|i| args.get(i + 1)).map(PathBuf::from) {
        if !is_k9_canary(&canary) {
            eprintln!("--koeder: nur eine Koederdatei von K9 ist erlaubt");
            std::process::exit(1);
        }
        let hold: u64 = args.iter().position(|a| a == "--sperren-ms").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(800);
        std::thread::spawn(move || {
            use std::os::windows::fs::OpenOptionsExt;
            // share_mode(0): nobody else can open the file while it is held.
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).share_mode(0).open(&canary) {
                let _ = f.write_all(&[0x5A; 4096]);
                let _ = f.flush();
                std::thread::sleep(Duration::from_millis(hold.min(10_000)));
            }
        });
        // The lock is in place before the first test file is touched.
        std::thread::sleep(Duration::from_millis(30));
    }
    let start = Instant::now();
    let mut done = 0u64;
    // Harmless look-alike: like unpacking an archive, N NEW files with packed content appear;
    // nothing that was there is touched. K9 must not raise an alarm.
    if let Some(n) = args.iter().position(|a| a == "--entpacken").and_then(|i| args.get(i + 1)).and_then(|v| v.parse::<u64>().ok()) {
        let mut buf = vec![0u8; 20_000];
        for i in 0..n.min(5000) {
            rng.fill(&mut buf);
            if std::fs::write(dir.join(format!("ausgepackt{i:04}.dat")), &buf).is_ok() {
                done += 1;
            }
            if let Some(wait) = Duration::from_millis(done * 1000 / rate).checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
        println!("{done} neue Dateien angelegt in {:.1} s", start.elapsed().as_secs_f32());
        return;
    }
    // Ransomware that writes an encrypted copy and deletes the original.
    let copy_delete = args.iter().any(|a| a == "--kopieren");
    for f in &files {
        let ok = if copy_delete { encrypt_copy(f, &mut rng).is_ok() } else { encrypt(f, &mut rng).is_ok() };
        if ok {
            done += 1;
        }
        // Keep the pace: file number n is due at n / rate seconds.
        let due = Duration::from_millis(done * 1000 / rate);
        if let Some(wait) = due.checked_sub(start.elapsed()) {
            std::thread::sleep(wait);
        }
    }
    println!("{done} von {} Dateien ueberschrieben in {:.1} s", files.len(), start.elapsed().as_secs_f32());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_k9_canary_may_be_named_outside_the_test_folder() {
        assert!(is_k9_canary(Path::new(r"C:\Users\x\Documents\!vs-koeder-nicht-loeschen.docx")));
        assert!(is_k9_canary(Path::new(r"C:\Users\x\Desktop\~vs-koeder-nicht-loeschen.docx")));
        assert!(!is_k9_canary(Path::new(r"C:\Users\x\Documents\Steuer.docx")));
        assert!(!is_k9_canary(Path::new(r"C:\Users\x\Documents\!vs-koeder-nicht-loeschen.docx.bak")));
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("k9-testsim-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn refuses_folders_without_the_marker() {
        let d = dir("ohne");
        std::fs::write(d.join("a.docx"), b"wichtig").unwrap();
        assert!(targets(&d).is_err(), "ohne Markerdatei");
        std::fs::write(d.join(MARKER), "irgendwas").unwrap();
        assert!(targets(&d).is_err(), "falscher Inhalt");
        assert_eq!(std::fs::read(d.join("a.docx")).unwrap(), b"wichtig");
        let _ = std::fs::remove_dir_all(&d);
    }

    // Behaves like ransomware (overwrite and rename): Trend Micro on the test PC asks about it.
    // Run on purpose only: cargo test -p k9-testsim -- --ignored
    #[test]
    #[ignore]
    fn overwrites_only_the_files_of_the_marked_folder() {
        let d = dir("mit");
        std::fs::write(d.join(MARKER), format!("{MARKER_LINE}\r\n")).unwrap();
        std::fs::write(d.join("a.docx"), vec![b'A'; 5000]).unwrap();
        std::fs::create_dir_all(d.join("unter")).unwrap();
        std::fs::write(d.join("unter").join("b.docx"), b"bleibt").unwrap();
        let files = targets(&d).unwrap();
        assert_eq!(files.len(), 1, "nicht die Markerdatei, nicht der Unterordner");
        let mut rng = Rng(7);
        encrypt(&files[0], &mut rng).unwrap();
        let out = std::fs::read(d.join("a.docx.k9test")).unwrap();
        assert_eq!(out.len(), 5000);
        assert!(out.iter().filter(|b| **b == b'A').count() < 100, "Inhalt ist ueberschrieben");
        assert_eq!(std::fs::read(d.join("unter").join("b.docx")).unwrap(), b"bleibt");
        assert!(targets(&d).unwrap().is_empty(), "schon ueberschriebene Dateien nicht noch einmal");
        let _ = std::fs::remove_dir_all(&d);
    }
}
