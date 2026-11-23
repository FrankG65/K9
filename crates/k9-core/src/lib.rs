//! k9-core: shared library of the K9 companion tool.
//!
//! Data flow: scanner -> engines -> findings -> pipeline (decision check)
//! -> store (pending detections) -> notifier -> user decision -> store.

// First, so that the macros t! and tf! are known in every module below.
#[macro_use]
pub mod sprache;
pub mod anhalten;
pub mod anmeldungen;
pub mod app;
pub mod arbeitsordner;
pub mod autostart;
pub mod basis;
pub mod clamav;
pub mod config;
pub mod dienst;
pub mod eingang;
pub mod engine;
pub mod erweiterungen;
pub mod firewall;
pub mod funktion;
pub mod gaming;
pub mod heimnetz;
pub mod herkunft;
pub mod infostealer;
pub mod ketten;
pub mod luecken;
pub mod model;
pub mod nachladen;
pub mod nativehost;
pub mod notify;
pub mod paths;
pub mod phishing;
pub mod pipeline;
pub mod priority;
pub mod quarantine;
pub mod ransom;
pub mod realtime;
pub mod scanner;
pub mod sigma;
pub mod skripte;
pub mod sperrlisten;
pub mod schutz;
pub mod schedule;
pub mod secrets;
pub mod sicherheit;
pub mod sofort;
pub mod speicher;
pub mod software;
pub mod sources;
pub mod store;
pub mod term;
pub mod treiber;
pub mod umzug;
pub mod urls;
pub mod verknuepfung;
pub mod virustotal;
pub mod wiederherstellung;
pub mod window;
pub mod winreg;
pub mod wochenbericht;
pub mod wmi_autostart;
pub mod yara;

pub use config::Config;
pub use model::{Action, Detection, Finding, Severity};
pub use store::Store;

/// Application name used for folders, credential entries and notifications.
pub const APP_NAME: &str = "K9";

/// Lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Cryptographically random bytes from the OS.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS random generator unavailable");
    buf
}

/// Current local time formatted for storage/display ("2026-11-13 09:30:00").
pub fn now_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Folder for unit-test files: in the build folder, never in %TEMP% (a
/// running agent watches %TEMP% and would report the test signatures).
#[cfg(test)]
pub(crate) fn test_tmp() -> std::path::PathBuf {
    let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("target").join("testtmp");
    std::fs::create_dir_all(&d).expect("Testordner");
    d
}

/// A folder under the user profile that the agent does not watch.
#[cfg(test)]
pub(crate) fn test_user_tmp() -> std::path::PathBuf {
    let d = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")).join("K9-Tests");
    std::fs::create_dir_all(&d).expect("Testordner");
    d
}
