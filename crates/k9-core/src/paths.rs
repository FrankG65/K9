//! Location of configuration and data folders.
//!
//! * Config: `%APPDATA%\K9\config.toml`
//! * Data (database, quarantine, logs, signatures):
//!   `%ProgramData%\K9` when it already exists and is writable or when
//!   running elevated, otherwise `%LOCALAPPDATA%\K9`.
//! * `K9_HOME` overrides both (portable/test mode).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::APP_NAME;

pub const HOME_ENV: &str = "K9_HOME";
/// Data folder override (set by the Windows service).
pub const DATA_ENV: &str = "K9_DATEN";

/// A user folder from the environment (LOCALAPPDATA, APPDATA, USERPROFILE, PUBLIC,
/// ProgramData …) for reading browser profiles, shortcuts and the like.
/// In test mode (`K9_HOME` set) only folders inside the test area – the folder
/// that holds `K9_HOME` – are returned: a test never reads real user data.
pub fn user_dir(var: &str) -> Option<PathBuf> {
    let value = std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = std::env::var_os(HOME_ENV).filter(|v| !v.is_empty()).map(PathBuf::from);
    guarded_user_dir(value, home.as_deref())
}

fn guarded_user_dir(value: Option<PathBuf>, home: Option<&Path>) -> Option<PathBuf> {
    let value = value?;
    let Some(home) = home else { return Some(value) };
    let area = home.parent()?.to_string_lossy().to_lowercase();
    let v = value.to_string_lossy().to_lowercase();
    if v.starts_with(&format!("{}\\", area.trim_end_matches('\\'))) {
        Some(value)
    } else {
        tracing::debug!("Testmodus: echter Benutzerordner {} wird nicht gelesen", value.display());
        None
    }
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    /// True when `K9_HOME` is set (tests / portable mode).
    pub portable: bool,
}

impl AppPaths {
    pub fn resolve() -> Result<Self> {
        if let Some(home) = std::env::var_os(HOME_ENV).filter(|v| !v.is_empty()) {
            let home = PathBuf::from(home);
            return Ok(Self { config_dir: home.clone(), data_dir: home, portable: true });
        }
        let appdata = std::env::var_os("APPDATA").context("APPDATA ist nicht gesetzt")?;
        let config_dir = PathBuf::from(appdata).join(APP_NAME);
        // The Windows service uses the agent's data folder of the installing user.
        if let Some(d) = std::env::var_os(DATA_ENV).filter(|v| !v.is_empty()) {
            return Ok(Self { config_dir, data_dir: PathBuf::from(d), portable: false });
        }
        Ok(Self { config_dir, data_dir: choose_data_dir()?, portable: false })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn database(&self) -> PathBuf {
        self.data_dir.join("k9.db")
    }
    /// With the Windows service the quarantine lies in the protected
    /// `%ProgramData%\K9\quarantaene` (only SYSTEM/Administrators).
    pub fn quarantine_dir(&self) -> PathBuf {
        if !self.portable {
            if let Some(dir) = crate::schutz::protected_quarantine() {
                return dir;
            }
        }
        self.user_quarantine_dir()
    }

    /// Quarantine folder in the user's data folder (without service, before migration).
    pub fn user_quarantine_dir(&self) -> PathBuf {
        self.data_dir.join("quarantaene")
    }
    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }
    pub fn signature_dir(&self) -> PathBuf {
        self.data_dir.join("signaturen")
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.user_quarantine_dir(), &self.log_dir(), &self.signature_dir()] {
            std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} kann nicht angelegt werden", dir.display()))?;
        }
        Ok(())
    }
}

fn choose_data_dir() -> Result<PathBuf> {
    if let Some(pd) = std::env::var_os("ProgramData") {
        let dir = PathBuf::from(pd).join(APP_NAME);
        if (dir.is_dir() && is_writable(&dir)) || (is_elevated() && std::fs::create_dir_all(&dir).is_ok()) {
            return Ok(dir);
        }
    }
    let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA ist nicht gesetzt")?;
    Ok(PathBuf::from(local).join(APP_NAME))
}

fn is_writable(dir: &Path) -> bool {
    let probe = dir.join(".schreibtest");
    let ok = std::fs::write(&probe, b"x").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// True when the current process runs with administrator rights.
pub fn is_elevated() -> bool {
    // SAFETY: plain query without arguments.
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Expands `%VAR%` placeholders in a path string with environment variables.
/// Unknown variables are left untouched.
pub fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(val) if !name.is_empty() => out.push_str(&val),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_never_get_real_user_folders() {
        let home = Path::new(r"F:\Projekt\target\e2e\vs-e2e-1234");
        let real = PathBuf::from(r"C:\Users\anna\AppData\Local");
        let fake = PathBuf::from(r"F:\Projekt\target\e2e\vs-e2e-profil-1234\Local");
        assert_eq!(guarded_user_dir(Some(real.clone()), Some(home)), None, "echtes Profil im Testmodus");
        assert_eq!(guarded_user_dir(Some(fake.clone()), Some(home)), Some(fake));
        assert_eq!(guarded_user_dir(Some(PathBuf::from(r"F:\Projekt\target\e2e-andere")), Some(home)), None);
        // Normal operation: the real folder.
        assert_eq!(guarded_user_dir(Some(real.clone()), None), Some(real));
        assert_eq!(guarded_user_dir(None, None), None);
    }

    #[test]
    fn expands_known_and_keeps_unknown() {
        std::env::set_var("VS_TEST_VAR", "C:\\X");
        assert_eq!(expand_env("%VS_TEST_VAR%\\a"), "C:\\X\\a");
        assert_eq!(expand_env("%GIBTS_NICHT_123%\\a"), "%GIBTS_NICHT_123%\\a");
        assert_eq!(expand_env("100%"), "100%");
    }
}
