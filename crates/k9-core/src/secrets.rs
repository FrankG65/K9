//! Secrets in the Windows Credential Manager (Anmeldeinformationsverwaltung),
//! never in the config file. Entries are stored under the service name
//! "K9" (visible under "Windows-Anmeldeinformationen").

use anyhow::{Context, Result};

use crate::paths::AppPaths;
use crate::APP_NAME;

pub const SMTP_PASSWORD: &str = "smtp-passwort";
pub const NTFY_TOKEN: &str = "ntfy-token";
pub const DASHBOARD_TOKEN: &str = "dashboard-token";

/// Names a user may set with `k9 geheimnis <name>`.
pub const USER_SECRETS: [&str; 5] = [SMTP_PASSWORD, NTFY_TOKEN, crate::sources::ABUSECH_KEY, crate::sources::NVD_KEY, crate::virustotal::VT_KEY];

fn entry(name: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(APP_NAME, name).context("Anmeldeinformationsverwaltung nicht verfügbar")
}

pub fn get(name: &str) -> Result<Option<String>> {
    // Inside the Windows service: its own protected store (DPAPI, SYSTEM only).
    if crate::schutz::in_service() {
        return Ok(crate::schutz::service_secret_get(name));
    }
    match entry(name)?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("Geheimnis kann nicht gelesen werden"),
    }
}

/// A secret under another Credential Manager name (only for moving from the old installation).
pub fn get_in(target: &str, name: &str) -> Result<Option<String>> {
    match keyring::Entry::new(target, name).context("Anmeldeinformationsverwaltung nicht verfügbar")?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("Geheimnis kann nicht gelesen werden"),
    }
}

/// Deletes a secret under another Credential Manager name (old installation).
pub fn delete_in(target: &str, name: &str) -> Result<bool> {
    match keyring::Entry::new(target, name).context("Anmeldeinformationsverwaltung nicht verfügbar")?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(e).context("Geheimnis kann nicht gelöscht werden"),
    }
}

pub fn set(name: &str, value: &str) -> Result<()> {
    entry(name)?.set_password(value).context("Geheimnis kann nicht gespeichert werden")
}

pub fn delete(name: &str) -> Result<bool> {
    match entry(name)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(e).context("Geheimnis kann nicht gelöscht werden"),
    }
}

/// Access token for the local dashboard. Created once (random, 256 bit) and
/// kept in the Credential Manager, so links in notifications stay valid
/// across agent restarts. In portable/test mode it lives in the data folder.
pub fn dashboard_token(paths: &AppPaths) -> Result<String> {
    if paths.portable {
        let file = paths.data_dir.join("dashboard-token.txt");
        if let Ok(t) = std::fs::read_to_string(&file) {
            if t.trim().len() >= 32 {
                return Ok(t.trim().to_string());
            }
        }
        let t = hex::encode(crate::random_bytes(32));
        std::fs::write(&file, &t)?;
        return Ok(t);
    }
    if let Some(t) = get(DASHBOARD_TOKEN)? {
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    let t = hex::encode(crate::random_bytes(32));
    set(DASHBOARD_TOKEN, &t)?;
    Ok(t)
}
