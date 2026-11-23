//! Move from the old installation ("Virenscanner", up to version 21b0cdc) to K9.
//!
//! The elevated `k9 dienst aktualisieren` copies the user's folders and Credential Manager
//! entries; the new service copies `%ProgramData%\Virenscanner` (with the security of every
//! file and folder) at its first start, because only SYSTEM may set SYSTEM as owner. Nothing old
//! is removed before the new service reports that everything works ([`Gesundheit`]). The old data
//! folders are then renamed to `*.alt` and kept until `k9 alte-installation entfernen`.
//!
//! The old names below are used only here (moving) and for removing our own old firewall rules.
//! No other code trusts or reads an old path or a `.alt` folder.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const OLD_APP: &str = "Virenscanner";
pub const OLD_SERVICE: &str = "Virenscanner-Dienst";
pub const OLD_REG_KEY: &str = "SOFTWARE\\Virenscanner";
pub const OLD_RUN_VALUE: &str = "Virenscanner-Agent";
pub const OLD_SHORTCUT: &str = "Virenscanner-Dashboard.lnk";
pub const OLD_AUMID_KEY: &str = "Software\\Classes\\AppUserModelId\\Virenscanner.Agent";
pub const OLD_USER_DB: &str = "virenscanner.db";
/// Suffix of the kept backup folders.
pub const ALT: &str = ".alt";
/// HKLM\SOFTWARE\K9 value: the new service copies the old protected folder at its start.
pub const PENDING_VALUE: &str = "UmzugVon";
/// Meta entry in the new protected database once the copy is complete.
pub const META_DONE: &str = "umzug_von_virenscanner";

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(var).unwrap_or_else(|| fallback.into()))
}

/// One folder of the old installation and its new place.
#[derive(Debug, Clone, PartialEq)]
pub struct Ordner {
    pub old: PathBuf,
    pub new: PathBuf,
}

impl Ordner {
    pub fn alt(&self) -> PathBuf {
        let mut s = self.old.clone().into_os_string();
        s.push(ALT);
        PathBuf::from(s)
    }
}

/// %ProgramData%\Virenscanner -> %ProgramData%\K9
pub fn programdata() -> Ordner {
    let base = env_dir("ProgramData", "C:\\ProgramData");
    Ordner { old: base.join(OLD_APP), new: base.join(crate::APP_NAME) }
}

/// %ProgramFiles%\Virenscanner -> %ProgramFiles%\K9 (only programs: never copied, removed at the end)
pub fn programfiles() -> Ordner {
    let base = env_dir("ProgramFiles", "C:\\Program Files");
    Ordner { old: base.join(OLD_APP), new: base.join(crate::APP_NAME) }
}

/// The user's folders (config in %APPDATA%, data in %LOCALAPPDATA%).
pub fn user_folders() -> Vec<Ordner> {
    ["APPDATA", "LOCALAPPDATA"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .map(|base| Ordner { old: base.join(OLD_APP), new: base.join(crate::APP_NAME) })
        .collect()
}

/// Is there an old installation that was not moved yet?
pub fn old_installation_present() -> bool {
    crate::winreg::key_exists(crate::winreg::HKLM, OLD_REG_KEY) || programdata().old.join("geschuetzt.db").is_file()
}

/// `path` with the root `old` replaced by `new` (case-insensitive, whole path parts only).
pub fn rewrite(path: &str, old: &Path, new: &Path) -> Option<String> {
    let o = old.display().to_string();
    let rest = path.get(o.len()..)?;
    let head = path.get(..o.len())?;
    (head.eq_ignore_ascii_case(&o) && (rest.is_empty() || rest.starts_with('\\'))).then(|| format!("{}{rest}", new.display()))
}

/// Copies a folder tree. `security`: every file and folder gets the owner and permissions of
/// its source (needs SYSTEM for SYSTEM-owned files). Returns the number of files.
pub fn copy_tree(src: &Path, dst: &Path, security: bool) -> Result<usize> {
    copy_tree_except(src, dst, security, &[])
}

/// Like [`copy_tree`], without the top-level folders `skip` (e.g. logs that a running program
/// of the new installation already writes to; the old ones stay in the backup).
pub fn copy_tree_except(src: &Path, dst: &Path, security: bool, skip: &[&str]) -> Result<usize> {
    let mut files = 0;
    let skipped = |p: &Path| p.strip_prefix(src).ok().and_then(|r| r.components().next()).is_some_and(|c| skip.iter().any(|s| c.as_os_str().eq_ignore_ascii_case(s)));
    for e in walkdir::WalkDir::new(src).follow_links(false).into_iter().filter_entry(|e| !skipped(e.path())) {
        let e = e?;
        if e.path_is_symlink() {
            continue; // never follow or copy links (could point anywhere)
        }
        let rel = e.path().strip_prefix(src)?;
        let target = dst.join(rel);
        if e.file_type().is_dir() {
            std::fs::create_dir_all(&target).with_context(|| format!("{} kann nicht angelegt werden", target.display()))?;
        } else {
            std::fs::copy(e.path(), &target).with_context(|| format!("{} kann nicht kopiert werden", e.path().display()))?;
            files += 1;
        }
        if security {
            if let Some(sddl) = crate::schutz::sddl_of(e.path()) {
                crate::schutz::set_security(&target, &sddl)?;
            }
        }
    }
    Ok(files)
}

/// What the new service reports after its start (the update waits for it).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Gesundheit {
    pub db_ok: bool,
    /// Decisions in the protected database and how many carry a valid signature.
    pub entscheidungen: usize,
    pub unterschrieben: usize,
    /// The signing key was loaded (not newly created – a new key would hide a failed move).
    pub schluessel_neu: bool,
    /// The service's key store can be decrypted (or does not exist).
    pub schluessel_lesbar: bool,
    /// The confirmed settings are trusted (or do not exist yet).
    pub einstellungen_ok: bool,
    /// Quarantine entries and how many files exist under the new path.
    pub quarantaene: usize,
    pub quarantaene_da: usize,
    /// Result of the move of the protected folder (None: nothing to move).
    pub umzug: Option<String>,
}

impl Gesundheit {
    /// Everything fine after a move? (Empty = yes; otherwise the problems.)
    pub fn problems(&self, after_move: bool) -> Vec<String> {
        let mut p = Vec::new();
        if !self.db_ok {
            p.push("Datenbank des Dienstes nicht lesbar".to_string());
        }
        if self.unterschrieben != self.entscheidungen {
            p.push(format!("nur {} von {} Entscheidungen gültig unterschrieben", self.unterschrieben, self.entscheidungen));
        }
        if after_move && self.schluessel_neu {
            p.push("Dienst-Schlüssel wurde neu erzeugt statt übernommen".to_string());
        }
        if !self.schluessel_lesbar {
            p.push("Schlüsselspeicher des Dienstes nicht lesbar".to_string());
        }
        if !self.einstellungen_ok {
            p.push("bestätigte Einstellungen nicht vertrauenswürdig".to_string());
        }
        if self.quarantaene_da != self.quarantaene {
            p.push(format!("nur {} von {} Quarantäne-Dateien vorhanden", self.quarantaene_da, self.quarantaene));
        }
        if after_move && self.umzug.as_deref() != Some("ok") {
            p.push(format!("Übernahme der geschützten Daten: {}", self.umzug.as_deref().unwrap_or("nicht erfolgt")));
        }
        p
    }
}

/// Service side, first start after the move: copies the old protected folder (only if it is
/// trustworthy: owned by SYSTEM/Administrators, not changeable by others) and points the
/// quarantine entries to the new folder.
pub fn copy_protected(old: &Path, new: &Path) -> Result<usize> {
    if !crate::schutz::owned_by_system(old) || crate::schutz::non_admin_can(old, crate::schutz::CHANGE_RIGHTS) != Some(false) {
        bail!("{} ist nicht geschützt – wird nicht übernommen", old.display());
    }
    if new.join("geschuetzt.db").exists() {
        bail!("{} enthält schon Daten – keine zweite Übernahme", new.display());
    }
    let n = copy_tree(old, new, true)?;
    let store = crate::store::Store::open_protected_admin(&new.join("geschuetzt.db"))?;
    let moved = store.rewrite_quarantine_paths(old, new)?;
    store.meta_set(META_DONE, &crate::now_string())?;
    // The programs are new (from this update): baseline and update marker, so the start counts
    // as an update and no tamper alarm is raised. A later change of the files still alarms.
    crate::basis::record_update(&store, &crate::dienst::install_dir())?;
    tracing::info!("Übernahme: {n} Dateien aus {} kopiert, {moved} Quarantäne-Einträge umgestellt", old.display());
    Ok(n)
}

/// Elevated update, user part: copies the user's folders (the user database gets its new name)
/// and the Credential Manager entries. The VirusTotal key is not copied (only the service keeps it).
pub fn copy_user_data(lines: &mut Vec<String>) -> Result<()> {
    // The new folders may already exist: k9.exe itself creates a default config.toml and an
    // empty database when it starts. Before the first move they hold nothing of value, so the
    // old files win (copied over them).
    for f in user_folders() {
        if !f.old.is_dir() {
            continue;
        }
        let n = copy_tree_except(&f.old, &f.new, false, &["logs"])?;
        let db = f.new.join(OLD_USER_DB);
        if db.is_file() {
            std::fs::copy(&db, f.new.join("k9.db")).context("k9.db kann nicht ersetzt werden")?;
            let _ = std::fs::remove_file(&db);
        }
        lines.push(format!("Übernommen: {} → {} ({n} Dateien)", f.old.display(), f.new.display()));
    }
    let mut names: Vec<&str> = crate::secrets::USER_SECRETS.to_vec();
    names.push(crate::secrets::DASHBOARD_TOKEN);
    let mut copied = Vec::new();
    for name in names.into_iter().filter(|n| *n != crate::virustotal::VT_KEY) {
        if let Ok(Some(v)) = crate::secrets::get_in(OLD_APP, name) {
            // The old value wins (e.g. a dashboard token k9.exe created a moment ago).
            if crate::secrets::get(name).ok().flatten().as_deref() != Some(v.as_str()) {
                crate::secrets::set(name, &v)?;
                copied.push(name);
            }
        }
    }
    if !copied.is_empty() {
        lines.push(format!("Anmeldeinformationen übernommen: {}", copied.join(", ")));
    }
    Ok(())
}

/// Keeps the old data folders as backup (`*.alt`); returns the new names.
pub fn keep_as_backup() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut all = vec![programdata()];
    all.extend(user_folders());
    for f in all {
        if f.old.is_dir() && !f.alt().exists() && std::fs::rename(&f.old, f.alt()).is_ok() {
            out.push(f.alt());
        }
    }
    out
}

/// The kept backup folders.
pub fn backups() -> Vec<PathBuf> {
    let mut all = vec![programdata()];
    all.extend(user_folders());
    all.into_iter().map(|f| f.alt()).filter(|p| p.is_dir()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_moved_only_below_the_old_root() {
        let old = Path::new(r"C:\ProgramData\Virenscanner");
        let new = Path::new(r"C:\ProgramData\K9");
        assert_eq!(rewrite(r"C:\ProgramData\Virenscanner\quarantaene\a.vsq", old, new).as_deref(), Some(r"C:\ProgramData\K9\quarantaene\a.vsq"));
        assert_eq!(rewrite(r"c:\programdata\virenscanner\quarantaene\a.vsq", old, new).as_deref(), Some(r"C:\ProgramData\K9\quarantaene\a.vsq"));
        assert_eq!(rewrite(r"C:\ProgramData\Virenscanner.alt\x", old, new), None);
        assert_eq!(rewrite(r"C:\ProgramData\VirenscannerX\x", old, new), None);
        assert_eq!(rewrite(r"D:\Daten\x", old, new), None);
    }

    #[test]
    fn user_data_overwrites_fresh_defaults_but_not_the_logs() {
        let base = crate::test_tmp().join("umzug-kopie");
        let _ = std::fs::remove_dir_all(&base);
        let (old, new) = (base.join("alt"), base.join("neu"));
        std::fs::create_dir_all(old.join("logs")).unwrap();
        std::fs::create_dir_all(new.join("logs")).unwrap();
        std::fs::write(old.join("config.toml"), "alt").unwrap();
        std::fs::write(old.join("logs").join("agent.log"), "alt").unwrap();
        std::fs::write(new.join("config.toml"), "standard").unwrap();
        std::fs::write(new.join("logs").join("agent.log"), "neu").unwrap();
        // A target subfolder that already exists and is empty (e.g. created for a Trend exclusion).
        std::fs::create_dir_all(old.join("quellen").join("yara")).unwrap();
        std::fs::write(old.join("quellen").join("yara").join("regeln.yar"), "rule x {}").unwrap();
        std::fs::create_dir_all(new.join("quellen")).unwrap();
        assert_eq!(copy_tree_except(&old, &new, false, &["logs"]).unwrap(), 2);
        assert_eq!(std::fs::read_to_string(new.join("quellen").join("yara").join("regeln.yar")).unwrap(), "rule x {}");
        assert_eq!(std::fs::read_to_string(new.join("config.toml")).unwrap(), "alt");
        assert_eq!(std::fs::read_to_string(new.join("logs").join("agent.log")).unwrap(), "neu");
    }

    #[test]
    fn old_and_new_folders_and_backup_names() {
        let p = programdata();
        assert!(p.old.ends_with("Virenscanner") && p.new.ends_with("K9"));
        assert!(p.alt().display().to_string().ends_with("Virenscanner.alt"));
        assert!(programfiles().new.ends_with("K9"));
    }

    #[test]
    fn a_failed_move_is_never_reported_as_healthy() {
        let ok = Gesundheit {
            db_ok: true,
            entscheidungen: 3,
            unterschrieben: 3,
            schluessel_neu: false,
            schluessel_lesbar: true,
            einstellungen_ok: true,
            quarantaene: 2,
            quarantaene_da: 2,
            umzug: Some("ok".into()),
        };
        assert!(ok.problems(true).is_empty());
        let mut new_key = ok.clone();
        new_key.schluessel_neu = true;
        assert_eq!(new_key.problems(true).len(), 1);
        assert!(new_key.problems(false).is_empty(), "ohne Umzug darf ein neuer Schlüssel entstehen");
        let mut bad = ok.clone();
        bad.unterschrieben = 2;
        bad.quarantaene_da = 1;
        bad.umzug = Some("Fehler: x".into());
        assert_eq!(bad.problems(true).len(), 3);
    }
}
