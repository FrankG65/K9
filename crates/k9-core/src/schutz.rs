//! Protection of security-relevant state against programs running with the
//! user's rights (hardening step 1, active only with the Windows service):
//!
//! * Remembered decisions are signed by the service (Ed25519). The private key
//!   is readable only by SYSTEM/Administrators; the public key lies in
//!   `%ProgramData%\K9` (users: read only). A decision without a valid
//!   signature is ignored, so a program cannot "allow" itself in the database.
//! * Security settings of `config.toml` (real-time protection, exclusions,
//!   suspending processes, notification channels): a weakening change takes
//!   effect only after the user confirmed it; until then the confirmed values
//!   (kept by the service) apply.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HLOCAL, LocalFree};

use crate::config::Config;
use crate::model::Decision;

const PUBLIC_KEY_FILE: &str = "dienst-schluessel.pub";
const PRIVATE_DIR: &str = "geheim";
const PRIVATE_KEY_FILE: &str = "dienst-schluessel.p8";
const SETTINGS_FILE: &str = "einstellungen-bestaetigt.json";
const QUARANTINE_DIR: &str = "quarantaene";
const SOURCES_DIR: &str = "quellen";
const SECRETS_FILE: &str = "schluessel.dpapi";
/// Written by the elevated `k9 dienst aktualisieren`, imported and deleted by the service.
pub const SECRETS_IMPORT_FILE: &str = "import.json";
/// Secrets the service needs for its source updates.
pub const SERVICE_SECRETS: [&str; 3] = [crate::sources::ABUSECH_KEY, crate::sources::NVD_KEY, crate::virustotal::VT_KEY];

const PROTECTED_DB: &str = "geschuetzt.db";

/// The service's own database (decisions, quarantine list), if it exists.
pub fn protected_db() -> Option<PathBuf> {
    if cfg!(test) || portable() {
        return None;
    }
    let f = protected_dir().join(PROTECTED_DB);
    (f.is_file() && owned_by_system(&f)).then_some(f)
}

/// Path of the protected database (service side, also before it exists).
pub fn protected_db_path() -> PathBuf {
    protected_dir().join(PROTECTED_DB)
}

/// Protected source data (signatures, lists), if the service set it up.
pub fn protected_sources() -> Option<PathBuf> {
    if cfg!(test) || portable() {
        return None;
    }
    let dir = protected_dir().join(SOURCES_DIR);
    (dir.is_dir() && owned_by_system(&dir)).then_some(dir)
}

/// Service side: protected source folder (users: read only).
pub fn setup_protected_sources() -> Result<PathBuf> {
    let base = protected_dir();
    secure_dir(&base, SDDL_SHARED)?;
    let dir = base.join(SOURCES_DIR);
    secure_dir(&dir, SDDL_SHARED)?;
    Ok(dir)
}

/// Folder with the service's secrets (only SYSTEM/Administrators).
pub fn private_dir() -> PathBuf {
    protected_dir().join(PRIVATE_DIR)
}

fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN};
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input lives during the call; output freed with LocalFree.
    unsafe {
        if protect {
            CryptProtectData(&input, PCWSTR::null(), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)?;
        } else {
            CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)?;
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
        Ok(v)
    }
}

fn service_secrets() -> std::collections::BTreeMap<String, String> {
    as_system(service_secrets_inner)
}

fn service_secrets_inner() -> std::collections::BTreeMap<String, String> {
    std::fs::read(private_dir().join(SECRETS_FILE))
        .ok()
        .and_then(|b| dpapi(&b, false).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Service side: a secret (DPAPI with the SYSTEM account – only SYSTEM can decrypt).
pub fn service_secret_get(name: &str) -> Option<String> {
    service_secrets().remove(name)
}

pub fn service_secret_names() -> Vec<String> {
    service_secrets().into_keys().collect()
}

pub fn service_secret_set(name: &str, value: Option<&str>) -> Result<()> {
    as_system(|| service_secret_set_inner(name, value))
}

fn service_secret_set_inner(name: &str, value: Option<&str>) -> Result<()> {
    if !SERVICE_SECRETS.contains(&name) {
        bail!("Unbekanntes Geheimnis {name}");
    }
    let mut all = service_secrets();
    match value {
        Some(v) => all.insert(name.to_string(), v.to_string()),
        None => all.remove(name),
    };
    let dir = private_dir();
    secure_dir(&dir, SDDL_PRIVATE)?;
    let f = dir.join(SECRETS_FILE);
    std::fs::write(&f, dpapi(&serde_json::to_vec(&all)?, true)?)?;
    set_security(&f, SDDL_PRIVATE)
}

/// Service side: imports secrets handed over by the installation, then deletes the file.
pub fn import_service_secrets() -> Result<usize> {
    let f = private_dir().join(SECRETS_IMPORT_FILE);
    let Ok(bytes) = std::fs::read(&f) else { return Ok(0) };
    let _ = std::fs::remove_file(&f);
    let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&bytes)?;
    let mut n = 0;
    let have = service_secret_names();
    for (k, v) in map {
        // Only a first key: replacing one needs the confirmation (k9 geheimnis), never an update.
        if SERVICE_SECRETS.contains(&k.as_str()) && !v.is_empty() && !have.contains(&k) {
            service_secret_set(&k, Some(&v))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Protected quarantine folder, if the service set it up (owned by SYSTEM).
pub fn protected_quarantine() -> Option<PathBuf> {
    if cfg!(test) || portable() {
        return None; // tests/portable mode never touch the real installation
    }
    let dir = protected_dir().join(QUARANTINE_DIR);
    (dir.is_dir() && owned_by_system(&dir)).then_some(dir)
}

/// Service side: creates the protected quarantine folder (no access for users).
pub fn setup_protected_quarantine() -> Result<PathBuf> {
    let base = protected_dir();
    secure_dir(&base, SDDL_SHARED)?;
    let dir = base.join(QUARANTINE_DIR);
    secure_dir(&dir, SDDL_PRIVATE)?;
    Ok(dir)
}

/// The service's own signer (set inside the service process): decisions
/// made there are signed directly instead of over the pipe.
static LOCAL_SIGNER: std::sync::OnceLock<Signer> = std::sync::OnceLock::new();

pub fn set_local_signer(s: Signer) -> &'static Signer {
    LOCAL_SIGNER.get_or_init(|| s)
}

pub fn local_signer() -> Option<&'static Signer> {
    LOCAL_SIGNER.get()
}

static SERVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Called first thing in the service process.
pub fn mark_service() {
    SERVICE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// True inside the Windows service process.
pub fn in_service() -> bool {
    SERVICE.load(std::sync::atomic::Ordering::SeqCst) || LOCAL_SIGNER.get().is_some()
}

/// Owner SYSTEM; SYSTEM and Administrators full access, users read only.
pub const SDDL_SHARED: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
/// Owner SYSTEM; only SYSTEM and Administrators.
pub const SDDL_PRIVATE: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Portable/test mode (K9_HOME): never uses the installed service's state.
fn portable() -> bool {
    std::env::var_os(crate::paths::HOME_ENV).is_some_and(|v| !v.is_empty())
}

/// `%ProgramData%\K9` – written only by the service.
pub fn protected_dir() -> PathBuf {
    if cfg!(test) {
        // Unit tests never use the real %ProgramData%\K9.
        return std::env::current_dir().unwrap_or_default().join("target").join("test-programdata");
    }
    let pd = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
    PathBuf::from(pd).join(crate::APP_NAME)
}

/// The Windows service's own data folder is always the protected folder. A registered
/// value is accepted only if it is exactly that folder, without reparse points
/// (junctions, symbolic links) on the way; otherwise false is returned (warn).
pub fn service_data_dir(registered: &str) -> (PathBuf, bool) {
    let protected = protected_dir();
    let accepted = !registered.trim().is_empty()
        && !has_reparse_point(Path::new(registered))
        && match (std::fs::canonicalize(registered), std::fs::canonicalize(&protected)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
    (protected, accepted)
}

/// True if the path or one of its parent folders is a junction or symbolic link.
fn has_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    path.ancestors()
        .filter(|p| !p.as_os_str().is_empty())
        .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ========================================================= impersonation
//
// The service runs as SYSTEM. Everything in folders a user program can change
// (data folder, config.toml, the files of a finding) it touches only with the
// rights of the user (impersonation), so junctions/links planted there cannot
// redirect it into system folders. SYSTEM rights are used only for its own
// protected folders (`as_system`).

thread_local! {
    /// Token of the user this thread acts for (None = not impersonating).
    static USER_TOKEN: std::cell::Cell<Option<isize>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with the rights of `token` (the user), then returns to SYSTEM.
pub fn with_user<R>(token: windows::Win32::Foundation::HANDLE, f: impl FnOnce() -> R) -> R {
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    let previous = USER_TOKEN.with(|t| t.replace(Some(token.0 as isize)));
    // SAFETY: valid token; reverted below.
    let ok = unsafe { ImpersonateLoggedOnUser(token).is_ok() };
    let r = if ok {
        f()
    } else {
        tracing::warn!("Impersonation fehlgeschlagen – Aktion abgebrochen");
        USER_TOKEN.with(|t| t.set(previous));
        return with_user_failed(f);
    };
    // SAFETY: plain revert of this thread.
    unsafe {
        let _ = RevertToSelf();
    }
    USER_TOKEN.with(|t| t.set(previous));
    if let Some(p) = previous {
        // SAFETY: re-impersonate the outer user.
        unsafe {
            let _ = ImpersonateLoggedOnUser(windows::Win32::Foundation::HANDLE(p as _));
        }
    }
    r
}

/// Without impersonation nothing may run on user paths: `f` runs with a
/// marker so file operations fail instead of using SYSTEM rights.
fn with_user_failed<R>(f: impl FnOnce() -> R) -> R {
    IMPERSONATION_FAILED.with(|x| x.set(true));
    let r = f();
    IMPERSONATION_FAILED.with(|x| x.set(false));
    r
}

thread_local! {
    static IMPERSONATION_FAILED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// True if this thread currently acts with the user's rights.
pub fn impersonating() -> bool {
    USER_TOKEN.with(|t| t.get().is_some())
}

/// Inside the service: fails if a user path would be touched with SYSTEM rights.
pub fn ensure_user_context() -> Result<()> {
    if in_service() && (!impersonating() || IMPERSONATION_FAILED.with(|x| x.get())) {
        bail!("Sicherheitsabbruch: Dateizugriff im Benutzerordner ohne Benutzerrechte verweigert");
    }
    Ok(())
}

/// Runs `f` with the service's own (SYSTEM) rights, e.g. for the protected
/// quarantine; afterwards the thread acts for the user again.
pub fn as_system<R>(f: impl FnOnce() -> R) -> R {
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    let Some(tok) = USER_TOKEN.with(|t| t.get()) else { return f() };
    // SAFETY: revert and re-impersonate on this thread.
    unsafe {
        let _ = RevertToSelf();
    }
    USER_TOKEN.with(|t| t.set(None));
    let r = f();
    USER_TOKEN.with(|t| t.set(Some(tok)));
    unsafe {
        let _ = ImpersonateLoggedOnUser(windows::Win32::Foundation::HANDLE(tok as _));
    }
    r
}

/// Canonical path that lies inside `dir` and contains no reparse point
/// (junction/symlink) – for files the service reads with SYSTEM rights.
pub fn safe_inside(path: &Path, dir: &Path) -> Result<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE: u32 = 0x400;
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("{} fehlt", path.display()))?;
    if meta.file_attributes() & REPARSE != 0 || !meta.is_file() {
        bail!("{} ist keine normale Datei", path.display());
    }
    let canon = std::fs::canonicalize(path)?;
    let base = std::fs::canonicalize(dir)?;
    if !canon.starts_with(&base) {
        bail!("{} liegt nicht im geschützten Ordner", path.display());
    }
    Ok(canon)
}

// ================================================================== ACLs

/// Creates `dir` (if needed) and sets owner and DACL (service side, SYSTEM).
pub fn secure_dir(dir: &Path, sddl: &str) -> Result<()> {
    as_system(|| secure_dir_inner(dir, sddl))
}

fn secure_dir_inner(dir: &Path, sddl: &str) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("{} kann nicht angelegt werden", dir.display()))?;
    set_security(dir, sddl)
}

/// Sets owner and protected DACL of a file or folder.
pub fn set_security(path: &Path, sddl: &str) -> Result<()> {
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sd = crate::dienst::SecDesc::from_sddl(sddl)?;
    let p = wide(&path.display().to_string());
    // SAFETY: valid path and security descriptor.
    unsafe {
        SetFileSecurityW(
            PCWSTR(p.as_ptr()),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd.as_ptr(),
        )
        .ok()
        .with_context(|| format!("Rechte für {} können nicht gesetzt werden", path.display()))?;
    }
    Ok(())
}

/// Owner and permissions of a file or folder as SDDL ("O:..D:P(...)"), for copying them.
pub fn sddl_of(path: &Path) -> Option<String> {
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let p = wide(&path.display().to_string());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out pointers valid; both buffers are freed with LocalFree.
    unsafe {
        GetNamedSecurityInfoW(PCWSTR(p.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, None, None, None, None, &mut sd)
            .ok()
            .ok()?;
        let mut s = PWSTR::null();
        let r = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut s, None)
            .ok()
            .and_then(|_| s.to_string().ok());
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        r
    }
}

/// The service's key store can be decrypted (or there is none yet).
pub fn service_secrets_readable() -> bool {
    as_system(|| {
        let f = private_dir().join(SECRETS_FILE);
        !f.exists() || std::fs::read(&f).ok().and_then(|b| dpapi(&b, false).ok()).is_some_and(|b| serde_json::from_slice::<serde_json::Value>(&b).is_ok())
    })
}

/// The confirmed settings are trusted (or there are none yet).
pub fn confirmed_settings_ok() -> bool {
    let f = protected_dir().join(SETTINGS_FILE);
    !f.exists() || trusted_service_file(&f)
}

/// String SID of the owner of a file ("S-1-5-18" for SYSTEM).
pub fn owner_sid(path: &Path) -> Option<String> {
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let p = wide(&path.display().to_string());
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out pointers valid; descriptor freed below.
    unsafe {
        let r = GetNamedSecurityInfoW(PCWSTR(p.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut owner), None, None, None, &mut sd);
        if r.is_err() {
            return None;
        }
        let mut s = PWSTR::null();
        let res = ConvertSidToStringSidW(owner, &mut s).ok().and_then(|_| s.to_string().ok());
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        res
    }
}

/// Rights that change a file or the contents of a folder: write/add file, append/add
/// subfolder, delete child, delete, change permissions/owner, GENERIC_ALL, GENERIC_WRITE.
pub const CHANGE_RIGHTS: u32 = 0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
/// Rights on a parent folder that allow replacing a child: delete child,
/// change permissions/owner, GENERIC_ALL.
pub const REPLACE_CHILD_RIGHTS: u32 = 0x40 | 0x4_0000 | 0x8_0000 | 0x1000_0000;

/// Principals that malware running as the user cannot act as: SYSTEM, LocalService,
/// NetworkService, Administrators, TrustedInstaller, CREATOR OWNER/OWNER RIGHTS
/// (placeholders; the real owner is checked separately) and app containers.
fn privileged_sid(s: &str) -> bool {
    matches!(s, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544" | "S-1-3-0" | "S-1-3-4")
        || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        || s.starts_with("S-1-15-")
}

fn sid_string(sid: windows::Win32::Security::PSID) -> Option<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut s = PWSTR::null();
    // SAFETY: valid SID pointer; the string is freed with LocalFree.
    unsafe {
        let res = ConvertSidToStringSidW(sid, &mut s).ok().and_then(|_| s.to_string().ok());
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        res
    }
}

/// Whether a non-administrator can get one of `mask` on a file or folder: the owner
/// is a normal account (owners may always change the permissions), or an allow
/// entry grants such a right to anyone else than the privileged principals.
/// None: permissions not readable (e.g. the file does not exist).
pub fn non_admin_can(path: &Path, mask: u32) -> Option<bool> {
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const INHERIT_ONLY_ACE: u8 = 0x8;
    let p = wide(&path.display().to_string());
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out pointers valid; owner and DACL point into `sd`, which is freed last.
    unsafe {
        let r = GetNamedSecurityInfoW(
            PCWSTR(p.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if r.is_err() {
            return None;
        }
        let result = (|| {
            if !sid_string(owner).is_some_and(|s| privileged_sid(&s)) {
                return true;
            }
            if dacl.is_null() {
                return true; // no DACL: everyone has full access
            }
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() {
                    return true;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Mask & mask == 0 {
                    continue;
                }
                let sid = PSID(&allowed.SidStart as *const u32 as *mut _);
                if !sid_string(sid).is_some_and(|s| privileged_sid(&s)) {
                    return true;
                }
            }
            false
        })();
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        Some(result)
    }
}

/// Only files owned by SYSTEM or Administrators count as written by the service.
pub fn owned_by_system(path: &Path) -> bool {
    matches!(owner_sid(path).as_deref(), Some("S-1-5-18") | Some("S-1-5-32-544"))
}

// ============================================================ signatures

/// Signed text of a decision. The prefix "vs-entscheidung-v1" must never change (also not
/// for the name K9): every decision signed so far would become invalid.
fn decision_message(d: &Decision) -> Vec<u8> {
    format!("vs-entscheidung-v1|{}|{}|{}", d.sha256, d.rule_id, d.action.as_str()).into_bytes()
}

/// Public key of the service, if installed and trustworthy (owned by SYSTEM).
pub fn public_key() -> Option<Vec<u8>> {
    if cfg!(test) || portable() {
        return None;
    }
    let f = protected_dir().join(PUBLIC_KEY_FILE);
    if !owned_by_system(&f) {
        return None;
    }
    std::fs::read(&f).ok().filter(|k| k.len() == 32)
}

pub fn verify(public_key: &[u8], d: &Decision) -> bool {
    use ring::signature::{UnparsedPublicKey, ED25519};
    let Some(sig) = d.signature.as_deref().and_then(|s| hex::decode(s).ok()) else { return false };
    UnparsedPublicKey::new(&ED25519, public_key).verify(&decision_message(d), &sig).is_ok()
}

/// Signing key of the service (service side only).
pub struct Signer(ring::signature::Ed25519KeyPair);

impl Signer {
    /// Loads the key or creates a new one. `true` = newly created.
    pub fn load_or_create() -> Result<(Self, bool)> {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let base = protected_dir();
        secure_dir(&base, SDDL_SHARED)?;
        let private = base.join(PRIVATE_DIR);
        secure_dir(&private, SDDL_PRIVATE)?;
        let key_file = private.join(PRIVATE_KEY_FILE);
        let (pkcs8, created) = match std::fs::read(&key_file) {
            Ok(b) if owned_by_system(&key_file) => (b, false),
            _ => {
                let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(|_| anyhow::anyhow!("Schlüssel kann nicht erzeugt werden"))?;
                std::fs::write(&key_file, doc.as_ref())?;
                set_security(&key_file, SDDL_PRIVATE)?;
                (doc.as_ref().to_vec(), true)
            }
        };
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| anyhow::anyhow!("Dienst-Schlüssel ist beschädigt"))?;
        let pub_file = base.join(PUBLIC_KEY_FILE);
        std::fs::write(&pub_file, pair.public_key().as_ref())?;
        set_security(&pub_file, SDDL_SHARED)?;
        Ok((Self(pair), created))
    }

    pub fn sign(&self, d: &Decision) -> String {
        hex::encode(self.0.sign(&decision_message(d)).as_ref())
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Self(ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn public(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.0.public_key().as_ref().to_vec()
    }
}

/// Asks the service to sign a stored decision (after the user decided).
pub fn request_signature(store: &crate::Store, decision_id: i64) -> Result<()> {
    if let Some(s) = local_signer() {
        let d = store.decision_by_id(decision_id)?.context("Entscheidung existiert nicht")?;
        return store.set_decision_signature(d.id, &s.sign(&d));
    }
    if public_key().is_none() {
        return Ok(()); // no service: decisions work as before
    }
    use crate::dienst::{request, Message, PROTOCOL};
    match request(&Message::Signieren { v: PROTOCOL, entscheidung_id: decision_id })? {
        Message::Ergebnis { ok: true, .. } => Ok(()),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort: {other:?}"),
    }
}

// ============================================================== settings

/// How a switch of config.toml affects the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wirkung {
    /// Protective: switching it off weakens (needs confirmation); switching it on applies at once.
    Schuetzt,
    /// Switching it on weakens (e.g. gaming mode: lighter checks while a game runs).
    EinSchwaecht,
    /// No effect on the protection.
    Neutral,
}

/// How a list of config.toml affects the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenWirkung {
    /// New entries are exceptions (e.g. scan exceptions, game folders).
    NeuSchwaecht,
    /// Removed entries weaken (e.g. a notification channel).
    EntferntSchwaecht,
    /// Any change weakens (e.g. the watched folders).
    AenderungSchwaecht,
    Neutral,
}

use ListenWirkung as L;
use Wirkung as W;

/// Every bool switch of [`Config`] – a unit test checks that none is missing, so a new
/// switch can't be forgotten. The same rules apply in the service, the agent and k9.
pub const SCHALTER: &[(&str, Wirkung, &str)] = &[
    ("scan.cache", W::Neutral, "Scan-Cache"),
    ("quellen.yara_aktiv", W::Schuetzt, "YARA-Regeln"),
    ("quellen.yara_erweitert", W::Schuetzt, "YARA-Regeln: erweitertes Paket"),
    ("quellen.clamav_aktiv", W::Schuetzt, "ClamAV"),
    ("quellen.clamav_pua", W::Schuetzt, "ClamAV: unerwünschte Programme"),
    ("quellen.abusech_aktiv", W::Schuetzt, "abuse.ch-Listen"),
    ("quellen.openphish_aktiv", W::Schuetzt, "OpenPhish-Liste"),
    ("quellen.phishing_filter_aktiv", W::Schuetzt, "Phishing-Filter-Liste"),
    ("quellen.virustotal_aktiv", W::Schuetzt, "VirusTotal-Abfrage"),
    ("quellen.cve_aktiv", W::Schuetzt, "Schwachstellen-Prüfung (CVE)"),
    ("quellen.browserverlauf_pruefen", W::Schuetzt, "Browserverlauf prüfen"),
    ("quellen.treiber_aktiv", W::Schuetzt, "Treiber-Listen"),
    ("quellen.erweiterungen_aktiv", W::Schuetzt, "Liste schädlicher Browser-Erweiterungen"),
    ("quellen.sigma_aktiv", W::Schuetzt, "Sigma-Regeln für Programmstarts"),
    ("quellen.lolbas_aktiv", W::Schuetzt, "LOLBAS-Regeln für Programmstarts"),
    ("quellen.hagezi_tif_aktiv", W::Schuetzt, "große Liste von Schad-Domains (HaGeZi)"),
    ("quellen.spamhaus_drop_aktiv", W::Schuetzt, "Liste gekaperter Netze (Spamhaus DROP)"),
    ("echtzeit.aktiv", W::Schuetzt, "Echtzeitschutz"),
    ("echtzeit.prozesse", W::Schuetzt, "Programmstarts prüfen"),
    ("echtzeit.autostart", W::Schuetzt, "Autostarts prüfen"),
    ("echtzeit.netzwerk", W::Schuetzt, "Netzwerk prüfen"),
    ("echtzeit.ransomware", W::Schuetzt, "Ransomware-Erkennung"),
    ("echtzeit.ransomware_meldung_trotz_spiel", W::Schuetzt, "Ransomware-Meldung auch während eines Spiels"),
    ("echtzeit.ransomware_prozess_anhalten", W::Schuetzt, "Verdächtige Prozesse anhalten (Ransomware)"),
    ("echtzeit.usb", W::Schuetzt, "USB prüfen"),
    ("echtzeit.clamav", W::Schuetzt, "ClamAV in Echtzeit"),
    ("echtzeit.infostealer", W::Schuetzt, "Schutz vor Datendieben (Infostealer)"),
    ("echtzeit.powershell_skripte", W::Schuetzt, "PowerShell-Skriptprüfung"),
    ("echtzeit.download_herkunft", W::Schuetzt, "Programme aus dem Internet melden"),
    ("echtzeit.angriffsketten", W::Schuetzt, "Angriffsketten"),
    ("echtzeit.anmeldungen", W::Schuetzt, "Konten und Anmeldungen überwachen"),
    ("echtzeit.kritische_prozesse_anhalten", W::Schuetzt, "Kritische Programme anhalten"),
    ("echtzeit.neue_programme_anhalten", W::Schuetzt, "Neue Programme aus dem Internet anhalten"),
    ("echtzeit.speicher_scan", W::Schuetzt, "Speicher-Scan im Leerlauf"),
    ("phishing.aehnliche_domains", W::Schuetzt, "Ähnliche Domains melden"),
    ("schutz.schattenkopien", W::Schuetzt, "Schattenkopien im Leerlauf"),
    ("schutz.firewall_sperre", W::Schuetzt, "Firewall-Sperre"),
    ("arbeitsordner.aktiv", W::EinSchwaecht, "Arbeitsordner (leise Meldungen)"),
    ("sicherheitscheck.aktiv", W::Schuetzt, "Sicherheits-Check"),
    ("sicherheitscheck.programm_updates", W::Schuetzt, "Veraltete Programme anzeigen"),
    ("sicherheitscheck.wochenbericht", W::Schuetzt, "Wochenbericht"),
    ("sicherheitscheck.heimnetz", W::Schuetzt, "Neue Geräte im Heimnetz"),
    ("sicherheitscheck.neue_luecken", W::Schuetzt, "Neue Sicherheitslücken melden"),
    ("gaming.aktiv", W::EinSchwaecht, "Spielmodus"),
    ("gaming.vollbild_erkennen", W::EinSchwaecht, "Spiele an Vollbild erkennen"),
    ("gaming.kritische_sofort_extern", W::Schuetzt, "Kritische Meldungen während eines Spiels per E-Mail/Handy"),
];

/// Every list of [`Config`] (also checked by the unit test).
pub const LISTEN: &[(&str, ListenWirkung, &str)] = &[
    ("scan.standard_pfade", L::Neutral, "Standardpfade"),
    ("scan.ausnahmen", L::NeuSchwaecht, "Neue Scan-Ausnahme"),
    ("echtzeit.ordner", L::AenderungSchwaecht, "Überwachte Ordner geändert"),
    ("echtzeit.zusatz_ordner", L::EntferntSchwaecht, "Zusätzlich überwachter Ordner entfernt"),
    ("gaming.spiele_prozesse", L::NeuSchwaecht, "Neues Spiel (Programm)"),
    ("gaming.spiele_ordner", L::NeuSchwaecht, "Neuer Spiele-Ordner"),
    ("gaming.keine_spiele", L::EntferntSchwaecht, "Hilfsprogramm gilt wieder als Spiel"),
    ("arbeitsordner.ordner", L::NeuSchwaecht, "Neuer Arbeitsordner"),
    ("arbeitsordner.programme", L::NeuSchwaecht, "Neues Arbeitsprogramm"),
    ("sicherheitscheck.sicherung_ordner", L::Neutral, "Sicherungsordner"),
    ("meldungen.kanaele", L::EntferntSchwaecht, "Meldekanal entfernt"),
    ("email.empfaenger", L::Neutral, "E-Mail-Empfänger"),
    ("phishing.eigene_marken", L::EntferntSchwaecht, "Eigene Marke entfernt"),
    ("schutz.schattenkopien_laufwerke", L::EntferntSchwaecht, "Laufwerk für Schattenkopien entfernt"),
    ("zeitplan", L::Neutral, "Zeitpläne"),
];

pub fn switch_label(key: &str) -> &'static str {
    crate::sprache::tr(SCHALTER.iter().find(|s| s.0 == key).map(|s| s.2).unwrap_or("Einstellung"))
}

fn value_at<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    key.split('.').try_fold(v, |v, k| v.get(k))
}

fn value_at_mut<'a>(v: &'a mut serde_json::Value, key: &str) -> Option<&'a mut serde_json::Value> {
    key.split('.').try_fold(v, |v, k| v.get_mut(k))
}

fn shown(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => crate::config::Channel::parse(s).map(|c| c.label().to_string()).unwrap_or_else(|| s.clone()),
        other => other.to_string(),
    }
}

/// Security-relevant part of the configuration: the protective switches and lists.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecuritySettings {
    #[serde(default)]
    pub schalter: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    pub listen: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
}

impl SecuritySettings {
    pub fn of(c: &Config) -> Self {
        let v = serde_json::to_value(c).unwrap_or_default();
        let mut s = Self::default();
        for (k, w, _) in SCHALTER {
            if *w != W::Neutral {
                if let Some(b) = value_at(&v, k).and_then(|x| x.as_bool()) {
                    s.schalter.insert(k.to_string(), b);
                }
            }
        }
        for (k, w, _) in LISTEN {
            if *w != L::Neutral {
                if let Some(a) = value_at(&v, k).and_then(|x| x.as_array()) {
                    s.listen.insert(k.to_string(), a.clone());
                }
            }
        }
        s
    }

    /// Puts these values into a configuration.
    pub fn apply(&self, c: &mut Config) {
        let Ok(mut v) = serde_json::to_value(&*c) else { return };
        for (k, b) in &self.schalter {
            if let Some(x) = value_at_mut(&mut v, k) {
                *x = serde_json::Value::Bool(*b);
            }
        }
        for (k, a) in &self.listen {
            if let Some(x) = value_at_mut(&mut v, k) {
                *x = serde_json::Value::Array(a.clone());
            }
        }
        if let Ok(n) = serde_json::from_value(v) {
            *c = n;
        }
    }

    pub fn fingerprint(&self) -> String {
        crate::sha256_hex(serde_json::to_string(self).unwrap_or_default().as_bytes())
    }

    /// Entries missing in confirmed settings (switches added in a later version) are taken
    /// from `current` – like at the first start. True if something was added.
    pub fn complete_from(&mut self, current: &SecuritySettings) -> bool {
        let mut added = false;
        for (k, b) in &current.schalter {
            if !self.schalter.contains_key(k) {
                self.schalter.insert(k.clone(), *b);
                added = true;
            }
        }
        for (k, a) in &current.listen {
            if !self.listen.contains_key(k) {
                self.listen.insert(k.clone(), a.clone());
                added = true;
            }
        }
        added
    }

    /// What applies when `self` is in config.toml and `confirmed` was confirmed: stronger
    /// values at once, weaker ones keep the confirmed value. Returns the effective settings
    /// and the withheld (weakening) changes.
    pub fn safe(&self, confirmed: &SecuritySettings) -> (SecuritySettings, Vec<String>) {
        let mut eff = self.clone();
        let mut weak = Vec::new();
        for (k, w, label) in SCHALTER {
            let label = crate::sprache::tr(label);
            let (Some(&now), Some(&old)) = (self.schalter.get(*k), confirmed.schalter.get(*k)) else { continue };
            let weaker = match w {
                W::Schuetzt => old && !now,
                W::EinSchwaecht => !old && now,
                W::Neutral => false,
            };
            if weaker {
                eff.schalter.insert(k.to_string(), old);
                weak.push(format!("{label}: {}", if now { t!("ein", "on") } else { t!("aus", "off") }));
            }
        }
        for (k, w, label) in LISTEN {
            let label = crate::sprache::tr(label);
            let (Some(now), Some(old)) = (self.listen.get(*k), confirmed.listen.get(*k)) else { continue };
            match w {
                L::NeuSchwaecht => {
                    let new: Vec<_> = now.iter().filter(|x| !old.contains(x)).collect();
                    if !new.is_empty() {
                        weak.extend(new.iter().map(|x| format!("{label}: {}", shown(x))));
                        eff.listen.insert(k.to_string(), now.iter().filter(|x| old.contains(x)).cloned().collect());
                    }
                }
                L::EntferntSchwaecht => {
                    let gone: Vec<_> = old.iter().filter(|x| !now.contains(x)).cloned().collect();
                    if !gone.is_empty() {
                        weak.extend(gone.iter().map(|x| format!("{label}: {}", shown(x))));
                        let mut keep = now.clone();
                        keep.extend(gone);
                        eff.listen.insert(k.to_string(), keep);
                    }
                }
                L::AenderungSchwaecht => {
                    if now != old {
                        let list = if now.is_empty() { "Standard".to_string() } else { now.iter().map(shown).collect::<Vec<_>>().join(", ") };
                        weak.push(format!("{label}: {list}"));
                        eff.listen.insert(k.to_string(), old.clone());
                    }
                }
                L::Neutral => {}
            }
        }
        (eff, weak)
    }

    /// Changes from `confirmed` to `self` that weaken the protection
    /// (empty = nothing to confirm; stronger settings need no confirmation).
    pub fn weakenings(&self, confirmed: &SecuritySettings) -> Vec<String> {
        self.safe(confirmed).1
    }

    /// Settings files of older versions (fixed fields instead of the lists above).
    fn from_json(bytes: &[u8]) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        if v.get("schalter").is_some() {
            return serde_json::from_value(v).ok();
        }
        let mut s = Self::default();
        for (old, new) in [
            ("echtzeit_aktiv", "echtzeit.aktiv"),
            ("prozesse", "echtzeit.prozesse"),
            ("autostart", "echtzeit.autostart"),
            ("netzwerk", "echtzeit.netzwerk"),
            ("ransomware", "echtzeit.ransomware"),
            ("usb", "echtzeit.usb"),
            ("clamav_echtzeit", "echtzeit.clamav"),
            ("ransomware_prozess_anhalten", "echtzeit.ransomware_prozess_anhalten"),
            ("infostealer", "echtzeit.infostealer"),
        ] {
            if let Some(b) = v.get(old).and_then(|x| x.as_bool()) {
                s.schalter.insert(new.into(), b);
            }
        }
        for (old, new) in [("ordner", "echtzeit.ordner"), ("scan_ausnahmen", "scan.ausnahmen"), ("kanaele", "meldungen.kanaele")] {
            if let Some(a) = v.get(old).and_then(|x| x.as_array()) {
                s.listen.insert(new.into(), a.clone());
            }
        }
        Some(s)
    }
}

/// The confirmed settings file is trusted only if it belongs to SYSTEM/Administrators, no
/// one else may change it or its folder, and there is no junction or link on the way.
fn trusted_service_file(f: &Path) -> bool {
    f.is_file()
        && owned_by_system(f)
        && !has_reparse_point(f)
        && non_admin_can(f, CHANGE_RIGHTS) == Some(false)
        && f.parent().is_some_and(|d| non_admin_can(d, REPLACE_CHILD_RIGHTS) == Some(false))
}

/// Confirmed settings kept by the service (None without service).
pub fn confirmed_settings() -> Option<SecuritySettings> {
    if cfg!(test) || portable() {
        return None;
    }
    let f = protected_dir().join(SETTINGS_FILE);
    if !trusted_service_file(&f) {
        if f.exists() {
            tracing::warn!("{} wird nicht verwendet (Besitzer, Rechte oder Verknüpfungspunkt stimmen nicht)", f.display());
        }
        return None;
    }
    SecuritySettings::from_json(&std::fs::read(f).ok()?)
}

/// Service side: stores the confirmed settings.
pub fn store_confirmed_settings(s: &SecuritySettings) -> Result<()> {
    as_system(|| store_confirmed_inner(s))
}

fn store_confirmed_inner(s: &SecuritySettings) -> Result<()> {
    let base = protected_dir();
    secure_dir(&base, SDDL_SHARED)?;
    let f = base.join(SETTINGS_FILE);
    std::fs::write(&f, serde_json::to_vec_pretty(s)?)?;
    set_security(&f, SDDL_SHARED)
}

/// Service, agent and k9: weakening changes in config.toml that are not confirmed yet
/// are replaced by the confirmed values (stronger ones apply). Returns the withheld changes.
pub fn enforce_confirmed(c: &mut Config) -> Vec<String> {
    let Some(mut confirmed) = confirmed_settings() else { return Vec::new() };
    let current = SecuritySettings::of(c);
    confirmed.complete_from(&current);
    let (eff, weak) = current.safe(&confirmed);
    if !weak.is_empty() {
        eff.apply(c);
    }
    weak
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_switch_and_list_has_an_english_name() {
        for s in SCHALTER {
            assert!(crate::sprache::english(s.2).is_some(), "{}", s.2);
        }
        for l in LISTEN {
            assert!(crate::sprache::english(l.2).is_some(), "{}", l.2);
        }
        assert_eq!(crate::sprache::with(crate::sprache::Sprache::En, || switch_label("echtzeit.aktiv")), "Real-time protection");
        assert_eq!(switch_label("echtzeit.aktiv"), "Echtzeitschutz");
    }

    #[test]
    fn service_uses_only_the_protected_data_folder() {
        let protected = protected_dir();
        std::fs::create_dir_all(&protected).unwrap();
        // The protected folder itself is accepted.
        assert_eq!(service_data_dir(&protected.display().to_string()), (protected.clone(), true));
        // A folder in the user profile is ignored (the protected folder is used instead).
        let user = tempfile::tempdir_in(crate::test_user_tmp()).unwrap();
        assert_eq!(service_data_dir(&user.path().display().to_string()), (protected.clone(), false));
        assert_eq!(service_data_dir(""), (protected.clone(), false));
        // A junction that points to the protected folder is ignored as well.
        let tmp = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let link = tmp.path().join("verbindung");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&protected)
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(made, "Verbindungspunkt konnte nicht angelegt werden");
        assert_eq!(service_data_dir(&link.display().to_string()), (protected, false));
        let _ = std::fs::remove_dir(&link);
    }
    use crate::model::Action;

    fn decision(action: Action) -> Decision {
        Decision {
            id: 1,
            sha256: "ab".repeat(32),
            rule_id: "R".into(),
            threat_name: "t".into(),
            action,
            decided_at: "x".into(),
            note: None,
            signature: None,
        }
    }

    #[test]
    fn decisions_signed_by_the_old_installation_stay_valid() {
        // The signed text is fixed: a key and a decision of the old "Virenscanner" verify in K9.
        let d = decision(Action::Freigabe);
        assert_eq!(decision_message(&d), format!("vs-entscheidung-v1|{}|R|freigabe", "ab".repeat(32)).into_bytes());
        let s = Signer::for_test();
        let mut signed = d.clone();
        signed.signature = Some(s.sign(&d));
        assert!(verify(&s.public(), &signed));
    }

    #[test]
    fn forged_or_changed_decisions_fail_verification() {
        let s = Signer::for_test();
        let pk = s.public();
        let mut d = decision(Action::Quarantaene);
        assert!(!verify(&pk, &d), "unsigned");
        d.signature = Some(s.sign(&d));
        assert!(verify(&pk, &d));
        // A program changes the signed "Quarantäne" into "Freigabe" -> invalid.
        d.action = Action::Freigabe;
        assert!(!verify(&pk, &d));
        // Signed with another key -> invalid.
        let other = Signer::for_test();
        let mut e = decision(Action::Freigabe);
        e.signature = Some(other.sign(&e));
        assert!(!verify(&pk, &e));
    }

    #[test]
    fn only_weakening_changes_need_confirmation() {
        let base = SecuritySettings::of(&Config::default());
        let mut c = Config::default();
        c.echtzeit.aktiv = false;
        c.scan.ausnahmen.push("C:\\Spiele".into());
        let weak = SecuritySettings::of(&c).weakenings(&base);
        assert_eq!(weak.len(), 2, "{weak:?}");
        // Switching something on is never asked (also freezing processes).
        let mut c2 = Config::default();
        c2.echtzeit.ransomware_prozess_anhalten = true;
        c2.echtzeit.kritische_prozesse_anhalten = true;
        assert!(SecuritySettings::of(&c2).weakenings(&base).is_empty());
    }

    #[test]
    fn every_switch_and_list_of_the_configuration_is_classified() {
        let v = serde_json::to_value(Config::default()).unwrap();
        let mut seen = Vec::new();
        for (section, val) in v.as_object().unwrap() {
            match val {
                serde_json::Value::Array(_) => seen.push((section.clone(), false)),
                serde_json::Value::Object(o) => {
                    for (k, x) in o {
                        match x {
                            serde_json::Value::Bool(_) => seen.push((format!("{section}.{k}"), true)),
                            serde_json::Value::Array(_) => seen.push((format!("{section}.{k}"), false)),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        for (key, is_bool) in &seen {
            if *is_bool {
                assert!(SCHALTER.iter().any(|s| s.0 == key), "Schalter {key} ist nicht eingeordnet (SCHALTER in schutz.rs)");
            } else {
                assert!(LISTEN.iter().any(|s| s.0 == key), "Liste {key} ist nicht eingeordnet (LISTEN in schutz.rs)");
            }
        }
        // And nothing in the tables that the configuration does not have.
        for (k, _, _) in SCHALTER {
            assert!(seen.iter().any(|(s, b)| s == k && *b), "{k} gibt es nicht");
        }
        for (k, _, _) in LISTEN {
            assert!(seen.iter().any(|(s, b)| s == k && !*b), "{k} gibt es nicht");
        }
    }

    #[test]
    fn weaker_values_keep_the_confirmed_value_stronger_ones_apply_at_once() {
        let mut ok = Config::default();
        ok.quellen.virustotal_aktiv = true;
        ok.schutz.firewall_sperre = true;
        ok.schutz.schattenkopien = true;
        ok.gaming.spiele_ordner = vec!["D:\\Spiele".into()];
        let confirmed = SecuritySettings::of(&ok);
        // A program running as the user switches VirusTotal and the firewall block off, adds a
        // game folder (games are never frozen), removes a channel and switches gaming mode on.
        let mut c = ok.clone();
        c.quellen.virustotal_aktiv = false;
        c.schutz.firewall_sperre = false;
        c.echtzeit.kritische_prozesse_anhalten = true;
        c.gaming.spiele_ordner.push("C:\\Users\\x\\AppData\\Local\\Temp".into());
        c.meldungen.kanaele.retain(|k| *k != crate::config::Channel::Fenster);
        let confirmed_no_gaming = {
            let mut s = confirmed.clone();
            s.schalter.insert("gaming.aktiv".into(), false);
            s
        };
        let (eff, weak) = SecuritySettings::of(&c).safe(&confirmed_no_gaming);
        assert_eq!(weak.len(), 5, "{weak:?}");
        assert!(weak.iter().any(|w| w == "VirusTotal-Abfrage: aus"), "{weak:?}");
        assert!(weak.iter().any(|w| w == "Spielmodus: ein"), "{weak:?}");
        assert!(weak.iter().any(|w| w.contains("Meldefenster")), "{weak:?}");
        let mut applied = c.clone();
        eff.apply(&mut applied);
        assert!(applied.quellen.virustotal_aktiv && applied.schutz.firewall_sperre && applied.schutz.schattenkopien);
        assert!(!applied.gaming.aktiv);
        assert!(applied.echtzeit.kritische_prozesse_anhalten, "stärker: sofort");
        assert_eq!(applied.gaming.spiele_ordner, vec!["D:\\Spiele".to_string()]);
        assert!(applied.meldungen.kanaele.contains(&crate::config::Channel::Fenster));
        // Settings outside the protection stay as written.
        assert_eq!(applied.dashboard.port, c.dashboard.port);
    }

    #[test]
    fn old_settings_files_are_read_and_new_switches_taken_from_the_current_file() {
        let old = br#"{"echtzeit_aktiv":true,"prozesse":true,"autostart":true,"netzwerk":true,"ransomware":true,"usb":true,
            "clamav_echtzeit":true,"ransomware_prozess_anhalten":false,"infostealer":true,"ordner":[],"scan_ausnahmen":[],"kanaele":["fenster","dashboard"]}"#;
        let mut confirmed = SecuritySettings::from_json(old).unwrap();
        assert_eq!(confirmed.schalter.get("echtzeit.aktiv"), Some(&true));
        let mut c = Config::default();
        c.quellen.virustotal_aktiv = true;
        c.gaming.spiele_ordner = vec!["E:\\Games".into()];
        let current = SecuritySettings::of(&c);
        assert!(confirmed.complete_from(&current));
        // Not yet tracked switches and lists are taken as they are (no alarm after the update).
        assert!(current.weakenings(&confirmed).is_empty());
        let json = serde_json::to_vec(&confirmed).unwrap();
        assert_eq!(SecuritySettings::from_json(&json).unwrap(), confirmed);
    }

    #[test]
    fn safe_inside_rejects_paths_outside_and_traversal() {
        let base = crate::test_tmp().join("sicher");
        std::fs::create_dir_all(&base).unwrap();
        let f = base.join("a.vsq");
        std::fs::write(&f, b"x").unwrap();
        assert!(safe_inside(&f, &base).is_ok());
        assert!(safe_inside(&base.join("..").join("sicher").join("a.vsq"), &base).is_ok());
        let outside = crate::test_tmp().join("draussen.vsq");
        std::fs::write(&outside, b"x").unwrap();
        assert!(safe_inside(&outside, &base).is_err());
        assert!(safe_inside(&base.join("..").join("draussen.vsq"), &base).is_err());
        assert!(safe_inside(&base, &base).is_err(), "Ordner ist keine Datei");
    }

    #[test]
    fn outside_the_service_user_paths_are_allowed() {
        assert!(ensure_user_context().is_ok());
    }

    #[test]
    fn user_files_are_not_trusted() {
        let f = std::env::current_dir().unwrap().join("Cargo.toml");
        assert!(!owned_by_system(&f));
    }
}
