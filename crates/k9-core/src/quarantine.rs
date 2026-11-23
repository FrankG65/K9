//! Quarantine: files are moved into the quarantine folder in an obfuscated
//! form (XOR with a random 32-byte key stored in the database), so they can
//! neither be executed nor detected as active malware. The original path and
//! a protected DACL (if any) are kept for restoring.
//!
//! Every action first verifies that the file still has the detected SHA-256,
//! so a file that changed after the scan is never touched by mistake.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::store::Store;

const MAGIC: &[u8; 4] = b"VSQ1";
const KEY_LEN: usize = 32;
const CHUNK: usize = 256 * 1024;

fn xor_in_place(buf: &mut [u8], key: &[u8], offset: u64) {
    let klen = key.len() as u64;
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[((offset + i as u64) % klen) as usize];
    }
}

/// Windows system files (below %SystemRoot%, Store apps in Program FilesWindowsApps)
/// are never moved or deleted – neither by the agent nor by the service.
pub fn is_protected_system_path(path: &Path) -> bool {
    let p = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy().to_lowercase();
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()).to_lowercase();
    p == windir || p.starts_with(&format!("{windir}\\")) || p.starts_with(&format!("{pf}\\windowsapps\\"))
}

fn refuse_system_file(path: &Path) -> Result<()> {
    if is_protected_system_path(path) {
        bail!("{} ist eine Windows-Systemdatei – Quarantäne und Löschen sind dafür gesperrt", path.display());
    }
    Ok(())
}

/// Waits between tries when a file cannot be opened for removal right away (5 s in total).
const OPEN_WAITS_MS: [u64; 5] = [250, 500, 1000, 1500, 1750];

/// Sharing violation (32) or access denied (5): usually a virus scanner (e.g. Trend Micro)
/// still has the file open for a moment.
fn held_briefly(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(32) | Some(5))
}

/// Runs `op` until it succeeds, fails for another reason or `waits` are used up.
/// Returns the last result and the number of tries.
pub fn retry_held<T>(waits: &[u64], mut op: impl FnMut() -> std::io::Result<T>, mut wait: impl FnMut(u64)) -> (std::io::Result<T>, usize) {
    let mut tries = 0;
    loop {
        tries += 1;
        match op() {
            Err(e) if held_briefly(&e) && tries <= waits.len() => wait(waits[tries - 1]),
            r => return (r, tries),
        }
    }
}

/// A file opened once for reading and deleting, shared only for reading: nobody can
/// change, rename or delete it in between, and nobody (no scan-on-close of a virus scanner)
/// can get between reading and removing – the removal goes through the same handle.
struct Exclusive {
    file: File,
    tries: usize,
}

impl Exclusive {
    fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, &OPEN_WAITS_MS, |ms| std::thread::sleep(std::time::Duration::from_millis(ms)))
    }

    fn open_with(path: &Path, waits: &[u64], wait: impl FnMut(u64)) -> std::io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        const GENERIC_READ: u32 = 0x8000_0000;
        const DELETE: u32 = 0x0001_0000;
        const FILE_SHARE_READ: u32 = 1;
        let (file, tries) = retry_held(
            waits,
            || std::fs::OpenOptions::new().access_mode(GENERIC_READ | DELETE).share_mode(FILE_SHARE_READ).open(path),
            wait,
        );
        file.map(|file| Self { file, tries }).map_err(|e| std::io::Error::new(e.kind(), format!("{e} ({tries} Versuche)")))
    }

    /// Reads everything, hashing it and handing each piece (with its offset) to `sink`.
    fn read_all(&mut self, mut sink: impl FnMut(&mut [u8], u64) -> Result<()>) -> Result<(String, u64)> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            sink(&mut buf[..n], offset)?;
            offset += n as u64;
        }
        Ok((hex::encode(hasher.finalize()), offset))
    }

    /// Marks the file for deletion (POSIX semantics: the name is gone as soon as this handle
    /// closes; older systems: classic delete-on-close). `false` takes the mark back.
    fn mark_delete(&self, delete: bool) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            FileDispositionInfo, FileDispositionInfoEx, SetFileInformationByHandle, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_DO_NOT_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS,
        };
        let h = HANDLE(self.file.as_raw_handle());
        let flags = if delete { FILE_DISPOSITION_INFO_EX_FLAGS(FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0 | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0) } else { FILE_DISPOSITION_FLAG_DO_NOT_DELETE };
        let ex = FILE_DISPOSITION_INFO_EX { Flags: flags };
        // SAFETY: valid handle owned by `self.file`; the structs live for the call.
        unsafe {
            if SetFileInformationByHandle(h, FileDispositionInfoEx, (&ex as *const FILE_DISPOSITION_INFO_EX).cast(), std::mem::size_of_val(&ex) as u32).is_ok() {
                return Ok(());
            }
            let plain = FILE_DISPOSITION_INFO { DeleteFile: delete };
            SetFileInformationByHandle(h, FileDispositionInfo, (&plain as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of_val(&plain) as u32)?;
        }
        Ok(())
    }
}

/// Moves `path` into quarantine. Returns the quarantine entry id.
pub fn quarantine_file(
    store: &Store,
    quarantine_dir: &Path,
    path: &Path,
    expected_sha256: &str,
    threat_name: &str,
    detection_id: Option<i64>,
) -> Result<i64> {
    let det = detection_id.map(|d| format!("Erkennung {d}")).unwrap_or_else(|| "ohne Erkennung".into());
    let r = quarantine_inner(store, quarantine_dir, path, expected_sha256, threat_name, detection_id);
    match &r {
        Ok((id, tries)) => tracing::info!("Quarantäne ({det}): {} → Eintrag {id} (geöffnet nach {tries} Versuch(en))", path.display()),
        Err(e) => tracing::warn!("Quarantäne fehlgeschlagen ({det}): {}: {e:#}", path.display()),
    }
    r.map(|(id, _)| id)
}

fn quarantine_inner(
    store: &Store,
    quarantine_dir: &Path,
    path: &Path,
    expected_sha256: &str,
    threat_name: &str,
    detection_id: Option<i64>,
) -> Result<(i64, usize)> {
    refuse_system_file(path)?;
    // Service: the finding's file is opened with the user's rights, the
    // protected quarantine is written with the service's rights.
    crate::schutz::ensure_user_context()?;
    crate::schutz::as_system(|| std::fs::create_dir_all(quarantine_dir))?;
    let key = crate::random_bytes(KEY_LEN);
    let stored = quarantine_dir.join(format!("{}.vsq", hex::encode(crate::random_bytes(12))));
    let sddl = acl::protected_dacl_sddl(path);
    let mut src = Exclusive::open(path).with_context(|| format!("Original {} kann nicht geöffnet werden (in Benutzung?)", path.display()))?;
    let tries = src.tries;

    // From here on every failure removes the copy; the original stays (its handle closes unmarked).
    let result = (|| -> Result<(i64, usize)> {
        let mut dst = BufWriter::new(crate::schutz::as_system(|| File::create(&stored))?);
        dst.write_all(MAGIC)?;
        let (sha, size) = src.read_all(|piece, offset| {
            xor_in_place(piece, &key, offset);
            dst.write_all(piece)?;
            Ok(())
        })?;
        dst.flush()?;
        drop(dst);
        if sha != expected_sha256 {
            bail!("Datei {} wurde seit dem Scan verändert – bitte erneut scannen", path.display());
        }
        src.mark_delete(true).with_context(|| format!("Original {} kann nicht entfernt werden", path.display()))?;
        match store.insert_quarantine(detection_id, &path.to_string_lossy(), &stored.to_string_lossy(), &sha, size, threat_name, &key, sddl.as_deref()) {
            Ok(id) => Ok((id, tries)),
            Err(e) => {
                let _ = src.mark_delete(false);
                Err(e)
            }
        }
    })();
    drop(src);
    if result.is_err() {
        let _ = crate::schutz::as_system(|| std::fs::remove_file(&stored));
    }
    result
}

/// Restores a quarantined file to its original path (or `target`).
/// Fails if the target already exists.
pub fn restore(store: &Store, id: i64, target: Option<&Path>) -> Result<PathBuf> {
    let entry = store.quarantine_entry(id)?.with_context(|| format!("Quarantäne-Eintrag {id} existiert nicht"))?;
    if entry.restored_at.is_some() {
        bail!("Quarantäne-Eintrag {id} wurde bereits wiederhergestellt");
    }
    let dest = target.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&entry.original_path));
    if dest.exists() {
        bail!("Ziel {} existiert bereits – bitte anderes Ziel angeben", dest.display());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::schutz::ensure_user_context()?;
    // The stored file name comes from the (user-writable) database: inside the
    // service only a regular file in the protected quarantine is read.
    let stored = if crate::schutz::in_service() {
        let q = crate::schutz::protected_quarantine().context("Geschützte Quarantäne fehlt")?;
        crate::schutz::as_system(|| crate::schutz::safe_inside(Path::new(&entry.stored_file), &q))?
    } else {
        PathBuf::from(&entry.stored_file)
    };
    let result = (|| -> Result<String> {
        let mut src = crate::schutz::as_system(|| File::open(&stored)).with_context(|| format!("{} fehlt", stored.display()))?;
        let mut magic = [0u8; 4];
        src.read_exact(&mut magic)?;
        if &magic != MAGIC {
            bail!("{} ist keine gültige Quarantänedatei", stored.display());
        }
        let mut dst = BufWriter::new(File::create(&dest)?);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            xor_in_place(&mut buf[..n], &entry.key, offset);
            hasher.update(&buf[..n]);
            dst.write_all(&buf[..n])?;
            offset += n as u64;
        }
        dst.flush()?;
        Ok(hex::encode(hasher.finalize()))
    })();
    match result {
        Ok(sha) if sha == entry.sha256 => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&dest);
            bail!("Prüfsumme stimmt nicht – Quarantänedatei beschädigt");
        }
        Err(e) => {
            let _ = std::fs::remove_file(&dest);
            return Err(e);
        }
    }
    if let Some(sddl) = &entry.sddl {
        if let Err(e) = acl::apply_sddl(&dest, sddl) {
            tracing::warn!("Berechtigungen für {} nicht wiederhergestellt: {e:#}", dest.display());
        }
    }
    crate::schutz::as_system(|| std::fs::remove_file(&stored))?;
    store.mark_restored(id)?;
    Ok(dest)
}

/// Deletes a detected file after verifying its hash.
pub fn delete_file(path: &Path, expected_sha256: &str) -> Result<()> {
    let r = (|| -> Result<usize> {
        crate::schutz::ensure_user_context()?;
        refuse_system_file(path)?;
        // Hash check and removal through one handle (see `Exclusive`).
        let mut f = Exclusive::open(path).with_context(|| format!("{} kann nicht gelöscht werden (in Benutzung?)", path.display()))?;
        let (sha, _) = f.read_all(|_, _| Ok(())).with_context(|| format!("{} nicht lesbar", path.display()))?;
        if sha != expected_sha256 {
            bail!("Datei {} wurde seit dem Scan verändert – bitte erneut scannen", path.display());
        }
        f.mark_delete(true).with_context(|| format!("{} kann nicht gelöscht werden", path.display()))?;
        Ok(f.tries)
    })();
    match &r {
        Ok(tries) => tracing::info!("Gelöscht: {} (geöffnet nach {tries} Versuch(en))", path.display()),
        Err(e) => tracing::warn!("Löschen fehlgeschlagen: {}: {e:#}", path.display()),
    }
    r.map(|_| ())
}

mod acl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use anyhow::Result;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// SDDL of the DACL if it is protected (not inherited). Inherited DACLs
    /// are re-created automatically when the file is restored.
    pub fn protected_dacl_sddl(path: &Path) -> Option<String> {
        let w = wide(path);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid NUL-terminated path; sd is freed with LocalFree.
        unsafe {
            let err = GetNamedSecurityInfoW(
                PCWSTR(w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            );
            if err.is_err() {
                return None;
            }
            let mut s = PWSTR::null();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                None,
            );
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            ok.ok()?;
            let text = s.to_string().ok();
            let _ = LocalFree(Some(HLOCAL(s.0 as _)));
            text.filter(|t| t.starts_with("D:P"))
        }
    }

    pub fn apply_sddl(path: &Path, sddl: &str) -> Result<()> {
        let w = wide(path);
        let s: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid NUL-terminated strings; sd is freed with LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None)?;
            let ok = SetFileSecurityW(
                PCWSTR(w.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            );
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            ok.ok()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(code: i32) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(code))
    }

    #[test]
    fn retry_while_held() {
        // released after two tries
        let mut n = 0;
        let mut waits = Vec::new();
        let (r, tries) = retry_held(
            &OPEN_WAITS_MS,
            || {
                n += 1;
                if n <= 2 { held(32) } else { Ok(()) }
            },
            |ms| waits.push(ms),
        );
        assert!(r.is_ok());
        assert_eq!((tries, waits), (3, vec![250, 500]));
        // access denied counts as well
        let mut n = 0;
        let (r, tries) = retry_held(&OPEN_WAITS_MS, || {
            n += 1;
            if n == 1 { held(5) } else { Ok(()) }
        }, |_| {});
        assert!(r.is_ok() && tries == 2);
        // stays held: 6 tries, 5 s of waiting, then the error
        let mut waits = Vec::new();
        let (r, tries) = retry_held(&OPEN_WAITS_MS, || held(32), |ms| waits.push(ms));
        assert_eq!(r.unwrap_err().raw_os_error(), Some(32));
        assert_eq!(tries, 6);
        assert_eq!(waits.iter().sum::<u64>(), 5000);
        // other errors (file not found) are not retried
        let (r, tries) = retry_held(&OPEN_WAITS_MS, || held(2), |_| panic!("nicht warten"));
        assert!(r.is_err() && tries == 1);
    }

    /// Keeps `file` open without delete sharing (like a virus scanner checking it) for `ms`.
    fn hold(file: &Path, ms: u64) -> std::thread::JoinHandle<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new().read(true).share_mode(1 /* FILE_SHARE_READ */).open(file).unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            drop(f);
        })
    }

    #[test]
    fn exclusive_handle_blocks_others_until_removed() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let file = dir.path().join("exklusiv.bin");
        std::fs::write(&file, b"inhalt").unwrap();
        let mut x = Exclusive::open_with(&file, &[], |_| {}).unwrap();
        // while we hold it: nobody else may write, rename or delete it; reading is fine
        assert!(std::fs::OpenOptions::new().write(true).open(&file).is_err());
        assert!(std::fs::rename(&file, dir.path().join("weg.bin")).is_err());
        assert!(std::fs::remove_file(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"inhalt");
        let (sha, n) = x.read_all(|_, _| Ok(())).unwrap();
        assert_eq!((sha, n), (crate::sha256_hex(b"inhalt"), 6));
        // mark, take back, close: the file stays
        x.mark_delete(true).unwrap();
        x.mark_delete(false).unwrap();
        drop(x);
        assert!(file.exists());
        // mark and close: gone (also when read-only)
        let mut perm = std::fs::metadata(&file).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&file, perm).unwrap();
        let x = Exclusive::open_with(&file, &[], |_| {}).unwrap();
        x.mark_delete(true).unwrap();
        drop(x);
        assert!(!file.exists());
    }

    #[test]
    fn quarantine_and_delete_with_a_held_file() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let qdir = dir.path().join("q");
        let store = Store::open_in_memory().unwrap();
        let content = b"kurz gesperrte Datei".to_vec();
        let sha = crate::sha256_hex(&content);

        // normal case
        let file = dir.path().join("frei.bin");
        std::fs::write(&file, &content).unwrap();
        quarantine_file(&store, &qdir, &file, &sha, "Test", None).unwrap();
        assert!(!file.exists());

        // released after ~400 ms: quarantine waits and succeeds
        let file = dir.path().join("kurz.bin");
        std::fs::write(&file, &content).unwrap();
        let t = hold(&file, 400);
        let id = quarantine_file(&store, &qdir, &file, &sha, "Test", None).unwrap();
        t.join().unwrap();
        assert!(!file.exists());
        assert!(store.quarantine_entry(id).unwrap().is_some());
        let restored = restore(&store, id, None).unwrap();
        assert_eq!(std::fs::read(&restored).unwrap(), content);

        // held during the whole wait: fails, original stays, no copy left, no entry
        let file = dir.path().join("lang.bin");
        std::fs::write(&file, &content).unwrap();
        let before = std::fs::read_dir(&qdir).unwrap().count();
        let entries = store.quarantine_files().unwrap().len();
        let t = hold(&file, 6000);
        let e = format!("{:#}", quarantine_file(&store, &qdir, &file, &sha, "Test", None).unwrap_err());
        assert!(e.contains("6 Versuche"), "{e}");
        assert!(file.exists());
        assert_eq!(std::fs::read_dir(&qdir).unwrap().count(), before, "keine Kopie zurückgelassen");
        assert_eq!(store.quarantine_files().unwrap().len(), entries);
        t.join().unwrap();

        // delete: briefly held → waits and deletes; changed content → refused, file stays
        let t = hold(&file, 400);
        delete_file(&file, &sha).unwrap();
        t.join().unwrap();
        assert!(!file.exists());
        std::fs::write(&file, b"anders").unwrap();
        assert!(delete_file(&file, &sha).is_err());
        assert!(file.exists());
        // changed after the scan: quarantine refuses, nothing left behind
        assert!(quarantine_file(&store, &qdir, &file, &sha, "Test", None).is_err());
        assert!(file.exists());
        assert_eq!(std::fs::read_dir(&qdir).unwrap().count(), before);
    }

    #[test]
    fn roundtrip_is_obfuscated_and_restorable() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let qdir = dir.path().join("q");
        let file = dir.path().join("probe.bin");
        let content = crate::engine::test_pattern_bytes();
        std::fs::write(&file, &content).unwrap();
        let sha = crate::sha256_hex(&content);
        let store = Store::open_in_memory().unwrap();

        let id = quarantine_file(&store, &qdir, &file, &sha, "Test", None).unwrap();
        assert!(!file.exists());
        let entry = store.quarantine_entry(id).unwrap().unwrap();
        let raw = std::fs::read(&entry.stored_file).unwrap();
        assert_eq!(&raw[..4], MAGIC);
        assert!(memchr::memmem::find(&raw, &content).is_none(), "Inhalt darf nicht im Klartext liegen");

        let restored = restore(&store, id, None).unwrap();
        assert_eq!(restored, file);
        assert_eq!(std::fs::read(&file).unwrap(), content);
        assert!(!Path::new(&entry.stored_file).exists());
        assert!(store.list_quarantine().unwrap().is_empty());
        assert!(restore(&store, id, None).is_err());
    }

    #[test]
    fn system_files_are_never_quarantined_or_deleted() {
        let windir = std::env::var("SystemRoot").unwrap();
        let ps = Path::new(&windir).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        assert!(ps.is_file());
        assert!(is_protected_system_path(&ps));
        let sha = crate::scanner::sha256_file(&ps).unwrap();
        let store = Store::open_in_memory().unwrap();
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let err = quarantine_file(&store, dir.path(), &ps, &sha, "Test", None).unwrap_err().to_string();
        assert!(err.contains("Systemdatei"), "{err}");
        assert!(delete_file(&ps, &sha).is_err());
        assert!(ps.is_file(), "Systemdatei muss unverändert bleiben");
        assert!(store.list_quarantine().unwrap().is_empty());
        assert!(!is_protected_system_path(dir.path()));
    }

    #[test]
    fn refuses_changed_file() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let file = dir.path().join("x.txt");
        std::fs::write(&file, b"neu").unwrap();
        let store = Store::open_in_memory().unwrap();
        assert!(quarantine_file(&store, &dir.path().join("q"), &file, &"0".repeat(64), "T", None).is_err());
        assert!(file.exists());
        assert!(delete_file(&file, &"0".repeat(64)).is_err());
        assert!(file.exists());
    }
}
