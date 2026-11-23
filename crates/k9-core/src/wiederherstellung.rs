//! Getting files back out of a shadow copy after a ransomware attack.
//!
//! K9 makes shadow copies while the PC is idle (`schattenkopie` in the service), and ransomware
//! that encrypts within the first second still costs the first files (BlackBasta in the tests of
//! 21./22.11.2026: 32 of 160 documents). This module reads a folder out of a shadow copy and
//! writes what is missing or different today into a NEW folder.
//!
//! Rules: the live folder is never touched, nothing is overwritten, nothing is deleted. The
//! user compares and copies back himself. Reading shadow copies needs administrator rights.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// One shadow copy of a drive.
#[derive(Debug, Clone, PartialEq)]
pub struct Kopie {
    /// Drive letter with colon, upper case ("C:").
    pub laufwerk: String,
    /// Device path of the copy (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12`).
    pub geraet: String,
    /// When it was made, "JJJJ-MM-TT HH:MM" (local time) – sorts as text.
    pub zeit: String,
}

/// Reads the lines `C:|\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12|2026-11-21 22:24`.
pub fn parse_list(text: &str) -> Vec<Kopie> {
    let mut out: Vec<Kopie> = text
        .lines()
        .filter_map(|l| {
            let mut p = l.trim().split('|');
            let (drive, device, time) = (p.next()?.trim(), p.next()?.trim(), p.next()?.trim());
            let ok = drive.len() == 2
                && drive.ends_with(':')
                && drive.as_bytes()[0].is_ascii_alphabetic()
                && device.to_ascii_lowercase().starts_with("\\\\?\\globalroot\\device\\harddiskvolumeshadowcopy")
                && device[device.len().saturating_sub(1)..].chars().all(|c| c.is_ascii_digit())
                && time.len() == 16;
            ok.then(|| Kopie { laufwerk: drive.to_ascii_uppercase(), geraet: device.to_string(), zeit: time.to_string() })
        })
        .collect();
    out.sort_by(|a, b| a.laufwerk.cmp(&b.laufwerk).then(b.zeit.cmp(&a.zeit)));
    out
}

/// All shadow copies of the PC, per drive the newest first. Needs administrator rights.
pub fn list() -> Result<Vec<Kopie>> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = Path::new(&windir).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    let cmd = "$v = @{}; Get-CimInstance Win32_Volume | Where-Object DriveLetter | ForEach-Object { $v[$_.DeviceID] = $_.DriveLetter }; \
               Get-CimInstance Win32_ShadowCopy | ForEach-Object { if ($v[$_.VolumeName]) { '{0}|{1}|{2}' -f $v[$_.VolumeName], $_.DeviceObject, $_.InstallDate.ToString('yyyy-MM-dd HH:mm') } }";
    let out = std::process::Command::new(exe).args(["-NoProfile", "-NonInteractive", "-Command", cmd]).output().context("PowerShell lässt sich nicht starten")?;
    if !out.status.success() {
        bail!("Schattenkopien lassen sich nicht abfragen: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(parse_list(&String::from_utf8_lossy(&out.stdout)))
}

/// The newest copy of the drive of `folder` made at or before `stand` (None: the newest).
pub fn choose<'a>(copies: &'a [Kopie], folder: &Path, stand: Option<&str>) -> Option<&'a Kopie> {
    let drive = drive_of(folder)?;
    copies.iter().filter(|k| k.laufwerk == drive && stand.is_none_or(|s| k.zeit.as_str() <= s)).max_by(|a, b| a.zeit.cmp(&b.zeit))
}

fn drive_of(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')).then(|| s[..2].to_ascii_uppercase())
}

/// Where `folder` lies inside the shadow copy.
pub fn shadow_path(kopie: &Kopie, folder: &Path) -> Option<PathBuf> {
    drive_of(folder)?;
    let rest = folder.to_string_lossy()[2..].replace('/', "\\");
    Some(PathBuf::from(format!("{}{}", kopie.geraet, rest)))
}

/// What a run found and did.
#[derive(Debug, Default, PartialEq)]
pub struct Bericht {
    /// Files of the copy that are gone today.
    pub fehlend: u64,
    /// Files of the copy that are different today (size or time of change).
    pub geaendert: u64,
    /// Files that are the same today (not copied, unless `alles`).
    pub gleich: u64,
    pub kopiert: u64,
    pub bytes: u64,
    /// Files that could not be read or written (with the reason), at most 20 are kept.
    pub fehler: Vec<String>,
    pub fehler_gesamt: u64,
}

/// Copies from `quelle` (the folder inside the shadow copy) into the new folder `ziel` every
/// file that is missing or different in `heute` (the live folder) – with `alles` every file.
/// `ziel` must not exist or be empty; nothing outside of it is written.
pub fn restore(quelle: &Path, heute: &Path, ziel: &Path, alles: bool) -> Result<Bericht> {
    if !quelle.is_dir() {
        bail!("Der Ordner ist in dieser Schattenkopie nicht vorhanden: {}", quelle.display());
    }
    if ziel.exists() && std::fs::read_dir(ziel).map(|mut d| d.next().is_some()).unwrap_or(true) {
        bail!("Der Zielordner ist nicht leer: {} – bitte einen neuen Ordner angeben", ziel.display());
    }
    let (z, h) = (ziel.to_string_lossy().to_lowercase(), heute.to_string_lossy().to_lowercase());
    if z == h || z.starts_with(&format!("{}\\", h.trim_end_matches('\\'))) {
        bail!("Der Zielordner darf nicht im wiederherzustellenden Ordner liegen");
    }
    let mut b = Bericht::default();
    let note = |b: &mut Bericht, text: String| {
        b.fehler_gesamt += 1;
        if b.fehler.len() < 20 {
            b.fehler.push(text);
        }
    };
    for entry in walkdir::WalkDir::new(quelle).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                note(&mut b, format!("{e}"));
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(quelle) else { continue };
        let Ok(old) = entry.metadata() else {
            note(&mut b, format!("{}: nicht lesbar", rel.display()));
            continue;
        };
        let state = match std::fs::metadata(heute.join(rel)) {
            Err(_) => 0,
            Ok(now) if now.len() != old.len() || now.modified().ok() != old.modified().ok() => 1,
            Ok(_) => 2,
        };
        match state {
            0 => b.fehlend += 1,
            1 => b.geaendert += 1,
            _ => b.gleich += 1,
        }
        if state == 2 && !alles {
            continue;
        }
        let target = ziel.join(rel);
        let copied = target.parent().map(std::fs::create_dir_all).transpose().map_err(anyhow::Error::from).and_then(|_| {
            if target.exists() {
                bail!("im Ziel schon vorhanden");
            }
            Ok(std::fs::copy(entry.path(), &target)?)
        });
        match copied {
            Ok(n) => {
                b.kopiert += 1;
                b.bytes += n;
            }
            Err(e) => note(&mut b, format!("{}: {e}", rel.display())),
        }
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_read_and_sorted_newest_first_per_drive() {
        let text = "C:|\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3|2026-11-20 22:10\r\n\
                    f:|\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7|2026-11-21 22:24\n\
                    C:|\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy12|2026-11-21 22:24\n\
                    Müll\nC:|C:\\Windows|2026-11-21 22:24\nC:|\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy9; rm|2026-11-21 22:24\n";
        let k = parse_list(text);
        assert_eq!(k.iter().map(|k| (k.laufwerk.as_str(), k.zeit.as_str())).collect::<Vec<_>>(), [("C:", "2026-11-21 22:24"), ("C:", "2026-11-20 22:10"), ("F:", "2026-11-21 22:24")]);
        // The newest copy of the folder's drive, or the newest at or before a given moment.
        let docs = Path::new(r"C:\Users\x\Documents");
        assert_eq!(choose(&k, docs, None).unwrap().geraet, r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12");
        assert_eq!(choose(&k, docs, Some("2026-11-21 12:00")).unwrap().zeit, "2026-11-20 22:10");
        assert!(choose(&k, docs, Some("2026-11-19 00:00")).is_none());
        assert!(choose(&k, Path::new(r"D:\x"), None).is_none());
        assert!(choose(&k, Path::new("Documents"), None).is_none(), "nur volle Pfade");
        assert_eq!(shadow_path(&k[0], docs).unwrap(), PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\x\Documents"));
    }

    #[test]
    fn only_missing_and_changed_files_are_copied_into_a_new_folder() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let (old, now, target) = (dir.path().join("kopie"), dir.path().join("heute"), dir.path().join("ziel"));
        std::fs::create_dir_all(old.join("Steuer")).unwrap();
        std::fs::create_dir_all(now.join("Steuer")).unwrap();
        // Same today, encrypted today (other content and size), gone today.
        std::fs::write(old.join("gleich.txt"), b"unveraendert").unwrap();
        std::fs::copy(old.join("gleich.txt"), now.join("gleich.txt")).unwrap();
        let t = std::fs::metadata(old.join("gleich.txt")).unwrap().modified().unwrap();
        std::fs::File::options().write(true).open(now.join("gleich.txt")).unwrap().set_modified(t).unwrap();
        std::fs::write(old.join("Steuer").join("2025.docx"), b"die echte Steuererklaerung").unwrap();
        std::fs::write(now.join("Steuer").join("2025.docx"), b"VERSCHLUESSELT").unwrap();
        std::fs::write(old.join("brief.docx"), b"ein Brief").unwrap();
        let b = restore(&old, &now, &target, false).unwrap();
        assert_eq!((b.fehlend, b.geaendert, b.gleich, b.kopiert, b.fehler_gesamt), (1, 1, 1, 2, 0));
        assert_eq!(std::fs::read(target.join("Steuer").join("2025.docx")).unwrap(), b"die echte Steuererklaerung");
        assert_eq!(std::fs::read(target.join("brief.docx")).unwrap(), b"ein Brief");
        assert!(!target.join("gleich.txt").exists());
        // The live folder is untouched.
        assert_eq!(std::fs::read(now.join("Steuer").join("2025.docx")).unwrap(), b"VERSCHLUESSELT");
        assert!(!now.join("brief.docx").exists());
        // Never into a folder that already holds something, never into the live folder.
        assert!(restore(&old, &now, &target, false).unwrap_err().to_string().contains("nicht leer"));
        assert!(restore(&old, &now, &now.join("zurueck"), false).unwrap_err().to_string().contains("darf nicht"));
        assert!(restore(&dir.path().join("fehlt"), &now, &dir.path().join("z2"), false).is_err());
        // With "alles" also the unchanged files.
        assert_eq!(restore(&old, &now, &dir.path().join("z3"), true).unwrap().kopiert, 3);
    }
}
