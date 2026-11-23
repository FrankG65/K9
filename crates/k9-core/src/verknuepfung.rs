//! Shortcuts "K9-Dashboard" on the desktop and in the Start menu of the
//! current user. They run `k9.exe dashboard` minimized, so no console window
//! appears in front.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use windows::core::{Interface, HSTRING};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoTaskMemFree, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWMINNOACTIVE;

pub const NAME: &str = "K9-Dashboard.lnk";

fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    // SAFETY: the returned string is freed with CoTaskMemFree.
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.0 as _));
        s.map(PathBuf::from)
    }
}

/// Desktop (also when redirected, e.g. to OneDrive) and Start menu "Programs" of this user.
pub fn locations() -> Vec<PathBuf> {
    [&FOLDERID_Desktop, &FOLDERID_Programs].into_iter().filter_map(known_folder).map(|d| d.join(NAME)).collect()
}

/// Creates or refreshes one shortcut.
pub fn create(link: &Path, k9: &Path) -> Result<()> {
    // SAFETY: per-thread COM init; the COM objects are released when dropped.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let sl: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).context("Verknüpfung nicht verfügbar")?;
        sl.SetPath(&HSTRING::from(k9.as_os_str()))?;
        sl.SetArguments(&HSTRING::from("dashboard"))?;
        if let Some(dir) = k9.parent() {
            sl.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))?;
        }
        sl.SetDescription(&HSTRING::from("K9-Dashboard im Browser öffnen"))?;
        // The K9 icon of k9.exe (embedded resource), also when the file type icon differs.
        sl.SetIconLocation(&HSTRING::from(k9.as_os_str()), 0)?;
        sl.SetShowCmd(SW_SHOWMINNOACTIVE)?;
        let file: IPersistFile = sl.cast()?;
        file.Save(&HSTRING::from(link.as_os_str()), true).with_context(|| format!("{} kann nicht gespeichert werden", link.display()))?;
    }
    Ok(())
}

/// Shortcuts for the installed k9.exe; returns the created paths.
pub fn create_all(k9: &Path) -> Vec<Result<PathBuf>> {
    locations().into_iter().map(|l| create(&l, k9).map(|_| l)).collect()
}

/// Removes the shortcuts (missing ones are fine); returns the removed paths.
/// Shortcuts of the old installation ("Virenscanner-Dashboard.lnk").
pub fn remove_old() -> Vec<PathBuf> {
    [&FOLDERID_Desktop, &FOLDERID_Programs]
        .into_iter()
        .filter_map(known_folder)
        .map(|d| d.join(crate::umzug::OLD_SHORTCUT))
        .filter(|l| std::fs::remove_file(l).is_ok())
        .collect()
}

pub fn remove_all() -> Vec<PathBuf> {
    locations().into_iter().filter(|l| std::fs::remove_file(l).is_ok()).collect()
}

/// Target and arguments of a shortcut (for checks).
pub fn target_of(link: &Path) -> Option<(PathBuf, String)> {
    // SAFETY: COM objects are released when dropped; buffers are sized.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let sl: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let file: IPersistFile = sl.cast().ok()?;
        file.Load(&HSTRING::from(link.as_os_str()), windows::Win32::System::Com::STGM_READ).ok()?;
        let mut path = [0u16; 1024];
        sl.GetPath(&mut path, std::ptr::null_mut(), 0).ok()?;
        let mut args = [0u16; 1024];
        sl.GetArguments(&mut args).ok()?;
        let s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())]);
        Some((PathBuf::from(s(&path)), s(&args)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_runs_k9_dashboard() {
        // In a test folder only – never the real desktop.
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let link = dir.path().join(NAME);
        let k9 = Path::new(r"C:\Program Files\K9\k9.exe");
        create(&link, k9).unwrap();
        let (target, args) = target_of(&link).unwrap();
        assert_eq!(target, k9);
        assert_eq!(args, "dashboard");
        assert!(locations().iter().all(|l| l.file_name().is_some_and(|n| n == NAME)));
    }
}
