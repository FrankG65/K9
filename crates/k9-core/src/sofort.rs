//! "Sofort": wake-up signals from Windows instead of a polling rhythm – registry keys
//! (autostart Run keys) and folders (Startup folders). The monitor waits for any of them
//! (with a timeout as backstop) and then looks only once, so nothing is busy in between.

use std::path::Path;

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
};
use windows::Win32::System::Registry::{RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME};
use windows::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

enum Quelle {
    Registry { key: HKEY, event: HANDLE },
    Ordner { handle: HANDLE },
}

/// Wakes up when one of the watched registry keys or folders changes.
#[derive(Default)]
pub struct Wecker {
    quellen: Vec<Quelle>,
}

// SAFETY: the handles are only used by the thread that owns the Wecker.
unsafe impl Send for Wecker {}

impl Wecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of watched keys and folders.
    pub fn len(&self) -> usize {
        self.quellen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.quellen.is_empty()
    }

    fn arm(key: HKEY, event: HANDLE) -> bool {
        // SAFETY: valid key and event (asynchronous notification, values and sub keys).
        unsafe { RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, Some(event), true).is_ok() }
    }

    /// Watches a registry key (values and sub keys). False if it can't be opened.
    pub fn registry(&mut self, hive: HKEY, path: &str) -> bool {
        if self.quellen.len() >= 60 {
            return false; // WaitForMultipleObjects takes at most 64 handles
        }
        let mut key = HKEY::default();
        // SAFETY: opens a key for notifications only; key and event are closed in Drop.
        unsafe {
            if RegOpenKeyExW(hive, &HSTRING::from(path), None, KEY_NOTIFY, &mut key).is_err() {
                return false;
            }
            let Ok(event) = CreateEventW(None, false, false, None) else {
                let _ = RegCloseKey(key);
                return false;
            };
            if !Self::arm(key, event) {
                let _ = RegCloseKey(key);
                let _ = CloseHandle(event);
                return false;
            }
            self.quellen.push(Quelle::Registry { key, event });
            true
        }
    }

    /// Watches a folder (new, renamed, deleted or changed files). False if it doesn't exist.
    pub fn ordner(&mut self, dir: &Path) -> bool {
        if self.quellen.len() >= 60 || !dir.is_dir() {
            return false;
        }
        // SAFETY: the change handle is closed in Drop.
        match unsafe { FindFirstChangeNotificationW(&HSTRING::from(dir.as_os_str()), false, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE) } {
            Ok(handle) if !handle.is_invalid() => {
                self.quellen.push(Quelle::Ordner { handle });
                true
            }
            _ => false,
        }
    }

    /// Waits up to `ms`. True: something changed (the source is armed again). Without any
    /// source it simply sleeps.
    pub fn wait(&self, ms: u32) -> bool {
        if self.quellen.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
            return false;
        }
        let handles: Vec<HANDLE> = self
            .quellen
            .iter()
            .map(|q| match q {
                Quelle::Registry { event, .. } => *event,
                Quelle::Ordner { handle } => *handle,
            })
            .collect();
        // SAFETY: valid handles owned by self.
        let r = unsafe { WaitForMultipleObjects(&handles, false, ms) };
        let i = r.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        let Some(q) = self.quellen.get(i) else { return false };
        match q {
            Quelle::Registry { key, event } => {
                Self::arm(*key, *event);
            }
            Quelle::Ordner { handle } => {
                // SAFETY: valid change handle.
                unsafe {
                    let _ = FindNextChangeNotification(*handle);
                }
            }
        }
        true
    }
}

impl Drop for Wecker {
    fn drop(&mut self) {
        for q in &self.quellen {
            // SAFETY: handles created in registry()/ordner().
            unsafe {
                match q {
                    Quelle::Registry { key, event } => {
                        let _ = RegCloseKey(*key);
                        let _ = CloseHandle(*event);
                    }
                    Quelle::Ordner { handle } => {
                        let _ = FindCloseChangeNotification(*handle);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn wakes_up_at_once_for_a_registry_value_and_a_new_file() {
        // Own test key in HKCU and an own test folder only.
        let key = format!("Software\\K9-Tests\\sofort-{}", std::process::id());
        crate::winreg::create_key(crate::winreg::HKCU, &key).unwrap();
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let mut w = Wecker::new();
        assert!(w.registry(crate::winreg::HKCU, &key));
        assert!(w.ordner(dir.path()));
        assert!(!w.registry(crate::winreg::HKCU, "Software\\K9-Tests\\gibt-es-nicht"));
        assert_eq!(w.len(), 2);
        assert!(!w.wait(200), "ohne Aenderung kein Signal");

        let k2 = key.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            crate::winreg::set_string(crate::winreg::HKCU, &k2, "Test", "x").unwrap();
        });
        let start = Instant::now();
        assert!(w.wait(10_000));
        assert!(start.elapsed() < Duration::from_secs(3), "Signal kommt sofort, nicht erst nach dem Zeitlimit");
        t.join().unwrap();

        // armed again: the next change wakes up too
        crate::winreg::set_string(crate::winreg::HKCU, &key, "Test2", "y").unwrap();
        assert!(w.wait(5000));

        std::fs::write(dir.path().join("neu.lnk"), b"x").unwrap();
        assert!(w.wait(5000), "neue Datei im Ordner");
        drop(w);
        crate::winreg::delete_tree(crate::winreg::HKCU, &key).unwrap();
    }
}
