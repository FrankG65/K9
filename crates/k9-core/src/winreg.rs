//! Minimal registry helpers (read strings/DWORDs, enumerate, delete/set values).

use anyhow::{bail, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
    KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RRF_RT_ANY,
    RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RRF_NOEXPAND, RRF_SUBKEY_WOW6464KEY,
};

pub use windows::Win32::System::Registry::{HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn hive_name(h: HKEY) -> &'static str {
    if h == HKLM {
        "HKLM"
    } else {
        "HKCU"
    }
}

pub fn hive_from_name(s: &str) -> HKEY {
    if s == "HKLM" {
        HKLM
    } else {
        HKCU
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: key was opened by RegOpenKeyExW.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// HKEY_CURRENT_USER of the impersonated user inside the service (the
/// predefined HKCU handle of a service process is the SYSTEM hive).
struct Root(HKEY, #[allow(dead_code)] Option<Key>); // the Key closes the opened hive on drop

fn root(hive: HKEY) -> Root {
    if hive == HKCU && crate::schutz::impersonating() {
        let mut k = HKEY::default();
        // SAFETY: opens the impersonated user's hive; closed by Key's Drop.
        let r = unsafe { windows::Win32::System::Registry::RegOpenCurrentUser((KEY_READ | KEY_SET_VALUE).0, &mut k) };
        if r == ERROR_SUCCESS {
            return Root(k, Some(Key(k)));
        }
    }
    Root(hive, None)
}

fn open(hive: HKEY, path: &str, access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> Option<Key> {
    let base = root(hive);
    let p = wide(path);
    let mut k = HKEY::default();
    // SAFETY: NUL-terminated path, out pointer valid.
    let r = unsafe { RegOpenKeyExW(base.0, PCWSTR(p.as_ptr()), None, access | KEY_WOW64_64KEY, &mut k) };
    (r == ERROR_SUCCESS).then_some(Key(k))
}

/// Opens a key for writing; the error names the Windows error (e.g. "Zugriff verweigert").
fn open_for_write(hive: HKEY, path: &str) -> Result<Key> {
    let base = root(hive);
    let p = wide(path);
    let mut k = HKEY::default();
    // SAFETY: NUL-terminated path, out pointer valid.
    let r = unsafe { RegOpenKeyExW(base.0, PCWSTR(p.as_ptr()), None, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &mut k) };
    if r != ERROR_SUCCESS {
        bail!("Registrierungsschlüssel {}\\{path} nicht beschreibbar: {}", hive_name(hive), win_error(r.0));
    }
    Ok(Key(k))
}

/// "Zugriff verweigert (Windows-Fehler 5)".
pub fn win_error(code: u32) -> String {
    let text = std::io::Error::from_raw_os_error(code as i32).to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).trim().trim_end_matches('.').to_string();
    format!("{text} (Windows-Fehler {code})")
}

/// Reads a REG_BINARY value.
pub fn read_binary(hive: HKEY, path: &str, value: &str) -> Option<Vec<u8>> {
    let base = root(hive);
    let p = wide(path);
    let v = wide(value);
    let mut len = 0u32;
    // SAFETY: size query, then read into a buffer of that size.
    unsafe {
        if RegGetValueW(base.0, PCWSTR(p.as_ptr()), PCWSTR(v.as_ptr()), RRF_RT_REG_BINARY | RRF_SUBKEY_WOW6464KEY, None, None, Some(&mut len)) != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if RegGetValueW(base.0, PCWSTR(p.as_ptr()), PCWSTR(v.as_ptr()), RRF_RT_REG_BINARY | RRF_SUBKEY_WOW6464KEY, None, Some(buf.as_mut_ptr().cast()), Some(&mut len)) != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn set_binary(hive: HKEY, path: &str, value: &str, data: &[u8]) -> Result<()> {
    let k = open_for_write(hive, path)?;
    let v = wide(value);
    // SAFETY: open key, data slice valid for the call.
    let r = unsafe { RegSetValueExW(k.0, PCWSTR(v.as_ptr()), None, windows::Win32::System::Registry::REG_BINARY, Some(data)) };
    if r != ERROR_SUCCESS {
        bail!("Wert {value} konnte nicht geschrieben werden: {}", win_error(r.0));
    }
    Ok(())
}

/// Reads a REG_SZ / REG_EXPAND_SZ value (not expanded).
pub fn read_string(hive: HKEY, path: &str, value: &str) -> Option<String> {
    let base = root(hive);
    let hive = base.0;
    let p = wide(path);
    let v = wide(value);
    let mut size = 0u32;
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    // SAFETY: size query, then read into a correctly sized buffer.
    unsafe {
        if RegGetValueW(hive, PCWSTR(p.as_ptr()), PCWSTR(v.as_ptr()), flags, None, None, Some(&mut size)) != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size2 = (buf.len() * 2) as u32;
        if RegGetValueW(
            hive,
            PCWSTR(p.as_ptr()),
            PCWSTR(v.as_ptr()),
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size2),
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]))
    }
}

pub fn read_dword(hive: HKEY, path: &str, value: &str) -> Option<u32> {
    let base = root(hive);
    let hive = base.0;
    let p = wide(path);
    let v = wide(value);
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: buffer of 4 bytes.
    let r = unsafe {
        RegGetValueW(hive, PCWSTR(p.as_ptr()), PCWSTR(v.as_ptr()), RRF_RT_REG_DWORD, None, Some(&mut data as *mut u32 as *mut _), Some(&mut size))
    };
    (r == ERROR_SUCCESS).then_some(data)
}

pub fn key_exists(hive: HKEY, path: &str) -> bool {
    open(hive, path, KEY_READ).is_some()
}

/// Whether a value of any type exists.
pub fn value_exists(hive: HKEY, path: &str, value: &str) -> bool {
    let base = root(hive);
    let p = wide(path);
    let v = wide(value);
    let mut size = 0u32;
    // SAFETY: size query only, no buffer.
    let r = unsafe { RegGetValueW(base.0, PCWSTR(p.as_ptr()), PCWSTR(v.as_ptr()), RRF_RT_ANY, None, None, Some(&mut size)) };
    r == ERROR_SUCCESS
}

pub fn subkeys(hive: HKEY, path: &str) -> Vec<String> {
    let Some(k) = open(hive, path, KEY_READ) else { return Vec::new() };
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        // SAFETY: buffer and length are valid.
        let r = unsafe { RegEnumKeyExW(k.0, i, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None) };
        if r != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&buf[..len as usize]));
        i += 1;
    }
    out
}

/// (name, string data) of all string values of a key.
pub fn string_values(hive: HKEY, path: &str) -> Vec<(String, String)> {
    let Some(k) = open(hive, path, KEY_READ) else { return Vec::new() };
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut name = [0u16; 1024];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 8192];
        let mut data_len = data.len() as u32;
        let mut typ = 0u32;
        // SAFETY: buffers and lengths are valid.
        let r = unsafe {
            RegEnumValueW(
                k.0,
                i,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut typ),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        i += 1;
        let t = REG_VALUE_TYPE(typ);
        if t != REG_SZ && t != REG_EXPAND_SZ {
            continue;
        }
        let words: Vec<u16> = data[..data_len as usize].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let end = words.iter().position(|c| *c == 0).unwrap_or(words.len());
        out.push((String::from_utf16_lossy(&name[..name_len as usize]), String::from_utf16_lossy(&words[..end])));
    }
    out
}

pub fn delete_value(hive: HKEY, path: &str, value: &str) -> Result<()> {
    let k = open_for_write(hive, path)?;
    let v = wide(value);
    // SAFETY: open key, NUL-terminated name.
    let r = unsafe { RegDeleteValueW(k.0, PCWSTR(v.as_ptr())) };
    if r != ERROR_SUCCESS {
        bail!("Wert {value} konnte nicht entfernt werden: {}", win_error(r.0));
    }
    Ok(())
}

/// Creates a key (and parents) if it does not exist.
pub fn create_key(hive: HKEY, path: &str) -> Result<()> {
    let base = root(hive);
    let p = wide(path);
    let mut k = HKEY::default();
    // SAFETY: valid NUL-terminated path; key closed right away.
    let r = unsafe { windows::Win32::System::Registry::RegCreateKeyW(base.0, PCWSTR(p.as_ptr()), &mut k) };
    if r != ERROR_SUCCESS {
        bail!("Registrierungsschlüssel {}\\{path} kann nicht angelegt werden ({:?})", hive_name(hive), r);
    }
    // SAFETY: key opened above.
    unsafe {
        let _ = RegCloseKey(k);
    }
    Ok(())
}

/// Deletes a key with all subkeys and values.
pub fn delete_tree(hive: HKEY, path: &str) -> Result<()> {
    let base = root(hive);
    let p = wide(path);
    // SAFETY: valid NUL-terminated path.
    let r = unsafe { windows::Win32::System::Registry::RegDeleteTreeW(base.0, PCWSTR(p.as_ptr())) };
    if r != ERROR_SUCCESS && r != windows::Win32::Foundation::ERROR_FILE_NOT_FOUND {
        bail!("Registrierungsschlüssel {}\\{path} kann nicht gelöscht werden ({:?})", hive_name(hive), r);
    }
    Ok(())
}

pub fn set_string(hive: HKEY, path: &str, value: &str, data: &str) -> Result<()> {
    let k = open_for_write(hive, path)?;
    let v = wide(value);
    let d = wide(data);
    // SAFETY: open key; data as little-endian UTF-16 bytes incl. NUL.
    let r = unsafe {
        let bytes = std::slice::from_raw_parts(d.as_ptr() as *const u8, d.len() * 2);
        RegSetValueExW(k.0, PCWSTR(v.as_ptr()), None, REG_SZ, Some(bytes))
    };
    if r != ERROR_SUCCESS {
        bail!("Wert {value} konnte nicht geschrieben werden: {}", win_error(r.0));
    }
    Ok(())
}

pub fn set_dword(hive: HKEY, path: &str, value: &str, data: u32) -> Result<()> {
    let k = open_for_write(hive, path)?;
    let v = wide(value);
    // SAFETY: open key; 4 data bytes.
    let r = unsafe {
        RegSetValueExW(k.0, PCWSTR(v.as_ptr()), None, windows::Win32::System::Registry::REG_DWORD, Some(&data.to_le_bytes()))
    };
    if r != ERROR_SUCCESS {
        bail!("Wert {value} konnte nicht geschrieben werden: {}", win_error(r.0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_is_created_before_a_value_is_written() {
        let key = format!("Software\\K9-Test-{}\\Neu\\Tief", std::process::id());
        assert!(set_dword(HKCU, &key, "Wert", 1).is_err(), "ohne Schlüssel kein Schreiben");
        create_key(HKCU, &key).unwrap();
        set_dword(HKCU, &key, "Wert", 1).unwrap();
        assert_eq!(read_dword(HKCU, &key, "Wert"), Some(1));
        delete_value(HKCU, &key, "Wert").unwrap();
        assert_eq!(read_dword(HKCU, &key, "Wert"), None);
        delete_tree(HKCU, &format!("Software\\K9-Test-{}", std::process::id())).unwrap();
        assert!(!key_exists(HKCU, &key));
    }

    #[test]
    fn errors_name_the_windows_error() {
        // never the real Run key: a key that does not exist names "not found"
        let e = set_string(HKLM, &format!("SOFTWARE\\K9-gibt-es-nicht-{}", std::process::id()), "x", "y").unwrap_err();
        assert!(format!("{e:#}").contains("Windows-Fehler 2"), "{e:#}");
        assert!(win_error(2).ends_with("(Windows-Fehler 2)"));
        let key = format!("Software\\K9-Test-{}-bin", std::process::id());
        create_key(HKCU, &key).unwrap();
        set_binary(HKCU, &key, "B", &[3, 0, 0, 0, 1, 2]).unwrap();
        assert_eq!(read_binary(HKCU, &key, "B"), Some(vec![3, 0, 0, 0, 1, 2]));
        delete_tree(HKCU, &key).unwrap();
    }

    #[test]
    fn reads_well_known_values() {
        let v = read_string(HKLM, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
        assert!(v.is_some_and(|s| s.contains("Windows")));
        assert!(!subkeys(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall").is_empty());
    }

    #[test]
    fn set_and_delete_in_hkcu_test_key() {
        // Uses our own key under HKCU\Software\K9-Test.
        let path = "Software\\K9-Test";
        let p = wide(path);
        let mut k = HKEY::default();
        unsafe {
            let _ = windows::Win32::System::Registry::RegCreateKeyW(HKCU, PCWSTR(p.as_ptr()), &mut k);
            let _ = RegCloseKey(k);
        }
        set_string(HKCU, path, "Probe", "C:\\x.exe /a").unwrap();
        assert!(string_values(HKCU, path).contains(&("Probe".to_string(), "C:\\x.exe /a".to_string())));
        delete_value(HKCU, path, "Probe").unwrap();
        assert!(read_string(HKCU, path, "Probe").is_none());
        unsafe {
            let _ = windows::Win32::System::Registry::RegDeleteKeyW(HKCU, PCWSTR(p.as_ptr()));
        }
    }
}
