//! Browser "native messaging": a browser extension talks to a helper program
//! on the PC. Chrome/Edge/Brave/Vivaldi/Opera start it with
//! `cmd.exe /d /s /c ""<host.exe>" chrome-extension://<id>/ --parent-window=N" < \\.\pipe\…`,
//! Firefox starts it with the manifest path and the extension id.
//!
//! Such a start is harmless only if the helper is registered for exactly
//! this extension (manifest under `Software\<Browser>\NativeMessagingHosts`)
//! and digitally signed. Newly registered helpers are a way for malicious
//! extensions to persist and are reported like autostart entries.

use std::path::{Path, PathBuf};

use crate::winreg::{self, HKCU, HKLM};

/// Registry keys with registered helpers (per user and machine, also 32-bit view).
pub const HOST_KEYS: [(&str, &str); 7] = [
    ("Chrome", "Software\\Google\\Chrome\\NativeMessagingHosts"),
    ("Edge", "Software\\Microsoft\\Edge\\NativeMessagingHosts"),
    ("Brave", "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts"),
    ("Vivaldi", "Software\\Vivaldi\\NativeMessagingHosts"),
    ("Chromium", "Software\\Chromium\\NativeMessagingHosts"),
    ("Opera", "Software\\Opera Software\\NativeMessagingHosts"),
    ("Firefox", "Software\\Mozilla\\NativeMessagingHosts"),
];

const BROWSERS: [&str; 7] = ["chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "chromium.exe", "firefox.exe"];

/// A registered helper.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub browser: &'static str,
    pub hive: &'static str,
    /// Registry key of this helper.
    pub key: String,
    pub name: String,
    pub manifest: PathBuf,
}

/// All registered helpers of all browsers.
pub fn registered_hosts() -> Vec<Host> {
    let mut out = Vec::new();
    for (hive, hive_name) in [(HKCU, "HKCU"), (HKLM, "HKLM")] {
        for (browser, base) in HOST_KEYS {
            for base in [base.to_string(), base.replacen("Software\\", "Software\\WOW6432Node\\", 1)] {
                for name in winreg::subkeys(hive, &base) {
                    let key = format!("{base}\\{name}");
                    if let Some(manifest) = winreg::read_string(hive, &key, "") {
                        out.push(Host { browser, hive: hive_name, key, name, manifest: PathBuf::from(crate::paths::expand_env(&manifest)) });
                    }
                }
            }
        }
    }
    out
}

/// Program and extension of a native-messaging start, if the command line
/// has that form: (helper exe, extension origin or id).
pub fn launch(parent: &str, cmdline: &str) -> Option<(PathBuf, String)> {
    let parent = parent.to_ascii_lowercase();
    if !BROWSERS.contains(&parent.as_str()) {
        return None;
    }
    let lower = cmdline.to_ascii_lowercase();
    // Chromium: chrome-extension://<32 letters a-p>/
    if let Some(i) = lower.find("chrome-extension://") {
        let rest = &lower[i + 19..];
        let id: String = rest.chars().take_while(|c| c.is_ascii_lowercase()).collect();
        if id.len() != 32 || !rest[id.len()..].starts_with('/') {
            return None;
        }
        let exe = quoted_exe(&cmdline[..i])?;
        return Some((exe, format!("chrome-extension://{id}/")));
    }
    // Firefox: "<host.exe>" "<manifest.json>" <extension id>
    if parent == "firefox.exe" {
        let exe = quoted_exe(cmdline)?;
        let id = cmdline.split_whitespace().last()?.trim_matches('"').to_string();
        return (!id.is_empty() && id.len() < 256).then_some((exe, id));
    }
    None
}

/// First quoted path ending in `.exe`.
fn quoted_exe(s: &str) -> Option<PathBuf> {
    s.split('"').map(str::trim).find(|p| p.to_ascii_lowercase().ends_with(".exe") && p.contains('\\')).map(PathBuf::from)
}

/// Does the manifest register `exe` for `origin` (Chromium) or extension id (Firefox)?
pub fn manifest_allows(manifest_json: &str, manifest_dir: &Path, exe: &Path, origin: &str) -> bool {
    let Ok(m) = serde_json::from_str::<serde_json::Value>(manifest_json) else { return false };
    let Some(path) = m["path"].as_str() else { return false };
    let path = Path::new(path);
    let path = if path.is_absolute() { path.to_path_buf() } else { manifest_dir.join(path) };
    if !path.to_string_lossy().eq_ignore_ascii_case(&exe.to_string_lossy()) {
        return false;
    }
    let listed = |field: &str| m[field].as_array().is_some_and(|a| a.iter().any(|o| o.as_str().is_some_and(|o| o.eq_ignore_ascii_case(origin))));
    listed("allowed_origins") || listed("allowed_extensions")
}

/// True if this browser start of a helper is legitimate: registered for
/// exactly this extension and the helper is digitally signed.
pub fn verified_launch(parent: &str, cmdline: &str) -> bool {
    let Some((exe, origin)) = launch(parent, cmdline) else { return false };
    let registered = registered_hosts().iter().any(|h| {
        let dir = h.manifest.parent().unwrap_or(Path::new(""));
        std::fs::read_to_string(&h.manifest).is_ok_and(|json| manifest_allows(&json, dir, &exe, &origin))
    });
    registered && crate::autostart::is_signed(&exe)
}

/// Helper program of a registration (from its manifest).
pub fn host_program(h: &Host) -> Option<PathBuf> {
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&h.manifest).ok()?).ok()?;
    let p = Path::new(json["path"].as_str()?);
    Some(if p.is_absolute() { p.to_path_buf() } else { h.manifest.parent()?.join(p) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TM: &str = r#"C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\Program Files\Trend Micro\Titanium\UIFramework\Toolbar\chromeextension\NativeMessageHost\ToolbarNativeMsgHost.exe" chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/ --parent-window=0" < \\.\pipe\chrome.nativeMessaging.in.1a2b > \\.\pipe\chrome.nativeMessaging.out.1a2b"#;
    const EXE: &str = r"C:\Program Files\Trend Micro\Titanium\UIFramework\Toolbar\chromeextension\NativeMessageHost\ToolbarNativeMsgHost.exe";

    #[test]
    fn recognises_chromium_launch() {
        let (exe, origin) = launch("chrome.exe", TM).unwrap();
        assert_eq!(exe, PathBuf::from(EXE));
        assert_eq!(origin, "chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/");
        assert!(launch("winword.exe", TM).is_none(), "nur Browser");
        assert!(launch("chrome.exe", "cmd.exe /c powershell -enc AAAA").is_none());
    }

    #[test]
    fn manifest_must_name_program_and_extension() {
        let dir = Path::new(r"C:\Program Files\Trend Micro\Titanium\UIFramework\Toolbar\chromeextension\NativeMessageHost");
        let exe = PathBuf::from(EXE);
        let origin = "chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/";
        let ok = r#"{"name":"com.trendmicro.tb","path":"ToolbarNativeMsgHost.exe","type":"stdio","allowed_origins":["chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/"]}"#;
        assert!(manifest_allows(ok, dir, &exe, origin));
        // Another extension may not use this helper.
        assert!(!manifest_allows(ok, dir, &exe, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"));
        // A manifest pointing to another program does not cover this one.
        let other = r#"{"path":"C:\\Temp\\evil.exe","allowed_origins":["chrome-extension://ohhcpmplhhiiaoiddkfboafbhiknefdf/"]}"#;
        assert!(!manifest_allows(other, dir, &exe, origin));
        assert!(!manifest_allows("kein json", dir, &exe, origin));
    }

    /// Live check on this PC (Trend Micro toolbar helper): cargo test -- --ignored
    #[test]
    #[ignore]
    fn live_trend_micro_helper_is_verified() {
        for h in registered_hosts() {
            eprintln!("{} {} {} -> {:?}", h.browser, h.hive, h.name, host_program(&h));
        }
        assert!(verified_launch("chrome.exe", TM));
    }

    #[test]
    fn unregistered_launch_is_not_verified() {
        // Fake extension id: no manifest on this PC registers it.
        let cmd = TM.replace("ohhcpmplhhiiaoiddkfboafbhiknefdf", "pppppppppppppppppppppppppppppppp");
        assert!(!verified_launch("chrome.exe", &cmd));
    }
}
