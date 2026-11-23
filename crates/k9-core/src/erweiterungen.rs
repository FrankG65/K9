//! Browser extensions: inventory (Chromium browsers and Firefox), policy and registry
//! installs, risk assessment and findings. Read only – an extension is never removed
//! or switched off by the scanner; the finding explains how to do it in the browser.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::model::{Finding, Kind, Severity};
use crate::winreg::{self, HKCU, HKLM};

/// Official update addresses of the stores.
const STORE_UPDATE_URLS: [&str; 3] = [
    "https://clients2.google.com/service/update2/crx",
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    "https://extension-updates.opera.com/api/omaha/update/",
];

pub const MALEXT_FILE: &str = "erweiterungen/malext-ids.txt";
pub const MALEXT_URL: &str = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    pub id: &'static str,
    pub name: &'static str,
    /// User data folder relative to %LOCALAPPDATA% (Chromium) or %APPDATA% (Opera/Firefox).
    pub dir: &'static str,
    pub roaming: bool,
    pub chromium: bool,
    /// Registry part for policies and external extensions (`Software\Policies\<x>`, `Software\<x>\Extensions`).
    pub reg: &'static str,
}

pub const BROWSERS: &[Browser] = &[
    Browser { id: "chrome", name: "Google Chrome", dir: "Google\\Chrome\\User Data", roaming: false, chromium: true, reg: "Google\\Chrome" },
    Browser { id: "edge", name: "Microsoft Edge", dir: "Microsoft\\Edge\\User Data", roaming: false, chromium: true, reg: "Microsoft\\Edge" },
    Browser { id: "brave", name: "Brave", dir: "BraveSoftware\\Brave-Browser\\User Data", roaming: false, chromium: true, reg: "BraveSoftware\\Brave" },
    Browser { id: "vivaldi", name: "Vivaldi", dir: "Vivaldi\\User Data", roaming: false, chromium: true, reg: "Vivaldi" },
    Browser { id: "opera", name: "Opera", dir: "Opera Software\\Opera Stable", roaming: true, chromium: true, reg: "Opera Software" },
    Browser { id: "firefox", name: "Firefox", dir: "Mozilla\\Firefox\\Profiles", roaming: true, chromium: false, reg: "Mozilla\\Firefox" },
];

/// How an extension got into the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Source {
    /// From the official store.
    Store,
    /// Installed outside the store (registry, preferences file, unpacked, command line).
    Outside,
    /// Forced by a policy of the administrator (or a program with admin rights).
    Policy,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Extension {
    pub browser: &'static str,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: Source,
    pub update_url: String,
    pub permissions: BTreeSet<String>,
    pub hosts: BTreeSet<String>,
    pub enabled: bool,
}

impl Extension {
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.browser, self.profile, self.id)
    }

    /// Fingerprint of the rights: an update with new rights is a new state.
    pub fn rights_hash(&self) -> String {
        let all: Vec<&str> = self.permissions.iter().chain(self.hosts.iter()).map(String::as_str).collect();
        crate::sha256_hex(all.join(",").as_bytes())[..16].to_string()
    }

    pub fn broad_hosts(&self) -> bool {
        self.hosts.iter().chain(self.permissions.iter()).any(|h| {
            let h = h.as_str();
            h == "<all_urls>" || h == "*://*/*" || h == "http://*/*" || h == "https://*/*" || h == "*://*/" || h == "https://*/"
        })
    }

    fn has(&self, p: &str) -> bool {
        self.permissions.contains(p)
    }
}

const SENSITIVE: [&str; 9] = ["cookies", "webRequest", "webRequestBlocking", "scripting", "clipboardRead", "debugger", "proxy", "nativeMessaging", "management"];
const CRITICAL: [&str; 4] = ["debugger", "proxy", "nativeMessaging", "management"];

/// Store or not, from a Chromium "location" value and the update address.
fn chromium_source(location: i64, from_webstore: bool, update_url: &str) -> Source {
    match location {
        7 | 9 => Source::Policy,
        _ if from_webstore || is_store_url(update_url) => Source::Store,
        _ => Source::Outside,
    }
}

pub fn is_store_url(url: &str) -> bool {
    let u = url.trim().to_lowercase();
    STORE_UPDATE_URLS.iter().any(|s| u.starts_with(s))
}

fn strings(v: &serde_json::Value) -> BTreeSet<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Display name: resolves "__MSG_name__" from the extension's default locale.
fn display_name(manifest: &serde_json::Value, dir: &Path) -> String {
    let raw = manifest["name"].as_str().unwrap_or("").to_string();
    let Some(key) = raw.strip_prefix("__MSG_").and_then(|r| r.strip_suffix("__")) else { return raw };
    let locale = manifest["default_locale"].as_str().unwrap_or("en");
    std::fs::read_to_string(dir.join("_locales").join(locale).join("messages.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|m| {
            m.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).and_then(|(_, v)| v["message"].as_str().map(String::from))
        })
        .unwrap_or(raw)
}

/// Highest version folder of an installed Chromium extension.
fn version_dir(ext_dir: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(ext_dir).ok()?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.join("manifest.json").is_file()).collect();
    dirs.sort();
    dirs.pop()
}

/// Extensions of one Chromium profile. `prefs` is "Secure Preferences" merged with
/// "Preferences" (extensions.settings), `profile_dir` the profile folder.
pub fn chromium_profile(browser: &'static str, profile: &str, prefs: &[serde_json::Value], profile_dir: &Path) -> Vec<Extension> {
    let mut settings: HashMap<String, serde_json::Value> = HashMap::new();
    for p in prefs {
        if let Some(map) = p["extensions"]["settings"].as_object() {
            for (k, v) in map {
                settings.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    let mut out = Vec::new();
    for (id, s) in settings {
        let location = s["location"].as_i64().unwrap_or(1);
        // Component extensions are part of the browser.
        if matches!(location, 5 | 10) || id.len() != 32 {
            continue;
        }
        let path = s["path"].as_str().unwrap_or("");
        let dir = if location == 4 && !path.is_empty() {
            Some(PathBuf::from(path))
        } else {
            version_dir(&profile_dir.join("Extensions").join(&id))
        };
        let manifest = dir
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("manifest.json")).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .or_else(|| s.get("manifest").cloned())
            .unwrap_or_default();
        let update_url = manifest["update_url"].as_str().unwrap_or("").to_string();
        let mut permissions = strings(&manifest["permissions"]);
        let mut hosts = strings(&manifest["host_permissions"]);
        permissions.extend(strings(&s["granted_permissions"]["api"]));
        hosts.extend(strings(&s["granted_permissions"]["explicit_host"]));
        hosts.extend(strings(&s["granted_permissions"]["scriptable_host"]));
        if let Some(cs) = manifest["content_scripts"].as_array() {
            for c in cs {
                hosts.extend(strings(&c["matches"]));
            }
        }
        // Manifest v2 puts hosts into "permissions".
        let (h, p): (BTreeSet<String>, BTreeSet<String>) = permissions.into_iter().partition(|x| x.contains("://") || x == "<all_urls>");
        hosts.extend(h);
        permissions = p;
        out.push(Extension {
            browser,
            profile: profile.to_string(),
            name: dir.as_deref().map(|d| display_name(&manifest, d)).unwrap_or_else(|| manifest["name"].as_str().unwrap_or("").to_string()),
            version: manifest["version"].as_str().unwrap_or("").to_string(),
            source: chromium_source(location, s["from_webstore"].as_bool().unwrap_or(false), &update_url),
            update_url,
            permissions,
            hosts,
            enabled: s["state"].as_i64().unwrap_or(1) == 1 && s["disable_reasons"].as_i64().unwrap_or(0) == 0,
            id,
        });
    }
    out
}

/// Firefox's own add-ons: shipped with Firefox (fixed locations) AND a Mozilla ID.
/// app-system-local/-user/-share are where other programs put add-ons – those stay reportable.
fn is_firefox_builtin(location: &str, id: &str) -> bool {
    let id = id.to_lowercase();
    ["app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons"].contains(&location)
        && ["@mozilla.org", "@mozilla.com", "@search.mozilla.org"].iter().any(|d| id.ends_with(d))
}

/// Profile folders below a browser's data folder (only directories: "Local State" is a file).
fn profile_dirs(base: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect()
}

/// Extensions of one Firefox profile (extensions.json).
pub fn firefox_profile(profile: &str, extensions_json: &serde_json::Value) -> Vec<Extension> {
    let mut out = Vec::new();
    for a in extensions_json["addons"].as_array().into_iter().flatten() {
        let location = a["location"].as_str().unwrap_or("");
        if a["type"].as_str() != Some("extension") || is_firefox_builtin(location, a["id"].as_str().unwrap_or("")) {
            continue; // Firefox's own built-in and system add-ons
        }
        let source_uri = a["sourceURI"].as_str().unwrap_or("");
        let source = if location.contains("policy") {
            Source::Policy
        } else if source_uri.starts_with("https://addons.mozilla.org/") || a["signedState"].as_i64().unwrap_or(0) >= 2 {
            Source::Store
        } else {
            Source::Outside
        };
        out.push(Extension {
            browser: "firefox",
            profile: profile.to_string(),
            id: a["id"].as_str().unwrap_or("").to_string(),
            name: a["defaultLocale"]["name"].as_str().unwrap_or("").to_string(),
            version: a["version"].as_str().unwrap_or("").to_string(),
            source,
            update_url: source_uri.to_string(),
            permissions: strings(&a["userPermissions"]["permissions"]),
            hosts: strings(&a["userPermissions"]["origins"]),
            enabled: a["active"].as_bool().unwrap_or(true),
        });
    }
    out
}

/// All extensions of all installed browsers of the current user.
pub fn inventory() -> Vec<Extension> {
    let local = crate::paths::user_dir("LOCALAPPDATA");
    let roaming = crate::paths::user_dir("APPDATA");
    let mut out = Vec::new();
    for b in BROWSERS {
        let Some(root) = (if b.roaming { &roaming } else { &local }) else { continue };
        let base = root.join(b.dir);
        if !base.is_dir() {
            continue;
        }
        let read = |p: PathBuf| std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        if b.chromium {
            // Opera keeps a single profile directly in its folder.
            let profiles: Vec<PathBuf> = if b.id == "opera" {
                vec![base.clone()]
            } else {
                profile_dirs(&base).into_iter().filter(|p| p.join("Preferences").is_file()).collect()
            };
            for p in profiles {
                let prefs: Vec<serde_json::Value> = ["Secure Preferences", "Preferences"].iter().filter_map(|f| read(p.join(f))).collect();
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                out.extend(chromium_profile(b.id, &name, &prefs, &p));
            }
        } else {
            for p in profile_dirs(&base) {
                if let Some(v) = read(p.join("extensions.json")) {
                    out.extend(firefox_profile(&p.file_name().unwrap_or_default().to_string_lossy(), &v));
                }
            }
        }
    }
    out
}

/// Developer mode switched on in a Chromium profile (shown in the dashboard only).
pub fn developer_mode() -> Vec<(String, String)> {
    let Some(local) = crate::paths::user_dir("LOCALAPPDATA") else { return Vec::new() };
    let mut out = Vec::new();
    for b in BROWSERS.iter().filter(|b| b.chromium && !b.roaming) {
        for dir in profile_dirs(&local.join(b.dir)) {
            let on = std::fs::read_to_string(dir.join("Preferences"))
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .is_some_and(|v| v["extensions"]["ui"]["developer_mode"].as_bool() == Some(true));
            if on {
                out.push((b.name.to_string(), dir.file_name().unwrap_or_default().to_string_lossy().to_string()));
            }
        }
    }
    out
}

/// An install instruction from a policy or the registry (outside the browser).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ForcedInstall {
    pub browser: &'static str,
    pub id: String,
    /// Update address or local path.
    pub source: String,
    /// Where it is registered (registry key).
    pub location: String,
    pub policy: bool,
    /// All values of a registry install key ("update_url=…;path=…;version=…"), part of the
    /// fingerprint: values added later make a new finding at the normal level.
    pub values: String,
}

/// Parses "id;update_url" values of ExtensionInstallForcelist (Chromium).
pub fn parse_forcelist(value: &str) -> (String, String) {
    let mut parts = value.splitn(2, ';');
    (parts.next().unwrap_or("").trim().to_string(), parts.next().unwrap_or("").trim().to_string())
}

/// Policies (ExtensionInstallForcelist, ExtensionSettings) and external registry
/// installs (Software\<browser>\Extensions\<id>) in HKLM and HKCU.
pub fn forced_installs() -> Vec<ForcedInstall> {
    let mut out = Vec::new();
    for b in BROWSERS {
        for (hive, hive_name) in [(HKLM, "HKLM"), (HKCU, "HKCU")] {
            let pol = format!("Software\\Policies\\{}", b.reg);
            if b.chromium {
                let key = format!("{pol}\\ExtensionInstallForcelist");
                for (_, v) in winreg::string_values(hive, &key) {
                    let (id, url) = parse_forcelist(&v);
                    out.push(ForcedInstall { browser: b.id, id, values: url.clone(), source: url, location: format!("{hive_name}\\{key}"), policy: true });
                }
            }
            if let Some(json) = winreg::read_string(hive, &pol, "ExtensionSettings") {
                for (id, url) in parse_extension_settings(&json) {
                    out.push(ForcedInstall { browser: b.id, id, values: url.clone(), source: url, location: format!("{hive_name}\\{pol}\\ExtensionSettings"), policy: true });
                }
            }
            if b.chromium {
                for base in [format!("Software\\{}\\Extensions", b.reg), format!("Software\\WOW6432Node\\{}\\Extensions", b.reg)] {
                    for id in winreg::subkeys(hive, &base) {
                        let key = format!("{base}\\{id}");
                        let src = winreg::read_string(hive, &key, "update_url").or_else(|| winreg::read_string(hive, &key, "path")).unwrap_or_default();
                        let values = ["update_url", "path", "version"]
                            .iter()
                            .filter_map(|v| winreg::read_string(hive, &key, v).map(|x| format!("{v}={x}")))
                            .collect::<Vec<_>>()
                            .join(";");
                        out.push(ForcedInstall { browser: b.id, id, source: src, location: format!("{hive_name}\\{key}"), policy: false, values });
                    }
                }
            }
        }
    }
    out
}

/// Force-installed extensions from an ExtensionSettings policy (JSON).
pub fn parse_extension_settings(json: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    v.as_object()
        .into_iter()
        .flatten()
        .filter(|(_, s)| matches!(s["installation_mode"].as_str(), Some("force_installed") | Some("normal_installed")))
        .map(|(id, s)| (id.clone(), s["update_url"].as_str().or(s["install_url"].as_str()).unwrap_or("").to_string()))
        .collect()
}

/// Known malicious extension IDs (MalExt Sentry list).
pub fn load_malicious(dir: &Path) -> HashSet<String> {
    std::fs::read_to_string(dir.join(MALEXT_FILE)).map(|t| parse_malicious(&t)).unwrap_or_default()
}

/// Only valid Chromium IDs (32 letters a–p) are taken.
pub fn parse_malicious(text: &str) -> HashSet<String> {
    text.split([',', '\n', '\r', ' '])
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.len() == 32 && s.bytes().all(|b| (b'a'..=b'p').contains(&b)))
        .collect()
}

/// Facts about a native helper an extension may start.
#[derive(Debug, Clone, Default)]
pub struct NativeHelper {
    pub unsigned_or_writable: bool,
}

/// Risk of one extension: (severity, reason). `before` = rights hash known before (update).
pub fn assess(e: &Extension, malicious: &HashSet<String>, before: Option<&Extension>, helper: Option<&NativeHelper>) -> Option<(Severity, String)> {
    if malicious.contains(&e.id.to_lowercase()) {
        return Some((Severity::Kritisch, t!("steht auf der Liste bekannter Schad-Erweiterungen (MalExt Sentry)", "is on the list of known malicious extensions (MalExt Sentry)").into()));
    }
    let broad = e.broad_hosts();
    let sensitive: Vec<&str> = SENSITIVE.iter().copied().filter(|p| e.has(p)).collect();
    let critical = CRITICAL.iter().any(|p| e.has(p));
    let mut sev = match (e.source, broad && !sensitive.is_empty()) {
        (Source::Policy, _) if !e.update_url.is_empty() && !is_store_url(&e.update_url) => Severity::Kritisch,
        (Source::Policy, _) => Severity::Hoch,
        (Source::Outside, true) => Severity::Hoch,
        (Source::Outside, false) => Severity::Mittel,
        (Source::Store, true) => Severity::Mittel,
        (Source::Store, false) => Severity::Info,
    };
    // Update with new rights: escalation to dangerous rights is critical.
    if let Some(old) = before {
        let new_critical = CRITICAL.iter().any(|p| e.has(p) && !old.has(p));
        if new_critical && broad {
            sev = Severity::Kritisch;
        } else if broad && !old.broad_hosts() {
            sev = sev.max(Severity::Hoch);
        }
    }
    // A native helper that is unsigned or lies in a user folder.
    if e.has("nativeMessaging") && helper.is_some_and(|h| h.unsigned_or_writable) {
        sev = raise(sev);
    }
    let why = match e.source {
        Source::Policy => t!("wird per Richtlinie erzwungen", "is forced by a policy").to_string(),
        Source::Outside => t!("wurde außerhalb des offiziellen Stores installiert", "was installed outside the official store").to_string(),
        Source::Store => t!("aus dem offiziellen Store", "from the official store").to_string(),
    };
    let rights = if broad {
        tf!("darf alle Webseiten lesen und ändern{}", "may read and change all websites{}", if sensitive.is_empty() { String::new() } else { format!(" ({})", sensitive.join(", ")) })
    } else if critical {
        tf!("hat weitreichende Rechte ({})", "has far-reaching permissions ({})", sensitive.join(", "))
    } else {
        t!("hat eingeschränkte Rechte", "has limited permissions").into()
    };
    Some((sev, format!("{why}, {rights}")))
}

fn raise(s: Severity) -> Severity {
    match s {
        Severity::Info => Severity::Niedrig,
        Severity::Niedrig => Severity::Mittel,
        Severity::Mittel => Severity::Hoch,
        _ => Severity::Kritisch,
    }
}

fn browser_name(id: &str) -> &'static str {
    BROWSERS.iter().find(|b| b.id == id).map(|b| b.name).unwrap_or("Browser")
}

/// How to remove it (in the browser; policies need admin rights).
fn removal_hint(e: &Extension) -> String {
    let page = match e.browser {
        "edge" => "edge://extensions",
        "brave" => "brave://extensions",
        "vivaldi" => "vivaldi://extensions",
        "opera" => "opera://extensions",
        "firefox" => "about:addons",
        _ => "chrome://extensions",
    };
    if e.source == Source::Policy {
        format!("Erzwungen per Richtlinie – im Browser nicht entfernbar. Hast du das nicht selbst eingerichtet, Richtlinie in der Registry entfernen (Administratorrechte, Anleitung Kapitel „Browser-Erweiterungen“). Prüfen: {page}")
    } else {
        tf!("Kennst du die Erweiterung nicht: im Browser {page} öffnen und „Entfernen“. Nichts wurde automatisch geändert.", "If you do not know the extension: open {page} in the browser and “Remove”. Nothing was changed automatically.")
    }
}

pub fn finding(e: &Extension, severity: Severity, why: &str) -> Finding {
    let name = if e.name.is_empty() { e.id.clone() } else { e.name.clone() };
    Finding {
        path: PathBuf::from(tf!("{} ({}, Profil {}): {}", "{} ({}, profile {}): {}", name, browser_name(e.browser), e.profile, e.id)),
        sha256: crate::sha256_hex(format!("ext|{}|{}|{}", e.browser, e.id, e.rights_hash()).as_bytes()),
        size: 0,
        rule_id: format!("ERWEITERUNG:{}", e.browser.to_uppercase()),
        threat_name: tf!("Browser-Erweiterung „{name}“ {why}", "Browser extension “{name}” {why}"),
        category: t!("Browser-Erweiterung", "Browser extension").into(),
        severity,
        engine: "erweiterungen".into(),
        kind: Kind::Erweiterung,
        details: Some(serde_json::json!({
            "browser": browser_name(e.browser), "profil": e.profile, "id": e.id, "version": e.version,
            "quelle": format!("{:?}", e.source), "update_url": e.update_url,
            "rechte": e.permissions.iter().cloned().collect::<Vec<_>>(), "seiten": e.hosts.iter().cloned().collect::<Vec<_>>(),
            "hinweis": removal_hint(e),
        })),
    }
}

/// Finding for an install instruction in the registry (policy or external install).
pub fn forced_finding(f: &ForcedInstall, malicious: &HashSet<String>) -> Option<Finding> {
    let local = Path::new(&f.source).is_absolute() || f.source.to_lowercase().starts_with("file:");
    let store = is_store_url(&f.source);
    // A key without any values installs nothing (left behind or prepared by a program).
    let empty = !f.policy && f.values.is_empty();
    let severity = if malicious.contains(&f.id.to_lowercase()) || (f.policy && !store) {
        Severity::Kritisch
    } else if empty {
        Severity::Info
    } else if local || !store || f.policy {
        Severity::Hoch
    } else {
        return None; // registry install of a store extension (e.g. by a known program): inventory only
    };
    let what = if f.policy { t!("Richtlinie erzwingt", "A policy forces") } else { t!("Registry-Eintrag installiert", "A registry entry installs") };
    Some(Finding {
        path: PathBuf::from(format!("{} ({})", f.location, f.id)),
        sha256: crate::sha256_hex(format!("ext-reg|{}|{}|{}|{}", f.location.to_lowercase(), f.id, f.source, f.values).as_bytes()),
        size: 0,
        rule_id: if f.policy { "ERWEITERUNG:RICHTLINIE".into() } else { "ERWEITERUNG:REGISTRY".into() },
        threat_name: if empty {
            tf!("Leerer Registry-Eintrag für die Browser-Erweiterung {} in {} (installiert nichts)", "Empty registry entry for the browser extension {} in {} (installs nothing)", f.id, browser_name(f.browser))
        } else {
            tf!("{what} die Browser-Erweiterung {} in {} (Quelle: {})", "{what} the browser extension {} in {} (source: {})", f.id, browser_name(f.browser), if f.source.is_empty() { "?" } else { &f.source })
        },
        category: t!("Browser-Erweiterung", "Browser extension").into(),
        severity,
        engine: "erweiterungen".into(),
        kind: Kind::Erweiterung,
        details: Some(serde_json::json!({
            "browser": browser_name(f.browser), "id": f.id, "quelle": f.source, "schluessel": f.location,
            "hinweis": t!("Typischer Weg von Adware, sich festzusetzen. Hast du das nicht selbst eingerichtet: Schlüssel in der Registry entfernen (Administratorrechte, Anleitung Kapitel „Browser-Erweiterungen“). Nichts wurde automatisch geändert.", "A typical way for adware to settle in. If you did not set this up yourself: remove the key in the registry (administrator rights, guide chapter “Browser-Erweiterungen”). Nothing was changed automatically."),
        })),
    })
}

/// Browser shortcuts with suspicious arguments (e.g. `--load-extension`, ChromeLoader).
pub fn suspicious_shortcut_args(target: &Path, args: &str) -> Option<&'static str> {
    let exe = target.file_name()?.to_string_lossy().to_lowercase();
    if !["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "firefox.exe"].contains(&exe.as_str()) {
        return None;
    }
    let a = args.to_lowercase();
    if a.contains("--load-extension") {
        Some(t!("lädt beim Start eine Erweiterung aus einem Ordner (--load-extension)", "loads an extension from a folder at start (--load-extension)"))
    } else if a.contains("--remote-debugging") {
        Some(t!("startet den Browser fernsteuerbar (--remote-debugging)", "starts the browser remote-controllable (--remote-debugging)"))
    } else if a.contains("--disable-extensions-except") {
        Some(t!("schaltet alle Erweiterungen außer einer ab (--disable-extensions-except)", "switches off all extensions except one (--disable-extensions-except)"))
    } else {
        None
    }
}

/// Folders with shortcuts to check: desktop (user and public), Start menu, pinned taskbar.
pub fn shortcut_folders() -> Vec<PathBuf> {
    let env = crate::paths::user_dir;
    let mut out = Vec::new();
    if let Some(p) = env("USERPROFILE") {
        out.push(p.join("Desktop"));
    }
    if let Some(p) = env("PUBLIC") {
        out.push(p.join("Desktop"));
    }
    if let Some(p) = env("APPDATA") {
        out.push(p.join("Microsoft\\Windows\\Start Menu\\Programs"));
        out.push(p.join("Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar"));
    }
    if let Some(p) = env("ProgramData") {
        out.push(p.join("Microsoft\\Windows\\Start Menu\\Programs"));
    }
    out
}

pub fn shortcut_finding(link: &Path, target: &Path, args: &str, why: &str) -> Finding {
    Finding {
        path: link.to_path_buf(),
        sha256: crate::sha256_hex(format!("ext-lnk|{}|{}|{}", link.display(), target.display(), args).to_lowercase().as_bytes()),
        size: 0,
        rule_id: "ERWEITERUNG:VERKNUEPFUNG".into(),
        threat_name: tf!("Browser-Verknüpfung {why}", "Browser shortcut {why}"),
        category: t!("Browser-Erweiterung", "Browser extension").into(),
        severity: Severity::Hoch,
        engine: "erweiterungen".into(),
        kind: Kind::Erweiterung,
        details: Some(serde_json::json!({
            "ziel": target.display().to_string(), "befehl": args,
            "hinweis": t!("So setzt sich Adware wie „ChromeLoader“ fest. Verknüpfung löschen und neu anlegen (Rechtsklick auf die Browser-Datei → Verknüpfung erstellen). Nichts wurde automatisch geändert.", "This is how adware like “ChromeLoader” settles in. Delete the shortcut and create it again (right-click the browser file → Create shortcut). Nothing was changed automatically."),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(source: Source, perms: &[&str], hosts: &[&str]) -> Extension {
        Extension {
            browser: "chrome",
            profile: "Default".into(),
            id: "a".repeat(32),
            name: "Test".into(),
            version: "1".into(),
            source,
            update_url: String::new(),
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            enabled: true,
        }
    }

    #[test]
    fn chromium_profile_is_read_from_prefs_and_manifest() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let id = "abcdefghijklmnopabcdefghijklmnop";
        let vdir = dir.path().join("Extensions").join(id).join("1.2_0");
        std::fs::create_dir_all(vdir.join("_locales").join("de")).unwrap();
        std::fs::write(
            vdir.join("manifest.json"),
            r#"{"name":"__MSG_appName__","default_locale":"de","version":"1.2","permissions":["cookies","tabs","https://*/*"],"content_scripts":[{"matches":["<all_urls>"]}]}"#,
        )
        .unwrap();
        std::fs::write(vdir.join("_locales").join("de").join("messages.json"), r#"{"appName":{"message":"Spar-Helfer"}}"#).unwrap();
        let prefs = serde_json::json!({ "extensions": { "settings": {
            id: { "location": 1, "from_webstore": false, "state": 1 },
            "mhjfbmdgcfjbbpaeojofohoefgiehjai": { "location": 5 }
        }}});
        let list = chromium_profile("chrome", "Default", &[prefs], dir.path());
        assert_eq!(list.len(), 1, "Komponenten-Erweiterungen zählen nicht");
        let e = &list[0];
        assert_eq!(e.name, "Spar-Helfer");
        assert_eq!(e.source, Source::Outside, "nicht aus dem Store");
        assert!(e.broad_hosts() && e.permissions.contains("cookies") && !e.permissions.contains("https://*/*"));
        assert_eq!(assess(e, &HashSet::new(), None, None).unwrap().0, Severity::Hoch);
    }

    #[test]
    fn risk_levels() {
        let none = HashSet::new();
        assert_eq!(assess(&ext(Source::Store, &["storage"], &[]), &none, None, None).unwrap().0, Severity::Info);
        assert_eq!(assess(&ext(Source::Store, &["cookies"], &["<all_urls>"]), &none, None, None).unwrap().0, Severity::Mittel);
        assert_eq!(assess(&ext(Source::Outside, &["storage"], &[]), &none, None, None).unwrap().0, Severity::Mittel);
        let mut forced = ext(Source::Policy, &[], &[]);
        forced.update_url = "https://evil.example/update.xml".into();
        assert_eq!(assess(&forced, &none, None, None).unwrap().0, Severity::Kritisch);
        forced.update_url = "https://clients2.google.com/service/update2/crx".into();
        assert_eq!(assess(&forced, &none, None, None).unwrap().0, Severity::Hoch);
        // On the list: always critical.
        let listed: HashSet<String> = [("a".repeat(32))].into();
        assert_eq!(assess(&ext(Source::Store, &[], &[]), &listed, None, None).unwrap().0, Severity::Kritisch);
        // Update gains debugger + all sites: critical; the rights hash changes.
        let old = ext(Source::Store, &["storage"], &["<all_urls>"]);
        let new = ext(Source::Store, &["storage", "debugger"], &["<all_urls>"]);
        assert_eq!(assess(&new, &none, Some(&old), None).unwrap().0, Severity::Kritisch);
        assert_ne!(old.rights_hash(), new.rights_hash());
        // Native helper unsigned / in a user folder: one level up.
        let nm = ext(Source::Store, &["nativeMessaging"], &[]);
        assert_eq!(assess(&nm, &none, None, Some(&NativeHelper { unsigned_or_writable: true })).unwrap().0, Severity::Niedrig);
    }

    #[test]
    fn registry_installs_and_lists() {
        assert_eq!(parse_forcelist("abc;https://x/u.xml"), ("abc".into(), "https://x/u.xml".into()));
        let s = parse_extension_settings(r#"{"*":{"installation_mode":"allowed"},"abc":{"installation_mode":"force_installed","update_url":"https://evil/u"}}"#);
        assert_eq!(s, vec![("abc".to_string(), "https://evil/u".to_string())]);
        let none = HashSet::new();
        let f = |policy: bool, src: &str| ForcedInstall { browser: "chrome", id: "a".repeat(32), source: src.into(), location: "HKLM\\x".into(), policy, values: format!("update_url={src}") };
        assert_eq!(forced_finding(&f(true, "https://evil/u"), &none).unwrap().severity, Severity::Kritisch);
        assert_eq!(forced_finding(&f(false, r"C:\Users\f\AppData\Local\ext.crx"), &none).unwrap().severity, Severity::Hoch);
        assert!(forced_finding(&f(false, "https://clients2.google.com/service/update2/crx"), &none).is_none());
        let ids = parse_malicious("abcdefghijklmnopabcdefghijklmnop,ZZZ,abcdefghijklmnopabcdefghijklmnoq\nnot-an-id");
        assert_eq!(ids.len(), 1, "nur gültige IDs (a–p, 32 Zeichen)");
    }

    #[test]
    fn suspicious_browser_shortcuts() {
        let chrome = Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        assert!(suspicious_shortcut_args(chrome, r"--load-extension=C:\Users\f\AppData\Local\x").is_some());
        assert!(suspicious_shortcut_args(chrome, "--profile-directory=Default").is_none());
        assert!(suspicious_shortcut_args(Path::new(r"C:\Tools\app.exe"), "--load-extension=x").is_none());
    }

    #[test]
    fn empty_registry_key_is_only_info_and_values_make_a_new_finding() {
        let none = HashSet::new();
        let empty = ForcedInstall { browser: "chrome", id: "b".repeat(32), source: String::new(), location: "HKCU\\x".into(), policy: false, values: String::new() };
        let a = forced_finding(&empty, &none).unwrap();
        assert_eq!(a.severity, Severity::Info);
        // Values appear later: different fingerprint, normal level (an earlier "Gesehen" does not cover it).
        let filled = ForcedInstall { source: r"C:\Users\x\boese.crx".into(), values: r"path=C:\Users\x\boese.crx;version=1".into(), ..empty };
        let b = forced_finding(&filled, &none).unwrap();
        assert_eq!(b.severity, Severity::Hoch);
        assert_ne!(a.sha256, b.sha256);
    }

    #[test]
    fn only_mozillas_own_add_ons_count_as_built_in() {
        let v = serde_json::json!({ "addons": [
            { "id": "webcompat@mozilla.org", "type": "extension", "location": "app-builtin-addons" },
            { "id": "addons-search-detection@mozilla.com", "type": "extension", "location": "app-builtin" },
            { "id": "ipp-activator@mozilla.com", "type": "extension", "location": "app-system-defaults" },
            { "id": "fremd@werbung.example", "type": "extension", "location": "app-builtin-addons", "signedState": 0 },
            { "id": "adware@mozilla.org", "type": "extension", "location": "app-system-local", "signedState": 0 },
            { "id": "google@search.mozilla.org", "type": "extension", "location": "app-builtin" },
            { "id": "x@evilmozilla.org", "type": "extension", "location": "app-builtin", "signedState": 0 },
            { "id": "x@search.mozilla.org.evil", "type": "extension", "location": "app-builtin", "signedState": 0 },
            { "id": "x@y", "type": "extension", "location": "app-system-user", "signedState": 0 },
            { "id": "z@y", "type": "extension", "location": "app-system-share", "signedState": 0 }
        ]});
        let ids: Vec<String> = firefox_profile("p", &v).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["fremd@werbung.example", "adware@mozilla.org", "x@evilmozilla.org", "x@search.mozilla.org.evil", "x@y", "z@y"]);
    }

    #[test]
    fn only_folders_are_profiles() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        std::fs::write(dir.path().join("Local State"), b"{}").unwrap();
        std::fs::create_dir_all(dir.path().join("Default")).unwrap();
        std::fs::create_dir_all(dir.path().join("Profile 1")).unwrap();
        let mut names: Vec<String> = profile_dirs(dir.path()).iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["Default", "Profile 1"]);
    }

    #[test]
    fn firefox_profile_is_read() {
        let v = serde_json::json!({ "addons": [
            { "id": "a@b", "type": "extension", "location": "app-profile", "sourceURI": "https://addons.mozilla.org/x.xpi",
              "signedState": 2, "version": "1", "defaultLocale": {"name": "Gut"}, "userPermissions": {"permissions": ["tabs"], "origins": []} },
            { "id": "sys@mozilla.org", "type": "extension", "location": "app-system-defaults" },
            { "id": "c@d", "type": "extension", "location": "app-profile", "signedState": 0, "version": "1",
              "userPermissions": {"permissions": ["cookies"], "origins": ["<all_urls>"]} }
        ]});
        let l = firefox_profile("p", &v);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].source, Source::Store);
        assert_eq!(l[1].source, Source::Outside);
    }
}
