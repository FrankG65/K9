//! Security check ("Sicherheits-Check" in the dashboard): a traffic light for the basic
//! protection of the PC – virus protection, firewall, Windows updates, Secure Boot, user
//! account control, remote desktop, memory integrity, the last backup and outdated programs.
//! Read only: K9 changes none of these settings; each point says what to do.
//! The agent runs it every 6 hours (never while a game runs), `winget` at most once a day.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::winreg::{read_dword, HKLM};

pub const FILE: &str = "sicherheitscheck.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Ampel {
    Gruen,
    Grau,
    Gelb,
    Rot,
}

impl Ampel {
    pub fn label(self) -> &'static str {
        match self {
            Ampel::Gruen => t!("in Ordnung", "fine"),
            Ampel::Gelb => t!("prüfen", "check"),
            Ampel::Rot => t!("handeln", "act"),
            Ampel::Grau => t!("unbekannt", "unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Punkt {
    pub name: String,
    pub ampel: Ampel,
    pub text: String,
    /// What to do (empty when green).
    pub tipp: String,
}

fn punkt(name: &str, ampel: Ampel, text: impl Into<String>, tipp: impl Into<String>) -> Punkt {
    Punkt { name: name.into(), ampel, text: text.into(), tipp: if ampel == Ampel::Gruen { String::new() } else { tipp.into() } }
}

/// A program with a newer version (from `winget upgrade`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Update {
    pub name: String,
    pub id: String,
    pub installiert: String,
    pub verfuegbar: String,
    /// Why the last attempt in the dashboard failed (shown in the row).
    #[serde(default)]
    pub hinweis: String,
    /// Official page of the program from the winget catalogue (https), offered after a failure.
    #[serde(default)]
    pub seite: String,
    /// Day ("18.11.2026") since which updating this version fails.
    #[serde(default)]
    pub fehler_seit: String,
}

impl Update {
    pub fn command(&self) -> String {
        format!("winget upgrade --id {} -e", self.id)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Bericht {
    /// Local time of the check ("YYYY-MM-DD HH:MM:SS").
    pub zeit: String,
    pub punkte: Vec<Punkt>,
    /// Outdated programs (None: winget not available or not checked yet).
    pub updates: Option<Vec<Update>>,
    pub updates_zeit: Option<String>,
    /// Newest file seen in the backup folders and when it was seen (drive may be unplugged).
    pub sicherung_zuletzt: Option<String>,
    /// Results of updates/uninstalls started in the dashboard (newest first, at most 10).
    #[serde(default)]
    pub aktionen: Vec<String>,
    /// "id|version" of updates winget lists but can't install on this PC ("not applicable"):
    /// taken off the list until a newer version appears.
    #[serde(default)]
    pub nicht_moeglich: Vec<String>,
    /// Language of the texts ("de"/"en"; empty in reports of older versions = German).
    #[serde(default)]
    pub sprache: String,
}

impl Bericht {
    /// Takes a fresh winget list (without the updates known to be impossible here).
    pub fn set_updates(&mut self, mut list: Vec<Update>) {
        list.retain(|u| !self.nicht_moeglich.contains(&format!("{}|{}", u.id, u.verfuegbar)));
        // Failure notes stay with the same program and version across the daily check.
        for u in &mut list {
            if let Some(old) = self.updates.iter().flatten().find(|o| o.id == u.id && o.verfuegbar == u.verfuegbar) {
                (u.hinweis, u.seite, u.fehler_seit) = (old.hinweis.clone(), old.seite.clone(), old.fehler_seit.clone());
            }
        }
        self.updates = Some(list);
        self.updates_zeit = Some(self.zeit.clone());
        if let Some(p) = self.punkte.iter_mut().find(|p| is_program_updates(&p.name)) {
            *p = assess_programs(self.updates.as_deref());
        }
    }
}

/// winget: "a newer version exists, but it does not apply to this system".
const NOT_APPLICABLE: i32 = 0x8A15_002Bu32 as i32;

/// Console text of winget: UTF-8, else the German characters of the OEM code page 850.
fn console_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b
            .iter()
            .map(|c| match c {
                0x81 => 'ü',
                0x84 => 'ä',
                0x94 => 'ö',
                0x8E => 'Ä',
                0x99 => 'Ö',
                0x9A => 'Ü',
                0xE1 => 'ß',
                c if c.is_ascii() => *c as char,
                _ => '?',
            })
            .collect(),
    }
}

impl Bericht {
    pub fn worst(&self) -> Ampel {
        self.punkte.iter().map(|p| p.ampel).filter(|a| *a != Ampel::Grau).max().unwrap_or(Ampel::Grau)
    }

    pub fn load(dir: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(dir.join(FILE)).ok()?).ok()
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::write(dir.join(FILE), serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Hours since the check (None: never).
    pub fn age_hours(&self) -> Option<i64> {
        age_hours(&self.zeit)
    }
}

fn age_hours(t: &str) -> Option<i64> {
    let t = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").ok()?;
    Some((chrono::Local::now().naive_local() - t).num_hours())
}

// ------------------------------------------------------------------ the points

/// Name of the point about outdated programs (in both languages: a stored report keeps the
/// language it was written in).
pub fn is_program_updates(name: &str) -> bool {
    name == "Programm-Updates" || name == "Program updates"
}

fn n_antivirus() -> &'static str {
    t!("Virenschutz", "Antivirus")
}
fn n_updates() -> &'static str {
    t!("Windows-Updates", "Windows updates")
}
fn n_backup() -> &'static str {
    t!("Datensicherung", "Backup")
}
fn n_lsa() -> &'static str {
    t!("Lokale Sicherheitsautorität", "LSA protection")
}
fn n_programs() -> &'static str {
    t!("Programm-Updates", "Program updates")
}
fn n_uac() -> &'static str {
    t!("Benutzerkontensteuerung", "User Account Control")
}
fn n_rdp() -> &'static str {
    t!("Remotedesktop", "Remote Desktop")
}
fn n_hvci() -> &'static str {
    t!("Speicherintegrität", "Memory integrity")
}
fn on() -> &'static str {
    t!("an", "on")
}
fn off() -> &'static str {
    t!("aus", "off")
}
fn unreadable() -> &'static str {
    t!("nicht lesbar", "cannot be read")
}

/// Virus protection from the Windows Security Center (productState: bits 12–15 on/off,
/// bits 4–7 signatures up to date = 0).
pub fn assess_antivirus(products: &[(String, u32)]) -> Punkt {
    if products.is_empty() {
        return punkt(n_antivirus(), Ampel::Grau, t!("Windows-Sicherheitscenter nicht lesbar", "Windows Security Center cannot be read"), "");
    }
    let on: Vec<&(String, u32)> = products.iter().filter(|(_, s)| (s >> 12) & 0xF == 1).collect();
    let names = |l: &[&(String, u32)]| {
        let mut n: Vec<&str> = Vec::new();
        for (x, _) in l {
            if !n.contains(&x.as_str()) {
                n.push(x);
            }
        }
        n.join(", ")
    };
    match on.as_slice() {
        [] => punkt(
            n_antivirus(),
            Ampel::Rot,
            t!("kein Virenschutz eingeschaltet", "no antivirus is switched on"),
            t!(
                "Trend Micro öffnen und den Echtzeitschutz einschalten (oder Windows Defender wieder einschalten).",
                "Open your antivirus and switch real-time protection on (or switch Windows Defender on again)."
            ),
        ),
        list if list.iter().any(|(_, s)| (s >> 4) & 0xF != 0) => punkt(
            n_antivirus(),
            Ampel::Gelb,
            tf!("{} an, aber Virendefinitionen nicht aktuell", "{} on, but virus definitions are out of date", names(list)),
            t!("Im Virenschutz „Aktualisieren“ wählen und die Internetverbindung prüfen.", "Choose “Update” in the antivirus and check the internet connection."),
        ),
        list => punkt(n_antivirus(), Ampel::Gruen, tf!("{} an und aktuell", "{} on and up to date", names(list)), ""),
    }
}

/// Windows firewall profiles (private, public) or another firewall in the Security Center.
pub fn assess_firewall(private: Option<bool>, public: Option<bool>, other: &[(String, u32)]) -> Punkt {
    let other_on: Vec<&str> = other.iter().filter(|(_, s)| (s >> 12) & 0xF == 1).map(|(n, _)| n.as_str()).collect();
    match (private, public) {
        (Some(true), Some(true)) => punkt("Firewall", Ampel::Gruen, t!("Windows-Firewall an (privates und öffentliches Netz)", "Windows Firewall on (private and public network)"), ""),
        _ if !other_on.is_empty() => punkt("Firewall", Ampel::Gruen, tf!("{} an", "{} on", other_on.join(", ")), ""),
        (None, None) => punkt("Firewall", Ampel::Grau, t!("Zustand nicht lesbar", "state cannot be read"), ""),
        (_, Some(false)) => punkt(
            "Firewall",
            Ampel::Rot,
            t!("Windows-Firewall im öffentlichen Netz aus", "Windows Firewall off in the public network"),
            t!(
                "Windows-Sicherheit → Firewall- & Netzwerkschutz → „Öffentliches Netzwerk“ einschalten.",
                "Windows Security → Firewall & network protection → switch on “Public network”."
            ),
        ),
        _ => punkt(
            "Firewall",
            Ampel::Gelb,
            t!("Windows-Firewall im privaten Netz aus", "Windows Firewall off in the private network"),
            t!(
                "Windows-Sicherheit → Firewall- & Netzwerkschutz → „Privates Netzwerk“ einschalten.",
                "Windows Security → Firewall & network protection → switch on “Private network”."
            ),
        ),
    }
}

/// Days since the newest installed Windows update.
pub fn assess_updates(days: Option<i64>) -> Punkt {
    let tipp = t!(
        "Einstellungen → Windows Update → „Nach Updates suchen“ und danach neu starten.",
        "Settings → Windows Update → “Check for updates”, then restart."
    );
    let ago = |d: i64| tf!("letztes Update vor {d} Tagen", "last update {d} days ago");
    match days {
        None => punkt(n_updates(), Ampel::Grau, t!("Datum des letzten Updates nicht lesbar", "date of the last update cannot be read"), ""),
        Some(d) if d > 60 => punkt(n_updates(), Ampel::Rot, ago(d), tipp),
        Some(d) if d > 35 => punkt(n_updates(), Ampel::Gelb, ago(d), tipp),
        Some(d) => punkt(n_updates(), Ampel::Gruen, ago(d), ""),
    }
}

/// Days since the newest file in the backup folders (None: nothing found / not set up).
/// `present`: at least one of the folders is reachable right now.
pub fn assess_backup(configured: bool, present: bool, days: Option<i64>, seen_at: Option<&str>) -> Punkt {
    let tipp = t!(
        "Externe Platte anschließen und sichern (z. B. Dateiversionsverlauf oder Veeam Agent Free), danach wieder abstecken.",
        "Connect the external drive and back up (e.g. File History or Veeam Agent Free), then unplug it again."
    );
    let when = seen_at.map(|s| tf!(" (zuletzt gesehen {s})", " (last seen {s})")).unwrap_or_default();
    let ago = |d: i64| tf!("letzte Sicherung vor {d} Tagen{when}", "last backup {d} days ago{when}");
    if configured && present && days.is_none() {
        return punkt(
            n_backup(),
            Ampel::Gelb,
            t!(
                "Sicherungsordner ist da, enthält aber noch keine Datei – noch keine Sicherung",
                "the backup folder is there but contains no file yet – no backup so far"
            ),
            t!(
                "K9 sichert nicht selbst. Mit einem Sicherungsprogramm (z. B. Dateiversionsverlauf von Windows oder Veeam Agent Free) in diesen Ordner sichern, danach die Platte wieder abstecken.",
                "K9 does not back up by itself. Back up into this folder with a backup program (e.g. Windows File History or Veeam Agent Free), then unplug the drive again."
            ),
        );
    }
    match (configured, days) {
        (false, _) => punkt(
            n_backup(),
            Ampel::Grau,
            t!("kein Sicherungsordner eingetragen", "no backup folder configured"),
            t!(
                "Sicherungsordner in config.toml unter [sicherheitscheck] eintragen, z. B. sicherung_ordner = ['E:\\Sicherung'] (Teil 3, „Sicherheits-Check“).",
                "Enter the backup folder in config.toml under [sicherheitscheck], e.g. sicherung_ordner = ['E:\\Backup']."
            ),
        ),
        (true, None) => punkt(
            n_backup(),
            Ampel::Gelb,
            t!(
                "Sicherungsordner nicht gefunden (Platte abgesteckt?) und noch nie gesehen",
                "backup folder not found (drive unplugged?) and never seen so far"
            ),
            tipp,
        ),
        (true, Some(d)) if d > 30 => punkt(n_backup(), Ampel::Rot, ago(d), tipp),
        (true, Some(d)) if d > 14 => punkt(n_backup(), Ampel::Gelb, ago(d), tipp),
        (true, Some(d)) => punkt(n_backup(), Ampel::Gruen, ago(d), ""),
    }
}

/// Protection of the local security authority (LSA, the part of Windows that keeps the
/// logins): registry value RunAsPPL, 1 or 2 = on (2 is what the switch in Windows Security
/// sets; read on the test PC on 23.11.2026).
pub fn assess_lsa(run_as_ppl: Option<u32>) -> Punkt {
    match run_as_ppl {
        Some(1) | Some(2) => punkt(n_lsa(), Ampel::Gruen, t!("geschützt", "protected"), ""),
        _ => punkt(
            n_lsa(),
            Ampel::Gelb,
            t!("Schutz aus", "protection off"),
            t!(
                "Windows-Sicherheit → Gerätesicherheit → Kernisolierung → „Schutz durch lokale Sicherheitsautorität“ einschalten, dann neu starten. Schützt Anmeldedaten vor dem Auslesen und kostet keine Leistung.",
                "Windows Security → Device security → Core isolation → switch on “Local Security Authority protection”, then restart. Protects sign-in data from being read out and costs no performance."
            ),
        ),
    }
}

pub fn assess_programs(updates: Option<&[Update]>) -> Punkt {
    match updates {
        None => punkt(n_programs(), Ampel::Grau, t!("noch nicht geprüft (winget)", "not checked yet (winget)"), ""),
        Some([]) => punkt(n_programs(), Ampel::Gruen, t!("alle über winget bekannten Programme aktuell", "all programs known to winget are up to date"), ""),
        Some(list) => punkt(
            n_programs(),
            Ampel::Gelb,
            tf!("{} Programme haben eine neuere Version", "{} programs have a newer version", list.len()),
            t!(
                "Liste unten im Kasten; alle auf einmal (normale PowerShell): winget upgrade --all",
                "List in the box below; all at once (normal PowerShell): winget upgrade --all"
            ),
        ),
    }
}

fn registry_points() -> Vec<Punkt> {
    let mut out = Vec::new();
    out.push(match read_dword(HKLM, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled") {
        Some(1) => punkt("Secure Boot", Ampel::Gruen, on(), ""),
        Some(_) => punkt(
            "Secure Boot",
            Ampel::Gelb,
            off(),
            t!(
                "Im BIOS/UEFI „Secure Boot“ einschalten (schützt vor Schadsoftware, die vor Windows startet).",
                "Switch on “Secure Boot” in the BIOS/UEFI (protects against malware that starts before Windows)."
            ),
        ),
        None => punkt("Secure Boot", Ampel::Grau, t!("nicht lesbar (älteres BIOS?)", "cannot be read (older BIOS?)"), ""),
    });
    let sys = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    let uac_tip = t!(
        "„Benutzerkontensteuerungseinstellungen ändern“ → Regler mindestens auf die zweite Stufe.",
        "“Change User Account Control settings” → slider at least on the second level."
    );
    out.push(match (read_dword(HKLM, sys, "EnableLUA"), read_dword(HKLM, sys, "ConsentPromptBehaviorAdmin")) {
        (Some(0), _) => punkt(n_uac(), Ampel::Rot, off(), uac_tip),
        (_, Some(0)) => punkt(n_uac(), Ampel::Gelb, t!("an, fragt aber nie nach", "on, but never asks"), uac_tip),
        (Some(_), _) => punkt(n_uac(), Ampel::Gruen, on(), ""),
        _ => punkt(n_uac(), Ampel::Grau, unreadable(), ""),
    });
    out.push(match read_dword(HKLM, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections") {
        Some(0) => punkt(
            n_rdp(),
            Ampel::Gelb,
            t!("an – andere können sich anmelden", "on – others can sign in"),
            t!("Brauchst du es nicht: Einstellungen → System → Remotedesktop → aus.", "If you do not need it: Settings → System → Remote Desktop → off."),
        ),
        Some(_) => punkt(n_rdp(), Ampel::Gruen, off(), ""),
        None => punkt(n_rdp(), Ampel::Grau, unreadable(), ""),
    });
    out.push(match read_dword(HKLM, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Enabled") {
        Some(1) => punkt(n_hvci(), Ampel::Gruen, on(), ""),
        _ => punkt(
            n_hvci(),
            Ampel::Gelb,
            off(),
            t!(
                "Mit k9 treiber prüfen, welche Treiber sie blockieren; danach Windows-Sicherheit → Gerätesicherheit → Kernisolierung. Kann ein paar Prozent FPS kosten.",
                "Use k9 treiber to see which drivers block it; then Windows Security → Device security → Core isolation. May cost a few percent of FPS."
            ),
        ),
    });
    out.push(assess_lsa(read_dword(HKLM, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL")));
    out
}

// ------------------------------------------------------------------ reading

fn security_center(class: &str) -> Vec<(String, u32)> {
    let Some(w) = crate::wmi_autostart::Wmi::connect("ROOT\\SecurityCenter2") else { return Vec::new() };
    w.query(&format!("SELECT displayName, productState, pathToSignedProductExe FROM {class}"))
        .unwrap_or_default()
        .into_iter()
        .filter(|o| still_installed(&o.get("pathToSignedProductExe")))
        .filter_map(|o| Some((o.get("displayName"), o.get("productState").parse().ok()?)))
        .collect()
}

/// Uninstalled products often stay registered in the Security Center (with "on"): an entry
/// whose program file is gone does not count. Entries without a file path (Windows Defender:
/// "windowsdefender://") are kept.
pub fn still_installed(exe: &str) -> bool {
    let p = crate::paths::expand_env(exe.trim().trim_matches('"'));
    !(p.len() > 3 && p.as_bytes()[1] == b':') || Path::new(&p).exists()
}

fn firewall_profiles() -> (Option<bool>, Option<bool>) {
    use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, NetFwPolicy2, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
    // SAFETY: plain COM getters; the interface is released when dropped.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let Ok(p): windows::core::Result<INetFwPolicy2> = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) else { return (None, None) };
        (
            p.get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE).ok().map(|b| b.as_bool()),
            p.get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC).ok().map(|b| b.as_bool()),
        )
    }
}

/// "M/D/YYYY" (Win32_QuickFixEngineering.InstalledOn) -> date.
fn qfe_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%m/%d/%Y").ok().or_else(|| chrono::NaiveDate::parse_from_str(s.trim(), "%Y%m%d").ok())
}

fn days_since_windows_update() -> Option<i64> {
    let w = crate::wmi_autostart::Wmi::connect("ROOT\\CIMV2")?;
    let newest = w.query("SELECT InstalledOn FROM Win32_QuickFixEngineering")?.into_iter().filter_map(|o| qfe_date(&o.get("InstalledOn"))).max()?;
    Some((chrono::Local::now().date_naive() - newest).num_days())
}

/// Newest change time in the backup folders (depth 3, at most 20 000 entries – cheap).
pub fn newest_file(folders: &[PathBuf]) -> Option<chrono::NaiveDateTime> {
    let mut newest: Option<std::time::SystemTime> = None;
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, u8)> = folders.iter().filter(|f| f.is_dir()).map(|f| (f.clone(), 0)).collect();
    if stack.is_empty() {
        return None;
    }
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > 20_000 {
                break;
            }
            let Ok(m) = e.metadata() else { continue };
            // Only files count. Windows creates the folders "System Volume Information" and
            // "$RECYCLE.BIN" on every drive by itself: an empty backup drive looked like a
            // backup of today (seen on 22.11.2026 with the new drive J:).
            if m.is_dir() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if depth < 3 && name != "system volume information" && name != "$recycle.bin" {
                    stack.push((e.path(), depth + 1));
                }
            } else if let Ok(t) = m.modified() {
                newest = Some(newest.map_or(t, |n| n.max(t)));
            }
        }
    }
    newest.map(|t| chrono::DateTime::<chrono::Local>::from(t).naive_local())
}

/// The check without winget. `previous`: the last report (keeps the program list and the
/// last time the backup drive was seen).
pub fn check(cfg: &crate::config::SicherheitscheckConfig, previous: Option<&Bericht>) -> Bericht {
    let now = chrono::Local::now().naive_local();
    let mut punkte = vec![assess_antivirus(&security_center("AntiVirusProduct"))];
    let (private, public) = firewall_profiles();
    punkte.push(assess_firewall(private, public, &security_center("FirewallProduct")));
    punkte.push(assess_updates(days_since_windows_update()));
    punkte.extend(registry_points());
    let folders: Vec<PathBuf> = cfg.sicherung_ordner.iter().map(|o| PathBuf::from(crate::paths::expand_env(o))).collect();
    let sicherung_zuletzt = newest_file(&folders)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .or_else(|| previous.and_then(|p| p.sicherung_zuletzt.clone()));
    let days = sicherung_zuletzt.as_deref().and_then(age_hours).map(|h| h / 24);
    let shown = sicherung_zuletzt.as_deref().and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()).map(|t| t.format("%d.%m.%Y").to_string());
    punkte.push(assess_backup(!folders.is_empty(), folders.iter().any(|f| f.is_dir()), days, shown.as_deref()));
    let updates = previous.and_then(|p| p.updates.clone());
    punkte.push(assess_programs(updates.as_deref()));
    Bericht {
        zeit: now.format("%Y-%m-%d %H:%M:%S").to_string(),
        punkte,
        updates,
        updates_zeit: previous.and_then(|p| p.updates_zeit.clone()),
        sicherung_zuletzt,
        aktionen: previous.map(|p| p.aktionen.clone()).unwrap_or_default(),
        nicht_moeglich: previous.map(|p| p.nicht_moeglich.clone()).unwrap_or_default(),
        sprache: crate::sprache::code().into(),
    }
}

impl Bericht {
    /// Written in the language that is active now (else it is checked again at once).
    pub fn fits_language(&self) -> bool {
        let lang = if self.sprache.is_empty() { "de" } else { self.sprache.as_str() };
        lang == crate::sprache::code()
    }
}

// ------------------------------------------------- update / uninstall on the user's click

/// What the dashboard may do with a program of the list (only after the user's click and
/// "Ja" in the confirmation window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgrammAktion {
    Aktualisieren,
    Deinstallieren,
    /// Start an installer the user downloaded himself (checked, see `nachladen`).
    Installieren,
    /// Search the official page for the installer and load it into Downloads (starts nothing).
    Laden,
    /// Like `Installieren`, but without windows (switches of the installer kit).
    StillInstallieren,
}

impl ProgrammAktion {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "aktualisieren" => Some(Self::Aktualisieren),
            "deinstallieren" => Some(Self::Deinstallieren),
            "installieren" => Some(Self::Installieren),
            "laden" => Some(Self::Laden),
            "still" => Some(Self::StillInstallieren),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aktualisieren => "aktualisieren",
            Self::Deinstallieren => "deinstallieren",
            Self::Installieren => "installieren",
            Self::Laden => "laden",
            Self::StillInstallieren => "still",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Aktualisieren => t!("Aktualisieren", "Update"),
            Self::Deinstallieren => t!("Deinstallieren", "Uninstall"),
            Self::Installieren => t!("Installieren", "Install"),
            Self::Laden => t!("Suchen und Laden", "Search and download"),
            Self::StillInstallieren => t!("Still installieren", "Install silently"),
        }
    }
}

/// A winget package id as winget writes it (no spaces, no quotes, no options).
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.starts_with('-') && id.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

/// Programs that are never uninstalled from the dashboard: the virus protection and K9 itself.
pub fn protected_program(u: &Update) -> bool {
    let n = format!("{} {}", u.name, u.id).to_lowercase();
    n.contains("trend micro") || n.contains("trendmicro") || u.id.eq_ignore_ascii_case("k9")
}

/// Runs winget for one package of the list (blocking, minutes possible). Installers may show
/// their own window or ask for administrator rights (UAC). Returns (ok, short text, "winget
/// can't install this update on this PC").
pub fn run_program_action(a: ProgrammAktion, u: &Update) -> (bool, String, bool) {
    if !valid_id(&u.id) {
        return (false, format!("ungültige Paket-ID {}", u.id), false);
    }
    let verb = match a {
        ProgrammAktion::Aktualisieren => "upgrade",
        ProgrammAktion::Deinstallieren => "uninstall",
        ProgrammAktion::Installieren | ProgrammAktion::Laden | ProgrammAktion::StillInstallieren => return (false, "nicht über winget".into(), false),
    };
    let mut args: Vec<String> = vec![verb.into(), "--id".into(), u.id.clone(), "-e".into()];
    args.extend(["--accept-source-agreements".into(), "--disable-interactivity".into()]);
    if a == ProgrammAktion::Aktualisieren {
        args.push("--accept-package-agreements".into());
    }
    CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
    let out = run_watched(&args, &u.id);
    match out {
        Err(e) => (false, e, false),
        Ok(o) => {
            let text = console_text(&o.stdout);
            let last = text
                .lines()
                .map(|l| l.rsplit('\r').next().unwrap_or(l).trim())
                .rfind(|l| l.len() > 3 && !l.chars().all(|c| "-\\|/█▒ ".contains(c)))
                .unwrap_or("")
                .chars()
                .take(200)
                .collect::<String>();
            (o.status.success(), last, o.status.code() == Some(NOT_APPLICABLE))
        }
    }
}

/// Set by "Abbrechen" in the dashboard: ends the winget run in progress.
pub static CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Did winget fail because the package can only be installed with administrator rights?
/// (0x80073D28, "The package installation failed because administrator privileges are required".)
pub fn needs_admin(output: &str) -> bool {
    let o = output.to_lowercase();
    o.contains("0x80073d28") || o.contains("administrator privileges are required")
}

/// What the user can do when the elevated start did not work: the same command in an
/// elevated console.
pub fn admin_hint(id: &str) -> String {
    tf!("Von Hand geht es so: Rechtsklick auf das Startmenü, „Terminal (Administrator)“ öffnen und eingeben: winget upgrade --id {id} -e", "By hand it works like this: right-click the Start menu, open “Terminal (Admin)” and enter: winget upgrade --id {id} -e")
}

/// How the start of winget with administrator rights ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erhoeht {
    /// winget ran; its exit code (0: done).
    Code(u32),
    /// The user did not confirm Windows' question (or it timed out).
    Abgelehnt,
    /// Windows could not start winget.
    Fehler(String),
    /// winget was still running after 30 minutes.
    Zeit,
}

/// Parameters of the elevated winget run (the same as without administrator rights).
fn elevated_params(id: &str) -> String {
    format!("upgrade --id {id} -e --accept-source-agreements --accept-package-agreements --disable-interactivity")
}

/// Result line for the dashboard after the elevated run.
pub fn elevated_result(r: &Erhoeht, id: &str) -> (bool, String) {
    let needs = t!("Dieses Programm lässt sich nur mit Administratorrechten aktualisieren.", "This program can only be updated with administrator rights.");
    match r {
        Erhoeht::Code(0) => (true, t!("mit Administratorrechten aktualisiert", "updated with administrator rights").into()),
        Erhoeht::Code(c) => (false, tf!("{needs} Auch mit Administratorrechten meldete winget einen Fehler (Code 0x{c:08X}). {}", "{needs} winget reported an error with administrator rights as well (code 0x{c:08X}). {}", admin_hint(id))),
        Erhoeht::Abgelehnt => (
            false,
            tf!("{needs} Die Windows-Abfrage dazu wurde nicht mit „Ja“ bestätigt. Noch einmal „Aktualisieren“ wählen und im Fenster von Windows „Ja“ wählen. {}", "{needs} The Windows question for it was not confirmed with “Yes”. Choose “Update” again and choose “Yes” in the window of Windows. {}", admin_hint(id)),
        ),
        Erhoeht::Fehler(e) => (false, tf!("{needs} Windows konnte winget nicht mit Administratorrechten starten ({e}). {}", "{needs} Windows could not start winget with administrator rights ({e}). {}", admin_hint(id))),
        Erhoeht::Zeit => (false, tf!("{needs} winget lief mit Administratorrechten nach 30 Minuten immer noch; K9 wartet nicht länger. Sieh im Fenster von winget nach.", "{needs} winget was still running with administrator rights after 30 minutes; K9 does not wait any longer. Have a look at the winget window.")),
    }
}

/// Updates a package with administrator rights: starts winget through Windows' own question
/// (user account control). K9 never sees a password - Windows asks in its own window: "Ja" for
/// an administrator account, the password of an administrator for any other account.
/// Blocking; winget shows its console window with the progress.
pub fn run_upgrade_elevated(u: &Update) -> (bool, String) {
    if !valid_id(&u.id) {
        return (false, format!("ungültige Paket-ID {}", u.id));
    }
    elevated_result(&run_elevated("winget.exe", &elevated_params(&u.id)), &u.id)
}

fn run_elevated(file: &str, params: &str) -> Erhoeht {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (verb, f, p) = (wide("runas"), wide(file), wide(params));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(f.as_ptr()),
        lpParameters: PCWSTR(p.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: all strings live until the call returns; the process handle is closed below.
    unsafe {
        if let Err(e) = ShellExecuteExW(&mut info) {
            return if e.code() == ERROR_CANCELLED.to_hresult() { Erhoeht::Abgelehnt } else { Erhoeht::Fehler(e.message()) };
        }
        if info.hProcess.is_invalid() {
            return Erhoeht::Fehler("kein Prozess gestartet".into());
        }
        let waited = WaitForSingleObject(info.hProcess, LIMIT.as_millis() as u32);
        let mut code = 0u32;
        let got = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        if waited == WAIT_TIMEOUT {
            return Erhoeht::Zeit;
        }
        match got {
            Ok(()) => Erhoeht::Code(code),
            Err(e) => Erhoeht::Fehler(e.message()),
        }
    }
}

pub const ABGEBROCHEN: &str = "von dir abgebrochen";
/// winget may work this long on one program.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// A download without any progress for this long is hung (Windows' download service
/// sometimes stops shortly before the end).
const STALL: std::time::Duration = std::time::Duration::from_secs(4 * 60);

/// Newest change in winget's download folder of this package (None: no download yet/any more).
fn download_activity(id: &str) -> Option<std::time::SystemTime> {
    let dir = std::env::temp_dir().join("WinGet");
    let prefix = format!("{}.", id.to_lowercase());
    let mut newest = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if !e.file_name().to_string_lossy().to_lowercase().starts_with(&prefix) {
            continue;
        }
        for f in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
            if let Ok(t) = f.metadata().and_then(|m| m.modified()) {
                newest = Some(newest.map_or(t, |n: std::time::SystemTime| n.max(t)));
            }
        }
    }
    newest
}

/// Runs winget and watches it: "Abbrechen", the time limit and a hung download end it
/// (with its child processes). Err: why it was ended or could not start.
fn run_watched(args: &[String], id: &str) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    let mut child = std::process::Command::new("winget")
        .args(args)
        .creation_flags(0x0800_0000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("winget nicht gestartet: {e}"))?;
    let mut pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let pid = child.id();
    let start = std::time::Instant::now();
    let why = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = reader.join().unwrap_or_default();
                return Ok(std::process::Output { status, stdout, stderr: Vec::new() });
            }
            Ok(None) => {}
            Err(e) => break format!("winget nicht überwachbar: {e}"),
        }
        if CANCEL.swap(false, std::sync::atomic::Ordering::SeqCst) {
            break ABGEBROCHEN.to_string();
        }
        if start.elapsed() > LIMIT {
            break "nach 30 Minuten ohne Ergebnis beendet".to_string();
        }
        // Hung download: the installer has not started (winget has no child process except
        // its console) and the download file has not grown for minutes.
        if start.elapsed() > STALL {
            let busy = crate::realtime::process_snapshot().values().any(|p| p.ppid == pid && !p.name.eq_ignore_ascii_case("conhost.exe"));
            let stalled = download_activity(id).and_then(|t| t.elapsed().ok()).is_some_and(|d| d > STALL);
            if !busy && stalled {
                break "der Download bei winget ist hängen geblieben (seit über 4 Minuten kein Fortschritt) – beendet".to_string();
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    };
    // End winget together with anything it started.
    let _ = std::process::Command::new("taskkill").args(["/PID", &pid.to_string(), "/T", "/F"]).creation_flags(0x0800_0000).output();
    let _ = child.kill();
    let _ = child.wait();
    Err(why)
}

/// Refreshes winget's catalogue (a corrected download address may have been published).
pub fn refresh_winget_sources() {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("winget").args(["source", "update", "--disable-interactivity"]).creation_flags(0x0800_0000).output();
}

/// Official page of a package from the winget catalogue ("Startseite"/"Homepage", else the
/// publisher's address). Only https; the catalogue is reviewed by Microsoft's winget team.
pub fn official_page(id: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    if !valid_id(id) {
        return None;
    }
    let out = std::process::Command::new("winget")
        .args(["show", "--id", id, "-e", "--accept-source-agreements", "--disable-interactivity"])
        .creation_flags(0x0800_0000)
        .output()
        .ok()?;
    parse_official_page(&console_text(&out.stdout))
}

/// Installer addresses of a package from the winget catalogue (https only).
pub fn catalogue_installer_urls(id: &str) -> Vec<String> {
    use std::os::windows::process::CommandExt;
    if !valid_id(id) {
        return Vec::new();
    }
    let out = std::process::Command::new("winget")
        .args(["show", "--id", id, "-e", "--accept-source-agreements", "--disable-interactivity"])
        .creation_flags(0x0800_0000)
        .output();
    out.map(|o| parse_installer_urls(&console_text(&o.stdout))).unwrap_or_default()
}

pub fn parse_installer_urls(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in text.lines().map(|l| l.rsplit('\r').next().unwrap_or(l)) {
        let Some((label, url)) = l.split_once(": ") else { continue };
        let label = label.trim().to_lowercase().replace([' ', '-'], "");
        let url = url.trim();
        if label == "installerurl" && url.starts_with("https://") && url.len() <= 400 && url.chars().all(|c| c.is_ascii_graphic() && !"\"'<>`".contains(c)) && !out.iter().any(|x| x == url) {
            out.push(url.to_string());
        }
    }
    out
}

pub fn parse_official_page(text: &str) -> Option<String> {
    let find = |labels: &[&str]| {
        text.lines().map(|l| l.rsplit('\r').next().unwrap_or(l)).find_map(|l| {
            let (label, url) = l.split_once(": ")?;
            let url = url.trim();
            let ok = labels.iter().any(|x| label.trim().eq_ignore_ascii_case(x))
                && url.starts_with("https://")
                && url.len() <= 300
                && url.chars().all(|c| c.is_ascii_graphic() && !"\"'<>`".contains(c));
            ok.then(|| url.to_string())
        })
    };
    find(&["Startseite", "Homepage"]).or_else(|| find(&["Herausgeber-URL", "Publisher Url"]))
}

/// Result of "Suchen und Laden": stays in the list, the note says what happened.
pub fn note_program_download(dir: &Path, u: &Update, ok: bool, text: &str) {
    let Some(mut b) = Bericht::load(dir) else { return };
    let now = chrono::Local::now().format("%d.%m.%Y %H:%M").to_string();
    let line = if ok { tf!("geladen und geprüft: {text}", "downloaded and checked: {text}") } else { tf!("nicht geladen: {text}", "not downloaded: {text}") };
    b.aktionen.insert(0, tf!("{now} Suchen und Laden {}: {line}", "{now} Search and download {}: {line}", u.name));
    b.aktionen.truncate(10);
    if let Some(x) = b.updates.as_mut().and_then(|l| l.iter_mut().find(|x| x.id == u.id)) {
        if !ok {
            x.hinweis = tf!("Suchen und Laden ({now}) ohne Erfolg: {text}", "Search and download ({now}) without success: {text}");
        }
    }
    let _ = b.save(dir);
}

/// Remembers the official page for a program whose update failed.
pub fn note_program_page(dir: &Path, id: &str, page: &str) {
    let Some(mut b) = Bericht::load(dir) else { return };
    if let Some(x) = b.updates.as_mut().and_then(|l| l.iter_mut().find(|x| x.id == id)) {
        x.seite = page.to_string();
        let _ = b.save(dir);
    }
}

/// Notes the result in the stored report. The program leaves the list on success and when
/// winget can't install the update here at all; another failure is shown in its row.
pub fn note_program_action(dir: &Path, a: ProgrammAktion, u: &Update, ok: bool, text: &str, impossible: bool) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut b) = Bericht::load(dir) else { return };
    let now = chrono::Local::now().format("%d.%m.%Y %H:%M").to_string();
    let result = if ok {
        t!("erledigt", "done")
    } else if impossible {
        t!("nicht möglich – winget kann dieses Update auf deinem PC nicht installieren, aus der Liste genommen (bitte über das Programm selbst oder die Herstellerseite aktualisieren)", "not possible – winget cannot install this update on your PC, removed from the list (please update via the program itself or the publisher's page)")
    } else {
        t!("fehlgeschlagen", "failed")
    };
    b.aktionen.insert(0, format!("{now} {} {}: {result}{}", a.label(), u.name, if text.is_empty() { String::new() } else { format!(" ({text})") }));
    b.aktionen.truncate(10);
    if impossible && !ok {
        b.nicht_moeglich.push(format!("{}|{}", u.id, u.verfuegbar));
        b.nicht_moeglich.dedup();
    }
    if ok || impossible {
        if let Some(list) = b.updates.as_mut() {
            list.retain(|x| x.id != u.id);
        }
        if let Some(p) = b.punkte.iter_mut().find(|p| is_program_updates(&p.name)) {
            *p = assess_programs(b.updates.as_deref());
        }
    } else if let Some(x) = b.updates.as_mut().and_then(|l| l.iter_mut().find(|x| x.id == u.id)) {
        x.hinweis = format!("{} fehlgeschlagen ({now}){}", a.label(), if text.is_empty() { String::new() } else { format!(": {text}") });
        if x.fehler_seit.is_empty() {
            x.fehler_seit = now.split(' ').next().unwrap_or("").to_string();
        }
    }
    let _ = b.save(dir);
}

/// Programs with a newer version according to winget (None: winget missing or failed).
/// Runs with low priority and without a window; it only lists, never installs.
pub fn outdated_programs() -> Option<Vec<Update>> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("winget")
        .args(["upgrade", "--accept-source-agreements", "--disable-interactivity"])
        .creation_flags(0x0800_0000 | 0x0000_4000)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let list = parse_winget_upgrade(&text);
    // No table and no "no updates" line: winget failed (e.g. no network).
    if list.is_empty() && !text.contains("----") {
        return None;
    }
    Some(list)
}

/// Columns start where a header word starts.
fn columns(header: &str) -> Vec<usize> {
    let c: Vec<char> = header.chars().collect();
    (0..c.len()).filter(|&i| !c[i].is_whitespace() && (i == 0 || c[i - 1].is_whitespace())).collect()
}

pub fn parse_winget_upgrade(text: &str) -> Vec<Update> {
    let mut out = Vec::new();
    let mut cols: Option<Vec<usize>> = None;
    for raw in text.lines() {
        let l = raw.rsplit('\r').next().unwrap_or(raw);
        let t = l.trim_start();
        if t.starts_with("Name") && (l.contains(" ID ") || l.contains(" Id ")) {
            cols = Some(columns(l)).filter(|c| c.len() >= 4);
            continue;
        }
        if t.starts_with("---") || t.is_empty() {
            continue;
        }
        let Some(c) = &cols else { continue };
        let ch: Vec<char> = l.chars().collect();
        let cell = |i: usize| -> String {
            let (a, b) = (c[i], c.get(i + 1).copied().unwrap_or(ch.len()));
            if a >= ch.len() {
                return String::new();
            }
            ch[a..b.min(ch.len())].iter().collect::<String>().trim().to_string()
        };
        let (name, id, inst, avail) = (cell(0), cell(1), cell(2), cell(3));
        if name.is_empty() || id.is_empty() || id.contains(' ') || avail.is_empty() || avail.contains(' ') || !id.contains('.') {
            continue;
        }
        out.push(Update { name: name.trim_end_matches('…').trim().to_string(), id, installiert: inst, verfuegbar: avail, hinweis: String::new(), seite: String::new(), fehler_seit: String::new() });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_that_needs_an_administrator_gets_a_german_hint_with_the_command() {
        let out = "Installation fehlgeschlagen mit Exitcode: 0x80073d28 : The package installation failed because administrator privileges are required. Please contact an administrator to install this package.";
        assert!(needs_admin(out));
        assert!(needs_admin("Installer failed with exit code: 0x80073D28"));
        assert!(!needs_admin("Installation fehlgeschlagen mit Exitcode: 0x80072ee7 : keine Verbindung"));
        let hint = admin_hint("Anthropic.Claude");
        assert!(hint.contains("Terminal (Administrator)") && hint.ends_with("winget upgrade --id Anthropic.Claude -e"), "{hint}");
        // Since 0.46.0 K9 starts winget through Windows' own question; these are the results.
        let id = "Anthropic.Claude";
        assert_eq!(elevated_params(id), "upgrade --id Anthropic.Claude -e --accept-source-agreements --accept-package-agreements --disable-interactivity");
        assert_eq!(elevated_result(&Erhoeht::Code(0), id), (true, "mit Administratorrechten aktualisiert".to_string()));
        let (ok, text) = elevated_result(&Erhoeht::Abgelehnt, id);
        assert!(!ok && text.contains("nicht mit „Ja“ bestätigt") && text.ends_with("winget upgrade --id Anthropic.Claude -e"), "{text}");
        let (ok, text) = elevated_result(&Erhoeht::Code(0x8A15_002B), id);
        assert!(!ok && text.contains("Code 0x8A15002B") && text.contains("Terminal (Administrator)"), "{text}");
        let (ok, text) = elevated_result(&Erhoeht::Fehler("Zugriff verweigert".into()), id);
        assert!(!ok && text.contains("(Zugriff verweigert)"), "{text}");
        assert!(!elevated_result(&Erhoeht::Zeit, id).0);
        // A package id that could carry options never reaches the elevated start.
        let bad = Update { name: "x".into(), id: "a --override b".into(), installiert: "1".into(), verfuegbar: "2".into(), hinweis: String::new(), seite: String::new(), fehler_seit: String::new() };
        assert_eq!(run_upgrade_elevated(&bad), (false, "ungültige Paket-ID a --override b".to_string()));
    }

    #[test]
    fn traffic_lights() {
        assert_eq!(assess_antivirus(&[("Trend Micro Maximum Security".into(), 0x61000)]).ampel, Ampel::Gruen);
        assert_eq!(assess_antivirus(&[("Trend Micro".into(), 0x61010)]).ampel, Ampel::Gelb, "veraltete Definitionen");
        assert_eq!(assess_antivirus(&[("Windows Defender".into(), 0x60100)]).ampel, Ampel::Rot, "nichts an");
        assert_eq!(assess_firewall(Some(true), Some(false), &[]).ampel, Ampel::Rot);
        assert_eq!(assess_firewall(Some(false), Some(false), &[("Trend Micro Firewall".into(), 0x61000)]).ampel, Ampel::Gruen);
        assert_eq!(assess_updates(Some(70)).ampel, Ampel::Rot);
        assert_eq!(assess_updates(Some(3)).tipp, "");
        assert_eq!(assess_backup(false, false, None, None).ampel, Ampel::Grau);
        assert_eq!(assess_backup(true, false, Some(20), Some("01.11.2026")).ampel, Ampel::Gelb);
        assert_eq!(assess_backup(true, true, Some(3), Some("19.11.2026")).ampel, Ampel::Gruen);
        assert_eq!(assess_lsa(Some(2)).ampel, Ampel::Gruen);
        assert_eq!(assess_lsa(Some(1)).ampel, Ampel::Gruen);
        assert_eq!(assess_lsa(Some(0)).ampel, Ampel::Gelb);
        assert!(assess_lsa(None).tipp.contains("Schutz durch lokale Sicherheitsautorität"));
        // Drive plugged in but nothing saved yet: says so (not "Platte abgesteckt?").
        let empty = assess_backup(true, true, None, None);
        assert_eq!(empty.ampel, Ampel::Gelb);
        assert!(empty.text.contains("noch keine Sicherung"), "{}", empty.text);
        assert!(assess_backup(true, false, None, None).text.contains("nicht gefunden"));
        assert_eq!(assess_programs(Some(&[])).ampel, Ampel::Gruen);
        let b = Bericht { punkte: vec![assess_updates(Some(70)), assess_backup(false, false, None, None)], ..Default::default() };
        assert_eq!(b.worst(), Ampel::Rot);
        assert_eq!(qfe_date("11/12/2026"), chrono::NaiveDate::from_ymd_opt(2026, 11, 12));
        assert!(still_installed("windowsdefender://"));
        assert!(!still_installed("C:\\Program Files (x86)\\Kaspersky Lab\\gibt-es-nicht\\wmiav.exe"));
        assert!(still_installed("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn parses_winget_upgrade_in_german_and_english() {
        let de = "   - \r   \\ \rName                           ID                      Version      Verfügbar    Quelle\n\
                  ------------------------------------------------------------------------------------\n\
                  Mozilla Firefox (x64 de)       Mozilla.Firefox.de      132.0        133.0.3      winget\n\
                  7-Zip 24.07 (x64)              7zip.7zip               24.07        24.08        winget\n\
                  2 Aktualisierungen verfügbar.\n";
        let u = parse_winget_upgrade(de);
        assert_eq!(u.len(), 2);
        assert_eq!((u[0].name.as_str(), u[0].id.as_str(), u[0].installiert.as_str(), u[0].verfuegbar.as_str()), ("Mozilla Firefox (x64 de)", "Mozilla.Firefox.de", "132.0", "133.0.3"));
        assert_eq!(u[1].command(), "winget upgrade --id 7zip.7zip -e");
        let en = "Name   Id          Version Available Source\n-----\nGit    Git.Git     2.45.0  2.47.1    winget\n1 upgrades available.\n";
        assert_eq!(parse_winget_upgrade(en)[0].verfuegbar, "2.47.1");
        assert!(parse_winget_upgrade("Keine verfügbaren Upgrades gefunden.").is_empty());
    }

    #[test]
    fn package_ids_and_protected_programs() {
        assert!(valid_id("Mozilla.Firefox.de") && valid_id("Microsoft.VCRedist.2015+.x64"));
        assert!(!valid_id("x --force") && !valid_id("-h") && !valid_id("a\"b") && !valid_id(""));
        let u = |n: &str, id: &str| Update { name: n.into(), id: id.into(), installiert: "1".into(), verfuegbar: "2".into(), hinweis: String::new(), seite: String::new(), fehler_seit: String::new() };
        assert!(protected_program(&u("Trend Micro Maximum Security", "TrendMicro.MaximumSecurity")));
        assert!(!protected_program(&u("7-Zip 26.02 (x64)", "7zip.7zip")));
        assert_eq!(ProgrammAktion::parse("deinstallieren"), Some(ProgrammAktion::Deinstallieren));
        assert_eq!(ProgrammAktion::parse("loeschen"), None);
    }

    #[test]
    fn finished_and_impossible_updates_leave_the_list_failures_stay_with_a_note() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let u = |id: &str| Update { name: id.into(), id: id.into(), installiert: "1".into(), verfuegbar: "2".into(), hinweis: String::new(), seite: String::new(), fehler_seit: String::new() };
        let mut b = Bericht { zeit: "2026-11-18 07:00:00".into(), ..Default::default() };
        b.set_updates(vec![u("A.a"), u("B.b"), u("C.c")]);
        b.save(dir.path()).unwrap();
        note_program_action(dir.path(), ProgrammAktion::Aktualisieren, &u("A.a"), true, "Erfolgreich installiert", false);
        note_program_action(dir.path(), ProgrammAktion::Aktualisieren, &u("B.b"), false, "trifft nicht zu", true);
        note_program_action(dir.path(), ProgrammAktion::Aktualisieren, &u("C.c"), false, "Installer-Fehler 1603", false);
        let mut b = Bericht::load(dir.path()).unwrap();
        let list = b.updates.clone().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].id == "C.c" && list[0].hinweis.contains("1603") && list[0].fehler_seit.len() == 10);
        let since = list[0].fehler_seit.clone();
        assert!(b.aktionen[1].contains("nicht möglich"));
        // The next winget list still names B.b in the same version: it stays hidden.
        b.set_updates(vec![u("B.b"), u("C.c"), Update { verfuegbar: "3".into(), ..u("B.b") }]);
        let list = b.updates.unwrap();
        assert_eq!(list.iter().map(|x| x.verfuegbar.as_str()).collect::<Vec<_>>(), ["2", "3"]);
        assert_eq!(list[0].fehler_seit, since, "Hinweis bleibt ueber die taegliche Pruefung erhalten");
        assert_eq!(console_text(b"verf\x81gbar"), "verfügbar");
    }

    #[test]
    fn official_page_from_the_winget_catalogue_only_https() {
        let de = "Gefunden HWiNFO [REALiX.HWiNFO]\nHerausgeber-URL: https://www.hwinfo.com/\nStartseite: https://www.hwinfo.com/download/\nLizenz-URL: https://www.hwinfo.com/files/license.pdf\n";
        assert_eq!(parse_official_page(de).as_deref(), Some("https://www.hwinfo.com/download/"));
        assert_eq!(parse_official_page("Publisher Url: https://example.org/\n").as_deref(), Some("https://example.org/"));
        assert_eq!(parse_official_page("Homepage: http://unsicher.example/\nInstaller Url: https://x.example/a.exe\n"), None);
        assert_eq!(parse_official_page("Homepage: https://a.example/\"onclick\n"), None);
        let show = "Installer:\n  Installertyp: burn (zip)\n  Installer-URL: https://downloads.wdc.com/wdapp/WDSecurity_WIN.zip\n  Installer Url: http://unsicher.example/a.exe\n";
        assert_eq!(parse_installer_urls(show), vec!["https://downloads.wdc.com/wdapp/WDSecurity_WIN.zip".to_string()]);
    }

    #[test]
    fn newest_file_in_backup_folders() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        std::fs::create_dir_all(dir.path().join("a").join("b")).unwrap();
        std::fs::write(dir.path().join("a").join("b").join("x.bak"), b"1").unwrap();
        assert!(newest_file(&[dir.path().to_path_buf()]).is_some());
        assert!(newest_file(&[dir.path().join("fehlt")]).is_none());
        // A fresh drive: only the folders Windows creates by itself - that is no backup.
        let fresh = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        std::fs::create_dir_all(fresh.path().join("System Volume Information")).unwrap();
        std::fs::write(fresh.path().join("System Volume Information").join("IndexerVolumeGuid"), b"1").unwrap();
        std::fs::create_dir_all(fresh.path().join("$RECYCLE.BIN")).unwrap();
        std::fs::create_dir_all(fresh.path().join("leer")).unwrap();
        assert!(newest_file(&[fresh.path().to_path_buf()]).is_none());
        std::fs::write(fresh.path().join("leer").join("sicherung.bak"), b"1").unwrap();
        assert!(newest_file(&[fresh.path().to_path_buf()]).is_some());
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "liest den echten Zustand dieses PCs"]
    fn real_check() {
        let b = super::check(&Default::default(), None);
        for p in &b.punkte {
            println!("{:?} {}: {} | {}", p.ampel, p.name, p.text, p.tipp);
        }
        let u = super::outdated_programs();
        println!("winget: {:?}", u.as_ref().map(|l| l.len()));
        for x in u.unwrap_or_default().iter().take(40) {
            println!("  {} | {} | {} -> {}", x.name, x.id, x.installiert, x.verfuegbar);
        }
    }
}
