//! Configuration (`%APPDATA%\K9\config.toml`).
//!
//! The file is created with commented German defaults on first start.
//! Secrets (SMTP password, ntfy token) are never stored here but in the
//! Windows Credential Manager (see [`crate::secrets`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths::expand_env;
use crate::schedule::{ScheduleEntry, ScheduleKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Own native window (TaskDialog), independent of Windows notification settings.
    Fenster,
    Popup,
    Dashboard,
    Email,
    Handy,
}

impl Channel {
    pub fn parse(s: &str) -> Option<Channel> {
        match s.trim().to_lowercase().as_str() {
            "fenster" | "meldefenster" | "dialog" => Some(Channel::Fenster),
            "popup" | "windows" | "toast" => Some(Channel::Popup),
            "dashboard" | "browser" => Some(Channel::Dashboard),
            "email" | "e-mail" | "mail" => Some(Channel::Email),
            "handy" | "push" | "ntfy" => Some(Channel::Handy),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Channel::Fenster => t!("Meldefenster", "alert window"),
            Channel::Popup => t!("Windows-Popup", "Windows pop-up"),
            Channel::Dashboard => t!("Browser-Dashboard", "browser dashboard"),
            Channel::Email => t!("E-Mail", "e-mail"),
            Channel::Handy => t!("Handy (ntfy)", "phone (ntfy)"),
        }
    }
    /// External channels may still be used for critical detections while gaming.
    pub fn is_external(self) -> bool {
        matches!(self, Channel::Email | Channel::Handy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub standard_pfade: Vec<String>,
    pub ausnahmen: Vec<String>,
    pub max_dateigroesse_mb: u64,
    /// Parallel scan threads (1–8). Low values keep games smooth.
    pub max_threads: usize,
    /// Skip unchanged files (same path, size, change time, signature state).
    pub cache: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            standard_pfade: vec![
                "%USERPROFILE%\\Downloads".into(),
                "%USERPROFILE%\\Desktop".into(),
                "%USERPROFILE%\\Documents".into(),
                "%TEMP%".into(),
            ],
            ausnahmen: Vec::new(),
            max_dateigroesse_mb: 128,
            max_threads: 2,
            cache: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GamingConfig {
    pub aktiv: bool,
    pub vollbild_erkennen: bool,
    pub spiele_prozesse: Vec<String>,
    pub spiele_ordner: Vec<String>,
    /// Programs that lie in a games folder but are no games (overlays, wallpaper tools): while
    /// only these run, K9 is NOT in gaming mode. Seen on 22.11.2026: CrosshairX kept K9 in
    /// gaming mode for hours although no game was running.
    pub keine_spiele: Vec<String>,
    pub kritische_sofort_extern: bool,
    pub pruefintervall_sekunden: u64,
}

impl Default for GamingConfig {
    fn default() -> Self {
        Self {
            aktiv: true,
            vollbild_erkennen: true,
            spiele_prozesse: Vec::new(),
            spiele_ordner: vec![
                "\\steamapps\\common\\".into(),
                "\\Epic Games\\".into(),
                "\\GOG Galaxy\\Games\\".into(),
                "\\GOG Games\\".into(),
                "\\EA Games\\".into(),
                "\\Electronic Arts\\".into(),
                "\\Ubisoft Game Launcher\\games\\".into(),
                "\\Battle.net\\Games\\".into(),
                "\\Riot Games\\".into(),
                "\\XboxGames\\".into(),
            ],
            keine_spiele: ["crosshairx.exe", "wallpaper32.exe", "wallpaper64.exe", "webwallpaper32.exe", "losslessscaling.exe", "soundpad.exe", "obs64.exe"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            kritische_sofort_extern: true,
            pruefintervall_sekunden: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub kanaele: Vec<Channel>,
    /// "Später" im Meldefenster: nach so vielen Minuten erneut fragen.
    pub spaeter_minuten: u64,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self { kanaele: vec![Channel::Fenster, Channel::Dashboard], spaeter_minuten: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DashboardConfig {
    pub port: u16,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self { port: 47110 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    /// "tls" (Port 465) oder "starttls" (Port 587)
    pub verschluesselung: String,
    pub benutzer: String,
    pub absender: String,
    pub empfaenger: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HandyConfig {
    pub server: String,
    pub thema: String,
    pub prioritaet: u8,
}

impl Default for HandyConfig {
    fn default() -> Self {
        Self { server: "https://ntfy.sh".into(), thema: String::new(), prioritaet: 4 }
    }
}

/// Detection sources (step 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuellenConfig {
    /// Folder for downloaded signatures/rules. Empty = `<Datenordner>\quellen`.
    pub ordner: String,
    /// Default update interval in hours for all sources.
    pub aktualisieren_stunden: u64,
    /// Per-source overrides, e.g. `{ urlhaus = 6, cisa_kev = 24 }`.
    pub intervall_stunden: std::collections::BTreeMap<String, u64>,
    pub yara_aktiv: bool,
    /// "core" (wenige Fehlalarme) oder "extended" (mehr Regeln).
    pub yara_paket: String,
    /// Switch "yara-erweitert": load the package "extended" (as `yara_paket = "extended"`).
    pub yara_erweitert: bool,
    /// YARA-Forge-Regeln unter diesem Score (0–100) werden ignoriert.
    pub yara_min_score: i64,
    pub clamav_aktiv: bool,
    pub clamav_programmordner: String,
    pub clamav_port: u16,
    /// ClamAV also reports potentially unwanted programs (PUA; packers excluded).
    pub clamav_pua: bool,
    pub abusech_aktiv: bool,
    pub openphish_aktiv: bool,
    /// Second phishing list "phishing-filter" (malware-filter, CC BY-SA 4.0).
    pub phishing_filter_aktiv: bool,
    /// Look up the SHA-256 of new programs from the internet at VirusTotal (hash only, never the file).
    pub virustotal_aktiv: bool,
    pub cve_aktiv: bool,
    pub browserverlauf_pruefen: bool,
    /// Lists of vulnerable/malicious kernel drivers (Microsoft, LOLDrivers)
    pub treiber_aktiv: bool,
    /// List of malicious browser extensions (MalExt Sentry).
    pub erweiterungen_aktiv: bool,
    /// Sigma rules (SigmaHQ) for process starts: load the package and check every start (service).
    pub sigma_aktiv: bool,
    /// The Sigma rules of the level "medium" that LOLBAS refers to (quiet messages).
    pub lolbas_aktiv: bool,
    /// HaGeZi "Threat Intelligence Feeds" (medium): large list of malicious domains for the DNS check.
    pub hagezi_tif_aktiv: bool,
    /// Spamhaus DROP: hijacked and criminal networks for the connection check.
    pub spamhaus_drop_aktiv: bool,
}

impl Default for QuellenConfig {
    fn default() -> Self {
        Self {
            ordner: String::new(),
            aktualisieren_stunden: 24,
            intervall_stunden: Default::default(),
            yara_aktiv: true,
            yara_paket: "core".into(),
            yara_erweitert: false,
            yara_min_score: 60,
            clamav_aktiv: true,
            clamav_programmordner: "C:\\Program Files\\ClamAV".into(),
            clamav_port: 3310,
            clamav_pua: true,
            abusech_aktiv: true,
            openphish_aktiv: true,
            phishing_filter_aktiv: true,
            virustotal_aktiv: false,
            cve_aktiv: true,
            browserverlauf_pruefen: true,
            treiber_aktiv: true,
            erweiterungen_aktiv: true,
            sigma_aktiv: false,
            lolbas_aktiv: false,
            hagezi_tif_aktiv: false,
            spamhaus_drop_aktiv: false,
        }
    }
}

/// Interventions that change Windows (all off by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SchutzConfig {
    /// Shadow copy while the user is idle (never in a game; Windows rotates, we never delete).
    pub schattenkopien: bool,
    pub schattenkopien_stunden: u64,
    /// Drives with shadow copies, e.g. ["C:", "F:"].
    pub schattenkopien_laufwerke: Vec<String>,
    /// Older single-drive setting: used only if `schattenkopien_laufwerke` is not in the file.
    pub schattenkopien_laufwerk: String,
    /// Block known botnet command servers (high confidence only) in the Windows firewall.
    pub firewall_sperre: bool,
}

impl Default for SchutzConfig {
    fn default() -> Self {
        Self {
            schattenkopien: false,
            schattenkopien_stunden: 24,
            schattenkopien_laufwerke: vec!["C:".into()],
            schattenkopien_laufwerk: String::new(),
            firewall_sperre: false,
        }
    }
}

/// Work folders and work programs (other Claude projects, builds): behaviour findings whose
/// evidence lies only there are stored "quietly" (dashboard only, no Meldefenster).
/// Signature findings (hash lists, YARA, ClamAV) are never quiet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ArbeitsordnerConfig {
    pub aktiv: bool,
    /// Folders (prefix match, environment variables allowed).
    pub ordner: Vec<String>,
    /// Programs (full path) whose child processes count as work; only with a valid signature.
    pub programme: Vec<String>,
}

impl Default for ArbeitsordnerConfig {
    fn default() -> Self {
        Self {
            aktiv: true,
            ordner: vec!["%TEMP%\\claude".into()],
            programme: vec!["%USERPROFILE%\\.local\\bin\\claude.exe".into()],
        }
    }
}

/// Security check in the dashboard (see `sicherheit`), weekly report and home network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SicherheitscheckConfig {
    /// Traffic light "Sicherheits-Check" every 6 hours (read only).
    pub aktiv: bool,
    /// Outdated programs via winget (at most once a day, only lists).
    pub programm_updates: bool,
    /// Backup folders (e.g. on an external drive): the newest file there is the last backup.
    pub sicherung_ordner: Vec<String>,
    /// Weekly report (a Meldefenster with the summary of the last 7 days).
    pub wochenbericht: bool,
    /// New devices in the home network (ARP, own /24 network only, every hour, never while gaming).
    pub heimnetz: bool,
    /// New vulnerabilities (CVE, High/Critical) of installed programs, once a day from the NVD.
    pub neue_luecken: bool,
}

impl Default for SicherheitscheckConfig {
    fn default() -> Self {
        Self { aktiv: true, programm_updates: true, sicherung_ordner: Vec::new(), wochenbericht: true, heimnetz: true, neue_luecken: true }
    }
}

/// Phishing checks on queried domain names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PhishingConfig {
    /// Report lookalikes of well-known brands (steamcommunlty.com, paypal-login.example …).
    pub aehnliche_domains: bool,
    /// Additional own brands as domains, e.g. ["meinebank.de"].
    pub eigene_marken: Vec<String>,
}

impl Default for PhishingConfig {
    fn default() -> Self {
        Self { aehnliche_domains: true, eigene_marken: Vec::new() }
    }
}

/// Real-time protection (step 3, user mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EchtzeitConfig {
    pub aktiv: bool,
    /// Watched folders; empty = Downloads, Desktop, Documents, TEMP, Autostart folder.
    pub ordner: Vec<String>,
    /// Additional watched folders (no canary files there), e.g. a test folder.
    pub zusatz_ordner: Vec<String>,
    pub max_dateigroesse_mb: u64,
    pub prozesse: bool,
    pub autostart: bool,
    pub netzwerk: bool,
    pub netzwerk_intervall_sekunden: u64,
    pub ransomware: bool,
    /// Ransomware alarm window even during a game.
    pub ransomware_meldung_trotz_spiel: bool,
    /// Suspend suspected processes until the user decides (never kill). Default off.
    pub ransomware_prozess_anhalten: bool,
    pub usb: bool,
    /// Check new high-risk files additionally with ClamAV (clamd started on demand, never while gaming).
    pub clamav: bool,
    /// Stop clamd after this many idle minutes (frees about 1 GB RAM).
    pub clamav_leerlauf_minuten: u64,
    /// Report other programs opening stored logins (browser passwords/cookies, Steam,
    /// Discord, Telegram, wallets) – checked by the Windows service.
    pub infostealer: bool,
    /// Check PowerShell script blocks (event 4104) – checked by the Windows service.
    pub powershell_skripte: bool,
    /// Report unsigned programs from the internet (Mark of the Web) when they start.
    pub download_herkunft: bool,
    /// Combine steps of a program from the internet and its child processes into one attack chain.
    pub angriffsketten: bool,
    /// Report new user accounts, new administrators, remote desktop logons and many failed
    /// logons (Security event log, read by the Windows service).
    pub anmeldungen: bool,
    /// Freeze (suspend, never end) the process of a critical finding until the user decides.
    /// Off by default – an exception to "nothing happens automatically".
    pub kritische_prozesse_anhalten: bool,
    /// Freeze an unsigned program marked "from the internet" at its first start until the user
    /// releases it (like SmartScreen). Off by default: one more click for every new unsigned
    /// program. For ransomware that encrypts within the first second (BlackBasta).
    pub neue_programme_anhalten: bool,
    /// Memory scan while idle (see `speicher`): off by default because of anti-cheat systems.
    pub speicher_scan: bool,
    /// Minutes without keyboard/mouse before the memory scan may start.
    pub speicher_scan_leerlauf_minuten: u64,
}

impl Default for EchtzeitConfig {
    fn default() -> Self {
        Self {
            aktiv: true,
            ordner: Vec::new(),
            zusatz_ordner: Vec::new(),
            max_dateigroesse_mb: 64,
            prozesse: true,
            autostart: true,
            netzwerk: true,
            netzwerk_intervall_sekunden: 60,
            ransomware: true,
            ransomware_meldung_trotz_spiel: true,
            ransomware_prozess_anhalten: false,
            usb: true,
            clamav: true,
            clamav_leerlauf_minuten: 10,
            infostealer: true,
            powershell_skripte: true,
            download_herkunft: true,
            angriffsketten: true,
            anmeldungen: true,
            kritische_prozesse_anhalten: false,
            neue_programme_anhalten: false,
            speicher_scan: false,
            speicher_scan_leerlauf_minuten: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Language of all texts: "de", "en" or "auto" (the display language of Windows).
    pub sprache: String,
    pub scan: ScanConfig,
    pub quellen: QuellenConfig,
    pub echtzeit: EchtzeitConfig,
    pub phishing: PhishingConfig,
    pub schutz: SchutzConfig,
    pub arbeitsordner: ArbeitsordnerConfig,
    pub sicherheitscheck: SicherheitscheckConfig,
    pub zeitplan: Vec<ScheduleEntry>,
    pub gaming: GamingConfig,
    pub meldungen: NotifyConfig,
    pub dashboard: DashboardConfig,
    pub email: EmailConfig,
    pub handy: HandyConfig,
}

impl Default for Config {
    /// Must match [`DEFAULT_CONFIG`] (checked by a unit test).
    fn default() -> Self {
        Self {
            sprache: "auto".into(),
            scan: ScanConfig::default(),
            quellen: QuellenConfig::default(),
            echtzeit: EchtzeitConfig::default(),
            phishing: PhishingConfig::default(),
            schutz: SchutzConfig::default(),
            arbeitsordner: ArbeitsordnerConfig::default(),
            sicherheitscheck: SicherheitscheckConfig::default(),
            zeitplan: vec![ScheduleEntry {
                name: Some("Leerlauf-Scan".into()),
                kind: ScheduleKind::Leerlauf { minuten: 20, min_abstand_stunden: 24 },
                pfade: Vec::new(),
                pruefungen: Vec::new(),
            }],
            gaming: GamingConfig::default(),
            meldungen: NotifyConfig::default(),
            dashboard: DashboardConfig::default(),
            email: EmailConfig {
                smtp_port: 465,
                verschluesselung: "tls".into(),
                ..Default::default()
            },
            handy: HandyConfig::default(),
        }
    }
}

impl Config {
    /// Loads the config, creating the commented default file if missing.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, DEFAULT_CONFIG).with_context(|| format!("{} kann nicht geschrieben werden", path.display()))?;
            tracing::info!("Standardkonfiguration angelegt: {}", path.display());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("{} nicht lesbar", path.display()))?;
        Self::parse(&text).with_context(|| format!("Fehler in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        // Older files name one drive (schattenkopien_laufwerk) instead of the list.
        let old = cfg.schutz.schattenkopien_laufwerk.trim().to_string();
        if !old.is_empty() {
            let raw: toml::Table = toml::from_str(text)?;
            let has_list = raw.get("schutz").and_then(|s| s.get("schattenkopien_laufwerke")).is_some();
            if !has_list {
                cfg.schutz.schattenkopien_laufwerke = vec![old];
            }
        }
        for (i, e) in cfg.zeitplan.iter().enumerate() {
            e.kind.validate().with_context(|| format!("Zeitplan-Eintrag {}", i + 1))?;
        }
        Ok(cfg)
    }

    /// config.toml as it is now, read again at most every 30 seconds (switches of the agent
    /// apply without a restart). Unconfirmed weakening changes are withheld; a broken file
    /// gives `fallback`.
    pub fn live(path: &Path, fallback: &Config) -> Config {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};
        static CACHE: Mutex<Option<(PathBuf, Instant, Config)>> = Mutex::new(None);
        let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((f, t, c)) = g.as_ref() {
            if f == path && t.elapsed() < Duration::from_secs(30) {
                return c.clone();
            }
        }
        let cfg = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| Config::parse(&t).ok())
            .map(|mut c| {
                crate::schutz::enforce_confirmed(&mut c);
                c
            })
            .unwrap_or_else(|| fallback.clone());
        *g = Some((path.to_path_buf(), Instant::now(), cfg.clone()));
        cfg
    }

    pub fn default_scan_paths(&self) -> Vec<PathBuf> {
        self.scan.standard_pfade.iter().map(|p| PathBuf::from(expand_env(p))).collect()
    }

    pub fn exclusions(&self) -> Vec<PathBuf> {
        self.scan.ausnahmen.iter().map(|p| PathBuf::from(expand_env(p))).collect()
    }

    pub fn max_file_size(&self) -> u64 {
        self.scan.max_dateigroesse_mb.saturating_mul(1024 * 1024)
    }
}

/// Commented default configuration (German).
pub const DEFAULT_CONFIG: &str = r#"# ==========================================================================
#  K9 – Konfiguration
#  Änderungen werden beim nächsten Start von Agent bzw. k9 wirksam.
#  Passwörter/Tokens gehören NICHT hierher, sondern in die Windows-
#  Anmeldeinformationsverwaltung:  k9 geheimnis smtp-passwort
#                                  k9 geheimnis ntfy-token
#  Umgebungsvariablen wie %USERPROFILE% werden in Pfaden ersetzt.
# ==========================================================================

# Sprache aller Texte / language of all texts: "de", "en" oder "auto"
# (auto = Anzeigesprache von Windows; alles ausser Deutsch wird Englisch).
# Diese Zeile muss vor dem ersten Abschnitt [scan] stehen. Einfacher: k9 sprache en
sprache = "auto"

[scan]
# Ordner, die geplante Scans prüfen, wenn ein Zeitplan keine eigenen Pfade hat.
standard_pfade = [
    "%USERPROFILE%\\Downloads",
    "%USERPROFILE%\\Desktop",
    "%USERPROFILE%\\Documents",
    "%TEMP%",
]
# Ordner, die nie gescannt werden (z. B. große Spielebibliotheken).
ausnahmen = []
# Dateien über dieser Größe (MB) werden übersprungen. 0 = keine Grenze.
max_dateigroesse_mb = 128
# Parallele Scan-Threads (1–8). Wenige Threads = keine Ruckler beim Spielen.
max_threads = 2
# Unveränderte Dateien überspringen (gleicher Pfad, Größe, Änderungszeit und
# gleicher Signaturstand). Spart beim nächsten Scan sehr viel Zeit.
cache = true

# --------------------------------------------------------------------------
# Erkennungsquellen (Schritt 2). Alles wird lokal geprüft, es wird nichts
# hochgeladen. Details, Adressen und Lizenzen: docs\QUELLEN.md
# Aktualisierung: k9 quellen aktualisieren  (der Agent macht das automatisch,
# aber nie während eines Spiels).
# --------------------------------------------------------------------------
[quellen]
# Ablageordner; leer = <Datenordner>\quellen
ordner = ""
# Standard-Aktualisierungsintervall in Stunden für alle Quellen
aktualisieren_stunden = 24        # MalwareBazaar: stuendlich die neuesten Hashes, taeglich die ganze Liste
# Abweichende Intervalle je Quelle, z. B. { urlhaus = 6, openphish = 12 }
intervall_stunden = {}
# YARA-Regeln von YARA Forge: "core" (wenige Fehlalarme) oder "extended"
yara_aktiv = true
yara_paket = "core"
# Das Paket "extended" laden (rund doppelt so viele Regeln). Einschalten: k9 funktion yara-erweitert an,
# danach: k9 quellen aktualisieren yara_forge
yara_erweitert = false
# Regeln mit niedrigerem Score (0–100) werden ignoriert
yara_min_score = 60
# ClamAV (muss separat installiert sein: winget install Cisco.ClamAV).
# clamd wird nur während eines Scans gestartet (braucht dann ca. 1 GB RAM).
clamav_aktiv = true
clamav_programmordner = "C:\\Program Files\\ClamAV"
clamav_port = 3310
# ClamAV meldet auch potenziell unerwünschte Programme (PUA, z. B. Adware,
# Hacktools, Cracks, Spiel-Trainer). Packer werden nicht gemeldet, Werkzeuge nur
# als "Niedrig". Was du behalten willst: in der Meldung "Freigabe" wählen.
clamav_pua = true
# abuse.ch (MalwareBazaar, URLhaus, ThreatFox) – benötigt einen kostenlosen
# Auth-Key von https://auth.abuse.ch/ :  k9 geheimnis abusech-key
abusech_aktiv = true
# OpenPhish Community-Feed (Phishing-Adressen)
openphish_aktiv = true
# Zweite Phishing-Liste "phishing-filter" von malware-filter (Domains, CC BY-SA 4.0)
phishing_filter_aktiv = true
# VirusTotal: Pruefsumme neuer Programme aus dem Internet abfragen (nie die Datei hochladen).
# Die Pruefsumme geht an VirusTotal (Google). Kostenloser Schluessel nur fuer private Nutzung:
#   k9 geheimnis virustotal-key      Standard: aus
virustotal_aktiv = false
# Installierte Software gegen CISA KEV + NVD prüfen (optional NVD-API-Key:
# k9 geheimnis nvd-key, macht die erste Prüfung deutlich schneller)
cve_aktiv = true
# Browserverlauf (Chrome, Edge, Brave, Firefox) gegen Phishing-/Schad-Adressen prüfen
browserverlauf_pruefen = true
# Treiber gegen die Microsoft-Sperrliste und LOLDrivers pruefen (verwundbare/boesartige Treiber)
treiber_aktiv = true
# Liste schaedlicher Browser-Erweiterungen (MalExt Sentry, CC BY 4.0)
erweiterungen_aktiv = true
# Sigma-Regeln (SigmaHQ) für Programmstarts laden und jeden Start damit prüfen (Dienst)
sigma_aktiv = false
# LOLBAS: zusaetzlich die Sigma-Regeln der Stufe "mittel" laden, auf die die Liste der
# missbrauchten Windows-Programme (lolbas-project.github.io) verweist. Treffer nur leise im
# Dashboard (Probephase). Einschalten: k9 funktion lolbas an
lolbas_aktiv = false
# große Liste von Schad-Domains (HaGeZi Threat Intelligence Feeds, mittlere Liste) für die DNS-Prüfung
hagezi_tif_aktiv = false
# gekaperte und kriminelle Netze (Spamhaus DROP) für die Prüfung der Verbindungen
spamhaus_drop_aktiv = false

# --------------------------------------------------------------------------
# Zeitpläne – beliebig viele [[zeitplan]]-Einträge möglich.
#   art = "sofort"        nur auf Anforderung (k9 scan / Dashboard)
#   art = "staendig"      Dauerüberwachung (Platzhalter, Echtzeitschutz folgt in Schritt 3)
#   art = "taeglich"      uhrzeit = "HH:MM"
#   art = "woechentlich"  tage = ["Mo","Di","Mi","Do","Fr","Sa","So"], uhrzeit = "HH:MM"
#   art = "einmalig"      zeitpunkt = "JJJJ-MM-TT HH:MM"
#   art = "leerlauf"      minuten = N (ohne Tastatur-/Mauseingabe),
#                         min_abstand_stunden = 24 (höchstens so oft)
# Optional je Eintrag: name = "...", pfade = ["C:\\Ordner", ...],
#   pruefungen = ["dateien", "software", "urls", "autostart"]  (leer = alle)
# Während ein Spiel läuft, werden fällige Scans aufgeschoben, bis es beendet ist.
# --------------------------------------------------------------------------
[[zeitplan]]
name = "Leerlauf-Scan"
art = "leerlauf"
minuten = 20
min_abstand_stunden = 24

# [[zeitplan]]
# name = "Täglich mittags"
# art = "taeglich"
# uhrzeit = "12:30"

# [[zeitplan]]
# name = "Wochenende"
# art = "woechentlich"
# tage = ["Sa", "So"]
# uhrzeit = "10:00"
# pfade = ["%USERPROFILE%"]

# [[zeitplan]]
# art = "einmalig"
# zeitpunkt = "2026-12-24 18:00"

# --------------------------------------------------------------------------
# Echtzeitschutz (laeuft im Agent, ohne Treiber, mit Benutzerrechten).
# Auch hier gilt: nichts wird ohne deine Entscheidung verschoben, geloescht,
# deaktiviert oder beendet.
# --------------------------------------------------------------------------
[echtzeit]
aktiv = true
# Ueberwachte Ordner; leer = Downloads, Desktop, Dokumente, TEMP, Autostart-Ordner
ordner = []
# Zusaetzlich ueberwachte Ordner (ohne Koederdateien), z. B. ein Testordner
zusatz_ordner = []
# Groessere Dateien werden in Echtzeit nicht geprueft (der geplante Scan schon)
max_dateigroesse_mb = 64
# Neu gestartete Programme pruefen (z. B. Word startet PowerShell)
prozesse = true
# Neue Autostart-Eintraege melden
autostart = true
# Verbindungen und DNS-Namen mit bekannten Schad-Adressen abgleichen
netzwerk = true
netzwerk_intervall_sekunden = 60
# Ransomware-Erkennung (Koederdateien, Massenverschluesselung)
ransomware = true
# Ransomware-Alarm auch waehrend eines Spiels als Fenster anzeigen
ransomware_meldung_trotz_spiel = true
# Verdaechtige Prozesse bei Ransomware-Verdacht bis zu deiner Entscheidung
# ANHALTEN (nie beenden). Standard: aus. Kann ein harmloses Programm einfrieren,
# bis du im Meldefenster "Freigabe" waehlst.
ransomware_prozess_anhalten = false
# USB-Sticks und Speicherkarten beim Einstecken pruefen
usb = true
# Neue riskante Dateien (Programme, Skripte, Makro-Dokumente, Archive, PDFs,
# Installer) zusaetzlich mit ClamAV pruefen. ClamAV startet nur bei Bedarf,
# nie waehrend eines Spiels, und beendet sich nach der Leerlaufzeit wieder.
clamav = true
clamav_leerlauf_minuten = 10
# Melden, wenn ein fremdes Programm gespeicherte Zugangsdaten oeffnet (Browser-
# Passwoerter und Cookies, Steam, Discord, Telegram, Wallets). Prueft der Dienst.
infostealer = true
# PowerShell-Skripte vor der Ausfuehrung pruefen (auch verschleierte). Ohne die Windows-
# Richtlinie "Script Block Logging" nur die Skripte, die PowerShell selbst als verdaechtig
# einstuft; vollstaendig mit: k9 powershell-protokoll an (als Administrator)
powershell_skripte = true
# Melden, wenn ein unsigniertes Programm aus dem Internet startet (Herkunftsvermerk von Windows)
download_herkunft = true
# Angriffsketten: Schritte eines Programms aus dem Internet und seiner Kindprozesse
# (Skript, Autostart, Zugangsdaten, Schad-Adresse) zu einer Meldung zusammenfassen
angriffsketten = true
# Konten und Anmeldungen: neues Benutzerkonto, neuer Administrator, Anmeldung per
# Remotedesktop, viele falsche Passwoerter, geloeschtes Sicherheitsprotokoll (Dienst)
anmeldungen = true
# Programm einer KRITISCHEN Meldung (Angriffskette, Datendieb, kritisches Skript) anhalten
# (einfrieren, nie beenden), bis du entscheidest. Nie Spiele, Anti-Cheat, Windows,
# Microsoft/Trend Micro. Standard: aus (Ausnahme von "nichts passiert automatisch")
kritische_prozesse_anhalten = false
# Ein unsigniertes Programm aus dem Internet beim ERSTEN Start anhalten, bis du es freigibst
# (aehnlich SmartScreen). Gegen Ransomware, die schon in der ersten Sekunde verschluesselt.
# Preis: bei jedem neuen unsignierten Programm ein Klick. Nicht waehrend eines Spiels.
# Standard: aus. Einschalten: k9 funktion neue-programme an
neue_programme_anhalten = false
# Speicher-Scan im Leerlauf: sucht Schadcode, der nur im Arbeitsspeicher steht. Standard: aus.
# Laeuft nie, solange ein Spiel oder ein Anti-Cheat-Programm laeuft, und gar nicht auf einem PC
# mit staendig geladenem Anti-Cheat (Riot Vanguard, FACEIT). Prueft nur Programme aus
# Benutzerordnern oder ohne gueltige Signatur, nur lesend. Einschalten: k9 funktion speicher-scan an
speicher_scan = false
speicher_scan_leerlauf_minuten = 10

# --------------------------------------------------------------------------
# Phishing: aehnliche Domains bekannter Marken melden (steamcommunlty.com,
# paypal-login.example, discord-nitro.example ...). Offizielle Domains der Marken
# werden nie gemeldet. Eigene Marken als Domain eintragen, z. B. ["meinebank.de"].
# --------------------------------------------------------------------------
[phishing]
aehnliche_domains = true
eigene_marken = []

# --------------------------------------------------------------------------
# Eingriffe in Windows (alle Standard: aus)
# schattenkopien: im Leerlauf (nie waehrend eines Spiels) alle schattenkopien_stunden
# eine Schattenkopie jedes Laufwerks in schattenkopien_laufwerke anlegen. Windows loescht die
# aeltesten selbst, wenn sein Speicher voll ist; K9 loescht nie eine und aendert
# keinen Speicher. Laufwerke aendern: k9 funktion schattenkopien laufwerke C: F:
# --------------------------------------------------------------------------
[schutz]
schattenkopien = false
schattenkopien_stunden = 24
schattenkopien_laufwerke = ["C:"]
# firewall_sperre: ausgehende Verbindungen zu bekannten Botnetz-Steuerservern (abuse.ch Feodo
# Tracker, ThreatFox nur "botnet_cc" mit Sicherheit 100, hoechstens 30 Tage alt) in der
# Windows-Firewall sperren – genau Adresse und Port, hoechstens 1000. Entfernen jederzeit:
# k9 firewall entfernen. Risiko: geteilte Server-Adressen koennen mitgesperrt werden.
firewall_sperre = false

# --------------------------------------------------------------------------
# Arbeitsordner: Hier arbeiten andere Programme (z. B. Claude-Projekte, Builds).
# Verhaltensmeldungen (Ransomware-Verdacht durch viele Dateien, verdaechtige Befehlszeilen,
# Datendieb-Verdacht ...), deren Spuren nur hier liegen oder deren Programm von einem
# Arbeitsprogramm gestartet wurde, erscheinen nur leise im Dashboard (kein Meldefenster).
# Bekannte Schadsoftware (Hashlisten, YARA, ClamAV), Koederdateien und Selbstschutz
# werden hier immer normal gemeldet. Neue Eintraege schwaechen den Schutz und wirken erst
# nach deiner Bestaetigung: k9 arbeitsordner hinzufuegen "F:\Projekte"
# programme: nur mit gueltiger digitaler Signatur.
# --------------------------------------------------------------------------
[arbeitsordner]
aktiv = true
ordner = ["%TEMP%\\claude"]
programme = ["%USERPROFILE%\\.local\\bin\\claude.exe"]

# --------------------------------------------------------------------------
# Sicherheits-Check im Dashboard (nur lesen, K9 aendert keine Windows-Einstellung):
# Virenschutz, Firewall, Windows-Updates, Secure Boot, Benutzerkontensteuerung,
# Remotedesktop, Speicherintegritaet, letzte Datensicherung, veraltete Programme (winget).
# sicherung_ordner: Ordner deiner Datensicherung, z. B. ['E:\Sicherung'] (Platte darf
# abgesteckt sein, K9 merkt sich, wann es die neueste Sicherung zuletzt gesehen hat).
# wochenbericht: jede Woche eine Zusammenfassung als Meldefenster.
# heimnetz: neue Geraete im eigenen Netz melden (nie waehrend eines Spiels).
# --------------------------------------------------------------------------
[sicherheitscheck]
aktiv = true
programm_updates = true
sicherung_ordner = []
wochenbericht = true
heimnetz = true
# neue_luecken: einmal am Tag neue Sicherheitsluecken (CVE, Hoch/Kritisch) fuer installierte
# Programme melden, auch wenn sie noch nicht aktiv ausgenutzt werden (Quelle: NVD).
neue_luecken = true

[gaming]
# Gaming-Modus: während eines Spiels keine geplanten Scans, Meldungen werden
# gesammelt und danach zugestellt, der Agent bleibt nahezu ohne CPU-Last.
aktiv = true
# Vollbild-/D3D-Anwendungen, Präsentationsmodus und "Nicht stören" erkennen.
vollbild_erkennen = true
# Zusätzliche Spiel-Prozesse (Dateiname, z. B. "eldenring.exe").
spiele_prozesse = []
# Hilfsprogramme, die in einem Spieleordner liegen, aber KEIN Spiel sind (Fadenkreuz-Overlays,
# Hintergrundbild-Programme ...): Laufen nur sie, ist K9 nicht im Spielmodus.
keine_spiele = ["crosshairx.exe", "wallpaper32.exe", "wallpaper64.exe", "webwallpaper32.exe", "losslessscaling.exe", "soundpad.exe", "obs64.exe"]
# Prozesse aus diesen Ordnern gelten als Spiel (Teil des Pfades genügt).
spiele_ordner = [
    "\\steamapps\\common\\",
    "\\Epic Games\\",
    "\\GOG Galaxy\\Games\\",
    "\\GOG Games\\",
    "\\EA Games\\",
    "\\Electronic Arts\\",
    "\\Ubisoft Game Launcher\\games\\",
    "\\Battle.net\\Games\\",
    "\\Riot Games\\",
    "\\XboxGames\\",
]
# Kritische Funde trotz Spiel sofort per E-Mail/Handy melden (kein Popup).
kritische_sofort_extern = true
# Wie oft (Sekunden) der Agent prüft, ob gespielt wird.
pruefintervall_sekunden = 15

[meldungen]
# Mehrere Kanäle gleichzeitig möglich:
#   "fenster"   eigenes Meldefenster mit Quarantäne / Löschen / Freigabe / Später
#               (funktioniert auch, wenn Windows-Benachrichtigungen aus sind)
#   "popup"     Windows-Benachrichtigung (nur wenn diese in Windows eingeschaltet sind)
#   "dashboard" Browser-Dashboard, "email", "handy"
kanaele = ["fenster", "dashboard"]
# "Später" im Meldefenster: nach so vielen Minuten erneut fragen
# (spätestens beim nächsten Scan, der die Datei wieder findet).
spaeter_minuten = 60

[dashboard]
# Das Dashboard lauscht nur auf 127.0.0.1 (nicht aus dem Netzwerk erreichbar).
port = 47110

[email]
# Beispiel: smtp_server = "smtp.example.de", smtp_port = 465, verschluesselung = "tls"
smtp_server = ""
smtp_port = 465
# "tls" (meist Port 465) oder "starttls" (meist Port 587)
verschluesselung = "tls"
benutzer = ""
absender = ""
empfaenger = []

[handy]
# Push-Meldungen über ntfy (App "ntfy" für Android/iOS). Das Thema wirkt wie
# ein Passwort: lang und zufällig wählen. Optionaler Zugangstoken:
#   k9 geheimnis ntfy-token
server = "https://ntfy.sh"
thema = ""
# 1 = min … 5 = max
prioritaet = 4
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let c = Config::parse(DEFAULT_CONFIG).unwrap();
        let d = Config::default();
        assert_eq!(c.zeitplan, d.zeitplan);
        assert_eq!(c.scan.standard_pfade, d.scan.standard_pfade);
        assert_eq!(c.gaming.spiele_ordner, d.gaming.spiele_ordner);
        assert_eq!(c.email.smtp_port, d.email.smtp_port);
        assert_eq!(c.handy.server, d.handy.server);
        assert_eq!(c.zeitplan.len(), 1);
        assert_eq!(c.meldungen.kanaele, vec![Channel::Fenster, Channel::Dashboard]);
        assert_eq!(c.meldungen.spaeter_minuten, 60);
        assert_eq!(c.dashboard.port, 47110);
        assert!(c.gaming.aktiv);
        assert_eq!(c.arbeitsordner.ordner, d.arbeitsordner.ordner);
        assert_eq!(c.arbeitsordner.programme, d.arbeitsordner.programme);
        assert!(c.arbeitsordner.aktiv);
    }

    #[test]
    fn creates_file_on_first_run() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let p = dir.path().join("sub").join("config.toml");
        let c = Config::load_or_create(&p).unwrap();
        assert!(p.exists());
        assert_eq!(c.scan.max_dateigroesse_mb, 128);
    }

    #[test]
    fn partial_config_uses_defaults() {
        let c = Config::parse("[meldungen]\nkanaele = [\"email\", \"handy\"]\n").unwrap();
        assert_eq!(c.meldungen.kanaele, vec![Channel::Email, Channel::Handy]);
        assert_eq!(c.zeitplan.len(), 1, "fehlende Abschnitte nehmen die Standardwerte");
        assert_eq!(c.dashboard.port, 47110);
        assert!(Config::parse("[[zeitplan]]\nart = \"taeglich\"\nuhrzeit = \"99:00\"\n").is_err());
    }
}
