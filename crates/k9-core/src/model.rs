//! Detection data model.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What the user decided for a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Move into the obfuscated quarantine store (restorable).
    Quarantaene,
    /// Delete the file.
    Loeschen,
    /// Allow / ignore: never report this detection again.
    Freigabe,
    /// Disable an autostart entry (restorable).
    Deaktivieren,
    /// Update hint acknowledged (vulnerable software, visited bad URL).
    Gesehen,
    /// End a running process – only ever on the user's explicit choice.
    Beenden,
    /// Close this one finding without remembering anything ("Nur diesmal erlauben").
    Einmalig,
    /// Allow a rule for everything one work program (e.g. claude.exe) starts: later findings
    /// of this rule from that program are no longer opened. Only for quiet findings below
    /// "Kritisch"; remembered, signed by the service and revocable like every decision.
    Regelfreigabe,
}

impl Action {
    pub const ALL: [Action; 8] = [
        Action::Quarantaene,
        Action::Loeschen,
        Action::Freigabe,
        Action::Deaktivieren,
        Action::Gesehen,
        Action::Beenden,
        Action::Einmalig,
        Action::Regelfreigabe,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Quarantaene => "quarantaene",
            Action::Loeschen => "loeschen",
            Action::Freigabe => "freigabe",
            Action::Deaktivieren => "deaktivieren",
            Action::Gesehen => "gesehen",
            Action::Beenden => "beenden",
            Action::Einmalig => "einmalig",
            Action::Regelfreigabe => "regelfreigabe",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Action::Quarantaene => t!("Quarantäne", "Quarantine"),
            Action::Loeschen => t!("Löschen/Deaktivieren", "Delete/disable"),
            Action::Freigabe => t!("Freigabe", "Allow"),
            Action::Deaktivieren => t!("Deaktivieren", "Disable"),
            Action::Gesehen => t!("Hinweis gesehen", "Notice seen"),
            Action::Beenden => t!("Prozess beenden", "End process"),
            Action::Einmalig => t!("Nur diesmal erlauben", "Allow this once"),
            Action::Regelfreigabe => t!("Freigabe der Regel für ein Arbeitsprogramm", "Allow the rule for a work program"),
        }
    }

    /// True for decisions that only mean "do not report again".
    pub fn is_passive(self) -> bool {
        matches!(self, Action::Freigabe | Action::Gesehen | Action::Einmalig | Action::Regelfreigabe)
    }
}

/// What kind of thing a detection is about. Determines which actions exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A file on disk (also .url/.html/.eml files containing a malicious URL).
    #[default]
    Datei,
    /// Installed software with known exploited vulnerabilities (CVE).
    Software,
    /// Visited malicious URL (browser history) or hosts-file entry – nothing is modified.
    Url,
    /// Autostart entry (Run key, Startup folder, scheduled task, service).
    Autostart,
    /// Running process (suspicious start chain, malicious connection, ransomware behaviour).
    Prozess,
    /// Notice without an object to act on (self-protection: agent was stopped).
    Hinweis,
    /// Weakening change of a security setting in config.toml (needs confirmation).
    Einstellung,
    /// Kernel driver on a list of vulnerable/malicious drivers (or newly registered).
    Treiber,
    /// Browser extension, extension policy/registry install or browser shortcut (read only).
    Erweiterung,
    /// Inbound firewall rule that lets connections from anywhere in (see `eingang`).
    Firewall,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Datei => "datei",
            Kind::Software => "software",
            Kind::Url => "url",
            Kind::Autostart => "autostart",
            Kind::Prozess => "prozess",
            Kind::Hinweis => "hinweis",
            Kind::Einstellung => "einstellung",
            Kind::Treiber => "treiber",
            Kind::Erweiterung => "erweiterung",
            Kind::Firewall => "firewall",
        }
    }
    pub fn parse(s: &str) -> Kind {
        match s {
            "software" => Kind::Software,
            "url" => Kind::Url,
            "autostart" => Kind::Autostart,
            "prozess" => Kind::Prozess,
            "hinweis" => Kind::Hinweis,
            "einstellung" => Kind::Einstellung,
            "treiber" => Kind::Treiber,
            "erweiterung" => Kind::Erweiterung,
            "firewall" => Kind::Firewall,
            _ => Kind::Datei,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Kind::Datei => t!("Datei", "File"),
            Kind::Software => t!("Verwundbare Software", "Vulnerable software"),
            Kind::Url => t!("Schädliche Adresse", "Malicious address"),
            Kind::Autostart => t!("Autostart", "Autostart"),
            Kind::Prozess => t!("Verdächtiger Prozess", "Suspicious process"),
            Kind::Hinweis => t!("Hinweis", "Notice"),
            Kind::Einstellung => t!("Geänderte Sicherheitseinstellung", "Changed security setting"),
            Kind::Treiber => t!("Treiber", "Driver"),
            Kind::Erweiterung => t!("Browser-Erweiterung", "Browser extension"),
            Kind::Firewall => t!("Firewall-Regel", "Firewall rule"),
        }
    }

    /// Actions offered to the user for this kind (in button order).
    pub fn actions(self) -> &'static [Action] {
        match self {
            // "Einmalig" only when the file is gone (see pipeline::allowed_actions).
            Kind::Datei => &[Action::Quarantaene, Action::Loeschen, Action::Einmalig, Action::Freigabe],
            Kind::Software | Kind::Url => &[Action::Gesehen, Action::Freigabe],
            Kind::Autostart => &[Action::Deaktivieren, Action::Quarantaene, Action::Freigabe],
            // "Regelfreigabe" only for quiet findings of a work program (see pipeline::allowed_actions).
            Kind::Prozess => &[Action::Beenden, Action::Einmalig, Action::Quarantaene, Action::Freigabe, Action::Regelfreigabe],
            Kind::Hinweis => &[Action::Gesehen],
            Kind::Einstellung => &[Action::Freigabe, Action::Gesehen],
            Kind::Treiber => &[Action::Deaktivieren, Action::Gesehen, Action::Freigabe],
            // Removing is done in the browser (the finding explains how) – never by the scanner.
            Kind::Erweiterung => &[Action::Gesehen, Action::Freigabe],
            // Removing the rule only on the user's click (Loeschen = "Regel entfernen").
            Kind::Firewall => &[Action::Loeschen, Action::Freigabe, Action::Gesehen],
        }
    }

    /// Maps an action to this kind; `None` if not offered.
    /// "deaktivieren" on a file means delete (as in step 1).
    pub fn normalize(self, a: Action) -> Option<Action> {
        let a = match (self, a) {
            (Kind::Datei, Action::Deaktivieren) => Action::Loeschen,
            (Kind::Autostart, Action::Loeschen) => Action::Deaktivieren,
            (_, a) => a,
        };
        self.actions().contains(&a).then_some(a)
    }

    /// Button/label text of an action for this kind.
    pub fn action_label(self, a: Action) -> &'static str {
        match (self, a) {
            (Kind::Software, Action::Gesehen) => t!("Aktualisieren-Hinweis gesehen", "Update notice seen"),
            (Kind::Url | Kind::Hinweis | Kind::Erweiterung | Kind::Firewall, Action::Gesehen) => t!("Gesehen", "Seen"),
            (Kind::Firewall, Action::Loeschen) => t!("Regel entfernen", "Remove rule"),
            (Kind::Firewall, Action::Freigabe) => t!("Freigabe (diese Regel nicht mehr melden)", "Allow (do not report this rule again)"),
            (Kind::Software | Kind::Url, Action::Freigabe) => t!("Ignorieren", "Ignore"),
            (Kind::Autostart | Kind::Prozess, Action::Quarantaene) => t!("Datei in Quarantäne", "Quarantine the file"),
            (Kind::Prozess, Action::Freigabe) => t!("Freigabe (genau diese Befehlszeile)", "Allow (exactly this command line)"),
            (Kind::Einstellung, Action::Freigabe) => t!("Änderung übernehmen", "Accept the change"),
            (Kind::Treiber, Action::Deaktivieren) => t!("Treiber deaktivieren", "Disable driver"),
            (Kind::Treiber, Action::Freigabe) => t!("Ignorieren", "Ignore"),
            (Kind::Einstellung, Action::Gesehen) => t!("Ablehnen (bisherige Werte behalten)", "Reject (keep the previous values)"),
            _ => a.label(),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Action {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "quarantaene" | "quarantäne" | "q" => Ok(Action::Quarantaene),
            "loeschen" | "löschen" | "l" => Ok(Action::Loeschen),
            "freigabe" | "freigeben" | "ignorieren" | "f" => Ok(Action::Freigabe),
            "deaktivieren" | "d" => Ok(Action::Deaktivieren),
            "gesehen" | "g" => Ok(Action::Gesehen),
            "beenden" | "b" => Ok(Action::Beenden),
            "einmalig" | "diesmal" | "e" => Ok(Action::Einmalig),
            "regelfreigabe" => Ok(Action::Regelfreigabe),
            other => Err(format!(
                "Unbekannte Aktion '{other}' (erlaubt: quarantaene, loeschen, freigabe/ignorieren, deaktivieren, gesehen)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Niedrig,
    Mittel,
    Hoch,
    Kritisch,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Niedrig => "niedrig",
            Severity::Mittel => "mittel",
            Severity::Hoch => "hoch",
            Severity::Kritisch => "kritisch",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => t!("Info", "Info"),
            Severity::Niedrig => t!("Niedrig", "Low"),
            Severity::Mittel => t!("Mittel", "Medium"),
            Severity::Hoch => t!("Hoch", "High"),
            Severity::Kritisch => t!("Kritisch", "Critical"),
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "info" => Severity::Info,
            "niedrig" => Severity::Niedrig,
            "hoch" => Severity::Hoch,
            "kritisch" => Severity::Kritisch,
            _ => Severity::Mittel,
        }
    }
}

/// Threat category. Kept as free text in the database so new sources
/// (step 2: phishing lists, CVE feeds, PUA ...) can add categories.
pub mod category {
    pub const TEST: &str = "Test";
    pub const MALWARE: &str = "Schadsoftware";
}

/// Raw hit produced by an engine or check.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// File path, or a descriptive location for non-file kinds.
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    /// Stable rule identifier, e.g. `VS-TEST-0001` or `HASH:<sha256>`.
    pub rule_id: String,
    pub threat_name: String,
    pub category: String,
    pub severity: Severity,
    /// Engine that produced the finding (`hashliste`, `muster`, `yara`, `clamav`, `kev` ...).
    pub engine: String,
    pub kind: Kind,
    /// Kind-specific data (CVE list, autostart location, URL ...), stored as JSON.
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionStatus {
    /// Waiting for the user's decision.
    Offen,
    /// The user decided for this detection.
    Entschieden,
    /// A remembered decision was re-applied silently.
    Automatisch,
}

impl DetectionStatus {
    /// For the user (dashboard), in the active language.
    pub fn label(self) -> &'static str {
        match self {
            DetectionStatus::Offen => t!("offen", "open"),
            DetectionStatus::Entschieden => t!("entschieden", "decided"),
            DetectionStatus::Automatisch => t!("automatisch", "automatic"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DetectionStatus::Offen => "offen",
            DetectionStatus::Entschieden => "entschieden",
            DetectionStatus::Automatisch => "automatisch",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "entschieden" => DetectionStatus::Entschieden,
            "automatisch" => DetectionStatus::Automatisch,
            _ => DetectionStatus::Offen,
        }
    }
}

/// A stored detection (row of table `detections`).
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub rule_id: String,
    pub threat_name: String,
    pub category: String,
    pub severity: Severity,
    pub engine: String,
    pub first_seen: String,
    pub last_seen: String,
    pub status: DetectionStatus,
    pub action: Option<Action>,
    pub kind: Kind,
    pub details: Option<serde_json::Value>,
}

/// A remembered decision (row of table `decisions`).
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub id: i64,
    pub sha256: String,
    pub rule_id: String,
    pub threat_name: String,
    pub action: Action,
    pub decided_at: String,
    pub note: Option<String>,
    /// Signature of the Windows service (hex); see `schutz`.
    pub signature: Option<String>,
}

/// A quarantined file (row of table `quarantine`).
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineEntry {
    pub id: i64,
    pub detection_id: Option<i64>,
    pub original_path: String,
    pub stored_file: String,
    pub sha256: String,
    pub size: u64,
    pub threat_name: String,
    pub quarantined_at: String,
    pub restored_at: Option<String>,
    #[serde(skip)]
    pub key: Vec<u8>,
    #[serde(skip)]
    pub sddl: Option<String>,
}
