//! Language of every text the user sees: German (the language K9 was written in, default
//! inside the library) or English.
//!
//! Both versions of a text stand next to each other in the code:
//! `t!("Deutsch", "English")` for fixed texts and `tf!("Wert {}", "value {}", x)` for texts
//! with inserted values. The compiler checks both, so no text can be forgotten and no
//! placeholder can be mixed up.
//!
//! The programs choose the language once at start-up from `sprache` in config.toml
//! ("de", "en" or "auto" = the display language of Windows). Unit tests never call
//! [`apply`]: they always see German, whatever the PC is set to. Findings that are already
//! stored keep the language they were written in.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sprache {
    De,
    En,
}

static AKTIV: AtomicU8 = AtomicU8::new(0);

/// Overrides `sprache` in config.toml (used by the end-to-end test, which compares German
/// output).
pub const ENV: &str = "K9_SPRACHE";

pub fn set(s: Sprache) {
    AKTIV.store(s as u8, Ordering::Relaxed);
}

thread_local! {
    /// Language for the current thread only (tests of the English texts).
    static HIER: std::cell::Cell<Option<Sprache>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with another language on this thread only – other threads are not affected.
pub fn with<R>(s: Sprache, f: impl FnOnce() -> R) -> R {
    let before = HIER.with(|h| h.replace(Some(s)));
    let r = f();
    HIER.with(|h| h.set(before));
    r
}

pub fn aktiv() -> Sprache {
    if let Some(s) = HIER.with(|h| h.get()) {
        return s;
    }
    if AKTIV.load(Ordering::Relaxed) == Sprache::En as u8 {
        Sprache::En
    } else {
        Sprache::De
    }
}

/// English is active.
pub fn en() -> bool {
    aktiv() == Sprache::En
}

/// "de"/"deutsch", "en"/"english"; anything else ("auto", empty, unknown) means: decide by
/// the display language of Windows.
pub fn parse(value: &str) -> Option<Sprache> {
    match value.trim().to_ascii_lowercase().as_str() {
        "de" | "deutsch" | "german" => Some(Sprache::De),
        "en" | "englisch" | "english" => Some(Sprache::En),
        _ => None,
    }
}

/// German Windows -> German, every other display language -> English.
pub fn from_windows(lang_id: u16) -> Sprache {
    // The low 10 bits are the primary language; 0x07 is German (de-DE, de-AT, de-CH ...).
    if lang_id & 0x3ff == 0x07 {
        Sprache::De
    } else {
        Sprache::En
    }
}

/// The language for a value of `sprache` in config.toml.
pub fn resolve(config_value: &str) -> Sprache {
    let env = std::env::var(ENV).unwrap_or_default();
    parse(&env).or_else(|| parse(config_value)).unwrap_or_else(|| {
        // SAFETY: no arguments, returns a language identifier.
        from_windows(unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() })
    })
}

/// Called once by agent, k9 and the service after the configuration is read.
pub fn apply(config_value: &str) {
    if cfg!(test) {
        return;
    }
    set(resolve(config_value));
}

/// English for the fixed texts of constant tables (`const` data cannot call `t!`).
/// Every table that is shown to the user has a test that all its texts are listed here.
const TABELLE: &[(&str, &str)] = &[
    // infostealer::GROUPS
    ("Google Chrome (Passwörter, Cookies)", "Google Chrome (passwords, cookies)"),
    ("Microsoft Edge (Passwörter, Cookies)", "Microsoft Edge (passwords, cookies)"),
    ("Brave (Passwörter, Cookies)", "Brave (passwords, cookies)"),
    ("Vivaldi (Passwörter, Cookies)", "Vivaldi (passwords, cookies)"),
    ("Opera (Passwörter, Cookies)", "Opera (passwords, cookies)"),
    ("Firefox (Passwörter, Cookies)", "Firefox (passwords, cookies)"),
    ("Thunderbird (Passwörter)", "Thunderbird (passwords)"),
    ("Steam (Anmeldung)", "Steam (sign-in)"),
    ("Discord (Anmeldung)", "Discord (sign-in)"),
    ("Telegram (Sitzung)", "Telegram (session)"),
    ("Krypto-Wallet", "Crypto wallet"),
    // schutz::SCHALTER and schutz::LISTEN
    ("ClamAV", "ClamAV"),
    ("Scan-Cache", "Scan cache"),
    ("YARA-Regeln", "YARA rules"),
    ("YARA-Regeln: erweitertes Paket", "YARA rules: extended package"),
    ("ClamAV: unerwünschte Programme", "ClamAV: unwanted programs"),
    ("abuse.ch-Listen", "abuse.ch lists"),
    ("OpenPhish-Liste", "OpenPhish list"),
    ("Phishing-Filter-Liste", "Phishing filter list"),
    ("VirusTotal-Abfrage", "VirusTotal lookup"),
    ("Schwachstellen-Prüfung (CVE)", "Vulnerability check (CVE)"),
    ("Browserverlauf prüfen", "Check browser history"),
    ("Treiber-Listen", "Driver lists"),
    ("Liste schädlicher Browser-Erweiterungen", "List of malicious browser extensions"),
    ("Sigma-Regeln für Programmstarts", "Sigma rules for program starts"),
    ("LOLBAS-Regeln für Programmstarts", "LOLBAS rules for program starts"),
    ("große Liste von Schad-Domains (HaGeZi)", "large list of malicious domains (HaGeZi)"),
    ("Liste gekaperter Netze (Spamhaus DROP)", "List of hijacked networks (Spamhaus DROP)"),
    ("Echtzeitschutz", "Real-time protection"),
    ("Programmstarts prüfen", "Check program starts"),
    ("Autostarts prüfen", "Check autostarts"),
    ("Netzwerk prüfen", "Check network"),
    ("Ransomware-Erkennung", "Ransomware detection"),
    ("Ransomware-Meldung auch während eines Spiels", "Ransomware alert also during a game"),
    ("Verdächtige Prozesse anhalten (Ransomware)", "Suspend suspicious processes (ransomware)"),
    ("USB prüfen", "Check USB"),
    ("ClamAV in Echtzeit", "ClamAV in real time"),
    ("Schutz vor Datendieben (Infostealer)", "Protection against data thieves (infostealers)"),
    ("PowerShell-Skriptprüfung", "PowerShell script check"),
    ("Programme aus dem Internet melden", "Report programs from the internet"),
    ("Angriffsketten", "Attack chains"),
    ("Konten und Anmeldungen überwachen", "Watch accounts and sign-ins"),
    ("Kritische Programme anhalten", "Suspend critical programs"),
    ("Neue Programme aus dem Internet anhalten", "Suspend new programs from the internet"),
    ("Speicher-Scan im Leerlauf", "Memory scan when idle"),
    ("Ähnliche Domains melden", "Report look-alike domains"),
    ("Schattenkopien im Leerlauf", "Shadow copies when idle"),
    ("Firewall-Sperre", "Firewall block"),
    ("Arbeitsordner (leise Meldungen)", "Work folders (quiet findings)"),
    ("Sicherheits-Check", "Security check"),
    ("Veraltete Programme anzeigen", "Show outdated programs"),
    ("Wochenbericht", "Weekly report"),
    ("Neue Geräte im Heimnetz", "New devices in the home network"),
    ("Neue Sicherheitslücken melden", "Report new vulnerabilities"),
    ("Spielmodus", "Gaming mode"),
    ("Spiele an Vollbild erkennen", "Detect games by full screen"),
    ("Kritische Meldungen während eines Spiels per E-Mail/Handy", "Critical alerts during a game by e-mail/phone"),
    ("Standardpfade", "Standard paths"),
    ("Neue Scan-Ausnahme", "New scan exclusion"),
    ("Überwachte Ordner geändert", "Watched folders changed"),
    ("Zusätzlich überwachter Ordner entfernt", "Additionally watched folder removed"),
    ("Neues Spiel (Programm)", "New game (program)"),
    ("Neuer Spiele-Ordner", "New games folder"),
    ("Hilfsprogramm gilt wieder als Spiel", "Helper program counts as a game again"),
    ("Neuer Arbeitsordner", "New work folder"),
    ("Neues Arbeitsprogramm", "New work program"),
    ("Sicherungsordner", "Backup folder"),
    ("Meldekanal entfernt", "Alert channel removed"),
    ("E-Mail-Empfänger", "E-mail recipient"),
    ("Eigene Marke entfernt", "Own brand removed"),
    ("Laufwerk für Schattenkopien entfernt", "Drive for shadow copies removed"),
    ("Zeitpläne", "Schedules"),
    ("Einstellung", "Setting"),
    // ransom_wache::REASON
    ("viele Dateien wurden in kurzer Zeit verschlüsselt/überschrieben", "many files were encrypted/overwritten within a short time"),
    // model::category
    ("Schadsoftware", "Malware"),
    // skripte::RULES
    ("PowerShell-Skript schaltet die Schadsoftware-Prüfung von Windows (AMSI) ab", "PowerShell script switches off the malware check of Windows (AMSI)"),
    ("PowerShell-Skript löscht Schattenkopien oder Sicherungen – typisch für Ransomware", "PowerShell script deletes shadow copies or backups – typical for ransomware"),
    (
        "PowerShell-Skript greift auf gespeicherte Zugangsdaten zu (Browser, Steam, Discord, Telegram, Wallets)",
        "PowerShell script accesses stored sign-in data (browsers, Steam, Discord, Telegram, wallets)",
    ),
    ("PowerShell-Skript lädt Code aus dem Internet und führt ihn aus", "PowerShell script downloads code from the internet and runs it"),
    ("PowerShell-Skript lädt eine Datei aus dem Internet und startet sie", "PowerShell script downloads a file from the internet and starts it"),
    ("PowerShell-Skript lädt ein verstecktes Programm direkt in den Speicher", "PowerShell script loads a hidden program directly into memory"),
    ("PowerShell-Skript versucht, den Virenschutz abzuschwächen", "PowerShell script tries to weaken the virus protection"),
];

/// "de" or "en": stored with texts that are written once and shown later (security check).
pub fn code() -> &'static str {
    if en() {
        "en"
    } else {
        "de"
    }
}

/// Parts of texts that K9 stores in German and shows later (lines under "Letzte Aktionen",
/// the state of the detection sources). Longer parts first. Texts of other programs (winget)
/// stay as they are.
const GESPEICHERT: &[(&str, &str)] = &[
    (
        ": nicht möglich – winget kann dieses Update auf deinem PC nicht installieren, aus der Liste genommen (bitte über das Programm selbst oder die Herstellerseite aktualisieren)",
        ": not possible – winget cannot install this update on your PC, removed from the list (please update via the program itself or the publisher's page)",
    ),
    ("Dieses Programm lässt sich nur mit Administratorrechten aktualisieren", "This program can only be updated with administrator rights"),
    ("; K9 startet winget ohne diese Rechte.", "; K9 starts winget without these rights."),
    ("So geht es: Rechtsklick auf das Startmenü, „Terminal (Administrator)“ öffnen und eingeben:", "This is how: right-click the Start menu, open “Terminal (Admin)” and enter:"),
    ("Von Hand geht es so: Rechtsklick auf das Startmenü, „Terminal (Administrator)“ öffnen und eingeben:", "By hand it works like this: right-click the Start menu, open “Terminal (Admin)” and enter:"),
    ("Auch mit Administratorrechten meldete winget einen Fehler", "winget reported an error with administrator rights as well"),
    ("Die Windows-Abfrage dazu wurde nicht mit „Ja“ bestätigt.", "The Windows question for it was not confirmed with “Yes”."),
    ("Noch einmal „Aktualisieren“ wählen und im Fenster von Windows „Ja“ wählen.", "Choose “Update” again and choose “Yes” in the window of Windows."),
    ("mit Administratorrechten aktualisiert", "updated with administrator rights"),
    ("auch der zweite Versuch nach dem Erneuern des winget-Katalogs", "also at the second attempt after refreshing the winget catalogue"),
    ("der Download bei winget ist hängen geblieben (seit über 4 Minuten kein Fortschritt) – beendet", "the download in winget got stuck (no progress for over 4 minutes) – ended"),
    ("Installationsprogramm beendet (Code ", "setup program ended (code "),
    ("), winget meldet aber weiter eine neuere Version", "), but winget still reports a newer version"),
    ("die Datei wurde nach der Bestätigung verändert – nicht gestartet", "the file was changed after the confirmation – not started"),
    ("geladen und geprüft: ", "downloaded and checked: "),
    ("nicht geladen: ", "not downloaded: "),
    ("von dir abgebrochen", "cancelled by you"),
    ("nicht über winget", "not via winget"),
    ("keine bestätigte Datei", "no confirmed file"),
    ("nicht gestartet: ", "not started: "),
    (" Still installieren ", " Install silently "),
    (" Suchen und Laden ", " Search and download "),
    ("Suchen und Laden (", "Search and download ("),
    (") ohne Erfolg: ", ") without success: "),
    (" Aktualisieren ", " Update "),
    (" Deinstallieren ", " Uninstall "),
    (" Installieren ", " Install "),
    (": erledigt", ": done"),
    (": fehlgeschlagen", ": failed"),
    ("(signiert von ", "(signed by "),

    // state of the detection sources
    (" Regeln für Programmstarts, davon ", " rules for program starts, of which "),
    (" aus dem Zusatzpaket und ", " from the add-on package and "),
    (" mit den Angaben von K9 nie auslösbar; ", " can never fire with the data K9 has; "),
    (" nicht auswertbar)", " cannot be evaluated)"),
    (" und Emerging Threats", " and Emerging Threats"),
    (" Regeln der Stufe mittel für Programmstarts (davon ", " rules of level medium for program starts (of which "),
    (" nie auslösbar), ausgewählt über ", " can never fire), selected via "),
    (" LOLBAS-Programmen", " LOLBAS programs"),
    ("(neueste Proben ", "(newest samples "),
];

/// A stored German text in the active language (see GESPEICHERT).
pub fn stored(text: &str) -> String {
    if !en() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for (de, en) in GESPEICHERT {
        if out.contains(de) {
            out = out.replace(de, en);
        }
    }
    if out.contains(" selected via ") {
        out = out.replace(" von ", " of ");
    }
    out
}

/// The English text for a fixed German text of a constant table (German: unchanged).
pub fn tr(de: &str) -> &str {
    if !en() {
        return de;
    }
    english(de).unwrap_or(de)
}

/// The English text of the table, if there is one (for the tests of the tables).
pub fn english(de: &str) -> Option<&'static str> {
    TABELLE.iter().find(|(d, _)| *d == de).map(|(_, e)| *e)
}

/// A fixed text in the active language: `t!("Deutsch", "English")`.
#[macro_export]
macro_rules! t {
    ($de:expr, $en:expr $(,)?) => {
        if $crate::sprache::en() {
            $en
        } else {
            $de
        }
    };
}

/// A text with inserted values in the active language:
/// `tf!("Datei {} fehlt", "File {} is missing", name)`. Both texts get the same arguments.
#[macro_export]
macro_rules! tf {
    ($de:literal, $en:literal $(, $($arg:tt)*)?) => {
        if $crate::sprache::en() {
            format!($en $(, $($arg)*)?)
        } else {
            format!($de $(, $($arg)*)?)
        }
    };
}

/// Like `write!`, in the active language: `tw!(out, "Datei {}", "File {}", name)`.
#[macro_export]
macro_rules! tw {
    ($dst:expr, $de:literal, $en:literal $(, $($arg:tt)*)?) => {
        if $crate::sprache::en() {
            write!($dst, $en $(, $($arg)*)?)
        } else {
            write!($dst, $de $(, $($arg)*)?)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_values_and_windows_language() {
        assert_eq!(parse("de"), Some(Sprache::De));
        assert_eq!(parse(" EN "), Some(Sprache::En));
        assert_eq!(parse("english"), Some(Sprache::En));
        assert_eq!(parse("auto"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("fr"), None, "unbekannt: Windows entscheidet");
        assert_eq!(from_windows(0x0407), Sprache::De, "de-DE");
        assert_eq!(from_windows(0x0c07), Sprache::De, "de-AT");
        assert_eq!(from_windows(0x0409), Sprache::En, "en-US");
        assert_eq!(from_windows(0x040c), Sprache::En, "fr-FR: Englisch");
    }

    #[test]
    fn both_languages_side_by_side() {
        // Inside tests the library stays German; `apply` does nothing here.
        apply("en");
        assert_eq!(aktiv(), Sprache::De);
        assert_eq!(t!("Datei", "File"), "Datei");
        let n = 3;
        assert_eq!(tf!("{n} Dateien in {}", "{n} files in {}", "C:\\x"), "3 Dateien in C:\\x");
        assert_eq!(tf!("ohne Wert", "no value"), "ohne Wert");
        // English for one thread only.
        with(Sprache::En, || {
            assert_eq!(t!("Datei", "File"), "File");
            assert_eq!(tf!("{n} Dateien in {}", "{n} files in {}", "C:\\x"), "3 files in C:\\x");
        });
        assert_eq!(t!("Datei", "File"), "Datei");
    }
}
