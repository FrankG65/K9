//! `k9 funktion`: switching single functions on/off in config.toml without breaking the
//! file. Only the one `key = true/false` line changes (comments stay); a missing section or
//! key is added once. The result is checked by parsing it before anything is written.

use anyhow::{bail, Result};

use crate::config::Config;

/// A function that `k9 funktion` switches.
pub struct Funktion {
    pub name: &'static str,
    pub section: &'static str,
    pub key: &'static str,
    /// The service follows the switch without a restart (within about 30 seconds).
    pub live: bool,
}

pub const FUNKTIONEN: &[Funktion] = &[
    Funktion { name: "anhalten", section: "echtzeit", key: "kritische_prozesse_anhalten", live: true },
    Funktion { name: "ransomware-anhalten", section: "echtzeit", key: "ransomware_prozess_anhalten", live: false },
    Funktion { name: "neue-programme", section: "echtzeit", key: "neue_programme_anhalten", live: false },
    Funktion { name: "virustotal", section: "quellen", key: "virustotal_aktiv", live: true },
    Funktion { name: "sigma", section: "quellen", key: "sigma_aktiv", live: true },
    Funktion { name: "lolbas", section: "quellen", key: "lolbas_aktiv", live: true },
    Funktion { name: "yara-erweitert", section: "quellen", key: "yara_erweitert", live: true },
    Funktion { name: "schad-domains", section: "quellen", key: "hagezi_tif_aktiv", live: true },
    Funktion { name: "spamhaus-drop", section: "quellen", key: "spamhaus_drop_aktiv", live: true },
    Funktion { name: "firewall", section: "schutz", key: "firewall_sperre", live: true },
    Funktion { name: "schattenkopien", section: "schutz", key: "schattenkopien", live: true },
    Funktion { name: "angriffsketten", section: "echtzeit", key: "angriffsketten", live: true },
    Funktion { name: "download-herkunft", section: "echtzeit", key: "download_herkunft", live: true },
    Funktion { name: "skriptpruefung", section: "echtzeit", key: "powershell_skripte", live: false },
    Funktion { name: "datendiebe", section: "echtzeit", key: "infostealer", live: false },
    Funktion { name: "anmeldungen", section: "echtzeit", key: "anmeldungen", live: true },
    Funktion { name: "speicher-scan", section: "echtzeit", key: "speicher_scan", live: true },
    Funktion { name: "sicherheitscheck", section: "sicherheitscheck", key: "aktiv", live: true },
    Funktion { name: "programm-updates", section: "sicherheitscheck", key: "programm_updates", live: true },
    Funktion { name: "wochenbericht", section: "sicherheitscheck", key: "wochenbericht", live: true },
    Funktion { name: "heimnetz", section: "sicherheitscheck", key: "heimnetz", live: true },
    Funktion { name: "neue-luecken", section: "sicherheitscheck", key: "neue_luecken", live: true },
];

pub fn find(name: &str) -> Option<&'static Funktion> {
    let n = name.trim().to_lowercase();
    FUNKTIONEN.iter().find(|f| f.name == n)
}

impl Funktion {
    pub fn path(&self) -> String {
        format!("{}.{}", self.section, self.key)
    }

    pub fn label(&self) -> &'static str {
        crate::schutz::switch_label(&self.path())
    }

    /// The value in a configuration.
    pub fn value(&self, c: &Config) -> bool {
        let v = serde_json::to_value(c).unwrap_or_default();
        v.get(self.section).and_then(|s| s.get(self.key)).and_then(|b| b.as_bool()).unwrap_or(false)
    }
}

/// Name of a `[section]` header line (not `[[array]]`), comments ignored.
fn header(line: &str) -> Option<String> {
    let t = line.split('#').next().unwrap_or("").trim();
    if t.starts_with("[[") || !t.starts_with('[') || !t.ends_with(']') {
        return None;
    }
    Some(t[1..t.len() - 1].trim().to_string())
}

fn is_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

/// `key = …` line (not commented out).
fn is_key(line: &str, key: &str) -> bool {
    let t = line.trim_start();
    t.strip_prefix(key).is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// config.toml text with `section.key` set to `value`. Fails (nothing to write) if the
/// file is broken or the change could not be made safely.
pub fn set_bool(text: &str, f: &Funktion, value: bool) -> Result<String> {
    let v = if value { "true" } else { "false" };
    set_line(text, f.section, f.key, v, |c| f.value(c) == value)
}

/// "c", "C:", "C:\\" -> "C:"; anything else (more than one letter, other characters) -> None.
/// Only this form ever reaches a PowerShell command of the service.
pub fn drive_letter(cfg: &str) -> Option<String> {
    let t = cfg.trim().trim_end_matches('\\').trim_end_matches(':');
    let mut c = t.chars();
    match (c.next(), c.next()) {
        (Some(d), None) if d.is_ascii_alphabetic() => Some(format!("{}:", d.to_ascii_uppercase())),
        _ => None,
    }
}

/// The drives of a list, each once, in order (invalid entries are skipped).
pub fn drives(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in list.iter().filter_map(|d| drive_letter(d)) {
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// config.toml text with the shadow copy drives set to `list` (already checked letters).
pub fn set_drives(text: &str, list: &[String]) -> Result<String> {
    if list.is_empty() || drives(list) != list {
        bail!("Ungueltige Laufwerke – bitte z. B. so angeben: C: F:");
    }
    let literal = format!("[{}]", list.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", "));
    set_line(text, "schutz", "schattenkopien_laufwerke", &literal, |c| c.schutz.schattenkopien_laufwerke == list)
}

/// config.toml text with `section.key = v` (a TOML value); `check` confirms the result.
pub fn set_value(text: &str, section: &str, key: &str, v: &str, check: impl Fn(&Config) -> bool) -> Result<String> {
    set_line(text, section, key, v, check)
}

/// config.toml text with the language set ("auto", "de" or "en"). `sprache` is a key without a
/// section, so its line has to stand before the first `[section]`.
pub fn set_language(text: &str, value: &str) -> Result<String> {
    // A file saved with a byte order mark (Notepad, PowerShell 5): the new first line goes
    // behind the mark, otherwise the mark would end up in the middle of the file.
    if let Some(rest) = text.strip_prefix('\u{feff}') {
        return Ok(format!("\u{feff}{}", set_language(rest, value)?));
    }
    if !matches!(value, "auto" | "de" | "en") {
        bail!(t!("Bitte de, en oder auto angeben", "Please give de, en or auto"));
    }
    if Config::parse(text).is_err() {
        bail!(t!("config.toml enthaelt einen Fehler – bitte zuerst von Hand korrigieren", "config.toml contains an error – please correct it by hand first"));
    }
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let first_header = lines.iter().position(|l| is_header(l)).unwrap_or(lines.len());
    let new = format!("sprache = \"{value}\"");
    match (0..first_header).find(|&i| is_key(&lines[i], "sprache")) {
        Some(i) => lines[i] = new,
        None => lines.insert(0, new),
    }
    let out = lines.join(nl) + nl;
    match Config::parse(&out) {
        Ok(c) if c.sprache == value => Ok(out),
        _ => bail!(t!("Die Sprache liess sich nicht sicher eintragen – config.toml bleibt unveraendert", "The language could not be entered safely – config.toml stays unchanged")),
    }
}

fn set_line(text: &str, section: &str, key: &str, v: &str, check: impl Fn(&Config) -> bool) -> Result<String> {
    if Config::parse(text).is_err() {
        bail!("config.toml enthaelt einen Fehler – bitte zuerst von Hand korrigieren");
    }
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    match lines.iter().position(|l| header(l).as_deref() == Some(section)) {
        Some(h) => {
            let end = lines[h + 1..].iter().position(|l| is_header(l)).map_or(lines.len(), |i| h + 1 + i);
            match (h + 1..end).find(|&i| is_key(&lines[i], key)) {
                Some(i) => {
                    let indent: String = lines[i].chars().take_while(|c| c.is_whitespace()).collect();
                    let comment = lines[i].find('#').map(|p| lines[i][p..].to_string());
                    let old_value = lines[i].split('#').next().unwrap_or("").to_string();
                    // Keep the alignment of the comment where possible.
                    let mut new = format!("{indent}{key} = {v}");
                    if let Some(c) = comment {
                        let width = old_value.trim_end().len().max(new.len());
                        let pad = old_value.len().saturating_sub(width).max(1);
                        new = format!("{new:<width$}{}{c}", " ".repeat(pad));
                    }
                    lines[i] = new;
                }
                None => {
                    // After the last line of the section that is not empty.
                    let at = (h + 1..end).rev().find(|&i| !lines[i].trim().is_empty()).map_or(h + 1, |i| i + 1);
                    lines.insert(at, format!("{key} = {v}"));
                }
            }
        }
        None => {
            if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.push(format!("[{section}]"));
            lines.push(format!("{key} = {v}"));
        }
    }
    let mut out = lines.join(nl);
    out.push_str(nl);
    match Config::parse(&out) {
        Ok(c) if check(&c) => Ok(out),
        _ => bail!("config.toml konnte nicht sicher geaendert werden – bitte „{key} = {v}“ im Abschnitt [{section}] von Hand eintragen"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str) -> &'static Funktion {
        find(name).unwrap()
    }

    #[test]
    fn every_function_is_a_protective_switch_of_the_configuration() {
        for x in FUNKTIONEN {
            assert!(crate::schutz::SCHALTER.iter().any(|s| s.0 == x.path() && s.1 == crate::schutz::Wirkung::Schuetzt), "{}", x.path());
        }
    }

    #[test]
    fn the_language_goes_before_the_first_section_and_only_once() {
        let text = "# Kommentar\n[scan]\ncache = true\n";
        let en = set_language(text, "en").unwrap();
        assert!(en.starts_with("sprache = \"en\"\n# Kommentar\n"), "{en}");
        assert_eq!(Config::parse(&en).unwrap().sprache, "en");
        let auto = set_language(&en, "auto").unwrap();
        assert_eq!(auto.matches("sprache").count(), 1, "{auto}");
        assert_eq!(Config::parse(&auto).unwrap().sprache, "auto");
        assert_eq!(set_language(&auto, "auto").unwrap(), auto);
        assert!(set_language(text, "fr").is_err());
        assert!(set_language("[scan\n", "en").is_err());
        // With a byte order mark (PowerShell 5 "Out-File -Encoding utf8"): the mark stays first.
        let bom = set_language("\u{feff}zeitplan = []\n[scan]\ncache = true\n", "en").unwrap();
        assert!(bom.starts_with("\u{feff}sprache = \"en\"\nzeitplan = []"), "{bom:?}");
        assert_eq!(Config::parse(&bom).unwrap().sprache, "en");
    }

    #[test]
    fn missing_sections_are_added_once_and_a_second_run_changes_nothing() {
        let text = "# Kommentar\n[scan]\ncache = true\n\n[[zeitplan]]\nname = \"Leerlauf-Scan\"\nart = \"leerlauf\"\nminuten = 20\n";
        Config::parse(text).unwrap();
        let once = set_bool(text, f("virustotal"), true).unwrap();
        let twice = set_bool(&once, f("virustotal"), true).unwrap();
        assert_eq!(once, twice);
        assert_eq!(once.matches("[quellen]").count(), 1);
        assert!(once.starts_with("# Kommentar\n"));
    }

    #[test]
    fn the_default_file_keeps_its_comments_and_line_endings() {
        let text = crate::config::DEFAULT_CONFIG.replace("\r\n", "\n").replace('\n', "\r\n");
        for x in FUNKTIONEN {
            for on in [true, false] {
                let out = set_bool(&text, x, on).unwrap();
                assert!(x.value(&Config::parse(&out).unwrap()) == on, "{}", x.name);
                assert_eq!(out.lines().count(), text.lines().count(), "{}: nur die eine Zeile", x.name);
                assert!(!out.replace("\r\n", "").contains('\n'), "Zeilenenden");
                let comments = |s: &str| s.lines().filter(|l| l.trim_start().starts_with('#')).count();
                assert_eq!(comments(&out), comments(&text));
                assert_eq!(set_bool(&out, x, on).unwrap(), out, "{}: zweimal = einmal", x.name);
            }
        }
    }

    #[test]
    fn a_key_missing_in_an_existing_section_is_added_there() {
        let text = "[echtzeit]\naktiv = true # an\n\n[schutz]\nschattenkopien = false\n";
        let out = set_bool(text, f("anhalten"), true).unwrap();
        assert_eq!(out, "[echtzeit]\naktiv = true # an\nkritische_prozesse_anhalten = true\n\n[schutz]\nschattenkopien = false\n");
        let out = set_bool(text, f("schattenkopien"), true).unwrap();
        assert!(out.ends_with("[schutz]\nschattenkopien = true\n"), "{out}");
    }

    #[test]
    fn the_drive_list_is_written_once_and_only_clean_letters_are_accepted() {
        let d = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(drives(&d(&["C:", "f", "c:\\", "x;y", "F:"])), d(&["C:", "F:"]));
        for bad in ["", "CD:", "C:\\x", "1:", "C;", "C:'; Remove-Item x", "Ü:"] {
            assert_eq!(drive_letter(bad), None, "{bad}");
        }
        let text = crate::config::DEFAULT_CONFIG;
        let out = set_drives(text, &d(&["C:", "F:"])).unwrap();
        assert_eq!(Config::parse(&out).unwrap().schutz.schattenkopien_laufwerke, d(&["C:", "F:"]));
        assert_eq!(out.lines().count(), text.lines().count());
        assert_eq!(set_drives(&out, &d(&["C:", "F:"])).unwrap(), out);
        // A file without the section (as an older installation has it): appended once.
        let out = set_drives("[scan]\ncache = true\n", &d(&["C:", "F:"])).unwrap();
        assert!(out.ends_with("[schutz]\nschattenkopien_laufwerke = [\"C:\", \"F:\"]\n"), "{out}");
        assert!(set_drives(text, &d(&["C:", "x;y"])).is_err());
        assert!(set_drives(text, &[]).is_err());
        // The older single-drive key still counts while the list is missing.
        let old = Config::parse("[schutz]\nschattenkopien_laufwerk = \"D:\"\n").unwrap();
        assert_eq!(old.schutz.schattenkopien_laufwerke, d(&["D:"]));
        let both = Config::parse("[schutz]\nschattenkopien_laufwerk = \"D:\"\nschattenkopien_laufwerke = [\"C:\", \"F:\"]\n").unwrap();
        assert_eq!(both.schutz.schattenkopien_laufwerke, d(&["C:", "F:"]));
    }

    #[test]
    fn broken_files_and_unsafe_changes_are_refused() {
        assert!(set_bool("[schutz]\nfirewall_sperre = ja\n", f("firewall"), true).is_err());
        // A dotted key elsewhere: the change would not take effect -> refused, nothing written.
        assert!(set_bool("schutz.firewall_sperre = false\n", f("firewall"), true).is_err());
    }
}
