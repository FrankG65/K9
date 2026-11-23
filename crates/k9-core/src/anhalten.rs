//! Freezing a suspicious process until the user decides (opt-in, `echtzeit.kritische_prozesse_anhalten`,
//! default off): only for critical findings of a process (attack chain, credential theft,
//! critical PowerShell script), never for games, anti-cheat, Windows components, programs
//! signed by Microsoft or Trend Micro, or the K9 itself. The process is suspended,
//! never ended; "Prozess beenden" or "weiterlaufen lassen" in the Meldefenster decides.
//! It is never resumed automatically.

use crate::model::{Finding, Kind, Severity};

/// Parts of program paths/names of anti-cheat systems (lower case).
const ANTI_CHEAT: &[&str] = &[
    "easyanticheat", "\\beservice", "battleye", "\\vgc.exe", "\\vgk", "\\riot vanguard\\", "faceit", "eaanticheat", "ricochet", "xigncode",
    "gameguard", "nprotect", "mhyprot", "\\anticheat", "anti-cheat", "\\pnkbstr",
];

/// Critical findings of a process that may be frozen.
pub fn qualifies(f: &Finding) -> bool {
    f.severity == Severity::Kritisch
        && f.kind == Kind::Prozess
        && ["KETTE:", "INFOSTEALER:", "SKRIPT:"].iter().any(|p| f.rule_id.starts_with(p))
}

/// A finding of the file check on a program that has just been started: is it certain enough
/// to freeze the program at once? Yes for known malware (hash lists), the built-in patterns
/// and clear YARA/ClamAV families of severity Hoch or Kritisch – not for mere suspicion rules
/// (YARA "indicator"/"suspicious", ClamAV "PUA"), which also hit installers and tools.
pub fn known_malware_at_start(f: &Finding) -> bool {
    let rule = f.rule_id.to_uppercase();
    if rule.starts_with("HASH:") || f.engine == "muster" {
        return true;
    }
    let family = (rule.starts_with("YARA:") && !rule.contains("INDICATOR") && !rule.contains("SUSP")) || (rule.starts_with("CLAMAV:") && !rule.starts_with("CLAMAV:PUA."));
    family && f.severity >= Severity::Hoch
}

/// May this program be frozen? `Err` gives the reason why not.
pub fn freeze_allowed(path: &str, signer: Option<&str>, game_dirs: &[String], game_names: &[String], own_dir: &str) -> Result<(), &'static str> {
    let p = path.to_lowercase();
    if !std::path::Path::new(path).is_absolute() {
        return Err("Programm nicht sicher bekannt");
    }
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    if p.starts_with(&format!("{}\\", windir.trim_end_matches('\\'))) {
        return Err("Windows-Bestandteil");
    }
    if !own_dir.is_empty() && p.starts_with(&format!("{}\\", own_dir.to_lowercase().trim_end_matches('\\'))) {
        return Err("K9 selbst");
    }
    if let Some(s) = signer.map(str::to_lowercase) {
        if s.starts_with("microsoft") || s.starts_with("trend micro") {
            return Err("von Microsoft oder Trend Micro signiert");
        }
    }
    if ANTI_CHEAT.iter().any(|a| p.contains(a)) {
        return Err("Anti-Cheat");
    }
    let name = p.rsplit('\\').next().unwrap_or(&p);
    if game_names.iter().any(|g| g.eq_ignore_ascii_case(name)) || game_dirs.iter().any(|d| !d.is_empty() && p.contains(&d.to_lowercase())) {
        return Err("Spiel");
    }
    Ok(())
}

/// Marks a finding as frozen (the Meldefenster then offers end / let run).
pub fn mark_frozen(f: &mut Finding, pid: u32, path: &str, start: i64) {
    if let Some(d) = f.details.as_mut().and_then(|d| d.as_object_mut()) {
        d.insert("angehalten".into(), true.into());
        d.insert("pids".into(), serde_json::json!([pid]));
        d.insert("prozesse".into(), serde_json::json!([{ "pid": pid, "ziel": path, "startzeit": start }]));
        d.insert(
            "hinweis".into(),
            "Das Programm wurde ANGEHALTEN (eingefroren, nicht beendet). „Prozess beenden“ beendet es, „Freigabe“ oder „Nur diesmal erlauben“ lässt es weiterlaufen. Ohne deine Entscheidung bleibt es angehalten."
                .into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity) -> Finding {
        Finding {
            path: "p".into(),
            sha256: "a".repeat(64),
            size: 0,
            rule_id: rule.into(),
            threat_name: "t".into(),
            category: "c".into(),
            severity: sev,
            engine: "dienst".into(),
            kind: Kind::Prozess,
            details: Some(serde_json::json!({ "pid": 5, "hinweis": "alt" })),
        }
    }

    #[test]
    fn known_malware_is_frozen_at_start_suspicion_rules_are_not() {
        let file = |rule: &str, engine: &str, sev: Severity| {
            let mut f = finding(rule, sev);
            f.kind = Kind::Datei;
            f.engine = engine.into();
            f
        };
        assert!(known_malware_at_start(&file("HASH:malwarebazaar", "hash", Severity::Hoch)));
        assert!(known_malware_at_start(&file("TEST-MUSTER", "muster", Severity::Niedrig)));
        assert!(known_malware_at_start(&file("YARA:default:CRAIU_Crime_Lockbit3_Ransomware", "yara", Severity::Hoch)));
        assert!(known_malware_at_start(&file("CLAMAV:Win.Ransomware.Conti-1", "clamav", Severity::Hoch)));
        assert!(!known_malware_at_start(&file("YARA:default:DITEKSHEN_INDICATOR_TOOL_UAC", "yara", Severity::Hoch)), "Verdachtsregel");
        assert!(!known_malware_at_start(&file("YARA:default:SUSP_Packed", "yara", Severity::Hoch)));
        assert!(!known_malware_at_start(&file("CLAMAV:PUA.Win.Packer.Exesplitter-8", "clamav", Severity::Mittel)));
        assert!(!known_malware_at_start(&file("YARA:default:Family", "yara", Severity::Mittel)), "nur Hoch und Kritisch");
    }

    #[test]
    fn only_critical_process_findings_qualify() {
        assert!(qualifies(&finding("KETTE:ANGRIFF", Severity::Kritisch)));
        assert!(qualifies(&finding("INFOSTEALER:CHROME", Severity::Kritisch)));
        assert!(!qualifies(&finding("INFOSTEALER:CHROME", Severity::Hoch)));
        assert!(!qualifies(&finding("BROWSER:FERNSTEUERUNG", Severity::Kritisch)));
    }

    #[test]
    fn games_anti_cheat_windows_and_trusted_vendors_are_never_frozen() {
        let dirs = vec!["\\steamapps\\common\\".to_string()];
        let names = vec!["eldenring.exe".to_string()];
        let own = r"C:\Program Files\K9";
        let ok = |p: &str, s: Option<&str>| freeze_allowed(p, s, &dirs, &names, own);
        assert_eq!(ok(r"C:\Users\x\Downloads\dieb.exe", None), Ok(()));
        assert!(ok(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Some("Microsoft Windows")).is_err());
        assert!(ok(r"C:\Program Files\Tool\x.exe", Some("Microsoft Corporation")).is_err());
        assert!(ok(r"C:\Program Files\Trend Micro\x.exe", Some("Trend Micro, Inc.")).is_err());
        assert!(ok(r"D:\Spiele\steamapps\common\Spiel\SpielEAC.exe", None).is_err());
        assert!(ok(r"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe", None).is_err());
        assert!(ok(r"C:\Games\eldenring.exe", None).is_err());
        assert!(ok(r"C:\Program Files\K9\k9-agent.exe", None).is_err());
        assert!(ok("dieb.exe", None).is_err(), "nur volle Pfade");
    }

    #[test]
    fn frozen_findings_say_so_and_name_the_process() {
        let mut f = finding("KETTE:ANGRIFF", Severity::Kritisch);
        mark_frozen(&mut f, 42, r"C:\x\dieb.exe", 133);
        let d = f.details.unwrap();
        assert_eq!(d["angehalten"], true);
        assert_eq!(d["prozesse"][0]["startzeit"], 133);
        assert!(d["hinweis"].as_str().unwrap().contains("ANGEHALTEN"));
    }
}
