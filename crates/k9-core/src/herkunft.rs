//! Origin of downloaded files ("Mark of the Web"): browsers and mail programs add an
//! alternate data stream `Zone.Identifier` with the zone (3 = Internet, 4 = untrusted) and
//! usually the download address. An unsigned program from the internet starting for the
//! first time is the classic way in (fake cheats, mods, cracks).

use std::path::{Path, PathBuf};

use crate::model::{Finding, Kind, Severity};

/// Programs larger than this are fingerprinted by path, size and time instead of content.
const MAX_HASH: u64 = 200 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Zone {
    /// 0 local, 1 intranet, 2 trusted, 3 internet, 4 untrusted.
    pub zone: u32,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

impl Zone {
    pub fn from_internet(&self) -> bool {
        self.zone >= 3
    }
}

/// Parses the content of a `Zone.Identifier` stream.
pub fn parse_zone(text: &str) -> Option<Zone> {
    let mut z = Zone::default();
    let mut found = false;
    for line in text.lines() {
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "zoneid" => {
                z.zone = v.trim().parse().ok()?;
                found = true;
            }
            "hosturl" => z.host_url = Some(v.trim().to_string()).filter(|s| !s.is_empty()),
            "referrerurl" => z.referrer_url = Some(v.trim().to_string()).filter(|s| !s.is_empty()),
            _ => {}
        }
    }
    found.then_some(z)
}

/// Zone of a file (reads only the small stream, never the file).
pub fn zone_of(path: &Path) -> Option<Zone> {
    let stream = PathBuf::from(format!("{}:Zone.Identifier", path.display()));
    let meta = std::fs::metadata(&stream).ok()?;
    if meta.len() > 64 * 1024 {
        return None;
    }
    parse_zone(&std::fs::read_to_string(stream).ok()?)
}

/// Download address without query and fragment (they can hold access tokens).
pub fn short_url(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or("").chars().take(300).collect()
}

/// Fingerprint of the program: content hash, for very large files path + size + time.
pub fn program_identity(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) if m.len() <= MAX_HASH => crate::scanner::sha256_file(path).unwrap_or_else(|_| path.display().to_string().to_lowercase()),
        Ok(m) => format!("{}|{}|{:?}", path.display().to_string().to_lowercase(), m.len(), m.modified().ok()),
        Err(_) => path.display().to_string().to_lowercase(),
    }
}

/// Finding: unsigned program from the internet was started.
pub fn finding(path: &Path, zone: &Zone, identity: &str, pid: u32, cmd: &str, parent: &str) -> Finding {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let from = zone.host_url.as_deref().or(zone.referrer_url.as_deref()).map(short_url).unwrap_or_else(|| t!("unbekannt", "unknown").into());
    Finding {
        path: PathBuf::from(tf!("Programm {name} aus dem Internet gestartet", "Program {name} from the internet started")),
        sha256: crate::sha256_hex(format!("herkunft|{identity}").as_bytes()),
        size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        rule_id: "DOWNLOAD:UNSIGNIERT-GESTARTET".into(),
        threat_name: tf!("Unsigniertes Programm aus dem Internet gestartet: {name}", "Unsigned program from the internet started: {name}"),
        category: t!("Herkunft Internet", "Origin: internet").into(),
        severity: Severity::Mittel,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pid": pid, "ziel": path.display().to_string(), "befehl": cmd, "eltern": parent,
            "herkunft": from, "zone": zone.zone,
            "hinweis": t!("Das Programm stammt aus dem Internet und hat keine gültige Signatur eines Herstellers. Das ist der häufigste Weg für gefälschte Cheats, Mods und Cracks. Kennst du es und weißt, woher es kommt: „Freigabe“ (gilt nur für genau diese Datei). Sonst: „Prozess beenden“ und die Datei in Quarantäne.", "The program comes from the internet and has no valid signature of a publisher. This is the most common way for fake cheats, mods and cracks. If you know it and know where it comes from: “Allow” (applies to exactly this file only). Otherwise: “End process” and put the file into quarantine."),
        })),
    }
}

pub const FROZEN_RULE: &str = "DOWNLOAD:ANGEHALTEN";

/// Finding: an unsigned program from the internet was frozen at its first start (switch
/// "neue-programme"). A message of its own, not the one above: the service reports that one a
/// second or two later and would overwrite the note which process is frozen.
pub fn frozen_finding(path: &Path, zone: &Zone, identity: &str, pid: u32, cmd: &str, parent: &str) -> Finding {
    let mut f = finding(path, zone, identity, pid, cmd, parent);
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    f.path = PathBuf::from(tf!("Programm {name} aus dem Internet beim Start angehalten", "Program {name} from the internet suspended at start"));
    f.sha256 = crate::sha256_hex(format!("herkunft-angehalten|{identity}").as_bytes());
    f.rule_id = FROZEN_RULE.into();
    f.threat_name = tf!("Neues unsigniertes Programm aus dem Internet angehalten: {name}", "New unsigned program from the internet suspended: {name}");
    f.severity = Severity::Hoch;
    f.engine = "echtzeit".into();
    f
}

/// Programs that run script files: Windows Script Host, HTML applications, PowerShell, cmd.
const SCRIPT_HOSTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"];
/// Script files these hosts run.
const SCRIPT_EXT: &[&str] = &["js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "bat", "cmd"];

/// The script file a script host was started with: the first argument that names a script
/// file (`wscript "C:\Users\x\Downloads\rechnung.js"`). A name without folder (`wscript a.js`)
/// refers to the working folder of the process: `cwd` is asked for it only then. None for other
/// programs and for commands without a file (`powershell -Command …`, `mshta javascript:…`).
pub fn script_of(program: &str, cmd: &str, cwd: impl FnOnce() -> Option<PathBuf>) -> Option<PathBuf> {
    let name = program.rsplit(['\\', '/']).next().unwrap_or(program).to_ascii_lowercase();
    if !SCRIPT_HOSTS.contains(&name.as_str()) {
        return None;
    }
    // Split at spaces outside of quotes; quotes themselves are dropped.
    let mut args: Vec<String> = Vec::new();
    let (mut cur, mut quoted) = (String::new(), false);
    for c in cmd.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    args.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    let p = args.into_iter().skip(1).find_map(|a| {
        let a = a.trim();
        // Switches (`/c`, `//nologo`, `-File`) and addresses are not files.
        if a.starts_with('-') || a.contains("://") || (a.starts_with('/') && !a.contains('.')) {
            return None;
        }
        let p = PathBuf::from(a);
        let ext = p.extension()?.to_string_lossy().to_ascii_lowercase();
        SCRIPT_EXT.contains(&ext.as_str()).then_some(p)
    })?;
    let s = p.to_string_lossy();
    if s.as_bytes().get(1) == Some(&b':') || s.starts_with("\\\\") {
        return Some(p);
    }
    let dir = cwd()?;
    Some(dir.join(s.strip_prefix(".\\").unwrap_or(&s)))
}

/// Finding: a script from the internet was started (through a script host).
pub fn script_finding(script: &Path, zone: &Zone, identity: &str, pid: u32, host: &str, cmd: &str, parent: &str) -> Finding {
    let name = script.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let host_name = Path::new(host).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| host.to_string());
    let from = zone.host_url.as_deref().or(zone.referrer_url.as_deref()).map(short_url).unwrap_or_else(|| t!("unbekannt", "unknown").into());
    Finding {
        path: PathBuf::from(tf!("Skript {name} aus dem Internet gestartet", "Script {name} from the internet started")),
        sha256: crate::sha256_hex(format!("herkunft-skript|{identity}").as_bytes()),
        size: std::fs::metadata(script).map(|m| m.len()).unwrap_or(0),
        rule_id: "DOWNLOAD:SKRIPT-GESTARTET".into(),
        threat_name: tf!("Skript aus dem Internet gestartet: {name} (über {host_name})", "Script from the internet started: {name} (via {host_name})"),
        category: t!("Herkunft Internet", "Origin: internet").into(),
        severity: Severity::Hoch,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            // "ziel" is the running program (the script host): "Prozess beenden" ends it.
            "pid": pid, "ziel": host, "befehl": cmd, "eltern": parent,
            "skriptdatei": script.display().to_string(),
            "herkunft": from, "zone": zone.zone,
            "hinweis": t!("Diese Skriptdatei stammt aus dem Internet (Download, E-Mail-Anhang oder aus einem geladenen Archiv) und wurde gerade ausgeführt. Skripte (.js, .vbs, .hta, .ps1, .bat) sind einer der häufigsten Wege für Schadsoftware – oft getarnt als Rechnung, Lieferschein oder Bewerbung. Hast du sie nicht bewusst gestartet: „Prozess beenden“, die Datei löschen und einen vollständigen Scan starten. Kennst du das Skript und seine Quelle: „Freigabe“ (gilt nur für genau dieses Skript).", "This script file comes from the internet (download, e-mail attachment or from a downloaded archive) and has just been run. Scripts (.js, .vbs, .hta, .ps1, .bat) are one of the most common ways for malware – often disguised as an invoice, delivery note or job application. If you did not start it on purpose: “End process”, delete the file and start a full scan. If you know the script and its source: “Allow” (applies to exactly this script only)."),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_hosts_and_their_script_files() {
        let p = |s: &str| Some(PathBuf::from(s));
        let script_of = |a: &str, b: &str| super::script_of(a, b, || None);
        assert_eq!(script_of("wscript.exe", r#""C:\Windows\System32\WScript.exe" "C:\Users\f\Downloads\Rechnung 2026.js""#), p(r"C:\Users\f\Downloads\Rechnung 2026.js"));
        assert_eq!(script_of(r"C:\Windows\System32\mshta.exe", r#"mshta.exe "C:\Users\f\Downloads\a.hta""#), p(r"C:\Users\f\Downloads\a.hta"));
        assert_eq!(script_of("powershell.exe", r"powershell.exe -ExecutionPolicy Bypass -File C:\Users\f\Downloads\x.ps1 -Param 1"), p(r"C:\Users\f\Downloads\x.ps1"));
        assert_eq!(script_of("cmd.exe", r#"cmd.exe /c "C:\Users\f\Downloads\start.bat" "#), p(r"C:\Users\f\Downloads\start.bat"));
        assert_eq!(script_of("cscript.exe", r"cscript //nologo \\server\share\a.vbs"), p(r"\\server\share\a.vbs"));
        assert_eq!(script_of("mshta.exe", "mshta.exe javascript:alert(1)"), None);
        assert_eq!(script_of("powershell.exe", "powershell -Command Get-Date"), None);
        assert_eq!(script_of("wscript.exe", "wscript.exe a.js"), None, "relativer Pfad: Ordner unbekannt");
        // With the working folder of the process a short name is resolved.
        let dl = || Some(PathBuf::from(r"C:\Users\f\Downloads"));
        assert_eq!(super::script_of("wscript.exe", "wscript.exe a.js", dl), p(r"C:\Users\f\Downloads\a.js"));
        assert_eq!(super::script_of("cmd.exe", r"cmd /c .\start.bat", dl), p(r"C:\Users\f\Downloads\start.bat"));
        assert_eq!(super::script_of("cscript.exe", r#"cscript //nologo "unter ordner\b.vbs""#, dl), p(r"C:\Users\f\Downloads\unter ordner\b.vbs"));
        assert_eq!(super::script_of("powershell.exe", "powershell -File x.ps1", dl), p(r"C:\Users\f\Downloads\x.ps1"));
        assert_eq!(super::script_of("mshta.exe", "mshta https://beispiel.example/a.hta", dl), None, "Adresse, keine Datei");
        assert_eq!(super::script_of("powershell.exe", "powershell -Command Get-Date", || panic!("nicht noetig")), None);
        assert_eq!(script_of("notepad.exe", r"notepad.exe C:\Users\f\Downloads\a.js"), None, "kein Skripthost");
    }

    #[test]
    fn script_finding_names_script_and_host() {
        let z = Zone { zone: 3, host_url: Some("https://mail.example/anhang?id=geheim".into()), referrer_url: None };
        let f = script_finding(Path::new(r"C:\Users\f\Downloads\Rechnung.js"), &z, "abc", 9, r"C:\Windows\System32\wscript.exe", "wscript x", "explorer.exe");
        assert_eq!((f.rule_id.as_str(), f.severity), ("DOWNLOAD:SKRIPT-GESTARTET", Severity::Hoch));
        assert!(f.threat_name.contains("Rechnung.js") && f.threat_name.contains("wscript.exe"));
        let d = f.details.unwrap();
        assert_eq!(d["ziel"], r"C:\Windows\System32\wscript.exe");
        assert_eq!(d["skriptdatei"], r"C:\Users\f\Downloads\Rechnung.js");
        assert!(!d.to_string().contains("geheim"));
    }

    #[test]
    fn zone_identifier_is_parsed() {
        let z = parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://seite.example/\r\nHostUrl=https://cdn.example/cheat.exe?token=geheim\r\n").unwrap();
        assert_eq!(z.zone, 3);
        assert!(z.from_internet());
        assert_eq!(short_url(z.host_url.as_deref().unwrap()), "https://cdn.example/cheat.exe");
        assert!(!parse_zone("[ZoneTransfer]\nZoneId=1\n").unwrap().from_internet());
        assert_eq!(parse_zone("kaputt"), None);
    }

    #[test]
    fn zone_is_read_from_the_stream_and_the_finding_hides_tokens() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let exe = dir.path().join("mod-tool.exe");
        std::fs::write(&exe, b"MZ test").unwrap();
        assert_eq!(zone_of(&exe), None);
        std::fs::write(format!("{}:Zone.Identifier", exe.display()), "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://dl.example/mod-tool.exe?sig=abc\r\n").unwrap();
        let z = zone_of(&exe).unwrap();
        assert_eq!(z.zone, 3);
        let id = program_identity(&exe);
        assert_eq!(id, crate::scanner::sha256_file(&exe).unwrap());
        let f = finding(&exe, &z, &id, 7, "mod-tool.exe", "explorer.exe");
        assert_eq!(f.severity, Severity::Mittel);
        let d = f.details.unwrap();
        assert_eq!(d["herkunft"], "https://dl.example/mod-tool.exe");
        assert!(!d.to_string().contains("sig=abc"));
    }
}
