//! Infostealer protection: which files hold logins (browser passwords and cookies,
//! Steam, Discord, Telegram, wallets), who may open them, and how serious it is when
//! another program does. The service feeds file-open events in (ETW Kernel-File);
//! nothing is ever ended automatically.

use std::path::{Path, PathBuf};

use crate::model::{Finding, Kind, Severity};

/// A store of logins and the programs that own it.
pub struct Group {
    pub id: &'static str,
    pub label: &'static str,
    /// The path (lower case) must contain one of these …
    folders: &'static [&'static str],
    /// … and end with one of these (or contain it, for folders like "\tdata\").
    files: &'static [&'static str],
    /// Owners: (exact signer name, program path contains) – both must hold. Exact names,
    /// because per-user installs (Chrome, Discord, Telegram) live in user-writable folders.
    owners: &'static [(&'static str, &'static str)],
}

const CHROMIUM_FILES: &[&str] = &["\\login data", "\\login data for account", "\\cookies", "\\local state", "\\web data"];

pub const GROUPS: &[Group] = &[
    Group {
        id: "chrome",
        label: "Google Chrome (Passwörter, Cookies)",
        folders: &["\\google\\chrome\\user data\\"],
        files: CHROMIUM_FILES,
        owners: &[("Google LLC", "\\google\\")],
    },
    Group {
        id: "edge",
        label: "Microsoft Edge (Passwörter, Cookies)",
        folders: &["\\microsoft\\edge\\user data\\"],
        files: CHROMIUM_FILES,
        owners: &[("Microsoft Corporation", "\\microsoft\\edge")],
    },
    Group {
        id: "brave",
        label: "Brave (Passwörter, Cookies)",
        folders: &["\\bravesoftware\\brave-browser\\user data\\"],
        files: CHROMIUM_FILES,
        owners: &[("Brave Software, Inc.", "\\bravesoftware\\")],
    },
    Group {
        id: "vivaldi",
        label: "Vivaldi (Passwörter, Cookies)",
        folders: &["\\vivaldi\\user data\\"],
        files: CHROMIUM_FILES,
        // Not installed here – name as published by the vendor (unverified).
        owners: &[("Vivaldi Technologies AS", "\\vivaldi\\")],
    },
    Group {
        id: "opera",
        label: "Opera (Passwörter, Cookies)",
        folders: &["\\opera software\\"],
        files: CHROMIUM_FILES,
        // Unverified on this PC.
        owners: &[("Opera Norway AS", "\\opera")],
    },
    Group {
        id: "firefox",
        label: "Firefox (Passwörter, Cookies)",
        folders: &["\\mozilla\\firefox\\profiles\\"],
        files: &["\\logins.json", "\\key4.db", "\\cookies.sqlite"],
        owners: &[("Mozilla Corporation", "\\mozilla")],
    },
    Group {
        id: "thunderbird",
        label: "Thunderbird (Passwörter)",
        folders: &["\\thunderbird\\profiles\\"],
        files: &["\\logins.json", "\\key4.db"],
        owners: &[("Mozilla Corporation", "\\mozilla thunderbird\\")],
    },
    Group {
        id: "steam",
        label: "Steam (Anmeldung)",
        folders: &["\\steam\\"],
        files: &["\\config\\loginusers.vdf", "\\config\\config.vdf", "\\ssfn"],
        // Unverified on this PC.
        owners: &[("Valve Corp.", "\\steam\\"), ("Valve Corporation", "\\steam\\")],
    },
    Group {
        id: "discord",
        label: "Discord (Anmeldung)",
        folders: &["\\discord\\", "\\discordptb\\", "\\discordcanary\\"],
        files: &["\\local storage\\leveldb\\"],
        owners: &[("Discord Inc.", "\\discord")],
    },
    Group {
        id: "telegram",
        label: "Telegram (Sitzung)",
        folders: &["\\telegram desktop\\"],
        files: &["\\tdata\\"],
        // Unverified on this PC.
        owners: &[("Telegram FZ-LLC", "\\telegram desktop\\"), ("Telegram Messenger Inc", "\\telegram desktop\\")],
    },
    Group {
        id: "wallet",
        label: "Krypto-Wallet",
        folders: &["\\exodus\\", "\\electrum\\", "\\ethereum\\", "\\atomic\\", "\\local extension settings\\"],
        files: &["\\exodus.wallet\\", "\\wallets\\", "\\keystore\\", "\\local storage\\leveldb\\", "\\nkbihfbeogaeaoehlefnkodbefgpgknn"],
        owners: &[
            // Wallet apps: unverified names; without a match their own access is reported (Mittel).
            ("Exodus Movement, Inc.", "\\exodus\\"),
            ("Electrum Technologies GmbH", "\\electrum\\"),
            // Browser wallet extensions are opened by the browser itself.
            ("Google LLC", "\\google\\"),
            ("Microsoft Corporation", "\\microsoft\\edge"),
            ("Brave Software, Inc.", "\\bravesoftware\\"),
        ],
    },
];

/// The group a file belongs to (path in any case; NT paths are converted before).
pub fn group_of(path: &str) -> Option<&'static Group> {
    let p = path.to_lowercase();
    if is_side_file(&p) {
        return None;
    }
    // The program code of a browser extension ("…\User Data\Profile 1\Extensions\<id>\…") holds
    // no logins, whatever its folders are called. Seen on 23.11.2026: a folder "js\cookies"
    // inside an extension counted as the cookie store of Brave and Chrome (three critical
    // findings while a script only added up folder sizes).
    if p.contains("\\user data\\") && p.contains("\\extensions\\") {
        return None;
    }
    // A store that is one file must be that file: the path ends with its name. Stores that are
    // folders (tdata, leveldb, a wallet extension's settings) match everything inside.
    let hit = |f: &&str| if EXACT_FILES.contains(f) { p.ends_with(*f) } else { p.contains(*f) };
    GROUPS.iter().find(|g| g.folders.iter().any(|f| p.contains(f)) && g.files.iter().any(hit))
}

/// Stores that are exactly one file (lower case, with the leading backslash).
const EXACT_FILES: &[&str] = &[
    "\\login data",
    "\\login data for account",
    "\\cookies",
    "\\local state",
    "\\web data",
    "\\logins.json",
    "\\key4.db",
    "\\cookies.sqlite",
    "\\config\\loginusers.vdf",
    "\\config\\config.vdf",
];

/// The access only opens a folder (to list it, to add up sizes): nothing is read. Whoever
/// wants the logins has to open the files inside - those accesses are still seen.
/// ETW names an opened folder with a trailing backslash; otherwise the file system is asked.
pub fn lists_folder(file: &str) -> bool {
    file.ends_with('\\') || Path::new(file).is_dir()
}

/// Side files of a store that hold no logins on their own and are only touched by the program
/// that works on the store: SQLite companions (-wal, -shm, -journal) and the temporary file a
/// browser writes before it replaces "Local State" ("Local State<id>.tmp"). A thief has to open
/// the store itself – that access is still seen. These side files caused findings "Programm
/// nicht sicher zuzuordnen" when a browser helper process ended within a moment.
fn is_side_file(lower_path: &str) -> bool {
    let name = lower_path.rsplit(['\\', '/']).next().unwrap_or(lower_path);
    ["-wal", "-shm", "-journal", ".tmp"].iter().any(|s| name.ends_with(s))
}

/// The Windows Explorer itself (from the Windows folder, signed by Microsoft).
pub fn is_windows_explorer(o: &Opener) -> bool {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    o.path.eq_ignore_ascii_case(&format!("{root}\\explorer.exe")) && o.signer.as_deref().is_some_and(|s| s.to_lowercase().starts_with("microsoft "))
}

/// The Explorer only lists a folder (tooltip with size and contents, folder tree, search):
/// nothing is read. Opening a file of a store is still reported.
pub fn explorer_lists_folder(o: &Opener, file: &str) -> bool {
    is_windows_explorer(o) && Path::new(file).is_dir()
}

/// Short name of a group ("Google Chrome") for button texts.
pub fn group_name(id: &str) -> Option<&'static str> {
    GROUPS.iter().find(|g| g.id == id).map(|g| g.label.split(" (").next().unwrap_or(g.label))
}

/// Facts about the program that opened the file.
#[derive(Debug, Clone, Default)]
pub struct Opener {
    pub path: String,
    /// Name of the valid signer (None: unsigned or invalid).
    pub signer: Option<String>,
    /// The program lies in a folder the user can write to.
    pub user_writable: bool,
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Owner or trusted component: nothing to do.
    Allowed,
    /// Another browser importing data: only noted in the event log.
    Logged,
    Report(Severity, &'static str),
}

/// Script hosts and Windows tools that stealers use (also to copy locked databases).
const LOLBINS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "esentutl.exe", "robocopy.exe", "xcopy.exe", "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
];

/// Trusted Windows components by exact name and folder (plus a Microsoft signature).
fn windows_component(lower_path: &str, signer: &str) -> bool {
    if !["microsoft windows", "microsoft corporation", "microsoft windows publisher"].contains(&signer) {
        return false;
    }
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    let sys32 = format!("{windir}\\system32\\");
    let named = |dir: &str, names: &[&str]| {
        lower_path.strip_prefix(dir).is_some_and(|rest| !rest.contains('\\') && names.contains(&rest))
    };
    named(&sys32, &["searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe", "wbengine.exe", "filehistory.exe"])
        // Defender: platform folder with version number, or Program Files.
        || (lower_path.contains("\\windows defender\\") && ["\\msmpeng.exe", "\\mpdefendercoreservice.exe"].iter().any(|n| lower_path.ends_with(n)))
}

fn is_browser_owner(lower_path: &str, signer: &str) -> bool {
    ["chrome", "edge", "brave", "vivaldi", "opera", "firefox"]
        .iter()
        .filter_map(|id| GROUPS.iter().find(|g| g.id == *id))
        .any(|g| owns(g, lower_path, signer))
}

fn owns(g: &Group, lower_path: &str, signer: &str) -> bool {
    g.owners.iter().any(|(s, root)| signer.eq_ignore_ascii_case(s) && lower_path.contains(root))
}

/// Decides for one file open. `groups_in_window` = number of different groups this
/// program touched within the last minute (including this one).
pub fn assess(g: &Group, o: &Opener, groups_in_window: usize, own_programs: &[PathBuf]) -> Verdict {
    let lower = o.path.to_lowercase();
    let signer = o.signer.as_deref().unwrap_or("").to_lowercase();
    if own_programs.iter().any(|p| p.as_os_str().to_string_lossy().eq_ignore_ascii_case(&o.path)) {
        return Verdict::Allowed;
    }
    if !signer.is_empty() {
        if owns(g, &lower, &signer) || windows_component(&lower, &signer) {
            return Verdict::Allowed;
        }
        // Virus protection reading files to check them.
        if signer == "trend micro, inc." && lower.contains("\\trend micro\\") {
            return Verdict::Allowed;
        }
        // "Import data from another browser" (e.g. Edge reads Chrome).
        if ["chrome", "edge", "brave", "vivaldi", "opera", "firefox"].contains(&g.id) && is_browser_owner(&lower, &signer) {
            return Verdict::Logged;
        }
    }
    let name = lower.rsplit('\\').next().unwrap_or(&lower);
    let pattern = groups_in_window >= 2;
    if pattern {
        return Verdict::Report(Severity::Kritisch, t!("liest Zugangsdaten mehrerer Programme kurz nacheinander – typisch für Datendiebe (Infostealer)", "reads sign-in data of several programs in quick succession – typical for data thieves (infostealers)"));
    }
    if LOLBINS.contains(&name) {
        return Verdict::Report(Severity::Hoch, t!("ein Skript- oder Windows-Werkzeug greift auf gespeicherte Zugangsdaten zu", "a script or Windows tool accesses stored sign-in data"));
    }
    match (&o.signer, o.user_writable) {
        (None, true) => Verdict::Report(Severity::Kritisch, t!("ein unsigniertes Programm aus einem Benutzerordner greift auf gespeicherte Zugangsdaten zu", "an unsigned program from a user folder accesses stored sign-in data")),
        (None, false) => Verdict::Report(Severity::Hoch, t!("ein unsigniertes Programm greift auf gespeicherte Zugangsdaten zu", "an unsigned program accesses stored sign-in data")),
        (Some(_), _) => Verdict::Report(Severity::Mittel, t!("ein Programm eines anderen Herstellers greift auf gespeicherte Zugangsdaten zu", "a program of another publisher accesses stored sign-in data")),
    }
}

/// Finding for a reported access. `identity` = signer, or the program's SHA-256 if unsigned:
/// a release then fits exactly this program file and this group.
pub fn finding(g: &Group, o: &Opener, file: &str, pid: u32, severity: Severity, why: &str, identity: &str) -> Finding {
    let name = Path::new(&o.path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| o.path.clone());
    let advice = if severity >= Severity::Hoch {
        t!("Kennst du dieses Programm nicht? Dann „Prozess beenden“ und danach – am besten von einem anderen, sauberen Gerät – \
         alle Passwörter ändern und dich überall abmelden (Google-/Microsoft-Konto, Steam, Discord, Telegram, Wallets). \
         Nichts wurde automatisch beendet.", "Do you not know this program? Then “End process” and afterwards – preferably from another, clean device – \
         change all passwords and sign out everywhere (Google/Microsoft account, Steam, Discord, Telegram, wallets). \
         Nothing was ended automatically.")
    } else {
        t!("Gehört das zu einem Programm, das du selbst nutzt (z. B. Passwortmanager, Sicherung)? Dann „Freigabe“. Nichts wurde automatisch beendet.", "Does this belong to a program you use yourself (e.g. password manager, backup)? Then “Allow”. Nothing was ended automatically.")
    };
    Finding {
        path: PathBuf::from(tf!("Prozess {name} liest {}", "Process {name} reads {}", crate::sprache::tr(g.label))),
        sha256: crate::sha256_hex(format!("infostealer|{}|{}|{}", o.path.to_lowercase(), g.id, identity.to_lowercase()).as_bytes()),
        size: 0,
        rule_id: format!("INFOSTEALER:{}", g.id.to_uppercase()),
        threat_name: format!("{name}: {why}"),
        category: t!("Datendiebstahl", "Data theft").into(),
        severity,
        engine: "dienst".into(),
        kind: Kind::Prozess,
        details: Some(serde_json::json!({
            "pid": pid, "ziel": o.path, "befehl": "", "eltern": "",
            "datei": file, "gruppe": g.id, "signierer": o.signer,
            "hinweis": advice,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_group_has_an_english_label_and_the_fingerprint_ignores_the_language() {
        use crate::sprache::{with, Sprache};
        for g in GROUPS {
            assert!(crate::sprache::english(g.label).is_some(), "{}", g.label);
        }
        let o = Opener { path: r"C:\Users\f\x.exe".into(), signer: None, user_writable: true };
        let de = finding(&GROUPS[0], &o, "f", 1, Severity::Hoch, "w", "id");
        let en = with(Sprache::En, || finding(&GROUPS[0], &o, "f", 1, Severity::Hoch, "w", "id"));
        assert_eq!(de.sha256, en.sha256);
        assert!(de.path.to_string_lossy().contains(" liest "), "{:?}", de.path);
        assert!(en.path.to_string_lossy().contains(" reads ") && en.path.to_string_lossy().contains("passwords"), "{:?}", en.path);
        assert_eq!(en.category, "Data theft");
    }

    fn opener(path: &str, signer: Option<&str>, writable: bool) -> Opener {
        Opener { path: path.into(), signer: signer.map(String::from), user_writable: writable }
    }

    #[test]
    fn listing_folders_and_extension_code_are_no_reads() {
        // The three critical findings of 23.11.2026 (a script added up folder sizes).
        let base = r"C:\Users\f\AppData\Local";
        assert!(group_of(&format!(r"{base}\BraveSoftware\Brave-Browser\User Data\Profile 8\Extensions\imhhfjfjfhjjjgaedcanngoffjmcblgi\39.0.3.135_0\js\cookies\")).is_none());
        assert!(group_of(&format!(r"{base}\Google\Chrome\User Data\Profile 3\Extensions\imhhfjfjfhjjjgaedcanngoffjmcblgi\39.1.11.166_0\js\cookies\index.js")).is_none());
        assert!(group_of(&format!(r"{base}\Google\Chrome\User Data\Profile 3\Extensions\x\1.0\Login Data")).is_none(), "Programmcode einer Erweiterung");
        // The wallet extension's settings folder is a store - but opening the folder is no read.
        let wallet = format!(r"{base}\BraveSoftware\Brave-Browser\User Data\Profile 1\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\");
        assert_eq!(group_of(&wallet).unwrap().id, "wallet");
        assert!(lists_folder(&wallet), "Ordner (endet mit \\): nur aufgelistet");
        let inside = format!("{wallet}000005.ldb");
        assert_eq!(group_of(&inside).unwrap().id, "wallet");
        assert!(!lists_folder(&inside), "Datei im Ordner: wird weiter gemeldet");
        // The real stores are still recognised, a file that only contains the name is not.
        assert_eq!(group_of(&format!(r"{base}\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies")).unwrap().id, "brave");
        assert!(group_of(&format!(r"{base}\Google\Chrome\User Data\Default\Network\Cookies Backup\alt.txt")).is_none());
        assert!(group_of(&format!(r"{base}\Google\Chrome\User Data\Default\Login Data For Account")).is_some());
        assert_eq!(group_of(r"C:\Program Files (x86)\Steam\ssfn1234567890").unwrap().id, "steam");
        // A folder without the trailing backslash is found by asking the file system (neutral names).
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let file = dir.path().join("datei.bin");
        std::fs::write(&file, b"x").unwrap();
        assert!(lists_folder(&dir.path().display().to_string()));
        assert!(!lists_folder(&file.display().to_string()));
    }

    #[test]
    fn explorer_listing_a_folder_is_not_a_read() {
        let root = std::env::var("SystemRoot").unwrap();
        let explorer = Opener { path: format!("{root}\\EXPLORER.EXE"), signer: Some("Microsoft Windows".into()), user_writable: false };
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        // Neutral names: a folder really named like a wallet would be reported by the installed K9
        // each time the tests run (it was, on 19.11.2026). The function only asks "folder or file?".
        let folder = dir.path().join("Ordner").join("Unterordner");
        std::fs::create_dir_all(&folder).unwrap();
        let file = folder.join("datei.bin");
        std::fs::write(&file, b"x").unwrap();
        assert!(is_windows_explorer(&explorer));
        assert!(explorer_lists_folder(&explorer, &folder.display().to_string()), "Ordner anzeigen: still");
        assert!(!explorer_lists_folder(&explorer, &file.display().to_string()), "Datei oeffnen: wird gemeldet");
        // Not the real Explorer: unsigned, or another folder.
        let fake = Opener { path: format!("{root}\\explorer.exe"), signer: None, user_writable: false };
        assert!(!explorer_lists_folder(&fake, &folder.display().to_string()));
        let copy = Opener { path: r"C:\Users\f\Downloads\explorer.exe".into(), signer: Some("Microsoft Windows".into()), user_writable: true };
        assert!(!explorer_lists_folder(&copy, &folder.display().to_string()));
    }

    #[test]
    fn credential_files_are_recognised() {
        let chrome = r"C:\Users\anna\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        assert_eq!(group_of(chrome).unwrap().id, "chrome");
        assert_eq!(group_of(&chrome.to_uppercase()).unwrap().id, "chrome", "Groß-/Kleinschreibung egal");
        assert_eq!(group_of(r"C:\Users\f\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies").unwrap().id, "chrome");
        assert_eq!(group_of(r"C:\Users\f\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json").unwrap().id, "firefox");
        assert_eq!(group_of(r"C:\Program Files (x86)\Steam\config\loginusers.vdf").unwrap().id, "steam");
        assert_eq!(group_of(r"C:\Users\f\AppData\Roaming\discord\Local Storage\leveldb\000003.log").unwrap().id, "discord");
        assert_eq!(group_of(r"C:\Users\f\AppData\Roaming\Telegram Desktop\tdata\key_datas").unwrap().id, "telegram");
        assert!(group_of(r"C:\Users\f\AppData\Local\Google\Chrome\User Data\Default\History").is_none());
        // Side files (18.11.2026: #199, #209-#212, #223) are no access to logins on their own.
        assert!(group_of(r"C:\Users\f\AppData\Local\Microsoft\Edge\User Data\Local Statef7684546-7bea-4576-bc0f-e57fee2ef70a.tmp").is_none());
        assert!(group_of(r"C:\Users\f\AppData\Local\Google\Chrome\User Data\Profile 12\Network\Cookies-wal").is_none());
        assert!(group_of(r"C:\Users\f\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data-journal").is_none());
        assert_eq!(group_of(r"C:\Users\f\AppData\Local\Microsoft\Edge\User Data\Local State").unwrap().id, "edge");
        assert!(group_of(r"C:\Program Files (x86)\Steam\steamapps\common\game.exe").is_none());
    }

    #[test]
    fn owners_and_windows_components_are_allowed_others_reported() {
        let chrome = group_of(r"C:\Users\f\AppData\Local\Google\Chrome\User Data\Default\Login Data").unwrap();
        let ok = opener(r"C:\Program Files\Google\Chrome\Application\chrome.exe", Some("Google LLC"), false);
        assert_eq!(assess(chrome, &ok, 1, &[]), Verdict::Allowed);
        let updater = opener(r"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe", Some("Google LLC"), false);
        assert_eq!(assess(chrome, &updater, 1, &[]), Verdict::Allowed, "Hersteller-Helfer im Herstellerordner");
        // A "chrome.exe" without Google's signature or from elsewhere is no owner.
        let fake = opener(r"C:\Users\f\AppData\Local\Temp\chrome.exe", None, true);
        assert_eq!(assess(chrome, &fake, 1, &[]), Verdict::Report(Severity::Kritisch, "ein unsigniertes Programm aus einem Benutzerordner greift auf gespeicherte Zugangsdaten zu"));
        let indexer = opener(r"C:\Windows\System32\SearchProtocolHost.exe", Some("Microsoft Windows"), false);
        assert_eq!(assess(chrome, &indexer, 1, &[]), Verdict::Allowed);
        // Signed Microsoft tools are NOT generally allowed.
        let ps = opener(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Some("Microsoft Windows"), false);
        assert!(matches!(assess(chrome, &ps, 1, &[]), Verdict::Report(Severity::Hoch, _)));
        let esent = opener(r"C:\Windows\System32\esentutl.exe", Some("Microsoft Windows"), false);
        assert!(matches!(assess(chrome, &esent, 1, &[]), Verdict::Report(Severity::Hoch, _)));
        // Edge importing from Chrome: only logged.
        let edge = opener(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", Some("Microsoft Corporation"), false);
        assert_eq!(assess(chrome, &edge, 1, &[]), Verdict::Logged);
        // Signed, unknown vendor: medium; several stores within a minute: critical.
        let other = opener(r"C:\Program Files\Tool\tool.exe", Some("Some Vendor GmbH"), false);
        assert!(matches!(assess(chrome, &other, 1, &[]), Verdict::Report(Severity::Mittel, _)));
        assert!(matches!(assess(chrome, &other, 2, &[]), Verdict::Report(Severity::Kritisch, _)));
        // A signer that only contains the vendor's name is no owner (per-user installs are writable).
        let lookalike = opener(r"C:\Users\f\AppData\Local\Google\Chrome\Application\chrome.exe", Some("Google LLC Updates Ltd"), true);
        assert!(matches!(assess(chrome, &lookalike, 1, &[]), Verdict::Report(Severity::Mittel, _)));
        let discord = group_of(r"C:\Users\f\AppData\Roaming\discord\Local Storage\leveldb\1.log").unwrap();
        let real = opener(r"C:\Users\f\AppData\Local\Discord\app-0.0.308\Discord.exe", Some("Discord Inc."), true);
        assert_eq!(assess(discord, &real, 1, &[]), Verdict::Allowed);
        // Our own programs.
        let own = vec![PathBuf::from(r"C:\Program Files\K9\k9-agent.exe")];
        assert_eq!(assess(chrome, &opener(r"C:\Program Files\K9\k9-agent.exe", None, false), 1, &own), Verdict::Allowed);
    }

    #[test]
    fn release_fits_only_program_group_and_identity() {
        let chrome = &GROUPS[0];
        let steam = GROUPS.iter().find(|g| g.id == "steam").unwrap();
        let o = opener(r"C:\x\tool.exe", None, false);
        let a = finding(chrome, &o, "f", 1, Severity::Hoch, "w", "abc");
        assert_ne!(a.sha256, finding(steam, &o, "f", 1, Severity::Hoch, "w", "abc").sha256);
        assert_ne!(a.sha256, finding(chrome, &o, "f", 1, Severity::Hoch, "w", "def").sha256, "andere Programmdatei");
        assert_eq!(a.sha256, finding(chrome, &o, "g", 2, Severity::Hoch, "w", "abc").sha256, "PID und Datei egal");
        assert!(a.details.unwrap()["hinweis"].as_str().unwrap().contains("Passwörter ändern"));
    }
}
