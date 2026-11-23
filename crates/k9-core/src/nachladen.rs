//! "Selbst geladen": when winget can't download an update (wrong address in its catalogue),
//! the user loads the installer from the official page into Downloads. K9 never guesses a
//! download link. It offers "Installieren" for a file in Downloads only if
//!   * it is an .exe or .msi of the last 14 days with a valid digital signature,
//!   * it is signed by the SAME publisher as the installed program (its program files),
//!   * its file name or product name contains the program's name,
//!   * and K9 has no open finding for it (hash lists, YARA, ClamAV check Downloads anyway).
//!
//! The check runs again right before the start, with the file's SHA-256 from the confirmation.

use std::path::{Path, PathBuf};

use crate::sicherheit::Update;

/// File types K9 accepts as an installer.
const INSTALLER_EXT: [&str; 4] = ["exe", "msi", "msix", "msixbundle"];

/// A downloaded installer that passed the checks.
#[derive(Debug, Clone, PartialEq)]
pub struct Kandidat {
    pub datei: PathBuf,
    pub signiert_von: String,
    pub sha256: String,
    /// The publisher name differs, but only slightly (same company under a changed name, e.g.
    /// "WESTERN DIGITAL CORPORATION" / "Western Digital Technologies, Inc."): the names of the
    /// installed version. Such a file is only installed after an explicit extra confirmation.
    pub abweichend: Option<String>,
}

/// The same company under a slightly different name? The first two words (letters and digits
/// only, forms like Inc/GmbH ignored) must be equal; a single-word name must be equal and at
/// least 6 letters long.
pub fn similar_publisher(a: &str, b: &str) -> bool {
    const FORMS: [&str; 16] = ["inc", "llc", "ltd", "gmbh", "corp", "corporation", "co", "sa", "ag", "bv", "sro", "limited", "company", "kg", "ab", "oy"];
    let words = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .map(|w| w.to_lowercase())
            .filter(|w| !w.is_empty() && !FORMS.contains(&w.as_str()))
            .collect()
    };
    let (x, y) = (words(a), words(b));
    // Certificates for individuals all start with "Open Source Developer, <name>".
    if x.starts_with(&["open".to_string(), "source".to_string()]) {
        return false;
    }
    match (x.len().min(y.len()), x.first(), y.first()) {
        (0, _, _) => false,
        (1, Some(p), Some(q)) => p == q && p.len() >= 6,
        _ => x[..2] == y[..2] && x[0].len() + x[1].len() >= 8,
    }
}

/// Lowercase letters and digits only ("HWiNFO® 64" -> "hwinfo64").
fn plain(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

/// The word that identifies the program: the first word with at least 4 letters/digits that
/// is no version number ("Mozilla Thunderbird (x64 de)" -> "mozilla"; "7-Zip 26.02" -> "7zip").
pub fn key_word(name: &str) -> Option<String> {
    name.split_whitespace().map(plain).find(|w| w.len() >= 4 && !w.chars().all(|c| c.is_ascii_digit()))
}

/// Does the file (name / product name of its version info) belong to this program?
pub fn names_match(program: &str, id: &str, file_name: &str, product: &str) -> bool {
    let hay = format!("{} {}", plain(file_name), plain(product));
    let id_word = id.rsplit('.').next().map(plain).filter(|w| w.len() >= 4);
    key_word(program).into_iter().chain(id_word).any(|w| hay.contains(&w))
}

fn exe_in(value: &str) -> Option<PathBuf> {
    let v = value.trim();
    let p = if let Some(rest) = v.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        // "C:\x\a.exe,0" or "C:\x\unins000.exe /S"
        let lower = v.to_lowercase();
        let end = lower.find(".exe")? + 4;
        v[..end].to_string()
    };
    let p = PathBuf::from(crate::paths::expand_env(&p));
    (p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) && p.is_file()).then_some(p)
}

fn valid_signer(p: &Path) -> Option<String> {
    crate::autostart::is_signed(p).then(|| crate::treiber::signer_name(p)).flatten().filter(|s| !s.trim().is_empty())
}

/// Publishers that signed the installed program's files (from its uninstall entry).
pub fn installed_signers(u: &Update) -> Vec<String> {
    let want = plain(&u.name);
    let mut out: Vec<String> = Vec::new();
    for sw in crate::software::inventory() {
        let have = plain(&sw.name);
        if have.is_empty() || !(have == want || (have.len() >= 5 && want.starts_with(&have)) || (want.len() >= 5 && have.starts_with(&want))) {
            continue;
        }
        let Some((hive, path)) = sw.registry.split_once('\\') else { continue };
        let hive = crate::winreg::hive_from_name(hive);
        let mut files: Vec<PathBuf> = ["DisplayIcon", "UninstallString"].iter().filter_map(|v| crate::winreg::read_string(hive, path, v)).filter_map(|v| exe_in(&v)).collect();
        if let Some(dir) = crate::winreg::read_string(hive, path, "InstallLocation").map(|d| PathBuf::from(d.trim().trim_matches('"'))).filter(|d| d.is_dir()) {
            files.extend(program_files_in(&dir));
        }
        // The first few signed programs are enough (signature checks cost time).
        let mut checked = 0;
        for f in files {
            if let Some(s) = valid_signer(&f) {
                checked += 1;
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            if checked >= 6 {
                break;
            }
        }
    }
    for s in store_app_publishers(u) {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// Programs (.exe) of an installation folder: the folder itself and up to two levels below
/// (LibreOffice keeps them in "program", others in "bin"), at most 40.
fn program_files_in(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0u8)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten().take(400) {
            let p = e.path();
            if p.is_dir() {
                if depth < 2 {
                    stack.push((p, depth + 1));
                }
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                out.push(p);
                if out.len() >= 40 {
                    return out;
                }
            }
        }
    }
    out
}

/// "CN=..." of a publisher string from an app manifest (quotes as in the certificate).
pub fn common_name(publisher: &str) -> Option<String> {
    let p = publisher.replace("&quot;", "\"").replace("&amp;", "&");
    let rest = &p[p.find("CN=")? + 3..];
    let cn = match rest.strip_prefix('"') {
        Some(q) => q.split('"').next()?,
        None => rest.split(',').next()?,
    };
    (!cn.trim().is_empty()).then(|| cn.trim().to_string())
}

/// Publishers of installed store/MSIX apps that match the program (e.g. TradingView): from
/// the app manifest in the protected folder "Program Files\WindowsApps" – Windows only
/// installs a package whose signature matches that publisher.
fn store_app_publishers(u: &Update) -> Vec<String> {
    const PACKAGES: &str = "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages";
    let words: Vec<String> = key_word(&u.name).into_iter().chain(u.id.split('.').next().map(plain).filter(|w| w.len() >= 4)).collect();
    let apps = std::env::var("ProgramFiles").map(|p| format!("{}\\windowsapps\\", p.to_lowercase())).unwrap_or_default();
    let mut out = Vec::new();
    if words.is_empty() || apps.len() < 16 {
        return out;
    }
    for sub in crate::winreg::subkeys(crate::winreg::HKCU, PACKAGES) {
        let name = plain(sub.split('_').next().unwrap_or(""));
        if !words.iter().any(|w| name.contains(w.as_str())) {
            continue;
        }
        let Some(root) = crate::winreg::read_string(crate::winreg::HKCU, &format!("{PACKAGES}\\{sub}"), "PackageRootFolder") else { continue };
        if !root.to_lowercase().starts_with(&apps) {
            continue;
        }
        let Ok(manifest) = std::fs::read_to_string(Path::new(&root).join("AppxManifest.xml")) else { continue };
        let Some(i) = manifest.find("Publisher=\"") else { continue };
        let value = manifest[i + 11..].split('"').next().unwrap_or("");
        if let Some(cn) = common_name(value) {
            if !out.contains(&cn) {
                out.push(cn);
            }
        }
    }
    out
}

pub fn downloads_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Downloads")).filter(|p| p.is_dir())
}

/// Checks one file for one program. `blocked`: K9 has an open finding for this file.
pub fn check_file(u: &Update, file: &Path, signers: &[String], blocked: &dyn Fn(&Path) -> bool) -> Result<Kandidat, String> {
    let ext = file.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if !INSTALLER_EXT.contains(&ext.as_str()) {
        return Err("keine .exe-, .msi- oder .msix-Datei".into());
    }
    let name = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let info = crate::treiber::version_info(file);
    if !names_match(&u.name, &u.id, &name, &info.produkt) {
        return Err("Dateiname passt nicht zum Programm".into());
    }
    let signer = valid_signer(file).ok_or("keine gültige digitale Signatur")?;
    if signers.is_empty() {
        return Err("Hersteller der installierten Version nicht feststellbar".into());
    }
    let same = signers.iter().any(|s| s.eq_ignore_ascii_case(&signer));
    if !same && !signers.iter().any(|s| similar_publisher(s, &signer)) {
        return Err(format!("signiert von „{signer}“, die installierte Version von „{}“", signers.join("“, „")));
    }
    let abweichend = (!same).then(|| signers.join("“, „"));
    if blocked(file) {
        return Err("K9 hat eine offene Meldung zu dieser Datei".into());
    }
    let sha256 = crate::scanner::sha256_file(file).map_err(|e| format!("nicht lesbar: {e}"))?;
    Ok(Kandidat { datei: file.to_path_buf(), signiert_von: signer, sha256, abweichend })
}

/// The newest downloaded installer in Downloads (last 14 days) that passes all checks.
pub fn find(u: &Update, blocked: &dyn Fn(&Path) -> bool) -> Option<Kandidat> {
    let dir = downloads_dir()?;
    let limit = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(14 * 86400))?;
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let ext = p.extension()?.to_string_lossy().to_ascii_lowercase();
            let t = e.metadata().ok()?.modified().ok()?;
            let name = p.file_name()?.to_string_lossy().to_string();
            // Cheap filters first: the signature is checked only for files named like the program.
            (INSTALLER_EXT.contains(&ext.as_str()) && t >= limit && (names_match(&u.name, &u.id, &name, "") || ext == "exe")).then_some((t, p))
        })
        .collect();
    files.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut signers: Option<Vec<String>> = None;
    for (_, f) in files.into_iter().take(40) {
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !names_match(&u.name, &u.id, &name, &crate::treiber::version_info(&f).produkt) {
            continue;
        }
        let s = signers.get_or_insert_with(|| installed_signers(u));
        if let Ok(k) = check_file(u, &f, s, blocked) {
            return Some(k);
        }
    }
    None
}

/// Starts the installer with its normal windows (Windows asks for administrator rights if
/// the installer needs them) and waits until it ends. Ok(exit code).
pub fn run_installer(file: &Path) -> Result<u32, String> {
    run_installer_with(file, None)
}

/// The installer kit of a file and its switches for an installation without windows
/// (None: unknown – then only the normal installation with windows is offered).
/// Recognised by content: MSI, Inno Setup, NSIS (Nullsoft) and WiX Burn bundles.
pub fn silent_switches(file: &Path) -> Option<(&'static str, &'static str)> {
    use std::io::Read;
    if file.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")) {
        return Some(("Windows Installer (MSI)", "/qn /norestart"));
    }
    let mut head = Vec::new();
    std::fs::File::open(file).ok()?.take(12 * 1024 * 1024).read_to_end(&mut head).ok()?;
    silent_switches_of(&head)
}

pub fn silent_switches_of(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    let wide = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect() };
    if !head.starts_with(b"MZ") {
        return None;
    }
    if has(b"Inno Setup Setup Data") || has(b"JR.Inno.Setup") || has(&wide("Inno Setup")) {
        Some(("Inno Setup", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"))
    } else if has(b"Nullsoft.NSIS.exehead") || has(b"NullsoftInst") {
        Some(("NSIS (Nullsoft)", "/S"))
    } else if has(b".wixburn") {
        Some(("WiX-Paket", "/quiet /norestart"))
    } else {
        None
    }
}

/// Like [`run_installer`]; `silent`: switches for an installation without windows.
pub fn run_installer_with(file: &Path, silent: Option<&str>) -> Result<u32, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let msi = file.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi"));
    let extra = silent.unwrap_or("");
    let (target, params) = if msi { ("msiexec.exe".to_string(), format!("/i \"{}\" {extra}", file.display())) } else { (file.display().to_string(), extra.to_string()) };
    let (verb, f, p) = (wide("open"), wide(&target), wide(&params));
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
        ShellExecuteExW(&mut info).map_err(|e| format!("nicht gestartet: {e}"))?;
        if info.hProcess.is_invalid() {
            return Ok(0);
        }
        let _ = WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(name: &str, id: &str) -> Update {
        Update { name: name.into(), id: id.into(), installiert: "1".into(), verfuegbar: "2".into(), hinweis: String::new(), seite: String::new(), fehler_seit: String::new() }
    }

    #[test]
    fn file_names_must_contain_the_program_name() {
        assert!(names_match("HWiNFO® 64", "REALiX.HWiNFO", "hwi64_854.exe", "HWiNFO64"));
        assert!(names_match("HWiNFO® 64", "REALiX.HWiNFO", "HWiNFO_setup.exe", ""));
        assert!(!names_match("HWiNFO® 64", "REALiX.HWiNFO", "setup.exe", "Something Else"));
        assert!(names_match("7-Zip 26.02 (x64)", "7zip.7zip", "7zip-2606-x64.exe", ""));
        assert_eq!(key_word("Mozilla Thunderbird (x64 de)").as_deref(), Some("mozilla"));
        assert_eq!(key_word("Java 8 Update 361").as_deref(), Some("java"));
    }

    #[test]
    fn unsigned_other_publisher_and_reported_files_are_refused() {
        let u = upd("HWiNFO® 64", "REALiX.HWiNFO");
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let f = dir.path().join("hwinfo_setup.exe");
        std::fs::write(&f, b"MZ kein echtes Programm").unwrap();
        let err = check_file(&u, &f, &["REALiX".into()], &|_| false).unwrap_err();
        assert!(err.contains("Signatur"), "{err}");
        assert!(check_file(&u, &dir.path().join("a.zip"), &[], &|_| false).unwrap_err().contains(".exe"));
        assert_eq!(common_name("CN=&quot;TradingView, Inc.&quot;, O=&quot;TradingView, Inc.&quot;, S=Ohio, C=US").as_deref(), Some("TradingView, Inc."));
        assert_eq!(common_name("CN=Microsoft Corporation, O=Microsoft Corporation").as_deref(), Some("Microsoft Corporation"));
        assert_eq!(common_name("O=ohne"), None);
        // A validly signed Windows program named like the program, but from another publisher.
        let sys = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("notepad.exe");
        let copy = dir.path().join("hwinfo-notepad.exe");
        std::fs::copy(&sys, &copy).unwrap();
        if valid_signer(&copy).is_some() {
            let err = check_file(&u, &copy, &["REALiX".into()], &|_| false).unwrap_err();
            assert!(err.contains("signiert von"), "{err}");
            let signer = valid_signer(&copy).unwrap();
            assert!(check_file(&u, &copy, std::slice::from_ref(&signer), &|_| true).unwrap_err().contains("offene Meldung"));
            let ok = check_file(&u, &copy, &[signer], &|_| false).unwrap();
            assert_eq!(ok.sha256.len(), 64);
            assert!(check_file(&u, &copy, &[], &|_| false).unwrap_err().contains("nicht feststellbar"));
            assert!(ok.abweichend.is_none());
        }
    }

    #[test]
    fn installer_kits_are_recognised_by_content() {
        let mk = |marker: &[u8]| [b"MZ\x90\x00 stub ".as_slice(), marker, b" rest"].concat();
        assert_eq!(silent_switches_of(&mk(b"Inno Setup Setup Data (6.2.0)")).unwrap().0, "Inno Setup");
        assert_eq!(silent_switches_of(&mk(b"<assemblyIdentity name=\"Nullsoft.NSIS.exehead\"")).unwrap().1, "/S");
        assert_eq!(silent_switches_of(&mk(b".wixburn")).unwrap().1, "/quiet /norestart");
        assert!(silent_switches_of(&mk(b"irgendein anderes Programm")).is_none());
        assert!(silent_switches_of(b"Inno Setup Setup Data ohne MZ").is_none());
        assert_eq!(silent_switches(Path::new("C:\\x\\a.MSI")).unwrap().1, "/qn /norestart");
    }

    #[test]
    fn a_renamed_company_is_similar_a_different_one_is_not() {
        assert!(similar_publisher("Western Digital Technologies, Inc.", "WESTERN DIGITAL CORPORATION"));
        assert!(similar_publisher("TeamViewer Germany GmbH", "TeamViewer Germany AG"));
        assert!(similar_publisher("Mozilla Corporation", "Mozilla"));
        assert!(!similar_publisher("Western Digital Technologies, Inc.", "Western Union LLC"));
        assert!(!similar_publisher("Microsoft Corporation", "Microsofd Corporation"));
        assert!(!similar_publisher("AB Software", "AB Tools"), "zu kurz, um etwas zu beweisen");
        assert!(!similar_publisher("Inc.", "Inc."));
        assert!(!similar_publisher("Open Source Developer, Hans Muster", "Open Source Developer, Eva Beispiel"), "Sammelzertifikate fuer Einzelpersonen");
    }

    #[test]
    fn program_file_from_registry_values() {
        let sys = std::env::var("SystemRoot").unwrap();
        assert_eq!(exe_in(&format!("\"{sys}\\System32\\cmd.exe\" /c x")), Some(PathBuf::from(format!("{sys}\\System32\\cmd.exe"))));
        assert_eq!(exe_in(&format!("{sys}\\System32\\cmd.exe,0")), Some(PathBuf::from(format!("{sys}\\System32\\cmd.exe"))));
        assert_eq!(exe_in("MsiExec.exe /X{1234}"), None);
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "liest die installierten Programme dieses PCs"]
    fn real_signers() {
        for (n, id) in [("HWiNFO® 64", "REALiX.HWiNFO"), ("OBS Studio", "OBSProject.OBSStudio"), ("LibreOffice 26.8.3.1", "TheDocumentFoundation.LibreOffice"), ("TradingView", "TradingView.TradingViewDesktop"), ("WD Security", "WesternDigital.Security"), ("OpenOffice 4.1.17", "Apache.OpenOffice")] {
            let u = crate::sicherheit::Update { name: n.into(), id: id.into(), installiert: String::new(), verfuegbar: String::new(), hinweis: String::new(), seite: String::new(), fehler_seit: String::new() };
            println!("{n}: {:?}", super::installed_signers(&u));
        }
    }
}

// ------------------------------------------------ search the official page (on the user's click)

/// Host of an https address (lowercase), None for anything else.
fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    (!host.is_empty() && !host.contains('@') && !host.contains(':') && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')).then_some(host)
}

/// "www.hwinfo.com" -> "hwinfo.com" (the last two labels).
fn site_of(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    parts[parts.len().saturating_sub(2)..].join(".")
}

/// Installer links (.exe/.msi) of a page that lie on the manufacturer's own site (same domain
/// as the official page) – best first: 64 bit before others; never portable/ARM/32-bit-only files.
pub fn installer_links(html: &str, page: &str) -> Vec<String> {
    let Some(site) = host_of(page).map(|h| site_of(&h)) else { return Vec::new() };
    let origin = format!("https://{}", host_of(page).unwrap_or_default());
    let mut out: Vec<(i32, String)> = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("href=") {
        rest = &rest[i + 5..];
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        let Some(end) = rest[1..].find(q) else { break };
        let raw = rest[1..1 + end].replace("&amp;", "&");
        rest = &rest[1 + end..];
        let url = if raw.starts_with("https://") {
            raw
        } else if raw.starts_with('/') && !raw.starts_with("//") {
            format!("{origin}{raw}")
        } else {
            continue;
        };
        if url.len() > 300 || url.contains(['?', '#', ' ', '<', '>', '"', '\\']) {
            continue;
        }
        let Some(host) = host_of(&url) else { continue };
        if site_of(&host) != site {
            continue; // mirrors and download portals are not the manufacturer
        }
        let name = url.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
        if !(name.ends_with(".exe") || name.ends_with(".msi")) {
            continue;
        }
        if ["portable", "arm64", "aarch64", "win32", "x86.", "x86_", "x86-", "32bit", "32-bit", "_dos", "symbols", "debug"].iter().any(|b| name.contains(b)) {
            continue;
        }
        let score = if name.contains("64") { 2 } else { 0 } + if name.contains("setup") || name.contains("install") { 1 } else { 0 };
        if !out.iter().any(|(_, u)| *u == url) {
            out.push((score, url));
        }
    }
    // A 64-bit installer on the page: nothing else is considered.
    if out.iter().any(|(s, _)| *s >= 2) {
        out.retain(|(s, _)| *s >= 2);
    }
    out.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
    out.into_iter().map(|(_, u)| u).take(3).collect()
}

/// Same-site pages that probably lead to the download (address contains "download"), for
/// manufacturers who keep the installer one click away from the official page. At most 5.
pub fn download_pages(html: &str, page: &str) -> Vec<String> {
    let Some(host) = host_of(page) else { return Vec::new() };
    let site = site_of(&host);
    let origin = format!("https://{host}");
    let mut out: Vec<String> = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("href=") {
        rest = &rest[i + 5..];
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        let Some(end) = rest[1..].find(q) else { break };
        let raw = rest[1..1 + end].replace("&amp;", "&");
        rest = &rest[1 + end..];
        let url = if raw.starts_with("https://") {
            raw
        } else if raw.starts_with('/') && !raw.starts_with("//") {
            format!("{origin}{raw}")
        } else {
            continue;
        };
        let url = url.split('#').next().unwrap_or("").to_string();
        let lower = url.to_ascii_lowercase();
        let file = lower.rsplit('/').next().unwrap_or("");
        if url.len() > 300 || url.contains([' ', '<', '>', '"', '\\']) || !lower.contains("download") || [".exe", ".msi", ".zip", ".msix", ".pdf", ".png", ".jpg", ".css", ".js"].iter().any(|e| file.ends_with(e)) {
            continue;
        }
        if host_of(&url).is_some_and(|h| site_of(&h) == site) && url.trim_end_matches('/') != page.trim_end_matches('/') && !out.contains(&url) {
            out.push(url);
        }
    }
    out.truncate(5);
    out
}

fn safe_name(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c)).collect()
}

fn is_installer_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    INSTALLER_EXT.iter().any(|e| n.ends_with(&format!(".{e}")))
}

/// Loads `url` into `target` (via a ".k9-laedt" file next to it).
fn load_to(http: &reqwest::blocking::Client, url: &str, target: &Path) -> Result<(), String> {
    use std::io::{Read, Write};
    const MAX: u64 = 700 * 1024 * 1024;
    let part = target.with_file_name(format!("{}.k9-laedt", target.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
    let res = (|| -> Result<(), String> {
        let mut r = http.get(url).send().and_then(|r| r.error_for_status()).map_err(|e| format!("{e}"))?;
        let mut f = std::fs::File::create(&part).map_err(|e| format!("{e}"))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut buf).map_err(|e| format!("{e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX {
                return Err("Datei zu groß".into());
            }
            f.write_all(&buf[..n]).map_err(|e| format!("{e}"))?;
        }
        Ok(())
    })();
    match res.and_then(|()| std::fs::rename(&part, target).map_err(|e| format!("{e}"))) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Unpacks the installers (.exe/.msi/.msix, top level or one folder deep, at most 3) of a
/// ZIP archive into `dir`. Existing files are not overwritten. Returns (file, newly written).
pub fn unpack_installers(zip_file: &Path, dir: &Path) -> Result<Vec<(PathBuf, bool)>, String> {
    let f = std::fs::File::open(zip_file).map_err(|e| format!("{e}"))?;
    let mut zip = zip::ZipArchive::new(f).map_err(|e| format!("kein gültiges ZIP-Archiv: {e}"))?;
    let mut out = Vec::new();
    for i in 0..zip.len().min(2000) {
        let Ok(mut entry) = zip.by_index(i) else { continue };
        let Some(inner) = entry.enclosed_name() else { continue };
        if entry.is_dir() || inner.components().count() > 2 || entry.size() > 700 * 1024 * 1024 {
            continue;
        }
        let name = safe_name(&inner.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
        if !is_installer_name(&name) || name.len() < 5 {
            continue;
        }
        let target = dir.join(&name);
        let fresh = !target.exists();
        if fresh {
            let mut w = std::fs::File::create(&target).map_err(|e| format!("{e}"))?;
            if let Err(e) = std::io::copy(&mut entry, &mut w) {
                drop(w);
                let _ = std::fs::remove_file(&target);
                return Err(format!("Entpacken fehlgeschlagen: {e}"));
            }
        }
        out.push((target, fresh));
        if out.len() >= 3 {
            break;
        }
    }
    Ok(out)
}

/// Searches for the installer and loads it into Downloads, then checks it like a
/// self-downloaded file; a file that fails the check is deleted again. Nothing is started.
/// Where it looks, in this order (https only):
///   1. direct installer links on the official page (manufacturer's own site),
///   2. the same on up to 5 pages of that site whose address contains "download",
///   3. the installer address from the winget catalogue (also ZIP archives with the
///      installer inside) – for the cases where winget itself refuses the file because its
///      checksum in the catalogue is outdated.
///
/// The link is never trusted: only the valid signature of the same publisher as the
/// installed version counts.
pub fn fetch_installer(u: &Update, catalogue_urls: &[String], blocked: &dyn Fn(&Path) -> bool) -> Result<Kandidat, String> {
    let signers = installed_signers(u);
    if signers.is_empty() {
        return Err("Hersteller der installierten Version nicht feststellbar – ohne ihn lädt K9 nichts".into());
    }
    let dir = downloads_dir().ok_or("Ordner „Downloads“ nicht gefunden")?;
    let http = crate::sources::http().map_err(|e| format!("{e:#}"))?;
    let mut links: Vec<String> = Vec::new();
    let mut note = String::new();
    if host_of(&u.seite).is_some() {
        match crate::sources::download(&u.seite, &[], 4 * 1024 * 1024) {
            Ok(html) => {
                let html = String::from_utf8_lossy(&html).to_string();
                links = installer_links(&html, &u.seite);
                if links.is_empty() {
                    for sub in download_pages(&html, &u.seite) {
                        if let Ok(h) = crate::sources::download(&sub, &[], 4 * 1024 * 1024) {
                            links.extend(installer_links(&String::from_utf8_lossy(&h), &sub));
                        }
                        if !links.is_empty() {
                            break;
                        }
                    }
                }
            }
            Err(e) => note = format!("Seite nicht lesbar: {e:#}"),
        }
    }
    for c in catalogue_urls {
        let file = c.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
        if host_of(c).is_some() && !c.contains(['?', '#', ' ']) && (is_installer_name(&file) || file.ends_with(".zip")) && !links.contains(c) {
            links.push(c.clone());
        }
    }
    if links.is_empty() {
        return Err(if note.is_empty() { "weder auf der offiziellen Seite noch im winget-Katalog ein ladbares Installationsprogramm gefunden".into() } else { note });
    }
    let mut last = String::new();
    for url in links.into_iter().take(4) {
        let name = safe_name(url.rsplit('/').next().unwrap_or(""));
        // (file, loaded by K9 just now)
        let mut files: Vec<(PathBuf, bool)> = Vec::new();
        if name.to_ascii_lowercase().ends_with(".zip") {
            let zip_file = dir.join(format!("{name}.k9-archiv"));
            let res = load_to(&http, &url, &zip_file).and_then(|()| unpack_installers(&zip_file, &dir));
            let _ = std::fs::remove_file(&zip_file);
            match res {
                Ok(list) if !list.is_empty() => files = list,
                Ok(_) => last = format!("{name}: kein Installationsprogramm im Archiv"),
                Err(e) => last = format!("{name}: Laden fehlgeschlagen ({e})"),
            }
        } else {
            let target = dir.join(&name);
            if target.exists() {
                files.push((target, false));
            } else {
                match load_to(&http, &url, &target) {
                    Ok(()) => files.push((target, true)),
                    Err(e) => last = format!("{name}: Laden fehlgeschlagen ({e})"),
                }
            }
        }
        let mut found = None;
        for (file, fresh) in files {
            let shown = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            match check_file(u, &file, &signers, blocked) {
                Ok(k) if found.is_none() => found = Some(k),
                Ok(_) => {}
                Err(e) => {
                    // Only what K9 loaded itself is removed again.
                    if fresh {
                        let _ = std::fs::remove_file(&file);
                    }
                    last = format!("{shown}: {e}{}", if fresh { " – wieder gelöscht" } else { "" });
                }
            }
        }
        if let Some(k) = found {
            return Ok(k);
        }
    }
    Err(if last.is_empty() { "kein passendes Installationsprogramm gefunden".into() } else { last })
}

#[cfg(test)]
mod link_tests {
    use super::*;

    #[test]
    fn installers_are_unpacked_from_a_zip_archive_and_nothing_else() {
        use std::io::Write;
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let zip_path = dir.path().join("a.zip");
        let mut z = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let opt = zip::write::SimpleFileOptions::default();
        for (name, data) in [("WDSecuritySetup.exe", "MZ1"), ("liesmich.txt", "t"), ("a/b/c/tief.exe", "MZ2"), ("ordner/tool.msi", "m")] {
            z.start_file(name, opt).unwrap();
            z.write_all(data.as_bytes()).unwrap();
        }
        z.finish().unwrap();
        let out = dir.path().join("ziel");
        std::fs::create_dir_all(&out).unwrap();
        let got = unpack_installers(&zip_path, &out).unwrap();
        let names: Vec<String> = got.iter().map(|(p, _)| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, ["WDSecuritySetup.exe", "tool.msi"]);
        assert!(got.iter().all(|(_, fresh)| *fresh));
        assert!(!unpack_installers(&zip_path, &out).unwrap()[0].1, "vorhandene Datei wird nicht ueberschrieben");
        assert!(unpack_installers(&out.join("tool.msi"), &out).is_err());
    }

    #[test]
    fn only_installers_on_the_manufacturers_own_site() {
        let html = r#"<a href="https://www.hwinfo.com/files/hwi_860.zip">Portable</a>
            <a href="https://www.hwinfo.com/files/hwi64_860.exe">Installer</a>
            <a href='https://www.sac.sk/download/utildiag/hwi_860x.exe'>Mirror</a>
            <a href="/files/hwi32_setup.exe">32</a> <a href="/files/tool-portable.exe">p</a>
            <a href="https://files.hwinfo.com/x/setup-arm64.msi">arm</a>
            <a href="http://www.hwinfo.com/files/unsicher.exe">http</a>
            <a href="https://www.hwinfo.com/dl.exe?x=1">q</a>"#;
        let l = installer_links(html, "https://www.hwinfo.com/download/");
        assert_eq!(l, vec!["https://www.hwinfo.com/files/hwi64_860.exe".to_string()]);
        assert_eq!(installer_links("<a href=\"/files/app_setup.exe\">x</a>", "https://www.hwinfo.com/download/"), vec!["https://www.hwinfo.com/files/app_setup.exe".to_string()]);
        assert!(installer_links(html, "http://www.hwinfo.com/").is_empty());
        assert_eq!(site_of("files.hwinfo.com"), "hwinfo.com");
        let pages = download_pages(
            "<a href=\"/de/Download/windows/\">x</a> <a href='https://www.hwinfo.com/download/'>selbst</a> <a href=\"https://evil.example/download/\">fremd</a> <a href=\"/files/download.pdf\">pdf</a> <a href=\"/about\">a</a>",
            "https://www.hwinfo.com/download/",
        );
        assert_eq!(pages, vec!["https://www.hwinfo.com/de/Download/windows/".to_string()]);
        assert!(host_of("https://user@evil.example/").is_none());
    }
}
