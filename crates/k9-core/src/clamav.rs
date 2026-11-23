//! ClamAV integration: the official ClamAV for Windows (clamd + freshclam)
//! is used as an engine – no own CVD parser.
//!
//! * freshclam updates the signed databases into `<quellen>\clamav\db`.
//! * clamd listens on 127.0.0.1 only and is started just for the duration of
//!   a scan (it needs about 1 GB RAM with all signatures loaded).
//! * Files are streamed via the INSTREAM command.
//! * If ClamAV is not installed, the engine reports itself unavailable.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::QuellenConfig;
use crate::engine::{Engine, FileMeta, FileSession};
use crate::model::{Finding, Kind, Severity};
use crate::sources::{record, Update};

const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Files above this size are not sent to clamd: unpacking large installers and
/// archives recursively takes minutes. Hashes and YARA still cover them.
const MAX_STREAM: u64 = 40 * 1024 * 1024;

pub fn program_dir(cfg: &QuellenConfig) -> PathBuf {
    PathBuf::from(crate::paths::expand_env(&cfg.clamav_programmordner))
}

/// Path of clamd.exe if ClamAV is installed.
pub fn installed(cfg: &QuellenConfig) -> Option<PathBuf> {
    let p = program_dir(cfg).join("clamd.exe");
    p.is_file().then_some(p)
}

/// Does ClamAV start at all? Runs `clamd --version` (no signatures are loaded). The error
/// text names the Windows exit code; 0xC0000135 means a program file (DLL) is missing.
pub fn probe(cfg: &QuellenConfig) -> std::result::Result<(), String> {
    let Some(exe) = installed(cfg) else { return Ok(()) };
    if crate::schutz::in_service() && !is_under_program_files(&exe) {
        return Ok(());
    }
    let out = Command::new(&exe)
        .arg("--version")
        .creation_flags(BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("ClamAV ({}) lässt sich nicht starten: {e}.", exe.display()))?;
    match out.status.code() {
        Some(code) if !failed_to_start(code) => Ok(()),
        code => Err(probe_error(code)),
    }
}

/// Did Windows fail to start the program at all? Then the exit code is an NTSTATUS error
/// (0xC0000135 missing DLL, 0xC000007B damaged file, 0xC0000142 start failed …). A small
/// exit code means the program ran: without K9's configuration file `clamd --version` ends
/// with 1 ("Can't open/parse the config file") on a perfectly healthy installation
/// (measured on 21.11.2026) – that is no outage.
fn failed_to_start(code: i32) -> bool {
    (code as u32) >= 0xC000_0000
}

fn probe_error(code: Option<i32>) -> String {
    match code.map(|c| c as u32) {
        Some(0xC000_0135) => "ClamAV startet nicht: Es fehlt eine Programmdatei (Windows-Fehler 0xC0000135).".into(),
        Some(c) => format!("ClamAV startet nicht (Windows-Fehler 0x{c:08X})."),
        None => "ClamAV startet nicht (ohne Fehlernummer beendet).".into(),
    }
}

pub fn db_dir(sources_dir: &Path) -> PathBuf {
    sources_dir.join("clamav").join("db")
}

/// Writes our own clamd.conf/freshclam.conf (the installed ClamAV
/// configuration is not touched). Returns (clamd.conf, freshclam.conf).
pub fn write_configs(sources_dir: &Path, cfg: &QuellenConfig) -> Result<(PathBuf, PathBuf)> {
    let base = sources_dir.join("clamav");
    let db = db_dir(sources_dir);
    // Protected sources (service): clamd (runs as the user) gets its configuration
    // and log in the user's data folder; freshclam.conf is written only by the
    // service, never by a user process (it is used with SYSTEM rights).
    let writable = std::fs::create_dir_all(&db).is_ok() && is_writable_dir(&base);
    let work = if writable {
        base.clone()
    } else {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let w = local.join(crate::APP_NAME).join("clamav");
        std::fs::create_dir_all(&w)?;
        w
    };
    let clamd = work.join("clamd.conf");
    // clamd unpacks archives and PDFs into temporary files. In %TEMP% the real-time protection
    // would scan these pieces itself (YARA hits on "clamav-….tmp", a ransomware suspicion for
    // "pdf-tmp.…\pdf obj …"): they go to a folder of our own that is not watched.
    let tmp = work.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let fresh = base.join("freshclam.conf");
    std::fs::write(
        &clamd,
        format!(
            "# Von K9 erzeugt – nur 127.0.0.1\nTCPSocket {}\nTCPAddr 127.0.0.1\nDatabaseDirectory {}\nLogFile {}\nStreamMaxLength 48M\nMaxFileSize 40M\nMaxScanSize 100M\nMaxRecursion 10\nMaxFiles 5000\nMaxScanTime 15000\nMaxThreads 2\nForeground yes\nTemporaryDirectory {}\n{}",
            cfg.clamav_port,
            db.display(),
            work.join("clamd.log").display(),
            tmp.display(),
            pua_options(cfg.clamav_pua)
        ),
    )?;
    if !writable {
        return Ok((clamd, fresh));
    }
    std::fs::write(
        &fresh,
        format!(
            "# Von K9 erzeugt\nDatabaseDirectory {}\nDatabaseMirror database.clamav.net\nUpdateLogFile {}\n",
            db.display(),
            base.join("freshclam.log").display()
        ),
    )?;
    Ok((clamd, fresh))
}

/// clamd options for potentially unwanted programs: packers are no finding.
pub fn pua_options(on: bool) -> &'static str {
    if on { "DetectPUA yes\nExcludePUA Packed\nExcludePUA Packer\n" } else { "" }
}

/// Category and severity of a ClamAV name: PUA.*.Tool.* = Niedrig, other PUA = Mittel.
pub fn classify(name: &str) -> (String, Severity) {
    if !name.starts_with("PUA.") {
        (crate::model::category::MALWARE.into(), Severity::Hoch)
    } else if name.contains(".Tool.") {
        ("Unerwünschtes Programm (Werkzeug)".into(), Severity::Niedrig)
    } else {
        ("Unerwünschtes Programm".into(), Severity::Mittel)
    }
}

/// True for paths under %ProgramFiles% / %ProgramFiles(x86)% (no "..").
pub fn is_under_program_files(p: &Path) -> bool {
    let s = p.to_string_lossy().to_lowercase();
    !s.contains("..")
        && ["ProgramFiles", "ProgramFiles(x86)"].iter().filter_map(std::env::var_os).any(|pf| {
            let pf = pf.to_string_lossy().to_lowercase();
            s.starts_with(&format!("{}\\", pf.trim_end_matches('\\')))
        })
}

fn is_writable_dir(dir: &Path) -> bool {
    let probe = dir.join(".schreibtest");
    let ok = std::fs::write(&probe, b"x").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Runs freshclam (signature verification is done by freshclam itself).
pub fn update(sources_dir: &Path, cfg: &QuellenConfig) -> Result<Update> {
    if installed(cfg).is_none() {
        bail!(
            "ClamAV ist nicht installiert (erwartet in {}). Installation: winget install Cisco.ClamAV",
            program_dir(cfg).display()
        );
    }
    let (_, fresh_conf) = write_configs(sources_dir, cfg)?;
    let exe = program_dir(cfg).join("freshclam.exe");
    // The service runs freshclam with SYSTEM rights: only from a protected
    // program folder, never from a path a user program could have put into config.toml.
    if crate::schutz::in_service() && !is_under_program_files(&exe) {
        bail!("ClamAV-Programmordner {} liegt nicht unter Programme – der Dienst startet freshclam dort nicht", program_dir(cfg).display());
    }
    let out = Command::new(&exe)
        .arg(format!("--config-file={}", fresh_conf.display()))
        .creation_flags(BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("{} kann nicht gestartet werden", exe.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!("freshclam fehlgeschlagen: {}", text.lines().rev().take(3).collect::<Vec<_>>().join(" | "));
    }
    let db = db_dir(sources_dir);
    let mut files = Vec::new();
    let mut parts = Vec::new();
    let mut details = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for e in std::fs::read_dir(&db)?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".cvd") || name.ends_with(".cld") {
            files.push(record(sources_dir, &format!("clamav/db/{name}"))?);
            let base = name.trim_end_matches(".cvd").trim_end_matches(".cld").to_string();
            match read_cvd_header(&e.path()) {
                Some((ver, sigs)) => {
                    parts.push(format!("{base} {ver}"));
                    details.insert(base, sigs);
                    total += sigs;
                }
                None => parts.push(base),
            }
        }
    }
    if files.is_empty() {
        bail!("freshclam hat keine Signaturdateien geladen");
    }
    parts.sort();
    Ok(Update { version: parts.join(", "), entries: total, files, license: None, details })
}

/// Reads version and number of signatures from the 512-byte header of a
/// .cvd/.cld file: `ClamAV-VDB:<datum>:<version>:<signaturen>:<level>:...`.
pub fn read_cvd_header(path: &Path) -> Option<(u64, u64)> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 512];
    f.read_exact(&mut head).ok()?;
    parse_cvd_header(&head)
}

pub fn parse_cvd_header(head: &[u8]) -> Option<(u64, u64)> {
    let text = String::from_utf8_lossy(head);
    let fields: Vec<&str> = text.split(':').collect();
    if fields.first() != Some(&"ClamAV-VDB") || fields.len() < 4 {
        return None;
    }
    Some((fields[2].trim().parse().ok()?, fields[3].trim().parse().ok()?))
}

/// Signature counts of the currently present database files (for statistics).
pub fn signature_counts(sources_dir: &Path) -> std::collections::BTreeMap<String, u64> {
    let mut out = std::collections::BTreeMap::new();
    for e in std::fs::read_dir(db_dir(sources_dir)).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".cvd") || name.ends_with(".cld") {
            if let Some((_, sigs)) = read_cvd_header(&e.path()) {
                out.insert(name.trim_end_matches(".cvd").trim_end_matches(".cld").to_string(), sigs);
            }
        }
    }
    out
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// True if a clamd answers on 127.0.0.1:port.
pub fn ping(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr(port), Duration::from_millis(500)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.write_all(b"zPING\0").is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    matches!(s.read(&mut buf), Ok(n) if buf[..n].starts_with(b"PONG"))
}

/// clamd started by us for the duration of a scan; stopped on drop.
pub struct Daemon {
    child: Option<Child>,
}

impl Daemon {
    /// Uses a running clamd or starts one (waits until the signatures are loaded).
    pub fn start(sources_dir: &Path, cfg: &QuellenConfig) -> Result<Self> {
        if ping(cfg.clamav_port) {
            return Ok(Self { child: None });
        }
        let exe = installed(cfg).context("ClamAV ist nicht installiert")?;
        let has_db = std::fs::read_dir(db_dir(sources_dir))
            .map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".cvd") || e.file_name().to_string_lossy().ends_with(".cld")))
            .unwrap_or(false);
        if !has_db {
            bail!("Keine ClamAV-Signaturen vorhanden – bitte 'k9 quellen aktualisieren clamav'");
        }
        let (clamd_conf, _) = write_configs(sources_dir, cfg)?;
        let child = Command::new(&exe)
            .arg(format!("--config-file={}", clamd_conf.display()))
            .creation_flags(BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("{} kann nicht gestartet werden", exe.display()))?;
        let mut daemon = Self { child: Some(child) };
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(240) {
            if ping(cfg.clamav_port) {
                tracing::info!("clamd bereit nach {:?}", start.elapsed());
                return Ok(daemon);
            }
            if let Some(c) = daemon.child.as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    bail!("clamd wurde beendet ({status}) – siehe clamd.log im Ordner clamav");
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        bail!("clamd antwortet nicht")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Engine that streams each file to clamd (INSTREAM).
pub struct ClamdEngine {
    port: u16,
}

impl ClamdEngine {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

struct ClamdSession {
    stream: Option<TcpStream>,
    started: Instant,
}

impl ClamdSession {
    fn send(&mut self, chunk: &[u8]) {
        if let Some(s) = self.stream.as_mut() {
            let len = (chunk.len() as u32).to_be_bytes();
            if s.write_all(&len).and_then(|_| s.write_all(chunk)).is_err() {
                self.stream = None;
            }
        }
    }
}

/// Parses a clamd reply like `stream: Win.Test.EICAR_HDB-1 FOUND`.
pub fn parse_reply(reply: &str) -> Option<String> {
    let r = reply.trim_end_matches('\0').trim();
    let body = r.strip_prefix("stream:").unwrap_or(r).trim();
    body.strip_suffix("FOUND").map(|n| n.trim().to_string()).filter(|n| !n.is_empty())
}

impl FileSession for ClamdSession {
    fn feed(&mut self, chunk: &[u8]) {
        for part in chunk.chunks(64 * 1024) {
            self.send(part);
        }
    }

    fn finish(mut self: Box<Self>, meta: &FileMeta, sha256: &str) -> Vec<Finding> {
        let Some(mut s) = self.stream.take() else { return Vec::new() };
        if s.write_all(&[0, 0, 0, 0]).is_err() {
            return Vec::new();
        }
        let mut reply = Vec::new();
        let _ = s.read_to_end(&mut reply);
        let reply = String::from_utf8_lossy(&reply);
        tracing::debug!("clamd {:?} für {} ({} KB)", self.started.elapsed(), meta.path.display(), meta.size / 1024);
        match parse_reply(&reply) {
            Some(name) => vec![Finding {
                category: classify(&name).0,
                severity: classify(&name).1,
                path: meta.path.clone(),
                sha256: sha256.to_string(),
                size: meta.size,
                rule_id: format!("CLAMAV:{name}"),
                threat_name: format!("ClamAV: {name}"),
                engine: "clamav".into(),
                kind: Kind::Datei,
                details: None,
            }],
            None => {
                if reply.contains("ERROR") {
                    tracing::debug!("clamd-Fehler bei {}: {reply}", meta.path.display());
                }
                Vec::new()
            }
        }
    }
}

impl Engine for ClamdEngine {
    fn id(&self) -> &'static str {
        "clamav"
    }
    fn begin<'a>(&'a self, meta: &FileMeta) -> Option<Box<dyn FileSession + 'a>> {
        if meta.size > MAX_STREAM {
            return None;
        }
        let mut s = TcpStream::connect_timeout(&addr(self.port), Duration::from_secs(2)).ok()?;
        let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
        s.write_all(b"zINSTREAM\0").ok()?;
        Some(Box::new(ClamdSession { stream: Some(s), started: Instant::now() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn service_runs_freshclam_only_from_program_files() {
        let pf = std::env::var("ProgramFiles").unwrap();
        assert!(is_under_program_files(&std::path::Path::new(&pf).join("ClamAV").join("freshclam.exe")));
        assert!(!is_under_program_files(std::path::Path::new(r"C:\Users\x\AppData\Local\Temp\freshclam.exe")));
        assert!(!is_under_program_files(&std::path::Path::new(&pf).join("..").join("Users").join("freshclam.exe")));
        assert!(!is_under_program_files(std::path::Path::new(&format!(r"{pf}X\freshclam.exe"))));
    }

    #[test]
    fn pua_without_packers_and_tools_low() {
        assert!(pua_options(true).contains("DetectPUA yes") && pua_options(true).contains("ExcludePUA Packed"));
        assert_eq!(pua_options(false), "");
        assert_eq!(classify("PUA.Win.Tool.Kmsauto-1").1, Severity::Niedrig);
        assert_eq!(classify("PUA.Win.Adware.Test-1").1, Severity::Mittel);
        assert_eq!(classify("Win.Trojan.Test-1").1, Severity::Hoch);
    }

    #[test]
    fn cvd_header_parsing() {
        let mut head = b"ClamAV-VDB:12 Nov 2026 07-26 -0400:27822:2073451:90:abc:sig:raynman:1762946760".to_vec();
        head.resize(512, b' ');
        assert_eq!(parse_cvd_header(&head), Some((27822, 2073451)));
        assert_eq!(parse_cvd_header(b"kein Header"), None);
    }

    #[test]
    fn reply_parsing() {
        assert_eq!(parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND\0").as_deref(), Some("Win.Test.EICAR_HDB-1"));
        assert_eq!(parse_reply("stream: OK\0"), None);
        assert_eq!(parse_reply("INSTREAM size limit exceeded. ERROR\0"), None);
    }

    /// Fake clamd: checks the INSTREAM framing and reports a find for our test signature.
    #[test]
    fn instream_protocol_with_fake_clamd() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut cmd = [0u8; 10];
            c.read_exact(&mut cmd).unwrap();
            assert_eq!(&cmd, b"zINSTREAM\0");
            let mut data = Vec::new();
            loop {
                let mut len = [0u8; 4];
                c.read_exact(&mut len).unwrap();
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 {
                    break;
                }
                let mut chunk = vec![0u8; n];
                c.read_exact(&mut chunk).unwrap();
                data.extend(chunk);
            }
            let found = memchr::memmem::find(&data, &crate::engine::test_pattern_bytes()).is_some();
            let reply: &[u8] = if found { b"stream: K9.Test FOUND\0" } else { b"stream: OK\0" };
            c.write_all(reply).unwrap();
        });
        let engine = ClamdEngine::new(port);
        let meta = FileMeta { path: "x".into(), size: 10 };
        let mut session = engine.begin(&meta).unwrap();
        session.feed(b"vorher ");
        session.feed(&crate::engine::test_pattern_bytes());
        let f = session.finish(&meta, "ab");
        server.join().unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "CLAMAV:K9.Test");
    }

    #[test]
    fn unavailable_without_installation() {
        let cfg = QuellenConfig { clamav_programmordner: "C:\\gibt-es-nicht".into(), ..Default::default() };
        assert!(installed(&cfg).is_none());
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let err = update(dir.path(), &cfg).err().unwrap().to_string();
        assert!(err.contains("nicht installiert"));
        // No clamd on a random free port -> engine skips files instead of failing.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert!(ClamdEngine::new(port).begin(&FileMeta { path: "x".into(), size: 1 }).is_none());
    }
}

#[cfg(test)]
mod temp_dir_tests {
    use super::*;

    #[test]
    fn the_start_probe_names_a_missing_program_file() {
        assert!(probe_error(Some(0xC000_0135u32 as i32)).contains("fehlt eine Programmdatei"));
        assert_eq!(probe_error(Some(2)), "ClamAV startet nicht (Windows-Fehler 0x00000002).");
        assert!(probe_error(None).contains("ohne Fehlernummer"));
        // Only a start that Windows itself refused counts; a healthy clamd without its
        // configuration file ends with 1 and must never raise the alarm.
        assert!(failed_to_start(0xC000_0135u32 as i32) && failed_to_start(0xC000_007Bu32 as i32));
        assert!(!failed_to_start(0) && !failed_to_start(1) && !failed_to_start(2));
    }

    #[test]
    fn clamd_gets_a_temporary_folder_of_its_own() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let (clamd_conf, _) = write_configs(dir.path(), &QuellenConfig::default()).unwrap();
        let tmp = dir.path().join("clamav").join("tmp");
        assert!(tmp.is_dir(), "der Ordner wird angelegt");
        let conf = std::fs::read_to_string(clamd_conf).unwrap();
        assert!(conf.contains(&format!("TemporaryDirectory {}\n", tmp.display())), "{conf}");
    }
}
